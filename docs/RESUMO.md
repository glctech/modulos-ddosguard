# DDoS Guard — Resumo do Desenvolvimento

Registro completo do que foi construído, testado e corrigido durante o
desenvolvimento do módulo DDoS Guard para Zabbix 7.4.11.

---

## Estatísticas da sessão

| Métrica | Valor |
|---|---|
| Fases do projeto | 11 |
| Bugs corrigidos | 20+ |
| Hosts monitorados | 3 (appliance, webserver1, prx02) |
| Sistemas operacionais | 2 (Rocky Linux 8 + Ubuntu 22/24 + Windows Server) |
| Arquivos entregues | 50 |
| Bloqueios detectados ao vivo | 255.036+ |
| Templates criados | 5 |
| Integrações externas | 4 (Wazuh, Suricata, pfSense, FortiGate) |

---

## Fase 1 — Estrutura inicial do módulo

### O que foi construído

- **Template Zabbix 7.4.11** com 8 itens trapper (`ddosguard.attack.event`,
  `ddosguard.block.firewall`, `ddosguard.block.antivirus`,
  `ddosguard.attacks.rate`, `ddosguard.firewall.rate`,
  `ddosguard.antivirus.rate`, `ddosguard.distinct_ips.rate`,
  `ddosguard.agent.heartbeat`) + triggers + Template Dashboard

- **Tabelas auxiliares MySQL/PostgreSQL:**
  - `ddosguard_attacks` — eventos de ataque agregados por IP
  - `ddosguard_blocks` — bloqueios de firewall e antivírus
  - `ddosguard_host_status` — status de firewall/antivírus por host

- **Dois widgets de frontend PHP** instaláveis em `Administration → Modules`:
  - `DDoSAttackMonitor` — painel de ataques em tempo real (IP, país, tipo,
    tentativas, severidade, bloqueado, firewall, antivírus)
  - `DDoSBlockMonitor` — comparativo Firewall x Antivírus (totais por país,
    tabela detalhada de bloqueios)

- **API `ingest.php`** publicada no webroot do Zabbix: recebe eventos JSON
  via HTTP POST, valida o token, grava no banco e repassa contadores via
  `zabbix_sender`

### Bugs corrigidos nesta fase

- Tipo de item `TRAPPER` → `TRAP` (nome correto no schema do Zabbix 7.4)
- UUIDs decorativos substituídos por UUIDv4 reais
- Namespace PHP `Widgets\` → `Modules\` (módulos em `ui/modules/` usam prefixo `Modules\`)
- Largura dos widgets: 24 → 72 colunas (grid real do Zabbix)

---

## Fase 2 — Agente coletor Python (Linux)

### O que foi construído

- **`ddos_guard_agent.py`** multiplataforma (Python 3.6+):
  - Lê `iptables`/`UFW`/`fail2ban`/`ClamAV`/`auth.log` em tempo real
  - Geolocaliza IPs via GeoIP2 local (MaxMind) com fallback para ip-api.com
  - Agrega eventos por janela de 60s antes de enviar
  - Envia via HTTP POST para o `ingest.php`

- **`LogTailer`** com leitura incremental:
  - Detecta rotação de log por inode (logrotate)
  - `skip_existing=True` (padrão): pula para o final do arquivo ao iniciar,
    evitando reprocessar histórico de milhares de entradas antigas

- **Filtro `is_private_ip()`**: descarta RFC1918, loopback, broadcast e
  multicast antes de enviar ao servidor — elimina 192.168.x.x, 10.x.x.x,
  255.255.255.255 etc. que poluíam o banco

- **Serviço systemd `ddos-guard-agent`** com restart automático (RestartSec=5)

- **Instalador interativo `install_agent_linux.sh`**:
  - Detecta logs disponíveis automaticamente
  - Pergunta URL do ingest.php, token, hostname e hostid
  - Cria usuário de sistema `zabbix` se não existir
  - Grava `/etc/zabbix/ddos_guard_agent.conf` (sem BOM)
  - Registra e inicia o serviço systemd
  - Suporte a modo não-interativo via flags (`--yes --ingest-url ... --token ...`)

### Bugs corrigidos nesta fase

- `PermissionError` no `fail2ban.log` quebrava o ciclo inteiro — cada fonte
  de log agora falha silenciosamente (loga aviso só na primeira ocorrência)
  sem afetar as outras fontes
- Prefixo `IPTABLES_DROP:` adicionado ao regex de detecção (Rocky Linux usa
  esse prefixo em vez do padrão do iptables)
- Helpers de UI (`warn`/`ok`/`info`) do instalador shell escreviam para
  stdout, contaminando valores capturados via command substitution `$(...)` —
  corrigido redirecionando tudo para stderr

---

## Fase 3 — Assistente de configuração do servidor

### O que foi construído

- **`setup.py`** — assistente interativo compatível com Python 3.6+:
  - Detecta o webroot real lendo a diretiva `root` do `nginx.conf` via regex
    (em vez de adivinhar por lista de candidatos)
  - Detecta MySQL/PostgreSQL e lê credenciais do `zabbix_server.conf`
  - Gera token seguro com `secrets.token_hex(32)`
  - Escaneia o sistema por cópias antigas do `ingest.php` e oferece remover
  - Escreve `ingest.config.php` sem BOM via Python `open(..., 'w', encoding='utf-8')`
  - Testa a conexão com o banco usando `MYSQL_PWD`/`PGPASSWORD` via env
    (nunca como argumento na linha de comando)
  - Testa o endpoint HTTP no final

### Bugs corrigidos nesta fase

- `capture_output=True` e `text=True` do `subprocess.run` só existem no
  Python 3.7+ — o appliance roda Python 3.6. Substituído por
  `stdout=PIPE, stderr=PIPE, universal_newlines=True` via helper `_run()`
- Detecção de driver de banco usava heurística sem sentido (`"pgsql" in DBPort`)
  — corrigida para checar se a porta é 5432 ou 3306
- `$PSScriptRoot` não disponível em alguns contextos PowerShell — substituído
  por detecção robusta do caminho do script

### Problema raiz identificado em produção

5 cópias do `ingest.php` espalhadas pelo sistema de execuções anteriores em
diretórios diferentes. A cópia servida pelo Nginx
(`/usr/share/zabbix/ui/ddosguard/ingest.php`) estava **truncada em 2.775
bytes** (versão antiga sem leitura do `ingest.config.php`) enquanto as
outras tinham os 13.350 bytes corretos. Isso causava o erro `"invalid token"`
mesmo com a configuração correta. Solução: o `setup.py` agora varre o
sistema antes de publicar e oferece limpar cópias divergentes.

---

## Fase 4 — Agente Windows (Event Log nativo)

### O que foi construído

- **`WindowsEventLogReader`** via `wevtutil.exe` (100% nativo, sem pywin32):
  - Lê Security (Event ID 4625 — RDP/SMB brute-force)
  - Lê Windows Firewall (5152/5157 — bloqueios do Windows Filtering Platform)
  - Lê Windows Defender (1116/1117 — detecção e ação sobre malware)
  - Parse de XML com `xml.etree.ElementTree` da stdlib
  - Extrai campo `IpAddress:` do evento 4625 (não `Source Network Address:`)
  - Descarta `::1` (loopback IPv6) e valores nulos (`-`)

- **Instalador PowerShell `install_agent_windows.ps1`**:
  - Detecta e ignora o stub da Microsoft Store em `WindowsApps\python.exe`
  - Resolve o `python.exe` real para o Task Scheduler (que roda como SYSTEM
    e não acessa `AppData` do usuário)
  - Verifica e habilita o canal de log do Windows Firewall
  - Registra tarefa `DDoSGuardAgent` no Task Scheduler com restart automático
  - Grava `agent.conf` sem BOM via `.NET UTF8Encoding($false)`
  - Sem BOM UTF-8 no arquivo de saída (PowerShell 5.x grava BOM com `Set-Content -Encoding UTF8`)

### Bugs corrigidos nesta fase

| Problema | Causa | Correção |
|---|---|---|
| `No installed Python found` | Task Scheduler roda como SYSTEM sem acesso a `AppData` | Reinstalar Python com "Install for all users" |
| `MissingSectionHeaderError: ï»¿[general]` | BOM UTF-8 no agent.conf | `UTF8Encoding($false)` no PowerShell |
| `subprocess is not defined` | `import subprocess` removido acidentalmente na refatoração | Reimportado |
| pywin32 não instala | Python 3.14 não tem wheel no PyPI | Agente reescrito para usar `wevtutil.exe` sem pip |
| Script parava no `import win32evtlog` | `$ErrorActionPreference = "Stop"` tratava stderr do Python como erro fatal | Alterado para "Continue" + try/catch individuais |
| `Write-Warn` inválido | Cmdlet correto é `Write-Warning` | Corrigido |
| Acentos corrompidos (`estÃ¡`) | Script salvo em UTF-8 sem BOM, PowerShell 5.x lê como Windows-1252 | Script reescrito sem acentos + BOM adicionado |

---

## Fase 5 — Integração com o Zabbix (raw events JSON)

### Problema identificado

O `ingest.php` enviava via `zabbix_sender` apenas os **contadores**
(`ddosguard.attacks.rate`, `ddosguard.firewall.rate`, `ddosguard.antivirus.rate`)
mas **nunca** enviava os raw events JSON. Por isso os itens
`ddosguard.attack.event`, `ddosguard.block.firewall` e
`ddosguard.block.antivirus` ficavam sempre vazios no Latest data.

### Correções

- Adicionado envio dos 3 raw events JSON nos casos `attack`, `block_firewall`
  e `block_antivirus` do switch do `ingest.php`
- Deduplicação de bloqueios de firewall: mesmo IP nos últimos 60s faz
  `UPDATE` do timestamp em vez de inserir nova linha — evita milhares de
  linhas duplicadas quando o iptables gera dezenas de entradas por segundo
  para o mesmo IP atacante

### Diagnóstico de `zabbix_sender failed: 1`

O host precisa:
1. Existir no Zabbix com nome **exatamente igual** ao `zbx_host` do `agent.conf`
2. Ter o template `DDoS Guard - Agent` (ou `Security Monitoring`) associado
3. O template precisa conter o item com a chave correta

---

## Fase 6 — Configuração do ambiente Linux em produção

### Rocky Linux 8 (appliance Zabbix)

```bash
# Habilita log de bloqueios no iptables
iptables -I INPUT 10 -j LOG --log-prefix "IPTABLES_DROP: " --log-level 4

# Instala fail2ban (requer EPEL)
dnf install -y epel-release && dnf install -y fail2ban

# Configura fail2ban para SSH
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600 / findtime = 600 / maxretry = 3
banaction = iptables-multiport
[sshd]
enabled = true / port = ssh / logpath = /var/log/secure
EOF
systemctl enable --now fail2ban

# Instala ClamAV
dnf install -y clamav clamav-update clamd
freshclam && systemctl enable --now clamd@scan

# Permissões dos logs
chmod 644 /var/log/messages /var/log/secure /var/log/fail2ban.log
chmod 644 /var/log/clamav/clamd.log
```

### Ubuntu/Debian (hosts com UFW)

```bash
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow from 192.168.0.52 to any   # só o appliance, não a subnet inteira
ufw logging medium
chmod 644 /var/log/ufw.log /var/log/auth.log
```

> **Atenção:** `ufw allow from 192.168.0.0/24` impede que o tráfego da rede
> local gere `[UFW BLOCK]`. Use regras específicas por IP.

### Melhorias no agente para suportar esses ambientes

- Regex de detecção de DROP expandido: `IPTABLES_DROP|[UFW BLOCK]|DROP|REJECT|DENY`
- Linhas `[UFW AUDIT]` ignoradas (informativas, não bloqueios)
- Linhas `[UFW ALLOW]` de saída (`IN= OUT=enp0s3`) ignoradas

---

## Fase 7 — Template dedicado para o agente

### Motivação

O template `DDoS Guard - Security Monitoring` contém o dashboard, que só faz
sentido no appliance. Associar esse template em todos os hosts monitorados
causava itens sem dados e poluía o Zabbix.

### Solução

Novo arquivo `template_ddos_guard_agent.yaml` com:
- Apenas os 8 itens trapper que o agente envia
- 6 triggers de alerta por host (sem dashboard)

### Triggers do template do agente

| Trigger | Prioridade | Condição |
|---|---|---|
| Agente parou de enviar dados | Warning | Sem heartbeat por 15min |
| Pico de ataques (≥ 50/min) | High | `attacks.rate ≥ 50` por 2min |
| Possível DDoS (≥ 200/min) | Disaster | `attacks.rate ≥ 200` por 5min |
| Ataque distribuído (≥ 50 IPs) | Disaster | `distinct_ips ≥ 50` por 5min |
| Volume alto de bloqueios (≥ 500/min) | High | `firewall.rate ≥ 500` por 10min |
| Múltiplas detecções de malware (≥ 5/min) | High | `antivirus.rate ≥ 5` por 10min |

### Quando usar cada template

| Template | Arquivo | Onde associar |
|---|---|---|
| `DDoS Guard - Security Monitoring` | `template_ddos_guard.yaml` | Só no **appliance** (tem dashboard) |
| `DDoS Guard - Agent` | `template_ddos_guard_agent.yaml` | Em cada **host monitorado** |

---

## Fase 8 — Instalador MSI Windows (em andamento)

### O que foi construído

- Projeto de build `ddosguard_msi/` com estrutura completa:
  - `src/ddosguard_service.py` — wrapper de serviço Windows nativo
  - `src/ddosguard_setup_wizard.py` — wizard tkinter com auto-descoberta via API Zabbix
  - `build/build_service.spec` + `build_wizard.spec` — specs do PyInstaller
  - `wix/DDoSGuardAgent.wxs` — definição WiX v3 do MSI
  - `vbs/WriteAgentConf.vbs` + `FetchHostId.vbs` — scripts VBScript embutidos
  - `scripts/build_msi.ps1` — orquestra PyInstaller → WiX → .msi
  - `resources/banner.bmp`, `dialog.bmp`, `icon.ico` — gerados a partir do logo GLCTech

- **Assets visuais** criados a partir do logo oficial da GLCTech
  (`logo_2_.png`, 1952×544 RGBA):
  - Cores exatas extraídas: vermelho escuro `#C00000`, fundo `#080E1C`
  - `banner.bmp` (498×55px) — banner superior do instalador
  - `dialog.bmp` (164×312px) — painel lateral com ícone de radar
  - `icon.ico` (256/48/32/16px) — multi-resolução

- **Janela de configuração** (`GLCTechConfigDlg`) com:
  - Campo URL pré-preenchido com `http://192.168.0.52/ddosguard/ingest.php`
  - Campo token pré-preenchido
  - Campo hostname (padrão: `[ComputerName]`)
  - Campo hostid com botão "Buscar do Zabbix" (API REST: `user.login` → `host.get`)
  - Botão "Avançar" desativado até URL e token estarem preenchidos

### Bugs corrigidos no WiX v3

| Erro | Causa | Correção |
|---|---|---|
| `CNDL0006: Property Value=""` | WiX v3 rejeita string vazia em `Value` | Removido `Value=""`, adicionado `Secure="yes"` |
| `LGHT1076: String overflow` | VBScript > 255 chars na coluna `Target` | Movido para `<Binary>` + `BinaryKey` (padrão do MSI Zabbix oficial) |
| `LGHT0204: WixUI_Font_Title_Size_8` | Estilo não existe no WiX v3 | Definido `<TextStyle Id="GLCTech_SectionTitle">` próprio |
| Namespace WiX v4 | `wixtoolset.org/schemas/v4` incompatível com WiX 3.11 | Trocado para `schemas.microsoft.com/wix/2006/wi` |
| `REMOVE~="ALL"` | Operador `~=` é WiX v4 | Trocado para `REMOVE="ALL"` |

### Instalação silenciosa via GPO

```powershell
msiexec /i DDoSGuardAgent.msi /qn `
  INGEST_URL="http://192.168.0.52/ddosguard/ingest.php" `
  INGEST_TOKEN="fec640fb..." `
  HOSTNAME="WIN-SERVER01" `
  HOSTID="10085"
```

---

## Resultado final — Dashboard ao vivo

Ao final da sessão, o dashboard estava funcionando com dados reais:

- **84 eventos de ataque** de IPs externos reais: Brasil, EUA, Canadá, Chile
- **222 tentativas** agregadas no período
- **13 IPs de origem distintos**
- **255.036 bloqueios de firewall** detectados (CA 191k, CL 57k, US 3.9k, BR 1.9k)
- **7 detecções de antivírus** (ClamAV — Eicar-Signature)
- **Alertas automáticos** disparando e resolvendo: "Pico de tentativas ≥ 50/min",
  "Possível ataque DDoS ≥ 200 tentativas/min por 5min"
- **3 hosts ativos** enviando heartbeat: `appliance`, `webserver1`, `prx02`
- **DNS-SERVER** (Windows Server) com agente funcionando via Task Scheduler,
  heartbeat chegando a cada 10s

---

## Arquivos entregues no pacote final

```
zbx_ddos_guard/
├── templates/
│   ├── template_ddos_guard.yaml          # Template servidor (com dashboard)
│   └── template_ddos_guard_agent.yaml    # Template agente (por host)
├── sql/
│   └── schema.sql                        # Tabelas auxiliares
├── scripts/
│   ├── ingest.php                        # API de ingestão
│   ├── ddos_guard_agent.py               # Agente coletor Linux + Windows
│   ├── ddos_guard_agent.conf.example     # Config de exemplo
│   ├── ddos-guard-agent.service          # Unit systemd
│   ├── install_agent_linux.sh            # Instalador Linux
│   ├── install_agent_windows.ps1         # Instalador Windows
│   ├── setup.py                          # Assistente do servidor
│   └── provision_dashboard.py            # Cria dashboard via API
├── modules/
│   ├── DDoSAttackMonitor/                # Widget de ataques
│   └── DDoSBlockMonitor/                 # Widget de bloqueios
└── docs/
    ├── INSTALL.md                        # Guia de instalação completo
    └── RESUMO.md                         # Este arquivo
```

---

## Fase 9 — SOC Completo: Correlação, MITRE ATT&CK e Integrações

### O que foi adicionado (sem alterar a estrutura existente)

#### Motor de correlação automática (`scripts/correlator.php`)

- **Classificação de severidade dinâmica** (1-10):
  | Score | Label | Critérios |
  |---|---|---|
  | 1-2 | info | 1 fonte, < 5 tentativas |
  | 3-4 | low | 1 fonte, 5-50 tentativas |
  | 5-6 | medium | 2 fontes ou > 50 tentativas |
  | 7-8 | high | 3+ fontes ou > 200 tentativas |
  | 9-10 | critical | Múltiplas fontes + reincidência |

- **Correlação automática por IP** em janela de 2h — agrupa eventos de diferentes fontes no mesmo incidente
- **Escalada de severidade** — score sobe conforme chegam eventos de novas fontes
- **Classificação MITRE ATT&CK** automática por tipo de ataque:
  - `BRUTE_FORCE_SSH` → T1110.001 (Credential Access)
  - `BRUTE_FORCE_RDP` → T1110 (Credential Access)
  - `SYN_FLOOD` → T1498.001 (Impact)
  - `SQL_INJECTION` → T1190 (Initial Access)
  - `MALWARE` → T1204 (Execution)
  - `C2_COMMUNICATION` → T1071 (Command and Control)
- **Verificação de Threat Intelligence** via tabela `ddosguard_threat_intel`

#### Migration do banco (`sql/migration_v2_soc.sql`)

Novas tabelas (sem alterar as existentes):
- `ddosguard_correlations` — grupos de incidentes correlacionados
- `ddosguard_integration_events` — eventos brutos das integrações externas
- `ddosguard_threat_intel` — blacklists de IPs
- View `ddosguard_active_incidents` — incidentes não resolvidos

Novas colunas em `ddosguard_attacks`:
`severity_label`, `severity_score`, `correlated`, `correlation_id`,
`mitre_tactic`, `mitre_technique`, `threat_intel`, `threat_intel_src`, `updated_at`

> **Atenção:** MySQL 5.7/8.0 não suporta `IF NOT EXISTS` no `ALTER TABLE`.
> Execute as colunas manualmente se a migration falhar:
> ```sql
> ALTER TABLE ddosguard_attacks ADD COLUMN severity_label VARCHAR(16) NULL, ...
> ```

#### Bug corrigido durante implantação

A chave primária de `ddosguard_attacks` é `attack_id` (não `id`).
O `UPDATE` no correlator usava `ORDER BY id DESC` e nunca encontrava o registro.
Corrigido para `ORDER BY attack_id DESC`.

#### Integrações externas (`scripts/integrations/`)

| Arquivo | Plataforma | Método |
|---|---|---|
| `wazuh_receiver.php` | Wazuh HIDS/SIEM | Hook de integração nativa |
| `suricata_receiver.php` | Suricata IDS/IPS | eve.json via forwarder Python |
| `syslog_receiver.php` | pfSense + FortiGate | Syslog UDP/TCP via rsyslog |
| `install_integrations.sh` | Todas | Instalador automático |

#### Resultado validado em produção

```
IP: 185.220.101.50 (Alemanha)
Fontes detectadas: ["agent","fail2ban","suricata"]
Total de eventos: 5
Severidade final: critical (9)
MITRE: Credential Access / T1110.001 (Brute Force: Password Guessing)
Correlation ID: 089d4266-fcd5-4d11-abc9-8e9e16dd2209
```

---

## Fase 10 — Templates FortiGate e FortiSwitch

### Motivação

A análise do template oficial `FortiGate by SNMP` (Zabbix 7.4) revelou que ele
cobre bem a infraestrutura (CPU, memória, HA, interfaces) mas não tem nenhuma
trigger de segurança baseada nos contadores IPS/VPN/sessões. Os templates DDoS
Guard complementam o template SNMP sem duplicar coleta.

### Templates criados

#### `DDoS Guard - FortiGate Security`

Arquivo: `templates/template_ddos_guard_fortigate.yaml`

**8 itens | 7 triggers | 9 macros**

| Item | Tipo | Descrição |
|---|---|---|
| `ddosguard.firewall.rate` | TRAP | Bloqueios/min via syslog |
| `ddosguard.attack.event` | TRAP | Evento JSON de ataque via syslog |
| `ddosguard.block.firewall` | TRAP | Evento JSON de bloqueio via syslog |
| `ddosguard.block.antivirus` | TRAP | Detecção AV do FortiGate via syslog |
| `ddosguard.fg.ips.blocks.rate` | CALCULATED | Taxa IPS/min calculada sobre SNMP |
| `ddosguard.fg.sessions.alert` | CALCULATED | Sessões ativas calculadas sobre SNMP |
| `ddosguard.fg.vpn.down` | CALCULATED | Túneis VPN ativos calculados sobre SNMP |
| `ddosguard.agent.heartbeat` | TRAP | Pipeline syslog→DDoS Guard ativo |

**Triggers:**
- Pico de bloqueios IPS ≥ `{$FG.IPS.BLOCK.WARN}` (WARNING)
- Ataque detectado pelo IPS ≥ `{$FG.IPS.BLOCK.HIGH}` (HIGH)
- Saturação de sessões ≥ `{$FG.SESSION.HIGH}` (HIGH)
- Alto número de sessões ≥ `{$FG.SESSION.WARN}` (WARNING)
- Queda de mais de 2 túneis VPN (HIGH)
- Volume crítico de bloqueios via syslog (HIGH)
- Pipeline DDoS Guard parado há 30min (WARNING)

**Como usar:**
```
1. Associe "FortiGate by SNMP" no host (SNMP polling)
2. Associe "DDoS Guard - FortiGate Security" no mesmo host
3. Configure syslog no FortiGate:
   config log syslogd setting
     set status enable
     set server IP_DO_APPLIANCE
     set port 514
   end
```

#### `DDoS Guard - FortiSwitch Security`

Arquivo: `templates/template_ddos_guard_fortigate.yaml` (mesmo arquivo)

**7 itens | 6 triggers | 3 macros**

Detecta via syslog eventos específicos de switches:

| Item | Trigger | Prioridade |
|---|---|---|
| `ddosguard.fsw.port.violations` | Port security violation ≥ 10 em 5min | HIGH |
| `ddosguard.fsw.mac.spoof` | MAC Spoofing ≥ 5 eventos em 5min | HIGH |
| `ddosguard.fsw.dot1x.failures` | 802.1X failures ≥ 20 em 5min | WARNING |
| `ddosguard.fsw.loop.detected` | Qualquer loop detectado | **DISASTER** |
| `ddosguard.firewall.rate` | Volume alto de bloqueios | HIGH |
| `ddosguard.agent.heartbeat` | Pipeline parado há 30min | WARNING |

### Abordagem técnica

O template FortiGate usa dois mecanismos complementares:

1. **Itens CALCULATED** — cruzam dados do template SNMP existente sem
   duplicar coleta. Ex: `change(//ips.blocked[fgIpsIntrusionsBlocked.0])`
   calcula a taxa de bloqueios IPS por minuto a partir do contador SNMP.

2. **Itens TRAPPER** — recebem eventos em tempo real via `syslog_receiver.php`
   quando o FortiGate envia logs de bloqueio/ataque por syslog UDP 514.

### Configuração de syslog no FortiSwitch (gerenciado)

```
# Via FortiGate > WiFi & Switch Controller > Managed FortiSwitches
# Edit switch > Logging > Enable remote logging

# Ou via CLI do FortiSwitch standalone:
config log syslogd setting
  set status enable
  set server IP_DO_APPLIANCE_ZABBIX
  set port 514
end
```

---

## Fase 11 — Finalização e scripts de manutenção

### Scripts adicionados

#### `scripts/setup_windows_audit.ps1`

Configura auditoria de segurança em Windows Server para detecção pelo agente
DDoS Guard. Habilita via GUID (funciona em PT-BR e EN-US):

- **Logon/Logoff** — Event ID 4625 (logon falhado) via GUID `{0CCE9215-...}`
- **Account Lockout** — bloqueio de conta
- **Credential Validation** — validação NTLM/Kerberos
- **WFP Packet Drop** — Event ID 5152 (Windows Filtering Platform)
- **WFP Connection** — Event ID 5157
- Canal `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`
- Canal `Microsoft-Windows-Windows Defender/Operational`
- Configura log de firewall em arquivo (`pfirewall.log`)
- Reinicia o agente DDoS Guard automaticamente

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\setup_windows_audit.ps1
```

#### `scripts/fix_clamav.sh`

Corrige banco de dados corrompido do ClamAV no appliance Rocky Linux:

- Para os serviços do ClamAV
- Remove arquivos corrompidos (`main.cld`, `daily.cld` etc.)
- Verifica espaço em disco (mínimo 500MB)
- Corrige permissões (`clamupdate:clamupdate`)
- Executa `freshclam` para baixar definições novas
- Corrige o `clamav_log` no `agent.conf` para `/var/log/clamav/clamd.log`
- Testa com arquivo EICAR e verifica detecção
- Reinicia o agente DDoS Guard

```bash
bash /root/zbx_ddos_guard/scripts/fix_clamav.sh
```

#### `sql/migration_v2_soc.sql` — versão corrigida

Reescrita para compatibilidade com **MySQL 5.7, 8.0 e MariaDB 10.x**.
O MySQL 5.7 não suporta `IF NOT EXISTS` no `ALTER TABLE` — a nova versão
usa uma PROCEDURE helper que verifica `information_schema.COLUMNS` antes
de adicionar cada coluna:

```sql
DROP PROCEDURE IF EXISTS ddosguard_add_column;
CREATE PROCEDURE ddosguard_add_column(IN tbl, IN col, IN col_def)
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS ...) THEN
        SET @sql = CONCAT('ALTER TABLE ', tbl, ' ADD COLUMN ', col, ' ', col_def);
        PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
    END IF;
END;
```

A procedure é removida automaticamente ao final da migration.

### Bugs corrigidos nesta fase

| Bug | Causa | Correção |
|---|---|---|
| `block_firewall` retornava HTTP 500 | `SELECT id FROM ddosguard_blocks` — PK é `block_id` | Corrigido para `SELECT block_id` e `WHERE block_id=:id` |
| `correlator.php` não atualizava `ddosguard_attacks` | `ORDER BY id DESC` — PK é `attack_id` | Corrigido para `ORDER BY attack_id DESC` |
| `Migration v2` falhava no MySQL 5.7 | `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` não suportado | Reescrito com PROCEDURE helper |
| `clamav_log` errado no `agent.conf` | Caminho `clamav.log` em vez de `clamd.log` | Corrigido no `fix_clamav.sh` |
| ClamAV `Can't allocate memory` | Banco de dados corrompido (`main.cld`) | `fix_clamav.sh` remove e atualiza |

### Estado final dos templates

| Template | Arquivo | Hosts | Status |
|---|---|---|---|
| `DDoS Guard - Security Monitoring` | `template_ddos_guard.yaml` | Appliance (servidor) | ✅ Produção |
| `DDoS Guard - Agent` | `template_ddos_guard_agent.yaml` | Linux monitorados | ✅ Produção |
| `DDoS Guard - Agent Windows Server` | `template_ddos_guard_agent_windows.yaml` | Windows Server | ✅ Produção |
| `DDoS Guard - FortiGate Security` | `template_ddos_guard_fortigate.yaml` | FortiGate | ✅ Pronto |
| `DDoS Guard - FortiSwitch Security` | `template_ddos_guard_fortigate.yaml` | FortiSwitch | ✅ Pronto |

---

## Fase 12 — Suporte Debian 12/13 e correções de campo (v2)

Implantação em produção num appliance **Debian 13 + Zabbix 7.4.11**
(Apache porta 6030, MariaDB) revelou 6 bugs e 3 falhas de segurança.

### Bugs corrigidos

| # | Sintoma | Causa raiz | Correção |
|---|---|---|---|
| 1.1 | `401 invalid token` com token correto | `/etc/zabbix/ddosguard/ingest.config.php` era `root:root 640` — `www-data` não conseguia ler | `chown root:www-data` + `chmod 640` + teste `sudo -u www-data cat` no instalador |
| 1.2 | Ingest ~20s / `timed out` no agente | `DG_ZBX_SERVER = 'IP:6030'` — `zabbix_sender` interpreta a string inteira como hostname | `DG_ZBX_SERVER = '127.0.0.1'`; setup.py e instalador detectam e corrigem automaticamente |
| 1.3 | `processed: 0; failed: 1` no zabbix_sender | Nome **visível** (`Zabbix Server`) ≠ nome **técnico** (`debian`) | Instalador avisa no prompt; diagnóstico com query SQL incluído |
| 1.4 | Frontend caiu após `ufw enable` | `ufw --force enable` antes das regras — sem liberar porta 6030 | Ordem corrigida: regras → enable; porta extraída da URL do ingest |
| 1.5 | `freshclam: Failed to lock the log file` | Daemon `clamav-freshclam` já segura o lock | Instalador usa `systemctl enable --now clamav-freshclam`; nunca chama `freshclam` manualmente |
| 1.6 | `AH00558` no error.log do Apache | ServerName não configurado | `ServerName $(hostname)` em `conf-available/servername.conf` |

### Falhas de segurança corrigidas

| # | Risco | Correção |
|---|---|---|
| 2.1 | `chmod -R 777 /etc/zabbix/*` aplicado como workaround do 401 | Modelo definitivo de permissões (ver tabela abaixo); `install_debian_prereqs.sh` restaura idempotentemente |
| 2.2 | Symlink `ingest.config.php` dentro do webroot | Removido; instalador e prereqs.sh removem qualquer cópia/symlink no docroot |
| 2.3 | `chmod 777` em logs | Padronizado `644`; nota sobre logrotate adicionada |

**Modelo definitivo de permissões:**

| Arquivo | Dono:Grupo | Modo |
|---|---|---|
| `/etc/zabbix/ddosguard/ingest.config.php` | `root:www-data` | `640` |
| `/etc/zabbix/ddos_guard_agent.conf` | `root:zabbix` | `640` |
| `/etc/zabbix/zabbix_server.conf` | `root:zabbix` | `640` |
| Logs (`kern.log`, `auth.log` etc.) | `root:adm` | `644` |

### Novas dependências Debian

| Pacote | Situação anterior | Agora |
|---|---|---|
| `rsyslog` | Não mencionado | Instalado e habilitado (sem ele não existem `kern.log`/`auth.log`) |
| `ufw` | Assumido presente | Instalado automaticamente |
| `clamav-daemon` | Sempre instalado | **Condicional a RAM ≥ 6GiB** (~1GiB residente) |
| `python3-geoip2` | Opcional/ignorado | `pip3 --break-system-packages`; sem a base, `ip-api.com` pode travar coleta |

### Arquivos criados/atualizados

- **`scripts/install_agent_linux.sh` v2** — reescrito com 10 etapas estruturadas,
  suporte a Debian/RHEL, sanidade do servidor, testes finais com diagnóstico
- **`scripts/install_debian_prereqs.sh`** — novo, idempotente, correção de appliances
  já implantados com `chmod 777` ou configurações incorretas
- **`scripts/setup.py`** — corrigido: valida `DG_ZBX_SERVER` e remove `:porta`
  automaticamente se presente na resposta
- **`docs/CHANGELOG.md`** — registro completo das mudanças da v2
- **`docs/INSTALL.md`** — seções 16-18 adicionadas (Debian, problemas frequentes, permissões)

---

## Fase 13 — Integração Sophos XG/XGS + Central + Intercept X

### Motivação

Sophos é amplamente usado em empresas médias brasileiras — especialmente
clínicas, contabilidades e pequenas empresas que adquiriram o Sophos Home
ou XG via revendedor. A integração permite ao DDoS Guard cobrir ambientes
Sophos com a mesma qualidade dos templates FortiGate e MikroTik.

### Arquivos criados

| Arquivo | Linhas | Descrição |
|---|---|---|
| `scripts/integrations/sophos_receiver.php` | 526 | Receiver com parsers SFOS e CEF |
| `templates/template_ddos_guard_sophos.yaml` | ~200 | Template Zabbix 9 itens / 8 triggers / 7 macros |

### Dois parsers

#### `parse_sfos()` — formato SFOS (Device Standard Format)

Formato padrão do Sophos XG/XGS. Campos separados por espaço
no formato `key=value` ou `key="value":

```
device="SFW" date=2026-07-15 time=10:30:00
log_type="IPS" log_subtype="Drop" status="Deny"
src_ip=185.220.101.50 dst_port=22 protocol="TCP"
message="Brute Force SSH attempt detected"
```

#### `parse_cef()` — Common Event Format (alternativo)

```
CEF:0|Sophos|XG|SFOS 20.0|030906209024|Firewall Deny|3|
src=185.220.101.50 dpt=22 proto=TCP dvchost=sophos-xg
```

O receiver detecta automaticamente qual formato usar.

### Classificação automática

O receiver classifica cada log em tipo de ataque + MITRE ATT&CK
baseado nos campos `log_type` e `log_subtype` do SFOS:

```
Firewall/Deny     → block_firewall      (score 3)
IPS/Detection     → IPS_DETECTION       (score 6) T1190
IPS/SYN Flood     → SYN_FLOOD          (score 8) T1498.001
IPS/SQL Inject    → SQL_INJECTION       (score 6) T1190
Anti-Virus        → MALWARE            (score 7) T1204
ATP               → C2_COMMUNICATION   (score 9) T1071  ← DISASTER
Web Filter        → WEB_ATTACK         (score 4) T1190
Anti-Spam         → SPAM               (score 2) T1566
Firewall/port 22  → BRUTE_FORCE_SSH    (score 5) T1110.001
Firewall/port 3389→ BRUTE_FORCE_RDP    (score 5) T1110
```

### Destaque: item dedicado para ATP

O Advanced Threat Protection (ATP) do Sophos detecta comunicação
com servidores C2 (command & control) e botnets. Por ser indicativo
de comprometimento ativo, recebe tratamento especial:

- Item dedicado `ddosguard.sophos.atp` separado dos demais
- Score 9/10 → `critical` — máxima prioridade no correlator
- Trigger **DISASTER** com instruções de resposta a incidente
- MITRE ATT&CK: T1071 (Command and Control)

### Sophos Central / Intercept X

O Sophos Central não envia syslog nativo — as opções documentadas são:

1. **Sophos Syslog Forwarder** no servidor Windows (mais simples)
2. **API REST** do Sophos Central + `syslog_forwarder.py`
3. **Sophos XG como proxy** de logs do Central

### Estado dos templates (6 no total)

| Template | Arquivo | Status |
|---|---|---|
| `DDoS Guard - Security Monitoring` | `template_ddos_guard.yaml` | ✅ Produção |
| `DDoS Guard - Agent` | `template_ddos_guard_agent.yaml` | ✅ Produção |
| `DDoS Guard - Agent Windows Server` | `template_ddos_guard_agent_windows.yaml` | ✅ Produção |
| `DDoS Guard - FortiGate Security` | `template_ddos_guard_fortigate.yaml` | ✅ Produção |
| `DDoS Guard - FortiSwitch Security` | `template_ddos_guard_fortigate.yaml` | ✅ Pronto |
| `DDoS Guard - MikroTik Security` | `template_ddos_guard_mikrotik.yaml` | ✅ Produção |
| **`DDoS Guard - Sophos Security`** | **`template_ddos_guard_sophos.yaml`** | **✅ Pronto** |

### Estado das integrações (7 no total)

| Receiver | Plataforma | Formatos |
|---|---|---|
| `syslog_receiver.php` | pfSense, FortiGate, genérico | syslog |
| `mikrotik_receiver.php` | MikroTik CCR/CRS | DG-DROP/DG-SCAN/DG-BRUTE |
| `sophos_receiver.php` | Sophos XG/XGS, Central, Intercept X | SFOS, CEF |
| `wazuh_receiver.php` | Wazuh HIDS/SIEM | JSON |
| `suricata_receiver.php` | Suricata IDS/IPS | eve.json |
| `syslog_forwarder.py` | Genérico (substitui omprog) | qualquer syslog |
| `install_integrations.sh` | Todas | — |
