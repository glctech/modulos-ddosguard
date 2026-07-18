# DDoS Guard — Guia de Instalação

## Visão geral da arquitetura

```
[Host monitorado]                [Servidor Zabbix / Appliance]
ddos_guard_agent.py              ingest.php  (webroot do Zabbix)
  └── lê logs / Event Log   ──►  └── grava ddosguard_attacks / ddosguard_blocks
  └── envia via HTTP POST         └── repassa via zabbix_sender
                                  └── widgets do dashboard leem do banco
```

**Dois templates — use o correto:**

| Template | Arquivo | Onde associar |
|---|---|---|
| `DDoS Guard - Security Monitoring` | `template_ddos_guard.yaml` | Só no **appliance** |
| `DDoS Guard - Agent` | `template_ddos_guard_agent.yaml` | Em cada **host monitorado** |

---

## Pré-requisitos

### Servidor (appliance / Zabbix Server)
- Zabbix Server + Frontend **7.4.x**
- PHP com extensão `pdo_mysql` ou `pdo_pgsql`
- `zabbix_sender` instalado (`zabbix-sender` ou `zabbix-get`)
- Acesso de escrita ao banco de dados do Zabbix
- Python 3.6+ (para o `setup.py`)

### Hosts monitorados (Linux)
- Python 3.6+
- Acesso de leitura aos logs: `/var/log/messages` (Rocky/RHEL) ou
  `/var/log/kern.log` (Ubuntu/Debian), `/var/log/secure` ou
  `/var/log/auth.log`, `/var/log/ufw.log`, `/var/log/fail2ban.log`,
  `/var/log/clamav/clamd.log`
- Usuário que roda o agente precisa ter permissão de leitura nos logs:
  ```bash
  chmod 644 /var/log/messages /var/log/secure /var/log/ufw.log
  chmod 644 /var/log/fail2ban.log /var/log/clamav/clamd.log
  ```

### Hosts monitorados (Windows)
- Python **3.8 a 3.13** instalado **para todos os usuários**
  (Python 3.14 não tem suporte ao pywin32 ainda — não use para build do MSI)
- `wevtutil.exe` disponível no PATH (nativo em todo Windows Server)
- Sem dependências externas — o agente não precisa de `pip install`

---

## Parte 1 — Servidor (appliance)

### 1. Atalho — setup automático (recomendado)

```bash
# Como root na máquina que serve o frontend do Zabbix:
cd zbx_ddos_guard
python3 scripts/setup.py
```

O assistente detecta automaticamente:
- Servidor web (Nginx ou Apache) e lê o webroot real do `nginx.conf` /
  `httpd.conf` — evita copiar o `ingest.php` para o lugar errado
- Banco de dados e credenciais do `zabbix_server.conf`
- Caminhos do `zabbix_sender`

Opções úteis:
```bash
python3 scripts/setup.py --yes            # aceita todos os defaults
python3 scripts/setup.py --dry-run        # simula sem alterar nada
python3 scripts/setup.py --skip-db-test   # pula teste de conexão com banco
```

> **Atenção:** rode sempre a partir da pasta `zbx_ddos_guard/` (não de
> `externalscripts/` ou outro diretório) — o `setup.py` usa o diretório
> do script como raiz do pacote para localizar `ingest.php`, `schema.sql` etc.

### 2. Instalar o template no Zabbix

**Administration → Templates → Import** → selecione
`templates/template_ddos_guard.yaml`

Associe `DDoS Guard - Security Monitoring` **apenas no host do appliance**.

### 3. Criar as tabelas auxiliares

O `setup.py` faz isso automaticamente. Para fazer manualmente:

```bash
# MySQL / MariaDB
mysql -u zabbix -p zabbix < sql/schema.sql

# PostgreSQL
psql -U zabbix -d zabbix -f sql/schema.sql
```

> **Nota:** se o banco era criado com `SET NAMES utf8mb4`, o MariaDB 10.x
> pode precisar de `--default-character-set=utf8mb4` no comando `mysql`.

### 4. Publicar o `ingest.php`

O `setup.py` detecta o webroot correto lendo a diretiva `root` do `nginx.conf`.
No appliance oficial do Zabbix, o webroot é tipicamente `/usr/share/zabbix/ui`.

Para copiar manualmente:
```bash
# Confirme o webroot real:
grep -r "root " /etc/nginx/conf.d/*.conf 2>/dev/null

# Copie:
mkdir -p /usr/share/zabbix/ui/ddosguard
cp scripts/ingest.php /usr/share/zabbix/ui/ddosguard/
chmod 644 /usr/share/zabbix/ui/ddosguard/ingest.php
```

> **Problema comum:** se o `ingest.php` retornar `{"ok":false,"error":"invalid token"}`,
> verifique se não há **múltiplas cópias** do arquivo em caminhos diferentes
> (o `setup.py` escaneia e oferece limpar automaticamente). O arquivo correto
> tem **13.350 bytes**.

### 5. Configurar o `ingest.config.php`

O `setup.py` gera automaticamente em `/etc/zabbix/ddosguard/ingest.config.php`.
Para criar manualmente:

```php
<?php
return [
    'DG_INGEST_TOKEN'       => 'seu_token_aqui',
    'DG_DB_HOST'            => '127.0.0.1',
    'DG_DB_PORT'            => '3306',
    'DG_DB_NAME'            => 'zabbix',
    'DG_DB_USER'            => 'zabbix',
    'DG_DB_PASS'            => 'senha',
    'DG_DB_DRIVER'          => 'mysql',
    'DG_ZABBIX_SENDER_BIN'  => '/usr/bin/zabbix_sender',
    'DG_ZBX_SERVER'         => '127.0.0.1',
    'DG_ZBX_PORT'           => '10051',
];
```

> **BOM UTF-8:** se o arquivo for gravado com BOM (comum em editores Windows
> e em `Set-Content -Encoding UTF8` do PowerShell 5.x), o PHP vai falhar ao
> fazer `include`. Use sempre UTF-8 sem BOM.

### 6. Testar o endpoint

```bash
curl -s -X POST http://SEU_IP/ddosguard/ingest.php \
  -H "Content-Type: application/json" \
  -H "X-DG-Token: SEU_TOKEN" \
  -d '{"event_type":"heartbeat","zbx_host":"appliance"}'
# Deve retornar: {"ok":true}
```

### 7. Instalar os módulos de frontend (widgets)

Copie as pastas para o diretório de módulos do Zabbix:

```bash
cp -r modules/DDoSAttackMonitor /usr/share/zabbix/ui/modules/
cp -r modules/DDoSBlockMonitor  /usr/share/zabbix/ui/modules/
```

No Zabbix: **Administration → General → Modules** → clique em **Scan directory**
→ habilite `DDoSAttackMonitor` e `DDoSBlockMonitor`.

### 8. Montar o dashboard geral

```bash
python3 scripts/provision_dashboard.py \
  --url http://SEU_IP/zabbix \
  --user Admin --password sua_senha
```

---

## Parte 2 — Agente nos hosts monitorados

### Instalar o template do agente

**Administration → Templates → Import** → selecione
`templates/template_ddos_guard_agent.yaml`

Associe `DDoS Guard - Agent` em cada host que tem o agente instalado.

### Linux — instalador interativo

```bash
sudo bash scripts/install_agent_linux.sh
```

O instalador:
- Detecta automaticamente os logs disponíveis no sistema
- Pergunta URL do `ingest.php`, token, nome do host e hostid
- Cria o usuário `zabbix` de sistema se não existir
- Grava `/etc/zabbix/ddos_guard_agent.conf` (sem BOM)
- Instala o agente em `/opt/zabbix/ddosguard/`
- Registra e inicia o serviço systemd `ddos-guard-agent`

Instalação silenciosa (scripts de provisionamento):
```bash
sudo bash scripts/install_agent_linux.sh --yes \
  --ingest-url "http://192.168.0.52/ddosguard/ingest.php" \
  --token "SEU_TOKEN" \
  --zbx-host "meu-servidor" \
  --hostid 10085
```

#### Configurações necessárias no Rocky Linux / RHEL

```bash
# 1. Adiciona regra de LOG antes do DROP para que o iptables registre bloqueios
iptables -I INPUT 10 -j LOG --log-prefix "IPTABLES_DROP: " --log-level 4

# 2. Instala o fail2ban (requer EPEL)
dnf install -y epel-release && dnf install -y fail2ban

# 3. Configura o fail2ban para SSH
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
banaction = iptables-multiport

[sshd]
enabled  = true
port     = ssh
logpath  = /var/log/secure
EOF

systemctl enable --now fail2ban

# 4. Instala o ClamAV
dnf install -y clamav clamav-update clamd
freshclam
systemctl enable --now clamd@scan

# 5. Permissões dos logs
chmod 644 /var/log/messages /var/log/secure /var/log/fail2ban.log
chmod 644 /var/log/clamav/clamd.log

# 6. Atualiza agent.conf com os caminhos corretos
cat /etc/zabbix/ddos_guard_agent.conf
# Edite conforme necessário:
# iptables_log = /var/log/messages
# fail2ban_log = /var/log/fail2ban.log
# clamav_log   = /var/log/clamav/clamd.log
# auth_log     = /var/log/secure
```

#### Configurações necessárias no Ubuntu / Debian

```bash
# 1. Habilita o UFW com política deny
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow from 192.168.0.0/24   # ajuste para sua rede
ufw logging medium

# 2. Instala fail2ban e ClamAV
apt-get install -y fail2ban clamav clamav-daemon

# 3. Atualiza as definições de vírus
freshclam

# 4. Permissões
chmod 644 /var/log/ufw.log /var/log/auth.log
touch /var/log/fail2ban.log && chmod 644 /var/log/fail2ban.log

# 5. agent.conf Ubuntu
# iptables_log = /var/log/kern.log
# ufw_log      = /var/log/ufw.log
# fail2ban_log = /var/log/fail2ban.log
# clamav_log   = /var/log/clamav/clamd.log
# auth_log     = /var/log/auth.log
```

### Windows — instalador interativo

Abra o PowerShell **como Administrador**:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\install_agent_windows.ps1
```

O instalador:
- Detecta o Python no PATH (ignora o stub da Microsoft Store em `WindowsApps\`)
- Verifica compatibilidade do Python (avisa se for 3.14+)
- Detecta e usa `wevtutil.exe` nativo — **sem necessidade de `pip install`**
- Pergunta URL, token, hostname e hostid
- Resolve o `python.exe` real para o Task Scheduler (que roda como SYSTEM
  e não acessa `AppData` do usuário)
- Registra a tarefa `DDoSGuardAgent` no Task Scheduler com:
  - Início automático no boot
  - Restart automático em falha (a cada 1 minuto, 999 tentativas)
  - Log em `C:\ProgramData\DDoSGuard\agent.log`

Instalação silenciosa (GPO / SCCM):
```powershell
.\install_agent_windows.ps1 -Yes `
  -IngestUrl "http://192.168.0.52/ddosguard/ingest.php" `
  -Token "SEU_TOKEN" `
  -ZbxHost "WIN-SERVER01" `
  -HostId 10085
```

#### Problemas conhecidos no Windows

| Problema | Causa | Solução |
|---|---|---|
| `No installed Python found` | Task Scheduler roda como SYSTEM sem acesso a `AppData` | Reinstale o Python marcando **"Install for all users"** |
| `MissingSectionHeaderError: ï»¿[general]` | `agent.conf` gravado com BOM UTF-8 | Use `[System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding $false))` |
| `subprocess is not defined` | Versão antiga do agente sem `import subprocess` | Atualize o `ddos_guard_agent.py` |
| `pywin32` não instala | Python 3.14 não tem wheel do pywin32 no PyPI | Use Python 3.13 para build do MSI (o agente em si não precisa de pywin32) |

---

## Parte 3 — Template do agente (`DDoS Guard - Agent`)

O template `template_ddos_guard_agent.yaml` contém **apenas os 8 itens trapper**
que o agente envia, mais **6 triggers** de alerta por host — sem dashboard.

### Triggers incluídas

| Trigger | Prioridade | Condição |
|---|---|---|
| Agente parou de enviar dados | Warning | Sem heartbeat por 15min |
| Pico de ataques (≥ 50/min) | High | `attacks.rate ≥ 50` por 2min |
| Possível DDoS (≥ 200/min) | Disaster | `attacks.rate ≥ 200` por 5min |
| Ataque distribuído (≥ 50 IPs) | Disaster | `distinct_ips ≥ 50` por 5min |
| Volume alto de bloqueios (≥ 500/min) | High | `firewall.rate ≥ 500` por 10min |
| Múltiplas detecções de malware (≥ 5/min) | High | `antivirus.rate ≥ 5` por 10min |

---

## Gerenciar o agente

### Linux

```bash
systemctl status ddos-guard-agent
systemctl restart ddos-guard-agent
journalctl -u ddos-guard-agent -f
```

### Windows

```powershell
# Task Scheduler
Get-ScheduledTask -TaskName DDoSGuardAgent
Start-ScheduledTask  -TaskName DDoSGuardAgent
Stop-ScheduledTask   -TaskName DDoSGuardAgent

# Ver log em tempo real
Get-Content "C:\ProgramData\DDoSGuard\agent.log" -Wait -Tail 20
```

---

## Problemas frequentes

### `failed: 1` no zabbix_sender

```bash
# Verifica as chaves existentes no banco
mysql -u zabbix -p zabbix -e "SELECT key_ FROM items WHERE key_ LIKE 'ddosguard%';"

# Testa manualmente
/usr/bin/zabbix_sender -z 127.0.0.1 -p 10051 \
  -s "nome-do-host" -k "ddosguard.agent.heartbeat" -o 1 -v
```

O host precisa existir no Zabbix com o nome **exatamente igual** ao `zbx_host`
do `agent.conf`, e o template `DDoS Guard - Agent` precisa estar associado a ele.

### IPs privados aparecendo como atacantes

O agente filtra automaticamente RFC1918, loopback, broadcast e multicast.
Se ainda aparecerem, limpe o banco:
```sql
DELETE FROM ddosguard_attacks
WHERE src_ip LIKE '192.168.%'
   OR src_ip LIKE '10.%'
   OR src_ip IN ('0.0.0.0', '255.255.255.255');
```

### Muitos eventos duplicados no banco

O `ingest.php` deduplica bloqueios de firewall do mesmo IP nos últimos 60s.
Para deduplicar eventos de ataque também, aplique o índice:
```sql
ALTER TABLE ddosguard_attacks
  ADD INDEX idx_dedup (hostid, src_ip, attack_type, last_seen);
```

### GeoIP retornando NULL

```bash
# Verifica se o arquivo .mmdb existe
ls -lh /usr/share/GeoIP/GeoLite2-City.mmdb

# Testa o resolver
python3 -c "
import sys; sys.path.insert(0, '/opt/zabbix/ddosguard')
import ddos_guard_agent as dga
geo = dga.GeoResolver('/usr/share/GeoIP/GeoLite2-City.mmdb')
print(geo.resolve('8.8.8.8'))
"
```

Sem o `.mmdb`, o agente usa a API pública `ip-api.com` (limite de 45 req/min).
Baixe a base gratuita em https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
e instale em `/usr/share/GeoIP/GeoLite2-City.mmdb`.

### UFW não gerando `[UFW BLOCK]`

O UFW só bloqueia tráfego que não é permitido por nenhuma regra. Verifique:
```bash
ufw status numbered
# Se tiver "ALLOW IN 192.168.0.0/24" essa rede nunca gera BLOCK
# Remova a regra permissiva ampla e adicione só o necessário:
ufw delete allow from 192.168.0.0/24
ufw allow from 192.168.0.52 to any  # permite só o appliance
```

---

## Como funciona o fluxo completo

1. O `ddos_guard_agent.py` lê os arquivos de log (Linux) ou o Event Log
   (Windows) a cada `poll_interval` segundos (padrão: 10s).

2. Linhas com IPs externos (não-RFC1918) são classificadas por tipo de ataque
   e agregadas por janela de `aggregate_window` segundos (padrão: 60s).

3. A cada ciclo, o agente envia via HTTP POST para o `ingest.php`:
   - `heartbeat` — indicador de saúde do agente
   - `attack` — evento de ataque agregado (IP, tentativas, tipo, geoloc.)
   - `block_firewall` — bloqueio de firewall detectado
   - `block_antivirus` — detecção de antivírus

4. O `ingest.php`:
   - Valida o token (`X-DG-Token`)
   - Grava nas tabelas `ddosguard_attacks` / `ddosguard_blocks`
   - Envia os contadores ao Zabbix via `zabbix_sender` (itens trapper)
   - Envia os eventos JSON raw via `zabbix_sender` (para os triggers)

5. Os widgets `DDoSAttackMonitor` e `DDoSBlockMonitor` consultam diretamente
   as tabelas auxiliares via PDO — atualizando sem precisar de novas coletas.

6. O Zabbix Server avalia os itens trapper e dispara triggers quando os
   thresholds são atingidos (pico de ataques, DDoS distribuído etc.).

---

## 12. Templates FortiGate e FortiSwitch

### Importar

**Administration → Templates → Import** →
selecione `templates/template_ddos_guard_fortigate.yaml`

Dois templates serão importados:
- `DDoS Guard - FortiGate Security`
- `DDoS Guard - FortiSwitch Security`

### FortiGate — configuração mínima

**No Zabbix:** associe **ambos** os templates no host FortiGate:
- `FortiGate by SNMP` (template oficial — coleta SNMP)
- `DDoS Guard - FortiGate Security` (triggers de segurança + syslog)

**No FortiGate:**
```
config log syslogd setting
  set status enable
  set server IP_DO_APPLIANCE_ZABBIX
  set port 514
  set format default
  set facility local7
end

config log syslogd filter
  set severity warning
  set forward-traffic enable
end
```

**No appliance Zabbix** (habilita receiver syslog):
```bash
bash scripts/integrations/install_integrations.sh --syslog
```

### FortiSwitch — configuração

**Gerenciado pelo FortiGate:**
FortiGate → WiFi & Switch Controller → Managed FortiSwitches →
Edit switch → Logging → Enable remote logging → IP do appliance

**Standalone:**
```
config log syslogd setting
  set status enable
  set server IP_DO_APPLIANCE_ZABBIX
  set port 514
end
```

### Macros configuráveis por dispositivo

No Zabbix, em cada host FortiGate, ajuste as macros:

| Macro | Padrão | Descrição |
|---|---|---|
| `{$FG.IPS.BLOCK.WARN}` | 100 | Bloqueios IPS/min → WARNING |
| `{$FG.IPS.BLOCK.HIGH}` | 1000 | Bloqueios IPS/min → HIGH |
| `{$FG.SESSION.WARN}` | 50000 | Sessões ativas → WARNING |
| `{$FG.SESSION.HIGH}` | 100000 | Sessões ativas → HIGH |
| `{$FG.VPN.LOSS.WARN}` | 20 | % perda de pacotes VPN → WARNING |
| `{$FSW.PORT.VIOLATIONS.WARN}` | 10 | Violações port security → HIGH |
| `{$FSW.MAC.SPOOF.WARN}` | 5 | Eventos MAC spoofing → HIGH |
| `{$FSW.DOT1X.FAIL.WARN}` | 20 | Falhas 802.1X → WARNING |

---

## 13. Configuração de auditoria Windows Server

Execute no DNS-SERVER (ou em qualquer Windows Server monitorado):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\setup_windows_audit.ps1
```

O script usa GUIDs universais para habilitar auditoria — funciona em
qualquer idioma do Windows (PT-BR, EN-US, ES, etc.).

O que é habilitado:
- Logon/Logoff failures → Event ID 4625 (brute-force RDP/SMB)
- Account Lockout → Event ID 4740
- Credential Validation → NTLM/Kerberos failures
- WFP Packet Drop → Event ID 5152 (Windows Firewall)
- WFP Connection → Event ID 5157
- Canal Windows Firewall Advanced Security
- Canal Windows Defender Operational
- Log de firewall em `%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log`

---

## 14. Correção do ClamAV (Rocky Linux / RHEL)

Se o ClamAV apresentar erro `Can't allocate memory` ou `Malformed database`:

```bash
bash scripts/fix_clamav.sh
```

O script:
1. Para os serviços do ClamAV
2. Remove arquivos de banco corrompidos
3. Executa `freshclam` para baixar definições novas
4. Corrige o caminho do log no `agent.conf`
   (`clamav_log = /var/log/clamav/clamd.log`)
5. Testa com arquivo EICAR e confirma detecção
6. Reinicia o agente DDoS Guard

---

## 15. Migration v2 — MySQL 5.7 compatível

A migration `sql/migration_v2_soc.sql` usa uma PROCEDURE helper para
adicionar colunas de forma idempotente (pode ser executada múltiplas
vezes sem erro):

```bash
mysql -u zabbix_srv -p zabbix < sql/migration_v2_soc.sql
```

Se preferir executar manualmente (MySQL sem permissão de CREATE PROCEDURE):

```sql
-- ddosguard_attacks
ALTER TABLE ddosguard_attacks
  ADD COLUMN severity_label   VARCHAR(16)  NULL,
  ADD COLUMN severity_score   TINYINT      NULL DEFAULT 0,
  ADD COLUMN correlated       TINYINT(1)   NOT NULL DEFAULT 0,
  ADD COLUMN correlation_id   VARCHAR(64)  NULL,
  ADD COLUMN mitre_tactic     VARCHAR(64)  NULL,
  ADD COLUMN mitre_technique  VARCHAR(16)  NULL,
  ADD COLUMN threat_intel     TINYINT(1)   NOT NULL DEFAULT 0,
  ADD COLUMN threat_intel_src VARCHAR(64)  NULL,
  ADD COLUMN updated_at       DATETIME     NULL;

-- ddosguard_blocks
ALTER TABLE ddosguard_blocks
  ADD COLUMN severity_score   TINYINT      NULL DEFAULT 0,
  ADD COLUMN correlated       TINYINT(1)   NOT NULL DEFAULT 0,
  ADD COLUMN correlation_id   VARCHAR(64)  NULL,
  ADD COLUMN source_platform  VARCHAR(32)  NULL,
  ADD COLUMN mitre_technique  VARCHAR(16)  NULL,
  ADD COLUMN updated_at       DATETIME     NULL;
```

---

## 16. Suporte a Debian 12/13

O Debian minimal difere do Rocky Linux em vários pontos que quebravam a instalação.
Execute o script de prereqs antes do instalador:

```bash
sudo bash scripts/install_debian_prereqs.sh [--web-port 6030] [--mgmt-net 192.168.0.0/24]
```

### Diferenças críticas

| Dependência | Debian | Rocky Linux |
|---|---|---|
| `rsyslog` | **Precisa instalar** (Debian 12+ usa só journald; sem rsyslog não há `auth.log`/`kern.log`) | Já presente |
| `ufw` | **Precisa instalar** | N/A (usa firewalld) |
| `fail2ban` | `apt install fail2ban` | `dnf install epel-release && dnf install fail2ban` |
| `clamav-daemon` | **Condicional a RAM ≥ 6GiB** (~1GiB residente) | `clamd@scan` |
| Log do ClamAV | `/var/log/clamav/clamav.log` **ou** `clamd.log` | `/var/log/clamav/clamd.log` |
| GeoIP2 | `pip3 install geoip2 --break-system-packages` | `pip3 install geoip2` |

### Ordem correta do UFW (crítico!)

**ERRADO** — causa `ERR_CONNECTION_TIMED_OUT` no frontend:
```bash
ufw --force enable          # ← habilita deny incoming SEM liberar as portas
ufw allow ssh               # ← tarde demais, acesso SSH perdido
```

**CORRETO** — regras antes do enable:
```bash
ufw allow ssh
ufw allow 80/tcp            # ajuste para a porta real do frontend (ex: 6030)
ufw allow 10050/tcp         # Zabbix Agent
ufw allow 10051/tcp         # Zabbix Trapper
ufw default deny incoming
ufw default allow outgoing
ufw --force enable          # ← ativa com todas as portas ja liberadas
```

> **Atenção:** `ufw allow from 192.168.0.0/24` suprime eventos `[UFW BLOCK]`
> para toda a rede. Use regras específicas por porta para redes de gerenciamento
> se precisar detectar bloqueios internos.

---

## 17. Problemas frequentes — novos casos

### `401 invalid token` com token correto nos dois lados

Causa mais provável: **permissão do arquivo de configuração**.

```bash
# O www-data (PHP) precisa ler o config
ls -la /etc/zabbix/ddosguard/ingest.config.php
# Deve ser: -rw-r----- root:www-data

# Correção
chown root:www-data /etc/zabbix/ddosguard/ingest.config.php
chmod 640 /etc/zabbix/ddosguard/ingest.config.php
chmod 755 /etc/zabbix/ddosguard/

# Testa se o www-data consegue ler
sudo -u www-data cat /etc/zabbix/ddosguard/ingest.config.php | grep TOKEN
```

Outras causas em ordem de probabilidade:

1. **Symlink do config no webroot** — o `ingest.php` falha em silêncio ao tentar
   ler `/usr/share/zabbix/ui/ddosguard/ingest.config.php` que é um symlink quebrado:
   ```bash
   ls -la /usr/share/zabbix/ui/ddosguard/ingest.config.php
   # Se existir, remova: rm -f /usr/share/zabbix/ui/ddosguard/ingest.config.php
   ```

2. **Token diferente nos dois lados:**
   ```bash
   diff <(grep TOKEN /etc/zabbix/ddosguard/ingest.config.php) \
        <(grep token /etc/zabbix/ddos_guard_agent.conf)
   ```

3. **Erro PHP no include** — verifique:
   ```bash
   tail -20 /var/log/nginx/error.log
   tail -20 /var/log/apache2/error.log
   ```

### Ingest respondendo ~20s / `Erro no ciclo de coleta: timed out`

Causa: `DG_ZBX_SERVER` contém `IP:porta` (ex: `45.70.216.68:6030`).
O `zabbix_sender` interpreta a string inteira como hostname e trava 20s.

```bash
grep DG_ZBX_SERVER /etc/zabbix/ddosguard/ingest.config.php
# Errado:  'DG_ZBX_SERVER' => '45.70.216.68:6030'
# Correto: 'DG_ZBX_SERVER' => '127.0.0.1'

# Correção manual
sed -i "s/'DG_ZBX_SERVER' => '[^']*:[0-9]*'/'DG_ZBX_SERVER' => '127.0.0.1'/" \
    /etc/zabbix/ddosguard/ingest.config.php
```

### `freshclam` retorna `Failed to lock the log file`

Comportamento normal — o daemon `clamav-freshclam` já está atualizando e segura o lock.
**Não rode `freshclam` manualmente** enquanto o daemon estiver ativo:

```bash
systemctl status clamav-freshclam   # verifica se daemon esta ativo
journalctl -u clamav-freshclam -n 5 # confirma que esta atualizando normalmente
```

---

## 18. Modelo de permissões correto

**Nunca use `chmod 777` em arquivos do DDoS Guard** — logs com escrita aberta
permitem apagar ou forjar evidências de ataque.

| Arquivo | Dono:Grupo | Modo | Por quê |
|---|---|---|---|
| `/etc/zabbix/ddosguard/ingest.config.php` | `root:www-data` | `640` | PHP precisa ler; outros não |
| `/etc/zabbix/ddos_guard_agent.conf` | `root:zabbix` | `640` | Contém o token |
| `/etc/zabbix/zabbix_server.conf` | `root:zabbix` | `640` | Contém senha do banco |
| `/etc/zabbix/zabbix.conf.php` | `root:www-data` | `640` | Contém senha do banco |
| `ingest.php` no webroot | `root:root` | `644` | Só leitura pelo web server |
| Logs (`kern.log`, `auth.log` etc.) | `root:adm` | `644` | Agente roda como root |

Para restaurar o modelo correto em appliances com `chmod 777` já aplicado:
```bash
sudo bash scripts/install_debian_prereqs.sh
```

---

## 19. Integração Sophos XG/XGS + Central + Intercept X

### Importar o template

**Administration → Templates → Import** →
selecione `templates/template_ddos_guard_sophos.yaml`

Template importado: `DDoS Guard - Sophos Security`

Associe ao host correspondente no Zabbix (mesmo host do SNMP Sophos,
se houver, ou crie um host dedicado para o firewall Sophos).

---

### Configuração no Sophos XG/XGS

#### Via interface web (SFOS)

```
System
  └── Administration
        └── Notification Settings
              └── Log Settings
                    └── Syslog Server → Add

  Name:     DDoS Guard
  IP:       IP_DO_APPLIANCE_ZABBIX
  Port:     514
  Facility: LOCAL0
  Format:   Device Standard Format (SFOS)
  Severity: Information

Log Types habilitados:
  ✅ Firewall           (bloqueios de regra)
  ✅ IPS                (intrusões detectadas)
  ✅ Anti-Virus         (malware no tráfego)
  ✅ ATP                (Advanced Threat Protection — C2/botnet)
  ✅ Web Filter         (URLs maliciosas)
  ✅ Anti-Spam          (e-mail malicioso)
  ✅ System Health      (alertas do sistema)
```

#### Via CLI (SFOS)

```bash
# Adiciona o servidor syslog
system syslog add name "DDoSGuard" ipaddress IP_ZABBIX port 514

# Habilita todos os componentes de log
system syslog update name "DDoSGuard" logcomponent all

# Ativa o envio
system syslog enable

# Verifica
system syslog show
```

#### Formato CEF (alternativo)

Se preferir o formato CEF (Common Event Format):
```
Format: Common Event Format (CEF)
```
O `sophos_receiver.php` detecta automaticamente o formato e usa o parser correto.

---

### Configuração no appliance Zabbix

O syslog já deve estar configurado pelo `install_integrations.sh`.
Verifique se o receiver Sophos está no lugar:

```bash
# Copia o receiver para o webroot
cp scripts/integrations/sophos_receiver.php \
   /usr/share/zabbix/ui/ddosguard/integrations/

# Confirma que o rsyslog está ouvindo na porta 514
ss -ulnp | grep 514

# Verifica se os logs chegam
tail -f /var/log/ddosguard-syslog.log

# Testa o receiver diretamente com uma linha SFOS simulada
echo '<13>Jul 15 10:30:00 sophos-xg device="SFW" log_type="Firewall" log_subtype="Denied" status="Deny" src_ip=185.220.101.50 dst_port=22 protocol="TCP"' \
  >> /var/log/ddosguard-syslog.log
```

---

### Sophos Central / Intercept X

O Sophos Central **não envia syslog nativo**. Use uma das opções:

#### Opção 1 — Sophos Syslog Forwarder (recomendado)

Instale o Sophos Syslog Forwarder em um servidor Windows
gerenciado pelo Sophos Central:

```
Sophos Central → Endpoint Protection → Policies
→ Threat Protection → Syslog settings
  Server: IP_DO_APPLIANCE_ZABBIX
  Port:   514
  Format: CEF
```

#### Opção 2 — API REST do Sophos Central

Use a API para buscar eventos e encaminhar via syslog_forwarder.py.
Requer Client ID e Client Secret do Sophos Central:

```bash
# Configura as credenciais
cat >> /etc/zabbix/ddos_guard_agent.conf << 'EOF'

[sophos_central]
client_id     = SEU_CLIENT_ID
client_secret = SEU_CLIENT_SECRET
tenant_id     = SEU_TENANT_ID
EOF
```

---

### Macros configuráveis por host Sophos

No Zabbix, em cada host Sophos, ajuste conforme o ambiente:

| Macro | Padrão | Descrição |
|---|---|---|
| `{$SOPHOS.FW.BLOCK.WARN}` | 100 | Bloqueios firewall/min → WARNING |
| `{$SOPHOS.FW.BLOCK.HIGH}` | 1000 | Bloqueios firewall/min → HIGH |
| `{$SOPHOS.IPS.WARN}` | 50 | Detecções IPS/min → WARNING |
| `{$SOPHOS.IPS.HIGH}` | 500 | Detecções IPS/min → HIGH |
| `{$SOPHOS.AV.WARN}` | 5 | Detecções AV em 10min → HIGH |
| `{$SOPHOS.ATP.THRESHOLD}` | 1 | Qualquer ATP → DISASTER |
| `{$SOPHOS.HEARTBEAT.TIMEOUT}` | 30m | Sem syslog → WARNING |

---

### Verificação pós-configuração

```bash
# 1. Confirma que os logs chegam
tail -f /var/log/ddosguard-syslog.log | grep -i sophos

# 2. Testa o receiver via curl
curl -s http://localhost/zabbix/ddosguard/integrations/sophos_receiver.php \
  -H "Content-Type: application/json" \
  -H "X-DG-Token: SEU_TOKEN" \
  -d 'device="SFW" log_type="IPS" log_subtype="Drop" src_ip=185.220.101.50 dst_port=80 protocol="TCP"'

# 3. Verifica no banco
mysql -u zabbix_srv -p zabbix -e "
SELECT platform, src_ip, category, severity_label, created_at
FROM ddosguard_integration_events
WHERE platform='sophos'
ORDER BY id DESC LIMIT 5;"

# 4. Verifica no Zabbix
# Latest data → host Sophos → filtrar por "ddos"
# Os itens ddosguard.firewall.rate e ddosguard.attacks.rate
# devem começar a receber dados
```

---

### Diagrama do fluxo

```
Sophos XG/XGS
  │
  │ syslog UDP 514 (SFOS ou CEF)
  ▼
rsyslog (appliance Zabbix)
  │
  │ grava em /var/log/ddosguard-syslog.log
  ▼
syslog_forwarder.py
  │
  │ POST http://localhost/zabbix/ddosguard/integrations/sophos_receiver.php
  ▼
sophos_receiver.php
  │
  ├── parse_sfos() ou parse_cef()
  ├── classifica: Firewall/IPS/AV/ATP/WebFilter
  ├── grava em ddosguard_integration_events
  ├── grava em ddosguard_blocks ou ddosguard_attacks
  ├── correlator.php → score MITRE ATT&CK
  └── zabbix_sender → itens do template Sophos
        │
        ▼
      Zabbix Server
        │
        ▼
      Dashboard DDoS Guard SOC
```
