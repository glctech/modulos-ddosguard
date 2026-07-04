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
