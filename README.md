# DDoS Guard — Detecção de DDoS, Firewall & Antivírus para Zabbix 7.4

Módulo completo (template + agente coletor multiplataforma + API + dashboard)
para detectar, em tempo real, ataques DDoS / força bruta / malware.

## O que detecta

**Linux** (via leitura de logs):
- `iptables` / `nftables` — bloqueios com prefixo `IPTABLES_DROP:` no `/var/log/messages`
- `UFW` — bloqueios `[UFW BLOCK]` no `/var/log/ufw.log`
- `fail2ban` — bans e eventos "Found" em `/var/log/fail2ban.log`
- `ClamAV` — detecções `FOUND` no `/var/log/clamav/clamd.log`
- SSH brute-force — "Failed password" no `/var/log/auth.log` ou `/var/log/secure`

**Windows** (via Event Log nativo — sem pywin32, usa `wevtutil.exe`):
- Event ID 4625 — logon falhado (RDP / SMB brute-force)
- Event ID 5152/5157 — Windows Filtering Platform (bloqueios do Windows Firewall)
- Event ID 1116/1117 — Windows Defender (detecção e ação sobre malware)

**Firewalls via syslog** (receiver `integrations/syslog_receiver.php`):
- **MikroTik RouterOS 6.x / 7.x** — port scan, brute force (SSH/Telnet/Winbox),
  flood UDP/ICMP, classificados pelo `log-prefix` da regra que capturou o pacote
- **pfSense** — eventos `filterlog:`
- **FortiGate** — formato chave=valor com `devname=` / `logid=`
- **iptables / nftables** — formato genérico com `SRC=` / `DPT=`

**Em ambos:**
- Geolocalização por GeoIP2 local (MaxMind) com fallback para ip-api.com
- Filtro automático de IPs privados/inválidos (RFC1918, loopback, broadcast)

## O que mostra

- **Painel "Attack Monitor"**: IP de origem, país, tipo de ataque,
  porta/protocolo, tentativas, severidade, se foi bloqueado, firewall e antivírus ativos.
- **Painel "Block Monitor"**: bloqueios Firewall x Antivírus com totais,
  IPs distintos, países de origem e tabela detalhada por bloqueio.
- **Dashboard "DDoS Guard - Security Operations Center"**: cinco painéis
  próprios + Problemas nativo, em duas páginas, criado por
  `scripts/provision_dashboard.py`:

```bash
# Todos os widgets (2 páginas)
python3 scripts/provision_dashboard.py --url https://zabbix.local --token TOKEN

# Só o que uma instalação MikroTik-via-syslog realmente alimenta
python3 scripts/provision_dashboard.py --url ... --token ... --preset mikrotik

# Ver o layout antes de criar
python3 scripts/provision_dashboard.py --url ... --token ... --dry-run
```

Os widgets leem tabelas diferentes, então nenhum é redundante — mas três
deles (`attackmonitor`, `timeline`, `mitre`) dependem de
`ddosguard_attacks`, que o `syslog_receiver.php` não popula no caminho
MikroTik. O script avisa quando você seleciona um widget nessa situação.

## Dois templates — use o correto em cada host

| Template | Arquivo | Onde associar |
|---|---|---|
| `DDoS Guard - Security Monitoring` | `template_ddos_guard.yaml` | Só no **appliance/Zabbix Server** (tem dashboard) |
| `DDoS Guard - Agent` | `template_ddos_guard_agent.yaml` | Em **cada host monitorado** (Linux ou Windows) |

## Início rápido

```bash
# Na máquina que serve o frontend do Zabbix (como root):
cd zbx_ddos_guard
python3 scripts/setup.py
```

O assistente detecta o ambiente (Rocky Linux / Ubuntu, Nginx / Apache,
MySQL / PostgreSQL) e configura automaticamente o `ingest.php`, as tabelas
auxiliares e o agente coletor neste host.

## Instalar o agente em outros hosts

**Linux:**
```bash
sudo bash scripts/install_agent_linux.sh
```

**Windows (PowerShell como Administrador):**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\install_agent_windows.ps1
```

Veja o guia completo em **[`docs/INSTALL.md`](docs/INSTALL.md)**.

## Integração MikroTik (RouterOS 6.x / 7.x)

O RouterOS envia os eventos de firewall por syslog; o coletor classifica
cada evento pelo `log-prefix` da regra que capturou o pacote.

```bash
# 1. No coletor — receiver + rsyslog + logrotate
bash scripts/integrations/install_integrations.sh --syslog

# 2. Informe qual host do Zabbix representa o roteador
mysql -N -e "SELECT hostid, host FROM hosts \
  WHERE name LIKE '%CCR%' AND status IN (0,1);" <BANCO>

# ...e acrescente ao /etc/zabbix/ddosguard/ingest.config.php:
#   'DG_MIKROTIK_ZBX_HOST'   => 'MIKROTIK CCR 1009',
#   'DG_MIKROTIK_ZBX_HOSTID' => 10780,

# 3. No roteador — ajuste as variáveis do topo e importe
#    /import file-name=ddosguard-ccr.rsc
```

O nome precisa ser o **técnico** (`hosts.host`), idêntico byte a byte: o
`zabbix_sender` compara exato e rejeita em silêncio.

**Configure o heartbeat antes das regras de detecção.** Ele é um sinal a
cada minuto, independente de haver ataque, e é o que diferencia "nenhum
evento" de "pipeline morto":

```
nodata(/MIKROTIK CCR 1009/ddosguard.agent.heartbeat,5m)=1
```

Sem ele, ausência de dados é ambígua — e o pipeline pode ficar dias
morto sem ninguém perceber.

Detalhes em [`docs/INSTALL.md`](docs/INSTALL.md) e, quando algo não
funcionar, [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).

## Upgrade de instalações v2

```bash
bash scripts/upgrade_v3.sh --dry-run   # confira
bash scripts/upgrade_v3.sh
systemctl restart rsyslog
```

A v3 corrige seis falhas silenciosas do pipeline de syslog — nenhuma
delas gerava erro visível. Ver [`docs/CHANGELOG.md`](docs/CHANGELOG.md).

## Estrutura do pacote

```
zbx_ddos_guard/
├── templates/                           # Templates Zabbix (servidor, agente, MikroTik…)
├── sql/                                 # schema.sql + migração v2 SOC
├── mikrotik/
│   └── ddosguard-ccr.rsc                # Firewall, logging e scheduler do RouterOS
├── rsyslog/
│   ├── ddosguard-syslog.conf            # Receiver unificado (config canônica)
│   └── ddosguard-logrotate              # Rotação dos logs
├── scripts/
│   ├── ingest.php                       # API PHP: recebe eventos, grava BD, envia ao Zabbix
│   ├── correlator.php                   # Correlação e classificação de severidade
│   ├── upgrade_v3.sh                    # Upgrade de instalações v2 existentes
│   ├── dg-connections.py                # Alimenta ddosguard.mtk.connections (API binária)
│   ├── dg-distinct-ips.sh               # Alimenta ddosguard.distinct_ips.rate
│   ├── ddos_guard_agent.py              # Agente coletor multiplataforma
│   ├── install_agent_linux.sh           # Instalador interativo Linux
│   ├── install_agent_windows.ps1        # Instalador interativo Windows
│   ├── setup.py                         # Assistente de configuração do servidor
│   ├── provision_dashboard.py           # Cria dashboard via API REST
│   └── integrations/
│       ├── install_integrations.sh      # Instalador das integrações SOC
│       ├── syslog_receiver.php          # MikroTik / pfSense / FortiGate / genérico
│       ├── mikrotik_receiver.php        # Receiver dedicado (prefixos DG-*)
│       ├── suricata_receiver.php
│       ├── wazuh_receiver.php
│       └── sophos_receiver.php
├── modules/                             # Widgets do frontend (5 painéis)
├── zabbix/
│   └── ITEMS.md                         # Referência dos itens, fórmulas e triggers
└── docs/
    ├── INSTALL.md                       # Guia de instalação passo a passo
    ├── TROUBLESHOOTING.md               # Diagnóstico camada por camada
    ├── CHANGELOG.md                     # Histórico de correções
    └── RESUMO.md                        # Histórico do desenvolvimento
```

## Fluxo completo

```
Logs / Event Log                 MikroTik / pfSense / FortiGate
      │                                        │
      ▼                                        ▼ syslog UDP 514
ddos_guard_agent.py  ─ HTTP POST ─► ingest.php ◄─ rsyslog ─ omprog ─ syslog_receiver.php
(Linux ou Windows)                              │
                                    ┌───────────┴───────────┐
                                    ▼                       ▼
                         ddosguard_attacks            zabbix_sender
                         ddosguard_blocks          (triggers/alertas)
                         (MySQL/PostgreSQL)
                                    │
                                    ▼
                        Widgets do dashboard
                    (Attack Monitor / Block Monitor)
```

Compatível com Zabbix **7.4** — testado em Rocky Linux 8 (appliance oficial),
Debian 13 e Ubuntu 22.04/24.04 (hosts monitorados). Integração MikroTik
testada em **RouterOS 6.49.19 / CCR1009-7G-1C-1S+**. Agente Windows testado em
Windows Server 2019/2022 com Python 3.11–3.14.
