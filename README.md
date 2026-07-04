# DDoS Guard — Detecção de DDoS, Firewall & Antivírus para Zabbix 7.4.11

Módulo completo (template + agente coletor multiplataforma + API + dashboard)
para detectar, em tempo real, ataques DDoS / força bruta / malware.


## Imagens

<img width="1748" height="406" alt="image" src="https://github.com/user-attachments/assets/0836e02a-9d60-464f-b50a-5ca14372aaec" />

<img width="1726" height="330" alt="image" src="https://github.com/user-attachments/assets/11a1b4f5-5a6e-44b2-a402-24d7c73d8977" />

<img width="1736" height="271" alt="image" src="https://github.com/user-attachments/assets/46a92f88-a85d-4af9-9613-653c2fe1ec5d" />



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

**Em ambos:**
- Geolocalização por GeoIP2 local (MaxMind) com fallback para ip-api.com
- Filtro automático de IPs privados/inválidos (RFC1918, loopback, broadcast)

## O que mostra

- **Painel "Attack Monitor"**: IP de origem, país, tipo de ataque,
  porta/protocolo, tentativas, severidade, se foi bloqueado, firewall e antivírus ativos.
- **Painel "Block Monitor"**: bloqueios Firewall x Antivírus com totais,
  IPs distintos, países de origem e tabela detalhada por bloqueio.
- **Dashboard "DDoS Guard - Security Operations Center"**: os dois painéis
  + painel de Problemas/Alertas, disponível como Template Dashboard e
  como dashboard geral (via `scripts/provision_dashboard.py`).

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

## Estrutura do pacote

```
zbx_ddos_guard/
├── templates/
│   ├── template_ddos_guard.yaml         # Template servidor (itens + triggers + dashboard)
│   └── template_ddos_guard_agent.yaml   # Template agente (itens + triggers por host)
├── sql/
│   └── schema.sql                       # Tabelas auxiliares MySQL/PostgreSQL
├── scripts/
│   ├── ingest.php                       # API PHP: recebe eventos, grava BD, envia ao Zabbix
│   ├── ddos_guard_agent.py              # Agente coletor multiplataforma (Linux + Windows)
│   ├── ddos_guard_agent.conf.example    # Config de exemplo do agente
│   ├── ddos-guard-agent.service         # Unit systemd (Linux)
│   ├── install_agent_linux.sh           # Instalador interativo Linux
│   ├── install_agent_windows.ps1        # Instalador interativo Windows (PowerShell)
│   ├── setup.py                         # Assistente de configuração do servidor
│   └── provision_dashboard.py           # Cria dashboard via API REST do Zabbix
├── modules/
│   ├── DDoSAttackMonitor/               # Widget: painel de ataques
│   └── DDoSBlockMonitor/                # Widget: painel de bloqueios
└── docs/
    └── INSTALL.md                       # Guia de instalação passo a passo
```

## Fluxo completo

```
Logs / Event Log
      │
      ▼
ddos_guard_agent.py  ──── HTTP POST ────►  ingest.php
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

Compatível com Zabbix **7.4.11** — testado em Rocky Linux 8 (appliance oficial)
e Ubuntu 22.04/24.04 (hosts monitorados). Agente Windows testado em
Windows Server 2019/2022 com Python 3.11–3.14.
