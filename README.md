# DDoS Guard — Detecção de DDoS, Firewall & Antivírus para Zabbix 7.4.11

Módulo completo (template + agente coletor + API + dashboard) para detectar,
em tempo real, ataques DDoS / força bruta / malware, mostrando:

- **Painel "Attack Monitor"**: IP de origem, país, tipo de ataque,
  porta/protocolo, quantidade de tentativas, severidade, se foi bloqueado, e
  se o host tem **firewall** e **antivírus** ativos.
- **Painel "Block Monitor"**: bloqueios em tempo real comparando
  **Firewall x Antivírus** (totais, IPs distintos, países de origem) e uma
  tabela detalhada de cada bloqueio.
- **Dashboard pronto "DDoS Guard - Security Operations Center"**: os dois
  painéis acima + um painel nativo de Problemas/Alertas, já montados e
  posicionados — disponível tanto como **Template Dashboard** (importado
  junto com o template, aparece em Monitoring → Hosts → Dashboards) quanto
  como **dashboard geral** em Monitoring → Dashboards (criado com 1 comando
  via `scripts/provision_dashboard.py`, já que esse tipo de dashboard não é
  importável por arquivo no Zabbix).

Veja o passo a passo completo em **[`docs/INSTALL.md`](docs/INSTALL.md)** —
ou, se quiser pular direto para a configuração, rode o assistente interativo:

```bash
python3 scripts/setup.py
```
##Telas

<img width="1737" height="925" alt="Capturar_select-area_20260630045943" src="https://github.com/user-attachments/assets/5ed84f5c-2a8e-4ace-b037-f3ad4096be0e" />


Ele detecta o ambiente (appliance oficial, Apache/Nginx, MySQL/PostgreSQL) e
configura o `ingest.php`, as tabelas auxiliares e o agente coletor
automaticamente — só os passos feitos pela interface do Zabbix (importar o
template, habilitar os módulos, montar o dashboard) continuam manuais.

## Estrutura do pacote

```
zbx_ddos_guard/
├── templates/
│   └── template_ddos_guard.yaml      # Template Zabbix (itens trapper + triggers + Template Dashboard)
├── sql/
│   └── schema.sql                    # Tabelas auxiliares (ataques, bloqueios, status)
├── scripts/
│   ├── ingest.php                    # API que recebe eventos e alimenta DB + Zabbix
│   ├── ddos_guard_agent.py           # Agente coletor (lê logs em tempo real)
│   ├── ddos_guard_agent.conf.example # Configuração de exemplo do agente
│   ├── ddos-guard-agent.service      # Unit systemd do agente
│   ├── provision_dashboard.py        # Cria o dashboard em Monitoring > Dashboards via API
│   └── setup.py                      # Assistente interativo de configuração (recomendado)
├── modules/
│   ├── DDoSAttackMonitor/            # Widget de dashboard: painel de ataques
│   └── DDoSBlockMonitor/             # Widget de dashboard: painel de bloqueios
└── docs/
    └── INSTALL.md                    # Guia de instalação passo a passo
```

## Resumo do fluxo

```
Logs (iptables/ufw/fail2ban/clamav) → ddos_guard_agent.py → ingest.php
                                                                │
                                          ┌─────────────────────┴───────────────────┐
                                          ▼                                          ▼
                              Tabelas ddosguard_* (MySQL/Postgres)         zabbix_sender → Zabbix Server
                                          │                                  (triggers/alertas nativos)
                                          ▼
                       Widgets do dashboard (Attack Monitor / Block Monitor)
                       — atualizam sozinhos via "Refresh interval" do widget
```

Compatível com Zabbix **7.4.11** (testado contra a estrutura oficial de
módulos e widgets desse pacote-fonte).
