# DDoS Guard — Módulo de Detecção de DDoS / Firewall / Antivírus para Zabbix 7.4

Pacote completo com:

1. **Template Zabbix** (`templates/template_ddos_guard.yaml`) — itens trapper,
   triggers de DDoS/brute-force/malware e heartbeat.
2. **Banco de dados auxiliar** (`sql/schema.sql`) — tabelas para guardar os
   eventos detalhados (IP, país, tipo de ataque etc.) que alimentam os widgets.
3. **API de ingestão** (`scripts/ingest.php`) — recebe os eventos do agente,
   grava no banco e replica contadores ao Zabbix via `zabbix_sender`.
4. **Agente coletor** (`scripts/ddos_guard_agent.py`) — roda no host monitorado,
   lê logs de firewall (iptables/UFW/fail2ban) e antivírus (ClamAV), geolocaliza
   o IP de origem e envia tudo em tempo real (a cada poucos segundos).
5. **Módulo de frontend** (`modules/DDoSAttackMonitor` e `modules/DDoSBlockMonitor`)
   — dois widgets de dashboard nativos do Zabbix:
   - **DDoS Guard - Attack Monitor**: IP de origem, país, tipo de ataque,
     porta/protocolo, quantidade de tentativas, severidade, se foi bloqueado,
     e se o host tem firewall/antivírus ativo.
   - **DDoS Guard - Block Monitor**: bloqueios em tempo real, separados por
     Firewall x Antivírus, com comparativo visual, países de origem e tabela
     detalhada (regra/assinatura, ferramenta, horário).

Os dois widgets usam o mecanismo nativo de **auto-refresh** dos dashboards do
Zabbix (configurável por widget, ex.: 10s/30s/1min) — então o painel atualiza
sozinho, em tempo real, sem precisar de nenhuma extensão de navegador.

---

## 1. Pré-requisitos

- Zabbix Server + Frontend **7.4.x** já instalados e funcionando.
- Acesso de escrita ao banco de dados do Zabbix (MySQL/MariaDB ou PostgreSQL).
- PHP com extensão `pdo_mysql` ou `pdo_pgsql` disponível (para o `ingest.php`).
- Python 3.8+ no(s) host(s) onde o agente coletor vai rodar.
- (Opcional, recomendado) Base **GeoLite2-City** da MaxMind + `pip install geoip2`
  para geolocalização sem depender de API externa.

---

## Atalho — setup automático (recomendado)

Em vez de seguir manualmente os passos 3 a 7 abaixo, você pode rodar o
assistente interativo `scripts/setup.py` **na máquina que serve o frontend
do Zabbix** (o appliance, ou o servidor com Apache/Nginx). Ele detecta o
ambiente e configura a parte de **servidor**: cria as tabelas auxiliares,
gera um token seguro, publica o `ingest.php` no lugar certo e escreve o
`ingest.config.php`.

```bash
# Rode como root (ou root via sudo) na máquina que serve o frontend do Zabbix.
cd zbx_ddos_guard
python3 scripts/setup.py
```

Funciona só com a biblioteca padrão do Python 3 — não precisa de `pip`. Outras opções úteis:

```bash
# Aceita todos os valores detectados/sugeridos automaticamente, sem perguntar nada:
python3 scripts/setup.py --yes

# Simula a execução sem alterar nada no sistema (mostra o que faria):
python3 scripts/setup.py --dry-run

# Pula os testes de conexão com banco / endpoint HTTP (útil se ainda
# não tiver rede liberada para esse teste):
python3 scripts/setup.py --skip-db-test --skip-endpoint-test
```

Quando perguntado, ele também pode instalar o agente coletor *neste mesmo
host* (útil quando o appliance Zabbix também é um dos hosts monitorados,
como no caso mais comum). **Para os demais hosts que você quer monitorar**
(outros servidores Linux, ou qualquer host Windows), use os instaladores
dedicados do agente — ver passo 5 abaixo — que não mexem em nada do lado
servidor, só configuram a coleta naquele host específico.

No final, `setup.py` imprime um resumo com os caminhos gerados, a URL do
`ingest.php` e o token criado — **guarde a URL e o token**, você vai
precisar deles ao instalar o agente nos demais hosts. Ainda assim, **os
passos 2 (importar o template), 6 (habilitar os módulos de frontend pelo
Administration > General > Modules) e 7 (montar o dashboard) precisam ser
feitos pela interface do Zabbix** — nenhum script substitui isso.

Se preferir configurar manualmente passo a passo (ou entender o que o script
faz por debaixo dos panos), siga as seções abaixo.

---

## 2. Instalar o template no Zabbix

1. No frontend: **Data collection → Templates → Import**.
2. Selecione `templates/template_ddos_guard.yaml`.
3. Associe o template **"DDoS Guard - Security Monitoring"** a cada host que
   terá o agente coletor instalado (ex.: seu servidor web, firewall, etc.).

---

## 3. Criar as tabelas auxiliares no banco

```bash
# MySQL/MariaDB (ajuste usuário/senha/host conforme seu zabbix_server.conf)
mysql -u zabbix -p zabbix < sql/schema.sql

# PostgreSQL: descomente o bloco PostgreSQL dentro do schema.sql e rode:
# psql -U zabbix -d zabbix -f sql/schema.sql
```

---

## 4. Publicar a API de ingestão (`ingest.php`)

1. Copie `scripts/ingest.php` para dentro do diretório do frontend do Zabbix,
   por exemplo:
   ```bash
   mkdir -p /usr/share/zabbix/ddosguard
   cp scripts/ingest.php /usr/share/zabbix/ddosguard/ingest.php
   ```
2. Configure as variáveis de ambiente (no vhost do Apache/Nginx, ou direto no
   topo do arquivo): `DG_DB_HOST`, `DG_DB_NAME`, `DG_DB_USER`, `DG_DB_PASS`,
   `DG_DB_DRIVER`, `DG_ZBX_SERVER`, `DG_ZBX_PORT`, `DG_INGEST_TOKEN`.
3. Garanta que `zabbix_sender` esteja instalado no servidor onde o `ingest.php`
   roda (`apt install zabbix-sender` / `yum install zabbix-sender`).
4. Teste o endpoint:
   ```bash
   curl -X POST http://SEU_SERVIDOR/zabbix/ddosguard/ingest.php \
     -H "X-DG-Token: CHANGE_ME_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"event_type":"heartbeat","zbx_host":"meu-servidor-web-01","hostid":10500}'
   ```
   Resposta esperada: `{"ok":true}`

> **Importante:** troque `CHANGE_ME_TOKEN` por um token forte, e use o MESMO
> valor em `ingest.php` (`DG_INGEST_TOKEN`) e em `ddos_guard_agent.conf`
> (`ingest_token`).

---

## 5. Instalar o agente coletor nos hosts monitorados

O agente roda em **cada host** que você quer monitorar (servidores web,
banco de dados, controladores de domínio, RDS, etc.) e é independente da
parte de servidor (passos 2 a 4, que rodam só uma vez). Existem
instaladores dedicados para Linux e Windows — rode o que for adequado em
cada host.

### Linux

```bash
cd zbx_ddos_guard
sudo ./scripts/install_agent_linux.sh
```

Ele detecta sozinho os logs disponíveis (iptables/UFW/fail2ban/ClamAV/auth),
pergunta a URL do `ingest.php`, o token e o nome/hostid do host no Zabbix, e
já instala o serviço systemd. Para automatizar (ex.: scripts de provisionamento),
use os parâmetros sem interação:

```bash
sudo ./scripts/install_agent_linux.sh --yes \
  --ingest-url "http://192.168.0.52/ddosguard/ingest.php" \
  --token "SEU_TOKEN" \
  --zbx-host "meu-servidor-web-01" \
  --hostid 10084
```

Geolocalização local (opcional, recomendado para evitar rate-limit de API):
```bash
pip3 install geoip2
# baixe GeoLite2-City.mmdb (conta gratuita MaxMind) e coloque em
# /usr/share/GeoIP/GeoLite2-City.mmdb
```

### Windows

Requer **Python 3.8+** instalado (com "Add python.exe to PATH" marcado na
instalação) e o **[NSSM](https://nssm.cc/download)** para registrar o agente
como serviço — baixe `nssm.exe` (build win64) e coloque dentro da pasta
`scripts\`, ou deixe o instalador avisar onde colocá-lo.

Abra o PowerShell **como Administrador** e rode:

```powershell
cd zbx_ddos_guard\scripts
.\install_agent_windows.ps1
```

Ele detecta o Python, oferece instalar o `pywin32` (obrigatório — é como o
agente lê o Event Log do Windows), pergunta a URL/token/host, habilita o
log do Windows Firewall se estiver desligado (vem desabilitado por padrão
em muitas instalações), e registra o serviço `DDoSGuardAgent` via NSSM.

Para automatizar:
```powershell
.\install_agent_windows.ps1 -Yes `
  -IngestUrl "http://192.168.0.52/ddosguard/ingest.php" `
  -Token "SEU_TOKEN" `
  -ZbxHost "WIN-SERVER01" `
  -HostId 10085
```

No Windows, o agente detecta automaticamente:
- **Tentativas de RDP/logon brute-force** — Event Log "Security", evento 4625.
- **Bloqueios do Windows Firewall** — Event Log "Windows Firewall With
  Advanced Security/Firewall", eventos 5152/5157.
- **Detecções do Windows Defender** — Event Log "Windows Defender/Operational",
  eventos 1116/1117.

---

## 6. Instalar o módulo de frontend (os 2 widgets)

> **Importante sobre a estrutura de pastas:** o Zabbix só varre módulos de
> terceiros dentro de `<frontend>/modules/<NomeDoModulo>/` (a pasta
> `modules/` precisa estar na raiz do diretório do frontend, ex.:
> `/usr/share/zabbix/modules/`). A partir disso, o Zabbix monta
> automaticamente o namespace PHP esperado como `Modules\<NomeDoModulo>`
> — é por isso que o `Widget.php` de cada widget declara
> `namespace Modules\DDoSAttackMonitor;` / `namespace Modules\DDoSBlockMonitor;`
> (e não `Widgets\...`, que é reservado para os widgets *nativos* que ficam
> em `ui/widgets/`). Não renomeie as pastas dos módulos nem as mova para
> dentro de subpastas extras, ou o namespace vai parar de bater e o Zabbix
> mostrará o erro "Wrong Widget.php class name for module located at ...".

1. Copie as duas pastas de widget para o diretório de módulos do Zabbix
   frontend (por padrão `<frontend>/modules/`):
   ```bash
   cp -r modules/DDoSAttackMonitor /usr/share/zabbix/modules/
   cp -r modules/DDoSBlockMonitor  /usr/share/zabbix/modules/
   ```
2. No frontend: **Administration → General → Modules → Scan directory**.
3. Os módulos **"DDoS Guard - Attack Monitor"** e
   **"DDoS Guard - Block Monitor (Firewall & Antivírus)"** vão aparecer na
   lista — clique para habilitar (status **Enabled**) cada um.

---

## 7. Montar o dashboard

O pacote já traz um **módulo de dashboard pronto** chamado
**"DDoS Guard - Security Operations Center"**, com os 2 widgets customizados
+ um painel de problemas (alertas) já posicionados. Existem duas formas de
obtê-lo, dependendo de onde você quer vê-lo:

### Opção A — Dashboard dentro do host (Template Dashboard, importável por arquivo)

Já vem **embutido no template** `templates/template_ddos_guard.yaml`
(seção `dashboards:`). Ao importar o template (passo 2), o dashboard
"DDoS Guard - Security Operations Center" passa a aparecer automaticamente em:

> **Monitoring → Hosts → (clique no host) → aba Dashboards**

Sem nenhum passo extra — é importado junto com o template.

### Opção B — Dashboard geral (Monitoring → Dashboards), com 1 comando

Dashboards da tela **Monitoring → Dashboards** não são importáveis por
arquivo no Zabbix (só existem via API). Por isso incluímos o script
`scripts/provision_dashboard.py`, que cria esse mesmo dashboard ali através
da API REST:

```bash
# usando usuário/senha
python3 scripts/provision_dashboard.py \
  --url https://seu-zabbix.local \
  --user Admin --password 'sua_senha'

# ou usando um API token (Administration > General > API tokens > Create)
python3 scripts/provision_dashboard.py \
  --url https://seu-zabbix.local \
  --token SEU_API_TOKEN

# para tornar o dashboard privado (visível só para você) em vez de público:
python3 scripts/provision_dashboard.py --url ... --token ... --private

# para recriar do zero se já existir um dashboard com esse nome:
python3 scripts/provision_dashboard.py --url ... --token ... --force
```

Ao final, o script imprime o link direto:
`https://seu-zabbix.local/zabbix.php?action=dashboard.view&dashboardid=N`

### Montagem manual (caso prefira montar você mesmo)

1. **Monitoring → Dashboards → Create dashboard**.
2. Adicione o widget **"DDoS Guard - Attack Monitor"**:
   - Configure Host groups / Hosts (ou deixe vazio para ver todos).
   - Defina a janela de tempo (ex.: última hora) e o intervalo de
     **Refresh interval** do próprio widget (ex.: 10 segundos) para efeito de
     tempo real.
3. Adicione o widget **"DDoS Guard - Block Monitor"** do mesmo jeito.
4. Opcional: adicione também widgets nativos do Zabbix (Graph, Problems) usando
   os itens `ddosguard.attacks.rate`, `ddosguard.firewall.rate`,
   `ddosguard.antivirus.rate` para gráficos de tendência histórica nativos —
   basta apontar o widget "Graph (classic)" para esses itens, em cada host.

---

## 8. Como funciona o fluxo completo (resumo)

```
[Host monitorado]
   iptables/ufw/fail2ban/clamav logs
            │
            ▼
   ddos_guard_agent.py  (lê logs, agrega, geolocaliza)
            │  HTTP POST JSON (a cada poucos segundos)
            ▼
   ingest.php  ──────────────► grava em ddosguard_attacks / ddosguard_blocks
            │                  (lido pelos widgets do dashboard)
            │
            └──────────────►  zabbix_sender ──► Zabbix Server
                                                  (itens trapper, triggers,
                                                   alertas nativos)
```

---

## 9. Reportar "tem firewall? tem antivírus?"

O agente detecta automaticamen­te (quando `has_firewall`/`has_antivirus = auto`
no `.conf`) verificando se `iptables`/`ufw`/`fail2ban` ou `clamd` estão em
execução no host, e envia esse status (evento `status`) para a tabela
`ddosguard_host_status`, que é exibida na coluna "Firewall" / "Antivírus" do
painel **Attack Monitor**.

Se quiser forçar manualmente (por exemplo, reportar um firewall de hardware
externo que o agente não consegue detectar localmente), basta enviar um POST
para o `ingest.php` com `event_type: "status"` e os campos `has_firewall`,
`firewall_name`, `has_antivirus`, `antivirus_name`.

---

## 10. Customização rápida

- **Limiar dos triggers de DDoS** (ex.: 200 tentativas/min): edite os valores
  na expressão dos triggers depois de importar o template, em
  *Data collection → Templates → Triggers*.
- **Mais fontes de log**: edite `_process_*` em `ddos_guard_agent.py` e
  adicione novas seções em `[sources]` no `.conf` (ex.: Suricata/Snort `eve.json`).
- **Cores/layout dos widgets**: edite o `<style>` embutido em
  `modules/*/views/widget.view.php`.

> **Nota técnica (caso você adicione novos campos de seleção/dropdown):**
> a classe `CWidgetFieldSelect` do Zabbix 7.4 sempre salva e valida o valor
> como **inteiro** (`ZBX_WIDGET_FIELD_TYPE_INT32`), mesmo que as opções
> exibidas ao usuário sejam texto. Por isso, neste módulo, todos os campos
> `CWidgetFieldSelect` (`time_range`, `order_by`, `block_source_filter`) usam
> **chaves numéricas** (ex.: `0 => _('Firewall + Antivírus')`) em vez de
> strings (`'all' => ...`) — usar uma chave de texto causa o erro
> `Invalid parameter "...": an integer is expected.` ao salvar o widget no
> dashboard. Se for criar um novo campo de seleção, siga o mesmo padrão: o
> valor salvo é sempre um código inteiro, e o controller (`WidgetView.php`)
> deve interpretar esse inteiro (ver os `switch`/`if` em
> `fetchAttacks()`/`fetchBlocks()` como exemplo).

---

## 11. Template dedicado para o agente (`DDoS Guard - Agent`)

O arquivo `templates/template_ddos_guard_agent.yaml` é um template leve
para associar **em cada host monitorado** (servidores Linux e Windows com
o `ddos_guard_agent.py` instalado). Ele contém apenas os 8 itens trapper
e 6 triggers essenciais — sem dashboard.

### Quando usar qual template

| Template | Onde associar | O que tem |
|---|---|---|
| `DDoS Guard - Security Monitoring` | Só no appliance/Zabbix Server | Itens + triggers + **dashboard** |
| `DDoS Guard - Agent` | Em cada host monitorado | Só itens + triggers por host |

### Importar e associar

1. **Administration → Templates → Import**
   Importe `template_ddos_guard_agent.yaml`

2. **Data collection → Hosts → [seu host] → Templates**
   Associe `DDoS Guard - Agent` em cada servidor que tem o agente instalado

3. O template `DDoS Guard - Security Monitoring` continua associado
   **apenas no appliance** (ou no host onde o Zabbix Server roda)

### Triggers incluídas no `DDoS Guard - Agent`

| Trigger | Prioridade | Condição |
|---|---|---|
| Agente parou de enviar dados | Warning | Sem heartbeat por 15min |
| Pico de ataques (>= 50/min) | High | `attacks.rate >= 50` por 2min |
| Possível DDoS (>= 200/min) | Disaster | `attacks.rate >= 200` por 5min |
| Ataque distribuído (>= 50 IPs) | Disaster | `distinct_ips >= 50` por 5min |
| Volume alto de bloqueios | High | `firewall.rate >= 500` por 10min |
| Múltiplas detecções de malware | High | `antivirus.rate >= 5` por 10min |
