# DDoS Guard — CHANGELOG

## v3.3 — Dashboard SOC: remove dados fabricados, corrige inconsistências (2026-08-15)

Motivado por um print do dashboard "DDoS Guard - Security Operations
Center" em produção mostrando os KPIs zerados (Eventos 24h, Tentativas,
Bloqueados, Críticos todos em 0) ao lado de um painel "Alertas
recentes" com 4 eventos reais de força bruta SSH — uma contradição
visível para qualquer operador de NOC.

### O achado principal: métricas fabricadas exibidas como reais

O widget `DDoSSOCOverview` tinha um bloco inteiro de UI — "Tempo de
resposta ao incidente", com as etapas Anomalia → Threshold → Trigger →
Alerta → **NOC AI** → Mitigação, tempos fixos (T+0s, T+30s, T+32s,
T+45s, T+2m, T+8m) e as métricas "45s / 8m / 1,57G" — **inteiramente
hardcoded no PHP**, sem nenhuma ligação com `$data`. Aparecia
idêntico em toda carga da página, para qualquer host, com ou sem
ataque em andamento. O estágio "NOC AI" não corresponde a nenhum
componente real do pipeline.

O widget `DDoSTimeline` ("Response Timeline") tinha o mesmo padrão: as
métricas MTTD=30s / MTTA=45s / MTTM=8m no cabeçalho eram literais
fixos, nunca calculados — inclusive quando a lista de incidentes abaixo
delas estava vazia ("Nenhum incidente nos últimos 7 dias"), o que por
si só já denunciava a inconsistência.

**Correção:** os dois blocos fabricados foram removidos.
`DDoSSOCOverview` ganhou uma faixa de status real (baseada no heartbeat
de cada host: "Monitoramento ativo — N/M hosts íntegros" ou "Atenção —
N hosts sem heartbeat recente"). `DDoSTimeline` passou a mostrar quatro
números reais que já eram calculados pela consulta mas nunca exibidos
(eventos 24h, IPs distintos 24h, pico de tentativas 24h, contagem de
incidentes 7d) em vez de inventar métricas de tempo de resposta que o
sistema não tem como medir com confiança (exigiria saber quando o
ataque *realmente* começou, não só quando foi registrado).

### Bug real: KPIs e "Alertas recentes" usavam janelas de tempo diferentes

Os KPIs do `DDoSSOCOverview` filtravam `created_at >= agora-24h`, mas a
consulta de "Alertas recentes" não tinha filtro de tempo nenhum — trazia
sempre os 5 eventos mais recentes de **toda a história** da tabela,
não das últimas 24h. Em um período sem eventos recentes, os KPIs
corretamente mostravam 0 enquanto "Alertas recentes" continuava
exibindo eventos antigos, sem indicar sua idade — exatamente o que o
print mostrou.

**Correção:** adicionado campo configurável de janela de tempo (1h / 6h
/ 24h / 7 dias, mesmo padrão já usado em `DDoSAttackMonitor`), aplicado
de forma idêntica aos KPIs e a "Alertas recentes". O rótulo do painel
agora mostra a janela ativa ("Alertas recentes (últimas 24h)").

### Bug real: host com agente morto continuava "OK" para sempre

O status de host verificava apenas se o item `ddosguard.agent.heartbeat`
**já recebeu algum valor alguma vez** — e como esse item só recebe o
valor `1` (nunca `0`), um host cujo agente parou de enviar heartbeat há
dias continuava marcado como "OK" indefinidamente. Não havia checagem
de horário nenhuma, apesar de o próprio heartbeat ter sido desenhado
justamente para isso (ver v3, "a lição").

**Correção:** a consulta agora busca também o horário (`clock`) do
último heartbeat; um host só é considerado "OK" se o heartbeat mais
recente estiver dentro de 15 minutos (mesmo padrão do macro
`{$DG.HEARTBEAT.TIMEOUT}` dos templates). Hosts com heartbeat velho
mostram há quanto tempo ("há 3h"), hosts sem heartbeat nunca mostram
"nunca" — nunca mais "OK" silencioso.

### Métrica removida por ser enganosa: "taxa" de bloqueio

O KPI "Bloqueados" mostrava `bloqueios / eventos × 100` como "taxa",
mas `ddosguard_blocks` e `ddosguard_attacks` são tabelas alimentadas
por pipelines diferentes sem relação de cardinalidade garantida — a
própria documentação já alertava que instalações só-MikroTik nunca
populam `ddosguard_attacks` (ver `README.md`, "Qual preset usar").
Nessas instalações a "taxa" seria sempre 0% mesmo com milhares de
bloqueios reais; em outras poderia passar de 100%. Removida; o card
agora só mostra a contagem e a janela de tempo, como os demais.

### Filtro por host/grupo agora funcional no SOC Overview

O formulário do widget já tinha campos "Host groups"/"Hosts", mas o
controller nunca os lia — a seleção não tinha efeito nenhum. Agora os
quatro KPIs, "Alertas recentes" e o painel de hosts respeitam o filtro,
igual aos demais widgets do módulo.

### Testes

`tests/test_dashboard_widgets.py` (novo, 8 casos): varre o código-fonte
dos widgets tocados (não há instância Zabbix disponível neste ambiente
para executar o framework de UI de verdade) garantindo que os padrões
de dado fabricado removidos não voltem, que KPIs e alertas usam a mesma
janela de tempo, que o status de host depende do horário do heartbeat
e não só do valor, e que a "taxa" enganosa não retorna. `php -l` limpo
em todo o diretório `modules/`.

---

## v3.2 — Auditoria completa do repositório (2026-08-14)

Extensão da correção `min()`→`sum()` da v3.1 (que cobriu só os dois
templates de agente) para **todo o restante do projeto**, mais uma
melhoria de segurança encontrada na varredura.

### Bug `min()` corrigido nos 4 templates restantes

O mesmo bug da v3.1 — trigger de volume usando `min()` sobre um item
que o receiver/agente sempre envia como evento individual (valor
sempre `1`), tornando a trigger praticamente impossível de disparar —
também existia em:

| Template | Trigger(s) corrigida(s) |
|---|---|
| `template_ddos_guard.yaml` (servidor) | Múltiplas detecções de malware (`antivirus.rate`) |
| `template_ddos_guard_sophos.yaml` | Volume crítico/alto de bloqueios (`firewall.rate`) e de detecções IPS (`attacks.rate`) — 4 triggers |
| `template_ddos_guard_fortigate.yaml` | Volume crítico de bloqueios FortiGate e violações de segurança FortiSwitch (`firewall.rate`) |
| `template_ddos_guard_mikrotik.yaml` | Volume crítico/alto de bloqueios (`firewall.rate`) |

`ddosguard.mtk.portscan` e `ddosguard.mtk.bruteforce` (MikroTik) já
usavam `sum()` corretamente — não precisaram de correção.

`tests/test_templates.py` ganhou uma suíte que varre **todos** os
templates do diretório (não só os dois de agente) procurando `min()`
sobre qualquer um dos itens conhecidos por serem eventos individuais
(`ddosguard.firewall.rate`, `ddosguard.antivirus.rate`,
`ddosguard.mtk.portscan`, `ddosguard.mtk.bruteforce`) — proteção contra
o bug voltar a ser introduzido em um template novo ou reimportado.

### Segurança: senha do `provision_dashboard.py` sai da linha de comando

`--password` na CLI fica visível para qualquer usuário local via `ps
aux` e costuma ficar gravado no histórico do shell — o próprio projeto
já evita esse padrão no `setup.py` (usa `MYSQL_PWD`/`PGPASSWORD` via
variável de ambiente), mas o `provision_dashboard.py` não seguia a
mesma prática para a senha da API do Zabbix.

Corrigido sem quebrar compatibilidade: se `--user` for passado sem
`--password` (e sem `--token`), o script agora pergunta a senha de
forma interativa via `getpass` (não ecoa na tela, não fica em
histórico). Chamadas de automação que já passam `--password`
explicitamente continuam funcionando exatamente como antes.

### Demais áreas revisadas nesta rodada

Sem achados adicionais que justificassem mudança de código:

- **Views dos 5 widgets de dashboard** — usam a API nativa de
  construção de HTML do Zabbix (`CDiv`, `CSpan`, `CTableInfo`), que
  escapa automaticamente todo conteúdo dinâmico (IP, país, nome de
  malware, etc.) — sem XSS armazenado.
- **`mikrotik/ddosguard-ccr.rsc`** — ordem das regras de firewall e
  escada de detecção de port scan/brute force revisadas; nenhuma
  alteração necessária.
- **`sql/migration_v2_soc.sql`** — todo o SQL dinâmico é montado a
  partir de literais fixos (nomes de coluna/tabela do próprio script),
  sem entrada externa — sem risco de injeção.
- **Instaladores (`install_agent_linux.sh`, `install_debian_prereqs.sh`
  etc.)** — sem uso de `curl | bash`, `eval` ou `chmod 777`; senhas de
  banco já tratadas via variável de ambiente, não argumento de CLI.

---

## v3.1 — Melhorias na detecção Firewall/Antivírus dos templates de agente (2026-08-14)

Evolução direta da auditoria de 2026-08 (`docs/AUDITORIA_2026-08.md`), nos
dois templates de agente: `template_ddos_guard_agent.yaml` (Linux/Windows
genérico) e `template_ddos_guard_agent_windows.yaml` (Windows Server
dedicado).

### Bug corrigido: `min()` nas triggers de volume de firewall/antivírus

- **Sintoma:** as triggers "Volume alto de bloqueios de firewall" e
  "Múltiplas detecções de malware" praticamente nunca disparavam em
  produção, mesmo sob volume real de bloqueios/detecções.
- **Causa:** o agente (`ddos_guard_agent.py`) envia cada bloqueio de
  firewall e cada detecção de antivírus como um evento HTTP individual,
  sempre com valor `1` (ver `_process_firewall_lines`,
  `_process_clamav_lines`, `_process_windows_firewall_events`,
  `_process_windows_defender_events`) — ao contrário de
  `ddosguard.attacks.rate`, que carrega a contagem real agregada por
  ciclo. As triggers usavam `min(...)>=N`, que exige que **todo** valor
  no período seja `>= N`; como cada amostra individual vale `1`, a
  condição nunca era satisfeita para `N` maior que 1.
- **Correção:** expressão trocada para `sum(...)>=N`, que soma os
  eventos no período — o comportamento que "volume de bloqueios/N min"
  sempre pretendeu medir. `ddosguard.attacks.rate` e
  `ddosguard.distinct_ips.rate` não foram alteradas: já carregam
  contagens/gauges legítimos, e `min()` ali funciona como histerese
  intencional (exige volume sustentado ao longo da janela, não um pico
  isolado).

### Thresholds configuráveis por host (macros)

O template `template_ddos_guard_agent_windows.yaml` já usava macros
`{$DG.*}` para os limiares das triggers; `template_ddos_guard_agent.yaml`
(Linux/genérico) tinha tudo hardcoded na expressão. Adicionadas as
mesmas oito macros ao template Linux/genérico, para paridade entre os
dois:
`{$DG.HEARTBEAT.TIMEOUT}`, `{$DG.ATTACK.WARN}`, `{$DG.ATTACK.DISASTER}`,
`{$DG.DISTINCT_IPS.DISASTER}`, `{$DG.FIREWALL.WARN}`, `{$DG.AV.WARN}`,
`{$DG.AV.HIGH}`, `{$DG.AV.DISASTER}` — valores padrão idênticos aos já
usados nas triggers anteriores, para não alterar o comportamento de
instalações existentes na importação.

### Severidade escalonada do antivírus (3 níveis)

Antes: uma única trigger HIGH em `>= 5 detecções/10min`. Agora, nos dois
templates de agente:

| Trigger | Prioridade | Condição padrão |
|---|---|---|
| Antivírus detectou ameaça | WARNING | `>= {$DG.AV.WARN}` (1) detecção/10min |
| Múltiplas detecções de malware | HIGH | `>= {$DG.AV.HIGH}` (5) detecções/10min |
| Possível surto de malware | DISASTER | `>= {$DG.AV.DISASTER}` (20) detecções/10min |

Encadeadas por `dependencies` (mesmo padrão já usado nas triggers de
`attacks.rate`): a trigger de nível mais alto depende da anterior, então
uma única detecção não dispara três alertas superpostos — a UI do Zabbix
mostra apenas o nível mais severo ativo.

### Nova trigger: firewall + antivírus correlacionados

Firewall e antivírus eram avaliados de forma totalmente independente,
mesmo sendo, juntos, um indicador mais forte de comprometimento ativo do
que qualquer um isoladamente (ex.: invasor explorando o host pela rede e
deixando um artefato malicioso no disco). Nova trigger HIGH, sem
dependência das demais:

```
sum(ddosguard.firewall.rate,15m)>0 and sum(ddosguard.antivirus.rate,15m)>0
```

Janela de 15 minutos — mais ampla que os 10 minutos das triggers
individuais — para dar margem a eventos de fontes diferentes que não
chegam no mesmo instante.

### Compatibilidade

Nenhum item, chave, payload JSON ou coluna de banco foi alterado — só
expressões de trigger e macros novas. Reimportar os dois templates é
seguro em instalações existentes; hosts que já têm os templates
associados recebem as macros com os valores padrão atuais (equivalentes
ao comportamento anterior, exceto pela correção do bug `min()`/`sum()`,
que passa a fazer as triggers de firewall/antivírus disparar como
sempre deveriam).

---

## v3 — Integração MikroTik e correção do pipeline de syslog (2026-07-31)

Implantação em produção num **CCR1009-7G-1C-1S+ (RouterOS 6.49.19)**
enviando syslog para um appliance **Debian 13 + Zabbix 7.4.12**.

O pipeline `MikroTik → rsyslog → omprog → PHP → MySQL → zabbix_sender →
Zabbix` estava quebrado em **seis pontos independentes**. Nenhum gerava
erro visível: o rsyslog subia normalmente, o PHP não escrevia em lugar
nenhum, os itens simplesmente ficavam vazios. O sistema aparentava
funcionar.

---

### Resumo executivo

| Categoria | Itens |
|---|---|
| Bugs corrigidos | 6 (todos silenciosos) |
| Falsos positivos corrigidos | 2 |
| Arquivos alterados | 7 |
| Arquivos novos | 8 |
| Limitações documentadas | 5 |

---

### 1. Bugs corrigidos

#### 1.1 `module(load="omprog")` ausente — receiver nunca executou

- **Sintoma:** itens de syslog vazios havia dias. `systemctl status
  rsyslog` mostrava `active (running)`.
- **Causa:** o `install_integrations.sh` gerava a config sem carregar o
  módulo `omprog`, mas declarando uma action que o usava. O rsyslog
  registra `module name 'omprog' is unknown`, **ignora o bloco e segue
  rodando** — a config quebrada não derruba o serviço.
- **Agravante:** havia dois arquivos em `/etc/rsyslog.d/` declarando
  `imudp` e o ruleset `ddosguard`. Como a leitura é alfabética, o input
  UDP acabou vinculado ao ruleset do arquivo que falhou.
- **Correção:** `install_integrations.sh` agora carrega o módulo, valida
  com `rsyslogd -N1` **antes** de reiniciar, e detecta arquivos
  conflitantes.
- **Arquivos:** `scripts/integrations/install_integrations.sh`,
  `rsyslog/ddosguard-syslog.conf` (novo).

#### 1.2 Template do omprog sem `\n` — 100% das mensagens rejeitadas

- **Sintoma:** após corrigir 1.1, o journal encheu de
  `omprog: messages must be terminated with \n at end of message`.
- **Causa:** o omprog exige quebra de linha ao fim de cada mensagem.
  `RSYSLOG_TraditionalForwardFormat` não a inclui.
- **Correção:** template `DGProgFmt` com `\n` explícito.

#### 1.3 `require_once 'ingest.php'` encerrava o processo do receiver

- **Sintoma:** `{"ok":false,"error":"invalid token"}` a cada mensagem.
- **Causa:** o `ingest.php` é um endpoint HTTP com código em nível
  superior. O `require` executava a validação de token e chamava
  `respond()`, que encerra com `exit` — antes de o receiver processar
  qualquer linha. Sob CLI não existe header `X-DG-Token`, então falhava
  sempre.
- **Diagnóstico em 5 segundos:**
  `php -r "require '.../ingest.php'; echo 'CHEGUEI AO FIM';"`
- **Correção:** guard de modo biblioteca no topo do bloco de execução:

  ```php
  if (defined('DG_INGEST_LIB') || PHP_SAPI === 'cli') { return; }
  ```

  Em PHP, `return` no escopo de um arquivo incluído interrompe o include
  preservando tudo que já foi definido. Os cinco receivers agora declaram
  `define('DG_INGEST_LIB', true)` antes do require.
- **Arquivos:** `scripts/ingest.php`, os cinco receivers.

#### 1.4 `while (fgets(STDIN))` travava sob omprog — o bug que só aparece em produção

- **Sintoma:** funcionava perfeitamente em teste manual e **nunca** em
  produção. Um processo PHP vivo, arquivo de log recebendo, banco vazio.
- **Causa:** o omprog mantém **um** processo vivo e alimenta o stdin
  continuamente. Com

  ```php
  $lines = [];
  while (($line = fgets(STDIN)) !== false) { $lines[] = trim($line); }
  foreach ($lines as $line) { ... }
  ```

  o pipe nunca fecha, `fgets()` nunca retorna `false`, e o `foreach`
  jamais é alcançado. Em teste manual o STDIN encerra e tudo funciona —
  o que torna o bug particularmente enganoso.
- **Correção:** generator, processando cada linha assim que chega.
- **Arquivos:** `syslog_receiver.php`, `mikrotik_receiver.php`,
  `sophos_receiver.php`.

#### 1.5 `zabbix_sender -i -` sem aspas no host

- **Sintoma:** `processed: 0; failed: 1`, invisível — o `proc_open`
  descarta o stdout.
- **Causa:** no formato `-i -` os campos são separados por espaço.
  `MIKROTIK CCR 1009` era lido como host=`MIKROTIK`, key=`CCR`.
- **Correção:** host entre aspas em `send_to_zabbix()`. Afeta **todos**
  os envios, não só MikroTik.
- **Arquivo:** `scripts/ingest.php`.

#### 1.6 `db_connect()` dentro do loop

- **Causa:** com processo persistente, uma conexão PDO por linha. Sob
  carga real (dezenas de eventos/s) derruba o MySQL.
- **Correção:** conexão reaproveitada; o `catch` descarta o handle para
  forçar reconexão após `wait_timeout`.

---

### 2. Falsos positivos corrigidos

#### 2.1 Google e Cloudflare bloqueados como port scan

- **Sintoma:** `172.217.*`, `104.21.*` na address-list `DDOSGUARD-PORTSCAN`,
  com origem **porta 443** — tráfego de resposta de conexões que os
  clientes iniciaram.
- **Causa:** faltava `accept established,related` como primeira regra do
  chain `input`, e a detecção não exigia SYN puro. Pacotes RST/ACK
  tardios, de sessões já expiradas no conntrack (UDP expira em 10s),
  chegavam classificados como `new`.
- **Correção:** `accept established,related` em primeiro lugar e
  `tcp-flags=syn,!ack,!fin,!rst` nas quatro regras da escada de detecção.
- **Limitação:** escaneadores furtivos (FIN, NULL, XMAS) não usam SYN e
  passam. Detectá-los exige regra separada.

#### 2.2 Coletor autobloqueado

- **Sintoma:** um `nmap` de teste a partir do Zabbix colocou o próprio
  coletor na lista de bloqueio; o host apareceu "down" e **todos** os
  itens SNMP pararam.
- **Correção:** address-list `DDOSGUARD-WHITELIST` com accept em posição
  anterior a qualquer regra de detecção, aplicada pelo `.rsc`.

---

### 3. Itens do Zabbix

- **`ddosguard.mtk.cpu.util` não suportado.** A fórmula do template era
  `last(//system.cpu.util[,idle])` — chave do **agente Zabbix em Linux**,
  inexistente num host SNMP. Corrigida para
  `avg(last_foreach(//system.cpu.util[*]))`.

  Dois detalhes: o wildcard substitui um parâmetro **inteiro**, não parte
  dele (`[hrProcessorLoad.*]` não casa nada); e testar item calculado com
  `foreach` **no template** sempre falha, porque `//` resolve para o
  próprio template.

- **`ddosguard.mtk.connections`.** RouterOS 6.x não expõe o total de
  conexões por SNMP (o OID `1.3.6.1.4.1.14988.1.1.6.1.0` retorna sempre
  0, mesmo com 28 mil conexões ativas) e não tem REST API — introduzida
  apenas na 7.1. Alimentado por `dg-connections.py` via API binária
  (porta 8728), usando `/ip/firewall/connection/tracking/print`, que
  devolve o total pronto em vez de iterar milhares de objetos.

- **`ddosguard.distinct_ips.rate`.** Alimentado por `dg-distinct-ips.sh`
  via cron.

- **`hostid`, `severity_score` e `source_platform`** passaram a ser
  gravados em `ddosguard_blocks`. O `hostid` ia fixo em 0 e o dashboard
  mostrava "Host protegido: Desconhecido" em toda linha.

- **Descoberta de interfaces PPPoE.** Cada reconexão de cliente gera um
  `ifIndex` novo. Sem filtro, o host acumulou **12.349 itens**, a maioria
  órfã, sufocando a fila de pollers SNMP. Filtro documentado em
  `zabbix/ITEMS.md`.

---

### 4. Volume

Logar todo pacote dropado no chain `forward` de uma rede com clientes
PPPoE gera dezenas de mensagens por **segundo** — cada uma virando um
INSERT e uma chamada ao `zabbix_sender`. O `.rsc` desativa o log do drop
genérico e mantém apenas as regras de detecção, que geram dezenas de
eventos por **dia**.

Acrescentado logrotate e `EVENT` de purga com retenção de 90 dias.

---

### 4.1 Dashboard

O `provision_dashboard.py` criava apenas 3 widgets e ignorava os três
painéis SOC (`DDoSSOCOverview`, `DDoSTimeline`, `DDoSMitreHeatmap`)
adicionados na v2.

- Reescrito: monta 5 widgets próprios + Problems nativo, em duas
  páginas, com posicionamento recalculado quando algum é omitido —
  nenhum buraco no grid.
- Presets `full`, `mikrotik` e `minimal`, mais `--widgets` e `--exclude`
  para seleção manual.
- `--dry-run` imprime o JSON antes de criar.
- Verifica via `module.get` se os módulos estão instalados **e**
  habilitados antes de chamar `dashboard.create`, que falha com erro
  pouco informativo nesse caso.
- Avisa quando um widget selecionado depende de `ddosguard_attacks`,
  tabela que o `syslog_receiver.php` não popula no caminho MikroTik.

Nenhum módulo foi removido: os cinco leem tabelas diferentes e são
complementares. O que decide se um painel fica vazio é qual integração
alimenta cada tabela.

**Tratamento de erros de API.** Uma credencial inválida produzia 15
linhas de traceback, e o `checar_modulos()` capturava *qualquer* exceção
— inclusive a de autenticação — imprimindo "não foi possível verificar
os módulos" e seguindo adiante, o que mascarava a causa raiz.

- Exceção dedicada `ZabbixAuthError`, com mensagem explicando como gerar
  um token e como usar `--user`/`--password`. Sai com `rc=2`.
- `checar_modulos()` deixa erros de autenticação passarem em vez de
  engoli-los.
- Detecção dos placeholders comuns (`TOKEN`, `SEU_API_TOKEN`,
  `CHANGE_ME`) antes de chamar a API. O Zabbix responde a um token
  inválido com `Session terminated, re-login, please.`, que sugere sessão
  expirada e não credencial errada.
- A checagem de placeholder roda **depois** do `--dry-run`: conferir o
  layout não exige credencial.

Os exemplos da documentação usavam `--token TOKEN` literalmente, o que
levava exatamente a esse erro. Substituídos por valores claramente
ilustrativos e por `--user`/`--password`.

---

### 5. Arquivos novos

| Arquivo | Função |
|---|---|
| `mikrotik/ddosguard-ccr.rsc` | Firewall, logging e scheduler do RouterOS |
| `rsyslog/ddosguard-syslog.conf` | Config canônica do receiver |
| `rsyslog/ddosguard-logrotate` | Rotação dos logs |
| `scripts/upgrade_v3.sh` | Upgrade de instalações v2 |
| `scripts/dg-connections.py` | Alimenta `ddosguard.mtk.connections` |
| `scripts/dg-distinct-ips.sh` | Alimenta `ddosguard.distinct_ips.rate` |
| `docs/TROUBLESHOOTING.md` | Diagnóstico camada por camada |
| `zabbix/ITEMS.md` | Referência de itens, fórmulas e triggers |

---

### 6. Limitações conhecidas

- **`ddosguard.attack.event` não é alimentado.** O parser emite sempre
  `event_type=block_firewall`, então o caso `attack` do `ingest.php`
  nunca roda — e, por consequência, o `correlator.php` e o heatmap MITRE
  ficam zerados para eventos MikroTik. Promover alta severidade para
  `attack` é decisão de produto, não bug.
- **Sem enriquecimento GeoIP** no caminho MikroTik: País e ASN vazios.
- **Escaneadores furtivos** passam pela regra baseada em SYN.
- **Conexão PDO de longa duração** depende do `catch` para reconectar.
- **RouterOS 6.x** exige `librouteros` para o contador de conexões.

---

### 7. A lição

Seis falhas independentes, nenhuma gerando erro visível. O que teria
encurtado o diagnóstico de horas para minutos não era uma ferramenta
melhor — era o **heartbeat**: um sinal periódico, independente do evento
monitorado, que transforma silêncio em informação.

Sem ele, ausência de dados é ambígua: pode ser tranquilidade ou cegueira,
e não há como distinguir. Configure o heartbeat antes de qualquer regra
de detecção.

```
nodata(/MIKROTIK CCR 1009/ddosguard.agent.heartbeat,5m)=1
```

---

## v2 — Suporte completo a Debian 12/13 + correções de campo (2026-07-05)

Registro de todas as mudanças, correções e atualizações resultantes da
implantação em produção num appliance **Debian 13 + Zabbix 7.4.11**
(server, frontend Apache porta 6030, MySQL/MariaDB e agente no mesmo host).

---

## Resumo executivo

| Categoria | Itens |
|---|---|
| Bugs corrigidos | 6 |
| Falhas de segurança corrigidas | 3 |
| Arquivos atualizados | 2 (`install_agent_linux.sh`, `docs/INSTALL.md`) |
| Arquivos novos | 2 (`install_debian_prereqs.sh`, este `CHANGELOG.md`) |
| Pendência conhecida | 1 (validação de prompt no `setup.py`) |

---

## 1. Bugs corrigidos

### 1.1 `401 invalid token` com token correto nos dois lados — **causa raiz: permissão**

- **Sintoma:** agente logava `HTTP Error 401: Unauthorized` em todos os
  heartbeats; `curl` autenticado também recebia `{"ok":false,"error":"invalid token"}`,
  mesmo com o token do `agent.conf` idêntico ao do `ingest.config.php`.
- **Causa:** `/etc/zabbix/ddosguard/ingest.config.php` estava
  `-rw-r----- root:root` — o `www-data` (PHP) não conseguia ler. O
  `include` falhava em silêncio e o `ingest.php` caía no fallback
  `CHANGE_ME_TOKEN`, rejeitando o token válido.
- **Correção:** `chown root:www-data` + `chmod 640` no config e `755` no
  diretório. O instalador v2 aplica e **testa** a leitura com
  `sudo -u www-data cat` antes de concluir.
- **Arquivos:** `install_agent_linux.sh` (etapa 9a), `INSTALL.md`
  (novo item em "Problemas frequentes").

### 1.2 Ingest respondendo em ~20 s por request → `Erro no ciclo de coleta: timed out`

- **Sintoma:** após resolver o 401, o agente passou a logar timeouts no
  ciclo de coleta. `curl` com timing mostrou `connect: 0.001s` e
  `total: 20.03s` — hang interno no PHP.
- **Causa:** `DG_ZBX_SERVER => '45.70.216.68:6030'` no
  `ingest.config.php` (endereço do **frontend web** no campo que espera
  o host do **trapper**). O `zabbix_sender` tentava resolver a string
  `IP:porta` inteira como hostname e travava ~20 s por chamada.
- **Correção:** `DG_ZBX_SERVER => '127.0.0.1'` (porta pertence a
  `DG_ZBX_PORT`). Resposta do ingest caiu de 20 s para milissegundos.
  O instalador v2 detecta o padrão `host:porta` e corrige
  automaticamente; o teste final alerta se a latência passar de 5 s.
- **Arquivos:** `install_agent_linux.sh` (etapas 9b e 10b), `INSTALL.md`
  (novo item em "Problemas frequentes").
- **Pendente:** validar o prompt correspondente no `setup.py`
  (rejeitar `:` na resposta) para eliminar o erro na origem.

### 1.3 `processed: 0; failed: 1` no zabbix_sender — nome técnico vs nome visível

- **Sintoma:** envio manual com `-s "Zabbix Server"` (nome exibido no
  frontend) era rejeitado pelo trapper.
- **Causa:** o zabbix_sender exige o **nome técnico** do host (coluna
  `host` da tabela `hosts`), que no appliance era `debian`. Consulta SQL
  também revelou que entradas com nomes dos templates
  (`DDoS Guard - Security Monitoring`, `- Agent`, etc.) são os itens dos
  próprios templates — os itens "reais" pertencem ao host `debian`.
- **Correção:** documentada a distinção com a query de diagnóstico
  (`SELECT h.host, i.key_, i.type, i.status ...`). O instalador v2 avisa
  no prompt do `zbx_host` e valida com um heartbeat real
  (`processed: 1`) na etapa de testes.
- **Arquivos:** `install_agent_linux.sh` (etapas 4 e 10a), `INSTALL.md`
  (seção `failed: 1` ampliada).

### 1.4 Ordem errada do UFW no guia — `ufw enable` antes das regras

- **Sintoma real em campo:** o firewall subiu sem liberar a porta 6030 e
  o frontend do Zabbix caiu com `ERR_CONNECTION_TIMED_OUT` (dashboard
  inteiro com `Failed to load resource`). O acesso só não foi perdido
  porque a regra de SSH existia.
- **Causa:** a seção Debian/Ubuntu do `INSTALL.md` trazia
  `ufw --force enable` como **primeiro** comando; além disso não liberava
  a porta do frontend nem 10050/10051.
- **Correção:** seção reescrita com regras **antes** do enable, incluindo
  a porta web (com aviso para ajustar se não for 80), 10050 e 10051.
  O instalador v2 extrai a porta web da própria URL do ingest para nunca
  trancar o painel fora.
- **Arquivos:** `INSTALL.md` (seção Debian/Ubuntu), `install_agent_linux.sh`
  (etapa 8).

### 1.5 `freshclam` manual conflitando com o daemon

- **Sintoma:** `ERROR: Failed to lock the log file ... Resource
  temporarily unavailable` ao rodar `freshclam` na mão.
- **Causa:** o serviço `clamav-freshclam` já roda como daemon e segura o
  lock — o erro é esperado e inofensivo; as bases estavam atualizando
  normalmente (confirmado no log: daily/main/bytecode up-to-date).
- **Correção:** guia e instalador não chamam mais `freshclam` manual;
  usam `systemctl enable --now clamav-freshclam` com nota explicando o
  erro de lock.
- **Arquivos:** `INSTALL.md` (passo 3 da seção Debian),
  `install_agent_linux.sh` (etapa 2), `install_debian_prereqs.sh`.

### 1.6 Aviso AH00558 do Apache (ServerName)

- **Sintoma:** `Could not reliably determine the server's fully qualified
  domain name` a cada reload no `error.log`.
- **Correção:** `ServerName $(hostname)` em
  `conf-available/servername.conf` + `a2enconf` (com PATH corrigido para
  `/usr/sbin`, já que `a2enconf` não estava no PATH da sessão root).
- **Arquivos:** `install_debian_prereqs.sh` (etapa 6b).

---

## 2. Falhas de segurança corrigidas

### 2.1 `chmod -R 777 /etc/zabbix/*` (aplicado em campo como workaround do 401)

- **Risco:** expunha a **senha do banco** (`zabbix_server.conf`,
  `ingest.config.php`) para leitura e **escrita** por qualquer usuário
  ou processo da máquina — num servidor exposto à internet.
- **Correção — modelo de permissões definitivo:**

  | Arquivo | Dono:Grupo | Modo |
  |---|---|---|
  | `/etc/zabbix/ddosguard/ingest.config.php` | `root:www-data` | `640` |
  | `/etc/zabbix/ddos_guard_agent.conf` (contém token) | `root:zabbix` | `640` |
  | `/etc/zabbix/zabbix_server.conf` | `root:zabbix` | `640` |
  | `/etc/zabbix/zabbix.conf.php` | `root:www-data` | `640` |
  | `ingest.php` no webroot | `root:root` | `644` |
  | Logs lidos pelo agente | `root:adm` | `644` |

- O instalador v2 aplica esse modelo e o `install_debian_prereqs.sh`
  também o restaura (idempotente) caso um chmod amplo tenha passado.

### 2.2 Symlink do `ingest.config.php` dentro do webroot

- **Risco:** criado em campo como tentativa de correção do 401
  (`/usr/share/zabbix/ui/ddosguard/ingest.config.php`), poderia expor a
  senha do banco via HTTP caso o servidor web servisse o arquivo.
  Também era desnecessário — o `ingest.php` lê o caminho absoluto
  `/etc/zabbix/ddosguard/ingest.config.php`.
- **Correção:** removido; instalador v2 e `install_debian_prereqs.sh`
  removem qualquer cópia/symlink do config encontrada no docroot.

### 2.3 `chmod 777` em logs (`kern.log`, `clamav.log`)

- **Risco:** logs graváveis por qualquer usuário permitem apagar ou
  forjar evidência de ataque — exatamente o que o módulo se propõe a
  monitorar.
- **Correção:** padronizado `644` (o agente roda como root via systemd,
  não precisa de mais). Nota adicionada sobre o logrotate poder recriar
  com modo diferente (`create 0644 root adm` em
  `/etc/logrotate.d/rsyslog` se necessário).

---

## 3. Novas dependências e suporte a Debian 12/13

O Debian minimal difere do Rocky Linux (appliance de referência) e do
Ubuntu em pontos que quebravam a instalação:

| Dependência | Por quê | Antes | Agora |
|---|---|---|---|
| `rsyslog` | Debian 12+ usa só journald; **sem rsyslog não existem** `/var/log/auth.log` e `/var/log/kern.log` | não mencionado | instalado e habilitado automaticamente |
| `ufw` | não vem instalado no Debian (diferente do Ubuntu) | assumido presente | instalado automaticamente |
| `fail2ban` | fonte do `fail2ban.log` | instalação manual | instalado + `jail.local` mínimo (sshd) |
| `clamav-freshclam` (daemon) | assinaturas automáticas | `freshclam` manual (conflitava) | serviço habilitado |
| `clamav-daemon` (clamd) | escaneamento em tempo real | sempre implícito | **condicional à RAM ≥ 6 GiB** (consome ~1 GiB residente; abaixo disso sugere `clamscan` via cron) |
| `python3-geoip2` + GeoLite2 | geolocalização local | opcional/ignorado | `pip3 --break-system-packages`; **sem a base, ip-api.com (45 req/min) trava o ciclo de coleta em host exposto** |
| `zabbix-sender` | testes e ingest local | assumido | instalado quando disponível no repo |

Caminho do log do ClamAV: além de `/var/log/clamav/clamd.log`
(Rocky/Ubuntu), o instalador agora também detecta
`/var/log/clamav/clamav.log` (observado no Debian).

---

## 4. Arquivos alterados / criados

### `scripts/install_agent_linux.sh` — **v2 (reescrito)**

Mantém compatibilidade com os flags existentes
(`--yes`, `--ingest-url`, `--token`, `--zbx-host`, `--hostid`) e adiciona
`--web-port`, `--mgmt-net`, `--skip-firewall`, `--skip-deps`.

Etapas novas ou alteradas:

1. Instalação de dependências por família de distro (Debian/RHEL)
2. fail2ban + ClamAV com freshclam-daemon e clamd condicional à RAM
3. Prompt de conexão (inalterado)
4. Prompt do `zbx_host` com aviso **nome técnico ≠ nome visível**
5. Detecção de logs ampliada (kern/ufw/auth no Debian; messages/secure no
   RHEL; clamd.log **ou** clamav.log) + permissões 644
6. `agent.conf` gravado com **modo 640** dono `root:zabbix` (legível pelo serviço)
7. Unit systemd (usa a do repo se existir, senão gera)
8. Firewall com regras **antes** do enable e porta web extraída da URL
   do ingest; aviso de que `allow from REDE` ampla suprime eventos
   `[UFW BLOCK]` dessa rede
9. **Sanidade do lado servidor** (quando local): permissões do
   `ingest.config.php` + teste de leitura pelo www-data; correção
   automática de `DG_ZBX_SERVER` com `:porta`; remoção de config no docroot
10. **Testes finais:** heartbeat via `zabbix_sender` (diagnóstico do
    `failed: 1`), `curl` no ingest com medição de latência (alerta > 5 s
    apontando `DG_ZBX_SERVER`/`DG_DB_HOST`), 401 com as 4 causas em ordem
    de probabilidade, e verificação do journal do agente

### `docs/INSTALL.md` — atualizado

- Seção **"Configurações necessárias no Ubuntu / Debian"** reescrita:
  rsyslog, ordem correta do ufw (regras → enable), portas do frontend e
  do Zabbix, freshclam como daemon, geoip2/GeoLite2, permissões 644 com
  aviso contra 777, caminho alternativo `clamav.log`.
- **"Problemas frequentes"** — três adições:
  1. `401 invalid token` com token correto (permissão do config +
     proibição de symlink no webroot)
  2. Ingest lento (~20 s) / `timed out` no agente (`DG_ZBX_SERVER` com
     porta + alternativa geoip)
  3. `failed: 1` ampliado com a pegadinha nome técnico × visível e a
     query SQL de diagnóstico

### `scripts/install_debian_prereqs.sh` — **novo**

Módulo idempotente de preparação/correção para rodar **antes** do
instalador (ou em appliances já implantados para auditar/consertar):
pacotes, geoip2, serviços, logs, todo o modelo de permissões da seção 2,
fixes de configuração (DG_ZBX_SERVER, ServerName), firewall na ordem
segura e as mesmas validações finais do instalador.

---

## 5. Boas práticas operacionais documentadas

- **DebugLevel:** logs do server em nível 4/5 são para troubleshooting;
  em produção voltar a 3 (`zabbix_server -R log_level_decrease` ou
  `DebugLevel=3` + restart).
- **HTTPS no ingest:** o token trafega no header `X-DG-Token` em texto
  claro — para agentes remotos (Windows, FortiGate), publicar o ingest
  atrás de HTTPS. Agente local ao appliance pode usar loopback se o
  vhost escutar em 127.0.0.1.
- **Memória com clamd:** em appliance de 3,8 GiB, o clamd (~960 MiB)
  deixa a folga crítica; criar trigger no Zabbix para
  `vm.memory.size[available]` < 500 MiB ou migrar para scan agendado.
- **Itens SNMP inválidos geram ruído:** OIDs inexistentes no equipamento
  (caso real: Mikrotik CCR 1009, sinais RX/TX índices 3–9 → "No Such
  Object" + 14 triggers não avaliáveis) devem ser desabilitados no host.
- **Nunca rode `freshclam` manual** com `clamav-freshclam` ativo.

---

## 6. Pendências conhecidas

| # | Item | Ação sugerida |
|---|---|---|
| 1 | `setup.py` aceita `IP:porta` no prompt do `DG_ZBX_SERVER` | Validar a resposta: se contiver `:`, avisar e usar só o host (`val.split(":")[0]`) |
| 2 | Logrotate pode recriar logs com modo ≠ 644 | Documentar/aplicar `create 0644 root adm` em `/etc/logrotate.d/rsyslog` se o agente voltar a perder leitura |
| 3 | GeoLite2 exige download manual (licença MaxMind) | Avaliar prompt no instalador para caminho de um `.mmdb` já baixado |

---

## Ambiente de validação

| Componente | Versão / detalhe |
|---|---|
| SO | Debian 13 (Apache 2.4.67, MariaDB) |
| Zabbix | Server + Frontend + Agent 7.4.11 |
| Frontend | Apache, porta 6030 |
| Python | 3.x (agente via systemd, como root) |
| ClamAV | freshclam daemon 1.4.3, clamd ativo (~960 MiB) |
| Resultado final | Heartbeat e contadores populando; ingest < 1 s; journal sem 401/timeout |

---

## v2.1 — Correções adicionais de campo (2026-07-06)

Bugs encontrados durante implantação no servidor Debian 13 de produção.

### Bugs corrigidos

| # | Sintoma | Causa | Correção |
|---|---|---|---|
| 1.7 | Agente usa URL hardcoded (`http://127.0.0.1/ddosguard/ingest.php`) ignorando o `agent.conf` | `agent.conf` com `root:root 600` — usuário `zabbix` (User= no systemd) não conseguia ler | `chown root:zabbix` + `chmod 640` — grupo zabbix pode ler, outros não |
| 1.8 | `zabbix_sender: command not found` — itens não populam no Zabbix | `zabbix-sender` não vem instalado no Debian por padrão | Adicionado à lista de pacotes do instalador (`apt install zabbix-sender`) |
| 1.9 | `provision_dashboard.py` timeout ao usar IP:porta externo | IP público (`45.237.78.245:9003`) inacessível de dentro do servidor (NAT/proxy) | Usar `http://localhost/zabbix/` para execução local |

### Modelo de permissões corrigido

O `agent.conf` contém o token de autenticação — precisa ser protegido
mas legível pelo serviço:

| Arquivo | Dono:Grupo | Modo | Por quê |
|---|---|---|---|
| `/etc/zabbix/ddos_guard_agent.conf` | `root:zabbix` | `640` | Token protegido; serviço systemd (User=zabbix) precisa ler |

> **Atenção:** `root:root 600` impede que o usuário `zabbix` leia o arquivo.
> O agente falha silenciosamente no `configparser.read()` e usa o default
> hardcoded em vez da URL configurada.

### URL do ingest — local vs externo

| Contexto | URL correta |
|---|---|
| Agente no **mesmo servidor** | `http://localhost/zabbix/ddosguard/ingest.php` |
| Agente em **outro servidor** | `http://IP_PUBLICO:PORTA/zabbix/ddosguard/ingest.php` |
| `provision_dashboard.py` (local) | `http://localhost/zabbix/` |

### Ambiente de validação v2.1

| Componente | Versão |
|---|---|
| SO | Debian 12 (bookworm) |
| Zabbix | Server + Frontend + Agent 7.4.11 |
| Frontend | Apache porta 80 (NAT → 9003 externo) |
| Resultado | Todos os 8 itens populando; correlação ativa; dashboard funcionando |

---

## v2.2 — Syslog Forwarder e correções Debian (2026-07-08)

Implantação em ambiente real com detecção de ataque DDoS ativo
(1.57 Gbps no CONCENTRADOR BORDA) no primeiro dia de uso.

### Novos arquivos

| Arquivo | Descrição |
|---|---|
| `scripts/integrations/syslog_forwarder.py` | Forwarder Python que lê `/var/log/ddosguard-syslog.log` e envia ao ingest.php — substitui o `omprog` do rsyslog quando o módulo não está disponível |
| `templates/template_ddos_guard_mikrotik.yaml` | Template DDoS Guard para MikroTik (11 itens, 12 triggers, 10 macros) |
| `scripts/integrations/mikrotik_receiver.php` | Receiver syslog específico para MikroTik com parser de log_prefix (DG-DROP, DG-SCAN, DG-BRUTE) |

### Bugs corrigidos

| # | Sintoma | Causa | Correção |
|---|---|---|---|
| 1.9 | `install_integrations.sh` retorna erro no Debian | Webroot detectado como `/var/www/html` em vez de `/usr/share/zabbix/ui` | Cópia manual para o caminho correto |
| 2.0 | `omprog` não disponível no rsyslog 8.x Debian | Módulo separado não instalado por padrão | Substituído por `syslog_forwarder.py` rodando como serviço systemd |
| 2.1 | Forwarder usa URL externa com timeout | `ingest_url` no `agent.conf` apontava para IP:porta externo | Corrigido para `localhost` + detecção automática |
| 2.2 | Arquivo do forwarder não criado pelo heredoc | Terminal cortou o heredoc em linha longa | Reescrito com `python3 << 'EOF'` usando raw string |
| 2.3 | `agent.conf` ilegível pelo usuário `zabbix` | `root:root 600` — `User=zabbix` no systemd não conseguia ler | `chown root:zabbix 640` |
| 2.4 | `zabbix_sender` não encontrado no Debian | Não instalado por padrão | Adicionado ao instalador: `apt install zabbix-sender` |

### Detecção de ataque real em produção

No primeiro dia de uso em ambiente de produção real (ISP/provedor):
- **CONCENTRADOR BORDA (MikroTik CCR)** detectou flood de **1.57 Gbps**
  num link de 200 Mbps — ataque DDoS vindo pelo PPPoE de terceiros
- O DDoS Guard disparou alerta às **09:31** com histórico de 20+ eventos
  nos últimos 2 dias (maior evento: 9h 4min de duração)
- Dashboard SOC registrou **61 eventos, 181 tentativas, 43 IPs distintos**
  de US, CA, GB, FR, NL, DE, SG atacando o Zabbix Server na porta 3000
- Relatório HTML gerado automaticamente e enviado ao cliente com
  evidências com timestamps para acionar o provedor upstream

### Configuração MikroTik para syslog

```
/system logging action
  set [find name=remote] remote=IP_DO_ZABBIX remote-port=514 target=remote

/system logging
  add topics=firewall action=remote
  add topics=critical action=remote

/ip firewall filter
  add chain=input action=log log-prefix="DG-BRUTE:" \
      protocol=tcp dst-port=22,8291 connection-limit=5,32 place-before=0
  add chain=input action=log log-prefix="DG-DROP:" \
      connection-state=invalid place-before=0
  add chain=input action=log log-prefix="DG-SCAN:" \
      protocol=tcp tcp-flags=fin,psh,urg,!syn place-before=0
```

### Ambiente de validação v2.2

| Componente | Detalhe |
|---|---|
| SO | Debian 12 (bookworm) |
| Zabbix | 7.4.11 — Apache porta 80 (NAT → 6030/9003 externo) |
| MikroTik | CCR — CONCENTRADOR BORDA |
| Resultado | Ataque DDoS real detectado e documentado no primeiro dia |

---

## v2.3 — Integração Sophos XG/XGS + Central + Intercept X (2026-07-15)

### Novos arquivos

| Arquivo | Descrição |
|---|---|
| `scripts/integrations/sophos_receiver.php` | Receiver syslog para Sophos — parseia formato SFOS e CEF, classifica por log_type e envia ao ingest.php |
| `templates/template_ddos_guard_sophos.yaml` | Template Zabbix com 9 itens, 8 triggers e 7 macros para Sophos XG/XGS |

### Produtos suportados

| Produto | Método | Formato |
|---|---|---|
| Sophos XG / XGS Firewall | Syslog UDP 514 | SFOS (Device Standard Format) |
| Sophos XG / XGS Firewall | Syslog UDP 514 | CEF (Common Event Format) |
| Sophos Central | Via Syslog Forwarder Windows | JSON → SFOS |
| Sophos Intercept X | Via Syslog Forwarder Windows | JSON → SFOS |

### Detecções implementadas

| Log Sophos (log_type) | Tipo DDoS Guard | MITRE | Score |
|---|---|---|---|
| Firewall / Deny | `block_firewall` | — | 3 |
| IPS / Detection | `IPS_DETECTION` | T1190 | 6 |
| IPS / SYN Flood | `SYN_FLOOD` | T1498.001 | 8 |
| IPS / SQL Inject | `SQL_INJECTION` | T1190 | 6 |
| IPS / Port Scan | `PORT_SCAN` | T1595 | 4 |
| Anti-Virus | `MALWARE` | T1204 | 7 |
| **ATP** | **`C2_COMMUNICATION`** | **T1071** | **9** |
| Web Filter | `WEB_ATTACK` | T1190 | 4 |
| Anti-Spam | `SPAM` | T1566 | 2 |
| Firewall / SSH (22) | `BRUTE_FORCE_SSH` | T1110.001 | 5 |
| Firewall / RDP (3389) | `BRUTE_FORCE_RDP` | T1110 | 5 |

### Triggers do template

| Trigger | Criticidade | Condição |
|---|---|---|
| Volume crítico de bloqueios firewall | HIGH | ≥ 1.000 bloqueios/min |
| Pico de bloqueios firewall | WARNING | ≥ 100 bloqueios/min |
| Volume crítico IPS | HIGH | ≥ 500 detecções/min |
| Pico IPS | WARNING | ≥ 50 detecções/min |
| Malware detectado | HIGH | ≥ 5 detecções em 10min |
| **ATP / C2 detectado** | **DISASTER** | **Qualquer detecção** |
| Ataque distribuído | HIGH | ≥ 30 IPs distintos |
| Pipeline syslog parado | WARNING | Sem heartbeat por 30min |

> **ATP = DISASTER:** qualquer detecção de comunicação C2/botnet é crítica
> porque indica comprometimento ativo de um dispositivo na rede.

### Configuração mínima no Sophos XG/XGS

```
System > Administration > Notification Settings
> Log Settings > Syslog Server > Add
  Name:     DDoS Guard
  IP:       IP_DO_APPLIANCE_ZABBIX
  Port:     514
  Facility: LOCAL0
  Format:   Device Standard Format (SFOS)
  Severity: Information
> Log Types: ✅ Firewall ✅ IPS ✅ Anti-Virus ✅ ATP ✅ Web Filter
```

Via CLI (SFOS):
```
system syslog add name "DDoSGuard" ipaddress IP_ZABBIX port 514
system syslog update name "DDoSGuard" logcomponent all
system syslog enable
```

### Sophos Central / Intercept X

O Sophos Central não envia syslog nativo. Três opções:

1. **Sophos Syslog Forwarder** — instale no servidor Windows gerenciado
   pelo Central. Encaminha eventos para o appliance Zabbix.

2. **API + syslog_forwarder.py** — use a API REST do Sophos Central
   para buscar eventos e encaminhar via syslog local.

3. **XG como proxy** — configure o Sophos XG para receber eventos
   do Central e reencaminhar via syslog para o Zabbix.

---

## v2.4 — Revisão geral: templates, agente e módulos de dashboard (2026-07-27)

### Templates — 53 itens corrigidos em 6 templates

| Problema | Causa | Correção |
|---|---|---|
| Itens TRAP sem `delay` definido | Campo obrigatório omitido | `delay: '0'` (TRAP não faz polling) |
| Itens sem `history` definido | Campo omitido | `30d` para numéricos, `7d` para texto/JSON |
| Itens sem `trends` definido | Campo omitido | `365d` para numéricos, `0` para texto |
| Macros sem `description` | Documentação ausente | Descrição adicionada em todas as macros |
| UUIDs inválidos (com hífens) | Geração incorreta | `uuid.uuid4().hex` — 32 chars hex sem hífens |
| UUIDs dos template_groups aleatórios | Não batem com o Zabbix | UUIDs oficiais do Zabbix 7.4 restaurados |

**Templates atualizados:**

| Template | Itens | Triggers | Macros |
|---|---|---|---|
| DDoS Guard - Security Monitoring | 8 | 5 | 0 |
| DDoS Guard - Agent | 8 | 6 | 0 |
| DDoS Guard - Agent Windows | 9 | 7 | 6 |
| DDoS Guard - FortiGate Security | 8 | 7 | 9 |
| DDoS Guard - FortiSwitch Security | 7 | 6 | 3 |
| DDoS Guard - MikroTik Security | 11 | 12 | 10 |
| DDoS Guard - Sophos Security | 9 | 8 | 7 |

### Agente Python (ddos_guard_agent.py) — v2.0 → v2.4

| Melhoria | Descrição |
|---|---|
| Graceful shutdown | `SIGTERM`/`SIGINT` encerram o agente limpo via `threading.Event` |
| Retry com backoff | `send()` tenta 3× com espera 1s, 2s, 4s antes de desistir |
| Versão no log | Startup mostra `v2.4.0`, host e interval |
| Logging com nível | Prefixos `[INFO]`, `[WARN]`, `[ERROR]` em todos os logs |
| Loop não-bloqueante | `_shutdown_event.wait(timeout=interval)` — shutdown imediato |
| `agent_version` no payload | Enviado ao ingest para rastreabilidade de versão |
| Verificação Python 3.8+ | Instalador valida versão mínima do Python |

### Módulos de dashboard — v2.3 → visual unificado

| Módulo | O que mudou |
|---|---|
| `DDoSSOCOverview` | Reescrito com `CWidgetView` — KPIs + timeline + alertas + hosts |
| `DDoSMitreHeatmap` | Reescrito com `CWidgetView` — heatmap 6 táticas MITRE |
| `DDoSTimeline` | Reescrito com `CWidgetView` — incidentes + MTTD/MTTA/MTTM |
| `DDoSBlockMonitor` | View atualizada — cards com barra, top países, tabela melhorada |

**Problema raiz dos widgets em branco:**
As views retornavam HTML puro via `->show()` diretamente.
O Zabbix 7.4 exige `(new CWidgetView($data))->addItem(...)->show()`
para encapsular a resposta em JSON `{"name":"...","body":"...","messages":[]}`.

### Formato de atualização do dashboard (RF rate)

O dashboard atualiza a cada **60s** por padrão. Para tempo real (30s):
```sql
UPDATE widget SET rf_rate = 30
WHERE dashboard_pageid IN (
    SELECT dashboard_pageid FROM dashboard_page WHERE dashboardid = 407
);
```
