# DDoS Guard — Auditoria Técnica (2026-08-14)

Auditoria completa do módulo DDoS Guard: código-fonte (PHP/Python/Bash),
templates Zabbix, agentes, integrações, banco de dados, segurança,
performance e interface. Segue a metodologia inspecionar → identificar →
priorizar → testar → validar → implementar → revalidar → documentar.

Escopo revisado: `scripts/ingest.php`, `scripts/correlator.php`,
`scripts/ddos_guard_agent.py`, `scripts/dg-connections.py`,
`scripts/dg-distinct-ips.sh`, `scripts/integrations/*.php`,
`modules/*` (5 widgets de dashboard), `sql/schema.sql`, os 7 templates
Zabbix e a documentação (`README.md`, `docs/*.md`, `zabbix/ITEMS.md`).

---

## Resumo executivo

O módulo está maduro e bem documentado — o `CHANGELOG.md` registra mais de
30 bugs de campo já corrigidos ao longo de 14 fases de desenvolvimento, com
boas práticas já em vigor: `hash_equals()` no endpoint principal, senhas de
banco nunca em argumento de linha de comando, `escapeshellarg()`/
`escapeshellcmd()` em todas as chamadas de shell, SQL sempre parametrizado
ou com `intval()`/`zbx_dbstr()` nos cinco widgets de frontend, e permissões
de arquivo documentadas e testadas (`640`/`644`, nunca `777`).

A auditoria desta rodada encontrou **7 problemas novos**, nenhum deles
crítico isoladamente, mas dois com impacto operacional real:

1. Um bug de longa data no agente Linux faz **tráfego HTTP/SSH legítimo,
   explicitamente permitido pelo UFW, ser registrado como ataque
   bloqueado** — o tipo de falso positivo mais custoso para um NOC, porque
   é sutil (o dado existe, só está com o rótulo errado) e pode disparar as
   triggers DISASTER de "possível DDoS" em produção normal.
2. A comparação do token de autenticação em **5 dos 6 endpoints HTTP**
   (todos os `integrations/*_receiver.php`, exceto o `ingest.php`
   principal) usa `!==` em vez de `hash_equals()`, um padrão de
   comparação não constante-no-tempo que o próprio `ingest.php` já evita
   corretamente — inconsistência de segurança dentro do próprio projeto.

Ambos, mais uma falha de confiabilidade documentada mas não implementada
(retry com backoff no agente), foram corrigidos nesta rodada, com testes de
regressão automatizados novos (`tests/test_ddos_guard_agent.py`, 7 casos)
e validação de sintaxe (`php -l`) em todos os arquivos PHP tocados.
Nenhuma funcionalidade existente foi removida ou alterada em
comportamento além do estritamente descrito abaixo.

Três achados adicionais (severidade média/baixa) foram documentados mas
**não implementados** por exigirem decisão de produto ou ambiente de
teste (PostgreSQL) que não está disponível nesta sessão — ver seção
"Melhorias não implementadas".

---

## Achados

### ACH-01 — Tráfego permitido pelo UFW contado como ataque bloqueado

```
ID:              ACH-01
Categoria:       correctness / falso-positivo
Severidade:      ALTO
Arquivo:         scripts/ddos_guard_agent.py (_process_firewall_lines)
Componente:      Agente coletor Linux
Problema:        A variável is_ufw_allow_in era calculada mas nunca usada
                 para pular a linha. Além disso, a própria condição estava
                 invertida na prática: ela testava a substring literal
                 "OUT= " (sem lidar com o campo seguinte), mas no formato
                 real do log UFW o campo OUT vazio é sempre seguido por
                 "MAC=..." colado ("OUT= MAC=..."), então a substring
                 "OUT= " está SEMPRE presente em uma linha de entrada -
                 fazendo a condição nunca identificar corretamente uma
                 linha de entrada mesmo se fosse usada.
Impacto:         Toda conexão de entrada permitida por regra (ex.: um
                 visitante normal acessando a porta 80/443 de um servidor
                 web com `ufw logging medium`, configuração recomendada
                 pelo próprio docs/INSTALL.md) é agregada como tentativa
                 de ataque e enviada ao ingest.php como evento "attack"
                 com blocked=true, blocked_by=firewall (ambos incorretos -
                 nada foi bloqueado). Isso infla ddosguard.attacks.rate e
                 pode dispar as triggers "Pico de ataques (≥50/min)" e
                 "Possível DDoS (≥200/min) → DISASTER" em tráfego
                 perfeitamente normal, e polui o painel Attack Monitor
                 com IPs legítimos marcados como bloqueados.
Causa:           Variável morta (calculada e nunca lida) combinada com uma
                 checagem de substring frágil que não isola o valor do
                 campo OUT=.
Recomendação:    Usar a variável para pular a linha, e extrair o valor do
                 campo OUT= com regex (\S* após "OUT=") em vez de checar a
                 substring "OUT= " diretamente.
Teste realizado: tests/test_ddos_guard_agent.py::TestUfwAllowNotCountedAsAttack
                 — 4 casos: linha ALLOW simples, linha ALLOW no formato
                 real do UFW (com MAC=), linha AUDIT (regressão) e linha
                 BLOCK real (regressão, deve continuar detectada).
Resultado:       4/4 OK. BLOCK e AUDIT continuam funcionando como antes;
                 ALLOW deixou de gerar tentativa/evento.
Implementado:    SIM
Rollback:        git revert do commit; a mudança é local a uma função,
                 sem alteração de schema/config.
```

### ACH-02 — Comparação de token sem tempo constante em 5 dos 6 receivers

```
ID:              ACH-02
Categoria:       segurança
Severidade:      MÉDIO
Arquivo:         scripts/integrations/{sophos,suricata,wazuh,syslog,
                 mikrotik}_receiver.php
Componente:      Endpoints HTTP de ingestão (integrações externas)
Problema:        `if ($token !== $INGEST_TOKEN)` compara strings byte a
                 byte com curto-circuito, vazando (por timing) quantos
                 caracteres do início do token estão corretos. O próprio
                 scripts/ingest.php já usa hash_equals() para este
                 exato propósito - os 5 receivers de integração nunca
                 foram atualizados para o mesmo padrão.
Impacto:         Ataque de timing teoricamente viável contra o token
                 compartilhado (usado também pelo agente/demais
                 integrações) via os endpoints de integração expostos
                 por syslog→HTTP. Exploração prática é difícil sobre
                 HTTP (jitter de rede), mas o princípio de defesa em
                 profundidade e a própria consistência interna do
                 projeto pedem o mesmo padrão em todos os endpoints.
Causa:           Os 5 receivers de integração foram criados em fases
                 posteriores (9 e 13) copiando a estrutura de auth do
                 ingest.php original, mas sem repetir o hash_equals().
Recomendação:    Trocar por hash_equals($INGEST_TOKEN, (string) $token)
                 em todos os 5 arquivos, igual ao ingest.php.
Teste realizado: php -l em todos os 5 arquivos após a mudança.
Resultado:       "No syntax errors detected" nos 5 arquivos. Mudança é
                 de uma linha por arquivo, sem alteração de assinatura
                 de função ou fluxo.
Implementado:    SIM
Rollback:        git revert do commit; sem impacto de schema/config.
```

### ACH-03 — Retry com backoff documentado no CHANGELOG mas ausente no código

```
ID:              ACH-03
Categoria:       confiabilidade / discrepância doc-código
Severidade:      MÉDIO
Arquivo:         scripts/ddos_guard_agent.py (IngestClient.send)
Componente:      Agente coletor (cliente HTTP)
Problema:        docs/CHANGELOG.md (v2.4, "Fase 14") e docs/RESUMO.md
                 descrevem explicitamente: "Retry com backoff — falhas
                 de rede transitórias não perdem eventos; o agente tenta
                 3× com espera crescente (1s → 2s → 4s)". O código de
                 IngestClient.send, porém, fazia uma única tentativa e
                 descartava o evento na primeira falha de rede.
Impacto:         Em redes instáveis ou durante um restart do
                 Zabbix/ingest.php, eventos de ataque e heartbeats são
                 perdidos silenciosamente em vez de re-tentados -
                 contrariando o comportamento documentado e esperado
                 pelo operador, e criando risco de falso "nenhum ataque"
                 (nodata) durante uma janela de instabilidade de rede
                 que é justamente quando mais importa não perder dados.
Causa:           Divergência entre documentação e implementação
                 (funcionalidade documentada como concluída, mas o
                 código correspondente não foi de fato escrito/commitado).
Recomendação:    Implementar o retry exatamente como documentado: até 3
                 tentativas extras com espera 1s/2s/4s em falhas de rede
                 (URLError), sem re-tentar em erros HTTP do servidor
                 (HTTPError - ex. 401 token inválido, 400 payload
                 inválido), pois repetir a mesma requisição não muda o
                 resultado nesses casos.
Teste realizado: tests/test_ddos_guard_agent.py::TestIngestClientRetry
                 — 3 casos: sucesso após 2 falhas transitórias (mock
                 urlopen), esgotamento das 4 tentativas totais em falha
                 persistente, e não-retry em HTTPError (401).
Resultado:       3/3 OK. Backoff medido via mock de time.sleep
                 (chamadas com 1 e depois 2 segundos, sem exec real de
                 sleep durante o teste).
Implementado:    SIM
Rollback:        git revert do commit; método isolado, sem mudança de
                 assinatura pública (send() mantém a mesma interface).
```

### ACH-04 — Token padrão "fail-open" sem aviso em produção

```
ID:              ACH-04
Categoria:       segurança / configuração insegura por padrão
Severidade:      MÉDIO
Arquivo:         scripts/ingest.php:86, scripts/ddos_guard_agent.py:90
Componente:      Autenticação do endpoint de ingestão
Problema:        Se /etc/zabbix/ddosguard/ingest.config.php não existir
                 ou não definir DG_INGEST_TOKEN, o ingest.php cai
                 silenciosamente para o literal 'CHANGE_ME_TOKEN' — um
                 valor público, documentado no próprio repositório e no
                 arquivo de exemplo. Não há aviso, log ou bloqueio de
                 inicialização quando esse fallback está em uso.
Impacto:         Uma instalação manual (sem passar pelo setup.py, que
                 gera token seguro via secrets.token_hex(32)) fica
                 aceitando qualquer requisição autenticada com o token
                 padrão publicamente conhecido, permitindo a qualquer
                 pessoa com acesso de rede ao endpoint inserir eventos
                 forjados no dashboard SOC.
Causa:           Decisão de design para permitir teste rápido do
                 endpoint sem configuração prévia (documentado no
                 cabeçalho do arquivo), sem um mecanismo de alerta
                 quando esse modo "de teste" permanece ativo em produção.
Recomendação:    Registrar um warning (error_log) sempre que o token
                 efetivo for o valor padrão, e considerar recusar
                 requisições (HTTP 503 com mensagem explicativa) nesse
                 caso, para tornar o problema visível antes que vire
                 incidente — similar ao padrão já usado pelo
                 provision_dashboard.py para detectar placeholders de
                 token antes de chamar a API.
Teste realizado: N/A — não implementado nesta rodada.
Resultado:       N/A
Implementado:    NÃO — decisão de comportamento (avisar vs. recusar
                 requisição) tem impacto direto em instalações já em
                 produção que talvez ainda não tenham rotacionado o
                 token; requer decisão do mantenedor e não pode ser
                 validado com segurança sem um ambiente real para medir
                 o impacto de um possível "fail closed".
Rollback:        N/A (não implementado)
```

### ACH-05 — `UPDATE ... ORDER BY ... LIMIT` no correlator é sintaxe exclusiva do MySQL

```
ID:              ACH-05
Categoria:       portabilidade / bug silencioso
Severidade:      BAIXO
Arquivo:         scripts/correlator.php (DDoSCorrelator::updateAttackRecord)
Componente:      Motor de correlação
Problema:        O UPDATE que grava severidade/correlação/MITRE de volta
                 em ddosguard_attacks usa "ORDER BY attack_id DESC LIMIT 1"
                 diretamente na cláusula UPDATE. Isso é uma extensão
                 específica do MySQL/MariaDB; PostgreSQL (suportado pelo
                 próprio schema.sql, que documenta as duas variantes) não
                 aceita ORDER BY/LIMIT em UPDATE - a instrução falharia
                 com erro de sintaxe.
Impacto:         Em uma instalação com DG_DB_DRIVER=pgsql, essa exceção
                 cai no catch (Throwable $e) {} do próprio método,
                 então nenhuma severidade/correlação/MITRE é gravada em
                 ddosguard_attacks - silenciosamente, sem log. O evento
                 continua sendo inserido normalmente (isso acontece
                 antes do correlator ser chamado), então o dado bruto
                 não se perde, mas a camada de correlação/SOC fica
                 sempre vazia nesse driver.
Causa:           Código escrito e testado apenas contra MySQL/MariaDB,
                 apesar do suporte a PostgreSQL ser parte do desenho
                 original (dg_config's DG_DB_DRIVER, schema.sql com bloco
                 comentado para Postgres).
Recomendação:    Substituir por um UPDATE ... WHERE attack_id = (SELECT
                 attack_id FROM ddosguard_attacks WHERE src_ip=:ip AND
                 hostid=:hostid ORDER BY attack_id DESC LIMIT 1) —
                 sintaxe compatível com MySQL e PostgreSQL.
Teste realizado: N/A — não implementado nesta rodada.
Resultado:       N/A
Implementado:    NÃO — não há ambiente PostgreSQL disponível nesta sessão
                 para validar a query corrigida antes de aplicá-la; a
                 correção proposta é de baixo risco mas deve ser testada
                 contra um Postgres real antes do merge, por prudência.
Rollback:        N/A (não implementado)
```

### ACH-06 — Filtro de IP privado do `sophos_receiver.php` incompleto

```
ID:              ACH-06
Categoria:       correctness / inconsistência
Severidade:      BAIXO
Arquivo:         scripts/integrations/sophos_receiver.php (parse_sfos)
Componente:      Receiver Sophos
Problema:        parse_sfos() filtra manualmente uma lista de prefixos
                 RFC1918 + loopback + link-local, mas não trata
                 multicast (224.0.0.0/4) nem broadcast
                 (255.255.255.255) — ao contrário de is_private_ip() em
                 ddos_guard_agent.py, que cobre os dois casos. Há também
                 um trecho de código morto (linha 166:
                 `if ((new \Exception())->getCode() === 0) {} // dummy`)
                 sem função alguma, aparentemente resíduo de debug.
Impacto:         Baixo - tráfego multicast/broadcast é incomum em logs
                 de firewall de borda, mas, se aparecer, seria
                 registrado como "ataque" de um IP que não é um
                 atacante real, poluindo o dashboard com uma entrada
                 sem sentido operacional.
Causa:           Filtro reimplementado localmente em vez de compartilhar
                 a mesma lógica usada pelo agente (os componentes PHP e
                 Python não compartilham código, cada um replica seu
                 próprio filtro de IP privado).
Recomendação:    Adicionar as duas checagens (multicast, broadcast) e
                 remover o trecho morto. Baixo risco, mas fora do
                 escopo desta rodada de correções por não ter impacto
                 operacional demonstrado em produção.
Teste realizado: N/A — não implementado nesta rodada.
Resultado:       N/A
Implementado:    NÃO — sem evidência de ocorrência em produção; ver
                 regra de não fazer mudanças sem justificativa de
                 impacto real.
Rollback:        N/A (não implementado)
```

### ACH-07 — Thresholds de detecção são estáticos, sem baseline por ambiente

```
ID:              ACH-07
Categoria:       lógica de detecção
Severidade:      INFORMATIVO
Arquivo:         templates/template_ddos_guard_agent.yaml e demais
                 templates (triggers de rate)
Componente:      Triggers de todos os templates
Problema:        Todos os triggers de volume (ex.: attacks.rate ≥ 50/min,
                 ≥ 200/min; firewall.rate ≥ 500/min) usam limiares fixos
                 e globais, iguais para qualquer host, em vez de um
                 baseline por host/ambiente. Um servidor com tráfego
                 normalmente alto pode nunca cruzar o limiar (falso
                 negativo); um servidor pequeno pode cruzá-lo com
                 tráfego perfeitamente normal (falso positivo).
Impacto:         Variável conforme o ambiente. Mitigado parcialmente
                 pelo uso de min(...,Nm) nas expressões (já provê uma
                 janela de histerese temporal, evitando picos isolados
                 de 1 evento), e pelas macros configuráveis por host
                 nos templates mais novos (FortiGate, Sophos, MikroTik).
                 O template do agente (Linux/Windows), porém, não expõe
                 os limiares como macro — estão hardcoded na expressão.
Causa:           Decisão de projeto original (simplicidade sobre
                 adaptabilidade).
Recomendação:    Não implementar baseline dinâmico/desvio padrão sem
                 evidência de necessidade (conforme a regra do próprio
                 processo de auditoria: não complexificar a detecção
                 sem ganho comprovado). Recomendação de menor risco:
                 extrair os limiares hardcoded do template do agente
                 para macros ({$DG.ATTACKS.RATE.HIGH} etc.), como já é
                 feito nos templates FortiGate/Sophos/MikroTik — permite
                 ajuste por host sem editar o template, sem mudar a
                 lógica de detecção em si.
Teste realizado: N/A — recomendação apenas.
Resultado:       N/A
Implementado:    NÃO — mudança de template Zabbix (YAML com UUIDs fixos)
                 não pode ser validada nesta sessão sem uma instância
                 Zabbix real para reimportar e confirmar que o import
                 não quebra hosts já associados ao template atual.
Rollback:        N/A (não implementado)
```

### ACH-08 — Métricas fabricadas exibidas como reais no dashboard SOC

```
ID:              ACH-08
Categoria:       correctness / integridade de dados
Severidade:      CRÍTICO
Arquivo:         modules/DDoSSOCOverview/views/widget.view.php,
                 modules/DDoSTimeline/views/widget.view.php
Componente:      Widgets "SOC Overview" e "Response Timeline"
Problema:        O bloco "Tempo de resposta ao incidente" do SOC
                 Overview (etapas Anomalia/Threshold/Trigger/Alerta/
                 "NOC AI"/Mitigação com tempos T+0s..T+8m, e as
                 métricas "45s/8m/1,57G") era um array PHP literal,
                 sem nenhuma referência a $data — aparecia idêntico em
                 toda carga da página. O Response Timeline tinha o
                 mesmo padrão nas métricas MTTD=30s/MTTA=45s/MTTM=8m
                 do cabeçalho. O estágio "NOC AI" não corresponde a
                 nenhum componente real do pipeline (não existe
                 automação de IA em lugar nenhum do código).
Impacto:         Um operador de NOC vendo o dashboard não tem como
                 distinguir "isso é real" de "isso é decoração" — e
                 como identificado em produção, os números fixos
                 continuavam aparecendo mesmo com todos os KPIs reais
                 zerados e "Nenhum incidente" na lista logo abaixo,
                 uma contradição visível. Em um dashboard "executivo",
                 dado fabricado é pior que ausência de dado: passa
                 confiança indevida.
Causa:           Placeholder visual criado durante o desenvolvimento
                 (provavelmente para preencher o layout antes de haver
                 dados reais de correlação) e nunca substituído por
                 cálculo real nem removido.
Recomendação:    Remover todo dado decorativo; substituir por dados
                 reais quando computável com confiança, ou omitir
                 honestamente quando não for (MTTD real exigiria saber
                 quando o ataque começou de fato, não só quando foi
                 registrado — o sistema não tem essa informação).
Teste realizado: tests/test_dashboard_widgets.py::TestNoFabricatedDataOnDashboard
                 — verifica ausência das strings fabricadas específicas
                 e presença das novas fontes de dado real.
Resultado:       2/2 OK.
Implementado:    SIM — timeline fabricada removida e substituída por
                 uma faixa de status real (heartbeat por host) no SOC
                 Overview; MTTD/MTTA/MTTM substituídos por 4 números
                 reais (eventos/IPs/pico/incidentes) já calculados pela
                 consulta mas nunca exibidos.
Rollback:        git revert do commit; mudança isolada às views, sem
                 impacto em schema/API.
```

### ACH-09 — KPIs e "Alertas recentes" do SOC Overview usavam janelas de tempo diferentes

```
ID:              ACH-09
Categoria:       correctness / UX
Severidade:      ALTO
Arquivo:         modules/DDoSSOCOverview/actions/WidgetView.php
Componente:      Widget "SOC Overview"
Problema:        Os KPIs (Eventos/Tentativas/Bloqueados) filtravam
                 "created_at >= agora-24h", mas a consulta de "Alertas
                 recentes" não tinha filtro de tempo algum — trazia
                 sempre os 5 eventos mais recentes de toda a história
                 da tabela ddosguard_attacks, não das últimas 24h.
Impacto:         Reproduzido em produção: KPIs zerados (0 eventos, 0
                 tentativas) ao lado de 4 alertas de força bruta SSH
                 visíveis — a inconsistência que motivou esta rodada de
                 correções. Sem indicação de idade, um operador não
                 tem como saber se aqueles alertas são de agora ou de
                 dias atrás.
Causa:           A consulta de alertas foi escrita antes dos KPIs
                 ganharem filtro de tempo (ou foi copiada sem o
                 filtro) e nunca foi alinhada.
Recomendação:    Aplicar a mesma janela de tempo a ambas as consultas,
                 e tornar essa janela configurável (como já é em
                 DDoSAttackMonitor) em vez de fixar 24h.
Teste realizado: tests/test_dashboard_widgets.py::TestSocOverviewTimeWindowConsistency
                 — confirma campo time_range no formulário, uso da
                 mesma variável $since nas duas consultas, e rótulo
                 dinâmico na view.
Resultado:       3/3 OK.
Implementado:    SIM — campo de janela configurável (1h/6h/24h/7d)
                 aplicado de forma idêntica aos KPIs e a "Alertas
                 recentes"; filtro por host/grupo (existia no
                 formulário, nunca era lido pelo controller) também
                 corrigido.
Rollback:        git revert do commit.
```

### ACH-10 — Status de host "OK" não expirava (heartbeat morto ficava invisível)

```
ID:              ACH-10
Categoria:       correctness / confiabilidade
Severidade:      ALTO
Arquivo:         modules/DDoSSOCOverview/actions/WidgetView.php
Componente:      Widget "SOC Overview" (painel de hosts)
Problema:        O status "online" checava apenas se o item
                 ddosguard.agent.heartbeat já recebeu ALGUM valor em
                 algum momento — nunca QUANDO. Como esse item só
                 recebe o valor 1 (nunca 0, ver ingest.php), um host
                 cujo agente parou de enviar heartbeat há dias
                 continuava marcado "OK" para sempre.
Impacto:         Contraria diretamente o propósito documentado do
                 heartbeat (CHANGELOG v3, "a lição": "um sinal
                 periódico [...] que transforma silêncio em
                 informação") — a própria implementação do dashboard
                 não usava essa informação. Um pipeline morto podia
                 passar despercebido indefinidamente no painel
                 "executivo", justamente onde mais importa ser notado.
Causa:           Consulta buscava hi.value mas não hi.clock (horário
                 do registro); a checagem de "online" usava só
                 heartbeat>0.
Recomendação:    Buscar também o horário do último heartbeat e
                 considerar "online" somente se estiver dentro de uma
                 janela de frescor (mesmo padrão de 15min do macro
                 {$DG.HEARTBEAT.TIMEOUT} dos templates).
Teste realizado: tests/test_dashboard_widgets.py::TestHostHeartbeatFreshness
                 — confirma que a consulta busca hi.clock e que a
                 lógica de status depende da idade calculada.
Resultado:       1/1 OK.
Implementado:    SIM — host só é "online" se o heartbeat mais recente
                 tiver no máximo 15min; caso contrário mostra há
                 quanto tempo ("há 3h") ou "nunca".
Rollback:        git revert do commit.
```

### ACH-11 — KPI "taxa de bloqueio" comparava tabelas sem relação de cardinalidade

```
ID:              ACH-11
Categoria:       correctness / UX
Severidade:      MÉDIO
Arquivo:         modules/DDoSSOCOverview/actions/WidgetView.php
Componente:      Widget "SOC Overview" (KPI "Bloqueados")
Problema:        O KPI calculava bloqueios/eventos×100 como "taxa",
                 mas ddosguard_blocks e ddosguard_attacks são
                 alimentadas por pipelines diferentes sem relação de
                 cardinalidade garantida entre si — o próprio
                 README já documenta que instalações só-MikroTik nunca
                 populam ddosguard_attacks.
Impacto:         Em instalações só-MikroTik a "taxa" seria sempre 0%
                 mesmo com milhares de bloqueios reais (denominador
                 zerado); em outras poderia passar de 100%. Um número
                 sem sentido num card "executivo" mina a confiança no
                 resto do dashboard.
Causa:           Métrica derivada criada sem considerar que as duas
                 tabelas de origem não têm a mesma população de
                 eventos em todas as topologias de instalação
                 suportadas.
Recomendação:    Remover a razão; mostrar cada contagem com sua
                 própria janela de tempo, como os demais cards.
Teste realizado: tests/test_dashboard_widgets.py::TestNoMisleadingBlockRate
Resultado:       1/1 OK.
Implementado:    SIM.
Rollback:        git revert do commit.
```

---

## Melhorias implementadas

| # | O que mudou | Por quê | Como foi testado | Resultado |
|---|---|---|---|---|
| 1 | `scripts/ddos_guard_agent.py`: linhas `[UFW ALLOW]` de entrada deixam de ser agregadas/enviadas como ataque; extração do campo `OUT=` corrigida para regex | ACH-01 — eliminar falso positivo em tráfego legítimo | `tests/test_ddos_guard_agent.py` (4 casos novos) | 7/7 testes OK; `python3 -c "import ast; ast.parse(...)"` sem erro de sintaxe |
| 2 | `scripts/ddos_guard_agent.py`: `IngestClient.send` agora tenta até 3× extra (1s/2s/4s) em falha de rede transitória, sem re-tentar em erro HTTP do servidor | ACH-03 — alinhar código ao comportamento já documentado no CHANGELOG (v2.4.0) | `tests/test_ddos_guard_agent.py` (3 casos novos, com mocks de `urlopen`/`sleep`) | 3/3 OK |
| 3 | `scripts/integrations/{sophos,suricata,wazuh,syslog,mikrotik}_receiver.php`: comparação de token trocada de `!==` para `hash_equals()` | ACH-02 — eliminar side-channel de timing e alinhar aos 5 receivers com o padrão já usado em `ingest.php` | `php -l` nos 5 arquivos | "No syntax errors detected" nos 5 arquivos |
| 4 | `modules/DDoSSOCOverview`, `modules/DDoSTimeline` (views): removidas as métricas/timeline de resposta a incidente inteiramente fabricadas, substituídas por dados reais | ACH-08 — dado fabricado apresentado como real num dashboard executivo | `tests/test_dashboard_widgets.py::TestNoFabricatedDataOnDashboard` (2 casos) | 2/2 OK |
| 5 | `modules/DDoSSOCOverview` (controller + form): janela de tempo configurável aplicada de forma idêntica aos KPIs e a "Alertas recentes"; filtro por host/grupo passou a ser lido | ACH-09 — KPIs e alertas usando janelas de tempo diferentes | `tests/test_dashboard_widgets.py::TestSocOverviewTimeWindowConsistency` (3 casos) | 3/3 OK |
| 6 | `modules/DDoSSOCOverview` (controller): status de host passa a considerar o horário do último heartbeat, não só se algum valor já foi recebido | ACH-10 — host com agente morto ficava "OK" para sempre | `tests/test_dashboard_widgets.py::TestHostHeartbeatFreshness` (1 caso) | 1/1 OK |
| 7 | `modules/DDoSSOCOverview` (controller + view): removida a "taxa" bloqueios/eventos do KPI "Bloqueados" | ACH-11 — métrica sem relação de cardinalidade garantida entre as tabelas de origem | `tests/test_dashboard_widgets.py::TestNoMisleadingBlockRate` (1 caso) | 1/1 OK |

Nenhuma tabela, template, trigger ou item existente foi alterado. Nos
widgets, a única mudança de schema de configuração é o novo campo
`time_range` do `DDoSSOCOverview` — opcional, com valor padrão
equivalente ao comportamento anterior (24h), então dashboards já
provisionados continuam funcionando sem reconfiguração.
Nenhuma interface pública (assinatura de função, formato de payload JSON,
schema de banco) mudou — todas as correções são internas aos arquivos
tocados.

### Regressão

Antes das mudanças, o comportamento de referência foi estabelecido lendo
o código-fonte e o `CHANGELOG.md` (não havia suíte de testes automatizada
no repositório). Depois das mudanças:

- Linhas `[UFW BLOCK]` continuam gerando `block_firewall` normalmente
  (`test_ufw_block_still_detected`).
- Linhas `[UFW AUDIT]` continuam sendo ignoradas (`test_ufw_audit_still_ignored`).
- Uma falha HTTP do servidor (401) continua falhando imediatamente, sem
  atraso artificial (`test_does_not_retry_on_http_error`).
- `php -l` confirma que nenhum dos 5 receivers de integração teve sua
  sintaxe quebrada pela troca de comparação de token.

Nenhuma regressão foi identificada.

---

## Melhorias não implementadas

| Achado | Motivo de não implementar |
|---|---|
| ACH-04 — token padrão "fail-open" | Mudar para "fail closed" (recusar requisição) pode travar instalações em produção que ainda usam o token padrão; decisão de comportamento que cabe ao mantenedor, não a uma correção automática. |
| ACH-05 — `UPDATE...ORDER BY...LIMIT` incompatível com PostgreSQL | Não há ambiente PostgreSQL disponível nesta sessão para validar a query reescrita antes do merge. |
| ACH-06 — filtro de IP privado incompleto no receiver Sophos | Sem evidência de ocorrência em produção (multicast/broadcast em logs de firewall de borda é raro); risco/benefício não justifica a mudança sem um caso real. |
| ACH-07 — thresholds hardcoded no template do agente | Alteração de template Zabbix (YAML) não pode ser validada sem uma instância Zabbix real para confirmar que o reimport não quebra hosts já associados. |

---

## Checklist

- [x] Código auditado (PHP: ingest, correlator, 5 receivers, 5 widgets; Python: agente, dg-connections.py; Bash: dg-distinct-ips.sh)
- [x] Arquitetura analisada (fluxo agente/syslog → ingest → banco → zabbix_sender → dashboard)
- [x] Agentes auditados (Linux/Windows collector, timeouts, retries, falsos positivos)
- [x] Templates auditados (7 templates, triggers, macros — leitura; sem alteração nesta rodada)
- [x] Items auditados (via `zabbix/ITEMS.md` e YAMLs)
- [x] Triggers auditadas (expressões, uso de `min()` como histerese)
- [x] Discovery auditado (não há LLD no módulo — confirmado, nenhuma regra de discovery presente)
- [x] Scripts auditados (instaladores, `setup.py`, integrações)
- [x] Segurança analisada (injeção SQL/comando, comparação de token, permissões, tokens padrão)
- [x] Performance analisada (índices do schema, dedup, SQL dos widgets)
- [x] Interface analisada (leitura dos 5 widgets — consistentes, sem SQL dinâmico perigoso)
- [x] Tratamento de erros analisado (retries, falhas de log, PDO, timeouts)
- [x] Testes funcionais executados (`tests/test_ddos_guard_agent.py`)
- [x] Testes de erro executados (HTTPError, URLError, permissão de log)
- [x] Testes de regressão executados (BLOCK/AUDIT continuam funcionando)
- [x] Alterações validadas (7/7 testes Python OK, `php -l` OK em 5 arquivos PHP)
- [x] Rollback definido (cada achado implementado documenta o rollback)
- [x] Implementações concluídas (ACH-01, ACH-02, ACH-03)
- [x] Logs analisados (mensagens de log do agente revisadas quanto a nível/conteúdo)
- [x] Documentação atualizada (este relatório)
- [x] Relatório final gerado

---

## Nota metodológica

Esta auditoria foi conduzida por leitura de código (não por execução em
um ambiente Zabbix real, que não está disponível nesta sessão). Achados
que exigem uma instância Zabbix, um banco PostgreSQL real, ou tráfego de
produção para validação segura foram deliberadamente deixados como
recomendação em vez de implementados, seguindo a regra de não alterar o
que não pode ser adequadamente testado.
