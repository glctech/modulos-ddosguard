# DDoS Guard — Diagnóstico do pipeline de syslog

O pipeline tem sete camadas. **Todas falham em silêncio.** O rsyslog sobe
normalmente com blocos de configuração quebrados, o PHP não escreve em
lugar nenhum quando o `require` mata o processo, e o `zabbix_sender`
retorna `failed: 1` sem que ninguém leia a saída.

Este guia percorre as camadas na ordem em que o dado viaja. Não pule
etapas: um sintoma na camada 6 quase sempre tem causa na 2.

```
MikroTik ─1→ rede ─2→ rsyslog ─3→ omprog ─4→ PHP ─5→ MySQL ─6→ sender ─7→ Zabbix
```

---

## Diagnóstico rápido

Rode os quatro na sequência. O primeiro que falhar aponta a camada.

```bash
# 1. Os pacotes chegam?
timeout 10 tcpdump -n -i any udp port 514

# 2. O rsyslog grava?
date; tail -3 /var/log/mikrotik/ccr1009.log

# 3. O PHP reclama? (vazio = bom)
tail -c 2000 /var/log/ddosguard-omprog.log

# 4. Chega ao banco?
mysql -e "SELECT block_id, src_ip, reason, event_time \
  FROM ddosguard_blocks ORDER BY 1 DESC LIMIT 5;" <BANCO>
```

---

## Camada 1 — O MikroTik está gerando log?

```
/log print where message~"DDOSGUARD"
/system logging print
/ip firewall filter print stats where log=yes
```

**Nenhuma linha `DDOSGUARD-*`**: as regras de detecção não existem ou
estão abaixo de um `accept` que as impede de casar. Confira a ordem com
`/ip firewall filter print where chain=input`.

**Só heartbeat, nenhum evento de firewall**: normal em rede sem ataque.
O heartbeat existe exatamente para distinguir "sem eventos" de "pipeline
morto".

**Nem heartbeat**: verifique o scheduler (`/system scheduler print`) e se
existe uma regra `topics=info action=syslogremoto`.

---

## Camada 2 — O pacote sai do roteador e chega ao coletor?

No coletor:

```bash
timeout 15 tcpdump -n -i any udp port 514
```

Esperado: linhas `SYSLOG local7.*`.

**Nada capturado** e `/log print` no CCR mostra as mensagens → o problema
é o destino do syslog.

```
/system logging action print
/ping <IP_DO_COLETOR> count=4
```

> ### A armadilha mais comum de todas
>
> `Remote Address` apontando para o **IP público do próprio roteador**.
>
> Parece razoável — é o IP pelo qual você acessa tudo. Mas pacotes
> gerados pelo próprio router saem pelo chain `output` e **não passam
> pelo `dstnat`**, então o port-forward nunca se aplica. O pacote é
> entregue ao próprio equipamento e morre ali.
>
> O `Remote Address` tem que ser o IP do **coletor**. Se ele está atrás
> de NAT, use o **IP interno** dele.
>
> ```
> /ip address print          # o IP aqui NUNCA deve ir na action
> /ip firewall nat print where dst-port=<porta_web_do_zabbix>
> ```
>
> O campo `to-addresses` dessa regra de NAT é o IP interno do coletor.

Anote também o **IP de origem** que aparece no tcpdump. Ele pode ser
diferente do IP que você usa para administrar o CCR (o roteador escolhe a
interface de saída conforme a rota), e é esse que vai no filtro
`$fromhost-ip` do rsyslog.

Outros pontos da action que causam dor de cabeça depois:

| Campo | Valor certo | Se errado |
|---|---|---|
| `Remote Port` | 514 | Porta da interface web não é porta de syslog |
| `Syslog Facility` | `local7` | `syslog` (5) se mistura com o log do próprio daemon |
| `Syslog Severity` | `auto` | Fixo carimba tudo igual e destrói o filtro por severidade |
| `BSD Syslog` | marcado | Sem RFC 3164 o rsyslog parseia nos campos errados |

---

## Camada 3 — O rsyslog está escutando e gravando?

```bash
ss -lunp | grep :514
rsyslogd -N1
journalctl -u rsyslog -n 30 --no-pager
```

> ### O rsyslog não aborta com config quebrada
>
> Ele registra o erro, **ignora o bloco** e continua rodando. O
> `systemctl status` mostra `active (running)` e tudo parece normal.
> Sempre leia o journal, não o status.

### Erro: `module 'imudp' already in this config`

Dois arquivos em `/etc/rsyslog.d/` carregam o mesmo módulo. O rsyslog lê
em ordem alfabética (`-` vem antes de `.`), e o input acaba vinculado ao
ruleset do arquivo que falhou.

```bash
grep -rn 'imudp\|ruleset(name="ddosguard")' /etc/rsyslog.conf /etc/rsyslog.d/
```

Deixe **um** arquivo. Mova os outros para fora do diretório.

### Erro: `module name 'omprog' is unknown`

Falta `module(load="omprog")`. O `.so` existe no pacote principal do
rsyslog — não há pacote `rsyslog-omprog` no Debian:

```bash
ls /usr/lib/x86_64-linux-gnu/rsyslog/ | grep omprog
```

### Erro: `messages must be terminated with \n at end of message`

O template da action `omprog` não termina em `\n`. Templates nativos como
`RSYSLOG_TraditionalForwardFormat` **não incluem** a quebra de linha, e o
omprog rejeita 100% das mensagens.

Use o template `DGProgFmt` de `rsyslog/ddosguard-syslog.conf`.

### O arquivo não é criado

Se o input está vinculado a um ruleset nomeado (`ruleset="ddosguard"`),
as mensagens **não passam pelo ruleset padrão**. Uma action escrita fora
do bloco `ruleset(name="ddosguard")` nunca é avaliada.

---

## Camada 4 — O omprog está executando o PHP?

```bash
ps aux | grep "[s]yslog_receiver.php"
tail -c 2000 /var/log/ddosguard-omprog.log
```

O processo PHP deve aparecer **uma vez** e ficar vivo. O omprog não sobe
um processo por mensagem: ele mantém o binário rodando e alimenta o
stdin.

> ### O bug que só aparece em produção
>
> ```php
> $lines = [];
> while (($line = fgets(STDIN)) !== false) { $lines[] = trim($line); }
> foreach ($lines as $line) { ... }   // nunca alcançado
> ```
>
> Em teste manual (`echo ... | php script.php`) o STDIN encerra, `fgets`
> retorna `false`, e tudo funciona. Sob omprog o pipe **nunca fecha** —
> o script acumula linhas em memória para sempre e o `foreach` jamais
> roda.
>
> Sintoma: funciona perfeitamente quando você testa, e nunca em produção.
>
> Correção: generator, processando cada linha assim que chega.
>
> ```php
> $lines = (function () {
>     while (($line = fgets(STDIN)) !== false) { yield trim($line); }
> })();
> ```

---

## Camada 5 — O PHP está processando?

Teste isolado, com uma linha real copiada do log:

```bash
echo 'Jul 31 06:47:49 45.70.216.69 POP3CA DDOSGUARD-PORTSCAN input: in:sfp1 out:(unknown 0), proto TCP (SYN), 203.0.113.9:44123->45.70.216.68:22, len 40' \
  | php -d display_errors=1 -d error_reporting=E_ALL \
    /usr/share/zabbix/ui/ddosguard/integrations/syslog_receiver.php
```

### Saída `{"ok":false,"error":"invalid token"}`

O `require_once` do `ingest.php` está executando o endpoint HTTP. O
`ingest.php` tem código em nível superior que valida o token e chama
`respond()`, que encerra com `exit` — antes de o receiver processar
qualquer coisa.

Confirme em 5 segundos:

```bash
php -r "require '/usr/share/zabbix/ui/ddosguard/ingest.php'; echo 'CHEGUEI AO FIM';"
```

Se imprimir o erro e **não** imprimir `CHEGUEI AO FIM`, é isso.

Correção: o guard de modo biblioteca (v3). Exportar a variável de
ambiente `HTTP_X_DG_TOKEN` **não** resolve — sob CLI o PHP não popula
`$_SERVER` com headers.

### Saída vazia e nada no banco

O parser descartou a linha em silêncio:

```php
if (!$normalized || empty($normalized['src_ip'])) continue;
```

Adicione um log temporário logo antes desse `continue`:

```php
error_log("DG-DEBUG descartado [$platform]: $line");
```

E acompanhe com `tail -f /var/log/syslog`.

Causa mais comum: `detect_platform()` não reconhece o formato e cai no
parser genérico, que exige `SRC=` (sintaxe do iptables). O MikroTik usa
`IP:porta->IP:porta` e nunca casaria.

---

## Camada 6 — Chegou ao banco?

```bash
mysql -e "SELECT block_id, src_ip, reason, tool, event_time \
  FROM ddosguard_blocks WHERE tool='mikrotik' \
  ORDER BY 1 DESC LIMIT 10;" <BANCO>
```

Use `tool='mikrotik'` como filtro. `source_platform` só passou a ser
preenchido na v3 — em bases antigas ele é NULL e o filtro não retorna
nada, o que engana.

**Para de gravar depois de algumas horas, sem erro aparente**: o
`wait_timeout` do MySQL (8h por padrão) derrubou a conexão do processo
persistente. A v3 descarta o handle no `catch` e reconecta na linha
seguinte.

---

## Camada 7 — O Zabbix recebeu?

Teste direto:

```bash
zabbix_sender -z 127.0.0.1 -p 10051 \
  -s "MIKROTIK CCR 1009" \
  -k ddosguard.block.firewall \
  -o '{"teste":1}' -vv
```

`processed: 1` = o caminho está aberto e o problema é upstream.

> ### Host com espaço no nome quebra o `-i -`
>
> O `send_to_zabbix()` monta linhas e alimenta o `zabbix_sender -i -`,
> onde os campos são separados por **espaço**. Sem aspas, um host como
> `MIKROTIK CCR 1009` é lido como:
>
> ```
> host = MIKROTIK
> key  = CCR
> value= 1009 ddosguard.block.firewall {...}
> ```
>
> Resultado: `processed: 0; failed: 1` — e ninguém lê essa saída, porque
> o `proc_open` descarta o stdout.
>
> Reproduza:
>
> ```bash
> printf '%s\n' 'MIKROTIK CCR 1009 ddosguard.agent.heartbeat 1' \
>   | zabbix_sender -z 127.0.0.1 -p 10051 -i - -vv   # falha
> printf '%s\n' '"MIKROTIK CCR 1009" ddosguard.agent.heartbeat 1' \
>   | zabbix_sender -z 127.0.0.1 -p 10051 -i - -vv   # passa
> ```

Outras causas de rejeição:

- **Nome errado.** O sender exige o nome **técnico** (`hosts.host`), não
  o visível (`hosts.name`). Costumam ser iguais, mas não é garantido.
- **Item não é trapper.** Confirme o tipo (2 = trapper):

  ```bash
  mysql -e "SELECT i.key_, i.type, r.state, r.error \
    FROM items i LEFT JOIN item_rtdata r ON r.itemid=i.itemid \
    WHERE i.hostid=<HOSTID> AND i.key_ LIKE 'ddosguard%'\G" <BANCO>
  ```

  No Zabbix 6.0+ a coluna `state` saiu de `items` e foi para
  `item_rtdata` — daí o join.

---

## Itens permanentemente vazios

Antes de investigar coleta, confirme se **alguém escreve** no item. Itens
trapper sem produtor ficam vazios para sempre, e isso não é falha.

| Item | Quem alimenta |
|---|---|
| `ddosguard.mtk.portscan` | receiver, ao ver `DDOSGUARD-PORTSCAN` |
| `ddosguard.mtk.bruteforce` | receiver, ao ver `DDOSGUARD-BRUTEFORCE` |
| `ddosguard.mtk.connections` | cron `dg-connections.py` |
| `ddosguard.distinct_ips.rate` | cron `dg-distinct-ips.sh` |
| `ddosguard.attack.event` | ninguém (ver limitações no README) |

### `ddosguard.mtk.cpu.util` não suportado

A fórmula original era `last(//system.cpu.util[,idle])` — chave do
**agente Zabbix em Linux**, que não existe num host SNMP. Use:

```
avg(last_foreach(//system.cpu.util[*]))
```

Dois detalhes que custam tempo:

- O wildcard substitui um **parâmetro inteiro**, não parte dele.
  `system.cpu.util[hrProcessorLoad.*]` não casa nada.
- Testar item calculado com `foreach` **no template** sempre falha: `//`
  resolve para o próprio template, que não tem os itens SNMP. Salve com
  *Atualizar* e verifique no host.

---

## Falsos positivos na detecção

### Google e Cloudflare entrando na lista de port scan

Sintoma: `172.217.*`, `142.250.*`, `104.21.*` em `DDOSGUARD-PORTSCAN`,
com origem **porta 443**. Isso é tráfego de resposta de conexões que seus
clientes iniciaram.

Duas causas, e você provavelmente tem as duas:

1. **Falta `accept established,related` como primeira regra.** Sem ela,
   todo pacote de retorno passa pelas regras de detecção.
2. **A regra não exige SYN puro.** Pacotes RST/ACK tardios, de sessões já
   expiradas no conntrack (UDP expira em 10s), chegam como `new`.

```
/ip firewall filter add chain=input connection-state=established,related \
    action=accept place-before=0

/ip firewall filter set [find address-list~"DDOSGUARD-P"] \
    tcp-flags=syn,!ack,!fin,!rst

/ip firewall address-list remove [find list~"DDOSGUARD-P"]
```

> **Escaneadores furtivos** (FIN, NULL, XMAS) não usam SYN e passam por
> essa regra. Detectá-los exige uma regra separada, com lógica própria —
> não reaproveite a mesma escada.

### Você bloqueou o próprio Zabbix

Sintoma: `nmap` de teste a partir do coletor, e logo depois o host
aparece "down" e todos os itens SNMP param.

O scan colocou o IP do Zabbix na address-list e a regra de drop bloqueia
tudo dele, inclusive SNMP.

```
/ip firewall address-list remove [find list~"DDOSGUARD-P" address=<IP_ZABBIX>]
```

**Crie a whitelist antes de qualquer regra de detecção**, e teste sempre
de um IP externo — nunca do coletor.

---

## Volume: quando o sucesso vira problema

Logar todo pacote dropado no `forward` de uma rede com clientes PPPoE
gera **dezenas de mensagens por segundo**. Com o pipeline funcionando,
cada uma vira um INSERT no banco e uma chamada ao `zabbix_sender`.

```
/ip firewall filter set [find action=drop chain=forward log=yes] log=no
```

Logue apenas as regras de detecção. Uma regra de port scan bem calibrada
gera dezenas de eventos por **dia**, não por segundo.

Configure também a retenção antes que a tabela cresça:

```sql
CREATE EVENT IF NOT EXISTS ddosguard_purge
  ON SCHEDULE EVERY 1 DAY
  DO DELETE FROM ddosguard_blocks
     WHERE event_time < NOW() - INTERVAL 90 DAY;
SET GLOBAL event_scheduler = ON;
```

---

## Descoberta SNMP inflando o host

Um CCR com clientes PPPoE atribui um `ifIndex` novo a cada reconexão. Sem
filtro, a descoberta acumula milhares de itens órfãos que continuam sendo
consultados, saturando a fila de pollers e derrubando a coleta de itens
legítimos.

```bash
mysql -e "SELECT COUNT(*) total, SUM(r.state=1) nao_suportados \
  FROM items i LEFT JOIN item_rtdata r ON r.itemid=i.itemid \
  WHERE i.hostid=<HOSTID>;" <BANCO>
```

Um CCR1009 saudável tem ~200 itens. Se aparecerem milhares, aplique o
filtro de descoberta descrito em [ITEMS.md](../zabbix/ITEMS.md).

---

## Dashboard: erros do `provision_dashboard.py`

### `Session terminated, re-login, please.`

```
RuntimeError: Erro da API Zabbix em dashboard.get: {'code': -32602,
  'message': 'Invalid params.', 'data': 'Session terminated, re-login, please.'}
```

A mensagem sugere sessão expirada, mas na prática significa **credencial
inválida**. A causa mais comum é passar o placeholder da documentação:

```bash
python3 provision_dashboard.py --url ... --token TOKEN    # ← literal
```

Gere um token real em **Users → API tokens → Create API token** — o valor
só aparece uma vez, na criação. Ou autentique com usuário e senha:

```bash
--user Admin --password SUA_SENHA
```

Se o token era válido e parou de funcionar, verifique se ele tem data de
expiração e se o usuário associado continua ativo e com permissão de
criar dashboards.

### `não foi possível verificar os módulos`

O script tenta `module.get` antes de criar o dashboard. Quando a chamada
falha por motivo que **não** seja autenticação, ele apenas avisa e segue
— a verificação é conveniência, não requisito.

Se a mensagem aparecer junto de um erro de autenticação logo depois, a
causa é a credencial, não os módulos.

Para pular a verificação:

```bash
--skip-module-check
```

### `[FALTA] módulo 'X' não está instalado`

O widget existe no dashboard mas o módulo não foi publicado no frontend:

```bash
bash scripts/install_modules.sh
```

E habilite em **Administration → General → Modules**. Módulo instalado
mas desabilitado aparece como `[OFF]`.

### Widget aparece vazio no dashboard

Antes de investigar coleta, confirme qual tabela o widget lê:

| Widget | Tabela | Alimentado por |
|---|---|---|
| SOC Overview | `blocks` + `attacks` + `correlations` | tudo |
| Block Monitor | `blocks` | tudo |
| Attack Monitor | `attacks` + `host_status` | agente, Suricata, Wazuh, Sophos |
| Response Timeline | `attacks` | idem |
| MITRE Heatmap | `attacks` | idem |

O `syslog_receiver.php` emite sempre `event_type=block_firewall`, então
numa instalação **só com MikroTik** a tabela `ddosguard_attacks` nunca é
populada e os três últimos ficam permanentemente vazios. Isso não é
falha de coleta — use `--preset mikrotik`.

### `Já existe um dashboard com esse nome`

```bash
--force          # apaga e recria
--name "Outro"   # cria em paralelo
```

### Conferir o layout antes de criar

`--dry-run` imprime o JSON que seria enviado e **não exige credencial**:

```bash
python3 provision_dashboard.py --url http://IP/zabbix --dry-run
```

Útil também para conferir se a `--url` está certa: use o endereço do
frontend com o caminho, se houver (`http://IP/zabbix` num appliance
padrão, `http://IP:8080` num Docker com porta publicada). O script
acrescenta `/api_jsonrpc.php` sozinho.

---

## A lição que sustenta tudo isso

Cinco falhas independentes, nenhuma gerando erro visível, sistema
aparentando funcionar. O que teria encurtado o diagnóstico de horas para
minutos não era uma ferramenta melhor — era o heartbeat.

```
nodata(/MIKROTIK CCR 1009/ddosguard.agent.heartbeat,5m)=1
```

Um sinal periódico e independente do evento monitorado transforma
"silêncio" em informação. Sem ele, ausência de dados é ambígua: pode ser
tranquilidade ou pode ser cegueira, e você não tem como saber qual.

Configure o heartbeat **primeiro**, antes de qualquer regra de detecção.
