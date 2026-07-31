# Itens do template `DDoS Guard - MikroTik Security`

Referência de todos os itens, tipo, e **quem os alimenta**. A coluna
"Fonte" é a que mais economiza tempo em diagnóstico: item vazio quase
sempre significa que ninguém escreve nele, não que a coleta falhou.

| Chave | Tipo | Valor | Fonte |
|---|---|---|---|
| `ddosguard.agent.heartbeat` | trapper | uint | `syslog_receiver.php`, ao ver `DDOSGUARD-HEARTBEAT` |
| `ddosguard.block.firewall` | trapper | texto | `ingest.php`, caso `block_firewall` |
| `ddosguard.firewall.rate` | trapper | uint | `ingest.php`, caso `block_firewall` |
| `ddosguard.mtk.portscan` | trapper | uint | `syslog_receiver.php`, `attack_type=PORT_SCAN` |
| `ddosguard.mtk.bruteforce` | trapper | uint | `syslog_receiver.php`, `attack_type=BRUTE_FORCE` |
| `ddosguard.mtk.connections` | trapper | uint | cron `dg-connections.py` (API binária) |
| `ddosguard.distinct_ips.rate` | trapper | uint | cron `dg-distinct-ips.sh` (query no banco) |
| `ddosguard.attack.event` | trapper | texto | `ingest.php`, caso `attack` — **não alimentado** |
| `ddosguard.mtk.cpu.util` | calculado | float | itens SNMP do template MikroTik |
| `ddosguard.mtk.mem.util` | calculado | float | itens SNMP do template MikroTik |
| `ddosguard.mtk.bw.flood` | calculado | float | itens SNMP do template MikroTik |

## Fórmula do item de CPU

A fórmula original do template era `last(//system.cpu.util[,idle])` —
chave do **agente Zabbix em Linux**, que não existe num host monitorado
por SNMP. O CCR expõe um item por núcleo:

```
system.cpu.util[hrProcessorLoad.1] ... [hrProcessorLoad.9]
```

Fórmula correta:

```
avg(last_foreach(//system.cpu.util[*]))
```

Duas observações que custaram tempo:

- O wildcard do Zabbix substitui um **parâmetro inteiro**, não parte
  dele. `system.cpu.util[hrProcessorLoad.*]` não casa nada.
- Testar item calculado com `foreach` **no template** sempre falha: `//`
  resolve para o próprio template, que não tem os itens SNMP. Salve com
  *Atualizar* e verifique no host.

Alternativa sem wildcard, se preferir explicitar:

```
(last(//system.cpu.util[hrProcessorLoad.1])+
 last(//system.cpu.util[hrProcessorLoad.2])+
 last(//system.cpu.util[hrProcessorLoad.3])+
 last(//system.cpu.util[hrProcessorLoad.4])+
 last(//system.cpu.util[hrProcessorLoad.5])+
 last(//system.cpu.util[hrProcessorLoad.6])+
 last(//system.cpu.util[hrProcessorLoad.7])+
 last(//system.cpu.util[hrProcessorLoad.8])+
 last(//system.cpu.util[hrProcessorLoad.9]))/9
```

## Trigger de heartbeat

O sistema ficou dias com o pipeline morto sem nenhum alarme. Esta
trigger é o que impede a repetição:

```
nodata(/MIKROTIK CCR 1009/ddosguard.agent.heartbeat,5m)=1
```

Severidade recomendada: **Average**. Nome:
`MikroTik: Pipeline syslog parou em {HOST.NAME}`

## Regra de descoberta de interfaces

Um CCR com clientes PPPoE gera um `ifIndex` novo a cada reconexão. Sem
filtro, a descoberta acumulou **12.349 itens**, a maioria órfã de
sessões encerradas, sufocando a fila de pollers SNMP.

Em *Descoberta → Network interfaces discovery → Filtros*:

| Macro | Condição | Expressão regular |
|---|---|---|
| `{#IFNAME}` | não corresponde | `^(pppoe\|<pppoe\|ppp\|l2tp\|pptp\|ovpn\|sstp)-.*` |

E em *Ciclo de vida dos itens perdidos*: `1h` ou "Excluir
imediatamente", em vez do padrão de 30 dias.
