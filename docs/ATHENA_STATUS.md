# Cliente Athena — Status do Monitoramento DDoS Guard

**Data:** 14/07/2026  
**Ambiente:** Zabbix 7.4.12 — monitor.dsr9.com  
**Módulo:** DDoS Guard SOC v2.2 — GLCTech

---

## Dispositivos monitorados

| Host | Tipo | Status geral |
|---|---|---|
| `FRW-ATH-BA-HA-MTZ-01` | FortiGate — Firewall/UTM/VPN | ✅ SNMP ativo |
| `FRW-ATH-CORE-MEDIMAGEM-01` | FortiGate — Firewall/UTM/VPN | ✅ SNMP ativo |

---

## Status dos itens — FRW-ATH-BA-HA-MTZ-01

| Item | Último valor | Status |
|---|---|---|
| Active sessions alert | **16.974 sessões** | ✅ Coletando (47s) |
| IPS blocked intrusions rate | **0 /min** | ✅ Coletando (48s) |
| VPN tunnels down | **9 túneis ativos** | ✅ Coletando (1m 46s) |
| Agent heartbeat | — | ⚠️ Aguarda syslog |
| FortiGate attack event (JSON) | — | ⚠️ Aguarda syslog |
| FortiGate AV block event (JSON) | — | ⚠️ Aguarda syslog |
| FortiGate block event (JSON) | — | ⚠️ Aguarda syslog |
| FortiGate firewall blocks/min | — | ⚠️ Aguarda syslog |

---

## Status dos itens — FRW-ATH-CORE-MEDIMAGEM-01

| Item | Último valor | Status |
|---|---|---|
| Active sessions alert | **78.934 sessões** 🔴 | ✅ Coletando (33s) |
| IPS blocked intrusions rate | **0 /min** | ✅ Coletando (34s) |
| VPN tunnels down | **75 túneis ativos** | ✅ Coletando (32s) |
| Agent heartbeat | — | ⚠️ Aguarda syslog |
| FortiGate attack event (JSON) | — | ⚠️ Aguarda syslog |
| FortiGate AV block event (JSON) | — | ⚠️ Aguarda syslog |
| FortiGate block event (JSON) | — | ⚠️ Aguarda syslog |
| FortiGate firewall blocks/min | — | ⚠️ Aguarda syslog |

> ⚠️ **Atenção:** `FRW-ATH-CORE-MEDIMAGEM-01` com **78.934 sessões ativas**.
> O threshold de alerta WARNING está em 50.000 e HIGH em 100.000.
> Monitorar de perto — se atingir 100k, trigger de saturação dispara.

---

## O que está funcionando (via SNMP)

```
✅ Active sessions     — número de conexões ativas no FortiGate
✅ IPS intrusions rate — taxa de bloqueios IPS por minuto
✅ VPN tunnels         — número de túneis IPsec ativos
✅ Alertas automáticos — 7 triggers configuradas por dispositivo
✅ Tags por componente — sessions, vpn, ips, firewall, antivirus
```

O SNMP está coletando a cada 30-60 segundos e os dados chegam corretamente
ao Zabbix. Os alertas disparam automaticamente se os thresholds forem atingidos.

---

## O que está pendente (requer syslog)

Os 5 itens abaixo dependem de logs em tempo real enviados pelo FortiGate
via **syslog UDP na porta 514**:

```
⚠️ Agent heartbeat           — confirma que o pipeline syslog está ativo
⚠️ FortiGate attack event    — alertas de ataques detectados pelo IPS/UTM
⚠️ FortiGate AV block event  — detecções do antivírus do FortiGate
⚠️ FortiGate block event     — bloqueios de firewall em tempo real
⚠️ FortiGate firewall blocks/min — contador de bloqueios por minuto
```

---

## Como ativar o syslog nos FortiGates

Execute no CLI de **cada FortiGate** (via SSH ou console):

### 1. Configura o destino do syslog

```
config log syslogd setting
    set status enable
    set server IP_DO_SERVIDOR_ZABBIX
    set port 514
    set format default
    set facility local7
end
```

### 2. Configura o filtro de severidade

```
config log syslogd filter
    set severity warning
    set forward-traffic enable
    set local-traffic disable
    set sniffer-traffic disable
end
```

### 3. Verifica se o syslog está enviando

```
diagnose log test
diagnose sniffer packet any "host IP_DO_SERVIDOR_ZABBIX and port 514" 4
```

### 4. Confirma no servidor Zabbix

```bash
# No servidor Zabbix — verifica se os logs chegam
tcpdump -i any port 514 -n 2>/dev/null | head -10

# Verifica o arquivo de syslog do DDoS Guard
tail -f /var/log/ddosguard-syslog.log
```

---

## Alertas configurados (por dispositivo)

| Trigger | Criticidade | Condição atual |
|---|---|---|
| Saturação de sessões (≥ 100k) | 🔴 HIGH | MTZ: 17% / MEDIMAGEM: 79% |
| Alto número de sessões (≥ 50k) | 🟡 WARNING | MTZ: OK / **MEDIMAGEM: ATIVO** |
| Pico de bloqueios IPS (≥ 100/min) | 🟡 WARNING | Aguarda syslog |
| Ataque IPS crítico (≥ 1.000/min) | 🔴 HIGH | Aguarda syslog |
| Queda de túneis VPN (> 2 túneis) | 🔴 HIGH | OK |
| Volume crítico de bloqueios (≥ 5k/min) | 🔴 HIGH | Aguarda syslog |
| Pipeline syslog parado (30min) | 🟡 WARNING | Aguarda syslog |

> 💡 Os thresholds são configuráveis por dispositivo via Macros do Zabbix:
> `{$MTK.SESSION.WARN}`, `{$FG.SESSION.HIGH}` etc.

---

## Próximos passos recomendados

- [ ] Configurar syslog nos dois FortiGates (seção acima)
- [ ] Ajustar threshold de sessões do `FRW-ATH-CORE-MEDIMAGEM-01` se 78k for normal
- [ ] Ativar `forward-traffic` no filtro de syslog para ver bloqueios de firewall
- [ ] Configurar envio automático de relatório por e-mail (report_sender.py)
- [ ] Revisar a política de VPN do `FRW-ATH-BA-HA-MTZ-01` (apenas 9 túneis vs 75 do CORE)

---

*Gerado por GLCTech — DDoS Guard SOC v2.2*  
*suporte@glctech.com.br — glctech.com.br*
