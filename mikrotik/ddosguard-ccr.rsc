# =====================================================================
# DDoS Guard - Configuracao MikroTik RouterOS (v2.0)
# Testado em: RouterOS 6.49.19 / CCR1009-7G-1C-1S+
#
# ANTES DE APLICAR, ajuste as variaveis abaixo.
#
# Aplicar:
#   /import file-name=ddosguard-ccr.rsc
#
# Ou cole bloco a bloco em /terminal. NAO cole a saida do terminal de
# volta nele -- cada linha vira um comando invalido.
# =====================================================================

:local zabbixIP    "172.29.100.70"
:local adminIP     "186.220.197.160"
:local mgmtNet     "172.29.100.68/30"

# ---------------------------------------------------------------------
# 1. Envio de syslog para o coletor
# ---------------------------------------------------------------------
# ARMADILHA COMUM: o Remote Address precisa ser o IP do COLETOR, nunca o
# IP do proprio roteador. Pacotes gerados pelo router para o proprio IP
# publico saem pelo chain "output" e nao passam pelo dstnat, entao o
# port-forward nunca e aplicado e o log morre no proprio equipamento.
#
# syslog-facility=local7  -> permite isolar em arquivo proprio no rsyslog
# syslog-severity=auto    -> preserva a severidade real da mensagem
# bsd-syslog=yes          -> formato RFC 3164, parseavel pelo rsyslog

/system logging action
remove [find name="syslogremoto"]
add name=syslogremoto target=remote remote=$zabbixIP remote-port=514 \
    bsd-syslog=yes syslog-facility=local7 syslog-severity=auto

/system logging
remove [find action="syslogremoto"]
remove [find topics~"firewall" and action="remote"]
add topics=firewall action=syslogremoto
add topics=info     action=syslogremoto

# ---------------------------------------------------------------------
# 2. Heartbeat -- prova que o canal esta vivo mesmo sem ataque
# ---------------------------------------------------------------------
# Sem isso, um pipeline morto fica indistinguivel de "nao houve evento".
/system scheduler
remove [find name="ddosguard-heartbeat"]
add name=ddosguard-heartbeat interval=1m \
    on-event=":log info \"DDOSGUARD-HEARTBEAT alive\""

# ---------------------------------------------------------------------
# 3. Address lists de apoio
# ---------------------------------------------------------------------
/ip firewall address-list
remove [find list="DDOSGUARD-WHITELIST"]
add list=DDOSGUARD-WHITELIST address=$zabbixIP comment="Zabbix Server"
add list=DDOSGUARD-WHITELIST address=$mgmtNet  comment="Rede de gerencia"
add list=DDOSGUARD-WHITELIST address=$adminIP  comment="Admin"

# ---------------------------------------------------------------------
# 4. Firewall -- chain input
# ---------------------------------------------------------------------
# A ORDEM E CRITICA. As regras precisam estar exatamente nesta sequencia:
#
#   0  accept established,related   <- sem isso, trafego de RESPOSTA
#                                      (Google, Cloudflare) entra como
#                                      "new" e vira falso positivo
#   1  accept whitelist             <- protege Zabbix e admin de se
#                                      autobloquearem
#   2+ deteccao
#
# tcp-flags=syn,!ack,!fin,!rst garante que so SYN puro conte como
# tentativa de conexao. Sem essa flag, pacotes RST/ACK tardios de
# sessoes ja expiradas no conntrack sao contados como scan.

/ip firewall filter

add chain=input action=accept connection-state=established,related \
    comment="DDoS Guard 00: established/related" \
    place-before=0

add chain=input action=accept src-address-list=DDOSGUARD-WHITELIST \
    comment="DDoS Guard 01: whitelist"

# --- Port scan: escada de 4 niveis em 10s ---
add chain=input action=drop src-address-list=DDOSGUARD-PORTSCAN \
    log=yes log-prefix="DDOSGUARD-PORTSCAN" \
    comment="DDoS Guard 02: drop port scan"

add chain=input action=add-src-to-address-list protocol=tcp \
    connection-state=new tcp-flags=syn,!ack,!fin,!rst \
    src-address-list=DDOSGUARD-PS-3 \
    address-list=DDOSGUARD-PORTSCAN address-list-timeout=1h \
    comment="DDoS Guard 03: portscan nivel 4"

add chain=input action=add-src-to-address-list protocol=tcp \
    connection-state=new tcp-flags=syn,!ack,!fin,!rst \
    src-address-list=DDOSGUARD-PS-2 \
    address-list=DDOSGUARD-PS-3 address-list-timeout=10s \
    comment="DDoS Guard 04: portscan nivel 3"

add chain=input action=add-src-to-address-list protocol=tcp \
    connection-state=new tcp-flags=syn,!ack,!fin,!rst \
    src-address-list=DDOSGUARD-PS-1 \
    address-list=DDOSGUARD-PS-2 address-list-timeout=10s \
    comment="DDoS Guard 05: portscan nivel 2"

add chain=input action=add-src-to-address-list protocol=tcp \
    connection-state=new tcp-flags=syn,!ack,!fin,!rst \
    address-list=DDOSGUARD-PS-1 address-list-timeout=10s \
    comment="DDoS Guard 06: portscan nivel 1"

# --- Brute force em SSH / Telnet / Winbox ---
add chain=input action=drop protocol=tcp dst-port=22,23,8291 \
    src-address-list=DDOSGUARD-BF-BLOCK \
    log=yes log-prefix="DDOSGUARD-BRUTEFORCE" \
    comment="DDoS Guard 07: drop brute force"

add chain=input action=add-src-to-address-list protocol=tcp \
    dst-port=22,23,8291 connection-state=new \
    src-address-list=DDOSGUARD-BF-3 \
    address-list=DDOSGUARD-BF-BLOCK address-list-timeout=1d \
    comment="DDoS Guard 08: bruteforce nivel 4"

add chain=input action=add-src-to-address-list protocol=tcp \
    dst-port=22,23,8291 connection-state=new \
    src-address-list=DDOSGUARD-BF-2 \
    address-list=DDOSGUARD-BF-3 address-list-timeout=1m \
    comment="DDoS Guard 09: bruteforce nivel 3"

add chain=input action=add-src-to-address-list protocol=tcp \
    dst-port=22,23,8291 connection-state=new \
    src-address-list=DDOSGUARD-BF-1 \
    address-list=DDOSGUARD-BF-2 address-list-timeout=1m \
    comment="DDoS Guard 10: bruteforce nivel 2"

add chain=input action=add-src-to-address-list protocol=tcp \
    dst-port=22,23,8291 connection-state=new \
    address-list=DDOSGUARD-BF-1 address-list-timeout=1m \
    comment="DDoS Guard 11: bruteforce nivel 1"

# ---------------------------------------------------------------------
# 5. NAO logar drop generico no forward
# ---------------------------------------------------------------------
# Logar todo pacote dropado de cliente PPPoE gera dezenas de mensagens
# por SEGUNDO. Com o pipeline ativo, cada uma vira um processo PHP e um
# INSERT no banco. Logue apenas as regras de deteccao.
/ip firewall filter set [find action=drop chain=forward log=yes] log=no

# ---------------------------------------------------------------------
# 6. Endurecimento de acesso
# ---------------------------------------------------------------------
/snmp community set [find] addresses="$zabbixIP/32"
/ip service set www-ssl address="$zabbixIP/32"
/ip service set www     address="$zabbixIP/32"

# Usuario somente-leitura para a API binaria (RouterOS 6 nao tem REST)
# Ajuste a senha antes de aplicar.
# /user add name=zabbix-ro group=read password=TROQUE_ESTA_SENHA \
#     address="$zabbixIP/32"
# /ip service set api address="$zabbixIP/32" disabled=no

# ---------------------------------------------------------------------
# 7. Verificacao
# ---------------------------------------------------------------------
:put "--- logging ---"
/system logging print
:put "--- regras com log ---"
/ip firewall filter print stats where log=yes
:put "--- heartbeat ---"
/log print where message~"DDOSGUARD-HEARTBEAT"
:put "--- alcance do coletor ---"
/ping $zabbixIP count=3
