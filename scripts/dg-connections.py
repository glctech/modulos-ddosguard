#!/usr/bin/env python3
# =====================================================================
# DDoS Guard - Alimenta o item trapper ddosguard.mtk.connections
#
# RouterOS 6.x nao expoe o total de conexoes por SNMP (o OID
# 1.3.6.1.4.1.14988.1.1.6.1.0 retorna sempre 0) e nao tem REST API
# (introduzida apenas na 7.1). Por isso usamos a API binaria na 8728.
#
# Requer: pip3 install librouteros --break-system-packages
# No CCR : /ip service set api address=<IP_ZABBIX>/32 disabled=no
#
# Cron sugerido: * * * * *   (no crontab do ROOT -- o arquivo e 700
# porque contem credencial)
# =====================================================================
import os
import subprocess
import sys

from librouteros import connect

MTK_HOST = os.environ.get("DG_MTK_HOST", "45.70.216.68")
MTK_USER = os.environ.get("DG_MTK_USER", "zabbix-ro")
MTK_PASS = os.environ.get("DG_MTK_PASS", "TROQUE_ESTA_SENHA")
ZBX_HOST = os.environ.get("DG_ZBX_HOST", "MIKROTIK CCR 1009")
ZBX_SERVER = os.environ.get("DG_ZBX_SERVER", "127.0.0.1")
ZBX_PORT = os.environ.get("DG_ZBX_PORT", "10051")

try:
    api = connect(username=MTK_USER, password=MTK_PASS, host=MTK_HOST)
    total = 0
    # tracking/print devolve UMA linha com o total ja somado.
    # Iterar /ip/firewall/connection traria ~28k objetos a cada minuto.
    for row in api("/ip/firewall/connection/tracking/print"):
        total = int(row.get("total-entries", 0))
    api.close()
except Exception as exc:
    print("erro ao consultar o MikroTik: %s" % exc, file=sys.stderr)
    sys.exit(1)

if total:
    subprocess.run([
        "/usr/bin/zabbix_sender",
        "-z", ZBX_SERVER, "-p", ZBX_PORT,
        "-s", ZBX_HOST,
        "-k", "ddosguard.mtk.connections",
        "-o", str(total),
    ])
