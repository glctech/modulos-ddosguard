#!/bin/bash
# =====================================================================
# DDoS Guard - Alimenta o item trapper ddosguard.distinct_ips.rate
# Cron sugerido: */5 * * * *
# =====================================================================
set -uo pipefail

DB="${DG_DB:-webtelecom}"
ZBX_HOST="${DG_ZBX_HOST:-MIKROTIK CCR 1009}"
ZBX_SERVER="${DG_ZBX_SERVER:-127.0.0.1}"
ZBX_PORT="${DG_ZBX_PORT:-10051}"

N=$(mysql -N -e "SELECT COUNT(DISTINCT src_ip) FROM ddosguard_blocks \
    WHERE event_time > NOW() - INTERVAL 5 MINUTE;" "$DB" 2>/dev/null)

/usr/bin/zabbix_sender -z "$ZBX_SERVER" -p "$ZBX_PORT" \
    -s "$ZBX_HOST" -k ddosguard.distinct_ips.rate -o "${N:-0}"
