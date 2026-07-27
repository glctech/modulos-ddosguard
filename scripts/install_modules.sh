#!/bin/bash
# DDoS Guard - Instalador de módulos Zabbix 7.4
# Copia os widgets para o diretório de módulos do Zabbix

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULE_SRC="$SCRIPT_DIR/../modules"

# Detecta webroot
for d in /usr/share/zabbix/ui /usr/share/zabbix /var/www/html/zabbix; do
    if [ -d "$d/modules" ]; then
        WEBROOT="$d"; break
    fi
done

[ -z "$WEBROOT" ] && { echo "[ERR] Webroot Zabbix não encontrado"; exit 1; }
echo "[OK] Webroot: $WEBROOT"

MODULES_DIR="$WEBROOT/modules"
mkdir -p "$MODULES_DIR"

# Copia cada módulo
for mod in \
    DDoSAttackMonitor \
    DDoSBlockMonitor \
    DDoSSOCOverview \
    DDoSTimeline \
    DDoSMitreHeatmap; do
    
    src="$MODULE_SRC/$mod"
    dst="$MODULES_DIR/$mod"
    
    if [ ! -d "$src" ]; then
        echo "[SKIP] $mod — não encontrado em $src"
        continue
    fi
    
    rm -rf "$dst"
    cp -r "$src" "$dst"
    chown -R www-data:www-data "$dst" 2>/dev/null || \
    chown -R apache:apache      "$dst" 2>/dev/null || true
    echo "[OK] $mod instalado em $dst"
done

echo ""
echo "======================================"
echo " Módulos instalados com sucesso!"
echo "======================================"
echo ""
echo " Próximos passos no Zabbix:"
echo " Administration → General → Modules"
echo " Clique em 'Scan directory'"
echo " Ative cada módulo DDoS Guard"
echo ""
echo " Depois:"
echo " Monitoring → Dashboards → Create dashboard"
echo " Add widget → selecione 'DDoS Guard - SOC Overview'"
echo ""
