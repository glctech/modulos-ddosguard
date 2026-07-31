#!/bin/bash
# DDoS Guard - Instalador de Integrações SOC v2
# ==============================================
# Configura as integrações com Wazuh, Suricata, pfSense e FortiGate.
# Execute no appliance Zabbix como root.
#
# Uso:
#   bash install_integrations.sh [opções]
#
# Opções:
#   --webroot DIR    Webroot do Zabbix (padrão: detecta automaticamente)
#   --token TOKEN    Token do DDoS Guard (padrão: lê do ingest.config.php)
#   --yes            Aceita todos os defaults sem confirmar
#   --wazuh          Instala integração Wazuh
#   --suricata       Instala integração Suricata
#   --syslog         Instala receiver syslog (pfSense / FortiGate)
#   --all            Instala todas as integrações

set -euo pipefail

# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; exit 1; }
info() { echo -e "     $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(dirname "$SCRIPT_DIR")"
ASSUME_YES=0
INSTALL_WAZUH=0; INSTALL_SURICATA=0; INSTALL_SYSLOG=0

# Parse args
for arg in "$@"; do
    case "$arg" in
        --yes)      ASSUME_YES=1 ;;
        --wazuh)    INSTALL_WAZUH=1 ;;
        --suricata) INSTALL_SURICATA=1 ;;
        --syslog)   INSTALL_SYSLOG=1 ;;
        --all)      INSTALL_WAZUH=1; INSTALL_SURICATA=1; INSTALL_SYSLOG=1 ;;
        --webroot=*) WEBROOT="${arg#*=}" ;;
        --token=*)   TOKEN="${arg#*=}" ;;
    esac
done

echo "============================================================"
echo " DDoS Guard SOC - Instalador de Integrações v2"
echo "============================================================"
echo ""

# ----------------------------------------------------------------
# Detecta webroot automaticamente
# ----------------------------------------------------------------
if [ -z "${WEBROOT:-}" ]; then
    WEBROOT=$(grep -r "root " /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*.conf 2>/dev/null \
        | grep -v "#" | grep -oP "root\s+\K[^;]+" | head -1 || true)
    [ -z "$WEBROOT" ] && WEBROOT=$(grep -r "DocumentRoot" /etc/apache2/sites-enabled/*.conf \
        /etc/httpd/conf.d/*.conf 2>/dev/null | grep -oP "DocumentRoot\s+\K\S+" | head -1 || true)
    [ -z "$WEBROOT" ] && WEBROOT="/usr/share/zabbix/ui"
fi
ok "Webroot detectado: $WEBROOT"

DDOSGUARD_DIR="$WEBROOT/ddosguard"
[ -d "$DDOSGUARD_DIR" ] || err "Diretório $DDOSGUARD_DIR não encontrado. Execute setup.py primeiro."

# ----------------------------------------------------------------
# Lê token do config
# ----------------------------------------------------------------
if [ -z "${TOKEN:-}" ]; then
    CONFIG_FILE="/etc/zabbix/ddosguard/ingest.config.php"
    if [ -f "$CONFIG_FILE" ]; then
        TOKEN=$(grep "DG_INGEST_TOKEN" "$CONFIG_FILE" | grep -oP "'[^']+'" | tail -1 | tr -d "'")
    fi
fi
[ -z "${TOKEN:-}" ] && warn "Token não encontrado. Configure INGEST_URL e TOKEN manualmente nos receivers."
TOKEN="${TOKEN:-SEU_TOKEN_AQUI}"

# ----------------------------------------------------------------
# Executa migration do banco
# ----------------------------------------------------------------
echo ""
echo "==> Executando migration do banco (v2 SOC)..."
MIGRATION="$MODULE_DIR/sql/migration_v2_soc.sql"

if [ -f "$MIGRATION" ]; then
    # Detecta DB driver
    ZBX_CONF="/etc/zabbix/zabbix_server.conf"
    DB_HOST=$(grep "^DBHost=" "$ZBX_CONF" 2>/dev/null | cut -d= -f2 || echo "127.0.0.1")
    DB_PORT=$(grep "^DBPort=" "$ZBX_CONF" 2>/dev/null | cut -d= -f2 || echo "3306")
    DB_NAME=$(grep "^DBName=" "$ZBX_CONF" 2>/dev/null | cut -d= -f2 || echo "zabbix")
    DB_USER=$(grep "^DBUser=" "$ZBX_CONF" 2>/dev/null | cut -d= -f2 || echo "zabbix")
    DB_PASS=$(grep "^DBPassword=" "$ZBX_CONF" 2>/dev/null | cut -d= -f2 || true)

    if command -v mysql >/dev/null 2>&1; then
        MYSQL_PWD="$DB_PASS" mysql -u "$DB_USER" -h "$DB_HOST" -P "$DB_PORT" \
            "$DB_NAME" < "$MIGRATION" 2>/dev/null && ok "Migration executada." || \
            warn "Migration falhou — verifique as permissões do banco."
    else
        warn "mysql não encontrado. Execute manualmente:"
        info "  mysql -u $DB_USER -p $DB_NAME < $MIGRATION"
    fi
else
    warn "Arquivo de migration não encontrado: $MIGRATION"
fi

# ----------------------------------------------------------------
# Copia o syslog_forwarder.py para /opt/ddosguard
mkdir -p /opt/ddosguard
cp "$SCRIPT_DIR/syslog_forwarder.py" /opt/ddosguard/
chmod +x /opt/ddosguard/syslog_forwarder.py

# Instala servico systemd do forwarder
cat > /etc/systemd/system/ddosguard-syslog.service << 'UNIT'
[Unit]
Description=DDoS Guard Syslog Forwarder
After=network.target rsyslog.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/ddosguard/syslog_forwarder.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable ddosguard-syslog 2>/dev/null && ok "Servico ddosguard-syslog instalado"

# Copia os receivers para o webroot
# ----------------------------------------------------------------
echo ""
echo "==> Copiando receivers para $DDOSGUARD_DIR/integrations/"
mkdir -p "$DDOSGUARD_DIR/integrations"
cp "$SCRIPT_DIR"/*.php "$DDOSGUARD_DIR/integrations/" 2>/dev/null || true
cp "$MODULE_DIR/scripts/correlator.php" "$DDOSGUARD_DIR/" 2>/dev/null || true
chown -R www-data:www-data "$DDOSGUARD_DIR/integrations/" 2>/dev/null || \
chown -R nginx:nginx       "$DDOSGUARD_DIR/integrations/" 2>/dev/null || true
chmod 644 "$DDOSGUARD_DIR/integrations/"*.php 2>/dev/null || true
ok "Receivers copiados."

# ----------------------------------------------------------------
# Configuração pfSense / FortiGate via syslog
# ----------------------------------------------------------------
if [ "$INSTALL_SYSLOG" -eq 1 ]; then
    echo ""
    echo "==> Configurando receiver syslog (pfSense / FortiGate)..."

    # Conflito de imudp/ruleset derruba o bloco em SILENCIO: o rsyslog
    # loga o erro, ignora o bloco e continua rodando. Detecta antes.
    CONFLITOS=$(grep -rl 'imudp\|ruleset(name="ddosguard")' /etc/rsyslog.d/ 2>/dev/null \
        | grep -v 'ddosguard-syslog.conf' || true)
    if [ -n "$CONFLITOS" ]; then
        warn "Outros arquivos em /etc/rsyslog.d/ declaram imudp ou o ruleset ddosguard:"
        echo "$CONFLITOS" | sed 's/^/       /'
        warn "Mova-os para fora de /etc/rsyslog.d/ antes de prosseguir."
    fi

    mkdir -p /var/log/mikrotik

    cat > /etc/rsyslog.d/ddosguard-syslog.conf << EOF
# DDoS Guard - Receiver syslog (pfSense, FortiGate, MikroTik)
# Gerado por install_integrations.sh

module(load="imudp")
module(load="omprog")

# CRITICO: o omprog EXIGE que a mensagem termine em \\n. Templates
# nativos como RSYSLOG_TraditionalForwardFormat nao incluem a quebra de
# linha, e o rsyslog rejeita 100% das mensagens com:
#   "messages must be terminated with \\n at end of message"
template(name="DGProgFmt" type="string"
  string="%TIMESTAMP% %FROMHOST-IP% %syslogtag%%msg%\\n")

template(name="DGFileFmt" type="string"
  string="%TIMESTAMP:::date-rfc3339% %FROMHOST-IP% %syslogseverity-text% %msg%\\n")

input(type="imudp" port="514" ruleset="ddosguard")

ruleset(name="ddosguard") {
    action(type="omprog"
        name="ddosguard_php"
        binary="/usr/bin/php ${DDOSGUARD_DIR}/integrations/syslog_receiver.php"
        template="DGProgFmt"
        output="/var/log/ddosguard-omprog.log"
        queue.type="linkedList"
        queue.size="10000"
        queue.discardMark="9000"
        action.resumeRetryCount="-1")

    action(type="omfile"
        file="/var/log/ddosguard-syslog.log"
        template="DGFileFmt"
        queue.type="linkedList"
        queue.size="10000")

    stop
}
EOF

    # Valida ANTES de reiniciar: erro de sintaxe derruba o servico inteiro
    if rsyslogd -N1 >/dev/null 2>&1; then
        systemctl restart rsyslog 2>/dev/null && ok "rsyslog configurado (porta UDP 514)." || \
            warn "Reinicie o rsyslog manualmente: systemctl restart rsyslog"
    else
        err "rsyslogd -N1 acusou erro. Config NAO aplicada. Rode: rsyslogd -N1"
    fi

    cat > /etc/logrotate.d/ddosguard << 'LOGROT'
/var/log/mikrotik/*.log
/var/log/ddosguard-syslog.log
/var/log/ddosguard-omprog.log
{
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
LOGROT
    ok "logrotate configurado (/etc/logrotate.d/ddosguard)"

    echo ""
    info "Configuração pfSense:"
    info "  Status > System Logs > Settings > Remote Logging"
    info "  Remote log servers: $(hostname -I | awk '{print $1}'):514"
    info "  Content: Firewall Events"
    echo ""
    info "Configuração FortiGate:"
    info "  config log syslogd setting"
    info "    set status enable"
    info "    set server $(hostname -I | awk '{print $1}')"
    info "    set port 514"
    info "  end"
    echo ""
    info "Configuração MikroTik: importe mikrotik/ddosguard-ccr.rsc"
    info "  (ajuste as variáveis do topo do arquivo antes)"
fi

# ----------------------------------------------------------------
# Configuração Wazuh
# ----------------------------------------------------------------
if [ "$INSTALL_WAZUH" -eq 1 ]; then
    echo ""
    echo "==> Configurando integração Wazuh..."
    HOOK_URL="http://$(hostname -I | awk '{print $1}')/ddosguard/integrations/wazuh_receiver.php"

    cat << EOF

  Adicione ao /var/ossec/etc/ossec.conf no servidor Wazuh:

  <integration>
    <name>custom-ddosguard</name>
    <hook_url>${HOOK_URL}</hook_url>
    <api_key>${TOKEN}</api_key>
    <level>3</level>
    <alert_format>json</alert_format>
  </integration>

  Depois: systemctl restart wazuh-manager
EOF
    ok "Instruções Wazuh exibidas."
fi

# ----------------------------------------------------------------
# Configuração Suricata
# ----------------------------------------------------------------
if [ "$INSTALL_SURICATA" -eq 1 ]; then
    echo ""
    echo "==> Configurando integração Suricata..."
    HOOK_URL="http://$(hostname -I | awk '{print $1}')/ddosguard/integrations/suricata_receiver.php"

    # Instala o forwarder Python
    FORWARDER="/opt/ddosguard/suricata_forwarder.py"
    mkdir -p /opt/ddosguard
    cat > "$FORWARDER" << PYEOF
#!/usr/bin/env python3
"""DDoS Guard - Suricata eve.json forwarder"""
import json, time, urllib.request, urllib.error, sys

INGEST_URL = '${HOOK_URL}'
TOKEN      = '${TOKEN}'
EVE_LOG    = '/var/log/suricata/eve.json'
BATCH_SIZE = 50

def send(events):
    for event in events:
        try:
            data = json.dumps(event).encode()
            req  = urllib.request.Request(INGEST_URL, data=data, method='POST',
                headers={'Content-Type':'application/json','X-DG-Token':TOKEN})
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            print(f'[WARN] {e}', file=sys.stderr)

print(f'DDoS Guard Suricata forwarder iniciado. Lendo {EVE_LOG}')
try:
    with open(EVE_LOG) as f:
        f.seek(0, 2)
        batch = []
        while True:
            line = f.readline()
            if line:
                try:
                    ev = json.loads(line)
                    if ev.get('event_type') in ('alert', 'drop'):
                        batch.append(ev)
                        if len(batch) >= BATCH_SIZE:
                            send(batch); batch = []
                except json.JSONDecodeError:
                    pass
            else:
                if batch: send(batch); batch = []
                time.sleep(0.5)
except KeyboardInterrupt:
    pass
PYEOF
    chmod +x "$FORWARDER"

    # Cria serviço systemd
    cat > /etc/systemd/system/ddosguard-suricata.service << EOF
[Unit]
Description=DDoS Guard - Suricata Forwarder
After=network.target suricata.service
Requires=suricata.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${FORWARDER}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now ddosguard-suricata 2>/dev/null && \
        ok "Serviço ddosguard-suricata instalado e iniciado." || \
        warn "Inicie manualmente: systemctl start ddosguard-suricata"
fi

# ----------------------------------------------------------------
# Resumo final
# ----------------------------------------------------------------
echo ""
echo "============================================================"
echo " Instalação concluída!"
echo "============================================================"
echo ""
echo " Endpoints disponíveis:"
echo "   Wazuh:    http://IP/ddosguard/integrations/wazuh_receiver.php"
echo "   Suricata: http://IP/ddosguard/integrations/suricata_receiver.php"
echo "   Syslog:   http://IP/ddosguard/integrations/syslog_receiver.php"
echo "   Token:    $TOKEN"
echo ""
echo " Próximos passos:"
echo "   1. Execute a migration do banco se ainda não foi feita:"
echo "      mysql -u zabbix -p zabbix < sql/migration_v2_soc.sql"
echo "   2. Importe o template Zabbix atualizado"
echo "   3. Configure pfSense/FortiGate para enviar syslog na porta 514"
echo ""
