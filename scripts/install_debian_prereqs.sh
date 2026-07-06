#!/usr/bin/env bash
# =============================================================================
# DDoS Guard — Prerequisitos e Correcoes para Debian 12/13
# =============================================================================
# Script idempotente para rodar ANTES do instalador ou em appliances ja
# implantados para auditar e corrigir a configuracao.
#
# Cobre:
#   - Instalacao de pacotes necessarios no Debian minimal
#   - Modelo de permissoes correto (sem chmod 777)
#   - Correcao do DG_ZBX_SERVER com :porta (causa timeout de 20s)
#   - Remocao de ingest.config.php no webroot (risco de exposicao)
#   - UFW na ordem segura (regras ANTES do enable)
#   - ServerName do Apache (aviso AH00558)
#   - Validacoes finais com diagnosticos claros
#
# Uso:
#   sudo bash install_debian_prereqs.sh [--web-port 80] [--mgmt-net 192.168.0.0/24]
#
# Pode ser executado multiplas vezes sem efeitos colaterais.
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; exit 1; }
info() { echo -e "     $*"; }
step() { echo -e "\n${CYAN}${BOLD}======${NC} $* ${CYAN}${BOLD}======${NC}"; }

[ "$(id -u)" -eq 0 ] || err "Execute como root: sudo $0 $*"

WEB_PORT="80"; MGMT_NET=""
for arg in "$@"; do
    case "$arg" in
        --web-port=*) WEB_PORT="${arg#*=}" ;;
        --mgmt-net=*) MGMT_NET="${arg#*=}" ;;
    esac
done

echo -e "\n${BOLD}======================================================================"
echo -e " DDoS Guard — Prerequisitos Debian 12/13"
echo -e "======================================================================"

# ── 1. Verifica se e Debian ─────────────────────────────────────────────────
step "1. Verificando ambiente"
if [ ! -f /etc/debian_version ]; then
    warn "Este script e especifico para Debian/Ubuntu."
    info "Para Rocky Linux / RHEL use: dnf install epel-release && dnf install fail2ban clamav"
    exit 0
fi
DEBIAN_VER=$(cat /etc/debian_version 2>/dev/null || echo "desconhecida")
ok "Debian $DEBIAN_VER detectado"

# ── 2. Pacotes necessarios ──────────────────────────────────────────────────
step "2. Instalando pacotes"
apt-get update -q 2>/dev/null || warn "apt-get update falhou — verifique a conectividade"

PKGS=(python3 python3-pip curl rsyslog ufw fail2ban clamav clamav-freshclam)

# clamav-daemon condicional a RAM
RAM_GiB=$(awk '/MemTotal/{printf "%d", $2/1024/1024}' /proc/meminfo)
if [ "$RAM_GiB" -ge 6 ]; then
    PKGS+=(clamav-daemon)
    info "RAM: ${RAM_GiB}GiB — clamav-daemon sera instalado"
else
    warn "RAM: ${RAM_GiB}GiB < 6GiB — clamav-daemon nao sera instalado (consome ~1GiB)"
    info "Alternativa: scan agendado via cron"
    info "  echo '0 3 * * * root clamscan -r /home /var/www >> /var/log/clamav/clamav.log 2>&1' > /etc/cron.d/clamav-scan"
fi

apt-get install -y -q "${PKGS[@]}" 2>/dev/null && ok "Pacotes instalados" || \
    warn "Alguns pacotes nao puderam ser instalados"

# GeoIP2
pip3 install geoip2 --break-system-packages -q 2>/dev/null && \
    ok "python3-geoip2 instalado" || \
    warn "geoip2 nao instalado — usando ip-api.com (limite: 45 req/min)"

# ── 3. Servicos ─────────────────────────────────────────────────────────────
step "3. Habilitando servicos"

# rsyslog — sem ele nao existem /var/log/auth.log e /var/log/kern.log no Debian
systemctl enable --now rsyslog 2>/dev/null && ok "rsyslog ativo" || \
    warn "rsyslog nao habilitado"

# fail2ban
if [ -f /etc/fail2ban/jail.local ]; then
    ok "jail.local ja existe"
else
    cat > /etc/fail2ban/jail.local << 'F2B'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3

[sshd]
enabled  = true
port     = ssh
logpath  = /var/log/auth.log
F2B
    ok "jail.local criado com sshd"
fi
systemctl enable --now fail2ban 2>/dev/null && ok "fail2ban ativo" || \
    warn "fail2ban nao habilitado"

# clamav-freshclam como daemon (NAO rodar freshclam manual enquanto daemon ativo)
systemctl enable --now clamav-freshclam 2>/dev/null && \
    ok "clamav-freshclam daemon ativo" || warn "clamav-freshclam nao habilitado"
info "AVISO: nao rode 'freshclam' manualmente — o daemon ja atualiza e segura o lock"
info "  ERROR: Failed to lock the log file = daemon ativo, sem problemas reais"

if systemctl is-enabled clamav-daemon &>/dev/null; then
    systemctl enable --now clamav-daemon 2>/dev/null && ok "clamav-daemon ativo" || \
        warn "clamav-daemon nao habilitado"
fi

# ── 4. Logs e permissoes ────────────────────────────────────────────────────
step "4. Permissoes dos logs"
# Modelo correto — NUNCA 777 (permite forjar/apagar evidencias de ataque)
declare -A LOG_PATHS=(
    ["/var/log/kern.log"]="create"
    ["/var/log/auth.log"]="create"
    ["/var/log/ufw.log"]="touch"
    ["/var/log/fail2ban.log"]="touch"
    ["/var/log/clamav/clamd.log"]="touch"
    ["/var/log/clamav/clamav.log"]="touch"
)

for LOG_FILE in "${!LOG_PATHS[@]}"; do
    ACTION="${LOG_PATHS[$LOG_FILE]}"
    DIR="$(dirname "$LOG_FILE")"
    [ -d "$DIR" ] || mkdir -p "$DIR"
    [ "$ACTION" = "touch" ] && touch "$LOG_FILE" 2>/dev/null || true
    [ -f "$LOG_FILE" ] && chmod 644 "$LOG_FILE" 2>/dev/null && \
        ok "chmod 644 $LOG_FILE" || true
done

# Logrotate — garante modo 644 apos rotacao
LOGROTATE_RSYSLOG="/etc/logrotate.d/rsyslog"
if [ -f "$LOGROTATE_RSYSLOG" ] && ! grep -q "create 0644" "$LOGROTATE_RSYSLOG" 2>/dev/null; then
    cat >> "$LOGROTATE_RSYSLOG" << 'LR'
/var/log/kern.log {
    create 0644 root adm
}
/var/log/auth.log {
    create 0644 root adm
}
LR
    ok "logrotate atualizado para preservar modo 644"
fi

# ── 5. Modelo de permissoes do DDoS Guard ──────────────────────────────────
step "5. Permissoes dos arquivos DDoS Guard"

# Detecta WEB_USER
WEB_USER="www-data"
id www-data &>/dev/null || WEB_USER="nginx"

# Detecta webroot
WEBROOT=$(grep -rh "root " /etc/nginx/conf.d/*.conf \
    /etc/nginx/sites-enabled/*.conf \
    /etc/apache2/sites-enabled/*.conf 2>/dev/null | \
    grep -v "#" | grep -oP "root\s+\K[^;]+" | head -1 || true)
WEBROOT="${WEBROOT:-/usr/share/zabbix/ui}"

CONFIG_PHP="/etc/zabbix/ddosguard/ingest.config.php"
AGENT_CONF="/etc/zabbix/ddos_guard_agent.conf"
ZBX_SERVER_CONF="/etc/zabbix/zabbix_server.conf"

# ingest.config.php — root:www-data 640
if [ -f "$CONFIG_PHP" ]; then
    chown "root:$WEB_USER" "$CONFIG_PHP" 2>/dev/null || true
    chmod 640 "$CONFIG_PHP" 2>/dev/null
    chmod 755 "$(dirname "$CONFIG_PHP")" 2>/dev/null || true
    ok "$CONFIG_PHP: root:$WEB_USER 640"

    # Testa se www-data consegue ler
    if sudo -u "$WEB_USER" cat "$CONFIG_PHP" >/dev/null 2>&1; then
        ok "$WEB_USER consegue ler o config (401 nao ira ocorrer por permissao)"
    else
        warn "$WEB_USER NAO consegue ler $CONFIG_PHP — 401 ira ocorrer!"
    fi
else
    info "$CONFIG_PHP nao encontrado (execute setup.py primeiro)"
fi

# agent.conf — 600 (contem o token)
if [ -f "$AGENT_CONF" ]; then
    chmod 600 "$AGENT_CONF" 2>/dev/null
    ok "$AGENT_CONF: 600 (token protegido)"
fi

# zabbix_server.conf — root:zabbix 640
if [ -f "$ZBX_SERVER_CONF" ]; then
    chown root:zabbix "$ZBX_SERVER_CONF" 2>/dev/null || true
    chmod 640 "$ZBX_SERVER_CONF" 2>/dev/null || true
    ok "$ZBX_SERVER_CONF: root:zabbix 640"
fi

# Remove ingest.config.php do webroot (exposicao de senha via HTTP)
for f in "$WEBROOT/ddosguard/ingest.config.php" "$WEBROOT/ingest.config.php"; do
    if [ -e "$f" ]; then
        rm -f "$f"
        warn "REMOVIDO $f do webroot — expunha senha do banco via HTTP!"
    fi
done

# ── 6. Correcoes de configuracao ────────────────────────────────────────────
step "6. Correcoes de configuracao"

# 6a. DG_ZBX_SERVER com :porta causa timeout de ~20s no ingest
if [ -f "$CONFIG_PHP" ]; then
    if grep -qP "DG_ZBX_SERVER.*:\d+" "$CONFIG_PHP" 2>/dev/null; then
        warn "DG_ZBX_SERVER contem ':porta' — corrigindo (causa timeout de 20s)..."
        sed -i "s/\(DG_ZBX_SERVER.*'\)[^']*:\([0-9]*\)'/\1127.0.0.1'/" "$CONFIG_PHP"
        ok "DG_ZBX_SERVER corrigido para '127.0.0.1'"
        info "A porta vai para DG_ZBX_PORT (normalmente 10051)"
    else
        ok "DG_ZBX_SERVER sem ':porta' (correto)"
    fi
fi

# 6b. Apache ServerName (evita aviso AH00558 a cada reload)
APACHE_SERVERNAME="/etc/apache2/conf-available/servername.conf"
if command -v apache2 >/dev/null 2>&1; then
    if [ ! -f "$APACHE_SERVERNAME" ]; then
        echo "ServerName $(hostname)" > "$APACHE_SERVERNAME"
        /usr/sbin/a2enconf servername 2>/dev/null || \
            ln -sf "$APACHE_SERVERNAME" /etc/apache2/conf-enabled/servername.conf 2>/dev/null || true
        systemctl reload apache2 2>/dev/null || true
        ok "Apache ServerName configurado (aviso AH00558 eliminado)"
    else
        ok "Apache ServerName ja configurado"
    fi
fi

# ── 7. Firewall na ordem correta ────────────────────────────────────────────
step "7. Firewall (UFW)"
if ! command -v ufw >/dev/null 2>&1; then
    warn "UFW nao encontrado — instalando..."
    apt-get install -y -q ufw 2>/dev/null || true
fi

if command -v ufw >/dev/null 2>&1; then
    UFW_STATUS=$(ufw status 2>/dev/null | head -1)

    if echo "$UFW_STATUS" | grep -q "inactive"; then
        info "UFW inativo — configurando regras ANTES de ativar"
        ufw allow ssh
        ufw allow "$WEB_PORT"/tcp
        ufw allow 10050/tcp
        ufw allow 10051/tcp
        [ -n "$MGMT_NET" ] && ufw allow from "$MGMT_NET" to any
        ufw default deny incoming
        ufw default allow outgoing
        ufw logging medium
        ufw --force enable
        ok "UFW ativado com regras de seguranca"
    else
        ok "UFW ja ativo: $UFW_STATUS"
        # Garante que as portas criticas estao liberadas
        ufw allow ssh >/dev/null 2>&1 || true
        ufw allow "$WEB_PORT"/tcp >/dev/null 2>&1 || true
        ufw allow 10050/tcp >/dev/null 2>&1 || true
        ufw allow 10051/tcp >/dev/null 2>&1 || true
    fi

    if [ -n "$MGMT_NET" ]; then
        warn "Regra 'allow from $MGMT_NET' suprime eventos [UFW BLOCK] desta rede."
        info "Isso e esperado para redes de gerenciamento."
    fi
fi

# ── 8. Validacoes finais ────────────────────────────────────────────────────
step "8. Validacoes finais"

# Agent conf
if [ -f "$AGENT_CONF" ]; then
    ZBX_HOST_CONF=$(grep "^zbx_host" "$AGENT_CONF" | cut -d= -f2 | tr -d ' ' || echo "")
    INGEST_URL_CONF=$(grep "^ingest_url" "$AGENT_CONF" | cut -d= -f2 | tr -d ' ' || echo "")
    ok "agent.conf: zbx_host=$ZBX_HOST_CONF"

    # Testa o ingest com medicao de latencia
    if command -v curl >/dev/null 2>&1 && [ -n "$INGEST_URL_CONF" ]; then
        TOKEN_CONF=$(grep "^ingest_token" "$AGENT_CONF" | cut -d= -f2 | tr -d ' ' || echo "")
        LATENCY=$(curl -s -o /dev/null -w "%{time_total}" \
            -H "Content-Type: application/json" \
            -H "X-DG-Token: $TOKEN_CONF" \
            -d "{\"event_type\":\"heartbeat\",\"zbx_host\":\"$ZBX_HOST_CONF\"}" \
            "$INGEST_URL_CONF" 2>/dev/null | awk '{printf "%.1f", $1}' || echo "?")
        if echo "$LATENCY" | awk '{exit ($1 > 5)}' 2>/dev/null; then
            ok "Ingest respondeu em ${LATENCY}s"
        else
            warn "Ingest lento: ${LATENCY}s"
            info "Verifique DG_ZBX_SERVER e DG_DB_HOST no ingest.config.php"
        fi
    fi
fi

echo ""
echo -e "${BOLD}======================================================================"
echo -e " Prerequisitos aplicados com sucesso!"
echo -e "======================================================================"
echo ""
echo "Proximos passos:"
echo "  1. Execute o instalador do agente:"
echo "     bash scripts/install_agent_linux.sh"
echo ""
echo "  2. Verifique o status:"
echo "     systemctl status ddos-guard-agent"
echo "     journalctl -u ddos-guard-agent -f"
