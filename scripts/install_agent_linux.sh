#!/usr/bin/env bash
# =============================================================================
# DDoS Guard Agent - Instalador (Linux)
# =============================================================================
# Instala SOMENTE o agente coletor (ddos_guard_agent.py) neste host Linux,
# como serviço systemd. Não mexe em banco de dados, ingest.php ou
# dashboards do Zabbix - isso é feito uma única vez no servidor, via
# scripts/setup.py.
#
# Uso:
#   sudo ./install_agent_linux.sh
#   sudo ./install_agent_linux.sh --yes \
#        --ingest-url http://192.168.0.52/ddosguard/ingest.php \
#        --token SEU_TOKEN --zbx-host meu-host --hostid 10084
#
# Rode este script em CADA host Linux que você quer monitorar (servidores
# web, banco de dados, firewalls baseados em Linux, etc.).
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------
# Defaults / variáveis
# -----------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

INSTALL_DIR="/opt/zabbix/ddosguard"
CONFIG_PATH="/etc/zabbix/ddos_guard_agent.conf"
STATE_DIR="/var/lib/zabbix/ddosguard"
SERVICE_NAME="ddos-guard-agent"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
SERVICE_USER="zabbix"

ASSUME_YES=0
INGEST_URL=""
TOKEN=""
ZBX_HOST=""
HOSTID=""
POLL_INTERVAL="10"

# -----------------------------------------------------------------------
# Helpers de UI
# -----------------------------------------------------------------------
info()  { echo "  [i] $*" >&2; }
ok()    { echo "  [OK] $*" >&2; }
warn()  { echo "  [!] $*" >&2; }
error() { echo "  [ERRO] $*" >&2; }
header() {
    echo "" >&2
    echo "======================================================================" >&2
    echo " $*" >&2
    echo "======================================================================" >&2
}

ask() {
    # ask "pergunta" "default" -> imprime o valor escolhido em stdout
    local prompt="$1" default="${2:-}"
    local answer
    if [[ "$ASSUME_YES" == "1" ]]; then
        echo "$default"
        return
    fi
    if [[ -n "$default" ]]; then
        read -r -p "  ${prompt} [${default}]: " answer || true
        echo "${answer:-$default}"
    else
        read -r -p "  ${prompt}: " answer || true
        echo "$answer"
    fi
}

ask_required() {
    local prompt="$1" default="${2:-}"
    local value
    value="$(ask "$prompt" "$default")"
    while [[ -z "$value" ]]; do
        warn "Esse valor é obrigatório."
        value="$(ask "$prompt" "$default")"
    done
    echo "$value"
}

# -----------------------------------------------------------------------
# Parse de argumentos
# -----------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes) ASSUME_YES=1; shift ;;
        --ingest-url) INGEST_URL="$2"; shift 2 ;;
        --token) TOKEN="$2"; shift 2 ;;
        --zbx-host) ZBX_HOST="$2"; shift 2 ;;
        --hostid) HOSTID="$2"; shift 2 ;;
        --poll-interval) POLL_INTERVAL="$2"; shift 2 ;;
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        -h|--help)
            grep '^# ' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            error "Argumento desconhecido: $1"
            exit 1
            ;;
    esac
done

# -----------------------------------------------------------------------
# Checagens iniciais
# -----------------------------------------------------------------------
if [[ "$(id -u)" != "0" ]]; then
    error "Rode este script como root (ou via sudo)."
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    error "python3 não encontrado. Instale o Python 3 antes de continuar."
    exit 1
fi

SOURCE_AGENT="${SCRIPT_DIR}/ddos_guard_agent.py"
if [[ ! -f "$SOURCE_AGENT" ]]; then
    error "Não encontrei ${SOURCE_AGENT}."
    error "Rode este instalador de dentro da pasta scripts/ do pacote DDoS Guard."
    exit 1
fi

header "DDoS Guard Agent — Instalador (Linux)"
info "Este instalador configura SOMENTE o agente coletor neste host."
info "Host atual: $(hostname)"

# -----------------------------------------------------------------------
# Coleta das informações de conexão
# -----------------------------------------------------------------------
header "1. Conexão com o servidor DDoS Guard"

if [[ -z "$INGEST_URL" ]]; then
    INGEST_URL="$(ask_required "URL do ingest.php no servidor (ex.: http://192.168.0.52/ddosguard/ingest.php)" "")"
fi
if [[ -z "$TOKEN" ]]; then
    TOKEN="$(ask_required "Token de autenticação (o mesmo configurado no servidor)" "")"
fi

header "2. Identificação deste host no Zabbix"

DEFAULT_ZBX_HOST="$(hostname)"
if [[ -z "$ZBX_HOST" ]]; then
    ZBX_HOST="$(ask_required "Nome deste host EXATAMENTE como cadastrado no Zabbix (Data collection > Hosts)" "$DEFAULT_ZBX_HOST")"
fi
if [[ -z "$HOSTID" ]]; then
    HOSTID="$(ask "hostid numérico deste host no Zabbix (veja na URL ao abrir o host; pode deixar 0 por enquanto)" "0")"
fi

# -----------------------------------------------------------------------
# Detecção de fontes de log disponíveis
# -----------------------------------------------------------------------
header "3. Detectando fontes de log neste host"

detect_log() {
    local label="$1"; shift
    for candidate in "$@"; do
        if [[ -f "$candidate" ]]; then
            ok "${label}: ${candidate}"
            echo "$candidate"
            return
        fi
    done
    warn "${label}: não encontrado (deixando vazio, fonte fica desabilitada)"
    echo ""
}

IPTABLES_LOG="$(detect_log "Log do iptables/kernel" /var/log/kern.log /var/log/messages /var/log/iptables.log)"
UFW_LOG="$(detect_log "Log do UFW" /var/log/ufw.log)"
FAIL2BAN_LOG="$(detect_log "Log do fail2ban" /var/log/fail2ban.log)"
CLAMAV_LOG="$(detect_log "Log do ClamAV" /var/log/clamav/clamav.log /var/log/clamd.log)"
AUTH_LOG="$(detect_log "Log de autenticação (SSH)" /var/log/auth.log /var/log/secure)"

GEOIP_DB="/usr/share/GeoIP/GeoLite2-City.mmdb"
if [[ -f "$GEOIP_DB" ]]; then
    ok "Base GeoIP encontrada: ${GEOIP_DB}"
else
    warn "Base GeoLite2-City.mmdb não encontrada — o agente vai usar a API"
    warn "pública ip-api.com para geolocalizar IPs (com limite de requisições)."
fi

if python3 -c "import geoip2" >/dev/null 2>&1; then
    ok "Biblioteca 'geoip2' instalada."
else
    warn "Biblioteca Python 'geoip2' não instalada (opcional). Para instalar:"
    warn "    pip3 install geoip2  (ou: pip3 install --break-system-packages geoip2)"
fi

# -----------------------------------------------------------------------
# Instalação dos arquivos
# -----------------------------------------------------------------------
header "4. Instalando o agente"

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    warn "Usuário de sistema '${SERVICE_USER}' não existe neste host."
    if [[ "$(ask "Criar o usuário '${SERVICE_USER}' agora (sem login, sem home)?" "s")" =~ ^[sS] ]]; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
            || useradd --system --shell /sbin/nologin "$SERVICE_USER"
        ok "Usuário '${SERVICE_USER}' criado."
    else
        SERVICE_USER="root"
        warn "Usando 'root' para rodar o serviço (não recomendado para produção)."
    fi
fi

mkdir -p "$INSTALL_DIR"
cp "$SOURCE_AGENT" "${INSTALL_DIR}/ddos_guard_agent.py"
chmod 755 "${INSTALL_DIR}/ddos_guard_agent.py"
ok "Agente copiado para ${INSTALL_DIR}/ddos_guard_agent.py"

mkdir -p "$STATE_DIR"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "$STATE_DIR" 2>/dev/null || true

mkdir -p "$(dirname "$CONFIG_PATH")"
cat > "$CONFIG_PATH" <<EOF
[general]
zbx_host = ${ZBX_HOST}
hostid = ${HOSTID}
ingest_url = ${INGEST_URL}
ingest_token = ${TOKEN}
poll_interval = ${POLL_INTERVAL}
aggregate_window = 60
geoip_db_path = ${GEOIP_DB}
has_firewall = auto
has_antivirus = auto
state_file = ${STATE_DIR}/state.json

[sources]
iptables_log = ${IPTABLES_LOG}
ufw_log = ${UFW_LOG}
fail2ban_log = ${FAIL2BAN_LOG}
clamav_log = ${CLAMAV_LOG}
auth_log = ${AUTH_LOG}
EOF
chmod 640 "$CONFIG_PATH"
chown "root:${SERVICE_USER}" "$CONFIG_PATH" 2>/dev/null || true
ok "Configuração escrita em ${CONFIG_PATH}"

# -----------------------------------------------------------------------
# Serviço systemd
# -----------------------------------------------------------------------
header "5. Configurando o serviço systemd"

if command -v systemctl >/dev/null 2>&1; then
    cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=DDoS Guard Agent - coletor de eventos de seguranca para Zabbix
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/ddos_guard_agent.py --config ${CONFIG_PATH}
Restart=always
RestartSec=5
User=${SERVICE_USER}
Group=${SERVICE_USER}

[Install]
WantedBy=multi-user.target
EOF
    ok "Unit systemd escrita em ${SERVICE_PATH}"

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
    # "restart" em vez de "start": garante reload da config mesmo que o
    # serviço já estivesse rodando de uma instalação anterior.
    systemctl restart "$SERVICE_NAME"
    sleep 1

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        ok "Serviço '${SERVICE_NAME}' habilitado e rodando."
    else
        error "O serviço não ficou ativo. Veja os logs com:"
        error "    journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
        exit 1
    fi
else
    warn "systemctl não encontrado neste sistema."
    warn "Rode manualmente com: python3 ${INSTALL_DIR}/ddos_guard_agent.py --config ${CONFIG_PATH}"
    warn "ou configure um cron job com --once a cada minuto."
fi

# -----------------------------------------------------------------------
# Teste rápido
# -----------------------------------------------------------------------
header "6. Teste rápido"

info "Aguardando alguns segundos para o agente enviar o primeiro heartbeat..."
sleep 3
if command -v journalctl >/dev/null 2>&1; then
    if journalctl -u "$SERVICE_NAME" -n 20 --no-pager 2>/dev/null | grep -qi "unauthorized\|invalid token"; then
        error "O agente está recebendo erro de autenticação do servidor."
        error "Confira se o token usado bate com o configurado no ingest.config.php do servidor."
    elif journalctl -u "$SERVICE_NAME" -n 20 --no-pager 2>/dev/null | grep -qi "falha ao enviar"; then
        warn "O agente está rodando, mas teve falha ao enviar algum evento."
        warn "Veja o motivo com: journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
    else
        ok "Nenhum erro óbvio nos últimos logs. Acompanhe com:"
        echo "        journalctl -u ${SERVICE_NAME} -f"
    fi
fi

header "Resumo"
echo "  Agente instalado em ..... ${INSTALL_DIR}/ddos_guard_agent.py"
echo "  Configuração ............ ${CONFIG_PATH}"
echo "  Serviço .................. ${SERVICE_NAME} (systemd)"
echo "  zbx_host ................. ${ZBX_HOST}"
echo "  Servidor (ingest_url) .... ${INGEST_URL}"
echo ""
info "Confirme em Data collection > Hosts que o host '${ZBX_HOST}' existe no Zabbix"
info "e que o template 'DDoS Guard - Security Monitoring' está associado a ele."
echo ""
