#!/usr/bin/env bash
# =============================================================================
# DDoS Guard Agent — Instalador Linux v2
# =============================================================================
# Suporte: Rocky Linux 8/9, RHEL 8/9, AlmaLinux, CentOS Stream,
#          Ubuntu 22.04/24.04, Debian 12/13, Raspberry Pi OS
#
# Uso:
#   sudo ./install_agent_linux.sh
#   sudo ./install_agent_linux.sh --yes \
#        --ingest-url http://192.168.0.52/ddosguard/ingest.php \
#        --token SEU_TOKEN --zbx-host nome-tecnico-no-zabbix --hostid 10084
#
# Flags opcionais:
#   --web-port PORT        Porta do frontend Zabbix (para liberar no UFW)
#   --mgmt-net CIDR        Rede de gerenciamento (ex: 192.168.0.0/24)
#   --skip-firewall        Nao configura UFW
#   --skip-deps            Nao instala dependencias (assume ja instaladas)
# =============================================================================

set -euo pipefail

# ── Cores ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()    { echo -e "${GREEN}[OK]${NC} $*" >&2; }
warn()  { echo -e "${YELLOW}[!]${NC} $*" >&2; }
err()   { echo -e "${RED}[ERR]${NC} $*" >&2; exit 1; }
info()  { echo -e "     $*" >&2; }
step()  { echo -e "\n${CYAN}${BOLD}======${NC} $* ${CYAN}${BOLD}======${NC}" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_PY="$SCRIPT_DIR/ddos_guard_agent.py"
SERVICE_FILE="$SCRIPT_DIR/ddos-guard-agent.service"

# ── Defaults ────────────────────────────────────────────────────────────────
ASSUME_YES=0; SKIP_FW=0; SKIP_DEPS=0
INGEST_URL=""; TOKEN=""; ZBX_HOST=""; HOST_ID="0"
WEB_PORT=""; MGMT_NET=""

for arg in "$@"; do
    case "$arg" in
        --yes)            ASSUME_YES=1 ;;
        --skip-firewall)  SKIP_FW=1 ;;
        --skip-deps)      SKIP_DEPS=1 ;;
        --ingest-url=*)   INGEST_URL="${arg#*=}" ;;
        --token=*)        TOKEN="${arg#*=}" ;;
        --zbx-host=*)     ZBX_HOST="${arg#*=}" ;;
        --hostid=*)       HOST_ID="${arg#*=}" ;;
        --web-port=*)     WEB_PORT="${arg#*=}" ;;
        --mgmt-net=*)     MGMT_NET="${arg#*=}" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || err "Execute como root: sudo $0 $*"
HOSTNAME_DEFAULT="$(hostname -s)"

echo -e "\n${BOLD}======================================================================"
echo -e " DDoS Guard Agent — Instalador Linux v2"
echo -e "======================================================================${NC}"

# ── 1. Detecta a família da distro ──────────────────────────────────────────
step "1. Detectando ambiente"
DISTRO_FAMILY=""
if [ -f /etc/debian_version ]; then
    DISTRO_FAMILY="debian"
    PKG_MGR="apt-get"
    INSTALL="apt-get install -y -q"
    WEB_USER="www-data"
    SECURE_LOG="/var/log/auth.log"
    KERN_LOG="/var/log/kern.log"
    ok "Debian/Ubuntu detectado (apt)"
elif [ -f /etc/redhat-release ]; then
    DISTRO_FAMILY="rhel"
    PKG_MGR="dnf"
    INSTALL="dnf install -y -q"
    WEB_USER="nginx"
    SECURE_LOG="/var/log/secure"
    KERN_LOG="/var/log/messages"
    ok "Rocky/RHEL/AlmaLinux detectado (dnf)"
else
    warn "Distro nao reconhecida — assumindo Debian"
    DISTRO_FAMILY="debian"
    PKG_MGR="apt-get"
    INSTALL="apt-get install -y -q"
    WEB_USER="www-data"
    SECURE_LOG="/var/log/auth.log"
    KERN_LOG="/var/log/kern.log"
fi

# ── 2. Instala dependencias ──────────────────────────────────────────────────
step "2. Instalando dependencias"
if [ "$SKIP_DEPS" -eq 1 ]; then
    info "Pulando instalacao de dependencias (--skip-deps)"
else
    if [ "$DISTRO_FAMILY" = "debian" ]; then
        # Debian 12/13 minimal nao tem rsyslog — sem ele nao existem kern.log e auth.log
        apt-get update -q 2>/dev/null || true
        $INSTALL python3 python3-pip curl rsyslog ufw fail2ban \
                 clamav clamav-freshclam 2>/dev/null || warn "Alguns pacotes nao instalados"

        # Habilita rsyslog (Debian usa journald por padrao)
        systemctl enable --now rsyslog 2>/dev/null && ok "rsyslog habilitado" || true

        # ClamAV: clamd condicional a RAM >= 6 GiB (consome ~1 GiB residente)
        RAM_GiB=$(awk '/MemTotal/{printf "%d", $2/1024/1024}' /proc/meminfo)
        if [ "$RAM_GiB" -ge 6 ]; then
            $INSTALL clamav-daemon 2>/dev/null && \
                systemctl enable --now clamav-daemon 2>/dev/null && \
                ok "clamav-daemon habilitado (RAM: ${RAM_GiB}GiB)" || true
        else
            warn "RAM insuficiente para clamd (${RAM_GiB}GiB < 6GiB) — usando clamscan sob demanda"
            info "Adicione ao crontab: 0 3 * * * clamscan -r /home /var/www --log=/var/log/clamav/clamav.log"
        fi

        # GeoIP2 (sem a base, ip-api.com pode travar ciclos de coleta em hosts expostos)
        pip3 install geoip2 --break-system-packages -q 2>/dev/null && \
            ok "python3-geoip2 instalado" || \
            warn "geoip2 nao instalado — usando ip-api.com (limite 45 req/min)"

        # clamav-freshclam como daemon (NAO rodar freshclam manual se o daemon estiver ativo)
        systemctl enable --now clamav-freshclam 2>/dev/null && \
            ok "clamav-freshclam daemon habilitado" || true
        info "ATENCAO: nao rode 'freshclam' manualmente — o daemon segura o lock"

    elif [ "$DISTRO_FAMILY" = "rhel" ]; then
        # EPEL necessario para fail2ban e clamav
        dnf install -y -q epel-release 2>/dev/null || true
        $INSTALL python3 python3-pip curl rsyslog fail2ban \
                 clamav clamav-update clamd 2>/dev/null || warn "Alguns pacotes nao instalados"
        pip3 install geoip2 --break-system-packages -q 2>/dev/null || true
        freshclam 2>/dev/null || true
        systemctl enable --now clamd@scan 2>/dev/null || true
    fi

    # fail2ban — jail minimo para SSH
    if ! [ -f /etc/fail2ban/jail.local ]; then
        cat > /etc/fail2ban/jail.local << 'F2B'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3

[sshd]
enabled  = true
port     = ssh
F2B
    fi
    systemctl enable --now fail2ban 2>/dev/null && ok "fail2ban habilitado" || true
fi

# ── 3. Conexao com o servidor ────────────────────────────────────────────────
step "3. Conexao com o servidor DDoS Guard"

_prompt() { # _prompt "Mensagem" [default]
    local msg="$1" default="${2:-}"
    if [ "$ASSUME_YES" -eq 1 ] && [ -n "$default" ]; then
        echo "$default"; return
    fi
    read -rp "  $msg${default:+ [$default]}: " val >&2
    echo "${val:-$default}"
}

if [ -z "$INGEST_URL" ]; then
    INGEST_URL="$(_prompt "URL do ingest.php" "http://192.168.0.52/ddosguard/ingest.php")"
fi
if [ -z "$TOKEN" ]; then
    TOKEN="$(_prompt "Token de autenticacao")"
fi

# Extrai porta web da URL do ingest (evita travar o UFW na porta errada)
if [ -z "$WEB_PORT" ]; then
    WEB_PORT=$(echo "$INGEST_URL" | grep -oP ':\K\d+(?=/)' || echo "80")
    [ -z "$WEB_PORT" ] && WEB_PORT="80"
fi

# ── 4. Identificacao no Zabbix ───────────────────────────────────────────────
step "4. Identificacao no Zabbix"
info "IMPORTANTE: use o NOME TECNICO do host (coluna 'host' na tabela hosts)"
info "            O nome tecnico pode diferir do nome exibido no frontend!"
info "Query de diagnostico:"
info "  mysql -u zabbix -p zabbix -e \"SELECT h.host, h.name FROM hosts h"
info "    WHERE h.status=0 AND h.flags=0 ORDER BY h.host;\""

if [ -z "$ZBX_HOST" ]; then
    ZBX_HOST="$(_prompt "Nome TECNICO do host no Zabbix" "$HOSTNAME_DEFAULT")"
fi
if [ "$HOST_ID" = "0" ]; then
    HOST_ID="$(_prompt "hostid numerico (URL ao abrir o host)" "0")"
fi

# ── 5. Detecta fontes de log ─────────────────────────────────────────────────
step "5. Detectando fontes de log"

IPTABLES_LOG=""; UFW_LOG=""; FAIL2BAN_LOG=""; CLAMAV_LOG=""; AUTH_LOG=""

# kern.log / messages
for f in /var/log/kern.log /var/log/messages; do
    [ -f "$f" ] && IPTABLES_LOG="$f" && ok "iptables/kern: $f" && break
done
[ -z "$IPTABLES_LOG" ] && warn "Log do kernel nao encontrado"

# ufw.log
[ -f /var/log/ufw.log ] && UFW_LOG="/var/log/ufw.log" && ok "UFW: $UFW_LOG" || \
    warn "ufw.log nao encontrado (deixando vazio)"

# fail2ban.log
[ -f /var/log/fail2ban.log ] && FAIL2BAN_LOG="/var/log/fail2ban.log" && \
    ok "fail2ban: $FAIL2BAN_LOG" || warn "fail2ban.log nao encontrado"

# clamav — detecta clamd.log ou clamav.log (Debian usa clamav.log)
for f in /var/log/clamav/clamd.log /var/log/clamav/clamav.log; do
    [ -f "$f" ] && CLAMAV_LOG="$f" && ok "ClamAV: $f" && break
done
[ -z "$CLAMAV_LOG" ] && warn "Log do ClamAV nao encontrado"

# auth.log / secure
for f in /var/log/auth.log /var/log/secure; do
    [ -f "$f" ] && AUTH_LOG="$f" && ok "SSH/auth: $f" && break
done
[ -z "$AUTH_LOG" ] && warn "Log de autenticacao nao encontrado"

# Corrige permissoes dos logs (644 — suficiente para root via systemd)
# NUNCA use 777 em logs — permite forjar ou apagar evidencias de ataque
for LOG in "$IPTABLES_LOG" "$UFW_LOG" "$FAIL2BAN_LOG" "$CLAMAV_LOG" "$AUTH_LOG"; do
    [ -n "$LOG" ] && [ -f "$LOG" ] && chmod 644 "$LOG" 2>/dev/null || true
done

# Logrotate — garante que rotacao preserve modo 644
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
fi

# GeoIP2 — aviso se ausente
GEOIP_DB=""
for p in /usr/share/GeoIP /usr/local/share/GeoIP /var/lib/GeoIP; do
    [ -f "$p/GeoLite2-City.mmdb" ] && GEOIP_DB="$p/GeoLite2-City.mmdb" && \
        ok "GeoIP2: $GEOIP_DB" && break
done
if [ -z "$GEOIP_DB" ]; then
    warn "GeoLite2-City.mmdb nao encontrado — usando ip-api.com"
    info "Em hosts expostos com muito trafego, a API publica (45 req/min)"
    info "pode travar o ciclo de coleta. Instale a base local:"
    info "  https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
fi

# ── 6. Instala o agente ──────────────────────────────────────────────────────
step "6. Instalando o agente"
INSTALL_DIR="/opt/zabbix/ddosguard"
CONF_DIR="/etc/zabbix"
CONF_FILE="$CONF_DIR/ddos_guard_agent.conf"
STATE_DIR="/var/lib/zabbix/ddosguard"

mkdir -p "$INSTALL_DIR" "$STATE_DIR"
cp "$AGENT_PY" "$INSTALL_DIR/ddos_guard_agent.py"
chmod 755 "$INSTALL_DIR/ddos_guard_agent.py"
ok "Agente copiado para $INSTALL_DIR"

# Grava agent.conf com modo 600 (contém o token — nao expor)
cat > "$CONF_FILE" << CONF
[general]
zbx_host = ${ZBX_HOST}
hostid = ${HOST_ID}
ingest_url = ${INGEST_URL}
ingest_token = ${TOKEN}
poll_interval = 10
aggregate_window = 60
geoip_db_path = ${GEOIP_DB:-/usr/share/GeoIP/GeoLite2-City.mmdb}
has_firewall = auto
has_antivirus = auto
state_file = ${STATE_DIR}/state.json

[sources]
iptables_log = ${IPTABLES_LOG}
ufw_log = ${UFW_LOG}
fail2ban_log = ${FAIL2BAN_LOG}
clamav_log = ${CLAMAV_LOG}
auth_log = ${AUTH_LOG}
CONF

chmod 600 "$CONF_FILE"   # token nao deve ser legivel por outros usuarios
ok "Configuracao gravada em $CONF_FILE (modo 600)"

# ── 7. Configura o servico systemd ──────────────────────────────────────────
step "7. Configurando servico systemd"
UNIT_SRC="$SCRIPT_DIR/ddos-guard-agent.service"
UNIT_DEST="/etc/systemd/system/ddos-guard-agent.service"

if [ -f "$UNIT_SRC" ]; then
    cp "$UNIT_SRC" "$UNIT_DEST"
else
    cat > "$UNIT_DEST" << UNIT
[Unit]
Description=DDoS Guard Agent - coletor de eventos de seguranca para Zabbix
After=network.target syslog.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/ddos_guard_agent.py --config ${CONF_FILE}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT
fi

systemctl daemon-reload
systemctl enable --now ddos-guard-agent
ok "Servico ddos-guard-agent habilitado e iniciado"

# ── 8. Firewall (UFW) — regras ANTES do enable ──────────────────────────────
step "8. Configurando firewall"
if [ "$SKIP_FW" -eq 1 ]; then
    info "Pulando configuracao do firewall (--skip-firewall)"
elif command -v ufw >/dev/null 2>&1; then
    # CRITICO: adicionar todas as regras ANTES de ativar o UFW
    # Ativar com deny incoming sem liberar as portas trava o acesso
    ufw allow ssh
    [ -n "$WEB_PORT" ] && ufw allow "$WEB_PORT"/tcp
    ufw allow 10050/tcp   # Zabbix Agent
    ufw allow 10051/tcp   # Zabbix Trapper
    [ -n "$MGMT_NET" ] && ufw allow from "$MGMT_NET" to any

    ufw default deny incoming
    ufw default allow outgoing
    ufw logging medium

    # AVISO: "allow from REDE" suprime eventos [UFW BLOCK] para essa rede
    if [ -n "$MGMT_NET" ]; then
        warn "allow from $MGMT_NET suprime eventos [UFW BLOCK] da rede de gerenciamento."
        info "Use regras especificas por porta se precisar detectar bloqueios internos."
    fi

    ufw --force enable
    ok "UFW configurado (regras adicionadas antes do enable)"
else
    info "UFW nao encontrado — configure o firewall manualmente"
fi

# ── 9. Sanidade do lado servidor (quando o agente roda no proprio appliance) ─
step "9. Verificando configuracao do servidor (local)"

INGEST_HOST=$(echo "$INGEST_URL" | grep -oP '(?<=://)[^/]+(?=/)' | cut -d: -f1)
IS_LOCAL=0
if [[ "$INGEST_HOST" == "127.0.0.1" || "$INGEST_HOST" == "localhost" || \
      "$INGEST_HOST" == "$(hostname -I | awk '{print $1}')" ]]; then
    IS_LOCAL=1
fi

if [ "$IS_LOCAL" -eq 1 ]; then
    CONFIG_PHP="/etc/zabbix/ddosguard/ingest.config.php"

    # 9a. Permissoes do ingest.config.php
    if [ -f "$CONFIG_PHP" ]; then
        chown "root:$WEB_USER" "$CONFIG_PHP"
        chmod 640 "$CONFIG_PHP"
        chmod 755 "$(dirname "$CONFIG_PHP")"
        ok "Permissoes do ingest.config.php corrigidas (root:$WEB_USER 640)"

        # Testa se o www-data consegue ler (causa raiz do 401)
        if sudo -u "$WEB_USER" cat "$CONFIG_PHP" >/dev/null 2>&1; then
            ok "$WEB_USER consegue ler o config (401 nao devera ocorrer)"
        else
            warn "$WEB_USER NAO consegue ler o config — 401 ira ocorrer!"
            info "Verifique: chown root:$WEB_USER $CONFIG_PHP && chmod 640 $CONFIG_PHP"
        fi

        # 9b. DG_ZBX_SERVER nao pode ter porta (causa timeout de 20s)
        if grep -qP "DG_ZBX_SERVER.*:\d+" "$CONFIG_PHP" 2>/dev/null; then
            warn "DG_ZBX_SERVER contem ':porta' — isso causa timeout de ~20s no ingest!"
            info "Corrigindo automaticamente (mantendo so o host)..."
            sed -i "s/\(DG_ZBX_SERVER.*'\)[^']*:\([0-9]*\)'/\1127.0.0.1'/" "$CONFIG_PHP"
            ok "DG_ZBX_SERVER corrigido para '127.0.0.1'"
        fi

        # Remove qualquer copia/symlink do config no webroot (risco de exposicao via HTTP)
        WEBROOT=$(grep -r "root " /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*.conf \
            /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -v "#" | \
            grep -oP "root\s+\K[^;]+" | head -1 || true)
        WEBROOT="${WEBROOT:-/usr/share/zabbix/ui}"
        for f in "$WEBROOT/ddosguard/ingest.config.php" \
                 "$WEBROOT/ingest.config.php"; do
            if [ -e "$f" ]; then
                rm -f "$f"
                warn "Removido $f do webroot (exposicao de senha do banco via HTTP!)"
            fi
        done
    else
        info "ingest.config.php nao encontrado em $CONFIG_PHP"
        info "Execute scripts/setup.py primeiro para configurar o servidor"
    fi
fi

# ── 10. Testes finais ────────────────────────────────────────────────────────
step "10. Testes finais"
sleep 8   # aguarda o agente inicializar

# 10a. Heartbeat via zabbix_sender (diagnostico de failed: 1)
ZBX_SENDER=$(command -v zabbix_sender 2>/dev/null || true)
if [ -n "$ZBX_SENDER" ]; then
    SENDER_RESULT=$(
        "$ZBX_SENDER" -z 127.0.0.1 -p 10051 \
            -s "$ZBX_HOST" -k ddosguard.agent.heartbeat -o 1 2>&1 || true
    )
    if echo "$SENDER_RESULT" | grep -q "processed: 1"; then
        ok "zabbix_sender: heartbeat aceito (processed: 1)"
    elif echo "$SENDER_RESULT" | grep -q "failed: 1"; then
        warn "zabbix_sender: failed: 1 — possiveis causas:"
        info "  1. zbx_host='$ZBX_HOST' nao existe no Zabbix (ou e o nome visivel, nao o tecnico)"
        info "  2. Template 'DDoS Guard - Agent' nao esta associado ao host"
        info "  3. Item 'ddosguard.agent.heartbeat' esta desabilitado"
        info "  Diagnostico: mysql -u zabbix -p zabbix -e \\"
        info "    \"SELECT h.host, i.key_, i.status FROM hosts h"
        info "     JOIN items i ON i.hostid=h.hostid"
        info "     WHERE i.key_ LIKE 'ddosguard%' AND h.host='$ZBX_HOST';\""
    else
        info "zabbix_sender: $SENDER_RESULT"
    fi
fi

# 10b. Curl com medicao de latencia (detecta DG_ZBX_SERVER com porta)
if command -v curl >/dev/null 2>&1; then
    LATENCY=$(curl -s -o /dev/null -w "%{time_total}" \
        -H "Content-Type: application/json" \
        -H "X-DG-Token: $TOKEN" \
        -d '{"event_type":"heartbeat","zbx_host":"'"$ZBX_HOST"'"}' \
        "$INGEST_URL" 2>/dev/null | awk '{printf "%.1f", $1}' || echo "?")
    if echo "$LATENCY" | awk '{exit ($1 > 5)}' 2>/dev/null; then
        ok "Ingest respondeu em ${LATENCY}s"
    else
        warn "Ingest lento: ${LATENCY}s (esperado < 1s)"
        info "Causas mais comuns:"
        info "  1. DG_ZBX_SERVER contem 'IP:porta' em vez de so o IP"
        info "  2. DG_DB_HOST inacessivel (timeout de conexao com o banco)"
        info "  Verifique: grep DG_ZBX /etc/zabbix/ddosguard/ingest.config.php"
    fi

    # Testa 401 — causas em ordem de probabilidade
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Content-Type: application/json" \
        -H "X-DG-Token: $TOKEN" \
        -d '{"event_type":"heartbeat","zbx_host":"'"$ZBX_HOST"'"}' \
        "$INGEST_URL" 2>/dev/null || echo "000")
    if [ "$STATUS" = "200" ]; then
        ok "Ingest respondeu 200 OK"
    elif [ "$STATUS" = "401" ]; then
        warn "Ingest retornou 401 (mesmo com token correto) — causas em ordem:"
        info "  1. Permissao do config: chown root:$WEB_USER /etc/zabbix/ddosguard/ingest.config.php && chmod 640"
        info "  2. Symlink do config no webroot: ls -la \$WEBROOT/ddosguard/ingest.config.php"
        info "  3. Token diferente nos dois lados: diff <(grep TOKEN /etc/zabbix/ddosguard/ingest.config.php) <(grep token $CONF_FILE)"
        info "  4. PHP nao consegue fazer include: tail /var/log/nginx/error.log"
    else
        warn "Ingest retornou HTTP $STATUS"
    fi
fi

# 10c. Journal do agente
sleep 3
JOURNAL=$(journalctl -u ddos-guard-agent --since "30 seconds ago" \
    --no-pager -q 2>/dev/null | tail -5 || \
    systemctl status ddos-guard-agent --no-pager 2>/dev/null | tail -5)
if echo "$JOURNAL" | grep -q "Heartbeat enviado"; then
    ok "Agente enviando heartbeats com sucesso"
elif echo "$JOURNAL" | grep -q "401"; then
    warn "Agente com erro 401 — veja os diagnosticos acima"
else
    info "Acompanhe: journalctl -u ddos-guard-agent -f"
fi

# ── Resumo ───────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}======================================================================"
echo -e " Resumo"
echo -e "======================================================================${NC}"
echo -e "  Agente instalado em ..... ${INSTALL_DIR}/ddos_guard_agent.py"
echo -e "  Configuracao ............ ${CONF_FILE} (modo 600)"
echo -e "  Servico .................. ddos-guard-agent (systemd)"
echo -e "  zbx_host ................. ${ZBX_HOST}"
echo -e "  Servidor (ingest_url) .... ${INGEST_URL}"
echo ""
echo -e "  Verifique o status:"
echo -e "    systemctl status ddos-guard-agent"
echo -e "    journalctl -u ddos-guard-agent -f"
