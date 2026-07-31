#!/bin/bash
# =====================================================================
# DDoS Guard — Upgrade v2 → v3
# =====================================================================
# Substitui os arquivos PHP publicados no webroot pelas versões
# corrigidas deste repositório, faz backup do que estava lá e valida a
# sintaxe antes de concluir.
#
# É mais seguro que aplicar patches: se sua instalação já recebeu
# correções manuais, este script sobrescreve com a versão canônica.
#
# Uso:
#   bash scripts/upgrade_v3.sh [--ddosguard-dir DIR] [--dry-run]
#
# Padrão de DIR: /usr/share/zabbix/ui/ddosguard
# =====================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; exit 1; }
info() { echo -e "     $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
DDOSGUARD_DIR="/usr/share/zabbix/ui/ddosguard"
DRY=0

for arg in "$@"; do
    case "$arg" in
        --ddosguard-dir=*) DDOSGUARD_DIR="${arg#*=}" ;;
        --dry-run)         DRY=1 ;;
    esac
done

echo "============================================================"
echo " DDoS Guard — Upgrade v2 → v3"
[ "$DRY" -eq 1 ] && echo " MODO DRY-RUN — nada será gravado"
echo "============================================================"
info "origem : $REPO_DIR"
info "destino: $DDOSGUARD_DIR"
echo ""

[ -d "$DDOSGUARD_DIR" ] || err "Diretório não encontrado: $DDOSGUARD_DIR"
command -v php >/dev/null || err "php não encontrado no PATH"

STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="/root/ddosguard-backup-$STAMP"

# ----------------------------------------------------------------
# 1. Backup
# ----------------------------------------------------------------
if [ "$DRY" -eq 0 ]; then
    mkdir -p "$BACKUP"
    cp -a "$DDOSGUARD_DIR"/. "$BACKUP"/ 2>/dev/null || true
    ok "Backup em $BACKUP"
else
    info "(dry-run) backup iria para $BACKUP"
fi

# ----------------------------------------------------------------
# 2. Copia os arquivos corrigidos
# ----------------------------------------------------------------
FILES=(
    "scripts/ingest.php:ingest.php"
    "scripts/correlator.php:correlator.php"
    "scripts/integrations/syslog_receiver.php:integrations/syslog_receiver.php"
    "scripts/integrations/mikrotik_receiver.php:integrations/mikrotik_receiver.php"
    "scripts/integrations/suricata_receiver.php:integrations/suricata_receiver.php"
    "scripts/integrations/wazuh_receiver.php:integrations/wazuh_receiver.php"
    "scripts/integrations/sophos_receiver.php:integrations/sophos_receiver.php"
)

for pair in "${FILES[@]}"; do
    SRC="$REPO_DIR/${pair%%:*}"
    DST="$DDOSGUARD_DIR/${pair##*:}"
    [ -f "$SRC" ] || { warn "origem ausente, pulando: ${pair%%:*}"; continue; }

    if ! php -l "$SRC" >/dev/null 2>&1; then
        err "Sintaxe inválida na ORIGEM: $SRC"
    fi

    if [ "$DRY" -eq 1 ]; then
        info "(dry-run) $SRC -> $DST"
        continue
    fi

    mkdir -p "$(dirname "$DST")"
    install -m 0644 "$SRC" "$DST"
    php -l "$DST" >/dev/null || err "Sintaxe inválida após copiar: $DST"
    ok "${pair##*:}"
done

# O symlink ingest.config.php -> /etc/zabbix/ddosguard/ é preservado:
# não copiamos config, só código.

# ----------------------------------------------------------------
# 3. Verificações pós-upgrade
# ----------------------------------------------------------------
echo ""
echo "==> Verificações"

# 3.1 conflito de rsyslog
CONFLITOS=$(grep -rl 'imudp' /etc/rsyslog.d/ 2>/dev/null | wc -l)
if [ "$CONFLITOS" -gt 1 ]; then
    warn "$CONFLITOS arquivos em /etc/rsyslog.d/ carregam imudp."
    info "Só um pode carregar. Os demais fazem o rsyslog abortar o bloco em silêncio."
    grep -rl 'imudp' /etc/rsyslog.d/ | sed 's/^/       /'
else
    ok "Sem conflito de imudp em /etc/rsyslog.d/"
fi

# 3.2 template do omprog termina em \n
if grep -rq 'template="RSYSLOG_TraditionalForwardFormat"' /etc/rsyslog.d/ddosguard*.conf 2>/dev/null; then
    if grep -A6 'type="omprog"' /etc/rsyslog.d/ddosguard*.conf 2>/dev/null \
       | grep -q 'RSYSLOG_TraditionalForwardFormat'; then
        warn "A action omprog usa RSYSLOG_TraditionalForwardFormat, que NÃO termina em \\n."
        info "O rsyslog vai rejeitar todas as mensagens. Use rsyslog/ddosguard-syslog.conf."
    fi
else
    ok "Template do omprog aparenta estar correto"
fi

# 3.3 config do host MikroTik
CFG="/etc/zabbix/ddosguard/ingest.config.php"
if [ -f "$CFG" ]; then
    if grep -q 'DG_MIKROTIK_ZBX_HOST' "$CFG"; then
        ok "DG_MIKROTIK_ZBX_HOST presente em $CFG"
    else
        warn "Falta DG_MIKROTIK_ZBX_HOST em $CFG"
        info "Adicione (nome TÉCNICO do host, idêntico ao cadastro no Zabbix):"
        info "  'DG_MIKROTIK_ZBX_HOST'   => 'MIKROTIK CCR 1009',"
        info "  'DG_MIKROTIK_ZBX_HOSTID' => 10780,"
    fi
    PERM=$(stat -c '%a %U:%G' "$CFG" 2>/dev/null || echo "?")
    info "Permissão do config: $PERM (esperado 640 root:www-data)"
else
    warn "Config não encontrado: $CFG"
fi

# 3.4 zabbix_sender
if command -v zabbix_sender >/dev/null; then
    ok "zabbix_sender: $(command -v zabbix_sender)"
else
    warn "zabbix_sender não encontrado — o envio ao Zabbix vai falhar em silêncio"
fi

echo ""
echo "============================================================"
if [ "$DRY" -eq 1 ]; then
    echo " DRY-RUN concluído."
else
    echo " Upgrade concluído. Backup: $BACKUP"
    echo ""
    echo " Próximos passos:"
    echo "   1. systemctl restart rsyslog"
    echo "   2. sleep 60 && tail -c 2000 /var/log/ddosguard-omprog.log   (vazio = bom)"
    echo "   3. Confira o banco:"
    echo "      SELECT block_id, src_ip, reason, event_time"
    echo "        FROM ddosguard_blocks ORDER BY 1 DESC LIMIT 5;"
fi
echo "============================================================"
