#!/bin/bash
# DDoS Guard - Corretor do ClamAV (Rocky Linux / RHEL)
# =====================================================
# Corrige banco de dados corrompido e reconfigura o ClamAV
# Execute como root no appliance Zabbix.

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; }

echo "============================================================"
echo " DDoS Guard - Corretor do ClamAV"
echo "============================================================"

# 1. Para os servicos do ClamAV
echo ""
echo "==> Parando servicos do ClamAV..."
systemctl stop clamd@scan 2>/dev/null || true
systemctl stop clamav-freshclam 2>/dev/null || true
ok "Servicos parados"

# 2. Remove banco de dados corrompido
echo ""
echo "==> Removendo banco de dados corrompido..."
CLAMDB="/var/lib/clamav"
for f in main.cld main.cvd daily.cld daily.cvd bytecode.cld bytecode.cvd; do
    if [ -f "$CLAMDB/$f" ]; then
        rm -f "$CLAMDB/$f"
        ok "Removido: $CLAMDB/$f"
    fi
done

# 3. Verifica espaco em disco (precisa de ~500MB)
FREE_MB=$(df -m /var/lib/clamav | tail -1 | awk '{print $4}')
echo ""
echo "==> Espaco disponivel em /var/lib/clamav: ${FREE_MB}MB"
if [ "$FREE_MB" -lt 500 ]; then
    warn "Menos de 500MB disponivel — o freshclam pode falhar!"
fi

# 4. Corrige permissoes
echo ""
echo "==> Corrigindo permissoes..."
chown -R clamupdate:clamupdate /var/lib/clamav/ 2>/dev/null || \
chown -R clamav:clamav /var/lib/clamav/ 2>/dev/null || true
chmod 755 /var/lib/clamav/
ok "Permissoes corrigidas"

# 5. Atualiza as definicoes
echo ""
echo "==> Atualizando definicoes de virus (freshclam)..."
echo "    (pode demorar alguns minutos...)"
freshclam 2>&1 | tail -5
if [ $? -eq 0 ]; then
    ok "Definicoes atualizadas com sucesso"
else
    warn "freshclam retornou erro — verifique a conectividade"
fi

# 6. Verifica os arquivos baixados
echo ""
echo "==> Verificando banco de dados:"
ls -lh /var/lib/clamav/*.cvd /var/lib/clamav/*.cld 2>/dev/null || \
    warn "Nenhum arquivo de definicao encontrado"

# 7. Reinicia o clamd
echo ""
echo "==> Reiniciando clamd..."
systemctl start clamd@scan 2>/dev/null && ok "clamd@scan iniciado" || \
    warn "Nao foi possivel iniciar clamd@scan"

# 8. Corrige o agent.conf (caminho do log)
AGENT_CONF="/etc/zabbix/ddos_guard_agent.conf"
if [ -f "$AGENT_CONF" ]; then
    CURRENT_LOG=$(grep "^clamav_log" "$AGENT_CONF" | cut -d= -f2 | tr -d ' ')
    CORRECT_LOG="/var/log/clamav/clamd.log"

    if [ "$CURRENT_LOG" != "$CORRECT_LOG" ]; then
        echo ""
        echo "==> Corrigindo caminho do log do ClamAV no agent.conf..."
        sed -i "s|^clamav_log.*|clamav_log = $CORRECT_LOG|" "$AGENT_CONF"
        ok "clamav_log atualizado para: $CORRECT_LOG"
    else
        ok "clamav_log ja esta correto: $CORRECT_LOG"
    fi
fi

# 9. Garante permissao no log
touch /var/log/clamav/clamd.log 2>/dev/null || true
chmod 644 /var/log/clamav/clamd.log 2>/dev/null || true
chown clamupdate:clamupdate /var/log/clamav/clamd.log 2>/dev/null || \
chown clamav:clamav /var/log/clamav/clamd.log 2>/dev/null || true

# 10. Testa o ClamAV com o arquivo EICAR
echo ""
echo "==> Testando deteccao com arquivo EICAR..."
EICAR='/tmp/eicar_ddosguard_test.txt'
printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
    > "$EICAR"

clamscan --log=/var/log/clamav/clamd.log "$EICAR" 2>/dev/null
EXIT=$?
rm -f "$EICAR"

if [ $EXIT -eq 1 ]; then
    ok "ClamAV detectou o arquivo EICAR corretamente (exit=1 = virus encontrado)"
    tail -3 /var/log/clamav/clamd.log
elif [ $EXIT -eq 0 ]; then
    warn "ClamAV nao detectou o EICAR (exit=0 = limpo) — banco pode estar incompleto"
else
    warn "ClamAV retornou exit=$EXIT — possivel erro"
fi

# 11. Reinicia o agente DDoS Guard
echo ""
echo "==> Reiniciando o agente DDoS Guard..."
systemctl restart ddos-guard-agent 2>/dev/null && ok "Agente reiniciado" || \
    warn "Nao foi possivel reiniciar o agente"

echo ""
echo "============================================================"
echo -e "${GREEN} Correcao do ClamAV concluida!${NC}"
echo "============================================================"
echo ""
echo "Para testar a deteccao completa (agente → ingest → Zabbix):"
echo "  1. Aguarde 30s para o agente inicializar"
echo "  2. Execute: clamscan --log=/var/log/clamav/clamd.log /tmp/eicar_test.txt"
echo "  3. Verifique o log: journalctl -u ddos-guard-agent -n 10 --no-pager"
echo "  4. Verifique no Zabbix: Latest data > appliance > antivirus blocks"
