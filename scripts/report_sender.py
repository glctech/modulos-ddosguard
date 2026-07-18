#!/usr/bin/env python3
"""
DDoS Guard - Gerador e Enviador Automático de Relatórios
=========================================================
Coleta dados do banco MySQL, gera relatório HTML profissional
e envia por e-mail via SMTP.

USO:
  # Relatório diário
  python3 report_sender.py --to cliente@empresa.com --client "Athena"

  # Relatório de incidente (banner vermelho)
  python3 report_sender.py --to cliente@empresa.com --client "Athena" --incident

  # Múltiplos destinatários
  python3 report_sender.py --to "ti@athena.com,suporte@glctech.com.br" --client "Athena"

  # Apenas gera o HTML sem enviar
  python3 report_sender.py --to teste@glctech.com.br --client "Teste" --dry-run

CONFIGURAÇÃO (/etc/zabbix/ddosguard/report.conf):
  [smtp]
  host      = smtp.gmail.com
  port      = 587
  user      = suporte@glctech.com.br
  password  = sua_senha_ou_app_password
  from      = suporte@glctech.com.br
  from_name = GLCTech - Monitoramento

  [report]
  logo_path  = /etc/zabbix/ddosguard/logo_glctech.png
  output_dir = /tmp/ddosguard_reports
  client     = Nome Padrão do Cliente
  to         = cliente@empresa.com

CRON (relatório diário às 08:00):
  0 8 * * * root python3 /opt/zabbix/ddosguard/report_sender.py \
    --client "Athena" --to "ti@athena.com" >> /var/log/ddosguard_report.log 2>&1

CRON (relatório semanal às segundas 09:00):
  0 9 * * 1 root python3 /opt/zabbix/ddosguard/report_sender.py \
    --client "Athena" --to "ti@athena.com" --period 7d \
    >> /var/log/ddosguard_report.log 2>&1

INTEGRAÇÃO COM ZABBIX (disparar no alerta):
  Crie um Media Type do tipo Script no Zabbix com:
    Script: /usr/bin/python3 /opt/zabbix/ddosguard/report_sender.py
    Params: --to {ALERT.SENDTO} --client "Athena" --incident
"""

import os, sys, re, json, argparse, base64, configparser
import smtplib, ssl, subprocess
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from datetime import datetime, timedelta

# ── Caminhos padrão ──────────────────────────────────────────────────────────
CONFIG_PATH = '/etc/zabbix/ddosguard/report.conf'
AGENT_CONF  = '/etc/zabbix/ddos_guard_agent.conf'
OUTPUT_DIR  = '/tmp/ddosguard_reports'

# ── Carrega configurações ─────────────────────────────────────────────────────
def load_config():
    cfg = configparser.ConfigParser()
    cfg.read(CONFIG_PATH)
    return cfg

def load_agent_conf():
    data = {}
    try:
        for line in open(AGENT_CONF):
            line = line.strip()
            if '=' in line and not line.startswith('#') and not line.startswith('['):
                k, v = line.split('=', 1)
                data[k.strip()] = v.strip()
    except Exception as e:
        print(f'[WARN] agent.conf: {e}', file=sys.stderr)
    return data

def load_logo_b64(cfg):
    """Carrega o logo em base64 — do conf, do diretório do script ou do padrão."""
    logo_path = cfg.get('report', 'logo_path', fallback='')
    candidates = [
        logo_path,
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logo.png'),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logo_glctech.png'),
        '/etc/zabbix/ddosguard/logo_glctech.png',
    ]
    for p in candidates:
        if p and os.path.exists(p):
            return base64.b64encode(open(p, 'rb').read()).decode()
    return None

# ── Coleta dados do banco via PHP ─────────────────────────────────────────────
PHP_QUERY = r"""<?php
error_reporting(0);
$c = @include '/etc/zabbix/ddosguard/ingest.config.php';
if (!$c) { echo json_encode(['error'=>'config not found']); exit; }
try {
    $pdo = new PDO(
        $c['DG_DB_DRIVER'].':host='.$c['DG_DB_HOST'].';port='.$c['DG_DB_PORT'].
        ';dbname='.$c['DG_DB_NAME'].';charset=utf8mb4',
        $c['DG_DB_USER'], $c['DG_DB_PASS'],
        [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,
         PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);
} catch(Exception $e) {
    echo json_encode(['error'=>$e->getMessage()]); exit;
}
$period = isset($argv[1]) ? (int)$argv[1] : 24;
$since  = date('Y-m-d H:i:s', time() - $period * 3600);
$now    = date('Y-m-d H:i:s');

function q($pdo, $sql, $p=[]) {
    $s = $pdo->prepare($sql); $s->execute($p); return $s;
}

$a24  = q($pdo,"SELECT COUNT(*) c, COALESCE(SUM(attempts),0) att,
    COUNT(DISTINCT src_ip) ips, COUNT(DISTINCT hostid) hosts
    FROM ddosguard_attacks WHERE last_seen>=?"  ,[$since])->fetch();

$b24  = q($pdo,"SELECT COUNT(*) c, COUNT(DISTINCT src_ip) ips
    FROM ddosguard_blocks WHERE event_time>=?",[$since])->fetch();

$top  = q($pdo,"SELECT src_ip, country_name, attack_type,
    SUM(attempts) att, MAX(severity_label) sev, MAX(last_seen) ls
    FROM ddosguard_attacks WHERE last_seen>=?
    GROUP BY src_ip,country_name,attack_type
    ORDER BY att DESC LIMIT 5",[$since])->fetchAll();

$inc  = q($pdo,"SELECT src_ip,country_name,severity_score,severity_label,
    total_events,sources_json,last_seen
    FROM ddosguard_correlations
    WHERE resolved=0 AND severity_score>=7
    ORDER BY severity_score DESC,last_seen DESC LIMIT 5",[])->fetchAll();

$hosts = array_column(q($pdo,"SELECT DISTINCT h.host FROM hosts h
    JOIN items i ON i.hostid=h.hostid
    WHERE i.key_ LIKE 'ddosguard%' AND h.status=0 AND h.flags=0",[])->fetchAll(),'host');

$ctry = q($pdo,"SELECT country_name, COUNT(*) c
    FROM ddosguard_attacks WHERE last_seen>=? AND country_name IS NOT NULL
    GROUP BY country_name ORDER BY c DESC LIMIT 6",[$since])->fetchAll();

$types = q($pdo,"SELECT attack_type, COUNT(*) c
    FROM ddosguard_attacks WHERE last_seen>=?
    GROUP BY attack_type ORDER BY c DESC LIMIT 6",[$since])->fetchAll();

echo json_encode(compact('a24','b24','top','inc','hosts','ctry','types','now','period'));
"""

def get_db_data(period_hours=24):
    """Consulta o banco via PHP (tem acesso ao ingest.config.php)."""
    try:
        result = subprocess.run(
            ['php', '-r', PHP_QUERY, '--', str(period_hours)],
            capture_output=True, text=True, timeout=20)
        if result.returncode == 0 and result.stdout.strip().startswith('{'):
            return json.loads(result.stdout.strip())
    except Exception as e:
        print(f'[WARN] DB query: {e}', file=sys.stderr)
    return {}

# ── Renderização do HTML ──────────────────────────────────────────────────────
def render_html(client_name, data, logo_b64, is_incident=False):
    logo_src = f"data:image/png;base64,{logo_b64}" if logo_b64 else ''
    logo_img = (f'<img src="{logo_src}" alt="GLCTech" '
                f'style="height:48px;width:auto;display:block">'
                if logo_src else
                '<span style="color:#fff;font-size:18px;font-weight:bold">'
                'GLC<span style="color:#c00000">Tech</span></span>')

    now     = datetime.now()
    period  = int(data.get('period', 24))
    since   = (now - timedelta(hours=period)).strftime('%d/%m %H:%M')
    to_str  = now.strftime('%d/%m/%Y às %H:%M')

    a24   = data.get('a24', {})
    b24   = data.get('b24', {})
    top   = data.get('top', [])
    inc   = data.get('inc', [])
    hosts = data.get('hosts', [])
    ctry  = data.get('ctry', [])
    types = data.get('types', [])

    n_events   = int(a24.get('c', 0)   or 0)
    n_attempts = int(a24.get('att', 0) or 0)
    n_ips      = int(a24.get('ips', 0) or 0)
    n_blocks   = int(b24.get('c', 0)   or 0)
    n_hosts    = len(hosts)
    n_inc      = len(inc)

    banner_bg = '#c00000' if is_incident else '#0b5c2a'
    banner_lbl = ('⚠️ Alerta de segurança' if is_incident
                  else '📊 Relatório de monitoramento')

    def sev_color(s):
        return {'critical':'#c00000','high':'#c07000',
                'medium':'#b8860b','low':'#1a6a1a'}.get(s or 'info', '#555')

    def tag(text, bg, color):
        return (f'<span style="display:inline-block;background:{bg};color:{color};'
                f'padding:4px 10px;border-radius:12px;font-size:12px;margin:3px">'
                f'{text}</span>')

    top_rows = ''.join(f"""
      <tr>
        <td style="padding:9px 10px;border-bottom:1px solid #f0f0f0">
          <strong>{r.get("src_ip","")}</strong></td>
        <td style="padding:9px 10px;border-bottom:1px solid #f0f0f0;color:#666">
          {r.get("country_name") or "—"}</td>
        <td style="padding:9px 10px;border-bottom:1px solid #f0f0f0">
          {str(r.get("attack_type","")).replace("_"," ")}</td>
        <td style="padding:9px 10px;border-bottom:1px solid #f0f0f0;
            text-align:center;font-weight:bold">{int(r.get("att",0) or 0):,}</td>
        <td style="padding:9px 10px;border-bottom:1px solid #f0f0f0;text-align:center">
          <span style="background:{sev_color(r.get("sev"))}22;
              color:{sev_color(r.get("sev"))};padding:2px 8px;
              border-radius:10px;font-size:11px;font-weight:bold">
            {str(r.get("sev","INFO")).upper()}</span></td>
      </tr>""" for r in top) or (
        '<tr><td colspan="5" style="padding:16px;text-align:center;color:#888;'
        'font-size:13px">Nenhum ataque no período</td></tr>')

    inc_rows = ''.join(f"""
      <tr>
        <td style="padding:9px 10px;border-bottom:1px solid #f0f0f0">
          <strong style="color:#c00000">{r.get("src_ip","")}</strong></td>
        <td style="padding:9px 10px;border-bottom:1px solid #f0f0f0;color:#666">
          {r.get("country_name") or "—"}</td>
        <td style="padding:9px 10px;border-bottom:1px solid #f0f0f0;
            text-align:center;font-weight:bold;color:#c00000">
          {int(r.get("severity_score",0) or 0)}/10</td>
        <td style="padding:9px 10px;border-bottom:1px solid #f0f0f0;text-align:center">
          {int(r.get("total_events",0) or 0)}</td>
        <td style="padding:9px 10px;border-bottom:1px solid #f0f0f0;
            font-size:12px;color:#666">
          {", ".join(json.loads(r.get("sources_json") or "[]")) or "—"}</td>
      </tr>""" for r in inc) or (
        '<tr><td colspan="5" style="padding:16px;text-align:center;color:#1a6a1a;'
        'font-size:13px">✓ Nenhum incidente crítico ativo</td></tr>')

    ctry_tags  = ''.join(tag(f'{r["country_name"]} ({int(r["c"])})',
                             '#e8f0fe','#1a3a8a') for r in ctry) or \
                 '<span style="color:#888;font-size:13px">Sem dados</span>'

    type_tags  = ''.join(tag(f'{str(r["attack_type"]).replace("_"," ")} ({int(r["c"])})',
                             '#fff0f0','#c00000') for r in types) or \
                 '<span style="color:#888;font-size:13px">Sem dados</span>'

    host_tags  = ''.join(tag(f'✓ {h}','#f0fff0','#1a6a1a') for h in hosts) or \
                 '<span style="color:#888;font-size:13px">Nenhum host</span>'

    inc_badge = (f'<span style="background:#fde8e8;color:#c00000;padding:2px 8px;'
                 f'border-radius:10px;font-size:11px;font-weight:bold;margin-left:8px">'
                 f'{n_inc} ativo(s)</span>' if n_inc else '')

    def sec(title, extra=''):
        return (f'<div style="font-size:11px;font-weight:bold;color:#888;'
                f'text-transform:uppercase;letter-spacing:.08em;margin:20px 0 10px;'
                f'padding-bottom:8px;border-bottom:1px solid #eee">'
                f'{title}{extra}</div>')

    def tbl(rows, headers):
        ths = ''.join(f'<th style="padding:8px 10px;font-size:11px;font-weight:bold;'
                      f'color:#666;text-align:left;border-bottom:1px solid #ddd">'
                      f'{h}</th>' for h in headers)
        return (f'<table width="100%" cellpadding="0" cellspacing="0" style="'
                f'border:1px solid #eee;border-radius:6px;overflow:hidden;'
                f'margin-bottom:20px"><tr style="background:#f0f2f5">{ths}</tr>'
                f'{rows}</table>')

    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8">
<title>DDoS Guard — {client_name}</title></head>
<body style="margin:0;padding:0;background:#f0f2f5;
    font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#333">
<div style="max-width:680px;margin:0 auto;background:#fff">

  <div style="background:#0b1220;padding:24px 36px">{logo_img}</div>

  <div style="background:{banner_bg};padding:20px 36px">
    <div style="color:#fff;font-size:16px;font-weight:bold;margin-bottom:4px">
      {banner_lbl} — {client_name}</div>
    <div style="color:rgba(255,255,255,.7);font-size:12px">
      Período: {since} — {to_str} &nbsp;·&nbsp;
      Últimas {period}h &nbsp;·&nbsp; Gerado automaticamente</div>
  </div>

  <div style="padding:28px 36px 0">
    <div style="font-size:11px;font-weight:bold;color:#888;text-transform:uppercase;
        letter-spacing:.08em;margin-bottom:12px">Resumo do período</div>
    <table width="100%" cellpadding="0" cellspacing="8">
      <tr>
        <td style="background:#f8f9fb;border:1px solid #e8eaed;border-radius:6px;
            padding:14px;text-align:center">
          <div style="font-size:24px;font-weight:bold;color:#c00000">
            {n_events:,}</div>
          <div style="font-size:11px;color:#888;margin-top:4px">Eventos de ataque</div>
        </td><td width="8"></td>
        <td style="background:#f8f9fb;border:1px solid #e8eaed;border-radius:6px;
            padding:14px;text-align:center">
          <div style="font-size:24px;font-weight:bold;color:#c00000">
            {n_attempts:,}</div>
          <div style="font-size:11px;color:#888;margin-top:4px">Tentativas</div>
        </td><td width="8"></td>
        <td style="background:#f8f9fb;border:1px solid #e8eaed;border-radius:6px;
            padding:14px;text-align:center">
          <div style="font-size:24px;font-weight:bold;color:#e07800">
            {n_ips:,}</div>
          <div style="font-size:11px;color:#888;margin-top:4px">IPs distintos</div>
        </td><td width="8"></td>
        <td style="background:#f8f9fb;border:1px solid #e8eaed;border-radius:6px;
            padding:14px;text-align:center">
          <div style="font-size:24px;font-weight:bold;color:#1a6a1a">
            {n_blocks:,}</div>
          <div style="font-size:11px;color:#888;margin-top:4px">Bloqueios</div>
        </td>
      </tr>
    </table>
  </div>

  <div style="padding:20px 36px">
    {sec("Incidentes críticos ativos (score ≥ 7)", inc_badge)}
    {tbl(inc_rows, ["IP","País","Score","Eventos","Fontes"])}

    {sec("Top 5 IPs atacantes")}
    {tbl(top_rows, ["IP","País","Tipo de ataque","Tentativas","Severidade"])}

    <table width="100%" cellpadding="0" cellspacing="12">
      <tr>
        <td valign="top" width="50%">
          {sec("Origens (top países)")}
          {ctry_tags}
        </td>
        <td width="12"></td>
        <td valign="top" width="50%">
          {sec("Tipos de ataque")}
          {type_tags}
        </td>
      </tr>
    </table>

    <br>
    {sec(f"Hosts monitorados ({n_hosts})")}
    {host_tags}

    <br>
    <hr style="border:none;border-top:1px solid #eee;margin:20px 0">
    <div style="background:#f8f9fb;border:1px solid #e8eaed;border-radius:6px;
        padding:14px;font-size:12px;color:#555;line-height:1.7">
      Relatório gerado automaticamente pelo <strong>DDoS Guard SOC</strong> — GLCTech.
      Para suporte, responda este e-mail ou acesse
      <a href="https://glctech.com.br" style="color:#c00000">glctech.com.br</a>.
    </div>
  </div>

  <div style="background:#0b1220;padding:20px 36px;text-align:center">
    {logo_img}
    <div style="font-size:11px;color:#556677;margin-top:10px;line-height:1.7">
      suporte@glctech.com.br &nbsp;·&nbsp; DDoS Guard SOC &nbsp;·&nbsp; Zabbix 7.4<br>
      <a href="https://glctech.com.br" style="color:#7799aa;text-decoration:none">
        glctech.com.br</a>
    </div>
  </div>

</div></body></html>"""

# ── Envio de e-mail ───────────────────────────────────────────────────────────
def send_email(cfg, recipients, subject, html):
    host      = cfg.get('smtp', 'host',      fallback='smtp.gmail.com')
    port      = cfg.getint('smtp', 'port',   fallback=587)
    user      = cfg.get('smtp', 'user',      fallback='')
    password  = cfg.get('smtp', 'password',  fallback='')
    from_addr = cfg.get('smtp', 'from',      fallback=user)
    from_name = cfg.get('smtp', 'from_name', fallback='GLCTech - Monitoramento')

    if not user or not password:
        raise ValueError('SMTP user/password não configurados em report.conf')

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = f'{from_name} <{from_addr}>'
    msg['To']      = ', '.join(recipients)
    msg.attach(MIMEText(html, 'html', 'utf-8'))

    ctx = ssl.create_default_context()
    with smtplib.SMTP(host, port) as srv:
        srv.ehlo()
        srv.starttls(context=ctx)
        srv.login(user, password)
        srv.sendmail(from_addr, recipients, msg.as_string())

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description='DDoS Guard Report Sender')
    ap.add_argument('--to',       required=True,
                    help='Destinatário(s) separados por vírgula')
    ap.add_argument('--client',   default='Cliente',
                    help='Nome do cliente')
    ap.add_argument('--period',   default='24',
                    help='Período em horas (ex: 24, 48, 168 para 7 dias)')
    ap.add_argument('--incident', action='store_true',
                    help='Modo alerta de incidente (banner vermelho)')
    ap.add_argument('--dry-run',  action='store_true',
                    help='Gera HTML mas não envia o e-mail')
    ap.add_argument('--output',   default='',
                    help='Caminho para salvar o HTML gerado')
    args = ap.parse_args()

    period_hours = int(re.sub(r'[^0-9]', '', args.period) or '24')
    cfg          = load_config()
    agent_conf   = load_agent_conf()
    logo_b64     = load_logo_b64(cfg)

    print(f'[INFO] Coletando dados ({period_hours}h)...')
    data = get_db_data(period_hours)
    if data.get('error'):
        print(f'[WARN] Banco: {data["error"]}', file=sys.stderr)
        data = {}

    print(f'[INFO] Gerando HTML...')
    html = render_html(args.client, data, logo_b64, args.incident)

    # Salva HTML
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ts       = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_path = args.output or os.path.join(
        OUTPUT_DIR, f'relatorio_{args.client.replace(" ","_")}_{ts}.html')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f'[OK] HTML salvo: {out_path}')

    if args.dry_run:
        print('[INFO] --dry-run: e-mail NÃO enviado.')
        return out_path

    # Monta assunto
    a24 = data.get('a24', {})
    n   = int(a24.get('c', 0) or 0)
    pfx = '⚠️ ALERTA' if args.incident else '📊 Relatório'
    subject = (f'{pfx} de segurança DDoS Guard — {args.client}'
               + (f' · {n:,} eventos em {period_hours}h' if n else ''))

    recipients = [e.strip() for e in args.to.split(',') if e.strip()]
    print(f'[INFO] Enviando para {recipients}...')
    try:
        send_email(cfg, recipients, subject, html)
        print(f'[OK] E-mail enviado!')
    except Exception as e:
        print(f'[ERR] Falha ao enviar: {e}', file=sys.stderr)
        print(f'[INFO] HTML disponível em: {out_path}')
        sys.exit(1)

    return out_path

if __name__ == '__main__':
    main()
