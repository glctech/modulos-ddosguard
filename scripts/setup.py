#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS Guard - Setup interativo
=============================
Detecta automaticamente o ambiente do Zabbix (appliance oficial, ou
instalação manual com Apache/Nginx + PHP-FPM, MySQL/MariaDB ou
PostgreSQL) e configura corretamente:

  1. /etc/zabbix/ddosguard/ingest.config.php   (config do endpoint PHP)
  2. <webroot>/ddosguard/ingest.php             (cópia do endpoint)
  3. /etc/zabbix/ddos_guard_agent.conf          (config do agente coletor)
  4. Tabelas auxiliares no banco (executa sql/schema.sql se necessário)

Sem dependências externas — usa apenas a biblioteca padrão do Python 3
(roda em qualquer appliance, mesmo sem pip/venv disponível).

Uso:
    python3 setup.py
    python3 setup.py --yes        # aceita os defaults detectados sem perguntar
    python3 setup.py --dry-run    # mostra o que faria, sem escrever nada
"""

import argparse
import configparser
import getpass
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request

# ---------------------------------------------------------------------
# Constantes / caminhos padrão
# ---------------------------------------------------------------------

PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_CONFIG_DIR = "/etc/zabbix/ddosguard"
DEFAULT_INGEST_CONFIG_PATH = f"{DEFAULT_CONFIG_DIR}/ingest.config.php"
DEFAULT_AGENT_CONFIG_PATH = "/etc/zabbix/ddos_guard_agent.conf"
DEFAULT_STATE_DIR = "/var/lib/zabbix/ddosguard"

ZABBIX_SERVER_CONF_CANDIDATES = [
    "/etc/zabbix/zabbix_server.conf",
    "/usr/local/etc/zabbix_server.conf",
]

FRONTEND_WEBROOT_CANDIDATES = [
    "/usr/share/zabbix",        # appliance oficial / pacotes RPM/DEB padrão
    "/usr/share/zabbix/ui",     # algumas versões empacotam em /ui
    "/var/www/html/zabbix",
    "/var/www/zabbix",
]

NGINX_CONF_CANDIDATES = [
    "/etc/nginx/conf.d/zabbix.conf",
    "/etc/nginx/conf.d/zabbix_nginx_ssl.conf",
    "/etc/nginx/conf.d/zabbix_ssl.conf",
    "/etc/nginx/sites-enabled/zabbix.conf",
]

APACHE_CONF_CANDIDATES = [
    "/etc/httpd/conf.d/zabbix.conf",
    "/etc/apache2/conf-enabled/zabbix.conf",
    "/etc/apache2/sites-enabled/000-default.conf",
]

ZABBIX_SENDER_CANDIDATES = [
    "/usr/bin/zabbix_sender",
    "/usr/local/bin/zabbix_sender",
    "/usr/sbin/zabbix_sender",
]

GEOIP_DB_CANDIDATES = [
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
]

LOG_CANDIDATES = {
    "iptables_log": ["/var/log/kern.log", "/var/log/messages", "/var/log/iptables.log"],
    "ufw_log": ["/var/log/ufw.log"],
    "fail2ban_log": ["/var/log/fail2ban.log"],
    "clamav_log": ["/var/log/clamav/clamav.log", "/var/log/clamd.log"],
    "auth_log": ["/var/log/auth.log", "/var/log/secure"],
}


# ---------------------------------------------------------------------
# Helpers de UI no terminal
# ---------------------------------------------------------------------

def header(title):
    print()
    print("=" * 70)
    print(f" {title}")
    print("=" * 70)


def info(msg):
    print(f"  [i] {msg}")


def ok(msg):
    print(f"  [OK] {msg}")


def warn(msg):
    print(f"  [!] {msg}")


def err(msg):
    print(f"  [ERRO] {msg}")


def ask(prompt, default=None, secret=False, assume_yes=False):
    """Pergunta interativa com valor padrão. Se assume_yes, retorna o
    default direto sem perguntar (modo --yes)."""
    if assume_yes:
        return default if default is not None else ""

    suffix = f" [{default}]" if default not in (None, "") else ""
    full_prompt = f"  {prompt}{suffix}: "

    try:
        if secret:
            value = getpass.getpass(full_prompt)
        else:
            value = input(full_prompt)
    except EOFError:
        value = ""

    value = value.strip()
    if not value and default is not None:
        return default
    return value


def ask_yes_no(prompt, default=True, assume_yes=False):
    if assume_yes:
        return default
    d = "S/n" if default else "s/N"
    while True:
        v = input(f"  {prompt} [{d}]: ").strip().lower()
        if not v:
            return default
        if v in ("s", "sim", "y", "yes"):
            return True
        if v in ("n", "nao", "não", "no"):
            return False
        print("  Responda com s ou n.")


def _run(cmd, timeout=None, env=None, input_file=None):
    """Wrapper de subprocess.run compatível com Python 3.6+ (o appliance
    oficial do Zabbix roda Python 3.6, que não tem os parâmetros
    capture_output/text introduzidos no 3.7). Sempre retorna texto
    (stdout/stderr como str, não bytes)."""
    kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "universal_newlines": True,
        "timeout": timeout,
    }
    if env is not None:
        kwargs["env"] = env
    if input_file is not None:
        kwargs["stdin"] = input_file
    return subprocess.run(cmd, **kwargs)


# ---------------------------------------------------------------------
# Detecção do ambiente
# ---------------------------------------------------------------------

def find_first_existing(paths):
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def detect_webserver():
    """Retorna 'nginx', 'apache' ou None, com base no que está
    instalado/rodando no sistema."""
    if shutil.which("nginx") or find_first_existing(NGINX_CONF_CANDIDATES):
        # Confirma se nginx está de fato ativo (evita falso positivo se
        # os dois estiverem instalados mas só um rodando).
        if _service_is_active("nginx"):
            return "nginx"
    if shutil.which("httpd") or shutil.which("apache2") or find_first_existing(APACHE_CONF_CANDIDATES):
        if _service_is_active("httpd") or _service_is_active("apache2"):
            return "apache"
    # fallback: se nenhum está "ativo" mas existe config, assume pelo que existir
    if find_first_existing(NGINX_CONF_CANDIDATES):
        return "nginx"
    if find_first_existing(APACHE_CONF_CANDIDATES):
        return "apache"
    return None


def _service_is_active(service_name):
    try:
        result = _run(["systemctl", "is-active", service_name], timeout=5)
        return result.stdout.strip() == "active"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def detect_php_fpm_pool():
    """Tenta achar o arquivo de pool do PHP-FPM usado pelo Zabbix, para
    avisar sobre clear_env."""
    candidates = []
    for base in ("/etc/php-fpm.d", "/etc/php/*/fpm/pool.d"):
        if "*" in base:
            import glob
            candidates += glob.glob(base)
        else:
            candidates.append(base)

    for base in candidates:
        if not os.path.isdir(base):
            continue
        for fname in os.listdir(base):
            if fname.endswith(".conf") and ("zabbix" in fname.lower() or fname == "www.conf"):
                return os.path.join(base, fname)
    return None


def parse_zabbix_server_conf():
    """Lê DBHost/DBName/DBUser/DBPassword/DBPort do zabbix_server.conf,
    se existir e for legível."""
    path = find_first_existing(ZABBIX_SERVER_CONF_CANDIDATES)
    if not path:
        return {}, None

    values = {}
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip()
                if key in ("DBHost", "DBName", "DBUser", "DBPassword", "DBPort", "DBSocket"):
                    values[key] = value
    except PermissionError:
        return {}, path

    return values, path


def detect_db_driver():
    """Verifica qual cliente de banco está disponível (mysql ou psql),
    para inferir o driver mais provável."""
    if shutil.which("mysql"):
        return "mysql"
    if shutil.which("psql"):
        return "pgsql"
    return "mysql"


def detect_zabbix_sender():
    return find_first_existing(ZABBIX_SENDER_CANDIDATES) or shutil.which("zabbix_sender")


def detect_frontend_webroot():
    """Tenta achar o webroot real lendo a diretiva 'root' do vhost do
    Nginx/Apache (forma confiável) e só cai para a lista de caminhos
    prováveis se não conseguir ler a config do servidor web."""
    nginx_root = _read_nginx_root()
    if nginx_root:
        return nginx_root

    apache_root = _read_apache_documentroot()
    if apache_root:
        return apache_root

    return find_first_existing(FRONTEND_WEBROOT_CANDIDATES)


def _read_nginx_root():
    """Lê a primeira diretiva 'root <path>;' encontrada nos vhosts do
    Zabbix. Evita usar a lista de candidatos por nome de pasta, que pode
    escolher /usr/share/zabbix quando o Nginx na verdade serve a partir
    de /usr/share/zabbix/ui (ou vice-versa)."""
    conf_path = find_first_existing(NGINX_CONF_CANDIDATES)
    if not conf_path:
        return None
    try:
        with open(conf_path, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (PermissionError, OSError):
        return None

    match = re.search(r"\broot\s+([^\s;]+)\s*;", content)
    if match:
        path = match.group(1).strip()
        if os.path.isdir(path):
            return path
    return None


def _read_apache_documentroot():
    conf_path = find_first_existing(APACHE_CONF_CANDIDATES)
    if not conf_path:
        return None
    try:
        with open(conf_path, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (PermissionError, OSError):
        return None

    match = re.search(r"(?i)\bDocumentRoot\s+\"?([^\s\"]+)\"?", content)
    if match:
        path = match.group(1).strip()
        if os.path.isdir(path):
            return path
    return None


def detect_geoip_db():
    return find_first_existing(GEOIP_DB_CANDIDATES)


def detect_log_path(kind):
    for path in LOG_CANDIDATES.get(kind, []):
        if os.path.exists(path):
            return path
    return LOG_CANDIDATES.get(kind, [""])[0]


def generate_token():
    return secrets.token_hex(32)


# ---------------------------------------------------------------------
# Testes de conectividade
# ---------------------------------------------------------------------

def test_db_connection(driver, host, port, name, user, password):
    """Testa a conexão usando o cliente de linha de comando (mysql/psql)
    para não depender de extensões PHP/Python específicas instaladas."""
    env = os.environ.copy()

    if driver == "pgsql":
        if not shutil.which("psql"):
            return None, "cliente 'psql' não encontrado para testar (instale postgresql-client se quiser validar)"
        env["PGPASSWORD"] = password
        cmd = ["psql", "-h", host, "-p", str(port), "-U", user, "-d", name, "-c", "SELECT 1;"]
    else:
        if not shutil.which("mysql"):
            return None, "cliente 'mysql' não encontrado para testar (instale mysql-client/mariadb-client se quiser validar)"
        # Senha via variável de ambiente (evita aparecer em "ps aux" como argumento).
        env["MYSQL_PWD"] = password
        cmd = ["mysql", f"-h{host}", f"-P{port}", f"-u{user}", name, "-e", "SELECT 1;"]

    try:
        result = _run(cmd, timeout=10, env=env)
        if result.returncode == 0:
            return True, None
        return False, (result.stderr or result.stdout).strip()[:300]
    except subprocess.TimeoutExpired:
        return False, "timeout ao conectar"
    except FileNotFoundError:
        return None, "cliente de banco não encontrado"


def table_exists(driver, host, port, name, user, password, table):
    env = os.environ.copy()
    if driver == "pgsql":
        env["PGPASSWORD"] = password
        cmd = ["psql", "-h", host, "-p", str(port), "-U", user, "-d", name, "-tAc",
               f"SELECT to_regclass('{table}') IS NOT NULL;"]
        try:
            result = _run(cmd, timeout=10, env=env)
            return result.returncode == 0 and result.stdout.strip() == "t"
        except Exception:
            return None
    else:
        env["MYSQL_PWD"] = password
        cmd = ["mysql", f"-h{host}", f"-P{port}", f"-u{user}", name,
               "-N", "-e", f"SHOW TABLES LIKE '{table}';"]
        try:
            result = _run(cmd, timeout=10, env=env)
            return result.returncode == 0 and table in result.stdout
        except Exception:
            return None


def run_schema_sql(driver, host, port, name, user, password, schema_path):
    env = os.environ.copy()
    if driver == "pgsql":
        env["PGPASSWORD"] = password
        cmd = ["psql", "-h", host, "-p", str(port), "-U", user, "-d", name, "-f", schema_path]
        try:
            result = _run(cmd, timeout=30, env=env)
            return result.returncode == 0, (result.stderr or result.stdout).strip()[:500]
        except Exception as e:
            return False, str(e)
    else:
        env["MYSQL_PWD"] = password
        cmd = ["mysql", f"-h{host}", f"-P{port}", f"-u{user}", name]
        try:
            with open(schema_path, "r", encoding="utf-8") as f:
                result = _run(cmd, timeout=30, env=env, input_file=f)
            return result.returncode == 0, (result.stderr or result.stdout).strip()[:500]
        except Exception as e:
            return False, str(e)


def test_ingest_endpoint(url, token):
    body = json.dumps({
        "event_type": "heartbeat",
        "zbx_host": "setup-test",
        "hostid": 0,
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "X-DG-Token": token},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                return False, f"resposta não é JSON válido: {raw[:200]}"
            if parsed.get("ok"):
                return True, None
            return False, parsed.get("error", "erro desconhecido")
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read().decode(errors='replace')[:200]}"
    except urllib.error.URLError as e:
        return False, str(e.reason)


# ---------------------------------------------------------------------
# Geração de arquivos
# ---------------------------------------------------------------------

def php_quote(value):
    """Escapa uma string para uso segura dentro de aspas simples PHP."""
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def render_ingest_config_php(cfg):
    lines = ["<?php", "// Gerado automaticamente por setup.py em " + _now_str(), "return ["]
    for key in [
        "DG_INGEST_TOKEN", "DG_DB_HOST", "DG_DB_PORT", "DG_DB_NAME",
        "DG_DB_USER", "DG_DB_PASS", "DG_DB_DRIVER",
        "DG_ZABBIX_SENDER_BIN", "DG_ZBX_SERVER", "DG_ZBX_PORT",
    ]:
        lines.append(f"    {php_quote(key)} => {php_quote(cfg[key])},")
    lines.append("];")
    lines.append("")
    return "\n".join(lines)


def _now_str():
    import datetime
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def render_agent_conf(cfg):
    parser = configparser.ConfigParser()
    parser["general"] = {
        "zbx_host": cfg["zbx_host"],
        "hostid": str(cfg["hostid"]),
        "ingest_url": cfg["ingest_url"],
        "ingest_token": cfg["DG_INGEST_TOKEN"],
        "poll_interval": "10",
        "aggregate_window": "60",
        "geoip_db_path": cfg["geoip_db_path"],
        "has_firewall": "auto",
        "has_antivirus": "auto",
        "state_file": f"{DEFAULT_STATE_DIR}/state.json",
    }
    parser["sources"] = {
        "iptables_log": cfg["iptables_log"],
        "ufw_log": cfg["ufw_log"],
        "fail2ban_log": cfg["fail2ban_log"],
        "clamav_log": cfg["clamav_log"],
        "auth_log": cfg["auth_log"],
    }
    from io import StringIO
    buf = StringIO()
    parser.write(buf)
    return buf.getvalue()


def write_file(path, content, dry_run, mode=0o640):
    if dry_run:
        info(f"[dry-run] escreveria {path} ({len(content)} bytes)")
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    try:
        os.chmod(path, mode)
    except PermissionError:
        warn(f"não foi possível ajustar permissões de {path} (rode como root se precisar restringir acesso)")
    ok(f"escrito: {path}")


# ---------------------------------------------------------------------
# Fluxo principal
# ---------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--yes", action="store_true", help="Aceita todos os valores detectados/padrão sem perguntar.")
    ap.add_argument("--dry-run", action="store_true", help="Mostra o que seria feito, sem escrever nada nem rodar SQL.")
    ap.add_argument("--skip-db-test", action="store_true", help="Não tenta conectar no banco para validar.")
    ap.add_argument("--skip-endpoint-test", action="store_true", help="Não testa o endpoint ingest.php via HTTP no final.")
    args = ap.parse_args()

    if os.geteuid() != 0:
        warn("Você não está rodando como root. Algumas etapas (escrever em /etc/zabbix, "
             "rodar SQL, copiar para o webroot) podem falhar por permissão.")
        if not ask_yes_no("Continuar mesmo assim?", default=True, assume_yes=args.yes):
            sys.exit(1)

    header("DDoS Guard — Setup interativo")
    info("Este assistente detecta o ambiente do seu Zabbix e configura o módulo")
    info("DDoS Guard (ingest.php, agente coletor e tabelas auxiliares no banco).")

    # -------------------------------------------------------------
    # 1. Detecção de ambiente
    # -------------------------------------------------------------
    header("1. Detectando ambiente")

    webserver = detect_webserver()
    info(f"Servidor web detectado: {webserver or 'não identificado'}")

    php_fpm_pool = detect_php_fpm_pool()
    if webserver == "nginx":
        if php_fpm_pool:
            info(f"Pool do PHP-FPM encontrado: {php_fpm_pool}")
        else:
            warn("Não encontrei o pool do PHP-FPM automaticamente (não é bloqueante,"
                 " só impacta se você for usar variáveis de ambiente em vez do arquivo de config).")

    webroot = detect_frontend_webroot()
    info(f"Webroot do frontend Zabbix: {webroot or 'não encontrado automaticamente'}")

    sender_bin = detect_zabbix_sender()
    if sender_bin:
        ok(f"zabbix_sender encontrado em: {sender_bin}")
    else:
        warn("zabbix_sender não encontrado no PATH. Os contadores (triggers) não vão "
             "chegar ao Zabbix até instalar o pacote zabbix-sender / zabbix-get.")
        sender_bin = "/usr/bin/zabbix_sender"

    zbx_conf_values, zbx_conf_path = parse_zabbix_server_conf()
    if zbx_conf_path:
        ok(f"zabbix_server.conf encontrado: {zbx_conf_path}")
        if zbx_conf_values:
            for k, v in zbx_conf_values.items():
                shown = v if k != "DBPassword" else ("*" * len(v) if v else "(vazio)")
                info(f"  {k} = {shown}")
        else:
            warn("zabbix_server.conf encontrado mas sem permissão de leitura "
                 "(rode como root para auto-detectar credenciais do banco).")
    else:
        warn("zabbix_server.conf não encontrado nos caminhos padrão.")

    geoip_db = detect_geoip_db()
    if geoip_db:
        ok(f"Base GeoIP encontrada: {geoip_db}")
    else:
        warn("Base GeoLite2-City.mmdb não encontrada — o agente vai usar a API pública "
             "ip-api.com para geolocalizar IPs (funciona, mas com limite de requisições).")
        geoip_db = GEOIP_DB_CANDIDATES[0]

    # -------------------------------------------------------------
    # 2. Configuração do banco de dados
    # -------------------------------------------------------------
    header("2. Configuração do banco de dados")

    db_port_hint = zbx_conf_values.get("DBPort", "")
    if db_port_hint == "5432":
        db_driver_default = "pgsql"
    elif db_port_hint == "3306":
        db_driver_default = "mysql"
    else:
        db_driver_default = detect_db_driver()
    db_driver = ask("Driver do banco (mysql/pgsql)",
                     default=db_driver_default, assume_yes=args.yes)

    db_host = ask("Host do banco", default=zbx_conf_values.get("DBHost", "127.0.0.1"), assume_yes=args.yes)
    db_port_default = zbx_conf_values.get("DBPort") or ("5432" if db_driver == "pgsql" else "3306")
    db_port = ask("Porta do banco", default=db_port_default, assume_yes=args.yes)
    db_name = ask("Nome do banco", default=zbx_conf_values.get("DBName", "zabbix"), assume_yes=args.yes)
    db_user = ask("Usuário do banco", default=zbx_conf_values.get("DBUser", "zabbix"), assume_yes=args.yes)

    db_pass_default = zbx_conf_values.get("DBPassword", "")
    if args.yes:
        db_pass = db_pass_default
    else:
        prompt_suffix = " (Enter para usar a do zabbix_server.conf)" if db_pass_default else ""
        db_pass = ask(f"Senha do banco{prompt_suffix}", default=db_pass_default, secret=True, assume_yes=args.yes)

    if not args.skip_db_test:
        info("Testando conexão com o banco...")
        success, error = test_db_connection(db_driver, db_host, db_port, db_name, db_user, db_pass)
        if success is True:
            ok("Conexão com o banco OK.")
        elif success is False:
            err(f"Falha ao conectar no banco: {error}")
            if not ask_yes_no("Continuar mesmo assim?", default=False, assume_yes=args.yes):
                sys.exit(1)
        else:
            warn(f"Não testado: {error}")

    # -------------------------------------------------------------
    # 3. Tabelas auxiliares (schema.sql)
    # -------------------------------------------------------------
    header("3. Tabelas auxiliares (ddosguard_attacks / ddosguard_blocks / ddosguard_host_status)")

    schema_path = os.path.join(PACKAGE_ROOT, "sql", "schema.sql")
    needs_schema = True
    if not args.skip_db_test:
        exists = table_exists(db_driver, db_host, db_port, db_name, db_user, db_pass, "ddosguard_attacks")
        if exists is True:
            ok("Tabelas já existem — nada a fazer aqui.")
            needs_schema = False
        elif exists is False:
            warn("Tabelas auxiliares ainda não existem.")
        else:
            warn("Não foi possível verificar automaticamente se as tabelas existem.")

    if needs_schema and os.path.exists(schema_path):
        if ask_yes_no(f"Executar {schema_path} agora para criar as tabelas?", default=True, assume_yes=args.yes):
            if args.dry_run:
                info(f"[dry-run] executaria {schema_path} no banco {db_name}")
            else:
                success, output = run_schema_sql(db_driver, db_host, db_port, db_name, db_user, db_pass, schema_path)
                if success:
                    ok("Tabelas criadas/atualizadas com sucesso.")
                else:
                    err(f"Falha ao executar schema.sql: {output}")
                    warn("Você pode rodar manualmente depois, ex.: "
                         f"mysql -u{db_user} -p {db_name} < {schema_path}")
    elif needs_schema:
        warn(f"Não encontrei {schema_path} — rode manualmente depois.")

    # -------------------------------------------------------------
    # 4. Token de autenticação
    # -------------------------------------------------------------
    header("4. Token de autenticação (ingest.php <-> agente coletor)")

    suggested_token = generate_token()
    info("Esse token autentica as requisições do agente coletor para o ingest.php.")
    if ask_yes_no(f"Gerar um token novo e seguro automaticamente?", default=True, assume_yes=args.yes):
        token = suggested_token
        ok(f"Token gerado: {token}")
    else:
        token = ask("Cole o token que você quer usar", default=suggested_token, assume_yes=args.yes)

    # -------------------------------------------------------------
    # 5. Onde publicar o ingest.php
    # -------------------------------------------------------------
    header("5. Publicação do ingest.php")

    default_webroot = webroot or "/usr/share/zabbix"
    chosen_webroot = ask("Diretório raiz do frontend Zabbix (webroot)",
                          default=default_webroot, assume_yes=args.yes)
    ingest_dest_dir = os.path.join(chosen_webroot, "ddosguard")
    ingest_dest_path = os.path.join(ingest_dest_dir, "ingest.php")

    source_ingest = os.path.join(PACKAGE_ROOT, "scripts", "ingest.php")
    if not os.path.exists(source_ingest):
        err(f"Não encontrei {source_ingest} — confirme que está rodando este script "
            "de dentro da pasta do pacote DDoS Guard (zbx_ddos_guard/scripts/setup.py).")
        sys.exit(1)

    # Procura outras cópias de ingest.php espalhadas pelo sistema (de
    # execuções anteriores deste script rodadas de diretórios diferentes,
    # ou de testes manuais). Cópias divergentes do publicado são a causa
    # mais comum de "invalid token" mesmo com a config certa — o Nginx
    # acaba servindo um ingest.php antigo/incompleto em vez do atual.
    other_copies = _find_other_ingest_copies(ingest_dest_path)
    if other_copies:
        warn(f"Encontrei {len(other_copies)} outra(s) cópia(s) de ingest.php no sistema, "
             "além da que será publicada agora:")
        for path, size in other_copies:
            print(f"        {path}  ({size} bytes)")
        warn("Cópias divergentes confundem qual versão está realmente sendo servida "
             "(ex.: uma sem a leitura de ingest.config.php). Recomendado remover as antigas.")
        if ask_yes_no("Remover essas cópias antigas agora?", default=True, assume_yes=args.yes):
            for path, _ in other_copies:
                if args.dry_run:
                    info(f"[dry-run] removeria {path}")
                else:
                    try:
                        os.remove(path)
                        ok(f"removido: {path}")
                    except OSError as e:
                        warn(f"não consegui remover {path}: {e}")

    if args.dry_run:
        info(f"[dry-run] copiaria {source_ingest} -> {ingest_dest_path}")
    else:
        os.makedirs(ingest_dest_dir, exist_ok=True)
        shutil.copyfile(source_ingest, ingest_dest_path)
        try:
            os.chmod(ingest_dest_path, 0o644)
        except PermissionError:
            warn(f"não foi possível ajustar permissões de {ingest_dest_path}")
        ok(f"ingest.php copiado para {ingest_dest_path} "
           f"({os.path.getsize(ingest_dest_path)} bytes)")

    # Sugere uma URL pública plausível; como isso depende da config exata
    # do vhost (alias, document_root etc.), é só um ponto de partida —
    # o usuário confirma ou corrige no prompt abaixo.
    local_ip = _guess_local_ip()
    if chosen_webroot.rstrip("/") in ("/usr/share/zabbix", "/usr/share/zabbix/ui"):
        # Padrão do appliance oficial / pacotes RPM-DEB: o document_root do
        # vhost normalmente é /usr/share/zabbix, mas o Zabbix é acessado na
        # raiz do site (ex.: http://IP/), então o ingest.php também fica
        # na raiz, sem prefixo "/zabbix" extra.
        suggested_url = f"http://{local_ip}/ddosguard/ingest.php"
    else:
        # Outros layouts comuns costumam servir o Zabbix sob um subpath
        # "/zabbix" (ex.: document_root genérico /var/www/html com vários
        # apps). Ajuste conforme o seu vhost real.
        suggested_url = f"http://{local_ip}/zabbix/ddosguard/ingest.php"

    info("Não consigo confirmar com certeza o path da URL pública a partir do diretório "
         "de arquivos — confirme ou ajuste o valor sugerido abaixo conforme o seu vhost.")
    ingest_url = ask("URL pública completa do ingest.php (a que o agente vai chamar)",
                      default=suggested_url, assume_yes=args.yes)

    # -------------------------------------------------------------
    # 6. Escrever ingest.config.php
    # -------------------------------------------------------------
    header("6. Gravando configuração do ingest.php")

    ingest_cfg = {
        "DG_INGEST_TOKEN": token,
        "DG_DB_HOST": db_host,
        "DG_DB_PORT": db_port,
        "DG_DB_NAME": db_name,
        "DG_DB_USER": db_user,
        "DG_DB_PASS": db_pass,
        "DG_DB_DRIVER": db_driver,
        "DG_ZABBIX_SENDER_BIN": sender_bin,
    }

    # DG_ZBX_SERVER — nao pode conter :porta (causa timeout de ~20s no ingest)
    _zbx_server_raw = ask(
        "Endereço do Zabbix Server para zabbix_sender (so o IP/hostname, SEM :porta)",
        default="127.0.0.1", assume_yes=args.yes)
    if ":" in _zbx_server_raw:
        _zbx_server_clean = _zbx_server_raw.split(":")[0]
        warn(f"DG_ZBX_SERVER '{_zbx_server_raw}' contem ':porta' — "
             f"usando apenas '{_zbx_server_clean}' (a porta vai em DG_ZBX_PORT)")
        _zbx_server_raw = _zbx_server_clean
    ingest_cfg["DG_ZBX_SERVER"] = _zbx_server_raw
    ingest_cfg["DG_ZBX_PORT"] = ask(
        "Porta trapper do Zabbix Server", default="10051", assume_yes=args.yes)

    ingest_config_content = render_ingest_config_php(ingest_cfg)
    write_file(DEFAULT_INGEST_CONFIG_PATH, ingest_config_content, args.dry_run, mode=0o640)

    # -------------------------------------------------------------
    # 7. Configuração do agente coletor (host atual)
    # -------------------------------------------------------------
    header("7. Configuração do agente coletor neste host")

    info("O agente coletor (ddos_guard_agent.py) roda no host monitorado e lê logs locais.")
    if ask_yes_no("Configurar o agente coletor para rodar NESTE host agora?", default=True, assume_yes=args.yes):
        zbx_host_default = socket.gethostname()
        zbx_host = ask("Nome do host EXATAMENTE como cadastrado no Zabbix (Data collection > Hosts)",
                        default=zbx_host_default, assume_yes=args.yes)
        hostid = ask("hostid numérico deste host no Zabbix (veja na URL ao abrir o host)",
                      default="0", assume_yes=args.yes)

        agent_cfg = {
            "zbx_host": zbx_host,
            "hostid": hostid,
            "ingest_url": ingest_url,
            "DG_INGEST_TOKEN": token,
            "geoip_db_path": geoip_db,
            "iptables_log": detect_log_path("iptables_log"),
            "ufw_log": detect_log_path("ufw_log"),
            "fail2ban_log": detect_log_path("fail2ban_log"),
            "clamav_log": detect_log_path("clamav_log"),
            "auth_log": detect_log_path("auth_log"),
        }
        agent_conf_content = render_agent_conf(agent_cfg)
        write_file(DEFAULT_AGENT_CONFIG_PATH, agent_conf_content, args.dry_run, mode=0o640)

        if not args.dry_run:
            os.makedirs(DEFAULT_STATE_DIR, exist_ok=True)

        # Oferece instalar o agente + systemd unit.
        if ask_yes_no("Instalar o agente em /opt/zabbix/ddosguard e habilitar o serviço systemd?",
                       default=True, assume_yes=args.yes):
            _install_agent_and_service(args.dry_run)
    else:
        info("Pulando configuração do agente — você pode configurá-lo manualmente depois "
             "em outro host usando scripts/ddos_guard_agent.conf.example como base.")

    # -------------------------------------------------------------
    # 8. Teste final do endpoint
    # -------------------------------------------------------------
    if not args.skip_endpoint_test and not args.dry_run:
        header("8. Testando o endpoint ingest.php")
        info(f"Chamando {ingest_url} ...")
        success, error = test_ingest_endpoint(ingest_url, token)
        if success:
            ok("Endpoint respondeu OK! A configuração está funcionando de ponta a ponta.")
        else:
            err(f"Falha ao chamar o endpoint: {error}")
            warn("Verifique se o servidor web está rodando, se a URL está correta, e se o "
                 "PHP tem a extensão pdo_mysql/pdo_pgsql habilitada.")

    # -------------------------------------------------------------
    # Resumo final
    # -------------------------------------------------------------
    header("Resumo")
    print(f"  Config do ingest.php .... {DEFAULT_INGEST_CONFIG_PATH}")
    print(f"  ingest.php publicado .... {ingest_dest_path}")
    print(f"  URL do ingest.php ....... {ingest_url}")
    print(f"  Token .................... {token}")
    print(f"  Config do agente ........ {DEFAULT_AGENT_CONFIG_PATH}")
    print()
    info("Se ainda não importou, importe templates/template_ddos_guard.yaml no Zabbix")
    info("e habilite os módulos de frontend (Administration > General > Modules).")
    print()


SEARCH_DIRS_FOR_STALE_INGEST = [
    "/usr/share/zabbix",
    "/usr/share",
    "/var/www",
    "/var/lib/zabbix",
    "/usr/lib/zabbix",
    "/etc/zabbix",
    "/opt/zabbix",
]


def _find_other_ingest_copies(current_dest_path, max_depth=4):
    """Procura por arquivos ingest.php em diretórios plausíveis do
    Zabbix, fora o caminho que será publicado agora. Limitado a uma
    lista curta de raízes conhecidas e a uma profundidade razoável (em
    vez de 'find /' completo) para ser rápido mesmo em sistemas grandes
    ou com /usr/share cheio de pacotes."""
    current_dest_real = os.path.realpath(current_dest_path)
    found = []
    seen = set()

    for base in SEARCH_DIRS_FOR_STALE_INGEST:
        if not os.path.isdir(base):
            continue
        base_depth = base.rstrip(os.sep).count(os.sep)
        for root, dirs, files in os.walk(base):
            depth = root.rstrip(os.sep).count(os.sep) - base_depth
            if depth >= max_depth:
                dirs[:] = []  # não desce mais a partir daqui
                continue
            # Evita descer em pontos de montagem/diretórios gigantes irrelevantes.
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
            if "ingest.php" in files:
                full_path = os.path.join(root, "ingest.php")
                real_path = os.path.realpath(full_path)
                if real_path == current_dest_real or real_path in seen:
                    continue
                seen.add(real_path)
                try:
                    size = os.path.getsize(full_path)
                except OSError:
                    size = -1
                found.append((full_path, size))

    return found


def _guess_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _install_agent_and_service(dry_run):
    agent_install_dir = "/opt/zabbix/ddosguard"
    source_agent = os.path.join(PACKAGE_ROOT, "scripts", "ddos_guard_agent.py")
    source_service = os.path.join(PACKAGE_ROOT, "scripts", "ddos-guard-agent.service")
    dest_agent = os.path.join(agent_install_dir, "ddos_guard_agent.py")
    dest_service = "/etc/systemd/system/ddos-guard-agent.service"

    if dry_run:
        info(f"[dry-run] copiaria {source_agent} -> {dest_agent}")
        info(f"[dry-run] copiaria {source_service} -> {dest_service}")
        info("[dry-run] rodaria: systemctl daemon-reload && systemctl enable ddos-guard-agent "
             "&& systemctl restart ddos-guard-agent")
        return

    if not os.path.exists(source_agent):
        warn(f"Não encontrei {source_agent} — pulando instalação automática do agente.")
        return

    os.makedirs(agent_install_dir, exist_ok=True)
    shutil.copyfile(source_agent, dest_agent)
    os.chmod(dest_agent, 0o755)
    ok(f"Agente copiado para {dest_agent}")

    if os.path.exists(source_service):
        shutil.copyfile(source_service, dest_service)
        ok(f"Unit systemd copiada para {dest_service}")
        try:
            subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=10)
            subprocess.run(["systemctl", "enable", "ddos-guard-agent"], check=True, timeout=10)
            # IMPORTANTE: usa "restart", não "enable --now" / "start". Se o
            # serviço já estava rodando de uma execução anterior do setup.py,
            # "start" é um no-op e o processo continua com a config antiga em
            # memória (o agente só lê o .conf uma vez, no início). "restart"
            # garante que a configuração recém-gravada (token, host, etc.)
            # seja efetivamente recarregada.
            subprocess.run(["systemctl", "restart", "ddos-guard-agent"], check=True, timeout=10)
            ok("Serviço ddos-guard-agent habilitado e (re)iniciado com a configuração atual.")
        except subprocess.CalledProcessError as e:
            err(f"Falha ao habilitar/reiniciar o serviço: {e}")
        except FileNotFoundError:
            warn("systemctl não encontrado — habilite/reinicie o serviço manualmente neste sistema.")
    else:
        warn(f"Não encontrei {source_service} — crie/habilite o serviço systemd manualmente.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        warn("Cancelado pelo usuário.")
        sys.exit(130)
