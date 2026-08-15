#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS Guard - Provisionamento do Dashboard (Monitoring > Dashboards)
=====================================================================
Os dashboards de "Monitoring -> Dashboards" (diferente dos "Template
dashboards", que ficam dentro de um Template e sao importaveis via
YAML/XML) so podem ser criados via API REST (`dashboard.create`) — nao
existe arquivo de import para esse tipo no Zabbix 7.4.

Este script cria o dashboard "DDoS Guard - Security Operations Center".

WIDGETS DISPONIVEIS E DE ONDE CADA UM LE
----------------------------------------
Nenhum widget e redundante: eles consultam tabelas diferentes. O que
determina se um painel fica vazio e qual tabela a sua integracao
alimenta.

  widget            modulo             tabela(s)              alimentado por
  ---------------------------------------------------------------------------
  socoverview       DDoSSOCOverview    blocks + attacks       tudo
                                       + correlations
  blockmonitor      DDoSBlockMonitor   blocks                 tudo
  attackmonitor     DDoSAttackMonitor  attacks + host_status  agente, Suricata,
                                                              Wazuh, Sophos,
                                                              mikrotik_receiver
  timeline          DDoSTimeline       attacks                idem
  mitre             DDoSMitreHeatmap   attacks                idem

IMPORTANTE — instalacoes so com MikroTik via syslog_receiver.php:
    o parser emite sempre `event_type=block_firewall`, entao
    `ddosguard_attacks` nunca e populada e os tres ultimos widgets ficam
    permanentemente vazios. Use `--preset mikrotik` nesse caso.

PRESETS
-------
  full      (padrao) 5 widgets do DDoS Guard + Problems, em 2 paginas
  mikrotik  so o que o syslog_receiver alimenta: SOC Overview,
            Block Monitor e Problems — 1 pagina
  minimal   Block Monitor + Problems

Pre-requisitos:
    - Template "DDoS Guard - Security Monitoring" ja importado.
    - Modulos de frontend habilitados em
      Administration -> General -> Modules.
    - Usuario/token de API com permissao de criar dashboards.

Uso:
    python3 provision_dashboard.py --url https://zabbix.local --token TOKEN
    python3 provision_dashboard.py --url ... --token ... --preset mikrotik
    python3 provision_dashboard.py --url ... --token ... --exclude mitre,timeline
    python3 provision_dashboard.py --url ... --token ... --dry-run
"""

import argparse
import getpass
import json
import sys
import urllib.error
import urllib.request

# Tipos de campo de widget na API (diferente do YAML de import!):
#   0 = inteiro (ZBX_WIDGET_FIELD_TYPE_INT32)
#   1 = string  (ZBX_WIDGET_FIELD_TYPE_STR)
FIELD_INT = 0
FIELD_STR = 1

DASHBOARD_NAME = "DDoS Guard - Security Operations Center"

# Mapa apelido -> (widget type da API, modulo, depende de ddosguard_attacks)
WIDGETS = {
    "socoverview":   ("ddossocoverview",   "DDoSSOCOverview",   False),
    "blockmonitor":  ("ddosblockmonitor",  "DDoSBlockMonitor",  False),
    "attackmonitor": ("ddosattackmonitor", "DDoSAttackMonitor", True),
    "timeline":      ("ddostimeline",      "DDoSTimeline",      True),
    "mitre":         ("ddosmitre",         "DDoSMitreHeatmap",  True),
}

PRESETS = {
    "full":     ["socoverview", "blockmonitor", "timeline", "mitre", "attackmonitor"],
    "mikrotik": ["socoverview", "blockmonitor"],
    "minimal":  ["blockmonitor"],
}


class ZabbixAuthError(RuntimeError):
    """Token/credencial invalida ou sessao expirada."""


class ZabbixAPI:
    def __init__(self, url, token=None, user=None, password=None):
        self.url = url.rstrip("/") + "/api_jsonrpc.php"
        self.token = token
        self.id = 0
        if not token:
            if not user or not password:
                raise ValueError("Informe --token OU --user e --password.")
            self.token = self._login(user, password)

    def _request(self, method, params, auth=True):
        self.id += 1
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.id,
        }
        headers = {"Content-Type": "application/json-rpc"}
        if auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        req = urllib.request.Request(
            self.url, data=json.dumps(payload).encode("utf-8"),
            headers=headers, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            print("Erro HTTP chamando %s: %s" % (method, e), file=sys.stderr)
            raise

        if "error" in body:
            err = body["error"]
            data = str(err.get("data", ""))
            msg = str(err.get("message", ""))
            # O Zabbix devolve "Invalid params." + "Session terminated,
            # re-login, please." tanto para token invalido quanto para
            # sessao expirada. Sem tratar, vira um traceback opaco.
            if ("re-login" in data or "Not authorised" in data
                    or "Not authorized" in data or "authoriz" in msg.lower()):
                raise ZabbixAuthError(data or msg)
            raise RuntimeError("Erro da API Zabbix em %s: %s" % (method, err))
        return body["result"]

    def _login(self, user, password):
        return self._request("user.login", {
            "username": user,
            "password": password,
        }, auth=False)

    def call(self, method, params):
        return self._request(method, params)


def field(ftype, name, value):
    return {"type": ftype, "name": name, "value": str(value)}


def problems_widget(name, x, y, w, h, show_lines=10, severities=None):
    """Widget nativo de Problems filtrado pelas tags do DDoS Guard."""
    fields = [
        field(FIELD_STR, "tags.0.tag", "component"),
        field(FIELD_STR, "tags.0.value", "ddos"),
        field(FIELD_INT, "tags.0.operator", "0"),
        field(FIELD_STR, "tags.1.tag", "component"),
        field(FIELD_STR, "tags.1.value", "firewall"),
        field(FIELD_INT, "tags.1.operator", "0"),
        field(FIELD_STR, "tags.2.tag", "component"),
        field(FIELD_STR, "tags.2.value", "antivirus"),
        field(FIELD_INT, "tags.2.operator", "0"),
        # evaltype 2 = OR entre as tags
        field(FIELD_INT, "evaltype", "2"),
        field(FIELD_INT, "show_lines", str(show_lines)),
        field(FIELD_INT, "show_tags", "3"),
    ]
    for sev in (severities or []):
        fields.append(field(FIELD_INT, "severities.%d" % sev, str(sev)))
    return {
        "type": "problems", "name": name,
        "x": x, "y": y, "width": w, "height": h,
        "fields": fields,
    }


def build_pages(selected):
    """Monta as paginas conforme os widgets selecionados.

    O grid do Zabbix 7.4 tem 72 colunas. Widgets ausentes nao deixam
    buraco: a montagem e sequencial e recalcula as posicoes.
    """
    sel = set(selected)
    pages = []

    # ---------------- Pagina 1 — visao SOC ----------------
    p1 = []
    y = 0

    if "socoverview" in sel:
        p1.append({
            "type": "ddossocoverview",
            "name": "Visao geral do SOC",
            "x": 0, "y": y, "width": 72, "height": 8,
            "fields": [],
        })
        y += 8

    # Linha dupla: bloqueios a esquerda, timeline a direita
    dupla = [w for w in ("blockmonitor", "timeline") if w in sel]
    if dupla:
        largura = 72 // len(dupla)
        x = 0
        for w in dupla:
            if w == "blockmonitor":
                p1.append({
                    "type": "ddosblockmonitor",
                    "name": "Bloqueios: Firewall x Antivirus",
                    "x": x, "y": y, "width": largura, "height": 7,
                    "fields": [
                        field(FIELD_INT, "time_range", "60"),
                        field(FIELD_INT, "show_lines", "25"),
                        # 0 = todos, 1 = so firewall, 2 = so antivirus
                        field(FIELD_INT, "block_source_filter", "0"),
                    ],
                })
            else:
                p1.append({
                    "type": "ddostimeline",
                    "name": "Response Timeline",
                    "x": x, "y": y, "width": largura, "height": 7,
                    "fields": [],
                })
            x += largura
        y += 7

    # Linha dupla: MITRE a esquerda, Problems a direita
    if "mitre" in sel:
        p1.append({
            "type": "ddosmitre",
            "name": "MITRE ATT&CK - Taticas detectadas (24h)",
            "x": 0, "y": y, "width": 36, "height": 6,
            "fields": [],
        })
        p1.append(problems_widget("Incidentes", 36, y, 36, 6))
    else:
        p1.append(problems_widget("Incidentes", 0, y, 72, 6))
    y += 6

    pages.append({"name": "SOC", "widgets": p1})

    # ---------------- Pagina 2 — ataques ----------------
    if "attackmonitor" in sel:
        pages.append({
            "name": "Ataques",
            "widgets": [
                {
                    "type": "ddosattackmonitor",
                    "name": "Ataques em tempo real",
                    "x": 0, "y": 0, "width": 72, "height": 9,
                    "fields": [
                        field(FIELD_INT, "time_range", "60"),
                        field(FIELD_INT, "show_lines", "25"),
                        # 0 = tentativas, 1 = mais recente, 2 = severidade
                        field(FIELD_INT, "order_by", "2"),
                        field(FIELD_INT, "only_blocked", "0"),
                    ],
                },
                # So severidades altas nesta pagina: Warning(2)..Disaster(5)
                problems_widget("Alertas de alta severidade", 0, 9, 72, 6,
                                show_lines=15, severities=[2, 3, 4, 5]),
            ],
        })

    return pages


def checar_modulos(api, selected):
    """Avisa sobre modulos ausentes ou desabilitados.

    Sem esta checagem, o dashboard.create falha com um erro pouco
    informativo quando um modulo nao esta habilitado.
    """
    try:
        modulos = api.call("module.get", {"output": ["id", "status", "relative_path"]})
    except ZabbixAuthError:
        # Nao mascarar: e a causa raiz, nao um detalhe do module.get
        raise
    except Exception as e:
        print("  (nao foi possivel verificar os modulos: %s)" % e)
        return True

    por_id = {m.get("id"): m for m in modulos}
    faltando, desabilitados = [], []
    for apelido in selected:
        wtype, modname, _ = WIDGETS[apelido]
        m = por_id.get(wtype)
        if m is None:
            faltando.append((apelido, modname))
        elif str(m.get("status")) != "1":
            desabilitados.append((apelido, modname))

    ok = True
    for apelido, modname in faltando:
        print("  [FALTA]  modulo '%s' nao esta instalado (widget '%s')" % (modname, apelido))
        ok = False
    for apelido, modname in desabilitados:
        print("  [OFF]    modulo '%s' esta desabilitado (widget '%s')" % (modname, apelido))
        ok = False

    if not ok:
        print()
        print("  Instale com:  bash scripts/install_modules.sh")
        print("  Habilite em:  Administration -> General -> Modules")
    else:
        print("  %d modulo(s) verificado(s), todos habilitados." % len(selected))
    return ok


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--url", required=True,
                    help="URL base do frontend (ex.: https://zabbix.exemplo.com)")
    ap.add_argument("--token", help="API token (Administration > General > API tokens)")
    ap.add_argument("--user", help="Usuario (alternativa ao --token)")
    ap.add_argument("--password", help="Senha (alternativa ao --token)")
    ap.add_argument("--name", default=DASHBOARD_NAME, help="Nome do dashboard a criar")
    ap.add_argument("--preset", choices=sorted(PRESETS), default="full",
                    help="Conjunto de widgets (padrao: full)")
    ap.add_argument("--widgets",
                    help="Lista explicita, separada por virgula. Sobrepoe --preset. "
                         "Opcoes: " + ", ".join(sorted(WIDGETS)))
    ap.add_argument("--exclude", default="",
                    help="Remove widgets do preset (separados por virgula)")
    ap.add_argument("--private", action="store_true",
                    help="Cria como dashboard privado (padrao: publico)")
    ap.add_argument("--force", action="store_true",
                    help="Se ja existir dashboard com esse nome, apaga e recria")
    ap.add_argument("--skip-module-check", action="store_true",
                    help="Nao verifica se os modulos estao habilitados")
    ap.add_argument("--dry-run", action="store_true",
                    help="Mostra o JSON que seria enviado e sai")
    args = ap.parse_args()

    # ---- selecao de widgets ----
    if args.widgets:
        selected = [w.strip() for w in args.widgets.split(",") if w.strip()]
    else:
        selected = list(PRESETS[args.preset])

    excluidos = set(w.strip() for w in args.exclude.split(",") if w.strip())
    selected = [w for w in selected if w not in excluidos]

    invalidos = [w for w in selected if w not in WIDGETS]
    if invalidos:
        sys.exit("Widget desconhecido: %s. Validos: %s"
                 % (", ".join(invalidos), ", ".join(sorted(WIDGETS))))
    if not selected:
        sys.exit("Nenhum widget selecionado.")

    print("Widgets: %s" % ", ".join(selected))
    dependem_attacks = [w for w in selected if WIDGETS[w][2]]
    if dependem_attacks:
        print("  Dependem de ddosguard_attacks: %s" % ", ".join(dependem_attacks))
        print("  Ficam vazios em instalacoes so com MikroTik via syslog_receiver.php.")
    print()

    pages = build_pages(selected)
    dashboard = {
        "name": args.name,
        "display_period": 30,
        "auto_start": 1,
        "private": 1 if args.private else 0,
        "pages": pages,
    }

    if args.dry_run:
        print(json.dumps(dashboard, indent=2, ensure_ascii=False))
        n = sum(len(p["widgets"]) for p in pages)
        print("\n(dry-run) %d pagina(s), %d widget(s). Nada foi criado." % (len(pages), n))
        return

    # Daqui para baixo a API e chamada de verdade.
    # Placeholders copiados da documentacao produzem
    # "Session terminated, re-login, please", que nao sugere a causa.
    if args.token and args.token.strip().upper() in {
        "TOKEN", "SEU_API_TOKEN", "SEU_TOKEN", "API_TOKEN", "CHANGE_ME",
    }:
        sys.exit("O valor de --token e um placeholder ('%s').\n"
                 "Gere um token real em: Users -> API tokens -> Create API token\n"
                 "Ou use --user Admin --password SUA_SENHA." % args.token)

    # Se --user foi passado sem --password, pede a senha interativamente
    # em vez de exigi-la na linha de comando: um argumento de CLI fica
    # visivel para qualquer usuario local via `ps aux` e costuma ficar
    # gravado no historico do shell. Nao se aplica a --token (nao e uma
    # senha reutilizavel da mesma forma) nem quando --password ja foi
    # informado explicitamente (mantem scripts de automacao existentes
    # funcionando sem mudanca).
    password = args.password
    if args.user and not password and not args.token:
        password = getpass.getpass("Senha para o usuario '%s': " % args.user)

    api = ZabbixAPI(args.url, token=args.token, user=args.user, password=password)

    if not args.skip_module_check:
        print("Verificando modulos...")
        if not checar_modulos(api, selected):
            print("\nAbortado. Use --skip-module-check para ignorar.")
            sys.exit(1)
        print()

    existing = api.call("dashboard.get", {
        "output": ["dashboardid", "name"],
        "filter": {"name": [args.name]},
    })

    if existing:
        if not args.force:
            print("Ja existe um dashboard '%s' (dashboardid=%s)."
                  % (args.name, existing[0]["dashboardid"]))
            print("Use --force para apagar e recriar, ou escolha outro --name.")
            sys.exit(1)
        api.call("dashboard.delete", [existing[0]["dashboardid"]])
        print("Dashboard existente '%s' removido (--force)." % args.name)

    result = api.call("dashboard.create", [dashboard])
    dashboardid = result["dashboardids"][0]

    total = sum(len(p["widgets"]) for p in pages)
    print("Dashboard criado com sucesso.")
    print("  Nome       : %s" % args.name)
    print("  dashboardid: %s" % dashboardid)
    print("  Paginas    : %d  |  Widgets: %d" % (len(pages), total))
    print("  Acesse em  : %s/zabbix.php?action=dashboard.view&dashboardid=%s"
          % (args.url.rstrip("/"), dashboardid))


if __name__ == "__main__":
    try:
        main()
    except ZabbixAuthError as e:
        print("\n" + "=" * 62, file=sys.stderr)
        print("FALHA DE AUTENTICACAO NA API", file=sys.stderr)
        print("=" * 62, file=sys.stderr)
        print("  Resposta do Zabbix: %s" % e, file=sys.stderr)
        print("", file=sys.stderr)
        print("  O token informado e invalido ou expirou.", file=sys.stderr)
        print("", file=sys.stderr)
        print("  Gerar um token novo:", file=sys.stderr)
        print("    Users -> API tokens -> Create API token", file=sys.stderr)
        print("    (marque 'Set expiration date' como desejar e copie o", file=sys.stderr)
        print("     valor -- ele so aparece uma vez)", file=sys.stderr)
        print("", file=sys.stderr)
        print("  Ou autentique com usuario e senha:", file=sys.stderr)
        print("    --user Admin --password SUA_SENHA", file=sys.stderr)
        print("=" * 62, file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
