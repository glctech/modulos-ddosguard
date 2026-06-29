#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS Guard - Provisionamento do Dashboard (Monitoring > Dashboards)
=====================================================================
Os dashboards que aparecem em "Monitoring -> Dashboards" (diferente dos
"Template dashboards", que ficam dentro de um Template e são importáveis
via YAML/XML) só podem ser criados via API REST (`dashboard.create`) —
não existe arquivo de import para esse tipo de dashboard no Zabbix 7.4.

Este script cria automaticamente o dashboard:

    "DDoS Guard - Security Operations Center"

com os widgets:
    1. DDoS Guard - Attack Monitor      (painel de ataques)
    2. DDoS Guard - Block Monitor       (painel de bloqueios FW x AV)
    3. Problems (nativo)                (alertas com tag component=ddos/antivirus)

Pré-requisitos:
    - Template "DDoS Guard - Security Monitoring" já importado.
    - Módulos de frontend DDoSAttackMonitor / DDoSBlockMonitor já
      habilitados (Administration -> General -> Modules).
    - Um usuário/token de API com permissão de criar dashboards.

Uso:
    python3 provision_dashboard.py \
        --url https://meu-zabbix.local \
        --token SEU_API_TOKEN

    # ou autenticando com usuário/senha em vez de token:
    python3 provision_dashboard.py \
        --url https://meu-zabbix.local \
        --user Admin --password zabbix
"""

import argparse
import json
import sys
import urllib.request
import urllib.error


# Tipos de campo de widget na API (diferente do YAML de import!):
#   0 = inteiro (ZBX_WIDGET_FIELD_TYPE_INT32)
#   1 = string  (ZBX_WIDGET_FIELD_TYPE_STR)
FIELD_INT = 0
FIELD_STR = 1

DASHBOARD_NAME = "DDoS Guard - Security Operations Center"


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
            print(f"Erro HTTP chamando {method}: {e}", file=sys.stderr)
            raise

        if "error" in body:
            raise RuntimeError(f"Erro da API Zabbix em {method}: {body['error']}")
        return body["result"]

    def _login(self, user, password):
        result = self._request("user.login", {
            "username": user,
            "password": password,
        }, auth=False)
        return result

    def call(self, method, params):
        return self._request(method, params)


def field(ftype, name, value):
    return {"type": ftype, "name": name, "value": str(value)}


def build_widgets():
    """Monta a definição dos 3 widgets do dashboard (mesma disposição do
    Template Dashboard incluído no template_ddos_guard.yaml)."""

    attack_widget = {
        "type": "ddosattackmonitor",
        "name": "Ataques em tempo real",
        "x": 0, "y": 0, "width": 72, "height": 6,
        "fields": [
            field(FIELD_INT, "time_range", "60"),
            field(FIELD_INT, "show_lines", "25"),
            # order_by: 0 = tentativas, 1 = mais recente, 2 = severidade.
            field(FIELD_INT, "order_by", "0"),
            field(FIELD_INT, "only_blocked", "0"),
        ],
    }

    block_widget = {
        "type": "ddosblockmonitor",
        "name": "Bloqueios: Firewall x Antivírus",
        "x": 0, "y": 6, "width": 72, "height": 6,
        "fields": [
            field(FIELD_INT, "time_range", "60"),
            field(FIELD_INT, "show_lines", "25"),
            # block_source_filter: 0 = todos, 1 = apenas firewall, 2 = apenas antivírus.
            field(FIELD_INT, "block_source_filter", "0"),
        ],
    }

    problems_widget = {
        "type": "problems",
        "name": "Alertas de segurança (DDoS Guard)",
        "x": 0, "y": 12, "width": 72, "height": 5,
        "fields": [
            field(FIELD_STR, "tags.0.tag", "component"),
            field(FIELD_STR, "tags.0.value", "ddos"),
            field(FIELD_INT, "tags.0.operator", "0"),
            field(FIELD_STR, "tags.1.tag", "component"),
            field(FIELD_STR, "tags.1.value", "antivirus"),
            field(FIELD_INT, "tags.1.operator", "0"),
            field(FIELD_INT, "evaltype", "2"),
            field(FIELD_INT, "show_lines", "10"),
        ],
    }

    return [attack_widget, block_widget, problems_widget]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="URL base do frontend do Zabbix (ex.: https://zabbix.exemplo.com)")
    ap.add_argument("--token", help="API token (Administration > General > API tokens)")
    ap.add_argument("--user", help="Usuário (alternativa ao --token)")
    ap.add_argument("--password", help="Senha (alternativa ao --token)")
    ap.add_argument("--name", default=DASHBOARD_NAME, help="Nome do dashboard a criar")
    ap.add_argument("--private", action="store_true",
                     help="Cria como dashboard privado (default: público para todos os usuários)")
    ap.add_argument("--force", action="store_true",
                     help="Se já existir um dashboard com esse nome, apaga e recria.")
    args = ap.parse_args()

    api = ZabbixAPI(args.url, token=args.token, user=args.user, password=args.password)

    existing = api.call("dashboard.get", {
        "output": ["dashboardid", "name"],
        "filter": {"name": [args.name]},
    })

    if existing:
        if not args.force:
            print(f"Já existe um dashboard chamado '{args.name}' (dashboardid={existing[0]['dashboardid']}).")
            print("Use --force para apagar e recriar, ou escolha outro --name.")
            sys.exit(1)
        api.call("dashboard.delete", [existing[0]["dashboardid"]])
        print(f"Dashboard existente '{args.name}' removido (--force).")

    dashboard = {
        "name": args.name,
        "display_period": 30,
        "auto_start": 1,
        "private": 1 if args.private else 0,
        "pages": [
            {
                "name": "Visão geral",
                "widgets": build_widgets(),
            }
        ],
    }

    result = api.call("dashboard.create", [dashboard])
    dashboardid = result["dashboardids"][0]

    print("Dashboard criado com sucesso!")
    print(f"  Nome: {args.name}")
    print(f"  dashboardid: {dashboardid}")
    print(f"  Acesse em: {args.url.rstrip('/')}/zabbix.php?action=dashboard.view&dashboardid={dashboardid}")


if __name__ == "__main__":
    main()
