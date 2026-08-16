#!/usr/bin/env python3
"""
Testes de regressao para os widgets de dashboard PHP (modules/*).

Nao ha instancia Zabbix disponivel neste ambiente para executar os
widgets de verdade (eles dependem de classes do core do Zabbix como
CWidgetView/CDiv/DBselect), entao estes testes trabalham no nivel de
codigo-fonte: sintaxe valida (php -l) e ausencia/presenca de padroes
especificos de texto. Cobre a correcao de 2026-08-14 (ver
docs/CHANGELOG.md):

  1. DDoSSOCOverview e DDoSTimeline tinham blocos de UI inteiramente
     decorativos: um "Tempo de resposta ao incidente" com passos e
     tempos fixos (T+0s..T+8m, incluindo um estagio fictício "NOC AI")
     e metricas MTTD/MTTA/MTTM tambem fixas - nada disso era calculado
     a partir de dados reais. Isso produzia o bug visivel no dashboard
     em producao: KPIs zerados ao lado de um "Tempo de resposta" que
     sempre mostrava os mesmos "45s / 8m / 1.57G", como se houvesse
     atividade. Removido; substituido por dados reais ou por remocao
     honesta do que nao pode ser calculado com confianca.
  2. DDoSSOCOverview tinha um bug real: os KPIs filtravam por uma
     janela de tempo (created_at >= agora-24h) mas "Alertas recentes"
     nao tinha filtro de tempo nenhum - podia mostrar itens de dias
     atras ao lado de KPIs zerados para as ultimas 24h. Corrigido com
     um campo de janela de tempo configuravel aplicado a ambas as
     consultas.
  3. O status de host "online" checava so se o item de heartbeat JA
     recebeu algum valor (sempre 1), nunca QUANDO - um host cujo
     agente morreu ha dias continuava "OK" para sempre. Corrigido para
     considerar o horario (clock) do ultimo heartbeat.

Uso:
    python3 tests/test_dashboard_widgets.py
"""
import os
import subprocess
import unittest

MODULES_DIR = os.path.join(os.path.dirname(__file__), "..", "modules")


def read(*parts):
    path = os.path.join(MODULES_DIR, *parts)
    with open(path, encoding="utf-8") as f:
        return f.read()


def php_lint(*parts):
    path = os.path.join(MODULES_DIR, *parts)
    result = subprocess.run(
        ["php", "-l", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        universal_newlines=True,
    )
    return result.returncode, result.stdout


class TestNoFabricatedDataOnDashboard(unittest.TestCase):
    """O achado principal: nenhum widget deve exibir numeros/rotulos que
    nao vieram de uma consulta real."""

    def test_soc_overview_has_no_hardcoded_incident_timeline(self):
        src = read("DDoSSOCOverview", "views", "widget.view.php")
        banned = ["NOC AI", "T+45s", "T+32s", "T+30s", "T+2m", "T+8m",
                   "1.57G", "Tempo de resposta ao incidente", "Anomalia->Alerta"]
        for needle in banned:
            self.assertNotIn(
                needle, src,
                f"{needle!r} e residuo do bloco de timeline fabricado - nao deveria mais existir"
            )

    def test_timeline_widget_has_no_hardcoded_mttd_mtta_mttm(self):
        src = read("DDoSTimeline", "views", "widget.view.php")
        # As strings fixas '30s'/'45s'/'8m' emparelhadas com os rotulos
        # MTTD/MTTA/MTTM eram o padrao fabricado; os rotulos em si (como
        # texto documentando a decisao de removê-los) podem continuar
        # existindo em comentários, então a checagem é pela combinação
        # antiga específica, não pela palavra isolada.
        self.assertNotIn("'30s','#2fa84f','MTTD'", src)
        self.assertNotIn("'45s','#d63939','MTTA'", src)
        self.assertNotIn("'8m','#f0a30a','MTTM'", src)
        # Os quatro valores do cabecalho agora devem vir de $stats/$incidents.
        self.assertIn("stats['total']", src)
        self.assertIn("stats['ips']", src)
        self.assertIn("stats['max_att']", src)
        self.assertIn("count($incidents)", src)


class TestSocOverviewTimeWindowConsistency(unittest.TestCase):
    """KPIs e 'Alertas recentes' devem usar a mesma janela de tempo."""

    def test_widget_form_has_time_range_field(self):
        src = read("DDoSSOCOverview", "includes", "WidgetForm.php")
        self.assertIn("time_range", src)
        self.assertIn("CWidgetFieldSelect", src)

    def test_controller_uses_configurable_time_range_for_alerts(self):
        src = read("DDoSSOCOverview", "actions", "WidgetView.php")
        self.assertIn("fields_values['time_range']", src)
        # Regressao real de producao: widgets ja existentes no dashboard
        # (criados antes deste campo existir, ex.: via
        # provision_dashboard.py com "fields": []) nao tem "time_range"
        # em $fields_values - sem fallback, isso gera "Undefined array
        # key" e (int) null vira 0, fazendo toda consulta usar uma
        # janela de 0 minutos (tudo aparece zerado mesmo com dados reais).
        self.assertIn(
            "fields_values['time_range'] ?? self::DEFAULT_TIME_RANGE_MINUTES", src,
            "time_range precisa de fallback - $fields_values nao contem chaves "
            "nao salvas explicitamente, mesmo que o campo tenha um default no formulario"
        )
        # A consulta de alertas precisa referenciar a mesma variável
        # $since usada nos KPIs, não ficar sem filtro de tempo.
        alerts_query_start = src.index("SELECT a.attack_type")
        alerts_query = src[alerts_query_start:alerts_query_start + 400]
        self.assertIn("$since", alerts_query,
                       "a consulta de alertas precisa aplicar o mesmo filtro de tempo dos KPIs")
        # Não deve mais existir o antigo filtro hardcoded de 86400s (24h).
        self.assertNotIn("time() - 86400", src)

    def test_view_labels_time_window_dynamically(self):
        src = read("DDoSSOCOverview", "views", "widget.view.php")
        self.assertIn("range_label", src)
        self.assertIn("Alertas recentes (%1$s)", src)


class TestHostHeartbeatFreshness(unittest.TestCase):
    """Um host offline ha dias nao pode aparecer como 'OK'."""

    def test_controller_checks_heartbeat_clock_not_just_value(self):
        src = read("DDoSSOCOverview", "actions", "WidgetView.php")
        self.assertIn("hi.clock", src, "precisa buscar o horario do ultimo heartbeat, nao so o valor")
        self.assertIn("HEARTBEAT_STALE_SECONDS", src)
        # A logica de 'online' precisa depender da idade calculada.
        self.assertIn("age", src)


class TestNoMisleadingBlockRate(unittest.TestCase):
    """blocks/events*100 misturava duas tabelas sem relacao garantida de
    cardinalidade - podia mostrar taxas sem sentido (>100% ou
    proximas de 0 mesmo com bloqueios reais em instalacoes so-MikroTik)."""

    def test_rate_ratio_removed(self):
        controller_src = read("DDoSSOCOverview", "actions", "WidgetView.php")
        view_src = read("DDoSSOCOverview", "views", "widget.view.php")
        self.assertNotIn("blocks / max($events", controller_src)
        self.assertNotIn("'rate'", controller_src.replace("'rate_ratio'", ""))
        self.assertNotIn("% taxa", view_src)


class TestPhpSyntaxValid(unittest.TestCase):
    FILES = [
        ("DDoSSOCOverview", "includes", "WidgetForm.php"),
        ("DDoSSOCOverview", "actions", "WidgetView.php"),
        ("DDoSSOCOverview", "views", "widget.view.php"),
        ("DDoSTimeline", "views", "widget.view.php"),
    ]

    def test_all_touched_files_lint_clean(self):
        for parts in self.FILES:
            rc, output = php_lint(*parts)
            self.assertEqual(rc, 0, f"{'/'.join(parts)}: {output}")


if __name__ == "__main__":
    unittest.main()
