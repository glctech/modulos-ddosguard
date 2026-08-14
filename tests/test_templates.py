#!/usr/bin/env python3
"""
Testes de regressao para os templates Zabbix do DDoS Guard
(templates/*.yaml).

Cobre a melhoria de deteccao de 2026-08-14 (ver docs/CHANGELOG.md, v3.1):

  1. Varios itens sao alimentados por receivers/agente como eventos
     individuais (valor sempre 1): ddosguard.firewall.rate,
     ddosguard.antivirus.rate, ddosguard.mtk.portscan,
     ddosguard.mtk.bruteforce. Triggers de volume sobre esses itens
     precisam usar sum(), nao min() - min() exige que TODO valor no
     periodo seja >= limiar, o que nunca acontece quando cada amostra
     vale exatamente 1, tornando a trigger praticamente impossivel de
     disparar. Esse bug existia nos 6 templates do projeto; corrigido
     em todos.
  2. Nos templates de agente, os limiares de deteccao ficam em macros
     {$DG.*}, nao hardcoded.
  3. Existe uma trigger de correlacao firewall+antivirus por host nos
     templates de agente.
  4. Toda dependencia de trigger resolve para uma trigger real do mesmo
     template (nome + expressao identicos), em qualquer template.

Uso:
    python3 tests/test_templates.py
"""
import glob
import os
import unittest

import yaml

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")

# Itens que o agente/receivers enviam como evento individual (valor sempre
# 1) em vez de contagem/gauge agregada - min() nunca deveria ser usado em
# triggers de volume sobre eles.
PER_EVENT_COUNTER_KEYS = (
    "ddosguard.firewall.rate",
    "ddosguard.antivirus.rate",
    "ddosguard.mtk.portscan",
    "ddosguard.mtk.bruteforce",
)


def load_template(filename):
    path = os.path.join(TEMPLATES_DIR, filename)
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    return doc["zabbix_export"]["templates"][0]


def load_all_templates(filename):
    """Alguns arquivos (ex.: fortigate) exportam mais de um template."""
    path = os.path.join(TEMPLATES_DIR, filename)
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    return doc["zabbix_export"]["templates"]


def all_triggers(tpl):
    triggers = []
    for item in tpl["items"]:
        for trg in item.get("triggers", []):
            triggers.append(trg)
    return triggers


class TemplateInvariantsMixin:
    filename = None
    firewall_key = "ddosguard.firewall.rate"
    antivirus_key = "ddosguard.antivirus.rate"

    @classmethod
    def setUpClass(cls):
        cls.tpl = load_template(cls.filename)
        cls.triggers = all_triggers(cls.tpl)
        cls.macros = {m["macro"]: m["value"] for m in cls.tpl.get("macros", [])}

    def _trigger_named(self, needle):
        matches = [t for t in self.triggers if needle in t["name"]]
        self.assertEqual(
            len(matches), 1,
            f"esperava exatamente 1 trigger contendo {needle!r}, achei {len(matches)}"
        )
        return matches[0]

    def test_firewall_volume_trigger_uses_sum_not_min(self):
        trg = self._trigger_named("Volume alto de bloqueios de firewall")
        self.assertIn(f"sum(/{self.tpl['template']}/{self.firewall_key}", trg["expression"])
        self.assertNotIn(f"min(/{self.tpl['template']}/{self.firewall_key}", trg["expression"])

    def test_antivirus_triggers_use_sum_not_min(self):
        for needle in ["detectou ameaça", "detectou ameaca",
                        "Múltiplas detecções de malware", "Multiplas deteccoes de malware",
                        "surto de malware"]:
            for trg in self.triggers:
                if needle in trg["name"] and self.antivirus_key in trg["expression"]:
                    self.assertIn(f"sum(/{self.tpl['template']}/{self.antivirus_key}", trg["expression"],
                                  f"{trg['name']} deveria usar sum(), nao min()")
                    self.assertNotIn(f"min(/{self.tpl['template']}/{self.antivirus_key}", trg["expression"])

    def test_antivirus_has_three_severity_tiers(self):
        priorities = sorted(
            t["priority"] for t in self.triggers
            if self.antivirus_key in t["expression"] and "firewall" not in t["expression"]
        )
        self.assertEqual(priorities, ["DISASTER", "HIGH", "WARNING"])

    def test_thresholds_are_macros_not_hardcoded(self):
        # A trigger de correlacao (ambos os keys na mesma expressao) usa um
        # simples ">0" de presenca, nao um limiar de volume configuravel -
        # nao se aplica a checagem de macro.
        for trg in self.triggers:
            expr = trg["expression"]
            is_correlation = self.firewall_key in expr and self.antivirus_key in expr
            if is_correlation:
                continue
            if self.firewall_key in expr or self.antivirus_key in expr:
                self.assertIn("{$DG.", expr,
                               f"{trg['name']!r} deveria referenciar um limiar via macro {{$DG.*}}")

    def test_firewall_antivirus_correlation_trigger_exists(self):
        matches = [
            t for t in self.triggers
            if self.firewall_key in t["expression"] and self.antivirus_key in t["expression"]
        ]
        self.assertEqual(len(matches), 1)
        trg = matches[0]
        self.assertIn(" and ", trg["expression"])
        self.assertEqual(trg["priority"], "HIGH")

    def test_all_trigger_dependencies_resolve(self):
        index = {(t["name"], t["expression"]) for t in self.triggers}
        for trg in self.triggers:
            for dep in trg.get("dependencies", []):
                self.assertIn(
                    (dep["name"], dep["expression"]), index,
                    f"dependencia de {trg['name']!r} nao resolve para nenhuma trigger real"
                )

    def test_no_duplicate_trigger_uuids(self):
        uuids = [t["uuid"] for t in self.triggers]
        self.assertEqual(len(uuids), len(set(uuids)))


class TestAgentTemplate(TemplateInvariantsMixin, unittest.TestCase):
    filename = "template_ddos_guard_agent.yaml"


class TestAgentWindowsTemplate(TemplateInvariantsMixin, unittest.TestCase):
    filename = "template_ddos_guard_agent_windows.yaml"


class TestNoMinOnPerEventCountersAcrossAllTemplates(unittest.TestCase):
    """Todos os 6 templates do projeto, incluindo os que nao usam macros
    {$DG.*} (Security Monitoring, Sophos, FortiGate/FortiSwitch, MikroTik)
    - a checagem de sum() vs min() se aplica a todos, independente de
    estrutura de macro."""

    def test_no_template_uses_min_on_per_event_counters(self):
        offenders = []
        for filename in sorted(os.path.basename(p) for p in glob.glob(os.path.join(TEMPLATES_DIR, "*.yaml"))):
            for tpl in load_all_templates(filename):
                for trg in all_triggers(tpl):
                    expr = trg["expression"]
                    for key in PER_EVENT_COUNTER_KEYS:
                        if key in expr and f"min(/{tpl['template']}/{key}" in expr:
                            offenders.append((filename, tpl["template"], trg["name"], expr))
        self.assertEqual(
            offenders, [],
            f"trigger(s) usando min() sobre item(ns) de evento individual (deveria ser sum()): {offenders}"
        )

    def test_every_template_file_is_valid_yaml_with_templates(self):
        files = sorted(glob.glob(os.path.join(TEMPLATES_DIR, "*.yaml")))
        self.assertGreaterEqual(len(files), 6)
        for path in files:
            for tpl in load_all_templates(os.path.basename(path)):
                self.assertIn("template", tpl)
                self.assertIn("items", tpl)


if __name__ == "__main__":
    unittest.main()
