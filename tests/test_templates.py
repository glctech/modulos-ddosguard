#!/usr/bin/env python3
"""
Testes de regressao para os templates Zabbix de agente
(templates/template_ddos_guard_agent.yaml e
templates/template_ddos_guard_agent_windows.yaml).

Cobre a melhoria de deteccao de 2026-08-14 (ver docs/CHANGELOG.md, v3.1):

  1. ddosguard.firewall.rate e ddosguard.antivirus.rate sao enviados pelo
     agente como eventos individuais (valor sempre 1) - as triggers de
     volume precisam usar sum(), nao min(), ou nunca disparam na pratica.
  2. Os limiares de deteccao ficam em macros {$DG.*}, nao hardcoded.
  3. Existe uma trigger de correlacao firewall+antivirus por host.
  4. Toda dependencia de trigger resolve para uma trigger real do mesmo
     template (nome + expressao identicos).

Uso:
    python3 tests/test_templates.py
"""
import os
import unittest

import yaml

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


def load_template(filename):
    path = os.path.join(TEMPLATES_DIR, filename)
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    return doc["zabbix_export"]["templates"][0]


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


if __name__ == "__main__":
    unittest.main()
