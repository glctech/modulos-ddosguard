#!/usr/bin/env python3
"""
Testes de regressao para scripts/ddos_guard_agent.py.

Cobre dois bugs corrigidos na auditoria de 2026-08:

  1. Trafego [UFW ALLOW] de entrada (permitido por regra, portanto
     legitimo) nao deve ser agregado nem enviado como "attack" - ver
     _process_firewall_lines / is_ufw_allow_in.

  2. IngestClient.send deve tentar novamente (3x, backoff 1s/2s/4s) em
     falhas de rede transitorias (URLError), mas nao repetir em erros
     HTTP do servidor (HTTPError, ex.: 401 token invalido).

Uso:
    python3 tests/test_ddos_guard_agent.py
"""
import io
import os
import sys
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import ddos_guard_agent as dga  # noqa: E402


class DummyGeoResolver:
    def resolve(self, ip):
        return {"country": "US", "country_name": "United States", "city": None, "asn": None}


def make_agent():
    cfg = dga.load_config(None)
    agent = dga.DDoSGuardAgent.__new__(dga.DDoSGuardAgent)
    agent.cfg = cfg
    agent.zbx_host = "test-host"
    agent.hostid = "0"
    agent.aggregate_window = 60
    agent.geo = DummyGeoResolver()
    agent.ingest = mock.Mock()
    agent._agg = dga.defaultdict(lambda: {
        "attempts": 0, "first_seen": None, "last_seen": None,
        "target_port": None, "protocol": None, "source": None,
    })
    agent._distinct_ips_window = dga.deque()
    return agent


class TestUfwAllowNotCountedAsAttack(unittest.TestCase):
    def test_ufw_allow_in_is_skipped(self):
        agent = make_agent()
        line = ("Aug 14 10:00:00 host kernel: [UFW ALLOW] IN=eth0 OUT= "
                "SRC=203.0.113.9 DST=192.168.0.52 PROTO=TCP SPT=51000 DPT=80")
        agent._process_firewall_lines("ufw", [line])

        self.assertEqual(len(agent._agg), 0,
                          "trafego permitido (ALLOW) nao deve virar tentativa de ataque")
        agent.ingest.send.assert_not_called()

    def test_ufw_allow_in_real_world_format_with_mac_is_skipped(self):
        # Formato real do UFW: quando OUT= esta vazio, o proximo campo (MAC=)
        # vem colado sem espaco extra - "OUT= MAC=...". E exatamente esse
        # formato que a checagem por substring simples ("OUT= " not in line)
        # nunca detectava, pois a substring "OUT= " sempre aparece nele.
        agent = make_agent()
        line = ("Aug 14 10:00:03 host kernel: [UFW ALLOW] IN=eth0 OUT= "
                "MAC=aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00 "
                "SRC=203.0.113.9 DST=192.168.0.52 PROTO=TCP SPT=51002 DPT=80")
        agent._process_firewall_lines("ufw", [line])

        self.assertEqual(len(agent._agg), 0)
        agent.ingest.send.assert_not_called()

    def test_ufw_block_still_detected(self):
        agent = make_agent()
        line = ("Aug 14 10:00:01 host kernel: [UFW BLOCK] IN=eth0 OUT= "
                "SRC=203.0.113.9 DST=192.168.0.52 PROTO=TCP SPT=51001 DPT=22")
        agent._process_firewall_lines("ufw", [line])

        self.assertEqual(len(agent._agg), 1,
                          "bloqueio real ainda deve ser agregado")
        agent.ingest.send.assert_called_once()
        called_event_type = agent.ingest.send.call_args[0][0]
        self.assertEqual(called_event_type, "block_firewall")

    def test_ufw_audit_still_ignored(self):
        agent = make_agent()
        line = "Aug 14 10:00:02 host kernel: [UFW AUDIT] IN=eth0 SRC=203.0.113.9 DPT=443"
        agent._process_firewall_lines("ufw", [line])

        self.assertEqual(len(agent._agg), 0)
        agent.ingest.send.assert_not_called()


class FakeHTTPResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestIngestClientRetry(unittest.TestCase):
    def setUp(self):
        self.client = dga.IngestClient("http://127.0.0.1/ddosguard/ingest.php", "tok")

    @mock.patch("ddos_guard_agent.time.sleep", return_value=None)
    @mock.patch("ddos_guard_agent.urllib.request.urlopen")
    def test_retries_on_transient_network_error_then_succeeds(self, mock_urlopen, mock_sleep):
        mock_urlopen.side_effect = [
            urllib.error.URLError("connection refused"),
            urllib.error.URLError("connection refused"),
            FakeHTTPResponse(b"{}"),
        ]

        ok = self.client.send("heartbeat", "host", "0", {})

        self.assertTrue(ok)
        self.assertEqual(mock_urlopen.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)
        mock_sleep.assert_has_calls([mock.call(1), mock.call(2)])

    @mock.patch("ddos_guard_agent.time.sleep", return_value=None)
    @mock.patch("ddos_guard_agent.urllib.request.urlopen")
    def test_gives_up_after_max_attempts(self, mock_urlopen, mock_sleep):
        mock_urlopen.side_effect = urllib.error.URLError("timed out")

        ok = self.client.send("attack", "host", "0", {"src_ip": "1.2.3.4"})

        self.assertFalse(ok)
        self.assertEqual(mock_urlopen.call_count, 4)  # 1 tentativa inicial + 3 retries
        self.assertEqual(mock_sleep.call_count, 3)

    @mock.patch("ddos_guard_agent.time.sleep", return_value=None)
    @mock.patch("ddos_guard_agent.urllib.request.urlopen")
    def test_does_not_retry_on_http_error(self, mock_urlopen, mock_sleep):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://x", 401, "invalid token", {}, None
        )

        ok = self.client.send("heartbeat", "host", "0", {})

        self.assertFalse(ok)
        self.assertEqual(mock_urlopen.call_count, 1,
                          "erro HTTP do servidor nao deve ser re-tentado")
        mock_sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
