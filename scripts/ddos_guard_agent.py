#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS Guard Agent
================
Coletor que roda no host monitorado (ou em um coletor central que
recebe logs via syslog) e detecta, em tempo real:

  - Ataques de força bruta / flood (varrendo logs de firewall:
    iptables, ufw, nftables, fail2ban)
  - Detecções/bloqueios de antivírus (ClamAV - clamd.log / freshclam,
    ou qualquer ferramenta que escreva em log texto)
  - Geolocalização do IP de origem (GeoIP2 local, com fallback para
    API pública ip-api.com se a base local não estiver disponível)

E envia tudo para o endpoint ingest.php (ver scripts/ingest.php), que
grava no banco usado pelos widgets do dashboard e replica os
contadores para o Zabbix via zabbix_sender.

Uso:
    python3 ddos_guard_agent.py --config /etc/zabbix/ddos_guard_agent.conf

Pode ser executado como serviço systemd (recomendado, ver
docs/INSTALL.md) ou via cron a cada minuto com --once.

Dependências opcionais:
    pip install geoip2      # para geolocalização local (mais rápida, sem rate-limit)
    (sem geoip2 instalado, o agente usa a API pública ip-api.com)
"""

import argparse
import configparser
import json
import os
import re
import socket
import sys
import time
import urllib.request
import urllib.error
from collections import defaultdict, deque
from datetime import datetime, timezone

try:
    import geoip2.database
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False


# ---------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------
DEFAULT_CONFIG = {
    "general": {
        "zbx_host": socket.gethostname(),
        "hostid": "0",
        "ingest_url": "http://127.0.0.1/zabbix/ddosguard/ingest.php",
        "ingest_token": "CHANGE_ME_TOKEN",
        "poll_interval": "10",            # segundos entre leituras dos logs
        "aggregate_window": "60",         # segundos para agregar contagem de tentativas/IP
        "geoip_db_path": "/usr/share/GeoIP/GeoLite2-City.mmdb",
        "has_firewall": "auto",           # auto | yes | no
        "has_antivirus": "auto",
        "state_file": "/var/lib/zabbix/ddosguard/state.json",
    },
    "sources": {
        "iptables_log": "/var/log/kern.log",      # log onde aparecem linhas "iptables denied"
        "ufw_log": "/var/log/ufw.log",
        "fail2ban_log": "/var/log/fail2ban.log",
        "clamav_log": "/var/log/clamav/clamav.log",
        "auth_log": "/var/log/auth.log",          # tentativas de SSH brute force
    },
}

ATTACK_TYPE_MAP = [
    (re.compile(r"SYN.?FLOOD", re.I), "SYN_FLOOD"),
    (re.compile(r"UDP.?FLOOD", re.I), "UDP_FLOOD"),
    (re.compile(r"ICMP", re.I), "ICMP_FLOOD"),
    (re.compile(r"port ?scan", re.I), "PORT_SCAN"),
    (re.compile(r"Failed password|authentication failure", re.I), "BRUTE_FORCE_SSH"),
    (re.compile(r"slowloris|http.?flood", re.I), "HTTP_FLOOD"),
]


def now_ts():
    return int(time.time())


def log(msg):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------
# Geolocalização
# ---------------------------------------------------------------------
class GeoResolver:
    def __init__(self, db_path):
        self._reader = None
        self._cache = {}
        if HAS_GEOIP2 and os.path.exists(db_path):
            try:
                self._reader = geoip2.database.Reader(db_path)
                log(f"GeoIP2 local carregado: {db_path}")
            except Exception as e:
                log(f"Falha ao abrir base GeoIP2 ({e}); usando API pública como fallback.")

    def resolve(self, ip):
        if ip in self._cache:
            return self._cache[ip]

        result = {"country": None, "country_name": None, "city": None, "asn": None}

        if self._reader:
            try:
                resp = self._reader.city(ip)
                result["country"] = resp.country.iso_code
                result["country_name"] = resp.country.name
                result["city"] = resp.city.name
            except Exception:
                pass
        else:
            # Fallback: API pública gratuita (rate-limited ~45 req/min).
            try:
                url = f"http://ip-api.com/json/{ip}?fields=countryCode,country,city,as"
                with urllib.request.urlopen(url, timeout=3) as r:
                    data = json.loads(r.read().decode())
                    result["country"] = data.get("countryCode")
                    result["country_name"] = data.get("country")
                    result["city"] = data.get("city")
                    result["asn"] = data.get("as")
            except Exception:
                pass

        self._cache[ip] = result
        return result


# ---------------------------------------------------------------------
# Leitura incremental de arquivos de log (estilo "tail -F")
# ---------------------------------------------------------------------
class LogTailer:
    def __init__(self, path):
        self.path = path
        self._inode = None
        self._pos = 0

    def read_new_lines(self):
        if not self.path or not os.path.exists(self.path):
            return []
        try:
            st = os.stat(self.path)
        except OSError:
            return []

        # Detecta rotação de log (logrotate trocou o inode).
        if self._inode is not None and st.st_ino != self._inode:
            self._pos = 0
        self._inode = st.st_ino

        if st.st_size < self._pos:
            self._pos = 0  # arquivo truncado

        lines = []
        with open(self.path, "r", errors="ignore") as f:
            f.seek(self._pos)
            for line in f:
                lines.append(line.rstrip("\n"))
            self._pos = f.tell()
        return lines


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ip(line):
    # Prioriza padrões "SRC=x.x.x.x" (iptables) e "from x.x.x.x" (sshd/fail2ban).
    m = re.search(r"SRC=(\d{1,3}(?:\.\d{1,3}){3})", line)
    if m:
        return m.group(1)
    m = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", line)
    if m:
        return m.group(1)
    m = IP_RE.search(line)
    return m.group(0) if m else None


def classify_attack(line):
    for pattern, label in ATTACK_TYPE_MAP:
        if pattern.search(line):
            return label
    return "SUSPICIOUS_TRAFFIC"


def extract_port_proto(line):
    port = None
    proto = None
    m = re.search(r"DPT=(\d+)", line)
    if m:
        port = int(m.group(1))
    m = re.search(r"PROTO=(\w+)", line)
    if m:
        proto = m.group(1)
    return port, proto


# ---------------------------------------------------------------------
# Cliente HTTP do ingest
# ---------------------------------------------------------------------
class IngestClient:
    def __init__(self, url, token):
        self.url = url
        self.token = token

    def send(self, event_type, hostname, hostid, payload):
        body = dict(payload)
        body["event_type"] = event_type
        body["zbx_host"] = hostname
        body["hostid"] = hostid
        data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(
            self.url, data=data, method="POST",
            headers={
                "Content-Type": "application/json",
                "X-DG-Token": self.token,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                r.read()
            return True
        except urllib.error.URLError as e:
            log(f"Falha ao enviar evento '{event_type}' para o ingest: {e}")
            return False


# ---------------------------------------------------------------------
# Detector / agregador principal
# ---------------------------------------------------------------------
class DDoSGuardAgent:
    def __init__(self, cfg):
        self.cfg = cfg
        g = cfg["general"]
        s = cfg["sources"]

        self.zbx_host = g["zbx_host"]
        self.hostid = g["hostid"]
        self.aggregate_window = int(g["aggregate_window"])

        self.geo = GeoResolver(g["geoip_db_path"])
        self.ingest = IngestClient(g["ingest_url"], g["ingest_token"])

        self.tailers = {
            "iptables": LogTailer(s.get("iptables_log")),
            "ufw": LogTailer(s.get("ufw_log")),
            "fail2ban": LogTailer(s.get("fail2ban_log")),
            "clamav": LogTailer(s.get("clamav_log")),
            "auth": LogTailer(s.get("auth_log")),
        }

        # agregação em memória: (src_ip, attack_type) -> dados
        self._agg = defaultdict(lambda: {
            "attempts": 0, "first_seen": None, "last_seen": None,
            "target_port": None, "protocol": None, "source": None,
        })
        self._distinct_ips_window = deque()  # (timestamp, ip) para janela de 5 min

    # -------------------- detecção de firewall --------------------
    def _process_firewall_lines(self, source_name, lines):
        for line in lines:
            if not line:
                continue
            is_drop = bool(re.search(r"DROP|REJECT|DENY|BLOCK", line, re.I))
            ip = extract_ip(line)
            if not ip:
                continue

            attack_type = classify_attack(line)
            port, proto = extract_port_proto(line)
            ts = now_ts()

            key = (ip, attack_type)
            agg = self._agg[key]
            agg["attempts"] += 1
            agg["last_seen"] = ts
            agg["first_seen"] = agg["first_seen"] or ts
            agg["target_port"] = port or agg["target_port"]
            agg["protocol"] = proto or agg["protocol"]
            agg["source"] = source_name

            self._distinct_ips_window.append((ts, ip))

            if is_drop:
                geo = self.geo.resolve(ip)
                self.ingest.send("block_firewall", self.zbx_host, self.hostid, {
                    "src_ip": ip,
                    "country": geo["country"],
                    "country_name": geo["country_name"],
                    "tool": source_name,
                    "rule": line[-200:],
                    "target_port": port,
                    "protocol": proto,
                    "reason": attack_type,
                    "timestamp": ts,
                })

    def _process_fail2ban_lines(self, lines):
        for line in lines:
            if "Ban " not in line and "Found " not in line:
                continue
            ip = extract_ip(line)
            if not ip:
                continue
            ts = now_ts()
            geo = self.geo.resolve(ip)

            key = (ip, "BRUTE_FORCE_SSH")
            agg = self._agg[key]
            agg["attempts"] += 1
            agg["last_seen"] = ts
            agg["first_seen"] = agg["first_seen"] or ts
            agg["source"] = "fail2ban"
            self._distinct_ips_window.append((ts, ip))

            if "Ban " in line:
                self.ingest.send("block_firewall", self.zbx_host, self.hostid, {
                    "src_ip": ip,
                    "country": geo["country"],
                    "country_name": geo["country_name"],
                    "tool": "fail2ban",
                    "rule": "BAN",
                    "reason": "BRUTE_FORCE_SSH",
                    "timestamp": ts,
                })

    def _process_auth_lines(self, lines):
        for line in lines:
            if "Failed password" not in line and "authentication failure" not in line:
                continue
            ip = extract_ip(line)
            if not ip:
                continue
            ts = now_ts()
            key = (ip, "BRUTE_FORCE_SSH")
            agg = self._agg[key]
            agg["attempts"] += 1
            agg["last_seen"] = ts
            agg["first_seen"] = agg["first_seen"] or ts
            agg["source"] = "auth.log"
            self._distinct_ips_window.append((ts, ip))

    # -------------------- detecção de antivírus --------------------
    def _process_clamav_lines(self, lines):
        for line in lines:
            if "FOUND" not in line:
                continue
            # Formato típico: "/path/to/file: Win.Trojan.Generic-12345 FOUND"
            m = re.match(r"(.+?):\s+(.+?)\s+FOUND", line)
            if not m:
                continue
            file_path, malware = m.group(1).strip(), m.group(2).strip()
            ts = now_ts()
            ip = extract_ip(line)  # pode não existir (arquivo local), tudo bem
            geo = self.geo.resolve(ip) if ip else {"country": None, "country_name": None}

            self.ingest.send("block_antivirus", self.zbx_host, self.hostid, {
                "src_ip": ip or "127.0.0.1",
                "country": geo["country"],
                "country_name": geo["country_name"],
                "tool": "clamav",
                "malware": malware,
                "action": "quarantined",
                "file": file_path,
                "timestamp": ts,
            })

    # -------------------- ciclo principal --------------------
    def poll_once(self):
        self._process_firewall_lines("iptables", self.tailers["iptables"].read_new_lines())
        self._process_firewall_lines("ufw", self.tailers["ufw"].read_new_lines())
        self._process_fail2ban_lines(self.tailers["fail2ban"].read_new_lines())
        self._process_auth_lines(self.tailers["auth"].read_new_lines())
        self._process_clamav_lines(self.tailers["clamav"].read_new_lines())

        self._flush_aggregates()
        self._send_distinct_ip_count()
        self.ingest.send("heartbeat", self.zbx_host, self.hostid, {})

    def _flush_aggregates(self):
        if not self._agg:
            return
        for (ip, attack_type), data in list(self._agg.items()):
            geo = self.geo.resolve(ip)
            severity = self._estimate_severity(data["attempts"])
            self.ingest.send("attack", self.zbx_host, self.hostid, {
                "src_ip": ip,
                "country": geo["country"],
                "country_name": geo["country_name"],
                "city": geo["city"],
                "asn": geo.get("asn"),
                "attack_type": attack_type,
                "target_port": data["target_port"],
                "protocol": data["protocol"],
                "attempts": data["attempts"],
                "severity_code": severity,
                "blocked": True,
                "blocked_by": "firewall",
                "source": data["source"],
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
            })
        self._agg.clear()

    def _estimate_severity(self, attempts):
        if attempts >= 500:
            return 4  # critical
        if attempts >= 100:
            return 3  # high
        if attempts >= 20:
            return 2  # medium
        return 1      # low

    def _send_distinct_ip_count(self):
        """Calcula quantos IPs distintos atacaram nos últimos 5 minutos e
        envia esse contador junto do heartbeat (consumido pelo item
        ddosguard.distinct_ips.rate / trigger de DDoS distribuído)."""
        cutoff = now_ts() - 300  # 5 minutos
        while self._distinct_ips_window and self._distinct_ips_window[0][0] < cutoff:
            self._distinct_ips_window.popleft()
        distinct = len({ip for _, ip in self._distinct_ips_window})
        self.ingest.send("heartbeat", self.zbx_host, self.hostid, {"distinct_ips": distinct})


def load_config(path):
    parser = configparser.ConfigParser()
    parser.read_dict(DEFAULT_CONFIG)
    if path and os.path.exists(path):
        parser.read(path)
    return parser


def main():
    ap = argparse.ArgumentParser(description="DDoS Guard Agent - coletor de eventos de segurança para Zabbix")
    ap.add_argument("--config", default="/etc/zabbix/ddos_guard_agent.conf")
    ap.add_argument("--once", action="store_true", help="Executa um único ciclo de coleta e sai (uso via cron).")
    args = ap.parse_args()

    cfg = load_config(args.config)
    agent = DDoSGuardAgent(cfg)
    interval = int(cfg["general"]["poll_interval"])

    log("DDoS Guard Agent iniciado.")
    if args.once:
        agent.poll_once()
        return

    while True:
        try:
            agent.poll_once()
        except Exception as e:
            log(f"Erro no ciclo de coleta: {e}")
        time.sleep(interval)


if __name__ == "__main__":
    main()
