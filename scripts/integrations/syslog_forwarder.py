#!/usr/bin/env python3
"""
DDoS Guard - Syslog Forwarder
==============================
Le /var/log/ddosguard-syslog.log em tempo real e envia eventos
ao ingest.php. Substitui o omprog do rsyslog (compativel com
versoes do rsyslog sem o modulo omprog instalado).

Instalacao:
  1. python3 /path/install_syslog_forwarder.py
  2. systemctl enable --now ddosguard-syslog

Suporta: MikroTik (DG-DROP/DG-BRUTE/DG-SCAN), pfSense (filterlog),
         iptables (DROP/REJECT), FortiGate (action=drop)
"""
import sys, os, time, re, json, ipaddress
import urllib.request

SYSLOG_FILE  = "/var/log/ddosguard-syslog.log"
INGEST_URL   = "http://localhost/zabbix/ddosguard/ingest.php"
INGEST_TOKEN = ""
ZBX_HOST     = ""

try:
    for ln in open("/etc/zabbix/ddos_guard_agent.conf"):
        ln = ln.strip()
        if ln.startswith("ingest_token"):
            INGEST_TOKEN = ln.split("=", 1)[1].strip()
        elif ln.startswith("zbx_host"):
            ZBX_HOST = ln.split("=", 1)[1].strip()
        elif ln.startswith("ingest_url"):
            INGEST_URL = ln.split("=", 1)[1].strip()
except Exception as e:
    print(f"Erro ao ler agent.conf: {e}", file=sys.stderr)
    sys.exit(1)

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

def parse_line(line):
    """Extrai IP e classifica o evento da linha de syslog."""
    src_ip = None
    for pat in [
        r"src-ip[=:](\d+\.\d+\.\d+\.\d+)",
        r"(\d+\.\d+\.\d+\.\d+):\d+->",
        r"SRC=(\d+\.\d+\.\d+\.\d+)",
        r"srcip=(\d+\.\d+\.\d+\.\d+)",
        r"from (\d+\.\d+\.\d+\.\d+)",
    ]:
        m = re.search(pat, line)
        if m:
            src_ip = m.group(1)
            break

    if not src_ip or is_private(src_ip):
        return None

    # Classifica o tipo de evento
    attack_type = "SUSPICIOUS_TRAFFIC"
    event_type  = "block_firewall"

    if "DG-BRUTE" in line:
        attack_type = "BRUTE_FORCE_SSH"
        event_type  = "attack"
    elif "DG-SCAN" in line:
        attack_type = "PORT_SCAN"
        event_type  = "attack"
    elif "DG-DROP" in line or "DROP" in line or "drop" in line:
        event_type = "block_firewall"
    elif "filterlog" in line:
        event_type = "block_firewall"
    elif "action=drop" in line or "action=block" in line or "action=deny" in line:
        event_type = "block_firewall"
    elif "REJECT" in line or "reject" in line:
        event_type = "block_firewall"

    # Porta de destino
    dst_port = None
    m = re.search(r"->[\d.]+:(\d+)", line)
    if not m:
        m = re.search(r"DPT=(\d+)", line)
    if not m:
        m = re.search(r"dstport=(\d+)", line)
    if m:
        dst_port = int(m.group(1))

    # Protocolo
    proto = "TCP"
    m = re.search(r"proto\s+(\w+)", line, re.I)
    if not m:
        m = re.search(r"PROTO=(\w+)", line)
    if m:
        proto = m.group(1).upper()

    # Hostname da origem (para zbx_host)
    host = ZBX_HOST
    m = re.match(r"(?:<\d+>)?\w{3}\s+\d+\s+\d+:\d+:\d+\s+(\S+)", line)
    if m:
        candidate = m.group(1)
        skip = {"kernel", "root", "debian", "zabbix", "ubuntu", "localhost"}
        if candidate not in skip and not candidate.startswith("python"):
            host = candidate

    return {
        "event_type":  event_type,
        "zbx_host":    host,
        "src_ip":      src_ip,
        "attack_type": attack_type,
        "target_port": dst_port,
        "protocol":    proto,
        "attempts":    1,
        "blocked":     event_type == "block_firewall",
        "source":      "syslog",
    }

def send(payload):
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        INGEST_URL, data=data, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-DG-Token":   INGEST_TOKEN,
        })
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.read()
    except Exception as e:
        print(f"[WARN] send: {e}", file=sys.stderr)

if __name__ == "__main__":
    print(f"DDoS Guard Syslog Forwarder iniciado")
    print(f"  Arquivo : {SYSLOG_FILE}")
    print(f"  Ingest  : {INGEST_URL}")
    print(f"  Host    : {ZBX_HOST}")
    sys.stdout.flush()

    if not os.path.exists(SYSLOG_FILE):
        open(SYSLOG_FILE, "a").close()

    with open(SYSLOG_FILE, "r") as f:
        f.seek(0, 2)  # vai para o final
        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    payload = parse_line(line)
                    if payload:
                        result = send(payload)
                        print(f"[+] {payload['src_ip']} -> {payload['attack_type']}")
                        sys.stdout.flush()
            else:
                time.sleep(0.5)
