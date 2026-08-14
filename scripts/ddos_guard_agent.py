#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS Guard Agent
================
Coletor multiplataforma (Linux e Windows) que roda no host monitorado e
detecta, em tempo real:

  No Linux:
    - Ataques de força bruta / flood (varrendo logs de firewall:
      iptables, ufw, nftables, fail2ban)
    - Detecções/bloqueios de antivírus (ClamAV - clamd.log, ou qualquer
      ferramenta que escreva em log texto)

  No Windows:
    - Bloqueios do Windows Firewall (Event Log "Security", IDs 5152/5157
      - Windows Filtering Platform) e tentativas de logon falhadas /
      RDP brute-force (Event ID 4625)
    - Detecções do Windows Defender (Event Log "Microsoft-Windows-
      Windows Defender/Operational", IDs 1116/1117)

  Em ambos:
    - Geolocalização do IP de origem (GeoIP2 local, com fallback para
      API pública ip-api.com se a base local não estiver disponível)

E envia tudo para o endpoint ingest.php (ver scripts/ingest.php), que
grava no banco usado pelos widgets do dashboard e replica os
contadores para o Zabbix via zabbix_sender.

Uso:
    python3 ddos_guard_agent.py --config /etc/zabbix/ddos_guard_agent.conf      (Linux)
    python  ddos_guard_agent.py --config C:\\ProgramData\\DDoSGuard\\agent.conf  (Windows)

Pode ser executado como serviço systemd no Linux (ver
scripts/install_agent_linux.sh) ou como serviço do Windows via NSSM
(ver scripts/install_agent_windows.ps1), ou ainda manualmente com
--once para uso via cron / Agendador de Tarefas.

Dependências opcionais:
    pip install geoip2       # geolocalização local (mais rápida, sem rate-limit)
    pip install pywin32      # OBRIGATÓRIO no Windows, para ler o Event Log
    (sem geoip2, o agente usa a API pública ip-api.com)
"""

import argparse
import configparser
import json
import os
import platform
import re
import socket
import subprocess
import sys
import signal
import threading
import time
import urllib.request
import urllib.error
from collections import defaultdict, deque
from datetime import datetime, timezone

IS_WINDOWS = platform.system() == "Windows"

try:
    import geoip2.database
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False

HAS_WIN32EVTLOG = False  # mantido por compatibilidade, nao usado mais
# O agente Windows agora usa wevtutil.exe (nativo do Windows) em vez
# do pywin32, eliminando qualquer dependencia de 'pip install'.


# ---------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------
if IS_WINDOWS:
    _DEFAULT_STATE_FILE = r"C:\ProgramData\DDoSGuard\state.json"
    _DEFAULT_GEOIP_PATH = r"C:\ProgramData\DDoSGuard\GeoLite2-City.mmdb"
else:
    _DEFAULT_STATE_FILE = "/var/lib/zabbix/ddosguard/state.json"
    _DEFAULT_GEOIP_PATH = "/usr/share/GeoIP/GeoLite2-City.mmdb"

DEFAULT_CONFIG = {
    "general": {
        "zbx_host": socket.gethostname(),
        "hostid": "0",
        "ingest_url": "http://127.0.0.1/ddosguard/ingest.php",
        "ingest_token": "CHANGE_ME_TOKEN",
        "poll_interval": "10",            # segundos entre leituras dos logs
        "aggregate_window": "60",         # segundos para agregar contagem de tentativas/IP
        "geoip_db_path": _DEFAULT_GEOIP_PATH,
        "has_firewall": "auto",           # auto | yes | no
        "has_antivirus": "auto",
        "state_file": _DEFAULT_STATE_FILE,
    },
    "sources": {
        # --- Linux ---
        "iptables_log": "/var/log/kern.log",      # log onde aparecem linhas "iptables denied"
        "ufw_log": "/var/log/ufw.log",
        "fail2ban_log": "/var/log/fail2ban.log",
        "clamav_log": "/var/log/clamav/clamav.log",
        "auth_log": "/var/log/auth.log",          # tentativas de SSH brute force
        # --- Windows (Event Log, não são caminhos de arquivo) ---
        "windows_security_log": "Security",                                   # logon falhado / RDP brute-force
        "windows_firewall_log": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        "windows_defender_log": "Microsoft-Windows-Windows Defender/Operational",
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
    def __init__(self, path, skip_existing=True):
        """
        skip_existing=True (padrao): na primeira leitura, pula para o
        final do arquivo (ignora historico). Isso evita reprocessar
        milhares de entradas antigas do /var/log/messages ao reiniciar.
        skip_existing=False: le desde o inicio (util para debug).
        """
        self.path = path
        self._inode = None
        if skip_existing and path and os.path.exists(path):
            try:
                self._pos = os.path.getsize(path)
            except OSError:
                self._pos = 0
        else:
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
        try:
            with open(self.path, "r", errors="ignore") as f:
                f.seek(self._pos)
                for line in f:
                    lines.append(line.rstrip("\n"))
                self._pos = f.tell()
        except PermissionError:
            # Loga o aviso apenas uma vez (na primeira ocorrencia)
            if not getattr(self, '_perm_warned', False):
                log(f"Sem permissao para ler {self.path} - "
                    f"execute: chmod 644 {self.path}")
                self._perm_warned = True
        except OSError as e:
            log(f"Erro ao ler {self.path}: {e}")
        return lines


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class WindowsEventLogReader:
    """Le novos eventos do Windows Event Log usando wevtutil.exe,
    que e 100% nativo do Windows (sem necessidade de pywin32 ou
    qualquer pip install).

    wevtutil qe (query-events) retorna eventos em XML, que parseamos
    com o modulo xml.etree.ElementTree da biblioteca padrao do Python.
    Guarda o RecordNumber do ultimo evento lido para leitura incremental.
    """

    def __init__(self, channel, event_ids=None):
        self.channel = channel
        self.event_ids = set(event_ids) if event_ids else None
        self._last_record_number = None

    def read_new_events(self):
        if not self.channel:
            return []

        # Monta o XPath que filtra pelos event IDs que nos interessam.
        # Se nao foi especificado, pega todos (limitado a 100 mais recentes).
        if self.event_ids:
            ids_xpath = " or ".join(
                f"EventID={eid}" for eid in sorted(self.event_ids)
            )
            xpath = f"*[System[({ids_xpath})]]"
        else:
            xpath = "*"

        # Determina o ponto de partida: se ja lemos antes, filtra por
        # RecordNumber > ultimo lido. Na primeira execucao, pega so os
        # ultimos 50 eventos para nao processar historico gigante
        # (o log Security em producao pode ter milhoes de entradas).
        if self._last_record_number is not None:
            # Filtra por EventRecordID maior que o ultimo processado
            if self.event_ids:
                ids_xpath = " or ".join(
                    f"EventID={eid}" for eid in sorted(self.event_ids)
                )
                xpath = f"*[System[({ids_xpath}) and EventRecordID > {self._last_record_number}]]"
            else:
                xpath = f"*[System[EventRecordID > {self._last_record_number}]]"
            count_arg = []
        else:
            # Primeira execucao: pega so os 50 mais recentes
            count_arg = ["/c:50", "/rd:true"]

        cmd = [
            "wevtutil.exe", "qe", self.channel,
            "/f:xml",
            f"/q:{xpath}",
        ] + count_arg

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=15,
            )
        except FileNotFoundError:
            log("wevtutil.exe nao encontrado - Event Log nao sera lido.")
            return []
        except subprocess.TimeoutExpired:
            return []

        if not result.stdout.strip():
            return []

        # wevtutil retorna eventos XML sem raiz — adiciona wrapper para
        # que o ElementTree consiga parsear como um documento valido.
        xml_text = "<Events>" + result.stdout + "</Events>"
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_text)
        except Exception as e:
            log(f"Erro ao parsear XML do Event Log ({self.channel}): {e}")
            return []

        events = []
        max_record = self._last_record_number

        for event_elem in root.findall("Event"):
            ns = {"w": "http://schemas.microsoft.com/win/2004/08/events/event"}

            # Extrai EventID e EventRecordID do bloco System
            system = event_elem.find("w:System", ns)
            if system is None:
                continue

            eid_elem = system.find("w:EventID", ns)
            if eid_elem is None:
                continue
            try:
                event_id = int(eid_elem.text)
            except (TypeError, ValueError):
                continue

            record_elem = system.find("w:EventRecordID", ns)
            try:
                record_id = int(record_elem.text) if record_elem is not None else 0
            except (TypeError, ValueError):
                record_id = 0

            if max_record is None or record_id > max_record:
                max_record = record_id

            # Monta a mensagem concatenando todos os EventData/Data
            parts = []
            event_data = event_elem.find("w:EventData", ns)
            if event_data is not None:
                for data in event_data.findall("w:Data", ns):
                    name = data.get("Name", "")
                    val  = (data.text or "").strip()
                    if name and val and val not in ("-", "%%1833"):
                        parts.append(f"{name}: {val}")

            message = "\n".join(parts)

            events.append({
                "event_id": event_id,
                "record_id": record_id,
                "message": message,
                "time_generated": None,
            })

        if max_record is not None:
            self._last_record_number = max_record

        # Na primeira execucao vieram em ordem reversa (rd:true);
        # inverte para processar do mais antigo ao mais novo.
        if count_arg:
            events.reverse()

        return events


def is_private_ip(ip):
    """Retorna True para IPs que nao devem ser tratados como atacantes externos:
    RFC1918 (privados), loopback, link-local, broadcast e multicast."""
    if not ip:
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    # Loopback
    if a == 127:
        return True
    # RFC1918 privados
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    # Link-local
    if a == 169 and b == 254:
        return True
    # Broadcast / this-network
    if ip in ("0.0.0.0", "255.255.255.255"):
        return True
    # Multicast
    if 224 <= a <= 239:
        return True
    return False


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

    # Espera (segundos) entre tentativas, em caso de falha de rede transitoria
    # (timeout, conexao recusada, DNS). Erros HTTP do servidor (401, 400 etc.)
    # nao sao re-tentados: repetir a mesma requisicao nao muda o resultado.
    RETRY_BACKOFF = (1, 2, 4)

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

        attempts = len(self.RETRY_BACKOFF) + 1
        for attempt in range(1, attempts + 1):
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    r.read()
                if event_type == "heartbeat":
                    log(f"Heartbeat enviado com sucesso para {self.url}")
                return True
            except urllib.error.HTTPError as e:
                log(f"Falha ao enviar evento '{event_type}' para o ingest: {e}")
                return False
            except urllib.error.URLError as e:
                if attempt >= attempts:
                    log(f"Falha ao enviar evento '{event_type}' para o ingest "
                        f"apos {attempt} tentativas: {e}")
                    return False
                wait = self.RETRY_BACKOFF[attempt - 1]
                log(f"Falha ao enviar evento '{event_type}' (tentativa "
                    f"{attempt}/{attempts}): {e} - nova tentativa em {wait}s")
                time.sleep(wait)
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

        if IS_WINDOWS:
            log("Windows detectado — usando wevtutil.exe para leitura do Event Log (sem pywin32).")
            # Event ID 4625 = falha de logon (RDP/SMB/local brute-force).
            self.win_security = WindowsEventLogReader(s.get("windows_security_log"), event_ids=[4625])
            # Event IDs 5152/5157 = Windows Filtering Platform bloqueou um pacote/conexão.
            self.win_firewall = WindowsEventLogReader(s.get("windows_firewall_log"), event_ids=[5152, 5157])
            # Event IDs 1116 (detecção) / 1117 (ação tomada) do Windows Defender.
            self.win_defender = WindowsEventLogReader(s.get("windows_defender_log"), event_ids=[1116, 1117])
            self.tailers = {}
        else:
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

            # Detecta bloqueios: iptables DROP, UFW BLOCK, firewalld REJECT etc.
            is_drop = bool(re.search(
                r"DROP|REJECT|DENY|\[UFW BLOCK\]|IPTABLES_DROP|BLOCKED",
                line, re.I
            ))
            # UFW AUDIT e apenas informativo (nao e bloqueio nem ataque)
            if "[UFW AUDIT]" in line and "[UFW BLOCK]" not in line:
                continue
            # UFW ALLOW de trafego de ENTRADA com IP externo = trafego legitimo,
            # permitido explicitamente por uma regra. Nao e bloqueio nem ataque:
            # contá-lo como tentativa infla ddosguard.attacks.rate com conexões
            # normais (ex.: visitantes de um servidor web) e pode disparar as
            # triggers de "pico de ataques" / "possível DDoS" para tráfego legítimo.
            #
            # OUT= vazio (nada entre "OUT=" e o proximo campo) indica que o
            # pacote termina no proprio host (chain INPUT), e nao e roteado/
            # encaminhado (chain FORWARD, onde OUT= tem uma interface real).
            # Checar a substring "OUT= " sem uma regex casaria SEMPRE com o
            # formato padrao do UFW (`OUT= MAC=...`), fazendo esta deteccao
            # nunca disparar - por isso o valor do campo precisa ser extraido.
            out_match = re.search(r"OUT=(\S*)", line)
            is_ufw_allow_in = (
                "[UFW ALLOW]" in line and "IN=" in line
                and out_match is not None and out_match.group(1) == ""
            )
            if is_ufw_allow_in:
                continue

            ip = extract_ip(line)
            if not ip or is_private_ip(ip):
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
                    "city": geo.get("city"),
                    "asn": geo.get("asn"),
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
            if not ip or is_private_ip(ip):
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
                    "city": geo.get("city"),
                    "asn": geo.get("asn"),
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
            if not ip or is_private_ip(ip):
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

    # -------------------- detecção Windows: logon falhado / RDP brute-force --------------------
    def _process_windows_security_events(self, events):
        for ev in events:
            if ev["event_id"] != 4625:
                continue

            message = ev["message"]
            ts = now_ts()

            # No XML do evento 4625, o IP de origem fica em Data Name="IpAddress".
            # O WindowsEventLogReader monta a mensagem como "IpAddress: x.x.x.x\n..."
            ip = None
            m = re.search(r"IpAddress:\s*([^\s\r\n]+)", message)
            if m:
                raw_ip = m.group(1).strip()
                # Ignora loopback IPv4/IPv6 e valores nulos
                if raw_ip not in ("-", "::1", "::", "0.0.0.0") and \
                   not raw_ip.startswith("127."):
                    ip = raw_ip

            # Fallback: tenta extrair qualquer IPv4 da mensagem
            if not ip:
                ip = extract_ip(message)

            # Descarta loopback, nulos e IPs invalidos
            if not ip or ip in ("0.0.0.0", "-", "::1", "::") or ip.startswith("127."):
                continue

            key = (ip, "BRUTE_FORCE_RDP")
            agg = self._agg[key]
            agg["attempts"] += 1
            agg["last_seen"] = ts
            agg["first_seen"] = agg["first_seen"] or ts
            agg["source"] = "windows_security"
            self._distinct_ips_window.append((ts, ip))

    # -------------------- detecção Windows: Firewall bloqueou conexão --------------------
    def _process_windows_firewall_events(self, events):
        for ev in events:
            if ev["event_id"] not in (5152, 5157):
                continue
            ip = extract_ip(ev["message"])
            if not ip:
                continue
            ts = now_ts()

            port, proto = None, None
            m = re.search(r"Source Port:\s*(\d+)", ev["message"])
            if not m:
                m = re.search(r"\bSPT\s*[:=]\s*(\d+)", ev["message"])
            if m:
                port = int(m.group(1))
            m = re.search(r"Protocol:\s*(\d+)", ev["message"])
            if m:
                proto_num = m.group(1)
                proto = {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(proto_num, proto_num)

            key = (ip, "SUSPICIOUS_TRAFFIC")
            agg = self._agg[key]
            agg["attempts"] += 1
            agg["last_seen"] = ts
            agg["first_seen"] = agg["first_seen"] or ts
            agg["target_port"] = port or agg["target_port"]
            agg["protocol"] = proto or agg["protocol"]
            agg["source"] = "windows_firewall"
            self._distinct_ips_window.append((ts, ip))

            geo = self.geo.resolve(ip)
            self.ingest.send("block_firewall", self.zbx_host, self.hostid, {
                "src_ip": ip,
                "country": geo["country"],
                "country_name": geo["country_name"],
                "tool": "windows_firewall",
                "rule": ev["message"][-200:],
                "target_port": port,
                "protocol": proto,
                "reason": f"event_id_{ev['event_id']}",
                "timestamp": ts,
            })

    # -------------------- detecção Windows: Defender --------------------
    def _process_windows_defender_events(self, events):
        for ev in events:
            if ev["event_id"] not in (1116, 1117):
                continue
            message = ev["message"]
            ts = now_ts()

            malware = "Unknown threat"
            m = re.search(r"Name:\s*(.+)", message)
            if m:
                malware = m.group(1).split("\n")[0].strip()

            file_path = None
            m = re.search(r"Path:\s*(.+)", message)
            if m:
                file_path = m.group(1).split("\n")[0].strip()

            ip = extract_ip(message)
            geo = self.geo.resolve(ip) if ip else {"country": None, "country_name": None}

            self.ingest.send("block_antivirus", self.zbx_host, self.hostid, {
                "src_ip": ip or "127.0.0.1",
                "country": geo["country"],
                "country_name": geo["country_name"],
                "tool": "windows_defender",
                "malware": malware,
                "action": "detected" if ev["event_id"] == 1116 else "actioned",
                "file": file_path,
                "timestamp": ts,
            })

    # -------------------- ciclo principal --------------------
    def poll_once(self):
        if IS_WINDOWS:
            self._process_windows_security_events(self.win_security.read_new_events())
            self._process_windows_firewall_events(self.win_firewall.read_new_events())
            self._process_windows_defender_events(self.win_defender.read_new_events())
        else:
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



# ─────────────────────────────────────────────────────────────────────
VERSION = "2.4.0"
_shutdown_event = threading.Event()

def _handle_signal(signum, frame):
    """Graceful shutdown via SIGTERM / SIGINT."""
    log(f"[INFO] Sinal {signum} recebido — encerrando graciosamente...")
    _shutdown_event.set()

signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT,  _handle_signal)
# ─────────────────────────────────────────────────────────────────────

def main():
    default_config_path = (
        r"C:\ProgramData\DDoSGuard\agent.conf" if IS_WINDOWS
        else "/etc/zabbix/ddos_guard_agent.conf"
    )
    ap = argparse.ArgumentParser(description="DDoS Guard Agent - coletor de eventos de segurança para Zabbix")
    ap.add_argument("--config", default=default_config_path)
    ap.add_argument("--once", action="store_true", help="Executa um único ciclo de coleta e sai (uso via cron / Agendador de Tarefas).")
    args = ap.parse_args()

    if IS_WINDOWS:
        import shutil as _shutil
        if not _shutil.which("wevtutil"):
            log("AVISO: wevtutil.exe nao encontrado no PATH. "
                "O Event Log nao sera lido.")

    cfg = load_config(args.config)
    agent = DDoSGuardAgent(cfg)
    interval = int(cfg["general"]["poll_interval"])

    log(f"DDoS Guard Agent v{VERSION} iniciado ({platform.system()}) "
        f"| host={cfg['general']['zbx_host']} "
        f"| interval={interval}s")

    if args.once:
        agent.poll_once()
        return

    while not _shutdown_event.is_set():
        try:
            agent.poll_once()
        except Exception as e:
            log(f"[ERROR] Ciclo de coleta: {e}")
        # Usa evento para shutdown imediato (sem esperar o sleep inteiro)
        _shutdown_event.wait(timeout=interval)

    log("[INFO] DDoS Guard Agent encerrado.")


if __name__ == "__main__":
    main()
