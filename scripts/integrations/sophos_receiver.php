<?php
/**
 * DDoS Guard - Integração Sophos (syslog receiver)
 * ==================================================
 * Recebe logs do Sophos XG/XGS Firewall, Sophos Central e
 * Sophos Intercept X via syslog e normaliza para o DDoS Guard.
 *
 * CONFIGURAÇÃO NO SOPHOS XG/XGS:
 *   System > Administration > Notification Settings
 *     Log Settings > Syslog Server > Add
 *       Name:    DDoS Guard
 *       IP:      IP_DO_APPLIANCE_ZABBIX
 *       Port:    514
 *       Facility: LOCAL0
 *       Format:  Device Standard Format (SFOS)
 *     Severity: Information
 *
 *   Habilite os log types:
 *     ✅ Firewall (tráfego bloqueado)
 *     ✅ IPS (intrusões detectadas)
 *     ✅ Anti-Virus (malware detectado)
 *     ✅ ATP (Advanced Threat Protection)
 *     ✅ Web Filter (sites bloqueados)
 *     ✅ Anti-Spam
 *     ✅ System Health
 *
 * CONFIGURAÇÃO VIA CLI (SFOS):
 *   system syslog add name "DDoSGuard" ipaddress IP_ZABBIX port 514
 *   system syslog enable
 *
 * CONFIGURAÇÃO NO SOPHOS CENTRAL (Intercept X):
 *   Sophos Central não envia syslog diretamente.
 *   Use o Sophos Syslog Forwarder (agent) no Windows ou
 *   configure o log via API + syslog_forwarder.py
 *
 * RSYSLOG NO APPLIANCE (/etc/rsyslog.d/ddosguard.conf):
 *   Já configurado pelo install_integrations.sh
 *   Logs gravados em /var/log/ddosguard-syslog.log
 *   Processados pelo syslog_forwarder.py
 *
 * Formatos suportados:
 *   - SFOS (Sophos Firewall OS) — XG/XGS formato padrão
 *   - CEF (Common Event Format) — opcional no XG
 *   - Sophos Central JSON — via API forwarder
 */

// ── Bootstrap ────────────────────────────────────────────────────────────────
$config_path = '/etc/zabbix/ddosguard/ingest.config.php';
if (!file_exists($config_path)) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'config not found']);
    exit;
}

$cfg = include $config_path;
$INGEST_TOKEN   = $cfg['DG_INGEST_TOKEN'] ?? '';
$ZBX_SENDER_BIN = $cfg['DG_ZABBIX_SENDER_BIN'] ?? '/usr/bin/zabbix_sender';
$ZBX_SERVER     = $cfg['DG_ZBX_SERVER'] ?? '127.0.0.1';
$ZBX_PORT       = $cfg['DG_ZBX_PORT']   ?? '10051';
$DB_DRIVER      = $cfg['DG_DB_DRIVER']  ?? 'mysql';
$DB_HOST        = $cfg['DG_DB_HOST']    ?? '127.0.0.1';
$DB_PORT        = $cfg['DG_DB_PORT']    ?? '3306';
$DB_NAME        = $cfg['DG_DB_NAME']    ?? 'zabbix';
$DB_USER        = $cfg['DG_DB_USER']    ?? 'zabbix';
$DB_PASS        = $cfg['DG_DB_PASS']    ?? '';

// Detecta modo: HTTP POST ou stdin (syslog_forwarder.py)
$is_http = (PHP_SAPI === 'fpm-fcgi' || PHP_SAPI === 'apache2handler'
            || isset($_SERVER['HTTP_HOST']));

if ($is_http) {
    header('Content-Type: application/json; charset=utf-8');
    $token = $_SERVER['HTTP_X_DG_TOKEN'] ?? '';
    if ($token !== $INGEST_TOKEN) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'unauthorized']);
        exit;
    }
    $raw   = file_get_contents('php://input');
    $lines = [trim($raw)];
} else {
    $lines = [];
    while (($line = fgets(STDIN)) !== false) {
        $line = trim($line);
        if ($line !== '') $lines[] = $line;
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function db_connect_sophos(
    string $driver, string $host, string $port,
    string $name, string $user, string $pass): PDO
{
    return new PDO(
        "{$driver}:host={$host};port={$port};dbname={$name};charset=utf8mb4",
        $user, $pass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
         PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
    );
}

function zabbix_send_sophos(
    string $bin, string $server, string $port,
    string $host, array $items): void
{
    if (!file_exists($bin)) return;
    $args = ['-z', $server, '-p', $port, '-s', $host];
    foreach ($items as $key => $val) {
        $args = array_merge($args, ['-k', $key, '-o', (string)$val]);
    }
    $cmd = escapeshellcmd($bin) . ' '
         . implode(' ', array_map('escapeshellarg', $args))
         . ' 2>/dev/null';
    exec($cmd);
}

// ── Parser de log SFOS (Sophos Firewall OS) ──────────────────────────────────
/**
 * Formato SFOS — campos separados por espaço, key=value ou key="value":
 *   device="SFW" date=2026-07-15 time=10:30:00 timezone="BRT"
 *   log_id=010101600001 log_type="Firewall" log_component="Firewall Rule"
 *   log_subtype="Denied" status="Deny" priority=Information
 *   duration=0 fw_rule_id=7 policy_type=1
 *   user_name="" user_gp="" iap=0 ips_policy_id=0
 *   appfilter_policy_id=0 application="" application_risk=0
 *   application_technology="" application_category=""
 *   in_interface="Port1" out_interface="" src_mac=00:00:00:00:00:00
 *   src_ip=185.220.101.50 src_country_code=DEU dst_ip=192.168.1.1
 *   dst_country_code=BRA protocol="TCP" src_port=45123 dst_port=22
 *   sent_pkts=0 recv_pkts=0 sent_bytes=0 recv_bytes=0 tran_src_ip=""
 *   tran_src_port=0 tran_dst_ip="" tran_dst_port=0
 *   srczonetype="" srczone="" dstzonetype="" dstzone=""
 *   dir_disp="" connid="" vconnid="" hb_health="No Heartbeat"
 *   message="" appresolvedby="Signature" app_is_cloud=0
 */
function parse_sfos(string $line): ?array
{
    // Extrai todos os campos key=value ou key="value"
    preg_match_all('/(\w+)=(?:"([^"]*?)"|(\S+))/', $line, $m);
    $fields = [];
    foreach ($m[1] as $i => $key) {
        $fields[$key] = $m[2][$i] !== '' ? $m[2][$i] : $m[3][$i];
    }

    if (empty($fields)) return null;

    $src_ip    = $fields['src_ip']   ?? '';
    $dst_ip    = $fields['dst_ip']   ?? '';
    $dst_port  = (int)($fields['dst_port'] ?? 0);
    $src_port  = (int)($fields['src_port'] ?? 0);
    $protocol  = strtoupper($fields['protocol'] ?? 'TCP');
    $log_type  = $fields['log_type']      ?? '';
    $log_sub   = $fields['log_subtype']   ?? '';
    $status    = strtolower($fields['status']   ?? '');
    $message   = $fields['message']       ?? '';
    $hostname  = $fields['device_name']   ?? $fields['device'] ?? '';
    $severity  = strtolower($fields['priority'] ?? 'information');

    // Filtra IPs inválidos ou privados
    if (empty($src_ip) || $src_ip === '0.0.0.0') return null;
    try {
        if ((new \Exception())->getCode() === 0) {} // dummy
        $ip_obj = @inet_pton($src_ip);
        if ($ip_obj === false) return null;
        // RFC 1918 + loopback
        $priv = [
            '10.','192.168.','172.16.','172.17.','172.18.','172.19.',
            '172.20.','172.21.','172.22.','172.23.','172.24.','172.25.',
            '172.26.','172.27.','172.28.','172.29.','172.30.','172.31.',
            '127.','169.254.',
        ];
        foreach ($priv as $p) {
            if (str_starts_with($src_ip, $p)) return null;
        }
    } catch (Throwable $e) { return null; }

    // Classifica por log_type + log_subtype
    $attack_type = 'SUSPICIOUS_TRAFFIC';
    $event_type  = 'attack';
    $sev_score   = 3;
    $mitre_tac   = null;
    $mitre_tech  = null;
    $block_tool  = 'sophos';

    $lt = strtolower($log_type);
    $ls = strtolower($log_sub);

    if ($lt === 'firewall' || str_contains($ls, 'denied') || str_contains($ls, 'deny')) {
        $event_type  = 'block_firewall';
        $attack_type = 'SUSPICIOUS_TRAFFIC';
        $sev_score   = 3;

        if ($dst_port === 22 || $dst_port === 2222) {
            $attack_type = 'BRUTE_FORCE_SSH'; $sev_score = 5;
            $mitre_tac = 'Credential Access'; $mitre_tech = 'T1110.001';
        } elseif ($dst_port === 3389) {
            $attack_type = 'BRUTE_FORCE_RDP'; $sev_score = 5;
            $mitre_tac = 'Credential Access'; $mitre_tech = 'T1110';
        } elseif ($dst_port === 80 || $dst_port === 443 || $dst_port === 8080) {
            $attack_type = 'WEB_ATTACK'; $sev_score = 4;
            $mitre_tac = 'Initial Access'; $mitre_tech = 'T1190';
        }
    } elseif ($lt === 'ips' || str_contains($lt, 'intrusion')) {
        $event_type  = 'attack';
        $attack_type = 'IPS_DETECTION';
        $sev_score   = 6;
        $mitre_tac   = 'Initial Access';
        $mitre_tech  = 'T1190';

        if (str_contains(strtolower($message), 'sql')) {
            $attack_type = 'SQL_INJECTION'; $mitre_tech = 'T1190';
        } elseif (str_contains(strtolower($message), 'scan')) {
            $attack_type = 'PORT_SCAN'; $mitre_tac = 'Reconnaissance'; $mitre_tech = 'T1595';
        } elseif (str_contains(strtolower($message), 'flood') ||
                  str_contains(strtolower($message), 'dos')) {
            $attack_type = 'SYN_FLOOD'; $sev_score = 8;
            $mitre_tac = 'Impact'; $mitre_tech = 'T1498.001';
        }
    } elseif ($lt === 'anti-virus' || $lt === 'antivirus' || $lt === 'atp') {
        $event_type  = 'block_antivirus';
        $attack_type = 'MALWARE';
        $sev_score   = 7;
        $mitre_tac   = 'Execution';
        $mitre_tech  = 'T1204';
        $block_tool  = 'sophos-av';

        if ($lt === 'atp') {
            $attack_type = 'C2_COMMUNICATION';
            $sev_score   = 9;
            $mitre_tac   = 'Command and Control';
            $mitre_tech  = 'T1071';
        }
    } elseif (str_contains($lt, 'web') || str_contains($lt, 'filter')) {
        $event_type  = 'attack';
        $attack_type = 'WEB_ATTACK';
        $sev_score   = 4;
        $mitre_tac   = 'Initial Access';
        $mitre_tech  = 'T1190';
    } elseif (str_contains($lt, 'spam')) {
        $event_type  = 'attack';
        $attack_type = 'SPAM';
        $sev_score   = 2;
        $mitre_tac   = 'Initial Access';
        $mitre_tech  = 'T1566';
    }

    // Ajusta severidade pelo campo priority do SFOS
    if ($severity === 'critical' || $severity === 'emergency')  $sev_score = max($sev_score, 8);
    elseif ($severity === 'alert' || $severity === 'error')     $sev_score = max($sev_score, 6);
    elseif ($severity === 'warning')                            $sev_score = max($sev_score, 4);

    return [
        'event_type'    => $event_type,
        'zbx_host'      => $hostname ?: 'sophos-xg',
        'hostid'        => 0,
        'src_ip'        => $src_ip,
        'attack_type'   => $attack_type,
        'target_port'   => $dst_port ?: null,
        'protocol'      => $protocol,
        'attempts'      => 1,
        'blocked'       => in_array($event_type, ['block_firewall','block_antivirus']),
        'source'        => 'sophos',
        'platform'      => 'sophos',
        'tool'          => $block_tool,
        'log_type'      => $log_type,
        'log_subtype'   => $log_sub,
        'message'       => $message,
        'severity_code' => $sev_score,
        'mitre_tactic'  => $mitre_tac,
        'mitre_tech'    => $mitre_tech,
        'rule_id'       => $fields['log_id']      ?? null,
        'rule_name'     => $fields['log_component'] ?? null,
        'country'       => substr($fields['src_country_code'] ?? '', 0, 3) ?: null,
        'raw'           => $line,
    ];
}

// ── Parser CEF (Common Event Format — opcional Sophos XG) ────────────────────
function parse_cef(string $line): ?array
{
    // CEF:0|Sophos|XG|SFOS 18.5|030906209024|Firewall Deny|3|...
    if (!str_starts_with($line, 'CEF:')) return null;

    $parts = explode('|', $line, 8);
    if (count($parts) < 8) return null;

    $severity_cef = (int)($parts[6] ?? 0);
    $ext_raw      = $parts[7] ?? '';

    // Parseia extensões CEF: key=value
    preg_match_all('/(\w+)=((?:[^\s=]+(?:\s+(?!\w+=))*)+)/', $ext_raw, $m);
    $ext = [];
    foreach ($m[1] as $i => $key) {
        $ext[$key] = trim($m[2][$i]);
    }

    $src_ip   = $ext['src']  ?? $ext['spt']  ?? '';
    $dst_port = (int)($ext['dpt'] ?? 0);
    $protocol = strtoupper($ext['proto'] ?? 'TCP');
    $message  = $parts[5] ?? '';

    if (empty($src_ip)) return null;

    $attack_type = 'SUSPICIOUS_TRAFFIC';
    $event_type  = 'block_firewall';
    $sev_score   = min(10, (int)ceil($severity_cef * 10/10));

    if (str_contains(strtolower($message), 'intrusion') ||
        str_contains(strtolower($message), 'ips')) {
        $event_type = 'attack'; $attack_type = 'IPS_DETECTION'; $sev_score = max(6, $sev_score);
    } elseif (str_contains(strtolower($message), 'virus') ||
              str_contains(strtolower($message), 'malware')) {
        $event_type = 'block_antivirus'; $attack_type = 'MALWARE'; $sev_score = max(7, $sev_score);
    }

    return [
        'event_type'    => $event_type,
        'zbx_host'      => $ext['dvchost'] ?? 'sophos-xg',
        'hostid'        => 0,
        'src_ip'        => $src_ip,
        'attack_type'   => $attack_type,
        'target_port'   => $dst_port ?: null,
        'protocol'      => $protocol,
        'attempts'      => 1,
        'blocked'       => true,
        'source'        => 'sophos',
        'platform'      => 'sophos-cef',
        'tool'          => 'sophos',
        'severity_code' => $sev_score,
        'raw'           => $line,
    ];
}

// ── Processamento principal ──────────────────────────────────────────────────
$processed = 0;
$pdo = null;

foreach ($lines as $line) {
    if (empty($line)) continue;

    // Detecta formato
    $parsed = null;
    if (str_starts_with($line, 'CEF:')) {
        $parsed = parse_cef($line);
    } else {
        $parsed = parse_sfos($line);
    }

    if (!$parsed || empty($parsed['src_ip'])) continue;

    try {
        if (!$pdo) {
            $pdo = db_connect_sophos(
                $DB_DRIVER, $DB_HOST, $DB_PORT, $DB_NAME, $DB_USER, $DB_PASS
            );
        }

        // Resolve hostid pelo zbx_host
        try {
            $s = $pdo->prepare(
                "SELECT hostid FROM hosts WHERE host=:h AND status=0 LIMIT 1"
            );
            $s->execute([':h' => $parsed['zbx_host']]);
            $row = $s->fetch();
            $parsed['hostid'] = $row ? (int)$row['hostid'] : 0;
        } catch (Throwable $e) { $parsed['hostid'] = 0; }

        // Grava em ddosguard_integration_events
        try {
            $pdo->prepare("
                INSERT INTO ddosguard_integration_events
                    (platform, src_ip, dst_port, protocol,
                     severity_score, severity_label,
                     category, rule_id, rule_name,
                     mitre_tactic, mitre_technique,
                     description, raw_data, event_time, created_at)
                VALUES ('sophos', :ip, :dp, :proto,
                        :sc, :sl,
                        :cat, :rid, :rn,
                        :tac, :tech,
                        :desc, :raw, NOW(), NOW())
            ")->execute([
                ':ip'   => $parsed['src_ip'],
                ':dp'   => $parsed['target_port'],
                ':proto'=> $parsed['protocol'],
                ':sc'   => $parsed['severity_code'],
                ':sl'   => score_to_label($parsed['severity_code']),
                ':cat'  => $parsed['attack_type'],
                ':rid'  => $parsed['rule_id']   ?? null,
                ':rn'   => $parsed['rule_name'] ?? null,
                ':tac'  => $parsed['mitre_tactic'] ?? null,
                ':tech' => $parsed['mitre_tech']   ?? null,
                ':desc' => $parsed['message']  ?? null,
                ':raw'  => $parsed['raw'],
            ]);
        } catch (Throwable $e) {}

        // Grava ataque ou bloqueio
        $et = $parsed['event_type'];
        if (in_array($et, ['block_firewall', 'block_antivirus'])) {
            try {
                $pdo->prepare("
                    INSERT INTO ddosguard_blocks
                        (hostid, src_ip, country_code, block_source, tool,
                         target_port, protocol, reason, raw_data,
                         event_time, created_at)
                    VALUES (:hid, :ip, :cc, :bs, :tool,
                            :port, :proto, :reason, :raw,
                            NOW(), NOW())
                ")->execute([
                    ':hid'    => $parsed['hostid'],
                    ':ip'     => $parsed['src_ip'],
                    ':cc'     => $parsed['country'] ?? null,
                    ':bs'     => $et === 'block_antivirus' ? 'antivirus' : 'firewall',
                    ':tool'   => $parsed['tool'],
                    ':port'   => $parsed['target_port'],
                    ':proto'  => $parsed['protocol'],
                    ':reason' => $parsed['attack_type'],
                    ':raw'    => $parsed['raw'],
                ]);
            } catch (Throwable $e) {}
        } else {
            try {
                $pdo->prepare("
                    INSERT INTO ddosguard_attacks
                        (hostid, src_ip, country_code, attack_type,
                         target_port, protocol, attempts,
                         severity, blocked, source_tool,
                         severity_score, severity_label,
                         mitre_tactic, mitre_technique,
                         raw_data, first_seen, last_seen, created_at)
                    VALUES (:hid, :ip, :cc, :at,
                            :port, :proto, 1,
                            2, :blocked, :tool,
                            :sc, :sl,
                            :tac, :tech,
                            :raw, NOW(), NOW(), NOW())
                ")->execute([
                    ':hid'     => $parsed['hostid'],
                    ':ip'      => $parsed['src_ip'],
                    ':cc'      => $parsed['country'] ?? null,
                    ':at'      => $parsed['attack_type'],
                    ':port'    => $parsed['target_port'],
                    ':proto'   => $parsed['protocol'],
                    ':blocked' => $parsed['blocked'] ? 1 : 0,
                    ':tool'    => $parsed['tool'],
                    ':sc'      => $parsed['severity_code'],
                    ':sl'      => score_to_label($parsed['severity_code']),
                    ':tac'     => $parsed['mitre_tactic'] ?? null,
                    ':tech'    => $parsed['mitre_tech']   ?? null,
                    ':raw'     => $parsed['raw'],
                ]);
            } catch (Throwable $e) {}
        }

        // Envia ao Zabbix via zabbix_sender
        $zbx_host = $parsed['zbx_host'];
        $items = [];

        if ($et === 'block_firewall') {
            $items['ddosguard.firewall.rate']  = 1;
            $items['ddosguard.block.firewall'] = json_encode([
                'src_ip'      => $parsed['src_ip'],
                'country'     => $parsed['country'] ?? null,
                'tool'        => $parsed['tool'],
                'target_port' => $parsed['target_port'],
                'protocol'    => $parsed['protocol'],
                'reason'      => $parsed['attack_type'],
                'log_type'    => $parsed['log_type']    ?? null,
                'log_subtype' => $parsed['log_subtype'] ?? null,
            ], JSON_UNESCAPED_UNICODE);
        } elseif ($et === 'block_antivirus') {
            $items['ddosguard.antivirus.rate']  = 1;
            $items['ddosguard.block.antivirus'] = json_encode([
                'src_ip'   => $parsed['src_ip'],
                'tool'     => $parsed['tool'],
                'category' => $parsed['attack_type'],
                'message'  => $parsed['message'] ?? null,
                'mitre'    => $parsed['mitre_tech'] ?? null,
            ], JSON_UNESCAPED_UNICODE);
        } else {
            $items['ddosguard.attacks.rate']  = 1;
            $items['ddosguard.attack.event']  = json_encode([
                'src_ip'      => $parsed['src_ip'],
                'country'     => $parsed['country'] ?? null,
                'attack_type' => $parsed['attack_type'],
                'target_port' => $parsed['target_port'],
                'protocol'    => $parsed['protocol'],
                'severity'    => $parsed['severity_code'],
                'mitre_tactic'=> $parsed['mitre_tactic'] ?? null,
                'mitre_tech'  => $parsed['mitre_tech']   ?? null,
                'message'     => $parsed['message'] ?? null,
            ], JSON_UNESCAPED_UNICODE);
        }

        // ATP — ameaça crítica, item dedicado
        if ($parsed['attack_type'] === 'C2_COMMUNICATION') {
            $items['ddosguard.sophos.atp'] = json_encode([
                'src_ip'  => $parsed['src_ip'],
                'message' => $parsed['message'] ?? 'ATP Detection',
            ], JSON_UNESCAPED_UNICODE);
        }

        zabbix_send_sophos(
            $ZBX_SENDER_BIN, $ZBX_SERVER, $ZBX_PORT, $zbx_host, $items
        );
        $processed++;

    } catch (Throwable $e) {
        if ($is_http) error_log("DG Sophos: " . $e->getMessage());
    }
}

if ($is_http) {
    echo json_encode(['ok' => true, 'processed' => $processed]);
}

// ── Helper ───────────────────────────────────────────────────────────────────
function score_to_label(int $score): string
{
    if ($score >= 9) return 'critical';
    if ($score >= 7) return 'high';
    if ($score >= 5) return 'medium';
    if ($score >= 3) return 'low';
    return 'info';
}
