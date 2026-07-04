<?php
/**
 * DDoS Guard - Receiver Syslog Universal
 * ========================================
 * Recebe logs via syslog (UDP/TCP) de pfSense, FortiGate e outros firewalls.
 * Detecta automaticamente o formato e normaliza para o DDoS Guard.
 *
 * CONFIGURAÇÃO — pfSense:
 *   Status > System Logs > Settings > Remote Logging
 *   Remote log servers: IP_DO_ZABBIX:514
 *   Remote syslog contents: Firewall Events
 *
 * CONFIGURAÇÃO — FortiGate:
 *   config log syslogd setting
 *     set status enable
 *     set server IP_DO_ZABBIX
 *     set port 514
 *     set format default
 *     set facility local7
 *   end
 *
 * CONFIGURAÇÃO — rsyslog no appliance Zabbix:
 *   Adicione em /etc/rsyslog.d/ddosguard.conf:
 *   module(load="imudp")
 *   input(type="imudp" port="514")
 *   if $fromhost-ip == "IP_DO_PFSENSE" or $fromhost-ip == "IP_DO_FORTIGATE" then {
 *       action(type="omprog"
 *           binary="/usr/bin/php /caminho/syslog_receiver.php"
 *           template="RSYSLOG_TraditionalForwardFormat")
 *   }
 *
 * ALTERNATIVA — Endpoint HTTP (para forwarders como Filebeat/Logstash):
 *   Configure Filebeat/Logstash para enviar via HTTP POST para este script.
 *   O script aceita tanto POST HTTP quanto stdin (para omprog do rsyslog).
 */

require_once dirname(__DIR__) . '/ingest.php';
require_once dirname(__DIR__) . '/correlator.php';

// Detecta modo de operação: HTTP ou stdin (rsyslog omprog)
$is_http = (PHP_SAPI === 'fpm-fcgi' || PHP_SAPI === 'apache2handler' || isset($_SERVER['HTTP_HOST']));

if ($is_http) {
    // Modo HTTP: valida token
    $token = $_SERVER['HTTP_X_DG_TOKEN'] ?? '';
    if ($token !== $INGEST_TOKEN) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'unauthorized']);
        exit;
    }
    $lines = [file_get_contents('php://input')];
} else {
    // Modo stdin: lê linhas do rsyslog omprog
    $lines = [];
    while (($line = fgets(STDIN)) !== false) {
        $lines[] = trim($line);
    }
}

$processed = 0;
foreach ($lines as $line) {
    if (empty($line)) continue;

    // Detecta plataforma pelo formato
    $platform   = detect_platform($line);
    $normalized = null;

    switch ($platform) {
        case 'pfsense':
            $normalized = parse_pfsense($line);
            break;
        case 'fortigate':
            $normalized = parse_fortigate($line);
            break;
        default:
            $normalized = parse_generic_firewall($line);
    }

    if (!$normalized || empty($normalized['src_ip'])) continue;

    try {
        $pdo = db_connect($DB_DRIVER, $DB_HOST, $DB_PORT, $DB_NAME, $DB_USER, $DB_PASS);

        // Grava evento de integração
        try {
            $pdo->prepare("
                INSERT INTO ddosguard_integration_events
                    (platform, src_ip, dst_port, protocol, severity_score, severity_label,
                     category, rule_id, rule_name, raw_data, event_time, created_at)
                VALUES (:p, :ip, :dp, :proto, :sc, :sl, :cat, :rid, :rn, :raw, NOW(), NOW())
            ")->execute([
                ':p'    => $platform,
                ':ip'   => $normalized['src_ip'],
                ':dp'   => $normalized['target_port'] ?? null,
                ':proto'=> $normalized['protocol'] ?? null,
                ':sc'   => $normalized['severity_code'] ?? 3,
                ':sl'   => DDoSCorrelator::scoreToLabel($normalized['severity_code'] ?? 3),
                ':cat'  => $normalized['attack_type'] ?? null,
                ':rid'  => $normalized['rule_id'] ?? null,
                ':rn'   => $normalized['rule_name'] ?? null,
                ':raw'  => $line,
            ]);
        } catch (Throwable $e) {}

        // Grava bloqueio
        $pdo->prepare("
            INSERT INTO ddosguard_blocks
                (hostid, src_ip, block_source, tool, rule_or_signature,
                 target_port, protocol, reason, raw_data, event_time, created_at)
            VALUES (0, :ip, 'firewall', :tool, :rule, :port, :proto, :reason, :raw, NOW(), NOW())
        ")->execute([
            ':ip'     => $normalized['src_ip'],
            ':tool'   => $platform,
            ':rule'   => $normalized['rule_id'] ?? null,
            ':port'   => $normalized['target_port'] ?? null,
            ':proto'  => $normalized['protocol'] ?? null,
            ':reason' => $normalized['attack_type'] ?? 'BLOCK',
            ':raw'    => $line,
        ]);

        // Correlaciona
        DDoSCorrelator::process($pdo, $normalized, $normalized['zbx_host'], [
            'ZBX_SENDER_BIN' => $ZBX_SENDER_BIN,
            'ZBX_SERVER'     => $ZBX_SERVER,
            'ZBX_PORT'       => $ZBX_PORT,
        ]);

        $host = $normalized['zbx_host'];
        send_to_zabbix($ZBX_SENDER_BIN, $ZBX_SERVER, $ZBX_PORT, $host, [
            'ddosguard.firewall.rate'  => 1,
            'ddosguard.block.firewall' => json_encode($normalized, JSON_UNESCAPED_UNICODE),
        ]);
        $processed++;
    } catch (Throwable $e) {
        if ($is_http) error_log("DDoS Guard syslog_receiver: " . $e->getMessage());
    }
}

if ($is_http) echo json_encode(['ok' => true, 'processed' => $processed]);

// ----------------------------------------------------------------
// Detecta plataforma pelo formato da linha de syslog
// ----------------------------------------------------------------
function detect_platform(string $line): string
{
    // FortiGate: tem campos chave=valor com devname= ou logid=
    if (preg_match('/devname=\S+|logid=\d{10}/', $line)) return 'fortigate';
    // pfSense: tem formato filterlog ou pf com campos separados por vírgula
    if (str_contains($line, 'filterlog:') || str_contains($line, 'pf:')) return 'pfsense';
    return 'generic';
}

// ----------------------------------------------------------------
// Parser pfSense (filterlog)
// ----------------------------------------------------------------
function parse_pfsense(string $line): ?array
{
    // Formato pfSense filterlog:
    // <timestamp> <hostname> filterlog: <regra>,<interface>,<reason>,<action>,
    //   <direction>,<ip_version>,<tos>,...,<proto>,<src_ip>,<dst_ip>,<src_port>,<dst_port>
    if (!preg_match('/filterlog:\s+(.+)/', $line, $m)) return null;

    $fields = explode(',', $m[1]);
    if (count($fields) < 15) return null;

    $action   = $fields[3] ?? '';
    $src_ip   = $fields[count($fields) - 4] ?? null;
    $dst_ip   = $fields[count($fields) - 3] ?? null;
    $src_port = (int) ($fields[count($fields) - 2] ?? 0);
    $dst_port = (int) ($fields[count($fields) - 1] ?? 0);
    $proto    = strtoupper($fields[9] ?? 'TCP');

    if (empty($src_ip) || !in_array(strtolower($action), ['block', 'drop', 'reject'])) {
        return null;
    }

    return [
        'event_type'   => 'block_firewall',
        'zbx_host'     => gethostname(),
        'hostid'       => 0,
        'src_ip'       => $src_ip,
        'attack_type'  => 'SUSPICIOUS_TRAFFIC',
        'target_port'  => $dst_port ?: null,
        'protocol'     => $proto,
        'severity_code'=> 4,
        'blocked'      => true,
        'source'       => 'pfsense',
        'platform'     => 'pfsense',
        'rule_id'      => $fields[0] ?? null,
    ];
}

// ----------------------------------------------------------------
// Parser FortiGate (CEF / formato chave=valor)
// ----------------------------------------------------------------
function parse_fortigate(string $line): ?array
{
    // Extrai todos os campos chave=valor do FortiGate
    preg_match_all('/(\w+)="?([^"=]+)"?(?=\s+\w+=|\s*$)/', $line, $matches, PREG_SET_ORDER);
    $f = [];
    foreach ($matches as $m) {
        $f[$m[1]] = trim($m[2]);
    }

    $action  = strtolower($f['action'] ?? '');
    $src_ip  = $f['srcip'] ?? ($f['src'] ?? null);
    $dst_port= (int) ($f['dstport'] ?? ($f['dst_port'] ?? 0));
    $proto   = strtoupper($f['proto'] ?? ($f['protocol'] ?? 'TCP'));

    if (empty($src_ip)) return null;
    if (!in_array($action, ['block', 'deny', 'drop', 'reject', 'quarantine'])) return null;

    // Mapeia tipo de log FortiGate → attack_type
    $logid   = $f['logid'] ?? '';
    $attack_type = 'SUSPICIOUS_TRAFFIC';
    if (!empty($f['virus']) || str_starts_with($logid, '0211')) {
        $attack_type = 'MALWARE';
    } elseif (!empty($f['attack']) || str_starts_with($logid, '0419')) {
        $attack_type = 'EXPLOIT';
    } elseif (str_starts_with($logid, '0317')) {
        $attack_type = 'SYN_FLOOD';
    } elseif (!empty($f['botnet_c&c']) || str_starts_with($logid, '1059')) {
        $attack_type = 'C2_COMMUNICATION';
    }

    $severity_score = match (strtolower($f['severity'] ?? 'medium')) {
        'critical' => 9,
        'high'     => 7,
        'medium'   => 5,
        'low'      => 3,
        default    => 3,
    };

    return [
        'event_type'   => 'block_firewall',
        'zbx_host'     => $f['devname'] ?? gethostname(),
        'hostid'       => 0,
        'src_ip'       => $src_ip,
        'attack_type'  => $attack_type,
        'target_port'  => $dst_port ?: null,
        'protocol'     => $proto,
        'severity_code'=> $severity_score,
        'blocked'      => true,
        'source'       => 'fortigate',
        'platform'     => 'fortigate',
        'rule_id'      => $f['policyid'] ?? $logid,
        'rule_name'    => $f['policyname'] ?? ($f['msg'] ?? null),
        'country'      => $f['srccountry'] ?? null,
    ];
}

// ----------------------------------------------------------------
// Parser genérico (iptables, nftables, outros)
// ----------------------------------------------------------------
function parse_generic_firewall(string $line): ?array
{
    // Extrai SRC= e DPT= do formato iptables/nftables
    if (!preg_match('/SRC=(\d+\.\d+\.\d+\.\d+)/', $line, $sm)) return null;
    preg_match('/DPT=(\d+)/', $line, $dm);
    preg_match('/PROTO=(\w+)/', $line, $pm);

    $action = (str_contains($line, 'DROP') || str_contains($line, 'BLOCK') ||
               str_contains($line, 'REJECT')) ? 'block' : 'allow';
    if ($action !== 'block') return null;

    return [
        'event_type'   => 'block_firewall',
        'zbx_host'     => gethostname(),
        'hostid'       => 0,
        'src_ip'       => $sm[1],
        'attack_type'  => 'SUSPICIOUS_TRAFFIC',
        'target_port'  => isset($dm[1]) ? (int)$dm[1] : null,
        'protocol'     => isset($pm[1]) ? strtoupper($pm[1]) : 'TCP',
        'severity_code'=> 3,
        'blocked'      => true,
        'source'       => 'generic',
        'platform'     => 'generic',
    ];
}
