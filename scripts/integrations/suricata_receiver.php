<?php
/**
 * DDoS Guard - Integração Suricata
 * =================================
 * Recebe eventos do Suricata (eve.json) e encaminha ao DDoS Guard.
 *
 * CONFIGURAÇÃO NO SURICATA:
 *
 * 1. Configure o eve.json em /etc/suricata/suricata.yaml:
 *    outputs:
 *      - eve-log:
 *          enabled: yes
 *          filetype: regular
 *          filename: /var/log/suricata/eve.json
 *          types:
 *            - alert
 *            - flow
 *            - drop
 *
 * 2. Use o filebeat ou um script Python para enviar eventos:
 *    #!/usr/bin/env python3
 *    # suricata_forwarder.py
 *    import json, time, urllib.request
 *    INGEST_URL = 'http://SEU_ZABBIX/ddosguard/integrations/suricata_receiver.php'
 *    TOKEN      = 'SEU_TOKEN'
 *    EVE_LOG    = '/var/log/suricata/eve.json'
 *
 *    with open(EVE_LOG) as f:
 *        f.seek(0, 2)  # vai para o final
 *        while True:
 *            line = f.readline()
 *            if line:
 *                req = urllib.request.Request(INGEST_URL,
 *                    data=line.encode(),
 *                    headers={'Content-Type':'application/json','X-DG-Token':TOKEN},
 *                    method='POST')
 *                try: urllib.request.urlopen(req, timeout=3)
 *                except: pass
 *            else:
 *                time.sleep(0.5)
 *
 * 3. Ou configure o Suricata para enviar syslog e use syslog_parser.php
 *
 * ALTERNATIVA — Filebeat:
 *   Adicione um output HTTP no filebeat.yml apontando para este endpoint.
 */

// Declara que o ingest.php deve se comportar como biblioteca: sem isso o
// require abaixo executa o endpoint HTTP e encerra o processo com
// "invalid token" antes de qualquer linha ser processada.
define('DG_INGEST_LIB', true);

require_once dirname(__DIR__) . '/ingest.php';
require_once dirname(__DIR__) . '/correlator.php';

// Valida token
$token = $_SERVER['HTTP_X_DG_TOKEN'] ?? '';
if (!hash_equals($INGEST_TOKEN, (string) $token)) {
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'unauthorized']);
    exit;
}

$raw   = file_get_contents('php://input');
$event = json_decode($raw, true);
if (!$event) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'invalid json']);
    exit;
}

$normalized = suricata_normalize($event);
if (!$normalized) {
    echo json_encode(['ok' => true, 'skipped' => true]);
    exit;
}

try {
    $pdo = db_connect($DB_DRIVER, $DB_HOST, $DB_PORT, $DB_NAME, $DB_USER, $DB_PASS);

    // Grava evento de integração
    try {
        $pdo->prepare("
            INSERT INTO ddosguard_integration_events
                (platform, src_ip, dst_port, protocol, severity_score, severity_label,
                 category, rule_id, rule_name, raw_data, event_time, created_at)
            VALUES
                ('suricata', :ip, :dport, :proto, :score, :label,
                 :cat, :rid, :rname, :raw, :etime, NOW())
        ")->execute([
            ':ip'    => $normalized['src_ip'],
            ':dport' => $normalized['target_port'] ?? null,
            ':proto' => $normalized['protocol'] ?? null,
            ':score' => $normalized['severity_code'],
            ':label' => DDoSCorrelator::scoreToLabel($normalized['severity_code']),
            ':cat'   => $normalized['attack_type'],
            ':rid'   => $normalized['rule_id'] ?? null,
            ':rname' => $normalized['rule_name'] ?? null,
            ':raw'   => json_encode($event, JSON_UNESCAPED_UNICODE),
            ':etime' => date('Y-m-d H:i:s', strtotime($event['timestamp'] ?? 'now')),
        ]);
    } catch (Throwable $e) {}

    // Grava em ddosguard_attacks
    $pdo->prepare("
        INSERT INTO ddosguard_attacks
            (hostid, src_ip, country_code, country_name, attack_type,
             target_port, protocol, attempts, severity, blocked,
             source_tool, raw_data, first_seen, last_seen, created_at)
        VALUES
            (:hostid, :ip, :cc, :cn, :atype,
             :port, :proto, 1, :sev, :blocked,
             'suricata', :raw, NOW(), NOW(), NOW())
    ")->execute([
        ':hostid'  => $normalized['hostid'] ?? 0,
        ':ip'      => $normalized['src_ip'],
        ':cc'      => $normalized['country'] ?? null,
        ':cn'      => $normalized['country_name'] ?? null,
        ':atype'   => $normalized['attack_type'],
        ':port'    => $normalized['target_port'] ?? null,
        ':proto'   => $normalized['protocol'] ?? null,
        ':sev'     => $normalized['severity_code'],
        ':blocked' => !empty($event['drop']) ? 1 : 0,
        ':raw'     => json_encode($event, JSON_UNESCAPED_UNICODE),
    ]);

    // Correlaciona
    DDoSCorrelator::process($pdo, $normalized, $normalized['zbx_host'], [
        'ZBX_SENDER_BIN' => $ZBX_SENDER_BIN,
        'ZBX_SERVER'     => $ZBX_SERVER,
        'ZBX_PORT'       => $ZBX_PORT,
    ]);

    // Envia ao Zabbix
    $host = $normalized['zbx_host'];
    send_to_zabbix($ZBX_SENDER_BIN, $ZBX_SERVER, $ZBX_PORT, $host, [
        'ddosguard.attacks.rate' => 1,
        'ddosguard.attack.event' => json_encode($normalized, JSON_UNESCAPED_UNICODE),
    ]);

    if (!empty($event['drop'])) {
        send_to_zabbix($ZBX_SENDER_BIN, $ZBX_SERVER, $ZBX_PORT, $host, [
            'ddosguard.firewall.rate'  => 1,
            'ddosguard.block.firewall' => json_encode($normalized, JSON_UNESCAPED_UNICODE),
        ]);
    }

} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
    exit;
}

echo json_encode(['ok' => true]);

function suricata_normalize(array $event): ?array
{
    $etype = $event['event_type'] ?? '';
    if (!in_array($etype, ['alert', 'drop'])) return null;

    $src_ip  = $event['src_ip']   ?? null;
    $dst_port= $event['dest_port']?? null;
    $proto   = strtoupper($event['proto'] ?? 'TCP');

    if (empty($src_ip)) return null;

    // Mapeia categoria Suricata → tipo DDoS Guard
    $category = strtolower($event['alert']['category'] ?? '');
    $attack_type = 'SUSPICIOUS_TRAFFIC';
    if (str_contains($category, 'brute'))          $attack_type = 'BRUTE_FORCE_SSH';
    elseif (str_contains($category, 'sql'))        $attack_type = 'SQL_INJECTION';
    elseif (str_contains($category, 'exploit'))    $attack_type = 'EXPLOIT';
    elseif (str_contains($category, 'malware') ||
            str_contains($category, 'trojan'))     $attack_type = 'MALWARE';
    elseif (str_contains($category, 'scan'))       $attack_type = 'PORT_SCAN';
    elseif (str_contains($category, 'dos') ||
            str_contains($category, 'flood'))      $attack_type = 'SYN_FLOOD';
    elseif (str_contains($category, 'c2') ||
            str_contains($category, 'botnet'))     $attack_type = 'C2_COMMUNICATION';

    // Severidade: Suricata usa 1(alta)-4(baixa), invertemos
    $suricata_sev = (int) ($event['alert']['severity'] ?? 3);
    $score = match ($suricata_sev) {
        1       => 8,  // Critical
        2       => 6,  // High
        3       => 4,  // Medium
        default => 2,  // Low
    };

    return [
        'event_type'    => 'attack',
        'zbx_host'      => gethostname(),
        'hostid'        => 0,
        'src_ip'        => $src_ip,
        'attack_type'   => $attack_type,
        'target_port'   => $dst_port,
        'protocol'      => $proto,
        'attempts'      => 1,
        'severity_code' => $score,
        'blocked'       => $etype === 'drop',
        'source'        => 'suricata',
        'platform'      => 'suricata',
        'rule_id'       => (string) ($event['alert']['signature_id'] ?? ''),
        'rule_name'     => $event['alert']['signature'] ?? '',
    ];
}
