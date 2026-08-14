<?php
/**
 * DDoS Guard - Integração Wazuh
 * ==============================
 * Recebe alertas do Wazuh e encaminha para o ingest.php.
 *
 * CONFIGURAÇÃO NO WAZUH:
 *
 * 1. Edite /var/ossec/etc/ossec.conf e adicione:
 *    <integration>
 *      <name>custom-ddosguard</name>
 *      <hook_url>http://SEU_ZABBIX/ddosguard/integrations/wazuh_receiver.php</hook_url>
 *      <api_key>SEU_TOKEN_DDOSGUARD</api_key>
 *      <level>3</level>
 *      <alert_format>json</alert_format>
 *    </integration>
 *
 * 2. Crie o script de integração em /var/ossec/integrations/custom-ddosguard:
 *    #!/usr/bin/env python3
 *    import sys, json, urllib.request
 *    alert = json.loads(open(sys.argv[1]).read())
 *    token = sys.argv[2]
 *    url   = sys.argv[3]
 *    req = urllib.request.Request(url,
 *        data=json.dumps(alert).encode(),
 *        headers={'Content-Type':'application/json','X-DG-Token':token},
 *        method='POST')
 *    urllib.request.urlopen(req, timeout=5)
 *
 * 3. Reinicie o Wazuh: systemctl restart wazuh-manager
 *
 * ALTERNATIVA — Syslog (Wazuh → rsyslog → este endpoint):
 *   Configure o Wazuh para enviar syslog e use syslog_parser.php
 */

// Declara que o ingest.php deve se comportar como biblioteca: sem isso o
// require abaixo executa o endpoint HTTP e encerra o processo com
// "invalid token" antes de qualquer linha ser processada.
define('DG_INGEST_LIB', true);

require_once dirname(__DIR__) . '/ingest.php';   // carrega helpers (db_connect, respond, etc)

// Valida token
$token = $_SERVER['HTTP_X_DG_TOKEN'] ?? ($_GET['token'] ?? '');
if (!hash_equals($INGEST_TOKEN, (string) $token)) {
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'unauthorized']);
    exit;
}

// Lê o payload do Wazuh
$raw = file_get_contents('php://input');
$alert = json_decode($raw, true);
if (!$alert) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'invalid json']);
    exit;
}

// Normaliza o alerta do Wazuh para o formato do DDoS Guard
$normalized = wazuh_normalize($alert);
if (!$normalized) {
    echo json_encode(['ok' => true, 'skipped' => true]);
    exit;
}

// Grava no banco
try {
    $pdo = db_connect($DB_DRIVER, $DB_HOST, $DB_PORT, $DB_NAME, $DB_USER, $DB_PASS);
    insert_integration_event($pdo, 'wazuh', $alert, $normalized);

    // Encaminha para o correlator
    require_once dirname(__DIR__) . '/correlator.php';
    DDoSCorrelator::process($pdo, $normalized, $normalized['zbx_host'], [
        'ZBX_SENDER_BIN' => $ZBX_SENDER_BIN,
        'ZBX_SERVER'     => $ZBX_SERVER,
        'ZBX_PORT'       => $ZBX_PORT,
    ]);

    // Envia ao Zabbix
    send_to_zabbix($ZBX_SENDER_BIN, $ZBX_SERVER, $ZBX_PORT, $normalized['zbx_host'], [
        'ddosguard.attacks.rate'  => 1,
        'ddosguard.attack.event'  => json_encode($normalized, JSON_UNESCAPED_UNICODE),
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
    exit;
}

echo json_encode(['ok' => true]);

// ----------------------------------------------------------------
// Normaliza alerta Wazuh → formato DDoS Guard
// ----------------------------------------------------------------
function wazuh_normalize(array $alert): ?array
{
    // Extrai campos principais do alerta Wazuh
    $rule_level = (int) ($alert['rule']['level'] ?? 0);
    $rule_id    = $alert['rule']['id'] ?? '';
    $rule_desc  = $alert['rule']['description'] ?? '';
    $rule_groups= $alert['rule']['groups'] ?? [];
    $agent_name = $alert['agent']['name'] ?? '';
    $agent_ip   = $alert['agent']['ip'] ?? '';
    $src_ip     = $alert['data']['srcip'] ?? ($alert['data']['src_ip'] ?? null);
    $timestamp  = $alert['timestamp'] ?? date('c');

    // Ignora alertas de baixo nível (< 3) ou sem IP de origem
    if ($rule_level < 3 || empty($src_ip)) {
        return null;
    }

    // Mapeia grupos do Wazuh para tipos de ataque do DDoS Guard
    $attack_type = 'SUSPICIOUS_TRAFFIC';
    $groups_str  = implode(',', $rule_groups);
    if (str_contains($groups_str, 'authentication_failed') ||
        str_contains($groups_str, 'brute_force')) {
        $attack_type = 'BRUTE_FORCE_SSH';
    } elseif (str_contains($groups_str, 'web_attack') ||
              str_contains($groups_str, 'sql_injection')) {
        $attack_type = 'SQL_INJECTION';
    } elseif (str_contains($groups_str, 'malware') ||
              str_contains($groups_str, 'trojan')) {
        $attack_type = 'MALWARE';
    } elseif (str_contains($groups_str, 'rootkit') ||
              str_contains($groups_str, 'exploit')) {
        $attack_type = 'EXPLOIT';
    } elseif (str_contains($groups_str, 'scan')) {
        $attack_type = 'PORT_SCAN';
    }

    // Converte nível Wazuh (1-15) para score DDoS Guard (1-10)
    $severity_score = (int) round($rule_level * 10 / 15);

    return [
        'event_type'    => 'attack',
        'zbx_host'      => $agent_name,
        'hostid'        => 0,
        'src_ip'        => $src_ip,
        'attack_type'   => $attack_type,
        'attempts'      => 1,
        'severity_code' => $severity_score,
        'blocked'       => false,
        'source'        => 'wazuh',
        'platform'      => 'wazuh',
        'rule_id'       => $rule_id,
        'rule_name'     => $rule_desc,
        'timestamp'     => strtotime($timestamp),
        'wazuh_level'   => $rule_level,
        'wazuh_groups'  => $rule_groups,
        'agent_ip'      => $agent_ip,
    ];
}

function insert_integration_event(PDO $pdo, string $platform, array $raw, array $norm): void
{
    try {
        $pdo->prepare("
            INSERT INTO ddosguard_integration_events
                (platform, hostid, src_ip, severity_score, severity_label,
                 category, rule_id, rule_name, description, raw_data,
                 event_time, created_at)
            VALUES
                (:platform, :hostid, :ip, :score, :label,
                 :category, :rule_id, :rule_name, :desc, :raw,
                 NOW(), NOW())
        ")->execute([
            ':platform'  => $platform,
            ':hostid'    => $norm['hostid'] ?? 0,
            ':ip'        => $norm['src_ip'] ?? null,
            ':score'     => $norm['severity_code'] ?? 1,
            ':label'     => DDoSCorrelator::scoreToLabel($norm['severity_code'] ?? 1),
            ':category'  => $norm['attack_type'] ?? null,
            ':rule_id'   => $norm['rule_id'] ?? null,
            ':rule_name' => $norm['rule_name'] ?? null,
            ':desc'      => $norm['rule_name'] ?? null,
            ':raw'       => json_encode($raw, JSON_UNESCAPED_UNICODE),
        ]);
    } catch (Throwable $e) {
        // Tabela não existe ainda (migration não executada)
    }
}
