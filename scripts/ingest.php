<?php
/**
 * DDoS Guard - Ingest API
 * =======================
 * Pequeno endpoint HTTP (PHP embutido, sem framework) que recebe os
 * eventos do coletor (ddos_guard_agent.py) e:
 *
 *   - Grava o evento detalhado nas tabelas auxiliares do módulo
 *     (ddosguard_attacks / ddosguard_blocks / ddosguard_host_status),
 *     que são lidas pelos widgets do dashboard.
 *
 *   - Repassa os contadores agregados para o Zabbix via zabbix_sender
 *     (itens trapper do template "DDoS Guard - Security Monitoring"),
 *     para que triggers/alertas nativos do Zabbix funcionem.
 *
 * Não depende de nenhuma classe interna do Zabbix — pode rodar como um
 * serviço PHP simples (php -S ou atrás do mesmo Apache/Nginx do
 * frontend do Zabbix, em /usr/share/zabbix/ddosguard/ingest.php).
 *
 * Configuração: edite as constantes abaixo ou exporte variáveis de
 * ambiente DG_DB_*, DG_ZBX_SERVER, DG_ZBX_PORT, DG_INGEST_TOKEN.
 */

declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');

// ---------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------
$DB_HOST   = getenv('DG_DB_HOST')   ?: '127.0.0.1';
$DB_PORT   = getenv('DG_DB_PORT')   ?: '3306';
$DB_NAME   = getenv('DG_DB_NAME')   ?: 'zabbix';
$DB_USER   = getenv('DG_DB_USER')   ?: 'zabbix';
$DB_PASS   = getenv('DG_DB_PASS')   ?: 'zabbix';
$DB_DRIVER = getenv('DG_DB_DRIVER') ?: 'mysql'; // mysql | pgsql

$ZBX_SENDER_BIN = getenv('DG_ZABBIX_SENDER_BIN') ?: '/usr/bin/zabbix_sender';
$ZBX_SERVER     = getenv('DG_ZBX_SERVER') ?: '127.0.0.1';
$ZBX_PORT       = getenv('DG_ZBX_PORT')   ?: '10051';

// Token simples para autenticar o agente (defina o mesmo valor no
// ddos_guard_agent.py / ddos_guard_agent.conf).
$INGEST_TOKEN = getenv('DG_INGEST_TOKEN') ?: 'CHANGE_ME_TOKEN';

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------
function respond(int $code, array $payload): void {
    http_response_code($code);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

function db_connect(string $driver, string $host, string $port, string $name, string $user, string $pass): PDO {
    if ($driver === 'pgsql') {
        $dsn = "pgsql:host=$host;port=$port;dbname=$name";
    } else {
        $dsn = "mysql:host=$host;port=$port;dbname=$name;charset=utf8mb4";
    }
    return new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
}

/**
 * Envia um par host-key-value para o Zabbix trapper via zabbix_sender CLI.
 * Usa o binário em vez de reimplementar o protocolo, para evitar
 * dependências extras (sockets binários do protocolo Zabbix).
 */
function send_to_zabbix(string $bin, string $server, string $port, string $hostname, array $kv): void {
    if (!is_executable($bin) || !$kv) {
        return;
    }
    $lines = [];
    foreach ($kv as $key => $value) {
        // formato: <host> <key> <value>
        $lines[] = sprintf('%s %s %s', $hostname, $key, $value);
    }
    $input = implode("\n", $lines) . "\n";

    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $cmd = sprintf('%s -z %s -p %s -i -',
        escapeshellcmd($bin), escapeshellarg($server), escapeshellarg($port)
    );
    $proc = proc_open($cmd, $descriptors, $pipes);
    if (is_resource($proc)) {
        fwrite($pipes[0], $input);
        fclose($pipes[0]);
        stream_get_contents($pipes[1]);
        stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($proc);
    }
}

// ---------------------------------------------------------------------
// Autenticação simples por token (header X-DG-Token)
// ---------------------------------------------------------------------
$headers = function_exists('getallheaders') ? getallheaders() : [];
$token = $headers['X-Dg-Token'] ?? $headers['X-DG-Token'] ?? ($_SERVER['HTTP_X_DG_TOKEN'] ?? '');
if (!hash_equals($INGEST_TOKEN, (string) $token)) {
    respond(401, ['ok' => false, 'error' => 'invalid token']);
}

$raw = file_get_contents('php://input');
$payload = json_decode($raw, true);
if (!is_array($payload)) {
    respond(400, ['ok' => false, 'error' => 'invalid json body']);
}

$event_type = $payload['event_type'] ?? null; // attack | block_firewall | block_antivirus | heartbeat | status
$hostname   = $payload['zbx_host'] ?? null;   // nome do host EXATO como cadastrado no Zabbix
$hostid     = isset($payload['hostid']) ? (int) $payload['hostid'] : 0;

if (!$event_type || !$hostname) {
    respond(400, ['ok' => false, 'error' => 'event_type and zbx_host are required']);
}

try {
    $pdo = db_connect($DB_DRIVER, $DB_HOST, $DB_PORT, $DB_NAME, $DB_USER, $DB_PASS);
} catch (Throwable $e) {
    respond(500, ['ok' => false, 'error' => 'db connection failed: ' . $e->getMessage()]);
}

$now = date('Y-m-d H:i:s');

switch ($event_type) {

    case 'attack':
        $stmt = $pdo->prepare("INSERT INTO ddosguard_attacks
            (hostid, src_ip, country_code, country_name, city, asn, attack_type,
             target_port, protocol, attempts, severity, blocked, blocked_by,
             source_tool, raw_data, first_seen, last_seen, created_at)
            VALUES (:hostid,:src_ip,:country_code,:country_name,:city,:asn,:attack_type,
             :target_port,:protocol,:attempts,:severity,:blocked,:blocked_by,
             :source_tool,:raw_data,:first_seen,:last_seen,:created_at)");
        $stmt->execute([
            ':hostid'       => $hostid,
            ':src_ip'       => $payload['src_ip'] ?? '',
            ':country_code' => $payload['country'] ?? null,
            ':country_name' => $payload['country_name'] ?? null,
            ':city'         => $payload['city'] ?? null,
            ':asn'          => $payload['asn'] ?? null,
            ':attack_type'  => $payload['attack_type'] ?? 'UNKNOWN',
            ':target_port'  => $payload['target_port'] ?? null,
            ':protocol'     => $payload['protocol'] ?? null,
            ':attempts'     => $payload['attempts'] ?? 1,
            ':severity'     => $payload['severity_code'] ?? 2,
            ':blocked'      => !empty($payload['blocked']) ? 1 : 0,
            ':blocked_by'   => $payload['blocked_by'] ?? null,
            ':source_tool'  => $payload['source'] ?? null,
            ':raw_data'     => json_encode($payload, JSON_UNESCAPED_UNICODE),
            ':first_seen'   => isset($payload['first_seen']) ? date('Y-m-d H:i:s', (int) $payload['first_seen']) : $now,
            ':last_seen'    => isset($payload['last_seen']) ? date('Y-m-d H:i:s', (int) $payload['last_seen']) : $now,
            ':created_at'   => $now,
        ]);

        send_to_zabbix($ZBX_SENDER_BIN, $ZBX_SERVER, $ZBX_PORT, $hostname, [
            'ddosguard.attacks.rate' => $payload['attempts'] ?? 1,
        ]);
        respond(200, ['ok' => true]);
        break;

    case 'block_firewall':
        $stmt = $pdo->prepare("INSERT INTO ddosguard_blocks
            (hostid, src_ip, country_code, country_name, block_source, tool,
             rule_or_signature, target_port, protocol, reason, raw_data, event_time, created_at)
            VALUES (:hostid,:src_ip,:country_code,:country_name,'firewall',:tool,
             :rule,:target_port,:protocol,:reason,:raw_data,:event_time,:created_at)");
        $stmt->execute([
            ':hostid'       => $hostid,
            ':src_ip'       => $payload['src_ip'] ?? '',
            ':country_code' => $payload['country'] ?? null,
            ':country_name' => $payload['country_name'] ?? null,
            ':tool'         => $payload['tool'] ?? null,
            ':rule'         => $payload['rule'] ?? null,
            ':target_port'  => $payload['target_port'] ?? null,
            ':protocol'     => $payload['protocol'] ?? null,
            ':reason'       => $payload['reason'] ?? null,
            ':raw_data'     => json_encode($payload, JSON_UNESCAPED_UNICODE),
            ':event_time'   => isset($payload['timestamp']) ? date('Y-m-d H:i:s', (int) $payload['timestamp']) : $now,
            ':created_at'   => $now,
        ]);

        send_to_zabbix($ZBX_SENDER_BIN, $ZBX_SERVER, $ZBX_PORT, $hostname, [
            'ddosguard.firewall.rate' => 1,
        ]);
        respond(200, ['ok' => true]);
        break;

    case 'block_antivirus':
        $stmt = $pdo->prepare("INSERT INTO ddosguard_blocks
            (hostid, src_ip, country_code, country_name, block_source, tool,
             rule_or_signature, reason, file_path, raw_data, event_time, created_at)
            VALUES (:hostid,:src_ip,:country_code,:country_name,'antivirus',:tool,
             :sig,:reason,:file_path,:raw_data,:event_time,:created_at)");
        $stmt->execute([
            ':hostid'       => $hostid,
            ':src_ip'       => $payload['src_ip'] ?? '',
            ':country_code' => $payload['country'] ?? null,
            ':country_name' => $payload['country_name'] ?? null,
            ':tool'         => $payload['tool'] ?? 'clamav',
            ':sig'          => $payload['malware'] ?? null,
            ':reason'       => $payload['action'] ?? 'quarantined',
            ':file_path'    => $payload['file'] ?? null,
            ':raw_data'     => json_encode($payload, JSON_UNESCAPED_UNICODE),
            ':event_time'   => isset($payload['timestamp']) ? date('Y-m-d H:i:s', (int) $payload['timestamp']) : $now,
            ':created_at'   => $now,
        ]);

        send_to_zabbix($ZBX_SENDER_BIN, $ZBX_SERVER, $ZBX_PORT, $hostname, [
            'ddosguard.antivirus.rate' => 1,
        ]);
        respond(200, ['ok' => true]);
        break;

    case 'status':
        // Atualiza se o host possui firewall/antivírus ativo (mostrado no painel).
        $stmt = $pdo->prepare("INSERT INTO ddosguard_host_status
            (hostid, has_firewall, firewall_name, has_antivirus, antivirus_name, last_heartbeat, updated_at)
            VALUES (:hostid,:hf,:fwname,:ha,:avname,:hb,:now)
            ON DUPLICATE KEY UPDATE
                has_firewall=:hf2, firewall_name=:fwname2,
                has_antivirus=:ha2, antivirus_name=:avname2,
                last_heartbeat=:hb2, updated_at=:now2");
        // Nota: para PostgreSQL troque por "ON CONFLICT (hostid) DO UPDATE SET ...".
        $stmt->execute([
            ':hostid' => $hostid,
            ':hf' => !empty($payload['has_firewall']) ? 1 : 0,
            ':fwname' => $payload['firewall_name'] ?? null,
            ':ha' => !empty($payload['has_antivirus']) ? 1 : 0,
            ':avname' => $payload['antivirus_name'] ?? null,
            ':hb' => $now,
            ':now' => $now,
            ':hf2' => !empty($payload['has_firewall']) ? 1 : 0,
            ':fwname2' => $payload['firewall_name'] ?? null,
            ':ha2' => !empty($payload['has_antivirus']) ? 1 : 0,
            ':avname2' => $payload['antivirus_name'] ?? null,
            ':hb2' => $now,
            ':now2' => $now,
        ]);
        respond(200, ['ok' => true]);
        break;

    case 'heartbeat':
        $kv = ['ddosguard.agent.heartbeat' => 1];
        if (isset($payload['distinct_ips'])) {
            $kv['ddosguard.distinct_ips.rate'] = (int) $payload['distinct_ips'];
        }
        send_to_zabbix($ZBX_SENDER_BIN, $ZBX_SERVER, $ZBX_PORT, $hostname, $kv);
        respond(200, ['ok' => true]);
        break;

    default:
        respond(400, ['ok' => false, 'error' => 'unknown event_type']);
}
