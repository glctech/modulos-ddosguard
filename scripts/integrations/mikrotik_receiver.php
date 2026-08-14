<?php
/**
 * DDoS Guard - Integração MikroTik (syslog receiver)
 * ====================================================
 * Recebe logs do MikroTik via syslog e normaliza para o DDoS Guard.
 * Detecta automaticamente os prefixos DG-DROP, DG-SCAN, DG-BRUTE
 * e outros formatos de log do RouterOS.
 *
 * CONFIGURACAO NO MIKROTIK (RouterOS 6.x / 7.x):
 *
 * # 1. Define o destino do syslog
 * /system logging action
 *   set [find name=remote] remote=IP_DO_APPLIANCE remote-port=514 target=remote
 *
 * # 2. Habilita topicos de seguranca
 * /system logging
 *   add topics=firewall action=remote
 *   add topics=critical action=remote
 *   add topics=warning action=remote
 *   add topics=interface action=remote
 *
 * # 3. Adiciona regras de firewall com log-prefix para deteccao
 * /ip firewall filter
 *   add chain=input action=log log-prefix="DG-DROP:" \
 *       connection-state=invalid place-before=0
 *   add chain=input action=log log-prefix="DG-BRUTE:" \
 *       protocol=tcp dst-port=22,8291 connection-limit=5,32
 *   add chain=forward action=log log-prefix="DG-SCAN:" \
 *       protocol=tcp tcp-flags=fin,psh,urg,!syn
 *
 * # 4. Verifica se os logs estao chegando no appliance
 * # No appliance: tail -f /var/log/syslog | grep mikrotik
 *
 * CONFIGURACAO DO RSYSLOG (no appliance Zabbix):
 *   Adicione em /etc/rsyslog.d/ddosguard.conf:
 *
 *   module(load="imudp")
 *   input(type="imudp" port="514" ruleset="ddosguard")
 *   ruleset(name="ddosguard") {
 *       action(type="omprog"
 *           binary="/usr/bin/php /caminho/mikrotik_receiver.php"
 *           template="RSYSLOG_TraditionalForwardFormat"
 *           queue.size="10000"
 *           queue.type="linkedList")
 *   }
 *
 * ALTERNATIVA — Pipe via arquivo de log:
 *   Se preferir nao usar omprog, configure rsyslog para gravar os
 *   logs do MikroTik em arquivo e use um script Python para processar.
 */

// Declara que o ingest.php deve se comportar como biblioteca: sem isso o
// require abaixo executa o endpoint HTTP e encerra o processo com
// "invalid token" antes de qualquer linha ser processada.
define('DG_INGEST_LIB', true);

require_once dirname(__DIR__) . '/ingest.php';
require_once dirname(__DIR__) . '/correlator.php';

// Detecta modo: HTTP (POST) ou stdin (rsyslog omprog)
$is_http = (PHP_SAPI === 'fpm-fcgi' || PHP_SAPI === 'apache2handler' || isset($_SERVER['HTTP_HOST']));

if ($is_http) {
    $token = $_SERVER['HTTP_X_DG_TOKEN'] ?? '';
    if (!hash_equals($INGEST_TOKEN, (string) $token)) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'unauthorized']);
        exit;
    }
    $lines = [file_get_contents('php://input')];
} else {
    // Generator, nao array: sob omprog o processo e persistente e o pipe
    // do stdin nunca fecha, entao fgets() nunca retorna false e o foreach
    // abaixo jamais era alcancado. Ver docs/TROUBLESHOOTING.md.
    $lines = (function () {
        while (($line = fgets(STDIN)) !== false) {
            yield trim($line);
        }
    })();
}

$processed = 0;
foreach ($lines as $line) {
    if (empty($line)) continue;

    $normalized = mikrotik_parse($line);
    if (!$normalized || empty($normalized['src_ip'])) continue;

    try {
        $pdo = db_connect($DB_DRIVER, $DB_HOST, $DB_PORT, $DB_NAME, $DB_USER, $DB_PASS);

        // Detecta zbx_host a partir do hostname no syslog
        $zbx_host = $normalized['zbx_host'] ?? gethostname();

        // Busca o hostid no banco pelo zbx_host
        try {
            $stmt = $pdo->prepare("SELECT h.hostid FROM hosts h WHERE h.host = :host AND h.status = 0 LIMIT 1");
            $stmt->execute([':host' => $zbx_host]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $hostid = $row ? (int)$row['hostid'] : 0;
        } catch (Throwable $e) {
            $hostid = 0;
        }
        $normalized['hostid'] = $hostid;

        // Grava evento de integracao
        try {
            $pdo->prepare("
                INSERT INTO ddosguard_integration_events
                    (platform, src_ip, dst_port, protocol, severity_score, severity_label,
                     category, rule_id, rule_name, raw_data, event_time, created_at)
                VALUES ('mikrotik', :ip, :dp, :proto, :sc, :sl, :cat, :rid, :rn, :raw, NOW(), NOW())
            ")->execute([
                ':ip'    => $normalized['src_ip'],
                ':dp'    => $normalized['target_port'] ?? null,
                ':proto' => $normalized['protocol'] ?? null,
                ':sc'    => $normalized['severity_code'] ?? 3,
                ':sl'    => DDoSCorrelator::scoreToLabel($normalized['severity_code'] ?? 3),
                ':cat'   => $normalized['attack_type'] ?? null,
                ':rid'   => $normalized['log_prefix'] ?? null,
                ':rn'    => $normalized['rule_name'] ?? null,
                ':raw'   => $line,
            ]);
        } catch (Throwable $e) {}

        // Grava bloqueio ou ataque no banco principal
        $event_type = $normalized['event_type'] ?? 'attack';
        if ($event_type === 'block_firewall') {
            try {
                $pdo->prepare("
                    INSERT INTO ddosguard_blocks
                        (hostid, src_ip, country_code, country_name, block_source, tool,
                         rule_or_signature, target_port, protocol, reason, raw_data,
                         event_time, created_at)
                    VALUES (0, :ip, :cc, :cn, 'firewall', 'mikrotik',
                            :rule, :port, :proto, :reason, :raw, NOW(), NOW())
                ")->execute([
                    ':ip'     => $normalized['src_ip'],
                    ':cc'     => $normalized['country'] ?? null,
                    ':cn'     => $normalized['country_name'] ?? null,
                    ':rule'   => $normalized['log_prefix'] ?? null,
                    ':port'   => $normalized['target_port'] ?? null,
                    ':proto'  => $normalized['protocol'] ?? null,
                    ':reason' => $normalized['attack_type'] ?? 'BLOCK',
                    ':raw'    => $line,
                ]);
            } catch (Throwable $e) {}
        }

        // Correlacao automatica
        DDoSCorrelator::process($pdo, $normalized, $zbx_host, [
            'ZBX_SENDER_BIN' => $ZBX_SENDER_BIN,
            'ZBX_SERVER'     => $ZBX_SERVER,
            'ZBX_PORT'       => $ZBX_PORT,
        ]);

        // Envia ao Zabbix via zabbix_sender
        $items = [];
        if ($event_type === 'block_firewall') {
            $items['ddosguard.firewall.rate']  = 1;
            $items['ddosguard.block.firewall'] = json_encode($normalized, JSON_UNESCAPED_UNICODE);
        } else {
            $items['ddosguard.attacks.rate']  = 1;
            $items['ddosguard.attack.event']  = json_encode($normalized, JSON_UNESCAPED_UNICODE);
        }

        // Itens especificos do MikroTik
        $prefix = $normalized['log_prefix'] ?? '';
        if (str_starts_with($prefix, 'DG-BRUTE')) {
            $items['ddosguard.mtk.bruteforce'] = 1;
        } elseif (str_starts_with($prefix, 'DG-SCAN')) {
            $items['ddosguard.mtk.portscan'] = 1;
        }

        send_to_zabbix($ZBX_SENDER_BIN, $ZBX_SERVER, $ZBX_PORT, $zbx_host, $items);
        $processed++;

    } catch (Throwable $e) {
        if ($is_http) error_log("DG MikroTik receiver: " . $e->getMessage());
    }
}

if ($is_http) echo json_encode(['ok' => true, 'processed' => $processed]);

// ----------------------------------------------------------------
// Parser do syslog do MikroTik
// ----------------------------------------------------------------
function mikrotik_parse(string $line): ?array
{
    // Formato syslog do MikroTik:
    // Jul  6 03:15:42 MikroTik-CCR kernel: input: in:ether1 ...
    //   src-mac xx:xx, proto TCP (SYN), 185.220.101.50:45123->192.168.1.1:22
    //   DG-BRUTE: in:ether1 out:(unknown 0) ...
    //
    // Ou formato RouterOS direto:
    // <hostname> <date> <time> <subsystem>,<topic>: <mensagem>

    $src_ip   = null;
    $dst_port = null;
    $proto    = 'TCP';
    $prefix   = '';
    $zbx_host = '';

    // Extrai hostname do syslog
    if (preg_match('/^\w{3}\s+\d+ \d+:\d+:\d+ (\S+)/', $line, $m)) {
        $zbx_host = $m[1];
    }

    // Extrai log-prefix (DG-DROP, DG-SCAN, DG-BRUTE, etc.)
    if (preg_match('/\b(DG-[A-Z]+):?/', $line, $m)) {
        $prefix = $m[1];
    }

    // Extrai IP de origem — formato RouterOS: src-ip=x.x.x.x ou IP:porta->IP:porta
    if (preg_match('/src-ip[=:](\d+\.\d+\.\d+\.\d+)/', $line, $m)) {
        $src_ip = $m[1];
    } elseif (preg_match('/(\d+\.\d+\.\d+\.\d+):(\d+)->/', $line, $m)) {
        $src_ip = $m[1];
    } elseif (preg_match('/from (\d+\.\d+\.\d+\.\d+)/', $line, $m)) {
        $src_ip = $m[1];
    }

    // Extrai porta de destino
    if (preg_match('/->[\d.]+:(\d+)/', $line, $m)) {
        $dst_port = (int) $m[1];
    } elseif (preg_match('/dst-port[=:](\d+)/', $line, $m)) {
        $dst_port = (int) $m[1];
    }

    // Extrai protocolo
    if (preg_match('/proto\s+(\w+)/i', $line, $m)) {
        $proto = strtoupper($m[1]);
    } elseif (preg_match('/protocol[=:](\w+)/i', $line, $m)) {
        $proto = strtoupper($m[1]);
    }

    if (empty($src_ip)) return null;

    // Classifica tipo de ataque pelo prefix
    $attack_type = 'SUSPICIOUS_TRAFFIC';
    $event_type  = 'attack';
    $severity    = 3;

    switch (true) {
        case str_starts_with($prefix, 'DG-BRUTE'):
            $attack_type = ($dst_port === 22) ? 'BRUTE_FORCE_SSH' : 'BRUTE_FORCE_WINBOX';
            $severity    = 6;
            break;
        case str_starts_with($prefix, 'DG-SCAN'):
            $attack_type = 'PORT_SCAN';
            $severity    = 4;
            break;
        case str_starts_with($prefix, 'DG-DROP'):
            $attack_type = 'SUSPICIOUS_TRAFFIC';
            $event_type  = 'block_firewall';
            $severity    = 3;
            break;
        default:
            // Sem prefix — tenta classificar pela mensagem
            $lower = strtolower($line);
            if (str_contains($lower, 'drop') || str_contains($lower, 'reject')) {
                $event_type  = 'block_firewall';
            }
            if (str_contains($lower, 'syn') && str_contains($lower, 'flood')) {
                $attack_type = 'SYN_FLOOD';
                $severity    = 7;
            } elseif ($dst_port === 22 || $dst_port === 8291) {
                $attack_type = 'BRUTE_FORCE_SSH';
                $severity    = 5;
            }
    }

    return [
        'event_type'    => $event_type,
        'zbx_host'      => $zbx_host ?: gethostname(),
        'hostid'        => 0,
        'src_ip'        => $src_ip,
        'attack_type'   => $attack_type,
        'target_port'   => $dst_port,
        'protocol'      => $proto,
        'attempts'      => 1,
        'severity_code' => $severity,
        'blocked'       => $event_type === 'block_firewall',
        'source'        => 'mikrotik',
        'platform'      => 'mikrotik',
        'log_prefix'    => $prefix,
        'rule_name'     => $prefix ?: 'mikrotik-firewall',
    ];
}
