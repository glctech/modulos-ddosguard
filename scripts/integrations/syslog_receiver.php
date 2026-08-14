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
 * CONFIGURAÇÃO — MikroTik RouterOS 6.x / 7.x:
 *   Ver mikrotik/ddosguard-ccr.rsc na raiz do projeto. Em resumo:
 *
 *   /system logging action
 *     add name=syslogremoto target=remote remote=IP_DO_COLETOR \
 *         remote-port=514 bsd-syslog=yes syslog-facility=local7 \
 *         syslog-severity=auto
 *   /system logging
 *     add topics=firewall action=syslogremoto
 *     add topics=info     action=syslogremoto
 *
 *   O `remote` precisa ser o IP do COLETOR. Apontar para o IP público do
 *   próprio roteador não funciona: pacotes gerados localmente saem pelo
 *   chain `output` e não passam pelo dstnat, então o port-forward nunca
 *   se aplica e o log morre no equipamento.
 *
 * ALTERNATIVA — Endpoint HTTP (para forwarders como Filebeat/Logstash):
 *   Configure Filebeat/Logstash para enviar via HTTP POST para este script.
 *   O script aceita tanto POST HTTP quanto stdin (para omprog do rsyslog).
 */

// Declara que o ingest.php deve se comportar como biblioteca: sem isso o
// require abaixo executa o endpoint HTTP e encerra o processo com
// "invalid token" antes de qualquer linha ser processada.
define('DG_INGEST_LIB', true);

require_once dirname(__DIR__) . '/ingest.php';
require_once dirname(__DIR__) . '/correlator.php';

// Detecta modo de operação: HTTP ou stdin (rsyslog omprog)
$is_http = (PHP_SAPI === 'fpm-fcgi' || PHP_SAPI === 'apache2handler' || isset($_SERVER['HTTP_HOST']));

if ($is_http) {
    // Modo HTTP: valida token
    $token = $_SERVER['HTTP_X_DG_TOKEN'] ?? '';
    if (!hash_equals($INGEST_TOKEN, (string) $token)) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'unauthorized']);
        exit;
    }
    $lines = [file_get_contents('php://input')];
} else {
    // Modo stdin: generator, não array.
    //
    // O omprog mantém UM processo vivo e alimenta o stdin continuamente.
    // Com `while (fgets(...)) { $lines[] = ... }` o pipe nunca fecha,
    // fgets() nunca retorna false, e o foreach abaixo jamais era
    // alcançado — o script acumulava linhas em memória para sempre.
    // Funcionava em teste manual (onde o STDIN encerra) e nunca em
    // produção. Com generator, cada linha é processada assim que chega.
    $lines = (function () {
        while (($line = fgets(STDIN)) !== false) {
            yield trim($line);
        }
    })();
}

$processed = 0;
$pdo = null;
foreach ($lines as $line) {
    if (empty($line)) continue;

    // Heartbeat: prova que o canal está vivo mesmo quando não há ataque.
    // Não passa pelos parsers de firewall — a mensagem não tem IP nem
    // protocolo e seria descartada silenciosamente logo adiante.
    if (str_contains($line, 'DDOSGUARD-HEARTBEAT')) {
        $hb_host = $MIKROTIK_ZBX_HOST ?: dg_syslog_hostname($line);
        if ($hb_host !== '') {
            send_to_zabbix($ZBX_SENDER_BIN, $ZBX_SERVER, $ZBX_PORT,
                $hb_host, ['ddosguard.agent.heartbeat' => 1]);
        }
        continue;
    }

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
        case 'mikrotik':
            $normalized = parse_mikrotik($line, $MIKROTIK_ZBX_HOST, $MIKROTIK_ZBX_HOSTID);
            break;
        default:
            $normalized = parse_generic_firewall($line);
    }

    if (!$normalized || empty($normalized['src_ip'])) continue;

    try {
        // Reaproveita a conexão: sob omprog o processo é persistente e
        // abrir um PDO por linha derrubava o MySQL sob carga real.
        if (!($pdo instanceof PDO)) {
            $pdo = db_connect($DB_DRIVER, $DB_HOST, $DB_PORT, $DB_NAME, $DB_USER, $DB_PASS);
        }

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
        //
        // v3: hostid, severity_score e source_platform passaram a ser
        // preenchidos. Antes o hostid ia fixo em 0 e o dashboard mostrava
        // "Host protegido: Desconhecido" em toda linha.
        $pdo->prepare("
            INSERT INTO ddosguard_blocks
                (hostid, src_ip, block_source, tool, rule_or_signature,
                 target_port, protocol, reason, severity_score, source_platform,
                 raw_data, event_time, created_at)
            VALUES (:hostid, :ip, 'firewall', :tool, :rule, :port, :proto,
                    :reason, :sev, :splat, :raw, NOW(), NOW())
        ")->execute([
            ':hostid' => $normalized['hostid'] ?? 0,
            ':ip'     => $normalized['src_ip'],
            ':tool'   => $platform,
            ':rule'   => $normalized['rule_id'] ?? null,
            ':port'   => $normalized['target_port'] ?? null,
            ':proto'  => $normalized['protocol'] ?? null,
            ':reason' => $normalized['attack_type'] ?? 'BLOCK',
            ':sev'    => $normalized['severity_code'] ?? 3,
            ':splat'  => $platform,
            ':raw'    => $line,
        ]);

        // Correlaciona
        DDoSCorrelator::process($pdo, $normalized, $normalized['zbx_host'], [
            'ZBX_SENDER_BIN' => $ZBX_SENDER_BIN,
            'ZBX_SERVER'     => $ZBX_SERVER,
            'ZBX_PORT'       => $ZBX_PORT,
        ]);

        $host  = $normalized['zbx_host'];
        $items = [
            'ddosguard.firewall.rate'  => 1,
            'ddosguard.block.firewall' => json_encode($normalized, JSON_UNESCAPED_UNICODE),
        ];

        // Contadores específicos do MikroTik. São itens trapper próprios
        // no template e, sem isto, ficavam permanentemente vazios.
        if ($platform === 'mikrotik') {
            $mtk_key = match ($normalized['attack_type'] ?? '') {
                'PORT_SCAN'   => 'ddosguard.mtk.portscan',
                'BRUTE_FORCE' => 'ddosguard.mtk.bruteforce',
                default       => null,
            };
            if ($mtk_key) {
                $items[$mtk_key] = 1;
            }
        }

        send_to_zabbix($ZBX_SENDER_BIN, $ZBX_SERVER, $ZBX_PORT, $host, $items);
        $processed++;
    } catch (Throwable $e) {
        // Em processo persistente a conexão pode morrer por wait_timeout
        // do MySQL (8h por padrão). Descartar o handle força a reconexão
        // na próxima linha, em vez de o receiver ficar mudo para sempre.
        $pdo = null;
        error_log("DDoS Guard syslog_receiver: " . $e->getMessage());
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
    // MikroTik RouterOS: "in:<iface> out:iface" seguido de "proto X".
    // Formato real do CCR1009:
    //   DDOSGUARD-PORTSCAN input: in:sfp1-vlan-777 out:(unknown 0),
    //   src-mac 64:5e:10:04:72:dc, proto TCP (SYN),
    //   186.237.54.112:47904->45.70.216.68:64093, len 40
    if (preg_match('/\bin:\S*\s+out:\S*/', $line) && str_contains($line, 'proto ')) {
        return 'mikrotik';
    }
    return 'generic';
}

// ----------------------------------------------------------------
// Extrai o hostname enviado no cabeçalho do syslog (fallback quando
// DG_MIKROTIK_ZBX_HOST não está configurado)
// ----------------------------------------------------------------
// Só cobre o formato BSD (RFC 3164), que é o entregue pelo template
// DGProgFmt do omprog:
//     Jul 31 06:38:38 45.70.216.69 POP3CA-WEB+ DDOSGUARD-PORTSCAN ...
//                     ^FROMHOST-IP ^syslogtag
//
// Formatos com timestamp ISO trazem a severidade nessa posição, não o
// hostname — tentar adivinhar ali devolvia "info" como nome de host e o
// zabbix_sender rejeitava em silêncio. Prefira sempre configurar
// DG_MIKROTIK_ZBX_HOST explicitamente.
function dg_syslog_hostname(string $line): string
{
    if (!preg_match('/^\w{3}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+(\S+)/', $line, $m)) {
        return '';
    }
    $host = rtrim($m[1], ':');

    // Descarta palavras de severidade/facility que aparecem nessa posição
    // quando o template do rsyslog não é o esperado.
    $reservadas = ['emerg', 'alert', 'crit', 'critical', 'err', 'error',
                   'warn', 'warning', 'notice', 'info', 'debug'];
    if (in_array(strtolower($host), $reservadas, true)) {
        return '';
    }
    return $host;
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
// Parser MikroTik RouterOS (6.x e 7.x)
// ----------------------------------------------------------------
// A classificação vem do log-prefix da regra de firewall, não do
// conteúdo do pacote. Cada regra de detecção no CCR carimba seu próprio
// prefixo (ver mikrotik/ddosguard-ccr.rsc), e é isso que dá semântica ao
// evento — o mesmo SYN pode ser scan, brute force ou tráfego comum
// dependendo de qual regra o capturou.
function parse_mikrotik(string $line, string $zbx_host = '', int $hostid = 0): ?array
{
    if (!preg_match('/\bproto\s+([A-Za-z]+)/', $line, $pm)) return null;
    $proto = strtoupper($pm[1]);

    $src_ip = null;
    $dst_port = null;

    // TCP/UDP: IP:porta->IP:porta
    if (preg_match('/(\d{1,3}(?:\.\d{1,3}){3}):(\d+)->(\d{1,3}(?:\.\d{1,3}){3}):(\d+)/', $line, $m)) {
        $src_ip   = $m[1];
        $dst_port = (int) $m[4];
    }
    // ICMP e demais protocolos sem porta: IP->IP
    elseif (preg_match('/(\d{1,3}(?:\.\d{1,3}){3})->(\d{1,3}(?:\.\d{1,3}){3})/', $line, $m)) {
        $src_ip = $m[1];
    } else {
        return null;
    }

    $attack_type = 'SUSPICIOUS_TRAFFIC';
    $severity    = 3;
    if (str_contains($line, 'DDOSGUARD-PORTSCAN')) {
        $attack_type = 'PORT_SCAN';   $severity = 4;
    } elseif (str_contains($line, 'DDOSGUARD-BRUTEFORCE')) {
        $attack_type = 'BRUTE_FORCE'; $severity = 6;
    } elseif (str_contains($line, 'DDOSGUARD-UDPFLOOD')) {
        $attack_type = 'UDP_FLOOD';   $severity = 7;
    } elseif (str_contains($line, 'DDOSGUARD-ICMPFLOOD')) {
        $attack_type = 'ICMP_FLOOD';  $severity = 7;
    }

    preg_match('/(DDOSGUARD-[A-Z-]+|DROP-FWD|DROP-IN)/', $line, $rm);
    $rule = $rm[1] ?? 'mikrotik-firewall';

    // Interfaces ajudam a distinguir ataque externo de tráfego interno
    preg_match('/\bin:<?([^>\s,]*)>?/', $line, $in);
    preg_match('/\bout:([^\s,]*)/', $line, $out);

    return [
        'event_type'    => 'block_firewall',
        'zbx_host'      => $zbx_host !== '' ? $zbx_host : dg_syslog_hostname($line),
        'hostid'        => $hostid,
        'src_ip'        => $src_ip,
        'attack_type'   => $attack_type,
        'target_port'   => $dst_port,
        'protocol'      => $proto,
        'attempts'      => 1,
        'severity_code' => $severity,
        'blocked'       => true,
        'source'        => 'mikrotik',
        'platform'      => 'mikrotik',
        'rule_id'       => $rule,
        'rule_name'     => $rule,
        'iface_in'      => $in[1] ?? null,
        'iface_out'     => $out[1] ?? null,
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
