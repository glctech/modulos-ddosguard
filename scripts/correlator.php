<?php
/**
 * DDoS Guard - Motor de Correlação e Classificação de Severidade
 * ==============================================================
 * Chamado pelo ingest.php após gravar cada evento.
 * Não altera a estrutura atual — apenas enriquece os dados com:
 *
 *   - Severidade dinâmica (Info → Low → Medium → High → Critical)
 *   - Correlação automática por IP (agrupa eventos de múltiplas fontes)
 *   - Classificação MITRE ATT&CK
 *   - Verificação de threat intelligence (blacklists)
 *
 * Uso no ingest.php (adicione após cada INSERT em ddosguard_attacks):
 *   require_once __DIR__ . '/correlator.php';
 *   DDoSCorrelator::process($pdo, $payload, $hostname, $zbx_config);
 */

class DDoSCorrelator
{
    // ----------------------------------------------------------------
    // Tabela de severidade baseada em múltiplos fatores
    // ----------------------------------------------------------------
    private static array $SEVERITY_MAP = [
        // [min_score, label, zabbix_priority]
        [9,  'critical', 5],
        [7,  'high',     4],
        [5,  'medium',   3],
        [3,  'low',      2],
        [1,  'info',     1],
    ];

    // MITRE ATT&CK mapping por tipo de ataque
    private static array $MITRE_MAP = [
        'BRUTE_FORCE_RDP'     => ['tactic' => 'Credential Access',  'technique' => 'T1110'],
        'BRUTE_FORCE_SSH'     => ['tactic' => 'Credential Access',  'technique' => 'T1110.001'],
        'BRUTE_FORCE_SMB'     => ['tactic' => 'Lateral Movement',   'technique' => 'T1021.002'],
        'SYN_FLOOD'           => ['tactic' => 'Impact',             'technique' => 'T1498.001'],
        'UDP_FLOOD'           => ['tactic' => 'Impact',             'technique' => 'T1498.001'],
        'HTTP_FLOOD'          => ['tactic' => 'Impact',             'technique' => 'T1499.002'],
        'SUSPICIOUS_TRAFFIC'  => ['tactic' => 'Discovery',          'technique' => 'T1046'],
        'PORT_SCAN'           => ['tactic' => 'Reconnaissance',     'technique' => 'T1595.001'],
        'SQL_INJECTION'       => ['tactic' => 'Initial Access',     'technique' => 'T1190'],
        'MALWARE'             => ['tactic' => 'Execution',          'technique' => 'T1204'],
        'EXPLOIT'             => ['tactic' => 'Initial Access',     'technique' => 'T1190'],
        'C2_COMMUNICATION'    => ['tactic' => 'Command and Control','technique' => 'T1071'],
        'DATA_EXFILTRATION'   => ['tactic' => 'Exfiltration',       'technique' => 'T1048'],
    ];

    // ----------------------------------------------------------------
    // Ponto de entrada principal
    // ----------------------------------------------------------------
    public static function process(
        PDO    $pdo,
        array  $payload,
        string $hostname,
        array  $zbx_config = []
    ): array {
        $src_ip    = $payload['src_ip'] ?? '';
        $hostid    = (int) ($payload['hostid'] ?? 0);
        $attack_type = $payload['attack_type'] ?? 'SUSPICIOUS_TRAFFIC';
        $source    = $payload['source'] ?? ($payload['platform'] ?? 'agent');

        if (empty($src_ip)) {
            return ['score' => 1, 'label' => 'info'];
        }

        // 1. Calcula severidade
        $score = self::calculateSeverity($pdo, $payload);

        // 2. Verifica threat intelligence
        $threat = self::checkThreatIntel($pdo, $src_ip);
        if ($threat) {
            $score = min(10, $score + 2);
        }

        // 3. Classifica MITRE ATT&CK
        $mitre = self::getMitre($attack_type);

        // 4. Correlaciona com eventos anteriores do mesmo IP
        $correlation_id = self::correlate($pdo, $payload, $score, $source);

        // 5. Atualiza o registro de ataque com os dados de correlação
        self::updateAttackRecord($pdo, $payload, $score, $correlation_id, $mitre, $threat);

        // 6. Envia ao Zabbix se severidade subiu (High ou Critical)
        if ($score >= 7 && !empty($zbx_config)) {
            self::notifyZabbix($zbx_config, $hostname, $src_ip, $score, $correlation_id);
        }

        $label = self::scoreToLabel($score);
        return [
            'score'          => $score,
            'label'          => $label,
            'correlation_id' => $correlation_id,
            'mitre'          => $mitre,
            'threat_intel'   => $threat !== null,
        ];
    }

    // ----------------------------------------------------------------
    // Calcula severidade (1-10) com base em múltiplos fatores
    // ----------------------------------------------------------------
    private static function calculateSeverity(PDO $pdo, array $payload): int
    {
        $score = 1;
        $src_ip   = $payload['src_ip'] ?? '';
        $attempts = (int) ($payload['attempts'] ?? 1);
        $hostid   = (int) ($payload['hostid'] ?? 0);

        // Fator 1: volume de tentativas
        if ($attempts >= 500)       $score += 4;
        elseif ($attempts >= 200)   $score += 3;
        elseif ($attempts >= 50)    $score += 2;
        elseif ($attempts >= 10)    $score += 1;

        // Fator 2: quantas fontes detectaram este IP na última hora
        $stmt = $pdo->prepare("
            SELECT COUNT(DISTINCT source_tool) as src_count,
                   COUNT(*) as total
            FROM ddosguard_attacks
            WHERE src_ip = :ip
              AND hostid = :hostid
              AND last_seen >= NOW() - INTERVAL 1 HOUR
        ");
        $stmt->execute([':ip' => $src_ip, ':hostid' => $hostid]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $source_count = (int) ($row['src_count'] ?? 1);
        $total_events = (int) ($row['total'] ?? 0);

        if ($source_count >= 3)     $score += 3;
        elseif ($source_count >= 2) $score += 2;

        // Fator 3: reincidência (já apareceu antes)
        if ($total_events >= 10)    $score += 2;
        elseif ($total_events >= 3) $score += 1;

        // Fator 4: tipo de ataque específico
        $attack_type = $payload['attack_type'] ?? '';
        $high_risk = ['SYN_FLOOD','UDP_FLOOD','HTTP_FLOOD','SQL_INJECTION',
                      'EXPLOIT','MALWARE','C2_COMMUNICATION','DATA_EXFILTRATION'];
        if (in_array($attack_type, $high_risk)) $score += 2;

        // Fator 5: porta alvo crítica
        $port = (int) ($payload['target_port'] ?? 0);
        $critical_ports = [22, 3389, 445, 1433, 3306, 5432, 6379, 27017];
        if (in_array($port, $critical_ports)) $score += 1;

        // Fator 6: bloqueio confirmado por múltiplas ferramentas
        if (!empty($payload['blocked'])) $score += 1;

        return min(10, max(1, $score));
    }

    // ----------------------------------------------------------------
    // Correlaciona eventos do mesmo IP em janela de 30 minutos
    // ----------------------------------------------------------------
    private static function correlate(
        PDO    $pdo,
        array  $payload,
        int    $score,
        string $source
    ): string {
        $src_ip  = $payload['src_ip'] ?? '';
        $hostid  = (int) ($payload['hostid'] ?? 0);
        $label   = self::scoreToLabel($score);

        // Busca correlação existente nas últimas 2h
        try {
            $stmt = $pdo->prepare("
                SELECT correlation_id, sources_json, total_events, severity_score
                FROM ddosguard_correlations
                WHERE src_ip  = :ip
                  AND hostid  = :hostid
                  AND resolved = 0
                  AND last_seen >= NOW() - INTERVAL 2 HOUR
                ORDER BY last_seen DESC
                LIMIT 1
            ");
            $stmt->execute([':ip' => $src_ip, ':hostid' => $hostid]);
            $existing = $stmt->fetch(PDO::FETCH_ASSOC);
        } catch (Throwable $e) {
            // Tabela ainda não existe (migration não foi executada)
            return self::generateUUID();
        }

        if ($existing) {
            $corr_id = $existing['correlation_id'];

            // Atualiza a correlação existente
            $sources = json_decode($existing['sources_json'] ?? '[]', true);
            if (!in_array($source, $sources)) {
                $sources[] = $source;
            }
            $new_score = max($existing['severity_score'], $score);

            $pdo->prepare("
                UPDATE ddosguard_correlations
                SET last_seen     = NOW(),
                    total_events  = total_events + 1,
                    severity_score = :score,
                    severity_label = :label,
                    sources_json  = :sources
                WHERE correlation_id = :cid
            ")->execute([
                ':score'   => $new_score,
                ':label'   => self::scoreToLabel($new_score),
                ':sources' => json_encode($sources),
                ':cid'     => $corr_id,
            ]);

            return $corr_id;
        }

        // Cria nova correlação
        $corr_id  = self::generateUUID();
        $attack_type = $payload['attack_type'] ?? 'UNKNOWN';

        try {
            $pdo->prepare("
                INSERT INTO ddosguard_correlations
                    (correlation_id, hostid, src_ip, country_code, country_name,
                     severity_score, severity_label, sources_json, attack_types,
                     total_events, first_seen, last_seen, created_at)
                VALUES
                    (:cid, :hostid, :ip, :cc, :cn,
                     :score, :label, :sources, :atypes,
                     1, NOW(), NOW(), NOW())
            ")->execute([
                ':cid'     => $corr_id,
                ':hostid'  => $hostid,
                ':ip'      => $src_ip,
                ':cc'      => $payload['country'] ?? null,
                ':cn'      => $payload['country_name'] ?? null,
                ':score'   => $score,
                ':label'   => $label,
                ':sources' => json_encode([$source]),
                ':atypes'  => json_encode([$attack_type]),
            ]);
        } catch (Throwable $e) {
            // Tabela não existe — migration não executada ainda
        }

        return $corr_id;
    }

    // ----------------------------------------------------------------
    // Verifica threat intelligence
    // ----------------------------------------------------------------
    private static function checkThreatIntel(PDO $pdo, string $ip): ?array
    {
        try {
            $stmt = $pdo->prepare("
                SELECT source, score, categories
                FROM ddosguard_threat_intel
                WHERE ip = :ip
                  AND active = 1
                  AND (expires_at IS NULL OR expires_at > NOW())
                ORDER BY score DESC
                LIMIT 1
            ");
            $stmt->execute([':ip' => $ip]);
            return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
        } catch (Throwable $e) {
            return null;
        }
    }

    // ----------------------------------------------------------------
    // Atualiza o registro de ataque com correlação e severidade
    // ----------------------------------------------------------------
    private static function updateAttackRecord(
        PDO     $pdo,
        array   $payload,
        int     $score,
        string  $corr_id,
        array   $mitre,
        ?array  $threat
    ): void {
        $src_ip = $payload['src_ip'] ?? '';
        $hostid = (int) ($payload['hostid'] ?? 0);

        try {
            $pdo->prepare("
                UPDATE ddosguard_attacks
                SET severity_score  = :score,
                    severity_label  = :label,
                    correlated      = 1,
                    correlation_id  = :cid,
                    mitre_tactic    = :tactic,
                    mitre_technique = :technique,
                    threat_intel    = :ti,
                    threat_intel_src = :ti_src,
                    updated_at      = NOW()
                WHERE src_ip = :ip
                  AND hostid = :hostid
                ORDER BY attack_id DESC
                LIMIT 1
            ")->execute([
                ':score'     => $score,
                ':label'     => self::scoreToLabel($score),
                ':cid'       => $corr_id,
                ':tactic'    => $mitre['tactic'] ?? null,
                ':technique' => $mitre['technique'] ?? null,
                ':ti'        => $threat ? 1 : 0,
                ':ti_src'    => $threat ? $threat['source'] : null,
                ':ip'        => $src_ip,
                ':hostid'    => $hostid,
            ]);
        } catch (Throwable $e) {
            // Colunas novas ainda não existem (migration não executada)
        }
    }

    // ----------------------------------------------------------------
    // Notifica Zabbix sobre correlação de alta severidade
    // ----------------------------------------------------------------
    private static function notifyZabbix(
        array  $zbx_config,
        string $hostname,
        string $src_ip,
        int    $score,
        string $corr_id
    ): void {
        $label = self::scoreToLabel($score);
        $data  = json_encode([
            'correlation_id' => $corr_id,
            'src_ip'         => $src_ip,
            'severity_score' => $score,
            'severity_label' => $label,
            'timestamp'      => time(),
        ]);

        // Envia item trapper para o Zabbix
        $bin    = $zbx_config['ZBX_SENDER_BIN'] ?? '/usr/bin/zabbix_sender';
        $server = $zbx_config['ZBX_SERVER']     ?? '127.0.0.1';
        $port   = $zbx_config['ZBX_PORT']       ?? '10051';

        $cmd = sprintf(
            '%s -z %s -p %s -s %s -k ddosguard.correlation.event -o %s 2>/dev/null',
            escapeshellarg($bin),
            escapeshellarg($server),
            escapeshellarg((string)$port),
            escapeshellarg($hostname),
            escapeshellarg($data)
        );
        shell_exec($cmd);
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------
    public static function scoreToLabel(int $score): string
    {
        foreach (self::$SEVERITY_MAP as [$min, $label]) {
            if ($score >= $min) return $label;
        }
        return 'info';
    }

    private static function getMitre(string $attack_type): array
    {
        return self::$MITRE_MAP[$attack_type] ?? [
            'tactic'    => 'Discovery',
            'technique' => 'T1046',
        ];
    }

    private static function generateUUID(): string
    {
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }
}
