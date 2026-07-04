-- DDoS Guard - Migration v2 - SOC Completo
-- ============================================
-- Adiciona suporte a correlacao automatica, classificacao de severidade
-- e integracoes com Wazuh, Suricata, pfSense, FortiGate.
--
-- SEGURO: nao altera nem remove colunas existentes.
-- Execute apenas uma vez no banco do Zabbix:
--   mysql -u zabbix_srv -p zabbix < migration_v2_soc.sql
--
-- Verificar se ja foi executado antes de rodar:
--   SELECT table_name FROM information_schema.tables
--   WHERE table_schema = DATABASE()
--   AND table_name LIKE 'ddosguard_%';

-- ----------------------------------------------------------------
-- 1. Novas colunas em ddosguard_attacks (sem alterar existentes)
-- ----------------------------------------------------------------
ALTER TABLE ddosguard_attacks
    ADD COLUMN IF NOT EXISTS severity_label  VARCHAR(16)  NULL COMMENT 'info|low|medium|high|critical',
    ADD COLUMN IF NOT EXISTS severity_score  TINYINT      NULL DEFAULT 0 COMMENT '1-10',
    ADD COLUMN IF NOT EXISTS source_count    TINYINT      NULL DEFAULT 1 COMMENT 'quantas fontes detectaram este IP',
    ADD COLUMN IF NOT EXISTS sources_json    TEXT         NULL COMMENT 'JSON com lista de fontes: ["wazuh","suricata"]',
    ADD COLUMN IF NOT EXISTS correlated      TINYINT(1)   NOT NULL DEFAULT 0 COMMENT '1=correlacionado com outros eventos',
    ADD COLUMN IF NOT EXISTS correlation_id  VARCHAR(64)  NULL COMMENT 'UUID do grupo de correlacao',
    ADD COLUMN IF NOT EXISTS mitre_tactic    VARCHAR(64)  NULL COMMENT 'MITRE ATT&CK tactic (ex: Initial Access)',
    ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(16)  NULL COMMENT 'MITRE ATT&CK technique ID (ex: T1110)',
    ADD COLUMN IF NOT EXISTS threat_intel    TINYINT(1)   NOT NULL DEFAULT 0 COMMENT '1=IP em blacklist conhecida',
    ADD COLUMN IF NOT EXISTS threat_intel_src VARCHAR(64) NULL COMMENT 'fonte da inteligencia de ameaca',
    ADD COLUMN IF NOT EXISTS updated_at      DATETIME     NULL;

-- ----------------------------------------------------------------
-- 2. Novas colunas em ddosguard_blocks
-- ----------------------------------------------------------------
ALTER TABLE ddosguard_blocks
    ADD COLUMN IF NOT EXISTS severity_score  TINYINT      NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS correlated      TINYINT(1)   NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS correlation_id  VARCHAR(64)  NULL,
    ADD COLUMN IF NOT EXISTS source_platform VARCHAR(32)  NULL COMMENT 'wazuh|suricata|pfsense|fortigate|agent',
    ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(16)  NULL,
    ADD COLUMN IF NOT EXISTS updated_at      DATETIME     NULL;

-- ----------------------------------------------------------------
-- 3. Tabela de correlacao de eventos (nova — nao existe antes)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ddosguard_correlations (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    correlation_id  VARCHAR(64)     NOT NULL COMMENT 'UUID do grupo',
    hostid          INT             NOT NULL DEFAULT 0,
    src_ip          VARCHAR(45)     NOT NULL,
    country_code    VARCHAR(4)      NULL,
    country_name    VARCHAR(128)    NULL,
    severity_score  TINYINT         NOT NULL DEFAULT 1,
    severity_label  VARCHAR(16)     NOT NULL DEFAULT 'info',
    sources_json    TEXT            NULL COMMENT 'lista de plataformas que detectaram',
    attack_types    TEXT            NULL COMMENT 'lista de tipos de ataque',
    mitre_tactics   TEXT            NULL,
    total_events    INT             NOT NULL DEFAULT 1,
    first_seen      DATETIME        NOT NULL,
    last_seen       DATETIME        NOT NULL,
    resolved        TINYINT(1)      NOT NULL DEFAULT 0,
    resolved_at     DATETIME        NULL,
    notes           TEXT            NULL,
    created_at      DATETIME        NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_correlation (correlation_id),
    KEY idx_ip         (src_ip),
    KEY idx_hostid     (hostid),
    KEY idx_severity   (severity_score),
    KEY idx_last_seen  (last_seen),
    KEY idx_resolved   (resolved)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Grupos de correlacao de eventos de seguranca';

-- ----------------------------------------------------------------
-- 4. Tabela de eventos brutos de integracoes externas
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ddosguard_integration_events (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    platform        VARCHAR(32)     NOT NULL COMMENT 'wazuh|suricata|pfsense|fortigate',
    event_id        VARCHAR(64)     NULL COMMENT 'ID do evento na plataforma de origem',
    hostid          INT             NOT NULL DEFAULT 0,
    src_ip          VARCHAR(45)     NULL,
    dst_ip          VARCHAR(45)     NULL,
    src_port        SMALLINT        NULL,
    dst_port        SMALLINT        NULL,
    protocol        VARCHAR(16)     NULL,
    severity_score  TINYINT         NOT NULL DEFAULT 1,
    severity_label  VARCHAR(16)     NOT NULL DEFAULT 'info',
    category        VARCHAR(64)     NULL COMMENT 'ids_alert|firewall_block|malware|...',
    rule_id         VARCHAR(64)     NULL,
    rule_name       VARCHAR(255)    NULL,
    mitre_tactic    VARCHAR(64)     NULL,
    mitre_technique VARCHAR(16)     NULL,
    description     TEXT            NULL,
    raw_data        MEDIUMTEXT      NULL COMMENT 'payload JSON original da plataforma',
    correlation_id  VARCHAR(64)     NULL,
    event_time      DATETIME        NOT NULL,
    created_at      DATETIME        NOT NULL,
    PRIMARY KEY (id),
    KEY idx_platform    (platform),
    KEY idx_src_ip      (src_ip),
    KEY idx_event_time  (event_time),
    KEY idx_severity    (severity_score),
    KEY idx_correlation (correlation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Eventos brutos recebidos das integracoes externas';

-- ----------------------------------------------------------------
-- 5. Tabela de blacklists / threat intelligence
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ddosguard_threat_intel (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip          VARCHAR(45)     NOT NULL,
    cidr        VARCHAR(50)     NULL COMMENT 'range CIDR se aplicavel',
    source      VARCHAR(64)     NOT NULL COMMENT 'abuseipdb|emerging_threats|custom|...',
    score       TINYINT         NOT NULL DEFAULT 1 COMMENT '1-100 (confianca)',
    categories  VARCHAR(255)    NULL COMMENT 'ssh,brute-force,scan,...',
    country     VARCHAR(4)      NULL,
    asn         VARCHAR(64)     NULL,
    first_seen  DATETIME        NULL,
    last_seen   DATETIME        NULL,
    expires_at  DATETIME        NULL COMMENT 'NULL=sem expiracao',
    active      TINYINT(1)      NOT NULL DEFAULT 1,
    created_at  DATETIME        NOT NULL,
    updated_at  DATETIME        NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_ip_source (ip, source),
    KEY idx_ip     (ip),
    KEY idx_active (active),
    KEY idx_score  (score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Inteligencia de ameacas e blacklists de IPs';

-- ----------------------------------------------------------------
-- 6. Indices adicionais para performance
-- ----------------------------------------------------------------
ALTER TABLE ddosguard_attacks
    ADD INDEX IF NOT EXISTS idx_severity_score (severity_score),
    ADD INDEX IF NOT EXISTS idx_correlation_id (correlation_id),
    ADD INDEX IF NOT EXISTS idx_correlated (correlated);

ALTER TABLE ddosguard_blocks
    ADD INDEX IF NOT EXISTS idx_correlation_id (correlation_id),
    ADD INDEX IF NOT EXISTS idx_source_platform (source_platform);

-- ----------------------------------------------------------------
-- 7. View de incidentes ativos (correlacoes nao resolvidas)
-- ----------------------------------------------------------------
CREATE OR REPLACE VIEW ddosguard_active_incidents AS
SELECT
    c.correlation_id,
    c.src_ip,
    c.country_name,
    c.severity_score,
    c.severity_label,
    c.sources_json,
    c.total_events,
    c.first_seen,
    c.last_seen,
    TIMESTAMPDIFF(MINUTE, c.first_seen, c.last_seen) AS duration_minutes,
    (SELECT COUNT(*) FROM ddosguard_attacks a
     WHERE a.correlation_id = c.correlation_id) AS attack_records,
    (SELECT COUNT(*) FROM ddosguard_blocks b
     WHERE b.correlation_id = c.correlation_id) AS block_records
FROM ddosguard_correlations c
WHERE c.resolved = 0
ORDER BY c.severity_score DESC, c.last_seen DESC;

SELECT 'Migration v2 SOC concluida com sucesso.' AS status;
