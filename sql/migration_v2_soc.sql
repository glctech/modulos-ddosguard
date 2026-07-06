-- DDoS Guard - Migration v2 - SOC Completo
-- ============================================
-- Compativel com MySQL 5.7, MySQL 8.0 e MariaDB 10.x/11.x
-- Nao usa DELIMITER (incompativel com mysql < arquivo.sql)
-- Usa IF NOT EXISTS nos CREATE TABLE/VIEW e verificacao manual
-- via information_schema para os ALTER TABLE.
--
-- Execute:
--   mysql -u zabbix_srv -p zabbix < migration_v2_soc.sql
--
-- Idempotente: pode ser executado multiplas vezes sem erro.

-- ----------------------------------------------------------------
-- 1. Novas colunas em ddosguard_attacks
--    Cada ALTER e condicional via information_schema
-- ----------------------------------------------------------------

-- severity_label
SET @col = 'severity_label';
SET @tbl = 'ddosguard_attacks';
SET @exists = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = @tbl
      AND COLUMN_NAME  = @col
);
SET @sql = IF(@exists = 0,
    'ALTER TABLE ddosguard_attacks ADD COLUMN severity_label VARCHAR(16) NULL',
    'SELECT ''severity_label ja existe'' AS info'
);
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

-- severity_score
SET @col = 'severity_score';
SET @exists = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'ddosguard_attacks'
      AND COLUMN_NAME  = @col
);
SET @sql = IF(@exists = 0,
    'ALTER TABLE ddosguard_attacks ADD COLUMN severity_score TINYINT NULL DEFAULT 0',
    'SELECT ''severity_score ja existe'' AS info'
);
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

-- source_count
SET @col = 'source_count';
SET @exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_attacks' AND COLUMN_NAME=@col);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_attacks ADD COLUMN source_count TINYINT NULL DEFAULT 1','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

-- sources_json
SET @col = 'sources_json';
SET @exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_attacks' AND COLUMN_NAME=@col);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_attacks ADD COLUMN sources_json TEXT NULL','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

-- correlated
SET @col = 'correlated';
SET @exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_attacks' AND COLUMN_NAME=@col);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_attacks ADD COLUMN correlated TINYINT(1) NOT NULL DEFAULT 0','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

-- correlation_id
SET @col = 'correlation_id';
SET @exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_attacks' AND COLUMN_NAME=@col);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_attacks ADD COLUMN correlation_id VARCHAR(64) NULL','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

-- mitre_tactic
SET @col = 'mitre_tactic';
SET @exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_attacks' AND COLUMN_NAME=@col);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_attacks ADD COLUMN mitre_tactic VARCHAR(64) NULL','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

-- mitre_technique
SET @col = 'mitre_technique';
SET @exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_attacks' AND COLUMN_NAME=@col);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_attacks ADD COLUMN mitre_technique VARCHAR(16) NULL','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

-- threat_intel
SET @col = 'threat_intel';
SET @exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_attacks' AND COLUMN_NAME=@col);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_attacks ADD COLUMN threat_intel TINYINT(1) NOT NULL DEFAULT 0','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

-- threat_intel_src
SET @col = 'threat_intel_src';
SET @exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_attacks' AND COLUMN_NAME=@col);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_attacks ADD COLUMN threat_intel_src VARCHAR(64) NULL','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

-- updated_at
SET @col = 'updated_at';
SET @exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_attacks' AND COLUMN_NAME=@col);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_attacks ADD COLUMN updated_at DATETIME NULL','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

-- ----------------------------------------------------------------
-- 2. Novas colunas em ddosguard_blocks
-- ----------------------------------------------------------------

SET @col = 'severity_score';
SET @exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_blocks' AND COLUMN_NAME=@col);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_blocks ADD COLUMN severity_score TINYINT NULL DEFAULT 0','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

SET @col = 'correlated';
SET @exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_blocks' AND COLUMN_NAME=@col);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_blocks ADD COLUMN correlated TINYINT(1) NOT NULL DEFAULT 0','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

SET @col = 'correlation_id';
SET @exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_blocks' AND COLUMN_NAME=@col);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_blocks ADD COLUMN correlation_id VARCHAR(64) NULL','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

SET @col = 'source_platform';
SET @exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_blocks' AND COLUMN_NAME=@col);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_blocks ADD COLUMN source_platform VARCHAR(32) NULL','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

SET @col = 'mitre_technique';
SET @exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_blocks' AND COLUMN_NAME=@col);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_blocks ADD COLUMN mitre_technique VARCHAR(16) NULL','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

SET @col = 'updated_at';
SET @exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_blocks' AND COLUMN_NAME=@col);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_blocks ADD COLUMN updated_at DATETIME NULL','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

-- ----------------------------------------------------------------
-- 3. Tabela de correlacao de eventos
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ddosguard_correlations (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    correlation_id  VARCHAR(64)     NOT NULL,
    hostid          INT             NOT NULL DEFAULT 0,
    src_ip          VARCHAR(45)     NOT NULL,
    country_code    VARCHAR(4)      NULL,
    country_name    VARCHAR(128)    NULL,
    severity_score  TINYINT         NOT NULL DEFAULT 1,
    severity_label  VARCHAR(16)     NOT NULL DEFAULT 'info',
    sources_json    TEXT            NULL,
    attack_types    TEXT            NULL,
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
    KEY idx_ip        (src_ip),
    KEY idx_hostid    (hostid),
    KEY idx_severity  (severity_score),
    KEY idx_last_seen (last_seen),
    KEY idx_resolved  (resolved)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------
-- 4. Tabela de eventos de integracoes externas
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ddosguard_integration_events (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    platform        VARCHAR(32)     NOT NULL,
    event_id        VARCHAR(64)     NULL,
    hostid          INT             NOT NULL DEFAULT 0,
    src_ip          VARCHAR(45)     NULL,
    dst_ip          VARCHAR(45)     NULL,
    src_port        SMALLINT        NULL,
    dst_port        SMALLINT        NULL,
    protocol        VARCHAR(16)     NULL,
    severity_score  TINYINT         NOT NULL DEFAULT 1,
    severity_label  VARCHAR(16)     NOT NULL DEFAULT 'info',
    category        VARCHAR(64)     NULL,
    rule_id         VARCHAR(64)     NULL,
    rule_name       VARCHAR(255)    NULL,
    mitre_tactic    VARCHAR(64)     NULL,
    mitre_technique VARCHAR(16)     NULL,
    description     TEXT            NULL,
    raw_data        MEDIUMTEXT      NULL,
    correlation_id  VARCHAR(64)     NULL,
    event_time      DATETIME        NOT NULL,
    created_at      DATETIME        NOT NULL,
    PRIMARY KEY (id),
    KEY idx_platform   (platform),
    KEY idx_src_ip     (src_ip),
    KEY idx_event_time (event_time),
    KEY idx_severity   (severity_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------
-- 5. Tabela de threat intelligence
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ddosguard_threat_intel (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip          VARCHAR(45)     NOT NULL,
    cidr        VARCHAR(50)     NULL,
    source      VARCHAR(64)     NOT NULL,
    score       TINYINT         NOT NULL DEFAULT 1,
    categories  VARCHAR(255)    NULL,
    country     VARCHAR(4)      NULL,
    asn         VARCHAR(64)     NULL,
    first_seen  DATETIME        NULL,
    last_seen   DATETIME        NULL,
    expires_at  DATETIME        NULL,
    active      TINYINT(1)      NOT NULL DEFAULT 1,
    created_at  DATETIME        NOT NULL,
    updated_at  DATETIME        NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_ip_source (ip, source),
    KEY idx_ip     (ip),
    KEY idx_active (active),
    KEY idx_score  (score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------
-- 6. Indices adicionais (condicionais via information_schema)
-- ----------------------------------------------------------------

SET @idx = 'idx_severity_score';
SET @exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_attacks' AND INDEX_NAME=@idx);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_attacks ADD INDEX idx_severity_score (severity_score)','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

SET @idx = 'idx_correlation_id';
SET @exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_attacks' AND INDEX_NAME=@idx);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_attacks ADD INDEX idx_correlation_id (correlation_id)','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

SET @idx = 'idx_correlated';
SET @exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_attacks' AND INDEX_NAME=@idx);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_attacks ADD INDEX idx_correlated (correlated)','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

SET @idx = 'idx_correlation_id';
SET @exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_blocks' AND INDEX_NAME=@idx);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_blocks ADD INDEX idx_correlation_id (correlation_id)','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

SET @idx = 'idx_source_platform';
SET @exists = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ddosguard_blocks' AND INDEX_NAME=@idx);
SET @sql = IF(@exists=0,'ALTER TABLE ddosguard_blocks ADD INDEX idx_source_platform (source_platform)','SELECT 1');
PREPARE _s FROM @sql; EXECUTE _s; DEALLOCATE PREPARE _s;

-- ----------------------------------------------------------------
-- 7. View de incidentes ativos
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
