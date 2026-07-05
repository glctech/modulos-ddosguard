-- DDoS Guard - Migration v2 - SOC Completo
-- ============================================
-- Compativel com MySQL 5.7, 8.0 e MariaDB 10.x
-- NAO usa IF NOT EXISTS no ALTER TABLE (nao suportado no MySQL 5.7)
-- Usa procedure para verificar se a coluna ja existe antes de adicionar.
--
-- Execute apenas uma vez:
--   mysql -u zabbix_srv -p zabbix < migration_v2_soc.sql

DELIMITER $$

-- Helper: adiciona coluna somente se nao existir
DROP PROCEDURE IF EXISTS ddosguard_add_column$$
CREATE PROCEDURE ddosguard_add_column(
    IN tbl VARCHAR(64),
    IN col VARCHAR(64),
    IN col_def TEXT
)
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME   = tbl
          AND COLUMN_NAME  = col
    ) THEN
        SET @sql = CONCAT('ALTER TABLE ', tbl, ' ADD COLUMN ', col, ' ', col_def);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END$$

DELIMITER ;

-- ----------------------------------------------------------------
-- 1. Novas colunas em ddosguard_attacks
-- ----------------------------------------------------------------
CALL ddosguard_add_column('ddosguard_attacks', 'severity_label',   "VARCHAR(16)  NULL COMMENT 'info|low|medium|high|critical'");
CALL ddosguard_add_column('ddosguard_attacks', 'severity_score',   "TINYINT      NULL DEFAULT 0 COMMENT '1-10'");
CALL ddosguard_add_column('ddosguard_attacks', 'source_count',     "TINYINT      NULL DEFAULT 1");
CALL ddosguard_add_column('ddosguard_attacks', 'sources_json',     "TEXT         NULL");
CALL ddosguard_add_column('ddosguard_attacks', 'correlated',       "TINYINT(1)   NOT NULL DEFAULT 0");
CALL ddosguard_add_column('ddosguard_attacks', 'correlation_id',   "VARCHAR(64)  NULL");
CALL ddosguard_add_column('ddosguard_attacks', 'mitre_tactic',     "VARCHAR(64)  NULL");
CALL ddosguard_add_column('ddosguard_attacks', 'mitre_technique',  "VARCHAR(16)  NULL");
CALL ddosguard_add_column('ddosguard_attacks', 'threat_intel',     "TINYINT(1)   NOT NULL DEFAULT 0");
CALL ddosguard_add_column('ddosguard_attacks', 'threat_intel_src', "VARCHAR(64)  NULL");
CALL ddosguard_add_column('ddosguard_attacks', 'updated_at',       "DATETIME     NULL");

-- ----------------------------------------------------------------
-- 2. Novas colunas em ddosguard_blocks
-- ----------------------------------------------------------------
CALL ddosguard_add_column('ddosguard_blocks', 'severity_score',   "TINYINT      NULL DEFAULT 0");
CALL ddosguard_add_column('ddosguard_blocks', 'correlated',       "TINYINT(1)   NOT NULL DEFAULT 0");
CALL ddosguard_add_column('ddosguard_blocks', 'correlation_id',   "VARCHAR(64)  NULL");
CALL ddosguard_add_column('ddosguard_blocks', 'source_platform',  "VARCHAR(32)  NULL");
CALL ddosguard_add_column('ddosguard_blocks', 'mitre_technique',  "VARCHAR(16)  NULL");
CALL ddosguard_add_column('ddosguard_blocks', 'updated_at',       "DATETIME     NULL");

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
-- 5. Tabela de threat intelligence / blacklists
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
-- 6. Indices adicionais para performance
-- ----------------------------------------------------------------
DROP PROCEDURE IF EXISTS ddosguard_add_index$$

DELIMITER $$
CREATE PROCEDURE ddosguard_add_index(
    IN tbl VARCHAR(64),
    IN idx VARCHAR(64),
    IN cols VARCHAR(128)
)
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME   = tbl
          AND INDEX_NAME   = idx
    ) THEN
        SET @sql = CONCAT('ALTER TABLE ', tbl, ' ADD INDEX ', idx, ' (', cols, ')');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END$$
DELIMITER ;

CALL ddosguard_add_index('ddosguard_attacks', 'idx_severity_score', 'severity_score');
CALL ddosguard_add_index('ddosguard_attacks', 'idx_correlation_id', 'correlation_id');
CALL ddosguard_add_index('ddosguard_attacks', 'idx_correlated',     'correlated');
CALL ddosguard_add_index('ddosguard_blocks',  'idx_correlation_id', 'correlation_id');
CALL ddosguard_add_index('ddosguard_blocks',  'idx_source_platform','source_platform');

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

-- Limpa as procedures auxiliares
DROP PROCEDURE IF EXISTS ddosguard_add_column;
DROP PROCEDURE IF EXISTS ddosguard_add_index;

SELECT 'Migration v2 SOC concluida com sucesso.' AS status;
