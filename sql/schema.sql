-- =====================================================================
-- DDoS Guard - Schema de banco de dados auxiliar
-- =====================================================================
-- Este módulo usa o MESMO banco de dados do Zabbix (zabbix_server.conf
-- -> DBName) para guardar os eventos detalhados (IP de origem, país,
-- tipo de ataque, contagem de tentativas, bloqueios de firewall/AV)
-- que alimentam os widgets do dashboard em tempo real.
--
-- Por quê uma tabela própria e não apenas "history_text" do Zabbix?
-- Porque os widgets precisam fazer agregações (GROUP BY país, IP,
-- tipo de ataque, ordenação por quantidade de tentativas) com
-- performance e índices adequados — o history nativo do Zabbix não
-- foi desenhado para esse tipo de consulta analítica.
--
-- Execute este script no banco do Zabbix (MySQL/MariaDB ou PostgreSQL,
-- existem duas versões abaixo, comentadas).
-- =====================================================================


-- ===================== MySQL / MariaDB ==================================

CREATE TABLE IF NOT EXISTS ddosguard_attacks (
    attack_id       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    hostid          BIGINT UNSIGNED NOT NULL,
    src_ip          VARCHAR(45)     NOT NULL,
    country_code    VARCHAR(2)      DEFAULT NULL,
    country_name    VARCHAR(100)    DEFAULT NULL,
    city            VARCHAR(100)    DEFAULT NULL,
    asn             VARCHAR(100)    DEFAULT NULL,
    attack_type     VARCHAR(50)     NOT NULL,        -- SYN_FLOOD, UDP_FLOOD, HTTP_FLOOD, BRUTE_FORCE, PORT_SCAN, MALWARE, ...
    target_port     INT             DEFAULT NULL,
    protocol        VARCHAR(10)     DEFAULT NULL,
    attempts        INT UNSIGNED    NOT NULL DEFAULT 1,
    severity        TINYINT         NOT NULL DEFAULT 2, -- 0 info,1 low,2 medium,3 high,4 critical
    blocked         TINYINT(1)      NOT NULL DEFAULT 0,
    blocked_by      VARCHAR(20)     DEFAULT NULL,     -- firewall | antivirus | ids | none
    source_tool     VARCHAR(50)     DEFAULT NULL,     -- iptables, ufw, fail2ban, suricata, clamav...
    raw_data        TEXT            DEFAULT NULL,     -- JSON original recebido
    first_seen      DATETIME        NOT NULL,
    last_seen       DATETIME        NOT NULL,
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_dg_attacks_hostid (hostid),
    KEY idx_dg_attacks_srcip (src_ip),
    KEY idx_dg_attacks_country (country_code),
    KEY idx_dg_attacks_type (attack_type),
    KEY idx_dg_attacks_lastseen (last_seen),
    KEY idx_dg_attacks_blocked (blocked, blocked_by)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ddosguard_blocks (
    block_id        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    hostid          BIGINT UNSIGNED NOT NULL,
    src_ip          VARCHAR(45)     NOT NULL,
    country_code    VARCHAR(2)      DEFAULT NULL,
    country_name    VARCHAR(100)    DEFAULT NULL,
    block_source    VARCHAR(20)     NOT NULL,     -- firewall | antivirus
    tool            VARCHAR(50)     DEFAULT NULL, -- iptables, ufw, nftables, fail2ban, clamav, defender...
    rule_or_signature VARCHAR(255)  DEFAULT NULL, -- regra do firewall ou nome da assinatura do malware
    target_port     INT             DEFAULT NULL,
    protocol        VARCHAR(10)     DEFAULT NULL,
    reason          VARCHAR(255)    DEFAULT NULL,
    file_path       VARCHAR(500)    DEFAULT NULL, -- preenchido apenas para bloqueios de antivírus
    raw_data        TEXT            DEFAULT NULL,
    event_time      DATETIME        NOT NULL,
    created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_dg_blocks_hostid (hostid),
    KEY idx_dg_blocks_srcip (src_ip),
    KEY idx_dg_blocks_source (block_source),
    KEY idx_dg_blocks_time (event_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ddosguard_host_status (
    hostid          BIGINT UNSIGNED NOT NULL PRIMARY KEY,
    has_firewall    TINYINT(1)      NOT NULL DEFAULT 0,
    firewall_name   VARCHAR(100)    DEFAULT NULL,
    has_antivirus   TINYINT(1)      NOT NULL DEFAULT 0,
    antivirus_name  VARCHAR(100)    DEFAULT NULL,
    last_heartbeat  DATETIME        DEFAULT NULL,
    updated_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- ===================== PostgreSQL (alternativa) =========================
-- Descomente e use este bloco caso o backend do Zabbix seja PostgreSQL.
--
-- CREATE TABLE IF NOT EXISTS ddosguard_attacks (
--     attack_id       BIGSERIAL PRIMARY KEY,
--     hostid          BIGINT NOT NULL,
--     src_ip          VARCHAR(45) NOT NULL,
--     country_code    VARCHAR(2),
--     country_name    VARCHAR(100),
--     city            VARCHAR(100),
--     asn             VARCHAR(100),
--     attack_type     VARCHAR(50) NOT NULL,
--     target_port     INT,
--     protocol        VARCHAR(10),
--     attempts        INT NOT NULL DEFAULT 1,
--     severity        SMALLINT NOT NULL DEFAULT 2,
--     blocked         SMALLINT NOT NULL DEFAULT 0,
--     blocked_by      VARCHAR(20),
--     source_tool     VARCHAR(50),
--     raw_data        TEXT,
--     first_seen      TIMESTAMP NOT NULL,
--     last_seen       TIMESTAMP NOT NULL,
--     created_at      TIMESTAMP NOT NULL DEFAULT NOW()
-- );
-- CREATE INDEX idx_dg_attacks_hostid ON ddosguard_attacks (hostid);
-- CREATE INDEX idx_dg_attacks_srcip ON ddosguard_attacks (src_ip);
-- CREATE INDEX idx_dg_attacks_country ON ddosguard_attacks (country_code);
-- CREATE INDEX idx_dg_attacks_type ON ddosguard_attacks (attack_type);
-- CREATE INDEX idx_dg_attacks_lastseen ON ddosguard_attacks (last_seen);
--
-- CREATE TABLE IF NOT EXISTS ddosguard_blocks (
--     block_id        BIGSERIAL PRIMARY KEY,
--     hostid          BIGINT NOT NULL,
--     src_ip          VARCHAR(45) NOT NULL,
--     country_code    VARCHAR(2),
--     country_name    VARCHAR(100),
--     block_source    VARCHAR(20) NOT NULL,
--     tool            VARCHAR(50),
--     rule_or_signature VARCHAR(255),
--     target_port     INT,
--     protocol        VARCHAR(10),
--     reason          VARCHAR(255),
--     file_path       VARCHAR(500),
--     raw_data        TEXT,
--     event_time      TIMESTAMP NOT NULL,
--     created_at      TIMESTAMP NOT NULL DEFAULT NOW()
-- );
-- CREATE INDEX idx_dg_blocks_hostid ON ddosguard_blocks (hostid);
-- CREATE INDEX idx_dg_blocks_source ON ddosguard_blocks (block_source);
-- CREATE INDEX idx_dg_blocks_time ON ddosguard_blocks (event_time);
--
-- CREATE TABLE IF NOT EXISTS ddosguard_host_status (
--     hostid          BIGINT PRIMARY KEY,
--     has_firewall    SMALLINT NOT NULL DEFAULT 0,
--     firewall_name   VARCHAR(100),
--     has_antivirus   SMALLINT NOT NULL DEFAULT 0,
--     antivirus_name  VARCHAR(100),
--     last_heartbeat  TIMESTAMP,
--     updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
-- );
