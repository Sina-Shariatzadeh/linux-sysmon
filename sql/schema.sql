-- ===========================================================================
-- sysmon PostgreSQL schema
-- Apply with:  psql -d sysmon -f sql/schema.sql   (idempotent)
--         or:  sysmond --init-db sql/schema.sql
-- ===========================================================================

-- One row per collection cycle. Child tables reference it so a whole frame
-- can be joined back together (or purged) by snapshot_id.
CREATE TABLE IF NOT EXISTS system_metrics (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL,
    hostname        TEXT        NOT NULL,
    cpu_total_pct   REAL        NOT NULL,
    load1           REAL,
    load5           REAL,
    load15          REAL,
    mem_used_pct    REAL,
    swap_used_pct   REAL,
    process_count   INTEGER,
    running_count   INTEGER,
    thread_count    INTEGER,
    tcp_established INTEGER,
    uptime_s        DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_system_metrics_ts ON system_metrics (ts);
CREATE INDEX IF NOT EXISTS idx_system_metrics_host_ts ON system_metrics (hostname, ts);

CREATE TABLE IF NOT EXISTS cpu_metrics (
    id          BIGSERIAL PRIMARY KEY,
    snapshot_id BIGINT      NOT NULL REFERENCES system_metrics (id) ON DELETE CASCADE,
    ts          TIMESTAMPTZ NOT NULL,
    core        SMALLINT    NOT NULL,
    usage_pct   REAL        NOT NULL,
    user_pct    REAL,
    system_pct  REAL,
    iowait_pct  REAL
);
CREATE INDEX IF NOT EXISTS idx_cpu_metrics_ts ON cpu_metrics (ts);
CREATE INDEX IF NOT EXISTS idx_cpu_metrics_snapshot ON cpu_metrics (snapshot_id);

CREATE TABLE IF NOT EXISTS memory_metrics (
    snapshot_id   BIGINT PRIMARY KEY REFERENCES system_metrics (id) ON DELETE CASCADE,
    ts            TIMESTAMPTZ NOT NULL,
    total_kb      BIGINT NOT NULL,
    used_kb       BIGINT NOT NULL,
    available_kb  BIGINT,
    buffers_kb    BIGINT,
    cached_kb     BIGINT,
    swap_total_kb BIGINT,
    swap_used_kb  BIGINT
);
CREATE INDEX IF NOT EXISTS idx_memory_metrics_ts ON memory_metrics (ts);

-- Disk I/O rates per physical device.
CREATE TABLE IF NOT EXISTS disk_metrics (
    id          BIGSERIAL PRIMARY KEY,
    snapshot_id BIGINT      NOT NULL REFERENCES system_metrics (id) ON DELETE CASCADE,
    ts          TIMESTAMPTZ NOT NULL,
    device      TEXT        NOT NULL,
    read_bps    DOUBLE PRECISION,
    write_bps   DOUBLE PRECISION,
    reads_ps    DOUBLE PRECISION,
    writes_ps   DOUBLE PRECISION,
    util_pct    REAL
);
CREATE INDEX IF NOT EXISTS idx_disk_metrics_ts ON disk_metrics (ts);
CREATE INDEX IF NOT EXISTS idx_disk_metrics_snapshot ON disk_metrics (snapshot_id);

-- Storage usage per mounted filesystem.
CREATE TABLE IF NOT EXISTS filesystem_metrics (
    id          BIGSERIAL PRIMARY KEY,
    snapshot_id BIGINT      NOT NULL REFERENCES system_metrics (id) ON DELETE CASCADE,
    ts          TIMESTAMPTZ NOT NULL,
    mount_point TEXT        NOT NULL,
    device      TEXT,
    fs_type     TEXT,
    total_bytes BIGINT,
    used_bytes  BIGINT,
    used_pct    REAL
);
CREATE INDEX IF NOT EXISTS idx_filesystem_metrics_ts ON filesystem_metrics (ts);
CREATE INDEX IF NOT EXISTS idx_filesystem_metrics_snapshot ON filesystem_metrics (snapshot_id);

CREATE TABLE IF NOT EXISTS network_metrics (
    id          BIGSERIAL PRIMARY KEY,
    snapshot_id BIGINT      NOT NULL REFERENCES system_metrics (id) ON DELETE CASCADE,
    ts          TIMESTAMPTZ NOT NULL,
    iface       TEXT        NOT NULL,
    rx_bps      DOUBLE PRECISION,
    tx_bps      DOUBLE PRECISION,
    rx_pps      DOUBLE PRECISION,
    tx_pps      DOUBLE PRECISION,
    rx_errors   BIGINT,
    tx_errors   BIGINT
);
CREATE INDEX IF NOT EXISTS idx_network_metrics_ts ON network_metrics (ts);
CREATE INDEX IF NOT EXISTS idx_network_metrics_snapshot ON network_metrics (snapshot_id);

-- Top-N processes, sampled every `process_store_every` frames.
CREATE TABLE IF NOT EXISTS processes (
    id          BIGSERIAL PRIMARY KEY,
    snapshot_id BIGINT      NOT NULL REFERENCES system_metrics (id) ON DELETE CASCADE,
    ts          TIMESTAMPTZ NOT NULL,
    pid         INTEGER     NOT NULL,
    ppid        INTEGER,
    name        TEXT        NOT NULL,
    username    TEXT,
    state       CHAR(1),
    cpu_pct     REAL,
    rss_kb      BIGINT,
    threads     INTEGER,
    exe         TEXT,
    cmdline     TEXT
);
CREATE INDEX IF NOT EXISTS idx_processes_ts ON processes (ts);
CREATE INDEX IF NOT EXISTS idx_processes_name_ts ON processes (name, ts);
CREATE INDEX IF NOT EXISTS idx_processes_snapshot ON processes (snapshot_id);

CREATE TABLE IF NOT EXISTS security_events (
    id        BIGSERIAL PRIMARY KEY,
    ts        TIMESTAMPTZ NOT NULL,
    hostname  TEXT        NOT NULL,
    severity  TEXT        NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    category  TEXT        NOT NULL,
    source    TEXT        NOT NULL,
    message   TEXT        NOT NULL,
    pid       INTEGER,
    details   JSONB       NOT NULL DEFAULT '{}'::jsonb,
    search    TSVECTOR GENERATED ALWAYS AS
              (to_tsvector('simple', category || ' ' || source || ' ' || message)) STORED
);
CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events (ts);
CREATE INDEX IF NOT EXISTS idx_security_events_category ON security_events (category, ts);
CREATE INDEX IF NOT EXISTS idx_security_events_search ON security_events USING GIN (search);

CREATE TABLE IF NOT EXISTS alerts (
    id           BIGSERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ NOT NULL,
    hostname     TEXT        NOT NULL,
    severity     TEXT        NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    metric       TEXT        NOT NULL,
    value        DOUBLE PRECISION,
    threshold    DOUBLE PRECISION,
    message      TEXT        NOT NULL,
    resolved     BOOLEAN     NOT NULL DEFAULT FALSE,
    acknowledged BOOLEAN     NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts);

-- ---------------------------------------------------------------------------
-- Convenience views for ad-hoc analytics
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_hourly_system AS
SELECT hostname,
       date_trunc('hour', ts)       AS hour,
       avg(cpu_total_pct)::REAL     AS avg_cpu,
       max(cpu_total_pct)::REAL     AS max_cpu,
       avg(mem_used_pct)::REAL      AS avg_mem,
       max(mem_used_pct)::REAL      AS max_mem,
       avg(load1)::REAL             AS avg_load1,
       count(*)                     AS samples
FROM system_metrics
GROUP BY hostname, date_trunc('hour', ts);

CREATE OR REPLACE VIEW v_event_log AS
SELECT 'security'::TEXT AS kind, id, ts, hostname, severity, category AS subject, message
FROM security_events
UNION ALL
SELECT 'alert'::TEXT, id, ts, hostname, severity, metric, message
FROM alerts;
