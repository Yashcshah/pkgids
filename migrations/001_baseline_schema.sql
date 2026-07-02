-- pkgids behavioral baseline schema
-- Run this once in the Supabase SQL editor (Dashboard → SQL Editor → New query)

-- ── packages ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS packages (
    id            BIGSERIAL PRIMARY KEY,
    ecosystem     TEXT        NOT NULL,
    name          TEXT        NOT NULL,
    version       TEXT        NOT NULL,
    artifact_hash TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (ecosystem, name, version)
);

ALTER TABLE packages ENABLE ROW LEVEL SECURITY;

CREATE POLICY "pkgids_packages_all" ON packages
    FOR ALL TO anon, authenticated
    USING (true) WITH CHECK (true);


-- ── behavior_profiles ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS behavior_profiles (
    id                       BIGSERIAL   PRIMARY KEY,
    package_id               BIGINT      NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    run_dir                  TEXT,
    run_ts                   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Phase outcomes
    install_status           TEXT,
    install_exit_code        INTEGER,
    install_duration_secs    REAL,
    import_status            TEXT,
    import_exit_code         INTEGER,
    import_duration_secs     REAL,

    -- Network features (derived from network.jsonl)
    network_domains          TEXT[]      NOT NULL DEFAULT '{}',
    network_hosts            TEXT[]      NOT NULL DEFAULT '{}',
    network_ports            INTEGER[]   NOT NULL DEFAULT '{}',

    -- Process / file features (derived from telemetry.jsonl + process_activity)
    subprocess_count         INTEGER     NOT NULL DEFAULT 0,
    suspicious_exec_count    INTEGER     NOT NULL DEFAULT 0,
    sensitive_file_count     INTEGER     NOT NULL DEFAULT 0,
    shell_cmd_count          INTEGER     NOT NULL DEFAULT 0,
    new_file_count           INTEGER     NOT NULL DEFAULT 0,
    any_suspicious           BOOLEAN     NOT NULL DEFAULT FALSE,

    -- Full JSONB activity blobs for deep queries
    install_process_activity JSONB,
    import_process_activity  JSONB,

    -- Verdict from validate.predict()
    prediction               TEXT
);

ALTER TABLE behavior_profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "pkgids_profiles_all" ON behavior_profiles
    FOR ALL TO anon, authenticated
    USING (true) WITH CHECK (true);

CREATE INDEX IF NOT EXISTS behavior_profiles_package_id_idx
    ON behavior_profiles (package_id);

CREATE INDEX IF NOT EXISTS behavior_profiles_run_ts_idx
    ON behavior_profiles (run_ts DESC);


-- ── behavior_diffs ────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS behavior_diffs (
    id              BIGSERIAL   PRIMARY KEY,
    ecosystem       TEXT        NOT NULL,
    name            TEXT        NOT NULL,
    from_version    TEXT        NOT NULL,
    to_version      TEXT        NOT NULL,
    from_profile_id BIGINT      REFERENCES behavior_profiles(id) ON DELETE SET NULL,
    to_profile_id   BIGINT      REFERENCES behavior_profiles(id) ON DELETE SET NULL,
    verdict         TEXT        NOT NULL DEFAULT 'clean',
    is_suspicious   BOOLEAN     NOT NULL DEFAULT FALSE,
    findings        JSONB       NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (ecosystem, name, from_version, to_version)
);

ALTER TABLE behavior_diffs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "pkgids_diffs_all" ON behavior_diffs
    FOR ALL TO anon, authenticated
    USING (true) WITH CHECK (true);

CREATE INDEX IF NOT EXISTS behavior_diffs_name_idx
    ON behavior_diffs (ecosystem, name);
