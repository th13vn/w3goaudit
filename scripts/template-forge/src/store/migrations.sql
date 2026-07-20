-- template-forge durable state. All pipeline progress lives here so any run
-- can pause and resume without re-fetching or re-spending on opencode.

CREATE TABLE IF NOT EXISTS run (
  id          TEXT PRIMARY KEY,
  kind        TEXT NOT NULL,            -- fetch | forge | improve
  started_at  TEXT NOT NULL,
  status      TEXT NOT NULL,            -- running | paused | done | failed
  args_json   TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS fetch_cursor (
  source      TEXT PRIMARY KEY,         -- defihacklabs | solodit
  cursor_json TEXT NOT NULL DEFAULT '{}',
  updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS candidate (
  id           TEXT PRIMARY KEY,
  kind         TEXT NOT NULL,           -- incident | finding
  source_ref   TEXT NOT NULL,
  title        TEXT NOT NULL,
  severity     TEXT NOT NULL,
  bucket       TEXT,
  status       TEXT NOT NULL,           -- CandidateStatus
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  UNIQUE (kind, source_ref)
);

CREATE INDEX IF NOT EXISTS idx_candidate_status ON candidate (status);

-- Resume cache: one row per (candidate, stage, attempt). A completed stage's
-- output_json is reused on resume instead of re-running the stage.
CREATE TABLE IF NOT EXISTS stage_result (
  candidate_id TEXT NOT NULL,
  stage        TEXT NOT NULL,
  attempt      INTEGER NOT NULL DEFAULT 0,
  status       TEXT NOT NULL,           -- ok | fail
  output_json  TEXT,
  machine_log  TEXT,
  created_at   TEXT NOT NULL,
  PRIMARY KEY (candidate_id, stage, attempt)
);

CREATE TABLE IF NOT EXISTS variant_result (
  candidate_id TEXT NOT NULL,
  variant_id   TEXT NOT NULL,
  kind         TEXT NOT NULL,           -- recall | precision
  expected     INTEGER NOT NULL,        -- expected fire (1/0)
  actual       INTEGER NOT NULL,        -- actual fire (1/0)
  passed       INTEGER NOT NULL,
  round        INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT NOT NULL,
  PRIMARY KEY (candidate_id, variant_id, round)
);

CREATE TABLE IF NOT EXISTS provenance (
  candidate_id TEXT PRIMARY KEY,
  links_json   TEXT NOT NULL DEFAULT '[]',
  cwe          TEXT NOT NULL DEFAULT '[]',
  owasp_sc     TEXT NOT NULL DEFAULT '[]',
  confidence   TEXT NOT NULL,
  dedup_of     TEXT
);

-- Single-writer advisory lock. One row, taken/released by a run.
CREATE TABLE IF NOT EXISTS forge_lock (
  id        INTEGER PRIMARY KEY CHECK (id = 1),
  owner     TEXT,
  taken_at  TEXT
);
INSERT OR IGNORE INTO forge_lock (id, owner, taken_at) VALUES (1, NULL, NULL);
