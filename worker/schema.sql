PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  totp_secret TEXT,
  totp_enabled INTEGER NOT NULL DEFAULT 0 CHECK (totp_enabled IN (0,1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  host TEXT NOT NULL,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('http','https','tcp')),
  url TEXT,
  host TEXT,
  port INTEGER,
  interval_seconds INTEGER NOT NULL DEFAULT 60,
  timeout_ms INTEGER NOT NULL DEFAULT 5000,
  expected_status INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS checks_target_idx ON checks(target_id);
CREATE TABLE IF NOT EXISTS check_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  check_id INTEGER NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
  ok INTEGER NOT NULL CHECK (ok IN (0,1)),
  latency_ms INTEGER,
  error TEXT,
  checked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS results_check_time_idx ON check_results(check_id, checked_at DESC);
CREATE TABLE IF NOT EXISTS agent_heartbeats (
  agent_id TEXT PRIMARY KEY,
  ip TEXT,
  metrics TEXT NOT NULL DEFAULT '{}',
  certificates TEXT,
  received_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_rate_limits (
  rate_key TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS login_rate_expiry_idx ON login_rate_limits(expires_at);
CREATE TABLE IF NOT EXISTS alert_states (
  check_id INTEGER PRIMARY KEY REFERENCES checks(id) ON DELETE CASCADE,
  state TEXT NOT NULL DEFAULT 'unknown' CHECK (state IN ('unknown','up','down')),
  changed_at TEXT NOT NULL
);
