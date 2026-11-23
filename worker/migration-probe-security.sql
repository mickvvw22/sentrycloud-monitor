-- Apply once to an existing SentryCloud Monitor D1 database before deploying
-- the outbound-only probe protocol. Existing heartbeats remain readable; each
-- new probe must be registered to receive an individually revocable token.
CREATE TABLE IF NOT EXISTS probes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_seen_at TEXT,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS probes_active_idx ON probes(revoked_at,last_seen_at);
CREATE TABLE IF NOT EXISTS probe_task_leases (
  check_id INTEGER PRIMARY KEY REFERENCES checks(id) ON DELETE CASCADE,
  probe_id TEXT NOT NULL REFERENCES probes(id),
  task_token TEXT NOT NULL,
  lease_until INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  completed_at TEXT
);
CREATE INDEX IF NOT EXISTS probe_task_lease_expiry_idx ON probe_task_leases(lease_until,completed_at);
CREATE TABLE IF NOT EXISTS certificate_probe_states (
  agent_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  state TEXT NOT NULL,
  changed_at TEXT NOT NULL,
  PRIMARY KEY (agent_id, hostname)
);
