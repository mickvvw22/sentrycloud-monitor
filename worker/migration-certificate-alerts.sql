-- Run once on databases that already have the certificates column.
CREATE TABLE IF NOT EXISTS certificate_alert_states (
  agent_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('ok','warning','expired','missing')),
  days_remaining INTEGER,
  changed_at TEXT NOT NULL,
  PRIMARY KEY (agent_id, hostname)
);
