-- Run once for databases initialized with the original MVP schema.
ALTER TABLE agent_heartbeats ADD COLUMN certificates TEXT;
