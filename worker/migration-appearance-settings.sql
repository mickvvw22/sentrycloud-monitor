-- Safe additive migration: adds one dashboard-wide appearance record without touching existing data.
CREATE TABLE IF NOT EXISTS appearance_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  config_json TEXT NOT NULL CHECK (length(config_json) <= 50000),
  updated_at TEXT NOT NULL,
  updated_by INTEGER REFERENCES users(id)
);
