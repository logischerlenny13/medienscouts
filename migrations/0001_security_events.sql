-- Minimales Protokoll für sicherheitsrelevante Anmeldeereignisse.
-- Es werden bewusst keine rohen IP-Adressen gespeichert.
CREATE TABLE IF NOT EXISTS security_events (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  country_code TEXT NOT NULL,
  country_name TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('login', 'suspicious_access')),
  decision TEXT NOT NULL CHECK (decision IN ('allowed', 'review')),
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_security_events_created_at
  ON security_events(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_user_id
  ON security_events(user_id);
