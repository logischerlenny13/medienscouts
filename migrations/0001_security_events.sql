-- Eindeutige IP-Liste für das geschützte Admin-Terminal.
-- Eine IP wird nur einmal gespeichert; erneute Aufrufe aktualisieren den Datensatz.
-- IP-Adressen sind personenbezogene Daten: Zugriff und Aufbewahrungsdauer
-- müssen in der Anwendung begrenzt und transparent geregelt werden.
CREATE TABLE IF NOT EXISTS ip_addresses (
  ip_address TEXT PRIMARY KEY,
  country_code TEXT NOT NULL,
  country_name TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  check_count INTEGER NOT NULL DEFAULT 1,
  last_event_type TEXT NOT NULL CHECK (last_event_type IN ('login', 'suspicious_access')),
  decision TEXT NOT NULL CHECK (decision IN ('allowed', 'review'))
);

CREATE INDEX IF NOT EXISTS idx_ip_addresses_last_seen
  ON ip_addresses(last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_ip_addresses_decision
  ON ip_addresses(decision);
