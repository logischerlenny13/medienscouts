-- Erweitert den Status um "blocked", ohne vorhandene IP-Einträge zu verlieren.
CREATE TABLE ip_addresses_new (
  ip_address TEXT PRIMARY KEY,
  country_code TEXT NOT NULL,
  country_name TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  check_count INTEGER NOT NULL DEFAULT 1,
  last_event_type TEXT NOT NULL CHECK (last_event_type IN ('login', 'suspicious_access')),
  decision TEXT NOT NULL CHECK (decision IN ('allowed', 'review', 'blocked'))
);

INSERT INTO ip_addresses_new (
  ip_address, country_code, country_name, first_seen, last_seen,
  check_count, last_event_type, decision
)
SELECT
  ip_address, country_code, country_name, first_seen, last_seen,
  check_count, last_event_type,
  CASE WHEN decision IN ('allowed', 'review') THEN decision ELSE 'review' END
FROM ip_addresses;

DROP TABLE ip_addresses;
ALTER TABLE ip_addresses_new RENAME TO ip_addresses;

CREATE INDEX IF NOT EXISTS idx_ip_addresses_last_seen
  ON ip_addresses(last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_ip_addresses_decision
  ON ip_addresses(decision);
