
-- name: create-blacklist
BEGIN;
CREATE TABLE IF NOT EXISTS blacklist (
  IPAddress TEXT NOT NULL,
  EntryDate TEXT NOT NULL,
  LastSeen TEXT NOT NULL,
  Reason TEXT NOT NULL,
  LogicalDelete INT NOT NULL
);
CREATE INDEX IF NOT EXISTS blacklist_1 ON blacklist (LogicalDelete, IPAddress);
COMMIT;

-- name: create-whitelist
BEGIN;
CREATE TABLE IF NOT EXISTS whitelist (
  IPAddress TEXT NOT NULL,
  EntryDate TEXT NOT NULL,
  Reason TEXT NOT NULL,
  LogicalDelete INT NOT NULL
);s
CREATE INDEX IF NOT EXISTS whitelist_1 ON whitelist (LogicalDelete, IPAddress);
COMMIT;

-- name: create-rules
BEGIN;
CREATE TABLE IF NOT EXISTS rules (
  RuleNum INT NOT NULL,
  Zone TEXT NOT NULL,
  FromIP TEXT NOT NULL,
  FromPort TEXT NOT NULL,
  ToIP TEXT NOT NULL,
  ToPort TEXT NOT NULL
);
COMMIT;

-- name: create-opts
BEGIN;
CREATE TABLE IF NOT EXISTS ruleopts (
  Inbound TEXT NOT NULL,
  Outbound TEXT NOT NULL
);
INSERT INTO ruleopts VALUES ("allow", "deny");
COMMIT;
