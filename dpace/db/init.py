"""
dpace.db.init
-------------
SQLite database initialisation.

Run directly to create (or migrate) dpace.db:

    python -m dpace.db.init
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path(__file__).parent / "dpace.db"

SCHEMA_SQL = """
-- DELETE (rollback journal) rather than WAL on purpose: in WAL mode committed
-- rows live in a separate dpace.db-wal file until a checkpoint, so Grafana --
-- which bind-mounts the database read-only -- would read a stale or empty DB.
-- DELETE mode keeps dpace.db self-contained after every commit.
PRAGMA journal_mode = DELETE;
PRAGMA foreign_keys = ON;

-- -----------------------------------------------------------------------
-- asset_inventory  (one row per discovered file)
-- -----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asset_inventory (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path       TEXT    NOT NULL UNIQUE,
    file_name       TEXT    NOT NULL,
    file_ext        TEXT,
    size_bytes      INTEGER,
    created_at      TEXT,           -- ISO-8601 UTC
    modified_at     TEXT,           -- ISO-8601 UTC
    scanned_at      TEXT    NOT NULL,
    classification  TEXT    CHECK(classification IN (
                                'Restricted','Confidential','Internal','Unclassified'
                            ))
);

CREATE INDEX IF NOT EXISTS idx_asset_classification
    ON asset_inventory(classification);
CREATE INDEX IF NOT EXISTS idx_asset_scanned_at
    ON asset_inventory(scanned_at);

-- -----------------------------------------------------------------------
-- scan_results  (one row per pattern match per file)
-- -----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id        INTEGER NOT NULL REFERENCES asset_inventory(id) ON DELETE CASCADE,
    pattern_id      TEXT    NOT NULL,
    pattern_name    TEXT    NOT NULL,
    match_count     INTEGER NOT NULL DEFAULT 0,
    severity        TEXT    CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    framework       TEXT,           -- pipe-separated: 'PCI|GDPR'
    nist_controls   TEXT,           -- pipe-separated control IDs
    gdpr_articles   TEXT,
    pci_requirements TEXT,
    scanned_at      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_asset_id
    ON scan_results(asset_id);
CREATE INDEX IF NOT EXISTS idx_scan_severity
    ON scan_results(severity);

-- -----------------------------------------------------------------------
-- policy_violations  (one row per detected violation)
-- -----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_violations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id        INTEGER REFERENCES asset_inventory(id) ON DELETE CASCADE,
    violation_type  TEXT    NOT NULL,
    mandate         TEXT    NOT NULL,
    framework       TEXT    NOT NULL,
    severity        TEXT    CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    age_days        INTEGER,
    limit_days      INTEGER,
    detail          TEXT,
    detected_at     TEXT    NOT NULL,
    resolved_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_violation_framework
    ON policy_violations(framework);
CREATE INDEX IF NOT EXISTS idx_violation_severity
    ON policy_violations(severity);
CREATE INDEX IF NOT EXISTS idx_violation_resolved
    ON policy_violations(resolved_at);
"""


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """
    Open (or create) the SQLite database at *db_path* and apply the schema.

    Returns an open :class:`sqlite3.Connection`.
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    logger.info("Database initialised at %s", db_path)
    return conn


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    init_db()
    print("dpace.db ready.")
