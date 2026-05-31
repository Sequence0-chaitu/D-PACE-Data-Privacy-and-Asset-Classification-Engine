"""
dpace.db.models
---------------
Thin database access helpers for D-PACE tables.
All writes go through these helpers to keep SQL out of business logic.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from dpace.scanner.discovery import FileAsset
from dpace.scanner.regex_engine import PatternMatch
from dpace.scanner.retention import RetentionViolation


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# asset_inventory
# ---------------------------------------------------------------------------

def upsert_asset(conn: sqlite3.Connection, asset: FileAsset, classification: str) -> int:
    """Insert or replace an asset record. Returns the row id."""
    sql = """
        INSERT INTO asset_inventory
            (file_path, file_name, file_ext, size_bytes, created_at, modified_at,
             scanned_at, classification)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(file_path) DO UPDATE SET
            file_name      = excluded.file_name,
            file_ext       = excluded.file_ext,
            size_bytes     = excluded.size_bytes,
            created_at     = excluded.created_at,
            modified_at    = excluded.modified_at,
            scanned_at     = excluded.scanned_at,
            classification = excluded.classification
    """
    cur = conn.execute(
        sql,
        (
            str(asset.path),
            asset.file_name,
            asset.extension,
            asset.size_bytes,
            asset.created_at.isoformat() if asset.created_at else None,
            asset.modified_at.isoformat() if asset.modified_at else None,
            _now(),
            classification,
        ),
    )
    conn.commit()
    # Fetch the id for this path
    row = conn.execute(
        "SELECT id FROM asset_inventory WHERE file_path = ?", (str(asset.path),)
    ).fetchone()
    return row["id"]


# ---------------------------------------------------------------------------
# scan_results
# ---------------------------------------------------------------------------

def insert_scan_results(
    conn: sqlite3.Connection, asset_id: int, matches: List[PatternMatch]
) -> None:
    """Bulk-insert pattern match records for *asset_id*."""
    now = _now()
    rows = [
        (
            asset_id,
            m.pattern_id,
            m.pattern_name,
            m.match_count,
            m.severity,
            "|".join(m.frameworks),
            "|".join(m.nist_controls),
            "|".join(m.gdpr_articles),
            "|".join(m.pci_requirements),
            now,
        )
        for m in matches
    ]
    conn.executemany(
        """
        INSERT INTO scan_results
            (asset_id, pattern_id, pattern_name, match_count, severity,
             framework, nist_controls, gdpr_articles, pci_requirements, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()


# ---------------------------------------------------------------------------
# policy_violations
# ---------------------------------------------------------------------------

def insert_violations(
    conn: sqlite3.Connection,
    asset_id: int,
    violations: List[RetentionViolation],
) -> None:
    """Insert retention (and other) violations."""
    now = _now()
    rows = [
        (
            asset_id,
            v.violation_type,
            v.mandate,
            v.framework,
            v.severity,
            v.age_days,
            v.limit_days,
            v.detail,
            v.detected_at.isoformat(),
        )
        for v in violations
    ]
    conn.executemany(
        """
        INSERT INTO policy_violations
            (asset_id, violation_type, mandate, framework, severity,
             age_days, limit_days, detail, detected_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Reporting queries
# ---------------------------------------------------------------------------

def classification_summary(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    """Return count of assets per classification level."""
    return conn.execute(
        """
        SELECT classification, COUNT(*) AS count
        FROM asset_inventory
        GROUP BY classification
        ORDER BY count DESC
        """
    ).fetchall()


def active_violations(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    """Return unresolved policy violations with asset context."""
    return conn.execute(
        """
        SELECT
            pv.id,
            ai.file_path,
            ai.file_name,
            pv.framework,
            pv.violation_type,
            pv.severity,
            pv.age_days,
            pv.limit_days,
            pv.mandate,
            pv.detail,
            pv.detected_at
        FROM policy_violations pv
        JOIN asset_inventory ai ON ai.id = pv.asset_id
        WHERE pv.resolved_at IS NULL
        ORDER BY
            CASE pv.severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH'     THEN 2
                WHEN 'MEDIUM'   THEN 3
                WHEN 'LOW'      THEN 4
                ELSE 5
            END,
            pv.detected_at DESC
        """
    ).fetchall()


def compliance_scorecard(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    """Return violation counts grouped by framework and severity."""
    return conn.execute(
        """
        SELECT
            framework,
            severity,
            COUNT(*) AS violation_count,
            SUM(CASE WHEN resolved_at IS NULL THEN 1 ELSE 0 END) AS open_count
        FROM policy_violations
        GROUP BY framework, severity
        ORDER BY framework,
            CASE severity
                WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4
            END
        """
    ).fetchall()
