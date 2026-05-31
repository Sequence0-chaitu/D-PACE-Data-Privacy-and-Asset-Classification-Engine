"""
dpace.cli
---------
D-PACE Command-Line Interface

Usage examples
--------------
    python -m dpace scan --path /home/user/mock_data/
    python -m dpace scan --path /home/user/mock_data/ --policy rules/mandates.json
    python -m dpace audit --violations-only
    python -m dpace report --format json --out reports/latest.json
    python -m dpace db stats
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

logger = logging.getLogger("dpace")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_policy(policy_path: str | Path) -> dict:
    with open(policy_path, encoding="utf-8") as fh:
        return json.load(fh)


def _get_db(policy: dict) -> object:
    from dpace.db.init import init_db, DEFAULT_DB_PATH
    return init_db(DEFAULT_DB_PATH)


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    from dpace.db.init import init_db, DEFAULT_DB_PATH
    from dpace.db import models
    from dpace.scanner.discovery import discover_files
    from dpace.scanner.regex_engine import RegexEngine
    from dpace.scanner.classifier import classify
    from dpace.scanner.retention import RetentionAuditor

    policy = _load_policy(args.policy)
    conn = init_db(DEFAULT_DB_PATH)
    engine = RegexEngine(policy, max_matches_per_file=policy["scan_settings"]["max_matches_per_file"])
    auditor = RetentionAuditor(policy["retention_policies"])

    scan_cfg = policy["scan_settings"]
    scanned = 0
    violations_total = 0

    print(f"[D-PACE] Scanning: {args.path}")
    print(f"[D-PACE] Policy:   {args.policy}\n")

    for asset in discover_files(
        root=args.path,
        extensions_in_scope=policy["file_extensions_in_scope"],
        extensions_excluded=policy["file_extensions_excluded"],
        max_file_size_mb=scan_cfg["max_file_size_mb"],
        follow_symlinks=scan_cfg["follow_symlinks"],
        scan_hidden=scan_cfg["scan_hidden_files"],
    ):
        matches = engine.scan(asset.content)
        classification = classify(matches)

        matched_frameworks: list = []
        for m in matches:
            matched_frameworks.extend(m.frameworks)
        matched_frameworks = list(set(matched_frameworks))

        asset_id = models.upsert_asset(conn, asset, classification)
        if matches:
            models.insert_scan_results(conn, asset_id, matches)

        violations = auditor.audit(asset, classification, matched_frameworks)
        if violations:
            models.insert_violations(conn, asset_id, violations)
            violations_total += len(violations)

        scanned += 1
        status = f"[{classification[:1]}]"
        flag = " ⚠" if violations else ""
        print(f"  {status} {asset.path.name} ({len(matches)} patterns){flag}")

    print(f"\n[D-PACE] Scan complete. Files: {scanned} | Violations: {violations_total}")
    conn.close()
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    from dpace.db.init import init_db, DEFAULT_DB_PATH
    from dpace.db import models

    conn = init_db(DEFAULT_DB_PATH)
    rows = models.active_violations(conn)

    if not rows:
        print("[D-PACE] No active violations found.")
        conn.close()
        return 0

    print(f"[D-PACE] Active violations: {len(rows)}\n")
    for row in rows:
        print(
            f"  [{row['severity']:8s}] {row['framework']:5s} | "
            f"{row['violation_type']} | "
            f"{row['file_name']} | "
            f"age={row['age_days']}d > limit={row['limit_days']}d"
        )
    conn.close()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from dpace.db.init import init_db, DEFAULT_DB_PATH
    from dpace.db import models

    conn = init_db(DEFAULT_DB_PATH)
    summary = [dict(r) for r in models.classification_summary(conn)]
    violations = [dict(r) for r in models.active_violations(conn)]
    scorecard = [dict(r) for r in models.compliance_scorecard(conn)]

    report = {
        "dpace_report": {
            "classification_summary": summary,
            "active_violations": violations,
            "compliance_scorecard": scorecard,
        }
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if args.format == "json":
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f"[D-PACE] Report written to {out_path}")
    else:
        # CSV — violations only
        import csv
        with open(out_path, "w", newline="", encoding="utf-8") as fh:
            if violations:
                writer = csv.DictWriter(fh, fieldnames=violations[0].keys())
                writer.writeheader()
                writer.writerows(violations)
        print(f"[D-PACE] CSV report written to {out_path}")

    conn.close()
    return 0


def cmd_db_stats(args: argparse.Namespace) -> int:
    from dpace.db.init import init_db, DEFAULT_DB_PATH
    from dpace.db import models

    conn = init_db(DEFAULT_DB_PATH)
    print("[D-PACE] Classification Summary")
    print("  {:<20} {:>8}".format("Classification", "Count"))
    print("  " + "-" * 30)
    for row in models.classification_summary(conn):
        print("  {:<20} {:>8}".format(row["classification"] or "None", row["count"]))

    print()
    print("[D-PACE] Compliance Scorecard")
    print("  {:<8} {:<10} {:>12} {:>10}".format("FW", "Severity", "Total Viol.", "Open"))
    print("  " + "-" * 44)
    for row in models.compliance_scorecard(conn):
        print("  {:<8} {:<10} {:>12} {:>10}".format(
            row["framework"], row["severity"],
            row["violation_count"], row["open_count"]
        ))
    conn.close()
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dpace",
        description="D-PACE — Data Privacy & Asset Classification Engine",
    )
    parser.add_argument(
        "--log-level", default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: WARNING)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Run a full discovery + classification scan")
    p_scan.add_argument("--path", required=True, help="Directory to scan")
    p_scan.add_argument(
        "--policy", default="rules/mandates.json",
        help="Path to mandates.json (default: rules/mandates.json)"
    )

    # audit
    p_audit = sub.add_parser("audit", help="Show retention violations")
    p_audit.add_argument("--violations-only", action="store_true")

    # report
    p_report = sub.add_parser("report", help="Export scan results")
    p_report.add_argument("--format", choices=["json", "csv"], default="json")
    p_report.add_argument("--out", default="reports/dpace_report.json")

    # db
    p_db = sub.add_parser("db", help="Database utilities")
    db_sub = p_db.add_subparsers(dest="db_command", required=True)
    db_sub.add_parser("stats", help="Print database summary")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s  %(name)s  %(levelname)s  %(message)s",
    )

    dispatch = {
        "scan":  cmd_scan,
        "audit": cmd_audit,
        "report": cmd_report,
    }

    if args.command == "db":
        rc = cmd_db_stats(args)
    else:
        rc = dispatch[args.command](args)

    sys.exit(rc)


if __name__ == "__main__":
    main()
