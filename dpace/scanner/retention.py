"""
dpace.scanner.retention
-----------------------
Retention Auditor

Checks file timestamps against retention windows defined in mandates.json
and returns policy violations for any files that exceed their allowed
storage duration.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from dpace.scanner.discovery import FileAsset

logger = logging.getLogger(__name__)


@dataclass
class RetentionViolation:
    """A single retention policy violation."""

    file_path: Path
    framework: str
    mandate: str
    violation_type: str        # e.g. 'RETENTION_EXCEEDED'
    severity: str
    age_days: int
    limit_days: int
    detail: str
    detected_at: datetime


class RetentionAuditor:
    """
    Evaluates file age against per-framework retention windows.

    Parameters
    ----------
    retention_policies:
        List of retention policy dicts from mandates.json.
    """

    def __init__(self, retention_policies: list) -> None:
        self._policies = retention_policies

    def audit(
        self,
        asset: FileAsset,
        classification: str,
        matched_frameworks: List[str],
    ) -> List[RetentionViolation]:
        """
        Check *asset* against all relevant retention policies.

        Parameters
        ----------
        asset:
            The file asset to audit.
        classification:
            The asset's resolved classification label.
        matched_frameworks:
            Frameworks detected during regex scan (e.g. ['PCI', 'GDPR']).

        Returns
        -------
        List[RetentionViolation]
            Empty list if no violations found.
        """
        violations: List[RetentionViolation] = []
        now = datetime.now(tz=timezone.utc)

        # Use modified_at as the reference timestamp; fall back to created_at
        ref_ts: Optional[datetime] = asset.modified_at or asset.created_at
        if ref_ts is None:
            logger.warning("Cannot audit retention for %s: no timestamp.", asset.path)
            return violations

        age_days = (now - ref_ts).days

        for policy in self._policies:
            fw = policy.get("framework", "")
            # Only audit against frameworks that are relevant to this asset.
            # A file with no sensitive-data matches holds no personal or
            # cardholder data, so no retention mandate applies to it.
            if fw not in matched_frameworks:
                continue

            limit = policy.get("default_retention_days", 365)
            severity = policy.get("violation_severity", "HIGH")
            mandate = policy.get("mandate", fw)

            if age_days > limit:
                detail = (
                    f"File age {age_days} days exceeds {fw} retention limit "
                    f"of {limit} days. Classification: {classification}."
                )
                violations.append(
                    RetentionViolation(
                        file_path=asset.path,
                        framework=fw,
                        mandate=mandate,
                        violation_type="RETENTION_EXCEEDED",
                        severity=severity,
                        age_days=age_days,
                        limit_days=limit,
                        detail=detail,
                        detected_at=now,
                    )
                )
                logger.info(
                    "[VIOLATION] %s | %s | age=%d days > limit=%d days",
                    fw,
                    asset.path.name,
                    age_days,
                    limit,
                )

        return violations
