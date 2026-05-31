"""
tests/test_scanner.py
---------------------
Unit tests for the D-PACE scanner modules.
"""

import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from dpace.scanner.regex_engine import RegexEngine, PatternMatch
from dpace.scanner.classifier import classify, escalate
from dpace.scanner.retention import RetentionAuditor, RetentionViolation
from dpace.scanner.discovery import FileAsset


# ---------------------------------------------------------------------------
# Minimal policy fixture
# ---------------------------------------------------------------------------

MINIMAL_POLICY = {
    "regex_patterns": [
        {
            "id": "SSN",
            "name": "US Social Security Number",
            "pattern": r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b",
            "classification": "Restricted",
            "severity": "CRITICAL",
            "frameworks": ["GDPR", "NIST"],
            "nist_controls": ["SC-28"],
            "gdpr_articles": ["Art. 9"],
            "pci_requirements": [],
        },
        {
            "id": "CREDIT_CARD_PAN",
            "name": "Payment Card PAN",
            "pattern": r"\b4[0-9]{12}(?:[0-9]{3})?\b",
            "classification": "Restricted",
            "severity": "CRITICAL",
            "frameworks": ["PCI"],
            "nist_controls": [],
            "gdpr_articles": [],
            "pci_requirements": ["Req 3.2"],
        },
        {
            "id": "EMAIL",
            "name": "Email Address",
            "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
            "classification": "Confidential",
            "severity": "MEDIUM",
            "frameworks": ["GDPR"],
            "nist_controls": [],
            "gdpr_articles": ["Art. 4(1)"],
            "pci_requirements": [],
        },
    ],
    "scan_settings": {
        "max_matches_per_file": 1000,
    },
}

RETENTION_POLICIES = [
    {
        "framework": "GDPR",
        "mandate": "GDPR Art. 5(1)(e)",
        "default_retention_days": 365,
        "violation_severity": "HIGH",
    },
    {
        "framework": "PCI",
        "mandate": "PCI DSS Req 9.4.3",
        "default_retention_days": 365,
        "violation_severity": "CRITICAL",
    },
]


# ---------------------------------------------------------------------------
# RegexEngine tests
# ---------------------------------------------------------------------------

class TestRegexEngine:
    def setup_method(self):
        self.engine = RegexEngine(MINIMAL_POLICY)

    def test_detects_ssn(self):
        matches = self.engine.scan("John Smith SSN: 123-45-6789")
        ids = [m.pattern_id for m in matches]
        assert "SSN" in ids

    def test_detects_credit_card(self):
        matches = self.engine.scan("Card: 4111111111111111")
        ids = [m.pattern_id for m in matches]
        assert "CREDIT_CARD_PAN" in ids

    def test_detects_email(self):
        matches = self.engine.scan("Contact: jane.doe@example.com")
        ids = [m.pattern_id for m in matches]
        assert "EMAIL" in ids

    def test_no_match_on_clean_content(self):
        matches = self.engine.scan("The quick brown fox jumps over the lazy dog.")
        assert matches == []

    def test_results_sorted_critical_first(self):
        content = "SSN: 234-56-7890 email: a@b.com 4111111111111111"
        matches = self.engine.scan(content)
        severities = [m.severity for m in matches]
        assert severities[0] == "CRITICAL"

    def test_match_count(self):
        content = "a@b.com c@d.com e@f.com"
        matches = self.engine.scan(content)
        email_match = next(m for m in matches if m.pattern_id == "EMAIL")
        assert email_match.match_count == 3


# ---------------------------------------------------------------------------
# Classifier tests
# ---------------------------------------------------------------------------

class TestClassifier:
    def _make_match(self, severity: str, classification: str) -> PatternMatch:
        return PatternMatch(
            pattern_id="X", pattern_name="X",
            match_count=1, severity=severity,
            classification=classification, frameworks=[],
        )

    def test_no_matches_returns_internal(self):
        assert classify([]) == "Internal"

    def test_critical_returns_restricted(self):
        m = self._make_match("CRITICAL", "Restricted")
        assert classify([m]) == "Restricted"

    def test_two_high_returns_restricted(self):
        m1 = self._make_match("HIGH", "Confidential")
        m2 = self._make_match("HIGH", "Confidential")
        assert classify([m1, m2]) == "Restricted"

    def test_one_high_returns_confidential(self):
        m = self._make_match("HIGH", "Confidential")
        assert classify([m]) == "Confidential"

    def test_medium_only_returns_confidential(self):
        m = self._make_match("MEDIUM", "Confidential")
        assert classify([m]) == "Confidential"

    def test_escalate(self):
        assert escalate("Internal", "Restricted") == "Restricted"
        assert escalate("Restricted", "Internal") == "Restricted"
        assert escalate("Confidential", "Confidential") == "Confidential"


# ---------------------------------------------------------------------------
# Retention Auditor tests
# ---------------------------------------------------------------------------

class TestRetentionAuditor:
    def _make_asset(self, age_days: int) -> FileAsset:
        now = datetime.now(tz=timezone.utc)
        modified = now - timedelta(days=age_days)
        return FileAsset(
            path=Path("/tmp/test.csv"),
            size_bytes=100,
            created_at=modified,
            modified_at=modified,
            extension=".csv",
            content="",
        )

    def setup_method(self):
        self.auditor = RetentionAuditor(RETENTION_POLICIES)

    def test_no_violation_within_window(self):
        asset = self._make_asset(age_days=100)
        violations = self.auditor.audit(asset, "Restricted", ["GDPR"])
        assert violations == []

    def test_violation_when_exceeds_window(self):
        asset = self._make_asset(age_days=400)
        violations = self.auditor.audit(asset, "Restricted", ["GDPR"])
        assert len(violations) == 1
        assert violations[0].framework == "GDPR"
        assert violations[0].violation_type == "RETENTION_EXCEEDED"

    def test_pci_violation_critical_severity(self):
        asset = self._make_asset(age_days=400)
        violations = self.auditor.audit(asset, "Restricted", ["PCI"])
        pci_v = [v for v in violations if v.framework == "PCI"]
        assert len(pci_v) == 1
        assert pci_v[0].severity == "CRITICAL"

    def test_no_violation_for_unrelated_framework(self):
        asset = self._make_asset(age_days=400)
        # File only has NIST matches; GDPR/PCI auditors should skip it
        violations = self.auditor.audit(asset, "Internal", ["NIST"])
        assert violations == []
