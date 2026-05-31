"""
dpace.scanner.regex_engine
--------------------------
PII / PCI Regex Matching Engine

Loads pattern definitions from mandates.json and runs them against
file content, returning structured match results.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)


@dataclass
class PatternMatch:
    """A single regex pattern match result for a file."""

    pattern_id: str
    pattern_name: str
    match_count: int
    severity: str
    classification: str
    frameworks: List[str]
    nist_controls: List[str] = field(default_factory=list)
    gdpr_articles: List[str] = field(default_factory=list)
    pci_requirements: List[str] = field(default_factory=list)


class RegexEngine:
    """
    Compiles and applies all patterns from the loaded policy.

    Parameters
    ----------
    policy:
        Parsed mandates.json dict.
    max_matches_per_file:
        Cap on the number of match objects stored per file.
    """

    def __init__(self, policy: dict, max_matches_per_file: int = 1000) -> None:
        self._max_matches = max_matches_per_file
        self._compiled: Dict[str, tuple] = {}  # id -> (compiled_re, meta)
        self._load_patterns(policy.get("regex_patterns", []))

    def _load_patterns(self, patterns: list) -> None:
        for pat in patterns:
            pid = pat["id"]
            try:
                compiled = re.compile(pat["pattern"], re.IGNORECASE)
                self._compiled[pid] = (compiled, pat)
                logger.debug("Loaded pattern: %s", pid)
            except re.error as exc:
                logger.error("Invalid regex for pattern %s: %s", pid, exc)

    def scan(self, content: str) -> List[PatternMatch]:
        """
        Run all compiled patterns against *content*.

        Returns a list of :class:`PatternMatch` (one per matching pattern),
        sorted by severity (CRITICAL first).
        """
        results: List[PatternMatch] = []

        for pid, (compiled, meta) in self._compiled.items():
            matches = compiled.findall(content)
            count = min(len(matches), self._max_matches)
            if count == 0:
                continue

            results.append(
                PatternMatch(
                    pattern_id=pid,
                    pattern_name=meta["name"],
                    match_count=count,
                    severity=meta.get("severity", "LOW"),
                    classification=meta.get("classification", "Internal"),
                    frameworks=meta.get("frameworks", []),
                    nist_controls=meta.get("nist_controls", []),
                    gdpr_articles=meta.get("gdpr_articles", []),
                    pci_requirements=meta.get("pci_requirements", []),
                )
            )

        _SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        results.sort(key=lambda r: _SEVERITY_ORDER.get(r.severity, 99))
        return results
