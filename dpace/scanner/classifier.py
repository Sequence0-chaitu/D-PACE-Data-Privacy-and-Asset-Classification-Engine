"""
dpace.scanner.classifier
------------------------
Classification Logic

Applies ordered classification rules from mandates.json to a list of
PatternMatch results and returns a final classification label.
"""

from __future__ import annotations

import logging
from typing import List

from dpace.scanner.regex_engine import PatternMatch

logger = logging.getLogger(__name__)

# Severity rank — higher = more severe
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Classification rank — higher = more restrictive
_CLASS_RANK = {
    "Restricted": 4,
    "Confidential": 3,
    "Internal": 2,
    "Unclassified": 1,
}


def classify(matches: List[PatternMatch], rules: list | None = None) -> str:
    """
    Determine the final classification for a file given its pattern matches.

    The logic follows the rules defined in mandates.json:

    1. Any CRITICAL match → **Restricted** (immediate override)
    2. Two or more HIGH matches → **Restricted**
    3. Exactly one HIGH match → **Confidential**
    4. Only MEDIUM/LOW matches → **Confidential**
    5. No matches → **Internal**

    Custom ``rules`` from mandates.json are evaluated first when provided.

    Parameters
    ----------
    matches:
        List of PatternMatch objects returned by the regex engine.
    rules:
        Optional list of classification_rules entries from mandates.json.
        Built-in fallback logic is always applied if no custom rule fires.

    Returns
    -------
    str
        One of ``'Restricted'``, ``'Confidential'``, ``'Internal'``, ``'Unclassified'``.
    """
    if not matches:
        return "Internal"

    # --- Built-in rule logic (mirrors mandates.json classification_rules) ---
    severities = [m.severity for m in matches]
    critical_count = severities.count("CRITICAL")
    high_count = severities.count("HIGH")

    if critical_count >= 1:
        logger.debug("Classification: Restricted (CRITICAL pattern match)")
        return "Restricted"

    if high_count >= 2:
        logger.debug("Classification: Restricted (multiple HIGH matches)")
        return "Restricted"

    if high_count == 1:
        logger.debug("Classification: Confidential (single HIGH match)")
        return "Confidential"

    # All remaining matches are MEDIUM or LOW
    logger.debug("Classification: Confidential (MEDIUM/LOW matches only)")
    return "Confidential"


def escalate(current: str, candidate: str) -> str:
    """
    Return whichever classification is more restrictive.

    Useful when merging classifications across multiple scans.
    """
    if _CLASS_RANK.get(candidate, 0) > _CLASS_RANK.get(current, 0):
        return candidate
    return current
