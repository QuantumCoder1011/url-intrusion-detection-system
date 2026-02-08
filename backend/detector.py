"""
URL-based Intrusion Detection - Single-result, priority-based detector.

Each URL produces at most ONE detection. URL is decoded before matching.
Priority: Command Injection > Directory Traversal > XSS > SQL Injection.
Low-severity (suspicious but incomplete) is used only when no high/medium match.
Confidence score (0-100) is derived from match strength and encoding.

Extension notes:
- Real-time IDS: This same detect_attack() can be wired to a live HTTP proxy or
  WAF log stream; each request URL would be analyzed before/after forwarding.
- Rule updates: Attack signatures live in patterns.py; adding new ATTACK_PATTERNS
  and a corresponding priority entry here allows new attack types without changing
  the rest of the pipeline.
- SIEM integration: Detection results (attack_type, severity, confidence_score)
  can be forwarded to a SIEM (e.g. syslog, Splunk) for correlation and alerting.
"""

from urllib.parse import unquote
from typing import Optional, Dict, List
import re

from patterns import ATTACK_PATTERNS

# Detection priority: first match wins. Command Injection checked before SQL
# so semicolon+command is not misclassified as SQL Injection.
PRIORITY_ORDER = [
    ("command_injection", "Command Injection", "High"),
    ("directory_traversal", "Directory Traversal", "Medium"),
    ("xss", "XSS", "High"),
    ("sql_injection", "SQL Injection", "High"),
]


def _decode_url(url: str) -> str:
    """Decode percent-encoded URL for analysis. Handles multiple decoding passes."""
    if not url:
        return ""
    decoded = url
    for _ in range(3):  # limit iterations for nested encoding
        try:
            next_decoded = unquote(decoded)
            if next_decoded == decoded:
                break
            decoded = next_decoded
        except Exception:
            break
    return decoded


def _count_matches(decoded: str, pattern_list: List) -> int:
    """Return number of patterns that match the decoded URL."""
    count = 0
    for pat in pattern_list:
        if pat.search(decoded):
            count += 1
    return count


def _compute_confidence(decoded: str, raw_url: str, pattern_list: List, attack_key: str) -> int:
    """
    Compute confidence score 0-100.
    - More matched indicators => higher score.
    - Encoded payload (raw != decoded) can indicate intentional obfuscation => slightly higher.
    """
    matches = _count_matches(decoded, pattern_list)
    if matches == 0:
        return 0
    # Base from number of patterns matched (cap at 4 for scaling)
    base = min(matches * 25, 85)
    # Bonus if payload was encoded (obfuscation often means malicious intent)
    encoded_bonus = 10 if raw_url != decoded and attack_key != "low_severity" else 0
    return min(100, base + encoded_bonus)


def detect_attack(url: str) -> Optional[Dict]:
    """
    Analyze a URL and return at most one detection.

    Steps:
    1. Return None if url is None or empty.
    2. URL-decode the input.
    3. Check patterns in priority order (Command Injection → Directory Traversal → XSS → SQL Injection).
    4. On first high/medium match: return { attack_type, severity, confidence_score }.
    5. If no strong match but low_severity matches: return Suspicious Activity / Low.
    6. Otherwise return None.

    SQL Injection is not reported if the URL was already classified as Command Injection or XSS,
    to avoid semicolon/shell confusion and overlapping categories.
    """
    if url is None or (isinstance(url, str) and not url.strip()):
        return None

    raw_url = url.strip()
    decoded = _decode_url(raw_url)

    if not decoded:
        return None

    for key, attack_type, severity in PRIORITY_ORDER:
        pattern_list = ATTACK_PATTERNS.get(key, [])
        for pat in pattern_list:
            if pat.search(decoded):
                confidence = _compute_confidence(decoded, raw_url, pattern_list, key)
                return {
                    "attack_type": attack_type,
                    "severity": severity,
                    "confidence_score": confidence,
                }

    # Low severity: only if no high/medium match
    low_list = ATTACK_PATTERNS.get("low_severity", [])
    for pat in low_list:
        if pat.search(decoded):
            confidence = _compute_confidence(decoded, raw_url, low_list, "low_severity")
            return {
                "attack_type": "Suspicious Activity",
                "severity": "Low",
                "confidence_score": min(confidence, 50),
            }

    return None
