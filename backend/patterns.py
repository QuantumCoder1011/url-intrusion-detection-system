"""
URL Intrusion Detection System - Attack pattern definitions.

This module defines compiled regex patterns for offline, rule-based URL analysis.
Patterns are scoped per attack type.

Extension notes:
- Rules can be updated for new attacks by adding entries to ATTACK_PATTERNS and
  corresponding handling in detector.py (priority order), without changing the
  rest of the application.
- In a production setup, patterns could be loaded from a config file or SIEM
  feed and hot-reloaded for zero-downtime rule updates.
"""

import re
from typing import Dict, Any

# ---------------------------------------------------------------------------
# ATTACK_PATTERNS: Compiled regex patterns per category.
# Order of keys does not define detection priority (see detector.py).
# Extending: add new keys and corresponding detection logic in detector.py.
# Real-time IDS: same patterns can be applied to live request streams.
# ---------------------------------------------------------------------------

ATTACK_PATTERNS: Dict[str, Any] = {
    # Shell execution: ; or && or || followed by common shell commands.
    # Scoped to avoid matching SQL semicolons; detector applies this first.
    "command_injection": [
        re.compile(
            r'[;&|]\s*(ls|cat|rm|whoami|pwd|uname|id|ps|netstat|mkdir|chmod|chown)\b',
            re.IGNORECASE
        ),
        re.compile(r'&&\s*(ls|cat|rm|whoami|pwd|uname|id)\b', re.IGNORECASE),
        re.compile(r'\|\|\s*(ls|cat|rm|whoami|pwd|uname|id)\b', re.IGNORECASE),
        re.compile(r'\$\s*\(', re.IGNORECASE),  # $(
        re.compile(r'`[^`]+`'),  # backtick command substitution
    ],

    # Directory traversal (includes path traversal): ../, ..\, encoded variants.
    "directory_traversal": [
        re.compile(r'\.\./'),
        re.compile(r'\.\.\\'),
        re.compile(r'\.\.%2[fF]'),
        re.compile(r'\.\.%5[cC]'),
        re.compile(r'\.\.%252[fF]'),
        re.compile(r'\.\.%255[cC]'),
        re.compile(r'(\.\./){2,}'),   # repeated traversal
        re.compile(r'(\.\.\\){2,}'),
        re.compile(r'/etc/passwd'),
        re.compile(r'/etc/shadow'),
    ],

    # Cross-Site Scripting: script tags, javascript:, event handlers.
    "xss": [
        re.compile(r'<script\s*[^>]*>', re.IGNORECASE),
        re.compile(r'javascript\s*:', re.IGNORECASE),
        re.compile(r'onerror\s*=', re.IGNORECASE),
        re.compile(r'onload\s*=', re.IGNORECASE),
        re.compile(r'onclick\s*=', re.IGNORECASE),
        re.compile(r'onmouseover\s*=', re.IGNORECASE),
        re.compile(r'<iframe[^>]*>', re.IGNORECASE),
        re.compile(r'<img[^>]*src\s*=\s*["\']?\s*javascript:', re.IGNORECASE),
        re.compile(r'<svg[^>]*onload', re.IGNORECASE),
        re.compile(r'alert\s*\(', re.IGNORECASE),
        re.compile(r'document\.cookie', re.IGNORECASE),
        re.compile(r'vbscript\s*:', re.IGNORECASE),
    ],

    # SQL Injection: classic payloads. Not applied if URL already matched
    # Command Injection or XSS (handled in detector to avoid semicolon/shell confusion).
    "sql_injection": [
        re.compile(r"'?\s*or\s*1\s*=\s*1\s*['\"]?", re.IGNORECASE),
        re.compile(r"'?\s*or\s*['\"]?a['\"]?\s*=\s*['\"]?a['\"]?", re.IGNORECASE),
        re.compile(r"'\s*--", re.IGNORECASE),
        re.compile(r'union\s+select', re.IGNORECASE),
        re.compile(r'select\s+.*\s+from\s+', re.IGNORECASE),
        re.compile(r'insert\s+into\s+', re.IGNORECASE),
        re.compile(r'delete\s+from\s+', re.IGNORECASE),
        re.compile(r'drop\s+table\s+', re.IGNORECASE),
        re.compile(r';\s*--', re.IGNORECASE),  # SQL comment after semicolon
    ],

    # Low severity: weak or incomplete indicators (single quote, keywords without full payload).
    # Used only when no high/medium match found; reported as "Suspicious Activity" / Low.
    "low_severity": [
        re.compile(r"%27|'"),  # single quote or encoded
        re.compile(r'\b(union|select|or|and)\b', re.IGNORECASE),  # SQL keywords alone
        re.compile(r'<\s*script', re.IGNORECASE),  # malformed script tag
        re.compile(r'=\s*[\'"][^"\']*[\'"]\s*or\s*', re.IGNORECASE),  # partial SQL
    ],
}
