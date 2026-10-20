"""Pure output redactor for MITR3 arsenal log/diagnostic safety.

This is a proposed replacement for the generic clean(text) helper.
Review and integrate only after Codex completes current edits.
No key values are read from the host.
"""
from __future__ import annotations

import re

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
URL_USERINFO = re.compile(r"(https?://)[^\s/@:]+:[^\s/@]+@", re.IGNORECASE)
AUTH_HEADER = re.compile(r"(\bAuthorization\s*:\s*(?:Bearer|Basic)\s+)([^\s,;]+)", re.IGNORECASE)
HEADER_KEY = re.compile(r"(\b(?:X-API-Key|api[-_ ]?key|client[-_ ]?secret)\s*:\s*)([^\s,;]+)", re.IGNORECASE)
ASSIGNMENT = re.compile(
    r"(\b(?:GOOGLE_API_KEY|GEMINI_API_KEY|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|HF_KEY|"
    r"api[-_]?key|access[-_]?token|refresh[-_]?token|client[-_]?secret|password|passwd|"
    r"secret|token)\s*=\s*)([^\s,;]+)",
    re.IGNORECASE,
)
QUERY_KEY = re.compile(
    r"([?&](?:api[-_]?key|access[-_]?token|refresh[-_]?token|password|secret|token)=)([^&#\s]+)",
    re.IGNORECASE,
)
CLI_KEY = re.compile(
    r"(\B--(?:api[-_]?key|access[-_]?token|client[-_]?secret|password|secret|token)\s+)(\S+)",
    re.IGNORECASE,
)
KNOWN_KEY_PATTERNS = [
    re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"(?<!\w)AQ\.[0-9A-Za-z_-]{25,}"),
]

def clean(text: str) -> str:
    """Redact likely token strings without saving or revealing their values."""
    text = ANSI.sub("", text)
    text = URL_USERINFO.sub(r"\1<redacted>@", text)
    for regex in (AUTH_HEADER, HEADER_KEY, ASSIGNMENT, QUERY_KEY, CLI_KEY):
        text = regex.sub(lambda m: m.group(1) + "<redacted>", text)
    for regex in KNOWN_KEY_PATTERNS:
        text = regex.sub("<redacted-key>", text)
    return text
