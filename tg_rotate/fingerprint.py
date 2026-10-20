"""Token fingerprinting and redaction.

The cardinal rule of this module: a full token must NEVER be printed,
logged, or persisted. Everything user-facing works with fingerprints
(SHA-256 hex) shown as ``<first8>…<last4-of-token>``.
"""
from __future__ import annotations

import hashlib
import re

# Telegram bot tokens look like <bot-id>:<secret>, e.g. 123456789:AAH... (35 chars).
# The secret part is 35 chars on current tokens; accept 30-35 to stay tolerant.
# The trailing negative lookahead stops the match from absorbing extra
# secret-charset characters glued to a token (e.g. "TOKEN-suffix"), which
# would otherwise fingerprint to the wrong value and silently miss.
TOKEN_RE = re.compile(r"\b\d{5,12}:[A-Za-z0-9_-]{30,35}(?![A-Za-z0-9_-])")


def fingerprint(token: str) -> str:
    """SHA-256 hex fingerprint of a token. Used for matching, never reversed."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def short(fp: str) -> str:
    """First 8 hex chars of a fingerprint -- the public identifier."""
    return fp[:8]


def tail(token: str) -> str:
    """Last 4 chars of a token -- safe to display, useless to an attacker alone."""
    return token[-4:] if len(token) >= 4 else "????"


def label(fp: str, token: str | None = None) -> str:
    """Human label for a token: ``a1b2c3d4…Wxyz``. Never contains the full token."""
    if token:
        return f"{fp[:8]}…{tail(token)}"
    return f"{fp[:8]}…"


def looks_like_token(s: str) -> bool:
    """Heuristic check that a string has the shape of a Telegram bot token."""
    return TOKEN_RE.fullmatch(s.strip()) is not None


def find_tokens(text: str) -> list[str]:
    """All token-shaped substrings in text (raw -- handle with care, never print)."""
    return TOKEN_RE.findall(text)


def redact_line(line: str) -> str:
    """Replace every token-shaped substring in a line with its redacted label."""
    def _sub(m: "re.Match[str]") -> str:
        tok = m.group(0)
        return f"[token {label(fingerprint(tok), tok)}]"

    return TOKEN_RE.sub(_sub, line)
