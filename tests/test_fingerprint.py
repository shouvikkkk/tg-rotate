"""Fingerprinting tests: shape detection, hashing, and the no-leak rule."""
from __future__ import annotations

import hashlib

from tg_rotate import fingerprint


def test_fingerprint_is_sha256(old_token):
    assert fingerprint.fingerprint(old_token) == hashlib.sha256(
        old_token.encode()).hexdigest()


def test_distinct_tokens_distinct_fingerprints(old_token, new_token):
    assert fingerprint.fingerprint(old_token) != fingerprint.fingerprint(new_token)


def test_looks_like_token_accepts_valid(old_token):
    assert fingerprint.looks_like_token(old_token)
    assert fingerprint.looks_like_token("  " + old_token + "  ")


def test_looks_like_token_rejects_garbage():
    assert not fingerprint.looks_like_token("hello")
    assert not fingerprint.looks_like_token("123:notarealtoken")
    assert not fingerprint.looks_like_token("")


def test_glued_suffix_does_not_match(old_token):
    # "TOKEN-suffix": the trailing lookahead must prevent a match, so a
    # glued suffix can never fingerprint to a wrong value and silently miss.
    assert fingerprint.find_tokens(old_token + "-suffix") == []


def test_redact_line_never_leaks(old_token):
    line = f"export BOT_TOKEN={old_token}"
    redacted = fingerprint.redact_line(line)
    assert old_token not in redacted
    assert fingerprint.short(fingerprint.fingerprint(old_token)) in redacted
    assert fingerprint.tail(old_token) in redacted


def test_label_never_contains_full_token(old_token, old_fp):
    lbl = fingerprint.label(old_fp, old_token)
    assert old_token not in lbl
