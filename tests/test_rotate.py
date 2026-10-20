"""Rotation engine tests: the full state machine, hermetic (no network).

Verification's Telegram calls are stubbed so the suite runs offline.
Transport-error paths are covered in test_probe.py / test_verify.py.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tg_rotate import probe, rotate_engine, state, verify


def _ok_report(*a, **k):
    r = verify.VerificationReport()
    r.checks.append(verify.CheckResult("a", True))
    r.checks.append(verify.CheckResult("b", True))
    return r


def _fail_report(*a, **k):
    r = verify.VerificationReport()
    r.checks.append(verify.CheckResult("a", True))
    r.checks.append(verify.CheckResult("b", False, "boom"))
    return r


@pytest.fixture()
def stub_verify_ok(monkeypatch):
    monkeypatch.setattr(verify, "run_verification", _ok_report)


@pytest.fixture()
def stub_verify_fail(monkeypatch):
    monkeypatch.setattr(verify, "run_verification", _fail_report)


def test_rotate_dry_run_changes_nothing(workspace, old_token, new_token,
                                        clean_home, stub_verify_ok):
    out = rotate_engine.rotate(
        old_token, new_token, [workspace], skip_api=True, dry_run=True)
    assert out.verification is None
    assert old_token in (workspace / ".env").read_text()


def test_rotate_replaces_every_copy(workspace, old_token, new_token,
                                    clean_home, stub_verify_ok, tmp_path):
    st_path = tmp_path / "state.json"
    out = rotate_engine.rotate(
        old_token, new_token, [workspace], state_path=st_path, skip_api=True)
    assert out.verification is not None and out.verification.passed
    assert not out.rolled_back
    for name in (".env", "config.yaml", "bot.py"):
        text = (workspace / name).read_text()
        assert old_token not in text
        assert new_token in text
    # State file records fingerprints only -- never full tokens.
    saved = st_path.read_text()
    assert old_token not in saved and new_token not in saved


def test_rotate_verification_failure_rolls_back(workspace, old_token, new_token,
                                                clean_home, stub_verify_fail, tmp_path):
    st_path = tmp_path / "state.json"
    out = rotate_engine.rotate(
        old_token, new_token, [workspace], state_path=st_path, skip_api=True)
    assert out.rolled_back
    assert out.verification is not None and not out.verification.passed
    for name in (".env", "config.yaml", "bot.py"):
        text = (workspace / name).read_text()
        assert old_token in text
        assert new_token not in text


def test_rotate_missing_old_token_raises(workspace, new_token, clean_home, tmp_path):
    with pytest.raises(RuntimeError, match="not found"):
        rotate_engine.rotate(
            "111111111:" + "Z" * 35, new_token, [workspace],
            state_path=tmp_path / "s.json", skip_api=True)


def test_read_new_token_rejects_same_token(old_token):
    with pytest.raises(ValueError, match="identical"):
        rotate_engine.read_new_token(old_token, token_arg=old_token,
                                     token_file=None)


def test_read_new_token_rejects_garbage(old_token):
    with pytest.raises(ValueError, match="does not look like"):
        rotate_engine.read_new_token(old_token, token_arg="nope",
                                     token_file=None)


def test_audit_skips_api(workspace, old_token, monkeypatch):
    called = []
    monkeypatch.setattr(probe, "get_me",
                        lambda *a, **k: called.append(1) or None)
    res = rotate_engine.audit(old_token, [workspace], skip_api=True)
    assert called == []
    assert len(res.locations) == 3
