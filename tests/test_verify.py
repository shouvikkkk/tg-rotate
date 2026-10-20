"""Verification tests: the four checks and their fail-closed semantics."""
from __future__ import annotations

from pathlib import Path

from tg_rotate import probe, verify


def _res(outcome, **kw):
    return probe.ProbeResult(outcome, **kw)


def test_old_token_gone_passes_when_absent(tmp_path, old_token):
    r = verify.check_old_token_gone(old_token, [tmp_path])
    assert r.passed


def test_old_token_gone_fails_when_present(workspace, old_token):
    r = verify.check_old_token_gone(old_token, [workspace])
    assert not r.passed
    assert old_token not in r.detail  # redacted detail


def test_new_token_works_ok(monkeypatch, new_token):
    monkeypatch.setattr(probe, "get_me",
                        lambda *a, **k: _res("ok", username="b", bot_id=1))
    r = verify.check_new_token_works(new_token)
    assert r.passed


def test_new_token_transport_error_fails_closed(monkeypatch, new_token):
    monkeypatch.setattr(probe, "get_me",
                        lambda *a, **k: _res("transport_error", detail="down"))
    r = verify.check_new_token_works(new_token)
    assert not r.passed
    assert "failing closed" in r.detail


def test_old_token_dead_ok(monkeypatch, old_token):
    monkeypatch.setattr(probe, "get_me",
                        lambda *a, **k: _res("revoked", http_status=401))
    assert verify.check_old_token_dead(old_token).passed


def test_old_token_still_alive_is_failure(monkeypatch, old_token):
    monkeypatch.setattr(probe, "get_me",
                        lambda *a, **k: _res("ok", username="b", bot_id=1))
    r = verify.check_old_token_dead(old_token)
    assert not r.passed
    assert "STILL WORKS" in r.detail


def test_old_token_dead_transport_error_fails_closed(monkeypatch, old_token):
    monkeypatch.setattr(probe, "get_me",
                        lambda *a, **k: _res("transport_error", detail="down"))
    r = verify.check_old_token_dead(old_token)
    assert not r.passed


def test_run_verification_skip_api(workspace, old_token, new_token):
    report = verify.run_verification(old_token, new_token, [workspace],
                                     skip_api=True)
    # old token still present in workspace -> fails on check 1, as it should.
    assert not report.passed
    assert report.checks[0].name == "old-token-gone"
    assert not report.checks[0].passed


def test_report_summary_counts():
    r = verify.VerificationReport()
    assert not r.passed  # empty report is not a pass
    r.checks.append(verify.CheckResult("a", True))
    r.checks.append(verify.CheckResult("b", False))
    assert r.summary() == "1/2 checks passed"
    assert len(r.failed()) == 1
