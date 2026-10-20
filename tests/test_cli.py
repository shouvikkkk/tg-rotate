"""CLI smoke tests: parsing and the redaction guarantee on stdout."""
from __future__ import annotations

from tg_rotate import cli, fingerprint


def test_version_flag(capsys):
    assert cli.main(["--version"]) == 0
    out = capsys.readouterr().out
    assert cli.__version__ in out


def test_help_lists_commands(capsys):
    assert cli.main(["--help"]) == 0
    out = capsys.readouterr().out
    for cmd in ("audit", "rotate", "watch", "verify"):
        assert cmd in out


def test_audit_redacts_token_on_stdout(workspace, old_token, capsys, monkeypatch):
    """The full token must never appear on stdout, even when audit finds it."""
    monkeypatch.setattr(cli.probe, "get_me", lambda *a, **k: None)
    rc = cli.main(["audit", "--old-token", old_token,
                   "--path", str(workspace), "--no-api"])
    assert rc == 0
    out = capsys.readouterr().out
    assert old_token not in out
    assert fingerprint.short(fingerprint.fingerprint(old_token)) in out


def test_rotate_requires_new_token(workspace, old_token):
    rc = cli.main(["rotate", "--old-token", old_token,
                   "--path", str(workspace), "--no-api", "--dry-run"])
    assert rc != 0  # no new token source -> error, not a silent no-op
