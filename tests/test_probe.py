"""Probe tests: outcome mapping and the fail-closed transport rule."""
from __future__ import annotations

import urllib.error

from tg_rotate import probe


def _ok_response(body: bytes):
    class R:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return body
    return R()


def test_get_me_ok(monkeypatch, new_token):
    body = b'{"ok": true, "result": {"id": 1, "username": "mybot"}}'
    monkeypatch.setattr(probe.urllib.request, "urlopen",
                        lambda *a, **k: _ok_response(body))
    res = probe.get_me(new_token)
    assert res.outcome == "ok"
    assert res.username == "mybot"
    assert res.bot_id == 1


def test_get_me_401_is_revoked(monkeypatch, old_token):
    err = urllib.error.HTTPError(
        "http://x", 401, "Unauthorized", {}, None)
    err.read = lambda: b'{"ok": false, "error_code": 401}'
    monkeypatch.setattr(probe.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(err))
    res = probe.get_me(old_token)
    assert res.outcome == "revoked"


def test_transport_error_fails_closed(monkeypatch, new_token):
    def boom(*a, **k):
        raise urllib.error.URLError("no route to host")
    monkeypatch.setattr(probe.urllib.request, "urlopen", boom)
    res = probe.get_me(new_token)
    assert res.outcome == "transport_error"
