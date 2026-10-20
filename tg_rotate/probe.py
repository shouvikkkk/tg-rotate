"""Minimal stdlib-only Telegram Bot API probing (urllib, no dependencies).

The key semantic this module enforces: a network error is NOT a pass.
Verification must FAIL CLOSED -- if we cannot reach Telegram, we cannot
claim anything about token state, so every caller treats
``transport_error`` as a hard failure.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

DEFAULT_API_BASE = "https://api.telegram.org"


@dataclass
class ProbeResult:
    outcome: str  # "ok" | "revoked" | "transport_error" | "api_error"
    http_status: int | None = None
    username: str | None = None
    bot_id: int | None = None
    detail: str = ""


def _describe(body: str) -> str:
    try:
        data = json.loads(body)
        return str(data.get("description", ""))[:200]
    except (json.JSONDecodeError, ValueError):
        return body[:200]


def get_me(
    token: str,
    base_url: str = DEFAULT_API_BASE,
    timeout: float = 10.0,
) -> ProbeResult:
    """Call getMe for a token.

    - 200 + ok:true        -> outcome "ok" (username/bot_id filled in)
    - HTTP 401             -> outcome "revoked" (Telegram's revoked/invalid signal)
    - anything unreachable -> outcome "transport_error" (must be treated as failure)
    """
    url = f"{base_url.rstrip('/')}/bot{token}/getMe"
    req = urllib.request.Request(url, headers={"User-Agent": "tg-rotate/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        if e.code == 401:
            return ProbeResult("revoked", http_status=401, detail=_describe(raw) or "Unauthorized")
        return ProbeResult(
            "api_error", http_status=e.code, detail=_describe(raw) or f"HTTP {e.code}"
        )
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return ProbeResult("transport_error", detail=f"{type(e).__name__}: {e}")
    except Exception as e:  # defensive: never let a probe raise
        return ProbeResult("transport_error", detail=f"{type(e).__name__}: {e}")

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return ProbeResult("api_error", http_status=200, detail="non-JSON response body")
    if data.get("ok"):
        result = data.get("result") or {}
        return ProbeResult(
            "ok",
            http_status=200,
            username=result.get("username"),
            bot_id=result.get("id"),
        )
    if data.get("error_code") == 401:
        return ProbeResult("revoked", http_status=401, detail=str(data.get("description", ""))[:200])
    return ProbeResult(
        "api_error",
        http_status=data.get("error_code"),
        detail=str(data.get("description", ""))[:200],
    )


def send_message(
    token: str,
    chat_id: str | int,
    text: str,
    base_url: str = DEFAULT_API_BASE,
    timeout: float = 10.0,
) -> bool:
    """Best-effort sendMessage (used for watch alerts). Returns True on ok:true."""
    url = f"{base_url.rstrip('/')}/bot{token}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()
    req = urllib.request.Request(
        url, data=data, headers={"User-Agent": "tg-rotate/0.1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8", "replace"))
            return bool(body.get("ok"))
    except Exception:
        return False
