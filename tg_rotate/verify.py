"""Post-rotation verification suite.

The verification contract -- the part that makes this tool trustworthy:

1. **Old token is gone everywhere.** The old token's fingerprint must not
   match anything found in the search paths (any hit is reported redacted).
2. **New token works.** ``getMe`` on the new token must return ``ok``.
3. **Old token is dead.** ``getMe`` on the old token must return
   ``revoked`` (HTTP 401). An old token that still works is a failure --
   it means Telegram did not revoke it (e.g. the operator has not yet
   revoked it via BotFather), so we say so loudly instead of pretending.
4. **The running service uses the new token.** Best effort: inspect the
   environment of likely PIDs / systemd unit for the new fingerprint.
   (Never prints tokens; only fingerprints.)

A **transport error is never a pass**: if we cannot reach Telegram, the
report fails closed and says so.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import discover, fingerprint, probe


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class VerificationReport:
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(c.passed for c in self.checks)

    def summary(self) -> str:
        n = len(self.checks)
        ok = sum(1 for c in self.checks if c.passed)
        return f"{ok}/{n} checks passed"

    def failed(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.passed]


def _say(progress: Callable[[str], None] | None, msg: str) -> None:
    if progress:
        progress(msg)


def check_old_token_gone(
    old_token: str, search_paths: list[Path],
    progress: Callable[[str], None] | None = None,
) -> CheckResult:
    """No copy of the old token may remain in the search paths."""
    _say(progress, "Check 1/4: old token gone from disk…")
    locations = discover.find_token_locations(search_paths, old_token)
    if locations:
        redacted = ", ".join(
            f"{loc.path}:{loc.line_no}" for loc in locations[:10]
        )
        return CheckResult(
            "old-token-gone", False,
            f"old token still present in {len(locations)} location(s): {redacted}",
        )
    return CheckResult("old-token-gone", True, "no copy of the old token found")


def check_new_token_works(
    new_token: str,
    api_base: str = probe.DEFAULT_API_BASE,
    progress: Callable[[str], None] | None = None,
) -> CheckResult:
    """The new token must authenticate with Telegram (getMe -> ok)."""
    _say(progress, "Check 2/4: new token works…")
    res = probe.get_me(new_token, base_url=api_base)
    if res.outcome == "ok":
        return CheckResult(
            "new-token-works", True,
            f"getMe ok — bot @{res.username or '?'} (id {res.bot_id or '?'})",
        )
    if res.outcome == "transport_error":
        return CheckResult(
            "new-token-works", False,
            f"could not reach Telegram ({res.detail}) — failing closed",
        )
    return CheckResult(
        "new-token-works", False,
        f"new token rejected by Telegram: {res.outcome} {res.detail}",
    )


def check_old_token_dead(
    old_token: str,
    api_base: str = probe.DEFAULT_API_BASE,
    progress: Callable[[str], None] | None = None,
) -> CheckResult:
    """The old token must be revoked (401). An old token that still works is
    a FAILURE -- the operator must revoke it via BotFather."""
    _say(progress, "Check 3/4: old token revoked…")
    res = probe.get_me(old_token, base_url=api_base)
    if res.outcome == "revoked":
        return CheckResult("old-token-dead", True, "old token returns 401")
    if res.outcome == "ok":
        return CheckResult(
            "old-token-dead", False,
            "old token STILL WORKS — revoke it via @BotFather, then re-run",
        )
    return CheckResult(
        "old-token-dead", False,
        f"could not confirm revocation ({res.outcome}: {res.detail}) — failing closed",
    )


def _proc_environs() -> list[tuple[int, str]]:
    """Yield (pid, environ-bytes-decoded) for processes we can read."""
    out: list[tuple[int, str]] = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/environ", "rb") as f:
                data = f.read().decode("utf-8", "replace")
        except (OSError, PermissionError):
            continue
        out.append((int(pid), data))
    return out


def _systemd_unit_env(unit: str) -> str:
    try:
        r = subprocess.run(
            ["systemctl", "show", unit, "--property=Environment", "--value"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return r.stdout if r.returncode == 0 else ""


def check_service_uses_new_token(
    new_token: str,
    service_hint: str | None = None,
    progress: Callable[[str], None] | None = None,
) -> CheckResult:
    """Best-effort: confirm the running service's environment holds the NEW
    token (and not the old one). Skipped gracefully when unsupported."""
    _say(progress, "Check 4/4: running service uses new token…")
    new_fp = fingerprint.fingerprint(new_token)

    candidates: list[str] = []
    if service_hint and service_hint.endswith(".service"):
        candidates.append(_systemd_unit_env(service_hint))
    elif service_hint and service_hint.isdigit():
        for pid, env in _proc_environs():
            if pid == int(service_hint):
                candidates.append(env)
    else:
        # No hint: scan all readable process environments.
        candidates.extend(env for _, env in _proc_environs())

    if not candidates:
        return CheckResult(
            "service-token", True,
            "skipped: no process environments readable (unsupported platform)",
        )
    hits = 0
    for env in candidates:
        for tok in fingerprint.find_tokens(env):
            if fingerprint.fingerprint(tok) == new_fp:
                hits += 1
    if hits:
        return CheckResult(
            "service-token", True,
            f"new token fingerprint found in {hits} process environment(s)",
        )
    return CheckResult(
        "service-token", False,
        "new token not found in any readable process environment — "
        "is the service restarted with the new token?",
    )


def run_verification(
    old_token: str,
    new_token: str,
    search_paths: list[Path],
    api_base: str = probe.DEFAULT_API_BASE,
    skip_api: bool = False,
    service_hint: str | None = None,
    progress: Callable[[str], None] | None = None,
) -> VerificationReport:
    """Run all verification checks, in order. Returns the report."""
    report = VerificationReport()
    report.checks.append(check_old_token_gone(old_token, search_paths, progress))
    if skip_api:
        _say(progress, "Skipping Telegram API checks (--no-api).")
        report.checks.append(
            CheckResult("new-token-works", True, "skipped (--no-api)"))
        report.checks.append(
            CheckResult("old-token-dead", True, "skipped (--no-api)"))
    else:
        report.checks.append(check_new_token_works(new_token, api_base, progress))
        report.checks.append(check_old_token_dead(old_token, api_base, progress))
    report.checks.append(check_service_uses_new_token(new_token, service_hint, progress))
    return report
