"""The rotation engine.

Implements the state machine:

    audit -> backup -> rotate -> verify -> done | failed

Every transition is recorded in the state file. The rotation step
replaces the token in each discovered location. Atomicity is
per-file (write temp file, fsync, os.replace); a backup directory
captures every file touched so a failed rotation can be rolled
back.

Safety rules:
- The NEW token is never taken from the same place the old one was
  found; the caller must supply it (stdin, file, or interactive
  prompt with the value masked).
- Rollback restores every touched file from backup on any failure
  after the rotate step.
- The state file never contains full tokens, only fingerprints.
"""
from __future__ import annotations

import datetime as _dt
import getpass
import os
import secrets
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import discover, fingerprint, probe, state, verify

BACKUP_DIR = Path.home() / ".tg-rotate" / "backups"
WATCH_DIR = Path.home() / ".tg-rotate"


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def ensure_dirs() -> None:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    WATCH_DIR.mkdir(parents=True, exist_ok=True)


def mask(v: str) -> str:
    """Redact a possibly-token-bearing value for display."""
    return fingerprint.redact_line(v)


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write *data* to *path* atomically (temp file + fsync + os.replace)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    atomic_write(path, text.encode("utf-8"), mode)


def backup_file(path: Path, run_id: str) -> Path:
    """Copy *path* into the per-run backup dir; return the backup path."""
    dest_dir = BACKUP_DIR / run_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / (path.name + ".bak")
    # Disambiguate identical basenames from different dirs.
    i = 1
    stem = dest
    while dest.exists():
        i += 1
        dest = stem.parent / f"{stem.name}.{i}"
    shutil.copy2(path, dest)
    return dest


def run_id_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(4)


def read_new_token(
    old_token: str,
    token_arg: str | None,
    token_file: str | None,
    from_stdin: bool = False,
) -> str:
    """Obtain the new token from the caller.

    Never reads the new token from the same locations the old token was
    discovered in. Resolution order: explicit arg > file > stdin > prompt.
    """
    if token_arg:
        tok = token_arg.strip()
    elif token_file:
        tok = Path(token_file).read_text(encoding="utf-8").strip()
    elif from_stdin or not sys.stdin.isatty():
        tok = sys.stdin.read().strip().splitlines()[0] if True else ""
        tok = tok.strip()
    else:
        tok = getpass.getpass("New bot token (input hidden): ").strip()
    if not tok:
        raise ValueError("no new token provided")
    if not fingerprint.looks_like_token(tok):
        raise ValueError("new value does not look like a Telegram bot token")
    if tok == old_token:
        raise ValueError("new token is identical to the old token")
    return tok


# ------------------------------------------------------------------
# audit
# ------------------------------------------------------------------

@dataclass
class AuditResult:
    old_fp: str
    locations: list[discover.Location] = field(default_factory=list)
    verified: bool = False
    api_username: str | None = None


def audit(
    old_token: str,
    search_paths: list[Path],
    api_base: str = probe.DEFAULT_API_BASE,
    skip_api: bool = False,
    progress: Callable[[str], None] | None = None,
) -> AuditResult:
    """Audit: verify the old token with Telegram and find all its copies."""
    old_fp = fingerprint.fingerprint(old_token)
    if progress:
        progress("Probing current token with Telegram…")
    api_username = None
    verified = False
    if not skip_api:
        res = probe.get_me(old_token, base_url=api_base)
        if res.outcome == "ok":
            verified = True
            api_username = res.username
            if progress:
                progress(f"Token valid — bot @{res.username or '?'}")
        elif res.outcome == "revoked":
            if progress:
                progress("Token is already revoked/invalid on Telegram (401). Continuing audit.")
        else:
            raise RuntimeError(
                f"cannot reach Telegram to verify token: {res.outcome} {res.detail}"
            )
    else:
        if progress:
            progress("Skipping Telegram API check (--no-api).")
    if progress:
        progress(f"Scanning {len(search_paths)} path(s) for copies of the token…")
    locations = discover.find_token_locations(search_paths, old_token)
    if progress:
        progress(f"Found {len(locations)} location(s).")
    return AuditResult(old_fp=old_fp, locations=locations, verified=verified,
                       api_username=api_username)


# ------------------------------------------------------------------
# rotation
# ------------------------------------------------------------------

@dataclass
class RotateOutcome:
    run_id: str
    state_path: Path
    verification: verify.VerificationReport | None = None
    rolled_back: bool = False


def rotate(
    old_token: str,
    new_token: str,
    search_paths: list[Path],
    state_path: Path | None = None,
    api_base: str = probe.DEFAULT_API_BASE,
    skip_api: bool = False,
    service_hint: str | None = None,
    dry_run: bool = False,
    progress: Callable[[str], None] | None = None,
) -> RotateOutcome:
    """Run the full rotate state machine.

    Returns the outcome; raises on unrecoverable errors (after rolling
    back anything already written).
    """
    ensure_dirs()
    rid = run_id_now()
    st_path = state_path or (Path.home() / ".tg-rotate" / "state.json")
    st_path.parent.mkdir(parents=True, exist_ok=True)
    st = state.load(st_path)

    old_fp = fingerprint.fingerprint(old_token)
    new_fp = fingerprint.fingerprint(new_token)

    def rec(phase: str, ok: bool = True, detail: str = "") -> None:
        st.record(rid, phase, old_fp, new_fp, ok=ok, detail=detail)
        state.save(st, st_path)

    rec("audit", detail=f"old={fingerprint.short(old_fp)}")

    # ---- discover ------------------------------------------------
    if progress:
        progress("Discovering token locations…")
    locations = discover.find_token_locations(search_paths, old_token)
    if not locations:
        rec("discover", ok=False, detail="no locations found for old token")
        raise RuntimeError("old token not found in any of the search paths")
    rec("discover", detail=f"{len(locations)} location(s)")

    # ---- backup --------------------------------------------------
    if progress:
        progress(f"Backing up {len(locations)} file(s)…")
    backups: dict[str, str] = {}
    for loc in locations:
        b = backup_file(loc.path, rid)
        backups[str(loc.path)] = str(b)
    rec("backup", detail=f"{len(backups)} file(s) backed up")

    # ---- rotate --------------------------------------------------
    if dry_run:
        rec("rotate", detail="dry-run: no files modified")
        if progress:
            progress("Dry run — no files modified.")
            for loc in locations:
                progress(f"  would replace in {loc.path}:{loc.line_no}")
        return RotateOutcome(run_id=rid, state_path=st_path)

    if progress:
        progress("Replacing token in files…")
    touched: list[Path] = []
    try:
        for loc in locations:
            _replace_in_file(loc.path, old_token, new_token)
            touched.append(loc.path)
            if progress:
                progress(f"  replaced in {loc.path}")
    except Exception as e:
        rec("rotate", ok=False, detail=f"failed at {len(touched)}/{len(locations)}: {e}")
        _rollback(backups, progress)
        rec("rollback", detail=f"restored {len(touched)} file(s)")
        raise RuntimeError(f"rotation failed and was rolled back: {e}") from e
    rec("rotate", detail=f"{len(touched)} location(s) replaced")

    # ---- verify --------------------------------------------------
    report = verify.run_verification(
        old_token=old_token,
        new_token=new_token,
        search_paths=search_paths,
        api_base=api_base,
        skip_api=skip_api,
        service_hint=service_hint,
        progress=progress,
    )
    ok = report.passed
    rec("verify", ok=ok, detail=report.summary())
    if not ok:
        if progress:
            progress("Verification FAILED — rolling back.")
        _rollback(backups, progress)
        rec("rollback", detail="verification failed; restored from backup")
        return RotateOutcome(run_id=rid, state_path=st_path,
                            verification=report, rolled_back=True)
    rec("done", detail=report.summary())
    if progress:
        progress("Rotation complete and verified.")
    return RotateOutcome(run_id=rid, state_path=st_path, verification=report)


def _replace_in_file(path: Path, old_token: str, new_token: str) -> None:
    """Replace every occurrence of old_token with new_token in *path*, atomically."""
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"{path} is not valid UTF-8: {e}") from e
    if old_token not in text:
        raise ValueError(f"old token no longer present in {path}")
    new_text = text.replace(old_token, new_token)
    atomic_write(path, new_text.encode("utf-8"), mode=_file_mode(path))


def _file_mode(path: Path) -> int:
    try:
        return path.stat().st_mode & 0o777
    except OSError:
        return 0o600


def _rollback(backups: dict[str, str],
              progress: Callable[[str], None] | None) -> None:
    for orig, bak in backups.items():
        try:
            shutil.copy2(bak, orig)
            if progress:
                progress(f"  restored {orig}")
        except OSError as e:
            if progress:
                progress(f"  FAILED to restore {orig}: {e}")


# ------------------------------------------------------------------
# watch
# ------------------------------------------------------------------

def watch(
    state_path: Path | None = None,
    interval: float = 300.0,
    api_base: str = probe.DEFAULT_API_BASE,
    alert_token: str | None = None,
    alert_chat_id: str | None = None,
    progress: Callable[[str], None] | None = None,
    once: bool = False,
    probe_fn: Callable[[str], probe.ProbeResult] | None = None,
) -> None:
    """Watch mode: re-probe the current token; alert if it dies unexpectedly."""
    st_path = state_path or (Path.home() / ".tg-rotate" / "state.json")
    st = state.load(st_path)
    run = st.last_successful_run()
    if not run or not run.get("new_fp"):
        raise RuntimeError("no successful rotation on record — nothing to watch")
    token = None
    # The state file must never hold the full token, so watch needs the
    # current token supplied via env for re-probing.
    token = os.environ.get("TG_ROTATE_TOKEN")
    if not token:
        raise RuntimeError("watch needs TG_ROTATE_TOKEN env var with the current token")
    new_fp = run["new_fp"]
    if fingerprint.fingerprint(token) != new_fp:
        raise RuntimeError("TG_ROTATE_TOKEN does not match the recorded current token")

    def _tick() -> bool:
        fn = probe_fn or (lambda t: probe.get_me(t, base_url=api_base))
        res = fn(token)
        if progress:
            progress(f"watch: getMe -> {res.outcome}")
        if res.outcome == "revoked":
            msg = ("tg-rotate watch: the current token for this host was revoked "
                   "outside of tg-rotate. Rotate it now.")
            if alert_token and alert_chat_id:
                probe.send_message(alert_token, alert_chat_id, msg)
            if progress:
                progress(msg)
            return False
        if res.outcome != "ok":
            if progress:
                progress(f"watch: transport/api issue ({res.detail}) — will retry")
        return True

    if once:
        _tick()
        return
    if progress:
        progress(f"watching every {interval}s — Ctrl-C to stop")
    try:
        while True:
            if not _tick():
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        if progress:
            progress("watch stopped")
