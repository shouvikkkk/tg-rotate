"""Discovery of every copy of a bot token on this host.

Three hunting grounds:
  1. config files  -- .env, YAML/TOML/JSON/INI, systemd units, etc. (file:line)
  2. shell env     -- os.environ of this process tree ($VAR)
  3. runtime       -- /proc/<pid>/cmdline + /proc/<pid>/environ of running processes

Matching is done by SHA-256 fingerprint so the raw token is only ever held
in memory, never printed or persisted. Kernel reality, stated honestly:
``/proc/<pid>/cmdline`` is world-readable, but ``/proc/<pid>/environ`` is
only readable for processes owned by the same user (EACCES otherwise) --
other users' process environments cannot be scanned.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import state as _state  # for STATE_DIR default exclusion
from .fingerprint import TOKEN_RE, fingerprint, redact_line, tail

MAX_FILE_BYTES = 2 * 1024 * 1024  # skip anything bigger than 2 MiB

CONFIG_SUFFIXES = {
    ".env", ".yaml", ".yml", ".toml", ".json", ".ini", ".cfg", ".conf",
    ".service", ".unit", ".timer", ".txt", ".sh", ".py", ".js", ".ts",
}
CONFIG_BASENAMES = {".env", ".envrc", "credentials", "secrets"}
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".tox", ".mypy_cache"}


@dataclass
class Hit:
    fingerprint: str
    source: str  # "config" | "shell-env" | "proc-cmdline" | "proc-environ"
    location: str  # file path, or "pid 1234 (name)"
    detail: str  # "line 12", "$VAR_NAME", "cmdline", ...
    token_tail: str = ""
    preview: str = ""  # redacted line preview (configs only)
    # raw matched token -- IN MEMORY ONLY, never serialized or printed.
    raw: str = field(default="", repr=False, compare=False)

    def public_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "source": self.source,
            "location": self.location,
            "detail": self.detail,
            "token_tail": self.token_tail,
            "preview": self.preview,
        }


def _wanted_match(fp: str, wanted: set[str] | None) -> bool:
    return wanted is None or fp in wanted


def _is_candidate_file(path: str) -> bool:
    base = os.path.basename(path)
    if base in CONFIG_BASENAMES:
        return True
    _, ext = os.path.splitext(base)
    return ext.lower() in CONFIG_SUFFIXES


def scan_configs(
    dirs: list[str],
    wanted: set[str] | None,
    exclude_dirs: list[str] | None = None,
) -> list[Hit]:
    """Scan config files under dirs for tokens. wanted=None reports every token-shaped hit."""
    hits: list[Hit] = []
    excludes = [os.path.abspath(d) for d in (exclude_dirs or [str(_state.STATE_DIR)])]
    for top in dirs:
        if not os.path.isdir(top):
            continue
        for root, subdirs, files in os.walk(top, followlinks=False):
            subdirs[:] = [d for d in subdirs if d not in SKIP_DIRS]
            for name in files:
                path = os.path.join(root, name)
                apath = os.path.abspath(path)
                if any(apath == ex or apath.startswith(ex + os.sep) for ex in excludes):
                    continue
                if not _is_candidate_file(path):
                    continue
                try:
                    if os.path.getsize(path) > MAX_FILE_BYTES:
                        continue
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except (OSError, UnicodeError):
                    continue
                for lineno, line in enumerate(content.splitlines(), start=1):
                    for m in TOKEN_RE.finditer(line):
                        tok = m.group(0)
                        fp = fingerprint(tok)
                        if _wanted_match(fp, wanted):
                            hits.append(
                                Hit(
                                    fingerprint=fp,
                                    source="config",
                                    location=apath,
                                    detail=f"line {lineno}",
                                    token_tail=tail(tok),
                                    preview=redact_line(line.strip()[:160]),
                                    raw=tok,
                                )
                            )
    return hits


def scan_shell_env(wanted: set[str] | None) -> list[Hit]:
    """Scan this process's environment variables for tokens."""
    hits: list[Hit] = []
    for var, value in os.environ.items():
        for m in TOKEN_RE.finditer(value):
            tok = m.group(0)
            fp = fingerprint(tok)
            if _wanted_match(fp, wanted):
                hits.append(
                    Hit(
                        fingerprint=fp,
                        source="shell-env",
                        location=f"${var}",
                        detail=f"environment variable {var}",
                        token_tail=tail(tok),
                        raw=tok,
                    )
                )
    return hits


def _iter_pids() -> list[int]:
    pids: list[int] = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return pids
    for entry in entries:
        if entry.isdigit():
            pids.append(int(entry))
    return pids


def _read_proc_file(pid: int, name: str) -> bytes | None:
    try:
        with open(f"/proc/{pid}/{name}", "rb") as f:
            return f.read(65536)
    except (OSError, FileNotFoundError, PermissionError, ProcessLookupError):
        return None


def _comm(pid: int) -> str:
    data = _read_proc_file(pid, "comm")
    return data.decode("utf-8", "replace").strip() if data else "?"


def scan_processes(
    wanted: set[str] | None,
    exclude_pids: set[int] | None = None,
) -> list[Hit]:
    """Scan /proc cmdline + environ of running processes for tokens.

    environ is only readable for same-user processes (kernel EACCES for
    others) -- those are skipped, honestly. cmdline is world-readable.
    """
    hits: list[Hit] = []
    excluded = set(exclude_pids or set()) | {os.getpid()}
    for pid in _iter_pids():
        if pid in excluded:
            continue
        name = _comm(pid)
        # cmdline: argv joined by NUL bytes
        raw = _read_proc_file(pid, "cmdline")
        if raw:
            text = raw.decode("utf-8", "replace")
            for m in TOKEN_RE.finditer(text):
                tok = m.group(0)
                fp = fingerprint(tok)
                if _wanted_match(fp, wanted):
                    hits.append(
                        Hit(
                            fingerprint=fp,
                            source="proc-cmdline",
                            location=f"pid {pid} ({name})",
                            detail="process command line",
                            token_tail=tail(tok),
                            raw=tok,
                        )
                    )
        # environ: NUL-separated KEY=VALUE
        raw = _read_proc_file(pid, "environ")
        if raw:
            for entry in raw.decode("utf-8", "replace").split("\x00"):
                if "=" not in entry:
                    continue
                var, _, value = entry.partition("=")
                for m in TOKEN_RE.finditer(value):
                    tok = m.group(0)
                    fp = fingerprint(tok)
                    if _wanted_match(fp, wanted):
                        hits.append(
                            Hit(
                                fingerprint=fp,
                                source="proc-environ",
                                location=f"pid {pid} ({name})",
                                detail=f"environment variable {var}",
                                token_tail=tail(tok),
                                raw=tok,
                            )
                        )
    return hits
