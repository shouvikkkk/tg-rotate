"""Rotation state file (``~/.tg-rotate/state.json``).

Records every rotation run: its phases, timestamps, and the SHA-256
fingerprints of the old and new tokens. FULL TOKENS ARE NEVER WRITTEN
HERE -- only fingerprints. The file is mode 0600 because even
fingerprints deserve a locked drawer.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
from dataclasses import dataclass, field
from pathlib import Path


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class RunRecord:
    run_id: str
    started: str = field(default_factory=_now)
    phases: list[dict] = field(default_factory=list)
    old_fp: str = ""
    new_fp: str = ""
    ok: bool = False
    finished: str | None = None

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "started": self.started,
            "finished": self.finished,
            "phases": self.phases,
            "old_fp": self.old_fp,
            "new_fp": self.new_fp,
            "ok": self.ok,
        }


@dataclass
class State:
    runs: list[dict] = field(default_factory=list)

    def record(self, run_id: str, phase: str, old_fp: str, new_fp: str,
               ok: bool = True, detail: str = "") -> dict:
        run = next((r for r in self.runs if r["run_id"] == run_id), None)
        if run is None:
            run = RunRecord(run_id=run_id, old_fp=old_fp, new_fp=new_fp).to_dict()
            self.runs.append(run)
        run["phases"].append({
            "phase": phase, "at": _now(), "ok": ok, "detail": detail,
        })
        if phase in ("done", "rollback"):
            run["ok"] = ok and phase == "done"
            run["finished"] = _now()
        return run

    def last_successful_run(self) -> dict | None:
        for run in reversed(self.runs):
            if run.get("ok"):
                return run
        return None

    def to_dict(self) -> dict:
        return {"runs": self.runs}


def load(path: Path) -> State:
    if not path.exists():
        return State()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        st = State()
        st.runs = data.get("runs", []) if isinstance(data, dict) else []
        return st
    except (json.JSONDecodeError, OSError, ValueError):
        # A corrupt state file must not block a rotation; start fresh but
        # keep a backup of the corrupt file for forensics.
        try:
            path.replace(path.with_suffix(".json.corrupt"))
        except OSError:
            pass
        return State()


def save(state: State, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(state.to_dict(), indent=2) + "\n"
    # Atomic write: temp file + os.replace, then lock down permissions.
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
