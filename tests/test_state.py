"""State-file tests: recording, persistence, and the no-token rule."""
from __future__ import annotations

import json

from tg_rotate import state


def test_record_and_reload(tmp_path, old_fp, new_fp):
    p = tmp_path / "state.json"
    st = state.load(p)
    st.record("run-1", "done", old_fp, new_fp, ok=True, detail="ok")
    state.save(st, p)
    st2 = state.load(p)
    run = st2.last_successful_run()
    assert run["run_id"] == "run-1"
    assert run["new_fp"] == new_fp
    assert old_fp in p.read_text()  # fingerprints, not tokens


def test_never_stores_full_token(tmp_path, old_token, new_token, old_fp, new_fp):
    p = tmp_path / "state.json"
    st = state.load(p)
    st.record("run-1", "done", old_fp, new_fp)
    state.save(st, p)
    blob = p.read_text()
    assert old_token not in blob
    assert new_token not in blob


def test_corrupt_state_starts_fresh_but_keeps_backup(tmp_path):
    p = tmp_path / "state.json"
    p.write_text("{not json", encoding="utf-8")
    st = state.load(p)
    assert st.runs == []
    assert (tmp_path / "state.json.corrupt").exists()


def test_last_successful_run_skips_failures(tmp_path, old_fp, new_fp):
    p = tmp_path / "state.json"
    st = state.load(p)
    st.record("r1", "rollback", old_fp, new_fp, ok=False)
    st.record("r2", "done", old_fp, new_fp, ok=True)
    assert st.last_successful_run()["run_id"] == "r2"


def test_save_is_mode_600(tmp_path):
    import os
    p = tmp_path / "state.json"
    state.save(state.State(), p)
    assert oct(p.stat().st_mode & 0o777) == "0o600"
