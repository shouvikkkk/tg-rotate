"""Discovery tests: find every copy, skip the noise."""
from __future__ import annotations

from tg_rotate import discover


def test_finds_all_three_copies(workspace, old_token):
    locs = discover.find_token_locations([workspace], old_token)
    assert len(locs) == 3
    names = sorted(l.path.name for l in locs)
    assert names == [".env", "bot.py", "config.yaml"]
    for loc in locs:
        assert loc.fingerprint


def test_ignores_binary_and_unrelated(workspace, old_token):
    # data.bin holds random bytes; no text file mentions the token besides 3.
    locs = discover.find_token_locations([workspace], old_token)
    assert all(l.path.suffix != ".bin" for l in locs)


def test_no_locations_when_absent(workspace, new_token):
    assert discover.find_token_locations([workspace], new_token) == []


def test_skips_huge_files(tmp_path, old_token):
    big = tmp_path / "big.log"
    big.write_bytes(b"x" * (discover.MAX_FILE_BYTES + 1024))
    locs = discover.find_token_locations([tmp_path], old_token)
    assert locs == []


def test_redacted_preview_never_contains_token(workspace, old_token):
    locs = discover.find_token_locations([workspace], old_token)
    assert locs
    for loc in locs:
        assert old_token not in loc.preview
        assert "[token" in loc.preview


def test_hidden_dirs_skipped(tmp_path, old_token):
    hidden = tmp_path / ".git"
    hidden.mkdir()
    (hidden / "config").write_text(f"tok={old_token}\n", encoding="utf-8")
    assert discover.find_token_locations([tmp_path], old_token) == []
