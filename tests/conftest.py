"""Shared fixtures for the tg-rotate test suite.

The tokens below are SYNTHETIC fixtures -- they look like real Telegram
bot tokens so the discovery/fingerprint code paths exercise realistically,
but they were generated randomly and have never been issued by Telegram.
Never copy real tokens into tests.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tg_rotate import fingerprint


def make_token(bot_id: int = 123456789, seed: str = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOpQ1") -> str:
    """A synthetic, valid-shaped token for tests (never a real token)."""
    assert len(seed) >= 30
    return f"{bot_id}:{seed[:35]}"


OLD_TOKEN = make_token(123456789, "OLDoldOLDoldOLDoldOLDoldOLDoldOLDxYz")
NEW_TOKEN = make_token(123456789, "NEWnewNEWnewNEWnewNEWnewNEWnewNEWxYz")


@pytest.fixture()
def old_token() -> str:
    return OLD_TOKEN


@pytest.fixture()
def new_token() -> str:
    return NEW_TOKEN


@pytest.fixture()
def old_fp(old_token: str) -> str:
    return fingerprint.fingerprint(old_token)


@pytest.fixture()
def new_fp(new_token: str) -> str:
    return fingerprint.fingerprint(new_token)


@pytest.fixture()
def workspace(tmp_path: Path, old_token: str):
    """A fake bot deployment: .env, config yaml, and a python file holding the token."""
    root = tmp_path / "deploy"
    root.mkdir()
    (root / ".env").write_text(
        f"BOT_TOKEN={old_token}\nOTHER=1\n", encoding="utf-8")
    (root / "config.yaml").write_text(
        f"telegram:\n  token: \"{old_token}\"\n", encoding="utf-8")
    (root / "bot.py").write_text(
        f'TOKEN = "{old_token}"  # the bot token\n', encoding="utf-8")
    # A file that must be ignored: binary content.
    (root / "data.bin").write_bytes(os.urandom(256))
    return root


@pytest.fixture()
def clean_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point HOME at a temp dir so rotate_engine dirs stay hermetic."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return home
