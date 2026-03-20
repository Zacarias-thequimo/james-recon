from __future__ import annotations

import sys
from pathlib import Path


def get_base_dir() -> Path:
    """Return base directory — works both in dev and PyInstaller bundle."""
    if getattr(sys, "_MEIPASS", None):
        return Path(sys._MEIPASS)
    return Path(__file__).parent.parent


def wordlist(name: str) -> Path:
    return get_base_dir() / "wordlists" / name
