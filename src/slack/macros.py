"""Macros for common messages"""

import tomllib
from pathlib import Path

_MACROS_FILE = Path(__file__).resolve().parents[2] / "macros.toml"

with _MACROS_FILE.open("rb") as f:
    raw_macros = tomllib.load(f)
    MACROS = {f"${k}": v.strip() for k, v in raw_macros.items()}


def expand_macros(text: str) -> str:
    """Expand macros in the given text"""
    if not text:
        return text

    for macro, replacement in MACROS.items():
        if macro in text:
            text = text.replace(macro, replacement)

    return text
