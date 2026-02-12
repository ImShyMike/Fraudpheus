"""Macros for common messages"""

import tomllib

with open("macros.toml", "rb") as f:
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
