"""Case tags system"""

import re
import tomllib
from pathlib import Path
from typing import Any, Optional, TypedDict, cast


class Tag(TypedDict):
    """Definition of a case tag"""

    true_name: str
    name: str
    info: Optional[str]
    user_autoresponse: Optional[str]
    triggers: list[str]
    priority: int


class TagInfo(TypedDict):
    """Structure for tag info"""

    name: str
    info: Optional[str]


_TAGS_FILE = Path(__file__).resolve().parents[2] / "tags.toml"

with _TAGS_FILE.open("rb") as f:
    raw_tags = cast(dict[str, dict[str, Any]], tomllib.load(f))
    TAGS: list[Tag] = [
        cast(
            Tag,
            {
                **value,
                "true_name": class_name,
                "name": value.get("name") or class_name,
            },
        )
        for class_name, value in raw_tags.items()
    ]


def get_tags_for_text(text: str) -> list[Tag]:
    """Get a list of tags that match the given text"""
    text = text.lower()
    matched_tags: list[Tag] = []
    for tag in TAGS:
        for trigger in tag["triggers"]:
            if re.search(trigger, text, re.IGNORECASE):
                matched_tags.append(tag)
                break

    matched_tags.sort(key=lambda tag: tag["priority"], reverse=True)
    return matched_tags


def get_tag_info(tag: Optional[Tag]) -> Optional[TagInfo]:
    """Get tag info for a given tag"""
    if not tag:
        return None
    return {
        "name": tag["name"],
        "info": tag.get("info"),
    }
