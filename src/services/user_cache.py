"""Cached user info helpers."""

from typing import Optional

from src.slack.helpers import UserInfo, get_user_info

_user_cache: dict[str, UserInfo] = {}


def cached_user_info(user_id: str) -> Optional[UserInfo]:
    """Get user info with caching."""
    if not user_id:
        return None
    if user_id in _user_cache:
        return _user_cache[user_id]
    info: Optional[UserInfo] = get_user_info(user_id)
    if info:
        _user_cache[user_id] = info
    return info


def get_user_name(user_id: Optional[str]) -> str:
    """Get user display name, falling back to 'Unknown'."""
    if not user_id:
        return "Unknown"
    info = cached_user_info(user_id)
    return info["name"] if info else "Unknown"
