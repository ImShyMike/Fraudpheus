"""Trust level lookups"""

from typing import TypedDict

import httpx

from src.config import HACKATIME_ADMIN_KEY

TRUST_LEVEL_MAP = {
    "blue": 0,
    "red": 1,
    "green": 2,
    "yellow": 3,
    "none": 4,
}


class UserStatsDict(TypedDict):
    """Structure for user stats"""

    total_heartbeats: int
    total_coding_time: int
    languages_used: int
    projects_worked_on: int
    days_active: int


class UserInfoDict(TypedDict):
    """Structure for user info"""

    id: str
    timezone: str
    country_code: str | None
    trust_level: str
    created_at: str
    last_heartbeat_at: str | None
    email_addresses: list[str]
    stats: UserStatsDict


class UserPayloadDict(TypedDict):
    """Payload for user data"""

    user: UserInfoDict


def get_trust_level(user_data: UserInfoDict | None) -> int:
    """Get trust level ID from user data"""
    if not user_data:
        return 4
    trust_level = user_data.get("trust_level") or "none"
    return TRUST_LEVEL_MAP.get(trust_level, 4)


def format_creation_date(user_data: UserInfoDict | None) -> str:
    """Format creation date from user data to YYYY-MM-DD format"""
    if not user_data or not user_data.get("created_at"):
        return "N/A"
    return user_data.get("created_at", "N/A").split("T")[0]


def format_coding_time(user_data: UserInfoDict | None) -> str:
    """Format total coding time from user data to 'Xh Ym' format"""
    if not user_data:
        return "N/A"
    total_coding_seconds = user_data.get("stats", {}).get("total_coding_time", 0)
    if total_coding_seconds == 0:
        return "N/A"
    hours = total_coding_seconds // 3600
    minutes = (total_coding_seconds % 3600) // 60
    return f"{hours}h {minutes}m"


def get_hackatime_id_from_slack_id(slack_id: str) -> str | None:
    """Get hackatime user ID from Slack ID"""
    if not HACKATIME_ADMIN_KEY:
        return None

    try:
        response = httpx.get(
            f"https://hackatime.hackclub.com/api/v1/users/{slack_id}/stats",
            headers={"content-type": "application/json"},
            timeout=10,
        )

        if response.status_code == 200:
            raw_data: dict[str, dict[str, str]] = response.json()
            stats_data: dict[str, str] = raw_data.get("data", {})
            return stats_data.get("user_id")
        else:
            print(
                f"Failed to fetch hackatime ID for {slack_id} "
                f"({response.status_code}): {response.text}"
            )
            return None
    except Exception as err:  # pylint: disable=broad-except
        print(f"Error fetching hackatime ID for {slack_id}: {err}")
        return None


def get_user_data(slack_id: str) -> UserInfoDict | None:
    """Get user's data from Hackatime"""
    if not HACKATIME_ADMIN_KEY:
        return None

    user_id = get_hackatime_id_from_slack_id(slack_id)

    if not user_id:
        return None

    try:
        response = httpx.get(
            f"https://hackatime.hackclub.com/api/admin/v1/user/info?user_id={user_id}",
            headers={
                "content-type": "application/json",
                "Authorization": f"Bearer {HACKATIME_ADMIN_KEY}",
            },
            timeout=10,
        )

        if response.status_code == 200:
            data: UserPayloadDict = response.json()
            return data.get("user")

        print(
            f"Failed to fetch trust level for {slack_id} ({response.status_code}): {response.text}"
        )
        return None
    except Exception as err:  # pylint: disable=broad-except
        print(f"Error fetching trust level for {slack_id}: {err}")
        return None
