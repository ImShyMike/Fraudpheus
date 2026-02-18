"""Trust level lookups"""

import httpx

from src.config import HACKATIME_ADMIN_KEY

TRUST_LEVEL_MAP = {
    "blue": 0,
    "red": 1,
    "green": 2,
    "yellow": 3,
    "none": 4,
}


def get_user_trust_level(slack_id: str) -> int:
    """Get user's trust level from hackatime API"""
    if not HACKATIME_ADMIN_KEY:
        return 4

    try:
        response = httpx.get(
            f"https://hackatime.hackclub.com/api/v1/users/{slack_id}/stats",
            headers={"content-type": "application/json"},
            timeout=10,
        )

        if response.status_code == 200:
            raw_data: dict[str, dict[str, str]] = response.json()
            stats_data: dict[str, str] = raw_data.get("data", {})
            user_id = stats_data.get("user_id")
        else:
            return 4
    except Exception as err:  # pylint: disable=broad-except
        print(f"Error fetching trust level for {slack_id}: {err}")
        return 4

    if not user_id:
        return 4

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
            data: dict[str, dict[str, str]] = response.json()
            user: dict[str, str] = data.get("user", {})
            trust_level = user.get("trust_level", "none")
            return TRUST_LEVEL_MAP.get(trust_level, 4)

        print(
            f"Failed to fetch trust level for {slack_id} ({response.status_code}): {response.text}"
        )
        return 4
    except Exception as err:  # pylint: disable=broad-except
        print(f"Error fetching trust level for {slack_id}: {err}")
        return 4
