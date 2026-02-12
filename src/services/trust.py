"""Trust level lookups."""

import httpx


def get_user_trust_level(slack_id: str) -> int:
    """Get user's trust level from hackatime API."""
    try:
        response = httpx.get(
            f"https://hackatime.hackclub.com/api/v1/users/{slack_id}/trust_factor",
            headers={"content-type": "application/json"},
            timeout=10,
        )

        if response.status_code == 200:
            data = response.json()
            return int(data.get("trust_value", 4))

        return 4
    except Exception as err:  # pylint: disable=broad-except
        print(f"Error fetching trust level for {slack_id}: {err}")
        return 4
