"""Backup export helpers"""

from datetime import datetime, timezone
from typing import Any, Optional, TypedDict

from slack_sdk.errors import SlackApiError

from src.config import CHANNEL, slack_client
from src.slack.helpers import thread_manager


class BackupMessage(TypedDict):
    """Structure for a message in backup export"""

    ts: str
    user: Optional[str]
    text: str
    timestamp: Optional[str]
    is_bot: bool
    bot_id: Optional[str]
    username: Optional[str]
    is_from_reported_user: bool


class BackupCase(TypedDict):
    """Structure for a fraud case in backup export"""

    case_id: str
    reported_user_id: str
    status: str
    thread_ts: str
    messages: list[BackupMessage]
    created_at: Optional[str]
    last_activity: Optional[str]
    total_messages: int


class BackupThread(TypedDict):
    """Structure for a thread in backup export"""

    user_id: str
    thread_ts: str
    status: str


class BackupUser(TypedDict):
    """Structure for a user in backup export"""

    id: str
    name: str
    real_name: str
    display_name: str
    email: str
    is_bot: bool
    avatar: str


class BackupStats(TypedDict):
    """Structure for backup export statistics"""

    total_cases: int
    active_cases: int
    completed_cases: int
    total_users: int
    total_messages: int


class BackupExport(TypedDict):
    """Structure for backup export data"""

    export_timestamp: str
    channel_id: str
    fraud_cases: list[BackupCase]
    users: dict[str, BackupUser]
    statistics: Optional[BackupStats]


def get_user_info_for_backup(user_id: str) -> BackupUser:
    """Get user info for backup export"""
    try:
        response: dict[str, Any] = slack_client.users_info(user=user_id)  # type: ignore
        user = response["user"]
        return {
            "id": user_id,
            "name": user.get("name", ""),
            "real_name": user.get("real_name", ""),
            "display_name": user.get("profile", {}).get("display_name", ""),
            "email": user.get("profile", {}).get("email", ""),
            "is_bot": user.get("is_bot", False),
            "avatar": user.get("profile", {}).get("image_72", ""),
        }
    except SlackApiError as e:
        print(f"Error getting user info for {user_id}: {e}")
        return {
            "id": user_id,
            "name": "unknown",
            "real_name": "Unknown User",
            "display_name": "Unknown",
            "email": "",
            "is_bot": False,
            "avatar": "",
        }


def create_backup_export() -> Optional[BackupExport]:
    """Export all thread data to JSON with full message history"""
    try:
        backup_data: BackupExport = {
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "channel_id": CHANNEL,
            "fraud_cases": [],
            "users": {},
            "statistics": None,
        }

        all_threads: list[BackupThread] = []

        for user_id, thread_info in thread_manager.active_cache.items():
            thread_ts = thread_info.get("thread_ts")
            if thread_ts:
                all_threads.append(
                    {"user_id": user_id, "thread_ts": thread_ts, "status": "active"}
                )

        for user_id, threads in thread_manager.completed_cache.items():
            for thread in threads:
                thread_ts = thread.get("thread_ts")
                if thread_ts:
                    all_threads.append(
                        {
                            "user_id": user_id,
                            "thread_ts": thread_ts,
                            "status": "completed",
                        }
                    )

        for thread_data in all_threads:
            user_id = thread_data["user_id"]
            thread_ts = thread_data["thread_ts"]
            status = thread_data["status"]

            try:
                response = slack_client.conversations_replies(  # type: ignore
                    channel=CHANNEL, ts=thread_ts, limit=1000
                )
                messages = response.get("messages", [])

                if not messages:
                    continue

                if user_id not in backup_data["users"]:
                    backup_data["users"][user_id] = get_user_info_for_backup(user_id)

                case_data: BackupCase = {
                    "case_id": thread_ts,
                    "reported_user_id": user_id,
                    "status": status,
                    "thread_ts": thread_ts,
                    "messages": [],
                    "created_at": None,
                    "last_activity": None,
                    "total_messages": len(messages),
                }

                for i, message in enumerate(messages):
                    msg_user_id = message.get("user")

                    if msg_user_id and msg_user_id not in backup_data["users"]:
                        backup_data["users"][msg_user_id] = get_user_info_for_backup(
                            msg_user_id
                        )

                    message_data: BackupMessage = {
                        "ts": message.get("ts"),
                        "user": msg_user_id,
                        "text": message.get("text", ""),
                        "timestamp": datetime.fromtimestamp(
                            float(message.get("ts", 0))
                        ).isoformat()
                        if message.get("ts")
                        else None,
                        "is_bot": message.get("bot_id") is not None,
                        "bot_id": message.get("bot_id"),
                        "username": message.get("username"),
                        "is_from_reported_user": msg_user_id == user_id
                        and not message.get("bot_id"),
                    }

                    case_data["messages"].append(message_data)

                    if i == 0:
                        case_data["created_at"] = message_data["timestamp"]

                    case_data["last_activity"] = message_data["timestamp"]

                backup_data["fraud_cases"].append(case_data)

            except Exception as err:  # pylint: disable=broad-except
                print(f"Error fetching thread {thread_ts}: {err}")

        backup_data["statistics"] = {
            "total_cases": len(backup_data["fraud_cases"]),
            "active_cases": len(
                [c for c in backup_data["fraud_cases"] if c["status"] == "active"]
            ),
            "completed_cases": len(
                [c for c in backup_data["fraud_cases"] if c["status"] == "completed"]
            ),
            "total_users": len(backup_data["users"]),
            "total_messages": sum(
                c["total_messages"] for c in backup_data["fraud_cases"]
            ),
        }

        return backup_data

    except Exception as err:  # pylint: disable=broad-except
        print(f"Error creating backup export: {err}")
        return None
