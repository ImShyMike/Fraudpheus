"""Daily DM reminder service for active threads"""

import threading
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from src.config import (
    CHANNEL,
    CHECK_INTERVAL_SECONDS,
    REMINDER_INTERVAL_HOURS,
    slack_client,
)

if TYPE_CHECKING:
    from src.services.thread_manager import ThreadManager

_timer: threading.Timer | None = None
_running = False  # pylint: disable=C0103


def _send_reminder(creator_id: str, user_id: str, thread_ts: str) -> bool:
    """Send a reminder DM to the creator of an inactive thread"""
    try:
        response: dict[str, Any] = slack_client.conversations_open(  # type: ignore
            users=[creator_id]
        )
        dm_channel: str = response["channel"]["id"]  # type: ignore

        thread_url = (
            f"https://hackclub.slack.com/archives"
            f"/{CHANNEL}/p{thread_ts.replace('.', '')}"
        )

        slack_client.chat_postMessage(  # type: ignore
            channel=dm_channel,
            text=(
                f"*Reminder:* <@{user_id}>'s case is still open "
                f"and has been inactive for over {REMINDER_INTERVAL_HOURS} hours.\n\n"
                f"<{thread_url}|View thread>"
            ),
            username="Thread Reminder",
            icon_emoji=":bell:",
        )
        return True
    except Exception as err:  # pylint: disable=broad-except
        print(f"Failed to send daily reminder to {creator_id} about {user_id}: {err}")
        return False


def _check_and_remind(thread_manager: "ThreadManager") -> None:
    """Check all active threads and send reminders"""
    global _timer  # pylint: disable=global-statement

    if not _running:
        return

    now = datetime.now()

    for user_id, thread_info in list(thread_manager.active_cache.items()):
        creator_id = thread_info.get("creator_id")
        if not creator_id:
            continue  # this isn't an fdchat thread

        if thread_manager.is_resolved(user_id):
            continue  # thread is resolved, no reminders

        last_activity = thread_info.get("last_activity", now)
        time_since_activity = now - last_activity
        if time_since_activity < timedelta(hours=REMINDER_INTERVAL_HOURS):
            continue # thread is still active

        created_at = thread_info.get("created_at", now)
        if last_activity == created_at:
            continue # thread is empty

        thread_ts = thread_info.get("thread_ts", "")
        if not thread_ts:
            continue

        if _send_reminder(creator_id, user_id, thread_ts):
            print(f"Sent daily reminder to creator {creator_id} about user {user_id}")

    # schedule the next check
    _timer = threading.Timer(
        CHECK_INTERVAL_SECONDS, _check_and_remind, args=[thread_manager]
    )
    _timer.daemon = True
    _timer.start()


def start_reminder_service(thread_manager: "ThreadManager") -> None:
    """Start the daily reminder background service"""
    global _running, _timer  # pylint: disable=global-statement

    if _running:
        print("Daily reminder service is already running")
        return

    _running = True
    print("Starting daily reminder service")

    _timer = threading.Timer(
        CHECK_INTERVAL_SECONDS, _check_and_remind, args=[thread_manager]
    )
    _timer.daemon = True
    _timer.start()


def stop_reminder_service() -> None:
    """Stop the daily reminder background service"""
    global _running, _timer  # pylint: disable=global-statement

    _running = False
    if _timer:
        _timer.cancel()
        _timer = None
    print("Stopped daily reminder service")
