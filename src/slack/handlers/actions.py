"""Slack action handlers"""

import time
from datetime import datetime, timezone
from typing import Any, Optional

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from src.config import CHANNEL, slack_app, slack_user_client
from src.slack.helpers import thread_manager
from src.services.webhook_dispatcher import dispatch_event


@slack_app.action("mark_completed")  # type: ignore
def handle_mark_completed(ack: Any, body: dict[str, Any], client: WebClient) -> None:
    """Complete the thread."""
    ack()

    user_id: str = body["actions"][0]["value"]
    messages_ts: str = body["message"]["ts"]

    try:
        client.reactions_add(  # type: ignore
            channel=CHANNEL, timestamp=messages_ts, name="white_check_mark"
        )

        success = thread_manager.complete_thread(user_id)
        if success:
            print(f"Marked thread for user {user_id} as completed")
            dispatch_event(
                "thread.status.changed",
                {
                    "thread_ts": body["message"]["ts"],
                    "user_slack_id": user_id,
                    "new_status": "completed",
                    "timestamp": datetime.now(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                },
            )
        else:
            print(f"Failed to mark {user_id}'s thread as completed")

    except SlackApiError as err:
        print(f"Error marking thread as completed: {err}")


@slack_app.action("delete_thread")  # type: ignore
def handle_delete_thread(ack: Any, body: dict[str, Any], client: WebClient) -> None:
    """Handle deleting thread."""
    ack()

    user_id: str = body["actions"][0]["value"]
    message_ts: str = body["message"]["ts"]

    try:
        thread_info: Any = {}

        if (
            user_id in thread_manager.active_cache
            and thread_manager.active_cache[user_id]["message_ts"] == message_ts
        ):
            thread_info = thread_manager.active_cache[user_id]
        elif user_id in thread_manager.completed_cache:
            for thread in thread_manager.completed_cache[user_id]:
                if thread["message_ts"] == message_ts:
                    thread_info = thread
                    break

        if not thread_info:
            print(f"Couldn't find thread info for {user_id} (messages ts {message_ts})")
            return

        thread_ts: Optional[str] = thread_info["thread_ts"]

        try:
            cursor: Optional[str] = None
            while True:
                api_args: dict[str, Any] = {
                    "channel": CHANNEL,
                    "ts": thread_ts,
                    "inclusive": True,
                    "limit": 100,
                }

                if cursor:
                    api_args["cursor"] = cursor

                response: dict[str, Any] = client.conversations_replies(**api_args)  # type: ignore
                messages: list[dict[str, Any]] = response["messages"]

                for msg in messages:
                    try:
                        slack_user_client.chat_delete(  # type: ignore
                            channel=CHANNEL, ts=msg["ts"], as_user=True
                        )
                        time.sleep(0.3)

                    except SlackApiError:
                        try:
                            client.chat_delete(channel=CHANNEL, ts=msg["ts"])  # type: ignore
                            time.sleep(0.3)

                        except SlackApiError as delete_err:
                            print(f"Couldn't delete messages {msg['ts']}: {delete_err}")
                            time.sleep(0.2)
                            continue

                if response.get("has_more", False) and response.get(
                    "response_metadata", {}
                ).get("next_cursor"):
                    cursor = response["response_metadata"]["next_cursor"]
                else:
                    break

        except SlackApiError as err:
            print(f"Error deleting thread: {err}")

        thread_manager.delete_thread(user_id, message_ts)

    except SlackApiError as err:
        print(f"Error deleting thread: {err}")
