"""Thread and message helpers"""

import re
from datetime import datetime, timezone
from typing import Any, Optional

from slack_sdk.errors import SlackApiError

from src.config import CHANNEL, JOE_URL, TRUST_EMOJI, TRUST_LABELS, slack_client
from src.services.hackatime import (
    format_coding_time,
    format_creation_date,
    get_trust_level,
    get_user_data,
)
from src.services.user_cache import get_user_name
from src.services.webhook_dispatcher import dispatch_event
from src.slack.helpers import (
    UserInfo,
    download_reupload_files,
    get_standard_channel_msg,
    thread_manager,
)


def extract_user_id(text: str) -> Optional[str]:
    """Extracts user ID from a mention text <@U000000> or from a direct ID"""
    mention_format = re.search(r"<@([A-Z0-9]+)>", text)
    if mention_format:
        return mention_format.group(1)

    id_match = re.search(r"\b(U[A-Z0-9]{8,})\b", text)
    if id_match:
        return id_match.group(1)

    return None


def get_past_threads_info(user_id: str) -> str:
    """Get formatted info about user's past threads"""
    completed_threads = thread_manager.get_completed_threads(user_id)

    if not completed_threads:
        return "No previous threads"

    thread_links: list[str] = []
    for thread in completed_threads[:5]:
        thread_ts = thread.get("thread_ts", "")
        if thread_ts:
            thread_url = (
                "https://hackclub.slack.com/archives"
                f"/{CHANNEL}/p{thread_ts.replace('.', '')}"
            )
            thread_links.append(f"• <{thread_url}|Thread from {thread_ts}>")

    result = f"*Past threads ({len(completed_threads)} total):*\n" + "\n".join(
        thread_links
    )
    if len(completed_threads) > 5:
        result += f"\n_...and {len(completed_threads) - 5} more_"

    return result


def post_message_to_channel(
    user_id: str,
    message_text: str,
    user_info: UserInfo,
    files: Optional[list[dict[str, Any]]] = None,
) -> Optional[bool]:
    """Post user's message to the given channel, either as new message or new reply"""
    if not message_text or message_text.strip() == "":
        return None

    if thread_manager.has_active_thread(user_id):
        thread_info = thread_manager.get_active_thread(user_id)
        if not thread_info:
            print(f"Could not retrieve thread info for user {user_id}")
            return False
        thread_ts = thread_info.get("thread_ts")
        if not thread_ts:
            print(f"Could not retrieve thread ts for user {user_id}")
            return False

        try:
            response: dict[str, Any] = slack_client.chat_postMessage(  # type: ignore
                channel=CHANNEL,
                thread_ts=thread_ts,
                text=f"{message_text}",
                username=user_info["display_name"],
                icon_url=user_info["avatar"],
            )

            if files:
                download_reupload_files(files, CHANNEL, thread_ts)

            file_name = files[0].get("name", "unknown") if files else "unknown"
            if file_name == "history.zip":
                print(f"Received history.zip file from user {user_id}")
                slack_client.chat_postMessage(  # type: ignore
                    channel=CHANNEL,
                    thread_ts=thread_ts,
                    text=f"<{JOE_URL}/history|Open in Joe>",
                    username="History Folder",
                    icon_emoji=":file_folder:",
                )

            thread_manager.update_thread_activity(user_id)
            if thread_manager.is_resolved(user_id):
                thread_manager.unresolve_thread(user_id)
                slack_client.chat_postMessage(  # type: ignore
                    channel=CHANNEL,
                    thread_ts=thread_ts,
                    text=(f"Thread with <@{user_id}> has been unresolved."),
                    username="Thread Info",
                    icon_emoji=":information_source:",
                    reply_broadcast=True,
                )
                slack_client.reactions_remove(  # type: ignore
                    channel=CHANNEL, timestamp=thread_ts, name="ballot_box_with_check"
                )
            dispatch_event(
                "message.user.new",
                {
                    "thread_ts": thread_ts,
                    "message": {
                        "id": response["ts"],
                        "content": message_text,
                        "timestamp": datetime.fromtimestamp(float(response["ts"]))
                        .astimezone(timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z"),
                        "is_from_user": True,
                        "author": {"name": user_info["display_name"]},
                    },
                },
            )
            return True

        except SlackApiError as err:
            print(f"Error writing to a thread: {err}")
            return False
    else:
        return create_new_thread(user_id, message_text, user_info, files)


def create_new_thread(
    user_id: str,
    message_text: str,
    user_info: UserInfo,
    files: Optional[list[dict[str, Any]]] = None,
) -> bool:
    """Create new thread in the channel"""
    try:
        response: dict[str, Any] = slack_client.chat_postMessage(  # type: ignore
            channel=CHANNEL,
            text=f"*{user_id}*:\n{message_text}",
            username=user_info["display_name"],
            icon_url=user_info["avatar"],
            blocks=get_standard_channel_msg(user_id, message_text),
        )

        success = thread_manager.create_active_thread(
            user_id, CHANNEL, response["ts"], response["ts"]
        )
        if success:
            user_data = get_user_data(user_id)
            trust_level = get_trust_level(user_data)
            trust_emoji = TRUST_EMOJI.get(trust_level, TRUST_EMOJI[4])
            trust_label = TRUST_LABELS.get(trust_level, TRUST_LABELS[4])
            past_threads = get_past_threads_info(user_id)

            emails = ", ".join(user_data["email_addresses"]) if user_data else "N/A"
            creation_date = format_creation_date(user_data)
            coding_time_str = format_coding_time(user_data)

            new_msg: dict[str, Any] = slack_client.chat_postMessage(  # type: ignore
                channel=CHANNEL,
                thread_ts=response["ts"],
                text=(
                    f"*User Info:*\n • Trust Level: {trust_label} {trust_emoji}"
                    f"\n • Emails: {emails}\n • Created: {creation_date}"
                    f"\n • Total Coding Time: {coding_time_str}\n\n{past_threads}\n\n"
                    f"<{JOE_URL}/profile/{user_id}|Open in Joe>"
                ),
                username="Thread Info",
                icon_emoji=":information_source:",
            )
            new_msg_ts: str = new_msg["ts"]

            if files:
                download_reupload_files(files, CHANNEL, new_msg_ts)

            dispatch_event(
                "thread.created",
                {
                    "thread_ts": response["ts"],
                    "user_slack_id": user_id,
                    "started_at": datetime.fromtimestamp(float(response["ts"]))
                    .astimezone(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "initial_message": "User initiated case",
                },
            )

            dispatch_event(
                "message.user.new",
                {
                    "thread_ts": response["ts"],
                    "message": {
                        "id": response["ts"],
                        "content": message_text,
                        "timestamp": datetime.fromtimestamp(float(response["ts"]))
                        .astimezone(timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z"),
                        "is_from_user": True,
                        "author": {"name": user_info["display_name"]},
                    },
                },
            )
        else:
            print(f"Failed to create thread for user {user_id}")

        return success

    except SlackApiError as err:
        print(f"Error creating new thread: {err}")
        return False


def get_author_name(user_id: str) -> str:
    """Get author name for event dispatch, falling back to 'Unknown'"""
    return get_user_name(user_id)
