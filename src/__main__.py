"""Main entry point"""

import asyncio
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional, TypedDict

import httpx
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from src.config import (
    CHANNEL,
    TRUST_EMOJI,
    TRUST_LABELS,
    airtable_base,
    slack_app,
    slack_client,
    slack_user_client,
)
from src.macros import MACROS, expand_macros
from src.thread_manager import ThreadManager
from src.webhooks import dispatch_event as dispatch_event_async

thread_manager = ThreadManager(airtable_base, slack_client)


class UserInfo(TypedDict):
    """Structure for user info"""

    name: str
    avatar: str
    display_name: str


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


def dispatch_event(event_type: str, data: dict[str, Any]):
    """Dispatch an event to all configured webhooks asynchronously."""
    asyncio.run(dispatch_event_async(event_type, data))


def get_user_trust_level(slack_id: str):
    """Get user's trust level from hackatime API"""
    try:
        response = httpx.post(
            f"https://hackatime.hackclub.com/api/v1/users/{slack_id}/trust_factor",
            headers={
                "content-type": "application/json",
            },
            timeout=10,
        )

        if response.status_code == 200:
            data = response.json()
            return data.get("trust_value", 4)

        return 4
    except Exception as err:  # pylint: disable=broad-except
        print(f"Error fetching trust level for {slack_id}: {err}")
        return 4


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


def check_inactive_threads():
    """Check for inactive threads and send close message after 5 days"""
    # while True:
    #     try:
    #         time.sleep(3600 * 12)
    #         inactive_threads = thread_manager.get_inactive_threads(120)

    #         for thread in inactive_threads:
    #             user_id = thread["user_id"]
    #             thread_info = thread["thread_info"]
    #             hours_inactive = thread["hours_inactive"]

    #             if hours_inactive >= 120:
    #                 try:
    #                     dm_response = client.conversations_open(users=[user_id])
    #                     dm_channel = dm_response["channel"]["id"]

    #                     client.chat_postMessage(
    #                         channel=dm_channel,
    #                         text="Heyo, it seems like this thread has gone quiet for a while. There is a good chance that this case is now resolved! If not, please open a new thread! :ohneheart:",
    #                         username="Arnav",
    #                         icon_emoji=":ban:"
    #                     )

    #                     thread_manager.complete_thread(user_id)
    #                     print(f"Auto-closed thread for user {user_id} after {hours_inactive} hours of inactivity")

    #                 except Exception as err:
    #                     print(f"Error auto-closing thread for user {user_id}: {err}")

    #     except Exception as err:
    #         print(f"Error in inactive thread checker: {err}")


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


def create_backup_export():
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

        # Collect active threads
        for user_id, thread_info in thread_manager.active_cache.items():
            thread_ts = thread_info.get("thread_ts")
            if thread_ts:
                all_threads.append(
                    {"user_id": user_id, "thread_ts": thread_ts, "status": "active"}
                )

        # Collect completed threads
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

        # Extract full message data for each thread
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

                # Get user info
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


def get_standard_channel_msg(user_id: str, message_text: str) -> list[dict[str, Any]]:
    """Get blocks for a standard message uploaded into channel with 2 buttons"""
    return [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"<@{user_id}> (User ID: `{user_id}`)"},
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": message_text}},
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Reply in this thread to send a response to the user",
                }
            ],
        },
        {
            "type": "actions",
            "elements": [
                {  # Complete this pain of a thread
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Mark as Completed"},
                    "style": "primary",
                    "action_id": "mark_completed",
                    "value": user_id,
                    "confirm": {
                        "title": {"type": "plain_text", "text": "Are you sure?"},
                        "text": {
                            "type": "mrkdwn",
                            "text": "This will mark the thread as complete.",
                        },
                        "confirm": {"type": "plain_text", "text": "Mark as Completed"},
                        "deny": {"type": "plain_text", "text": "Cancel"},
                    },
                },
                {  # Delete it pls
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Delete thread"},
                    "style": "danger",
                    "action_id": "delete_thread",
                    "value": user_id,
                    "confirm": {
                        "title": {"type": "plain_text", "text": "Are you sure?"},
                        "text": {
                            "type": "mrkdwn",
                            "text": "This will delete the entire thread and new replies will go into a new thread",
                        },
                        "confirm": {"type": "plain_text", "text": "Delete"},
                        "deny": {"type": "plain_text", "text": "Cancel"},
                    },
                },
            ],
        },
    ]


def get_user_info(user_id: str) -> Optional[UserInfo]:
    """Get user's profile info"""
    try:
        response: dict[str, Any] = slack_client.users_info(user=user_id)  # type: ignore
        user = response["user"]
        return {
            "name": user["real_name"] or user["name"],
            "avatar": user["profile"].get("image_72", ""),
            "display_name": user["profile"].get("display_name", user["name"]),
        }

    except SlackApiError as err:
        print(f"Error during user info collection: {err}")
        return None


def _get_author_name(user_id: str) -> str:
    """Get author name for event dispatch, falling back to 'Unknown'"""
    info = get_user_info(user_id)
    return info["name"] if info else "Unknown"


def post_message_to_channel(
    user_id: str,
    message_text: str,
    user_info: UserInfo,
    files: Optional[list[dict[str, Any]]] = None,
) -> Optional[bool]:
    """Post user's message to the given channel, either as new message or new reply"""
    if not message_text or message_text.strip() == "":
        return None

    file_yes = message_text == "[Shared a file]"
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

            if file_yes and files:
                download_reupload_files(files, CHANNEL, thread_ts)

            thread_manager.update_thread_activity(user_id)
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
        return create_new_thread(user_id, message_text, user_info)


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

        if files:
            download_reupload_files(files, CHANNEL, response["ts"])

        success = thread_manager.create_active_thread(
            user_id, CHANNEL, response["ts"], response["ts"]
        )
        if success:
            trust_level = get_user_trust_level(user_id)
            trust_emoji = TRUST_EMOJI.get(trust_level, TRUST_EMOJI[4])
            trust_label = TRUST_LABELS.get(trust_level, TRUST_LABELS[4])
            past_threads = get_past_threads_info(user_id)

            slack_client.chat_postMessage(  # type: ignore
                channel=CHANNEL,
                thread_ts=response["ts"],
                text=f"*User Info:*\n{trust_emoji} Trust Level: {trust_label}\n\n{past_threads}",
                username="Thread Info",
                icon_emoji=":information_source:",
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

        return success

    except SlackApiError as err:
        print(f"Error creating new thread: {err}")
        return False


def send_dm_to_user(
    user_id: str,
    reply_text: str,
    files: Optional[list[dict[str, Any]]] = None,
) -> Optional[str]:
    """Send a reply back to the user"""
    try:
        dm_response: dict[str, Any] = slack_client.conversations_open(users=[user_id])  # type: ignore
        dm_channel: str = dm_response["channel"]["id"]

        if files or reply_text == "[Shared file]":
            return None

        response: dict[str, Any] = slack_client.chat_postMessage(  # type: ignore
            channel=dm_channel,
            text=reply_text,
            username="Fraud Department",
            icon_emoji=":ban:",
        )

        return response["ts"] if response.get("ok") else None

    except SlackApiError as err:
        print(f"Error sending reply to user {user_id}: {err}")
        print(f"Error response: {err.response}")
        return None


def extract_user_id(text: str) -> Optional[str]:
    """Extracts user ID from a mention text <@U000000> or from a direct ID"""
    mention_format = re.search(r"<@([A-Z0-9]+)>", text)
    if mention_format:
        return mention_format.group(1)

    id_match = re.search(r"\b(U[A-Z0-9]{8,})\b", text)
    if id_match:
        return id_match.group(1)

    return None


@slack_app.command("/fdchat")  # type: ignore
def handle_fdchat_cmd(ack: Any, respond: Any, command: dict[str, Any]) -> None:
    """Handle conversations started by staff"""
    ack()
    # for the leekers
    if command.get("channel_id") != CHANNEL:
        respond(
            {
                "response_type": "ephemeral",
                "text": "This command can only be used in one place. If you don't know it, don't even try",
            }
        )
        return

    command_text = command.get("text", "").strip()

    if not command_text:
        respond(
            {
                "response_type": "ephemeral",
                "text": "Usage: /fdchat @user your message' or '/fdchat U000000 your message'",
            }
        )
        return

    requester_id: str = command.get("user_id", "")

    parts = command_text.split(" ", 1)
    user_id = parts[0]
    staff_message = expand_macros(parts[1])

    target_user_id = extract_user_id(user_id)
    if not target_user_id:
        respond(
            {
                "response_type": "ephemeral",
                "text": "Provide a valid user ID: U000000 or a mention: @name",
            }
        )
        return

    user_info = get_user_info(target_user_id)
    if not user_info:
        respond(
            {
                "response_type": "ephemeral",
                "text": f"Couldn't find user info for {target_user_id}",
            }
        )
        return

    if thread_manager.has_active_thread(target_user_id):
        thread_info = thread_manager.get_active_thread(target_user_id)

        if not thread_info:
            respond(
                {
                    "response_type": "ephemeral",
                    "text": f"Could not retrieve thread info for {target_user_id}",
                }
            )
            return

        try:
            thread_ts_value: Optional[str] = (
                thread_info.get("thread_ts") if thread_info else None
            )
            if not thread_ts_value:
                respond(
                    {
                        "response_type": "ephemeral",
                        "text": f"Could not retrieve thread ts for {target_user_id}",
                    }
                )
                return

            response: dict[str, Any] = slack_client.chat_postMessage(  # type: ignore
                channel=CHANNEL,
                thread_ts=thread_ts_value,
                text=f"*<@{requester_id}> continued:*\n{staff_message}",
            )
            dm_ts = send_dm_to_user(target_user_id, staff_message)
            thread_manager.update_thread_activity(target_user_id)

            if dm_ts:
                expanded_text = expand_macros(staff_message)
                if expanded_text != staff_message:
                    slack_client.chat_postMessage(  # type: ignore
                        channel=CHANNEL,
                        thread_ts=thread_ts_value,
                        text=f"📨 *Sent to user:*\n{expanded_text}",
                        username="Macro Echo",
                        icon_emoji=":outbox_tray:",
                    )
                thread_manager.store_message_mapping(
                    response["ts"],
                    target_user_id,
                    dm_ts,
                    staff_message,
                    thread_ts_value,
                )
                dispatch_event(
                    "message.staff.new",
                    {
                        "thread_ts": thread_ts_value,
                        "message": {
                            "id": response["ts"],
                            "content": staff_message,
                            "timestamp": datetime.fromtimestamp(float(response["ts"]))
                            .astimezone(timezone.utc)
                            .isoformat()
                            .replace("+00:00", "Z"),
                            "is_from_user": False,
                            "author": {"name": _get_author_name(requester_id)},
                        },
                    },
                )

            if dm_ts:
                respond(
                    {
                        "response_type": "ephemeral",
                        "text": f"Message sent in some older thread to {user_info['display_name']}",
                    }
                )
            else:
                respond(
                    {
                        "response_type": "ephemeral",
                        "text": f"It sucks, couldn't add a message to older thread for {user_info['display_name']}",
                    }
                )
            return
        except SlackApiError as err:  # pylint: disable=broad-except
            respond(
                {
                    "response_type": "ephemeral",
                    "text": "Something broke, awesome - couldn't add a message to an existing thread",
                }
            )
            print(f"Error adding message to existing thread: {err}")
            return
    try:  # Try, not trying. It was standing out a lot, I had to fix it a little
        dm_ts = send_dm_to_user(target_user_id, staff_message)
        if not dm_ts:
            respond(
                {
                    "response_type": "ephemeral",
                    "text": f"Failed to send DM to {target_user_id}",
                }
            )
            return
        original_sent_text = staff_message
        staff_message = (
            f"*<@{requester_id}> started a message to <@{target_user_id}>:*\n"
            + staff_message
        )

        response: dict[str, Any] = slack_client.chat_postMessage(  # type: ignore
            channel=CHANNEL,
            text=f"*<@{user_id}> started a message to <@{target_user_id}>:*\n {staff_message}",
            username=user_info["display_name"],
            icon_url=user_info["avatar"],
            blocks=get_standard_channel_msg(target_user_id, staff_message),
        )

        thread_manager.create_active_thread(
            target_user_id, CHANNEL, response["ts"], response["ts"]
        )

        trust_level = get_user_trust_level(target_user_id)
        trust_emoji = TRUST_EMOJI.get(trust_level, TRUST_EMOJI[4])
        trust_label = TRUST_LABELS.get(trust_level, TRUST_LABELS[4])
        past_threads = get_past_threads_info(target_user_id)

        slack_client.chat_postMessage(  # type: ignore
            channel=CHANNEL,
            thread_ts=response["ts"],
            text=f"*User Info:*\n{trust_emoji} Trust Level: {trust_label}\n\n{past_threads}",
            username="Thread Info",
            icon_emoji=":information_source:",
        )

        thread_manager.store_message_mapping(
            response["ts"], target_user_id, dm_ts, original_sent_text, response["ts"]
        )
        dispatch_event(
            "thread.created",
            {
                "thread_ts": response["ts"],
                "user_slack_id": target_user_id,
                "started_at": datetime.fromtimestamp(float(response["ts"]))
                .astimezone(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "initial_message": original_sent_text,
            },
        )
        dispatch_event(
            "message.staff.new",
            {
                "thread_ts": response["ts"],
                "message": {
                    "id": response["ts"],
                    "content": original_sent_text,
                    "timestamp": datetime.fromtimestamp(float(response["ts"]))
                    .astimezone(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "is_from_user": False,
                    "author": {"name": _get_author_name(requester_id)},
                },
            },
        )

        expanded_text = expand_macros(staff_message)
        if expanded_text != staff_message:
            slack_client.chat_postMessage(  # type: ignore
                channel=CHANNEL,
                thread_ts=response["ts"],
                text=f"📨 *Sent to user:*\n{expanded_text}",
                username="Macro Echo",
                icon_emoji=":outbox_tray:",
            )

        respond(
            {
                "response_type": "ephemeral",
                "text": f"Started conversation with {user_info['display_name']}, good luck",
            }
        )

        print(
            f"Successfully started conversation with {target_user_id} via slash command"
        )

    except SlackApiError as err:
        respond(
            {
                "response_type": "ephemeral",
                "text": f"Error starting conversation: {err}",
            }
        )


def handle_dms(
    user_id: str,
    message_text: str,
    files: list[dict[str, Any]],
    say: Any,
) -> None:
    """Receive and react to messages sent to the bot"""
    user_info = get_user_info(user_id)
    if not user_info:
        say("Hiya! Couldn't process your message, try again another time")
        return
    success = post_message_to_channel(user_id, message_text, user_info, files)
    if not success:
        say(
            "There was some error during processing of your message, try again another time"
        )


@slack_app.message("")  # type: ignore
def handle_all_messages(
    message: dict[str, Any],
    say: Any,
    client: WebClient,
    logger: logging.Logger,  # pylint: disable=unused-argument
) -> None:
    """Handle all messages related to the bot"""
    user_id: str = message["user"]
    message_text: str = message["text"]
    channel_type: str = message.get("channel_type", "")
    files: list[dict[str, Any]] = message.get("files", [])
    channel_id: Optional[str] = message.get("channel")

    print(f"Message received - Channel: {channel_id}, Type: {channel_type}")

    if message.get("bot_id"):
        return

    if channel_type == "im":
        handle_dms(user_id, message_text, files, say)
    elif channel_id == CHANNEL:
        if message_text and message_text.strip() == "!backup":
            handle_backup_command(message, client)
        elif message_text and message_text.strip() == "!bulkresolve":
            handle_bulkresolve_command(message, client)
        elif "thread_ts" in message:
            handle_channel_reply(message, client)


def handle_channel_reply(message: dict[str, Any], client: WebClient) -> None:
    """Handle replies in channel to send them to users"""
    thread_ts: str = message["thread_ts"]
    reply_text: str = message["text"]
    files: list[dict[str, Any]] = message.get("files", [])
    fraud_dept_ts: str = message["ts"]

    if reply_text and reply_text.strip() == "!backup":
        handle_backup_command(message, client)
        return

    if reply_text and reply_text.strip() == "!bulkresolve":
        handle_bulkresolve_command(message, client)
        return

    is_macro = reply_text and any(
        reply_text.startswith(macro) for macro in MACROS.keys()
    )

    if not reply_text or (
        not is_macro and len(reply_text) > 0 and reply_text[0] != "!"
    ):
        return

    if reply_text and reply_text[0] == "!" and not is_macro:
        reply_text = reply_text[1:]

    original_text = reply_text
    reply_text = expand_macros(reply_text)

    # if reply_text and files:
    #    return

    # Find user's active thread by TS (look in cache -> look at TS)
    target_user_id: Optional[str] = None
    for user_id in thread_manager.active_cache:
        thread_info = thread_manager.get_active_thread(user_id)

        # Check the TS
        if thread_info and thread_info["thread_ts"] == thread_ts:
            target_user_id = user_id
            break

    if target_user_id:
        dm_ts = send_dm_to_user(target_user_id, reply_text, files)

        # Some logging
        if dm_ts and thread_ts:
            thread_manager.store_message_mapping(
                fraud_dept_ts, target_user_id, dm_ts, reply_text, thread_ts
            )
            dispatch_event(
                "message.staff.new",
                {
                    "thread_ts": thread_ts,
                    "message": {
                        "id": fraud_dept_ts,
                        "content": reply_text,
                        "timestamp": datetime.fromtimestamp(float(fraud_dept_ts))
                        .astimezone(timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z"),
                        "is_from_user": False,
                        "author": {"name": _get_author_name(message["user"])},
                    },
                },
            )
            thread_manager.update_thread_activity(target_user_id)

            # Only echo if macros were used
            if original_text != reply_text:
                client.chat_postMessage(  # type: ignore
                    channel=CHANNEL,
                    thread_ts=thread_ts,
                    text=f"📨 *Sent to user:*\n{reply_text}",
                    username="Macro Echo",
                    icon_emoji=":outbox_tray:",
                )

            try:
                client.reactions_add(  # type: ignore
                    channel=CHANNEL, timestamp=message["ts"], name="done"
                )
            except SlackApiError as err:
                print(f"Failed to add done reaction: {err}")
        else:
            print(f"Failed to send reply to user {target_user_id}")
            try:
                client.reactions_add(channel=CHANNEL, timestamp=message["ts"], name="x")  # type: ignore
            except SlackApiError as err:
                print(f"Failed to add X reaction: {err}")
    else:
        print(f"Could not find user for thread {thread_ts}")


def handle_bulkresolve_command(message: dict[str, Any], client: WebClient) -> None:
    """Handle !bulkresolve command to auto-resolve threads inactive for 2+ days"""
    try:
        thread_ts: Optional[str] = message.get("thread_ts")
        user_id: Optional[str] = message.get("user")

        # for the goobers who try to run this elsewhere
        if thread_ts:
            client.chat_postMessage(  # type: ignore
                channel=CHANNEL,
                thread_ts=thread_ts,
                text="⚠️ The `!bulkresolve` command can only be used in the main channel, not in threads.",
                username="Bulk Resolve Bot",
            )
            return

        inactive_threads = thread_manager.get_inactive_threads(48)

        if not inactive_threads:
            client.chat_postMessage(  # type: ignore
                channel=CHANNEL,
                text="✅ No threads have been inactive for 2+ days. All threads are active!",
                username="Bulk Resolve Bot",
            )
            return

        initial_message = f"🔄 **Bulk Resolve Started**\n\nFound {len(inactive_threads)} thread(s) inactive for 2+ days.\nResolving threads and notifying users..."

        initial_response: dict[str, Any] = client.chat_postMessage(  # type: ignore
            channel=CHANNEL, text=initial_message, username="Bulk Resolve Bot"
        )

        initial_msg_ts: str = initial_response["ts"]

        def run_bulkresolve() -> None:
            resolved_count = 0
            failed_count = 0

            for thread_data in inactive_threads:
                target_user_id: str = thread_data["user_id"]
                thread_info = thread_data["thread_info"]
                hours_inactive: float = thread_data["hours_inactive"]

                try:
                    dm_response: dict[str, Any] = client.conversations_open(  # type: ignore
                        users=[target_user_id]
                    )
                    dm_channel: str = dm_response["channel"]["id"]

                    client.chat_postMessage(  # type: ignore
                        channel=dm_channel,
                        text="Heyo, it looks like this thread has gone quiet!",
                        blocks=[
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "Heyo, it looks like this thread has gone quiet!",
                                },
                            },
                            {
                                "type": "context",
                                "elements": [
                                    {
                                        "type": "mrkdwn",
                                        "text": "_This action has been performed automatically by a friendly bot_",
                                    }
                                ],
                            },
                        ],
                        username="Fraud Department",
                        icon_emoji=":ban:",
                    )

                    success = thread_manager.complete_thread(target_user_id)

                    if success:
                        resolved_count += 1
                        dispatch_event(
                            "thread.status.changed",
                            {
                                "thread_ts": thread_info.get("thread_ts"),
                                "user_slack_id": target_user_id,
                                "new_status": "completed",
                                "timestamp": datetime.now(timezone.utc)
                                .isoformat()
                                .replace("+00:00", "Z"),
                                "reason": "bulk_auto_resolve",
                            },
                        )
                        print(
                            f"Auto-resolved thread for user {target_user_id} (inactive for {hours_inactive:.1f} hours)"
                        )
                    else:
                        failed_count += 1

                except Exception as e:  # pylint: disable=broad-except
                    print(f"Error resolving thread for {target_user_id}: {e}")
                    failed_count += 1

            report = "✅ **Bulk Resolve Complete**\n\n"
            report += f"• Resolved: {resolved_count}\n"
            report += f"• Failed: {failed_count}\n"
            report += f"• Total: {len(inactive_threads)}"

            client.chat_postMessage(  # type: ignore
                channel=CHANNEL, text=report, username="Bulk Resolve Bot"
            )

            try:
                client.reactions_add(  # type: ignore
                    channel=CHANNEL, timestamp=initial_msg_ts, name="white_check_mark"
                )
            except SlackApiError as err:
                print(f"Failed to add reaction to initial message: {err}")

        # Run in background thread
        bulkresolve_thread = threading.Thread(target=run_bulkresolve, daemon=True)
        bulkresolve_thread.start()

        print(
            f"Bulk resolve command initiated by user {user_id} for {len(inactive_threads)} threads"
        )

    except Exception as err:  # pylint: disable=broad-except
        print(f"Error in bulkresolve command handler: {err}")
        try:
            client.chat_postMessage(  # type: ignore
                channel=CHANNEL,
                text=f"❌ **Bulk Resolve Error**\n\nFailed to execute: {str(err)[:200]}",
                username="Bulk Resolve Bot",
            )
        except Exception:  # pylint: disable=broad-except
            pass


def handle_backup_command(message: dict[str, Any], client: WebClient) -> None:
    """Handle !backup command to start fraud case extraction"""
    try:
        thread_ts: Optional[str] = message.get("thread_ts")
        user_id: Optional[str] = message.get("user")

        initial_message = (
            "🔄 **Backup Started**\n\nCreating backup of all thread data..."
        )

        if thread_ts:
            client.chat_postMessage(  # type: ignore
                channel=CHANNEL,
                thread_ts=thread_ts,
                text=initial_message,
                username="Backup Bot",
            )
        else:
            client.chat_postMessage(  # type: ignore
                channel=CHANNEL, text=initial_message, username="Backup Bot"
            )

        def run_backup() -> None:
            try:
                backup_data = create_backup_export()
                if not backup_data:
                    error_msg = "❌ **Backup Failed**\n\nCould not create export data"
                    if thread_ts:
                        client.chat_postMessage(  # type: ignore
                            channel=CHANNEL,
                            thread_ts=thread_ts,
                            text=error_msg,
                            username="Backup Bot",
                        )
                    else:
                        client.chat_postMessage(  # type: ignore
                            channel=CHANNEL, text=error_msg, username="Backup Bot"
                        )
                    return

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"fraudpheus_messages_{timestamp}.json"
                json_content = json.dumps(backup_data, indent=2, ensure_ascii=False)

                stats = backup_data["statistics"]
                success_msg = (
                    (
                        f"✅ **Message Export Complete!**\n\n**Statistics:**\n"
                        f"• {stats['total_cases']} fraud cases\n"
                        f"• {stats['total_messages']} total messages\n"
                        f"• {stats['total_users']} users"
                    )
                    if stats
                    else "✅ **Message Export Complete!**"
                )

                if thread_ts:
                    client.chat_postMessage(  # type: ignore
                        channel=CHANNEL,
                        thread_ts=thread_ts,
                        text=success_msg,
                        username="Backup Bot",
                    )
                else:
                    client.chat_postMessage(  # type: ignore
                        channel=CHANNEL, text=success_msg, username="Backup Bot"
                    )

                client.files_upload_v2(  # type: ignore
                    channel=CHANNEL,
                    content=json_content.encode("utf-8"),
                    filename=filename,
                    title=f"Fraudpheus Message Export - {timestamp}",
                    initial_comment="**Backup file attached below** 📎",
                    thread_ts=thread_ts,
                )

            except Exception as e:  # pylint: disable=broad-except
                error_msg = (
                    f"❌ **Backup Error**\n\nFailed to run backup: {str(e)[:500]}"
                )
                if thread_ts:
                    client.chat_postMessage(  # type: ignore
                        channel=CHANNEL,
                        thread_ts=thread_ts,
                        text=error_msg,
                        username="Backup Bot",
                    )
                else:
                    client.chat_postMessage(  # type: ignore
                        channel=CHANNEL, text=error_msg, username="Backup Bot"
                    )

        backup_thread = threading.Thread(target=run_backup, daemon=True)
        backup_thread.start()

        print(f"Backup command initiated by user {user_id}")

    except Exception as err:  # pylint: disable=broad-except
        print(f"Error in backup command handler: {err}")


@slack_app.action("mark_completed")  # type: ignore
def handle_mark_completed(ack: Any, body: dict[str, Any], client: WebClient) -> None:
    """Complete the thread"""
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
    """Handle deleting thread"""
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


@slack_app.event("file_shared")  # type: ignore
def handle_file_shared(
    event: dict[str, Any], client: WebClient, logger: logging.Logger
) -> None:
    """Handle files being shared"""
    try:
        file_id: str = event["file_id"]
        user_id: str = event["user_id"]
        file_info: dict[str, Any] = client.files_info(file=file_id)  # type: ignore
        file_data: dict[str, Any] = file_info["file"]

        groups: list[str] = file_data.get("groups", [])
        ims: list[str] = file_data.get("ims", [])

        if (
            ims
            and not file_data.get("initial_comment")
            and file_data.get("comments_count") == 0
        ):
            user_info = get_user_info(user_id)
            message_text = "[Shared a file]"
            if user_info:
                success = post_message_to_channel(
                    user_id, message_text, user_info, [file_data]
                )

                if not success:
                    try:
                        dm_response: dict[str, Any] = client.conversations_open(  # type: ignore
                            users=user_id
                        )
                        dm_channel: str = dm_response["channel"]["id"]
                        client.chat_postMessage(  # type: ignore
                            channel=dm_channel,
                            type="ephemeral",
                            username="Fraud Department",
                            icon_emoji=":ban:",
                            text="*No luck for you, there was an issue processing your file*",
                        )

                    except SlackApiError as err:
                        print(f"Failed to send error msg: {err}")

        elif (
            groups
            and not file_data.get("initial_comment")
            and file_data.get("comments_count") == 0
        ):
            shares: dict[str, Any] = file_data.get("shares", {})
            thread_ts: str = shares["private"][CHANNEL][0]["thread_ts"]

            for user, thread_info in thread_manager.active_cache.items():
                if thread_info["thread_ts"] == thread_ts:
                    send_dm_to_user(user, "[Shared file]", [file_data])

    except SlackApiError as err:
        logger.error(f"Error handling file_shared event: {err}")


def format_file(files: list[dict[str, Any]]) -> str:
    """Format file for a nice view in message"""
    if not files:
        return ""

    file_info: list[str] = []
    for file in files:
        file_type: str = file.get("mimetype", "unknown")
        file_name: str = file.get("name", "unknown file")
        file_size: int = file.get("size", 0)

        if file_size > 1024 * 1024:
            size_str = f"{file_size / (1024 * 1024):.1f}MB"
        elif file_size > 1024:
            size_str = f"{file_size / 1024:.1f}KB"
        else:
            size_str = f"{file_size}B"

        file_info.append(f"File *{file_name} ({file_type}, {size_str})")

    return "\n" + "\n".join(file_info)


def download_reupload_files(
    files: list[dict[str, Any]],
    channel: str,
    thread_ts: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Download files, then reupload them to the target channel"""
    reuploaded: list[dict[str, Any]] = []
    for file in files:
        try:
            file_url: Optional[str] = file.get("url_private_download") or file.get(
                "url_private"
            )
            if not file_url:
                print(
                    f"Can't really download without any url for file {file.get('name', 'unknown')}"
                )
                continue

            headers = {"Authorization": f"Bearer {os.getenv('SLACK_BOT_TOKEN')}"}
            response = httpx.get(file_url, headers=headers, timeout=10)

            if response.status_code == 200:
                upload_params: dict[str, Any] = {
                    "channel": channel,
                    "file": response.content,
                    "filename": file.get("name", "file"),
                    "title": file.get(
                        "title", file.get("name", "Some file without name?")
                    ),
                }

                if thread_ts:
                    upload_params["thread_ts"] = thread_ts

                upload_response: dict[str, Any] = slack_client.files_upload_v2(  # type: ignore
                    **upload_params
                )

                if upload_response.get("ok"):
                    reuploaded.append(upload_response["file"])
                else:
                    print(f"Failed to reupload file: {upload_response.get('error')}")

        except Exception as err:  # pylint: disable=broad-except
            print(f"Error processing file: {file.get('name', 'unknown')}: {err}")

    return reuploaded


@slack_app.event("message")  # type: ignore
def handle_message_events(body: dict[str, Any], logger: logging.Logger) -> None:
    """Handle message events including deletions"""
    event: dict[str, Any] = body.get("event", {})

    if event.get("subtype") == "message_deleted":
        handle_message_deletion(event, logger)
    elif event.get("subtype") == "message_changed":
        handle_message_changed(event, logger)


def handle_message_deletion(event: dict[str, Any], logger: logging.Logger) -> None:
    """Handle message deletion events"""
    try:
        deleted_ts: Optional[str] = event.get("deleted_ts")
        channel: Optional[str] = event.get("channel")

        if not deleted_ts or not channel:
            return

        if channel == CHANNEL:
            handle_fraud_dept_deletion(deleted_ts, logger)
        else:
            handle_user_dm_deletion(deleted_ts, channel, logger)

    except Exception as err:  # pylint: disable=broad-except
        logger.error(f"Error handling message deletion: {err}")


def handle_fraud_dept_deletion(deleted_ts: str, logger: logging.Logger) -> None:
    """Handle deletion of messages by fraud dept members"""
    try:
        mapping = thread_manager.get_message_mapping(deleted_ts)
        if not mapping:
            return

        user_id: str = mapping["user_id"]
        dm_ts: str = mapping["dm_ts"]

        try:
            dm_response: dict[str, Any] = slack_client.conversations_open(  # type: ignore
                users=[user_id]
            )
            dm_channel: str = dm_response["channel"]["id"]

            try:
                slack_user_client.chat_delete(  # type: ignore
                    channel=dm_channel, ts=dm_ts, as_user=True
                )
                print(f"Deleted DM message for user {user_id}")
            except SlackApiError:
                try:
                    slack_client.chat_delete(channel=dm_channel, ts=dm_ts)  # type: ignore
                    print(f"Deleted DM message for user {user_id} (as bot)")
                except SlackApiError as delete_err:
                    print(
                        f"Failed to delete DM message for user {user_id}: {delete_err}"
                    )

            mapping = thread_manager.get_message_mapping(deleted_ts)
            thread_ts: Optional[str] = mapping.get("thread_ts") if mapping else None
            thread_manager.remove_message_mapping(deleted_ts)
            if thread_ts:
                dispatch_event(
                    "message.deleted",
                    {"thread_ts": thread_ts, "message_id": deleted_ts},
                )

        except SlackApiError as err:
            print(f"Error accessing DM channel for user {user_id}: {err}")

    except Exception as err:  # pylint: disable=broad-except
        logger.error(f"Error in fraud dept deletion handler: {err}")


def handle_user_dm_deletion(  # pylint: disable=unused-argument
    deleted_ts: str, dm_channel: str, logger: logging.Logger
) -> None:
    """Handle deletion of messages by users"""


def handle_message_changed(event: dict[str, Any], logger: logging.Logger) -> None:
    """Handle message edit events"""
    try:
        message: dict[str, Any] = event.get("message", {})
        edited = message.get("edited")
        if not message or not edited:
            return
        ts: Optional[str] = message.get("ts")
        channel: Optional[str] = event.get("channel")
        if channel != CHANNEL:
            return
        mapping = thread_manager.get_message_mapping(ts) if ts else None
        if not mapping:
            return
        thread_ts: Optional[str] = mapping.get("thread_ts")
        content: str = message.get("text", "")
        dispatch_event(
            "message.updated",
            {
                "thread_ts": thread_ts,
                "message": {
                    "id": ts,
                    "content": content,
                    "timestamp": datetime.now(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "is_from_user": False,
                    "author": {"name": "Unknown"},
                },
            },
        )
    except Exception as err:  # pylint: disable=broad-except
        logger.error(f"Error handling message_changed: {err}")


@slack_app.error  # type: ignore
def error_handler(error: Any, body: Any, logger: logging.Logger) -> None:
    """Global error handler for Slack events"""
    logger.exception(f"Error: {error}")
    logger.info(f"Request body: {body}")


if __name__ == "__main__":
    # auto_close_thread = threading.Thread(target=check_inactive_threads, daemon=True)
    # auto_close_thread.start()

    handler = SocketModeHandler(slack_app, os.getenv("SLACK_APP_TOKEN"))
    print("Bot running!")
    print("Auto-close inactive threads system started")
    handler.start()
