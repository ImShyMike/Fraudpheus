"""Slack event handlers"""

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from src.config import CHANNEL, slack_app, slack_client, slack_user_client
from src.services.threads import get_author_name, post_message_to_channel
from src.services.webhook_dispatcher import dispatch_event
from src.slack.handlers.commands import (
    handle_backup_command,
    handle_bulkresolve_command,
)
from src.slack.helpers import get_user_info, send_dm_to_user, thread_manager
from src.slack.macros import MACROS, expand_macros


def handle_dms(
    user_id: str,
    message_text: str,
    files: list[dict[str, Any]],
    say: Any,
    client: WebClient,
    channel_id: str,
    message_ts: str,
) -> None:
    """Receive and react to messages sent to the bot"""
    user_info = get_user_info(user_id)
    if not user_info:
        say("Hiya! Couldn't process your message, try again another time")
        return
    success = post_message_to_channel(user_id, message_text, user_info, files)
    if not success:
        client.chat_postEphemeral(  # type: ignore
            channel=channel_id,
            user=user_id,
            text="An error occurred while processing your message. Please try again later.",
        )
    else:
        client.reactions_add(  # type: ignore
            channel=channel_id, timestamp=message_ts, name="white_check_mark"
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
    message_ts: str = message["ts"]
    files: list[dict[str, Any]] = message.get("files", [])
    channel_id: Optional[str] = message.get("channel")

    print(f"Message received - Channel: {channel_id}, Type: {channel_type}")

    if message.get("bot_id"):
        return

    if channel_type == "im":
        if channel_id:
            handle_dms(
                user_id, message_text, files, say, client, channel_id, message_ts
            )
        else:
            print(f"Warning: Received IM message without channel_id for user {user_id}")
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

    target_user_id: Optional[str] = None
    for user_id in thread_manager.active_cache:
        thread_info = thread_manager.get_active_thread(user_id)

        if thread_info and thread_info["thread_ts"] == thread_ts:
            target_user_id = user_id
            break

    if target_user_id:
        dm_ts = send_dm_to_user(target_user_id, reply_text, files)

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
                        "author": {"name": get_author_name(message["user"])},
                    },
                },
            )
            thread_manager.update_thread_activity(target_user_id)

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


@slack_app.event("file_shared")  # type: ignore
def handle_file_shared(
    event: dict[str, Any], client: WebClient, logger: logging.Logger
) -> None:
    """Handle files being shared"""
    try:
        file_id: str = event["file_id"]
        user_id: str = event["user_id"]
        print(f"File shared event - File ID: {file_id}, User ID: {user_id}")
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
                            username="Fraud Squad",
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
