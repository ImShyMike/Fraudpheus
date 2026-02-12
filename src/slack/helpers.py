"""Shared helpers"""

import os
from typing import Any, Optional, TypedDict

import httpx
from slack_sdk.errors import SlackApiError

from src.config import airtable_base, slack_client
from src.services.thread_manager import ThreadManager


class UserInfo(TypedDict):
    """Structure for user info"""

    name: str
    avatar: str
    display_name: str


thread_manager = ThreadManager(airtable_base, slack_client)


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


def get_standard_channel_msg(user_id: str, message_text: str) -> list[dict[str, Any]]:
    """Get blocks for a standard message uploaded into channel with 2 buttons"""
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"<@{user_id}> (User ID: `{user_id}`)",
            },
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": message_text},
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": ("Reply in this thread to send a response to the user"),
                }
            ],
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Mark as Completed",
                    },
                    "style": "primary",
                    "action_id": "mark_completed",
                    "value": user_id,
                    "confirm": {
                        "title": {
                            "type": "plain_text",
                            "text": "Are you sure?",
                        },
                        "text": {
                            "type": "mrkdwn",
                            "text": ("This will mark the thread as complete."),
                        },
                        "confirm": {
                            "type": "plain_text",
                            "text": "Mark as Completed",
                        },
                        "deny": {
                            "type": "plain_text",
                            "text": "Cancel",
                        },
                    },
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Delete thread",
                    },
                    "style": "danger",
                    "action_id": "delete_thread",
                    "value": user_id,
                    "confirm": {
                        "title": {
                            "type": "plain_text",
                            "text": "Are you sure?",
                        },
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                "This will delete the entire"
                                " thread and new replies will"
                                " go into a new thread"
                            ),
                        },
                        "confirm": {
                            "type": "plain_text",
                            "text": "Delete",
                        },
                        "deny": {
                            "type": "plain_text",
                            "text": "Cancel",
                        },
                    },
                },
            ],
        },
    ]


def send_dm_to_user(
    user_id: str,
    reply_text: str,
    files: Optional[list[dict[str, Any]]] = None,
) -> Optional[str]:
    """Send a reply back to the user"""
    try:
        dm_response: dict[str, Any] = slack_client.conversations_open(  # type: ignore
            users=[user_id]
        )
        dm_channel: str = dm_response["channel"]["id"]

        if reply_text == "[Shared file]":
            return None

        response: dict[str, Any] = slack_client.chat_postMessage(  # type: ignore
            channel=dm_channel,
            text=reply_text,
            username="Fraud Department",
            icon_emoji=":ban:",
        )

        if files:
            download_reupload_files(files, dm_channel)

        return response["ts"] if response.get("ok") else None

    except SlackApiError as err:
        print(f"Error sending reply to user {user_id}: {err}")
        print(f"Error response: {err.response}")
        return None


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
