"""REST API endpoints for Fraudpheus"""

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from slack_sdk.errors import SlackApiError

from src.config import CHANNEL, FRAUDPHEUS_API_KEY, slack_client
from src.services.thread_manager import AirtableMessage, TimedAirtableMessage
from src.services.user_cache import cached_user_info, get_user_name
from src.slack.helpers import (
    UserInfo,
    get_standard_channel_msg,
    send_dm_to_user,
    thread_manager,
)
from src.slack.macros import expand_macros
from src.webhooks import dispatch_event

if not FRAUDPHEUS_API_KEY:
    print("Warning: FRAUDPHEUS_API_KEY not set; API will reject all requests")

app = FastAPI()


def require_api_key(request: Request) -> None:
    """Validate Bearer token from Authorization header"""
    auth: Optional[str] = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        )
    token: str = auth.split(" ", 1)[1].strip()
    if token != FRAUDPHEUS_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        )


ThreadTuple = tuple[TimedAirtableMessage | AirtableMessage, str]


@app.get("/api/v1/threads")
async def list_threads(
    user_slack_id: Optional[str] = None,
    _: None = Depends(require_api_key),
) -> list[dict[str, Any]]:
    """List all threads for a user"""
    if not user_slack_id:
        raise HTTPException(400, "user_slack_id required")

    summaries: list[dict[str, Any]] = []
    all_threads: list[ThreadTuple] = []

    if thread_manager.has_active_thread(user_slack_id):
        active = thread_manager.get_active_thread(user_slack_id)
        if active is not None:
            all_threads.append((active, "active"))
    for completed in thread_manager.get_completed_threads(user_slack_id):
        all_threads.append((completed, "completed"))

    for t_item, thread_status in all_threads:
        thread_ts: Optional[str] = t_item["thread_ts"]
        if not thread_ts:
            continue
        started_at_iso: Optional[str] = None
        snippet: str = ""
        try:
            resp: dict[str, Any] = slack_client.conversations_replies(  # type: ignore
                channel=CHANNEL, ts=thread_ts, limit=1, inclusive=True
            )
            for m in resp.get("messages", []):
                if m.get("ts") == thread_ts:
                    ts_float: float = float(m["ts"]) if m.get("ts") else 0.0
                    started_at_iso = (
                        datetime.fromtimestamp(ts_float, tz=timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z")
                    )
                    snippet = m.get("text", "")
                    break
        except SlackApiError:
            pass
        summaries.append(
            {
                "thread_ts": thread_ts,
                "started_at": started_at_iso,
                "initial_message_snippet": snippet,
                "status": thread_status,
            }
        )
    summaries.sort(key=lambda x: float(x["thread_ts"]), reverse=True)
    return summaries


@app.post("/api/v1/threads", status_code=201)
async def start_thread(
    body: dict[str, Any],
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    """Start a new thread with a user"""
    user_slack_id: Optional[str] = body.get("user_slack_id")
    initial_message: Optional[str] = body.get("initial_message")
    author_slack_id: Optional[str] = body.get("author_slack_id")
    if not user_slack_id or not initial_message or not author_slack_id:
        raise HTTPException(400, "Missing required fields")

    user_info: Optional[UserInfo] = cached_user_info(user_slack_id)
    if not user_info:
        raise HTTPException(404, "User not found")

    dm_ts: Optional[str] = send_dm_to_user(
        user_slack_id, expand_macros(initial_message)
    )
    if not dm_ts:
        raise HTTPException(500, "Failed to send DM")

    try:
        channel_text: str = (
            f"*<@{author_slack_id}> started a message"
            f" to <@{user_slack_id}>:*\n{initial_message}"
        )
        response: dict[str, Any] = slack_client.chat_postMessage(  # type: ignore
            channel=CHANNEL,
            text=channel_text,
            blocks=get_standard_channel_msg(user_slack_id, channel_text),
            username=user_info["display_name"],
            icon_url=user_info["avatar"],
        )
        thread_manager.create_active_thread(
            user_slack_id, CHANNEL, response["ts"], response["ts"]
        )
        asyncio.create_task(
            dispatch_event(
                "thread.created",
                {
                    "thread_ts": response["ts"],
                    "user_slack_id": user_slack_id,
                    "started_at": datetime.fromtimestamp(
                        float(response["ts"]), tz=timezone.utc
                    )
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "initial_message": initial_message,
                },
            )
        )
        return {"thread_ts": response["ts"]}
    except SlackApiError as err:
        raise HTTPException(
            500,
            f"Slack error: {err.response['error'] if err.response else str(err)}",  # type: ignore
        ) from err


@app.get("/api/v1/threads/{thread_ts}")
async def get_thread_history(
    thread_ts: str,
    _: None = Depends(require_api_key),
) -> list[dict[str, Any]]:
    """Get message history for a thread"""
    try:
        replies: dict[str, Any] = slack_client.conversations_replies(  # type: ignore
            channel=CHANNEL, ts=thread_ts
        )
        messages: list[dict[str, Any]] = replies.get("messages", [])
        filtered: list[dict[str, Any]] = []
        target_user_id: Optional[str] = thread_manager.get_user_by_thread_ts(thread_ts)

        for m in messages:
            if m.get("ts") == thread_ts:
                continue
            text: str = m.get("text", "")
            user: Optional[str] = m.get("user")
            is_bot: bool = m.get("bot_id") is not None
            is_from_user: bool = user == target_user_id and not is_bot

            if is_from_user or (
                text
                and (
                    text.startswith("!")
                    or any(
                        text.startswith(k)
                        for k in [
                            "$final",
                            "$ban",
                            "$deduct",
                            "$noevidence",
                            "$dm",
                            "$alt",
                        ]
                    )
                )
            ):
                ts_float: float = float(m["ts"]) if m.get("ts") else 0.0
                if text.startswith("!"):
                    text = text[1:]
                filtered.append(
                    {
                        "id": m.get("ts"),
                        "content": text,
                        "timestamp": datetime.fromtimestamp(ts_float, tz=timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z"),
                        "is_from_user": is_from_user,
                        "author": {"name": get_user_name(user)},
                    }
                )
        filtered.sort(key=lambda x: str(x["id"]))
        return filtered
    except SlackApiError as err:
        if err.response and err.response.get("error") == "thread_not_found":  # type: ignore
            raise HTTPException(404, "Thread not found") from err
        raise HTTPException(
            500,
            f"Slack error: {err.response['error'] if err.response else str(err)}",  # type: ignore
        ) from err


@app.post("/api/v1/threads/{thread_ts}/messages", status_code=201)
async def send_message(
    thread_ts: str,
    body: dict[str, Any],
    _: None = Depends(require_api_key),
) -> dict[str, Any]:
    """Send a message in a thread"""
    content: Optional[str] = body.get("content")
    author_slack_id: Optional[str] = body.get("author_slack_id")
    if not content or not author_slack_id:
        raise HTTPException(400, "Missing required fields")

    target_user_id: Optional[str] = thread_manager.get_user_by_thread_ts(thread_ts)
    if not target_user_id:
        raise HTTPException(404, "Thread not found")

    expanded: str = expand_macros(content)
    dm_ts: Optional[str] = send_dm_to_user(target_user_id, expanded)
    if not dm_ts:
        raise HTTPException(500, "Failed to send DM")

    try:
        post: dict[str, Any] = slack_client.chat_postMessage(  # type: ignore
            channel=CHANNEL,
            thread_ts=thread_ts,
            text=f"*<@{author_slack_id}>:*\n{content}",
            blocks=[
                {
                    "type": "markdown",
                    "text": f"*<@{author_slack_id}>:*\n{content}",
                }
            ],
        )
        thread_manager.update_thread_activity(target_user_id)
        ts_float: float = float(post["ts"]) if post.get("ts") else 0.0
        thread_manager.store_message_mapping(
            post["ts"], target_user_id, dm_ts, expanded, thread_ts
        )
        author_name: str = get_user_name(author_slack_id)
        asyncio.create_task(
            dispatch_event(
                "message.staff.new",
                {
                    "thread_ts": thread_ts,
                    "message": {
                        "id": post["ts"],
                        "content": content,
                        "timestamp": datetime.fromtimestamp(ts_float, tz=timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z"),
                        "is_from_user": False,
                        "author": {"name": author_name},
                    },
                },
            )
        )
        return {
            "id": post["ts"],
            "content": content,
            "timestamp": datetime.fromtimestamp(ts_float, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "is_from_user": False,
            "author": {"name": author_name},
        }
    except SlackApiError as err:
        raise HTTPException(
            500,
            f"Slack error: {err.response['error'] if err.response else str(err)}",  # type: ignore
        ) from err


@app.post("/api/v1/threads/{thread_ts}/internal_note", status_code=201)
async def post_internal_note(
    thread_ts: str,
    body: dict[str, Any],
    _: None = Depends(require_api_key),
) -> dict[str, bool]:
    """Post an internal note in a thread"""
    content: Optional[str] = body.get("content")
    author_name: Optional[str] = body.get("author_name")
    attachments: list[dict[str, Any]] = body.get("attachments") or []
    if not content and not attachments:
        raise HTTPException(400, "Missing required fields")
    if not author_name:
        raise HTTPException(400, "Missing required fields")

    display_text: str = content or "(attachments)"

    main_text: str = f"**[Internal Note from {author_name}]:**"
    if content:
        main_text += f" {content}"

    blocks: list[dict[str, str]] = [{"type": "markdown", "text": main_text}]

    for att in attachments:
        if att.get("image_url"):
            blocks.append(
                {
                    "type": "image",
                    "image_url": att["image_url"],
                    "alt_text": att.get("alt_text", "attachment"),
                }
            )

    print(blocks)
    try:
        slack_client.chat_postMessage(  # type: ignore
            channel=CHANNEL,
            thread_ts=thread_ts,
            text=(f"[Internal Note from {author_name}]: {display_text}"),
            blocks=blocks,
        )
        return {"success": True}
    except SlackApiError as err:
        raise HTTPException(
            500,
            f"Slack error: {err.response['error'] if err.response else str(err)}",  # type: ignore
        ) from err
