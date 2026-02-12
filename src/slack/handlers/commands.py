"""Slash commands and admin commands"""

import json
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from src.config import (
    CHANNEL,
    IS_DEVELOPMENT,
    TRUST_EMOJI,
    TRUST_LABELS,
    slack_app,
    slack_client,
)
from src.slack.helpers import (
    get_standard_channel_msg,
    get_user_info,
    send_dm_to_user,
    thread_manager,
)
from src.slack.macros import expand_macros
from src.services.backup import create_backup_export
from src.services.threads import extract_user_id, get_author_name, get_past_threads_info
from src.services.trust import get_user_trust_level
from src.services.webhook_dispatcher import dispatch_event

FDCHAT_COMMAND = f"/fdchat{'_dev' if IS_DEVELOPMENT else ''}"


@slack_app.command(FDCHAT_COMMAND)  # type: ignore
def handle_fdchat_cmd(ack: Any, respond: Any, command: dict[str, Any]) -> None:
    """Handle conversations started by staff."""
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
                            "author": {"name": get_author_name(requester_id)},
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
                    "author": {"name": get_author_name(requester_id)},
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


def handle_bulkresolve_command(message: dict[str, Any], client: WebClient) -> None:
    """Handle !bulkresolve command to auto-resolve threads inactive for 2+ days."""
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
                    channel=CHANNEL,
                    timestamp=initial_msg_ts,
                    name="white_check_mark",
                )
            except SlackApiError as err:
                print(f"Failed to add reaction to initial message: {err}")

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
    """Handle !backup command to start fraud case extraction."""
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
