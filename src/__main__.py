"""Main entry point"""

import signal
import sys
from typing import Any

import uvicorn
from fastapi.responses import JSONResponse, Response
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_bolt.adapter.starlette import SlackRequestHandler
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route

from src.config import PORT, SLACK_APP_TOKEN, WEBSOCKET_MODE, slack_app
from src.services.daily_reminders import start_reminder_service, stop_reminder_service
from src.slack.handlers import actions as _actions
from src.slack.handlers import commands as _commands
from src.slack.handlers import events as _events
from src.slack.helpers import thread_manager

_REGISTERED_HANDLERS = (_actions, _commands, _events)


def create_app() -> Starlette:
    """Create Starlette app"""
    handler = SlackRequestHandler(slack_app)

    async def slack_events(request: Request) -> Response:
        return await handler.handle(request)

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    return Starlette(
        routes=[
            Route("/slack/events", slack_events, methods=["POST"]),
            Route("/health", health, methods=["GET"]),
        ]
    )


if __name__ == "__main__":
    start_reminder_service(thread_manager)
    print("Bot running!")

    socket_handler = None  # pylint: disable=invalid-name

    def shutdown_handler(signum: Any, _frame: Any):
        """Handle shutdown signals gracefully"""
        print(f"Received signal {signum}, shutting down...")
        if socket_handler:
            socket_handler.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    try:
        if WEBSOCKET_MODE:
            print("Running in development mode, using socket mode with app token")
            socket_handler = SocketModeHandler(slack_app, SLACK_APP_TOKEN)
            socket_handler.start()
        else:
            print("Running in production mode, using HTTP mode")
            starlette_app = create_app()
            uvicorn.run(starlette_app, host="0.0.0.0", port=PORT)
    finally:
        stop_reminder_service()
