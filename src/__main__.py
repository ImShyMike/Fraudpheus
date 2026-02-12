"""Main entry point"""

from slack_bolt.adapter.socket_mode import SocketModeHandler

from src.config import slack_app, SLACK_APP_TOKEN
from src.slack.handlers import actions as _actions
from src.slack.handlers import commands as _commands
from src.slack.handlers import events as _events

_REGISTERED_HANDLERS = (_actions, _commands, _events)


if __name__ == "__main__":
    handler = SocketModeHandler(slack_app, SLACK_APP_TOKEN)
    print("Bot running!")
    print("Auto-close inactive threads system started")
    handler.start()
