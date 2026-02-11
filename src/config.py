"""App configuration and setup"""

import os

from dotenv import load_dotenv
from pyairtable import Api
from slack_bolt import App
from slack_sdk import WebClient

load_dotenv()

REQUIRED_ENV = (
    "SLACK_BOT_TOKEN",
    "SLACK_SIGNING_SECRET",
    "SLACK_USER_TOKEN",
    "CHANNEL_ID",
    "AIRTABLE_API_KEY",
    "AIRTABLE_BASE_ID",
)

env = {name: os.getenv(name) for name in REQUIRED_ENV}

SLACK_BOT_TOKEN = env["SLACK_BOT_TOKEN"]
SLACK_SIGNING_SECRET = env["SLACK_SIGNING_SECRET"]
SLACK_USER_TOKEN = env["SLACK_USER_TOKEN"]
CHANNEL_ID = env["CHANNEL_ID"]
AIRTABLE_API_KEY = env["AIRTABLE_API_KEY"]
AIRTABLE_BASE_ID = env["AIRTABLE_BASE_ID"]

missing_env = [name for name, value in env.items() if not value]

if missing_env:
    raise ValueError(
        "Missing required environment variables: " + ", ".join(missing_env)
    )

app = App(
    token=SLACK_BOT_TOKEN,
    signing_secret=SLACK_SIGNING_SECRET,
)
client = WebClient(token=SLACK_BOT_TOKEN)
user_client = WebClient(token=SLACK_USER_TOKEN)

CHANNEL = env["CHANNEL_ID"]

airtable_api = Api(str(AIRTABLE_API_KEY))
airtable_base = airtable_api.base(str(AIRTABLE_BASE_ID))
