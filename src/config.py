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
    "CHANNEL_ID",
    "AIRTABLE_API_KEY",
    "AIRTABLE_BASE_ID",
    "FRAUDPHEUS_WEBHOOK_SECRET",
    "FRAUDPHEUS_API_KEY",
)

env: dict[str, str] = {name: os.getenv(name, "") for name in REQUIRED_ENV}

SLACK_BOT_TOKEN = env["SLACK_BOT_TOKEN"]
SLACK_SIGNING_SECRET = env["SLACK_SIGNING_SECRET"]
SLACK_USER_TOKEN = os.getenv("SLACK_USER_TOKEN", "")
CHANNEL_ID = env["CHANNEL_ID"]
AIRTABLE_API_KEY = env["AIRTABLE_API_KEY"]
AIRTABLE_BASE_ID = env["AIRTABLE_BASE_ID"]

missing_env = [name for name, value in env.items() if not value]

if missing_env:
    raise ValueError(
        "Missing required environment variables: " + ", ".join(missing_env)
    )

# === Slack configuration ===

slack_app = App(
    token=SLACK_BOT_TOKEN,
    signing_secret=SLACK_SIGNING_SECRET,
)
slack_client = WebClient(token=SLACK_BOT_TOKEN)
slack_user_client = WebClient(token=SLACK_USER_TOKEN)

CHANNEL = env["CHANNEL_ID"]

# === Airtable configuration ===

airtable_api = Api(AIRTABLE_API_KEY)
airtable_base = airtable_api.base(AIRTABLE_BASE_ID)

# === Webhook configuration ===

WEBHOOK_URLS = [
    u.strip() for u in os.getenv("FRAUDPHEUS_WEBHOOK_URLS", "").split(",") if u.strip()
]
WEBHOOK_SECRET = env["FRAUDPHEUS_WEBHOOK_SECRET"]
RETRY_DELAY = 5
MAX_ATTEMPTS = 3

# === API configuration ===

FRAUDPHEUS_API_KEY = env["FRAUDPHEUS_API_KEY"]

# === Other configuration ===

TRUST_EMOJI = {0: "🔵", 1: "🔴", 2: "🟢", 3: "🟡", 4: "⚠️"}

TRUST_LABELS = {
    0: "Blue (Normal)",
    1: "Red (Banned/Convicted)",
    2: "Green (Trusted)",
    3: "Yellow (Suspicious)",
    4: "Unknown",
}

IS_DEVELOPMENT = os.getenv("ENVIRONMENT") == "development"
