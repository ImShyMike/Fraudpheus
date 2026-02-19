"""Webhook dispatch helpers"""

import asyncio
import threading
from typing import Any

from src.webhooks import dispatch_event as dispatch_event_async


def dispatch_event(
    event_type: str,
    data: dict[str, Any],
) -> None:
    """Dispatch an event to all configured webhooks in a background thread"""

    def _run() -> None:
        asyncio.run(dispatch_event_async(event_type, data))

    threading.Thread(target=_run, daemon=True).start()
