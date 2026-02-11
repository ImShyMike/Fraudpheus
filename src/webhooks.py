"""Webhook dispatching logic"""

import asyncio
import hashlib
import hmac
import json
from typing import Any

import httpx

from src.config import MAX_ATTEMPTS, RETRY_DELAY, WEBHOOK_SECRET, WEBHOOK_URLS


def _sign(body_bytes: bytes) -> str:
    return hmac.new(WEBHOOK_SECRET.encode(), body_bytes, hashlib.sha256).hexdigest()


async def _deliver_async(
    url: str, body_bytes: bytes, headers: dict[str, str], client: httpx.AsyncClient
):
    attempt = 0
    while attempt < MAX_ATTEMPTS:
        try:
            resp = await client.post(url, content=body_bytes, headers=headers)
            if 200 <= resp.status_code < 300:
                return
            elif 500 <= resp.status_code < 600:
                pass  # TODO: log
            else:
                return  # TODO: log
        except Exception:
            # TODO: log
            pass
        attempt += 1
        if attempt < MAX_ATTEMPTS:
            await asyncio.sleep(RETRY_DELAY)


async def dispatch_event(event_type: str, data: dict[str, Any]):
    """Dispatch an event to all configured webhooks asynchronously."""
    payload: dict[str, Any] = {"event_type": event_type, "data": data}
    body_bytes = json.dumps(payload, separators=(",", ":")).encode()
    signature = _sign(body_bytes)
    headers = {"Content-Type": "application/json", "X-Fraudpheus-Signature": signature}
    timeout = httpx.Timeout(10.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        await asyncio.gather(
            *(
                _deliver_async(url, body_bytes, headers, client)
                for url in WEBHOOK_URLS
            ),
            return_exceptions=True,
        )
