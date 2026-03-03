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
            if 500 <= resp.status_code < 600:
                print(
                    f"Server error {resp.status_code} from {url}, attempt {attempt + 1}"
                )
                return
            print(
                f"Unexpected status code {resp.status_code} from {url}, attempt {attempt + 1}"
            )
        except Exception:  # pylint: disable=broad-except
            print(f"Error delivering webhook to {url}, attempt {attempt + 1}")
        attempt += 1
        if attempt < MAX_ATTEMPTS:
            await asyncio.sleep(RETRY_DELAY)
        else:
            print(f"Failed to deliver webhook to {url} after {MAX_ATTEMPTS} attempts")


async def dispatch_event(event_type: str, data: dict[str, Any]):
    """Dispatch an event to all configured webhooks asynchronously"""
    if not WEBHOOK_URLS:
        return
    payload: dict[str, Any] = {"event_type": event_type, "data": data}
    body_bytes = json.dumps(payload, separators=(",", ":")).encode()
    signature = _sign(body_bytes)
    headers = {"Content-Type": "application/json", "X-Fraudpheus-Signature": signature}
    timeout = httpx.Timeout(10.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        await asyncio.gather(
            *(_deliver_async(url, body_bytes, headers, client) for url in WEBHOOK_URLS),
            return_exceptions=True,
        )
