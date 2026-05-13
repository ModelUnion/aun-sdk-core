#!/usr/bin/env python3
import asyncio
import os
import sys
import time
import uuid
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient


os.environ.setdefault("AUN_ENV", "development")


def _aun_path() -> str:
    root = os.environ.get("AUN_DATA_ROOT", "").strip()
    if root:
        return f"{root}/token-refresh/python-{uuid.uuid4().hex[:8]}"
    return f"./.aun-token-refresh-python-{uuid.uuid4().hex[:8]}"


async def main() -> None:
    issuer = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
    aid = f"py-refresh-{uuid.uuid4().hex[:12]}.{issuer}"
    client = AUNClient({"aun_path": _aun_path()})
    client._config_model.require_forward_secrecy = False
    try:
        await client.auth.create_aid({"aid": aid})
        auth = await client.auth.authenticate({"aid": aid})
        initial_token = auth["access_token"]
        refresh_events: list[dict] = []
        client.on("token.refreshed", lambda payload: refresh_events.append(payload))
        await client.connect(auth, {
            "auto_reconnect": False,
            "heartbeat_interval": 0,
            "token_refresh_before": 3590,
        })

        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            current = (client._identity or {}).get("access_token")
            if current and current != initial_token:
                break
            await asyncio.sleep(1)

        refreshed_token = (client._identity or {}).get("access_token")
        if not refreshed_token or refreshed_token == initial_token:
            raise AssertionError("Python SDK token refresh did not rotate access_token within 45 seconds")
        pong = await client.call("meta.ping", {})
        if not pong:
            raise AssertionError("Python SDK ping after token refresh returned empty result")
        expires_at = (client._identity or {}).get("access_token_expires_at")
        if not isinstance(expires_at, (int, float)) or expires_at - time.time() < 3000:
            raise AssertionError(f"Python SDK refreshed token expiry is invalid: {expires_at!r}")
        print(f"Python SDK token refresh passed aid={aid} events={len(refresh_events)}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
