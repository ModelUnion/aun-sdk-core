"""collab.gc 的 SDK RPC 契约测试。"""

import pytest

from aun_core.collab import CollabClient


class _FakeClient:
    def __init__(self):
        self.calls = []

    async def call(self, method, params=None):
        self.calls.append((method, params or {}))
        return {
            "scanned": 3,
            "reachable": 2,
            "garbage": 1,
            "deleted": 0 if (params or {}).get("dry_run", True) else 1,
            "freed_bytes": 128,
        }


@pytest.mark.asyncio
async def test_gc_defaults_to_dry_run():
    client = _FakeClient()
    collab = CollabClient(client)

    result = await collab.gc("alice.aid.com:/proj")

    assert result["deleted"] == 0
    assert client.calls == [
        ("collab.gc", {"collab_root": "alice.aid.com:/proj", "dry_run": True})
    ]


@pytest.mark.asyncio
async def test_gc_can_request_cleanup():
    client = _FakeClient()
    collab = CollabClient(client)

    result = await collab.gc("alice.aid.com:/proj", dry_run=False)

    assert result["deleted"] == 1
    assert client.calls == [
        ("collab.gc", {"collab_root": "alice.aid.com:/proj", "dry_run": False})
    ]
