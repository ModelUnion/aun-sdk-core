"""collab create / snapshot create 的 SDK RPC 契约测试。"""

import pytest

from aun_core.collab import CollabClient


class _FakeClient:
    def __init__(self):
        self.calls = []

    async def call(self, method, params=None):
        self.calls.append((method, params or {}))
        return {"ok": True, "method": method}


@pytest.mark.asyncio
async def test_create_delegates_transaction_to_collab_rpc():
    client = _FakeClient()
    collab = CollabClient(client)

    result = await collab.create("alice.aid.com:/proj", "doc1.md", "BASE64")

    assert result["method"] == "collab.create"
    assert client.calls == [
        (
            "collab.create",
            {
                "collab_root": "alice.aid.com:/proj",
                "doc": "doc1.md",
                "source": "BASE64",
            },
        )
    ]


@pytest.mark.asyncio
async def test_tag_create_delegates_transaction_to_collab_rpc():
    client = _FakeClient()
    collab = CollabClient(client)

    result = await collab.tag.create("alice.aid.com:/proj", message="first tag", major=True)

    assert result["method"] == "collab.tag.create"
    assert client.calls == [
        (
            "collab.tag.create",
            {
                "collab_root": "alice.aid.com:/proj",
                "message": "first tag",
                "major": True,
            },
        )
    ]
