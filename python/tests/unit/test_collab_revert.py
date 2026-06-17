"""collab.revert 的 SDK RPC 契约测试。"""

import pytest

from aun_core.collab import CollabClient
from aun_core.errors import AUNError


class _FakeClient:
    def __init__(self):
        self.calls = []
        self.responses = {}

    async def call(self, method, params=None):
        self.calls.append((method, params or {}))
        response = self.responses.get(method, {"version": 5, "current_target": "alice.aid.com:/proj/v5"})
        if isinstance(response, BaseException):
            raise response
        return response


@pytest.mark.asyncio
async def test_revert_calls_collab_revert_with_exact_params():
    client = _FakeClient()
    collab = CollabClient(client)

    result = await collab.revert("alice.aid.com:/proj", "doc.md", rev=2, message="Revert to v2")

    assert result["version"] == 5
    assert client.calls == [
        (
            "collab.revert",
            {
                "collab_root": "alice.aid.com:/proj",
                "doc": "doc.md",
                "rev": 2,
                "message": "Revert to v2",
            },
        )
    ]


@pytest.mark.asyncio
async def test_revert_not_found_error_is_propagated():
    client = _FakeClient()
    client.responses["collab.revert"] = AUNError("version not found", code=-32004)
    collab = CollabClient(client)

    with pytest.raises(AUNError) as exc:
        await collab.revert("alice.aid.com:/proj", "doc.md", rev=99)

    assert exc.value.code == -32004
