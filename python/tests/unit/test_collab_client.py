import pytest

from aun_core import AUNClient
from aun_core.collab import CollabClient, CollabConflictError


class _FakeClient:
    def __init__(self):
        self.calls = []
        self.responses = {}

    async def call(self, method, params=None):
        params = params or {}
        self.calls.append((method, params))
        response = self.responses.get(method, {"ok": True, "method": method})
        if isinstance(response, BaseException):
            raise response
        return response


@pytest.mark.asyncio
async def test_collab_submit_calls_rpc_with_exact_params():
    client = _FakeClient()
    collab = CollabClient(client)

    result = await collab.submit("alice.aid.com:/proj", "d.md", "BASE64", base_version=3)

    assert result["method"] == "collab.submit"
    assert client.calls == [
        ("collab.submit", {
            "collab_root": "alice.aid.com:/proj",
            "doc": "d.md",
            "source": "BASE64",
            "base_version": 3,
        })
    ]


@pytest.mark.asyncio
async def test_collab_methods_match_server_rpc_contract():
    client = _FakeClient()
    collab = CollabClient(client)

    await collab.ls("alice.aid.com:/proj")
    await collab.create("alice.aid.com:/proj", "d.md", "S")
    await collab.read("alice.aid.com:/proj", "d.md")
    await collab.submit("alice.aid.com:/proj", "d.md", "S", 1)
    await collab.merge("alice.aid.com:/proj", "d.md", "S", 1)
    await collab.history("alice.aid.com:/proj", "d.md")
    await collab.get("alice.aid.com:/proj", "d.md", 1)
    await collab.diff("alice.aid.com:/proj", "d.md", 1, 2)
    await collab.export("alice.aid.com:/proj", "alice.aid.com:/copy")
    await collab.adopt("alice.aid.com:/proj", "alice.aid.com:/new")
    await collab.prune("alice.aid.com:/proj", "d.md")
    await collab.discover("g-team.aid.com")
    await collab.unregister("g-team.aid.com", "g-team.aid.com:/proj")
    await collab.snapshot.create("alice.aid.com:/proj", message="m", major=True)
    await collab.snapshot.list("alice.aid.com:/proj")
    await collab.snapshot.show("alice.aid.com:/proj", "1.0.0")
    await collab.snapshot.diff("alice.aid.com:/proj", "1.0.0", "1.0.1")
    await collab.snapshot.restore("alice.aid.com:/proj", "1.0.0", message="r")
    await collab.snapshot.rm("alice.aid.com:/proj", "1.0.0")
    await collab.snapshot.prune("alice.aid.com:/proj", before="2026-06-01", keep_last=2)

    assert [method for method, _ in client.calls] == [
        "collab.ls",
        "collab.create",
        "collab.read",
        "collab.submit",
        "collab.merge",
        "collab.history",
        "collab.get",
        "collab.diff",
        "collab.export",
        "collab.adopt",
        "collab.prune",
        "collab.discover",
        "collab.unregister",
        "collab.snapshot.create",
        "collab.snapshot.list",
        "collab.snapshot.show",
        "collab.snapshot.diff",
        "collab.snapshot.restore",
        "collab.snapshot.rm",
        "collab.snapshot.prune",
    ]
    assert client.calls[-1][1] == {
        "collab_root": "alice.aid.com:/proj",
        "before": "2026-06-01",
        "keep_last": 2,
    }
    assert client.calls[9][1] == {
        "src": "alice.aid.com:/proj",
        "new_root": "alice.aid.com:/new",
    }
    assert client.calls[19][1] == {
        "collab_root": "alice.aid.com:/proj",
        "before": "2026-06-01",
        "keep_last": 2,
    }


def test_aun_client_has_lazy_collab_facade():
    client = AUNClient()

    assert client.collab is client.collab
    assert isinstance(client.collab, CollabClient)


def test_python_sdk_does_not_implement_diff3():
    import pathlib
    import aun_core.collab as collab_pkg

    root = pathlib.Path(collab_pkg.__file__).resolve().parent
    assert not any(path.name.startswith("diff3") for path in root.rglob("*.py"))


def test_collab_rpc_namespace_is_not_storage_prefixed():
    import pathlib
    import aun_core.collab as collab_pkg

    root = pathlib.Path(collab_pkg.__file__).resolve().parent
    source = "\n".join(path.read_text(encoding="utf-8") for path in root.rglob("*.py"))
    assert "collab." in source
    assert "storage.collab." not in source


@pytest.mark.asyncio
async def test_collab_conflict_error_preserves_server_fields():
    from aun_core.errors import AUNError

    client = _FakeClient()
    client.responses["collab.submit"] = AUNError(
        "提交失败",
        code=-32009,
        data={"current_version": 4, "current_target": "alice.aid.com:/proj/v4", "hint": "merge first"},
    )
    collab = CollabClient(client)

    with pytest.raises(CollabConflictError) as exc:
        await collab.submit("alice.aid.com:/proj", "d.md", "S", 3)

    assert exc.value.current_version == 4
    assert exc.value.current_target == "alice.aid.com:/proj/v4"
    assert exc.value.hint == "merge first"
