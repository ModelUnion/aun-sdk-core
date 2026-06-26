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
async def test_collab_commit_calls_rpc_with_exact_params():
    client = _FakeClient()
    collab = CollabClient(client)

    result = await collab.commit("alice.aid.com:/proj", "d.md", "BASE64", onto=3)

    assert result["method"] == "collab.commit"
    assert client.calls == [
        ("collab.commit", {
            "collab_root": "alice.aid.com:/proj",
            "doc": "d.md",
            "source": "BASE64",
            "onto": 3,
            "message": "",
        })
    ]


@pytest.mark.asyncio
async def test_collab_methods_match_server_rpc_contract():
    client = _FakeClient()
    collab = CollabClient(client)

    await collab.ls_files("alice.aid.com:/proj")
    await collab.create("alice.aid.com:/proj", "d.md", "S")
    await collab.show("alice.aid.com:/proj", "d.md")
    await collab.commit("alice.aid.com:/proj", "d.md", "S", 1)
    await collab.merge("alice.aid.com:/proj", "d.md", "S", 1)
    await collab.log("alice.aid.com:/proj", "d.md")
    await collab.show("alice.aid.com:/proj", "d.md", rev=1)
    await collab.diff("alice.aid.com:/proj", "d.md", 1, 2)
    await collab.clone("alice.aid.com:/proj", "alice.aid.com:/copy")
    await collab.clone("alice.aid.com:/proj", "alice.aid.com:/new", reroot=True)
    await collab.prune("alice.aid.com:/proj", "d.md")
    await collab.gc("alice.aid.com:/proj", dry_run=False)
    await collab.reflog("alice.aid.com:/proj", "d.md", limit=5)
    await collab.revert("alice.aid.com:/proj", "d.md", 1, message="revert")
    await collab.ls_remote("g-team.aid.com")
    await collab.unregister("g-team.aid.com", "g-team.aid.com:/proj")
    await collab.set_acl("alice.aid.com:/proj", grantee_aid="bob.aid.com", perms="w", expires_at=123, max_uses=2)
    await collab.remove_acl("alice.aid.com:/proj", grantee_aid="bob.aid.com")
    await collab.tag.create("alice.aid.com:/proj", message="m", major=True)
    await collab.tag.list("alice.aid.com:/proj")
    await collab.tag.show("alice.aid.com:/proj", "1.0.0")
    await collab.tag.diff("alice.aid.com:/proj", "1.0.0", "1.0.1")
    await collab.tag.restore("alice.aid.com:/proj", "1.0.0", message="r")
    await collab.tag.rm("alice.aid.com:/proj", "1.0.0")
    await collab.tag.prune("alice.aid.com:/proj", before="2026-06-01", keep_last=2)

    assert [method for method, _ in client.calls] == [
        "collab.ls-files",
        "collab.create",
        "collab.show",
        "collab.commit",
        "collab.merge",
        "collab.log",
        "collab.show",
        "collab.diff",
        "collab.clone",
        "collab.clone",
        "collab.prune",
        "collab.gc",
        "collab.reflog",
        "collab.revert",
        "collab.ls-remote",
        "collab.unregister",
        "collab.set_acl",
        "collab.remove_acl",
        "collab.tag.create",
        "collab.tag.list",
        "collab.tag.show",
        "collab.tag.diff",
        "collab.tag.restore",
        "collab.tag.rm",
        "collab.tag.prune",
    ]
    assert client.calls[-1][1] == {
        "collab_root": "alice.aid.com:/proj",
        "before": "2026-06-01",
        "keep_last": 2,
    }
    assert client.calls[8][1] == {
        "src": "alice.aid.com:/proj",
        "dest": "alice.aid.com:/copy",
        "reroot": False,
    }
    assert client.calls[9][1] == {
        "src": "alice.aid.com:/proj",
        "dest": "alice.aid.com:/new",
        "reroot": True,
    }
    assert client.calls[16][1] == {
        "collab_root": "alice.aid.com:/proj",
        "grantee_aid": "bob.aid.com",
        "perms": "w",
        "expires_at": 123,
        "max_uses": 2,
    }
    assert client.calls[17][1] == {
        "collab_root": "alice.aid.com:/proj",
        "grantee_aid": "bob.aid.com",
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
    client.responses["collab.commit"] = AUNError(
        "提交失败",
        code=-32009,
        data={"current_version": 4, "current_target": "alice.aid.com:/proj/v4", "hint": "merge first"},
    )
    collab = CollabClient(client)

    with pytest.raises(CollabConflictError) as exc:
        await collab.commit("alice.aid.com:/proj", "d.md", "S", 3)

    assert exc.value.current_version == 4
    assert exc.value.current_target == "alice.aid.com:/proj/v4"
    assert exc.value.hint == "merge first"
