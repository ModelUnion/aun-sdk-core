import pytest

from aun_core.errors import AUNError
from aun_core.storage import (
    ConflictError,
    DanglingSymlinkError,
    LoopError,
    NodeView,
    StorageVFS,
)


class _FakeClient:
    def __init__(self, responses):
        self.aid = "alice.agentid.pub"
        self.calls = []
        self._responses = responses

    async def call(self, method, params=None):
        params = params or {}
        self.calls.append((method, params))
        response = self._responses.get(method)
        if isinstance(response, BaseException):
            raise response
        if callable(response):
            return response(params)
        return response if response is not None else {}


@pytest.mark.asyncio
async def test_vfs_symlink_and_readlink_call_lowlevel():
    client = _FakeClient({
        "storage.create_symlink": lambda p: {
            "type": "symlink",
            "node_type": "symlink",
            "owner_aid": p["owner_aid"],
            "bucket": p["bucket"],
            "path": p["path"],
            "name": "current.txt",
            "target": p["target"],
            "version": 1,
        },
        "storage.readlink": {
            "type": "symlink",
            "node_type": "symlink",
            "owner_aid": "alice.agentid.pub",
            "bucket": "default",
            "path": "public/current.txt",
            "name": "current.txt",
            "target": "/private/a.txt",
            "version": 1,
            "dangling": False,
        },
    })
    vfs = StorageVFS(client, use_fs_rpc=False)

    created = await vfs.symlink("/private/a.txt", "/public/current.txt", owner="alice.agentid.pub")
    link = await vfs.readlink("/public/current.txt", owner="alice.agentid.pub")

    assert isinstance(created, NodeView)
    assert created.type == "symlink"
    assert created.target == "/private/a.txt"
    assert link.target == "/private/a.txt"
    assert client.calls[0] == (
        "storage.create_symlink",
        {
            "path": "public/current.txt",
            "target": "/private/a.txt",
            "overwrite": False,
            "owner_aid": "alice.agentid.pub",
            "bucket": "default",
        },
    )
    assert client.calls[1][0] == "storage.readlink"


@pytest.mark.asyncio
async def test_vfs_repoint_cas_mismatch_maps_conflict():
    client = _FakeClient({
        "storage.atomic_repoint": {
            "ok": False,
            "current_version": 1,
            "current_target": "/private/v1.txt",
        },
    })
    vfs = StorageVFS(client, use_fs_rpc=False)

    with pytest.raises(ConflictError):
        await vfs.repoint(
            "/public/current.txt",
            "/private/v2.txt",
            owner="alice.agentid.pub",
            expected_version=2,
        )


@pytest.mark.asyncio
async def test_vfs_rename_symlink_calls_atomic_server_contract():
    client = _FakeClient({
        "storage.rename_symlink": lambda p: {
            "ok": True,
            "type": "symlink",
            "node_type": "symlink",
            "owner_aid": p["owner_aid"],
            "bucket": p["bucket"],
            "path": p["new_path"],
            "name": "latest.txt",
            "target": "/private/a.txt",
            "version": 2,
        },
    })
    vfs = StorageVFS(client, use_fs_rpc=False)

    node = await vfs.rename_symlink(
        "/public/current.txt",
        "/public/latest.txt",
        owner="alice.agentid.pub",
        overwrite=True,
        expected_version=1,
    )

    assert node.type == "symlink"
    assert node.path == "/public/latest.txt"
    assert client.calls == [
        (
            "storage.rename_symlink",
            {
                "path": "public/current.txt",
                "new_path": "public/latest.txt",
                "overwrite": True,
                "expected_version": 1,
                "owner_aid": "alice.agentid.pub",
                "bucket": "default",
            },
        ),
    ]


@pytest.mark.asyncio
async def test_vfs_lstat_and_remove_do_not_follow_symlink():
    client = _FakeClient({
        "storage.readlink": {
            "type": "symlink",
            "node_type": "symlink",
            "owner_aid": "alice.agentid.pub",
            "bucket": "default",
            "path": "public/current.txt",
            "name": "current.txt",
            "target": "/private/a.txt",
            "version": 1,
            "dangling": False,
        },
        "storage.resolve_path": {"type": "symlink", "path": "public/current.txt", "target": "/private/a.txt"},
        "storage.delete_symlink": {"deleted": True, "path": "public/current.txt"},
    })
    vfs = StorageVFS(client, use_fs_rpc=False)

    node = await vfs.lstat("/public/current.txt", owner="alice.agentid.pub")
    removed = await vfs.remove("/public/current.txt", owner="alice.agentid.pub")

    assert node.type == "symlink"
    assert removed.removed_count == 1
    assert [method for method, _ in client.calls] == [
        "storage.readlink",
        "storage.resolve_path",
        "storage.delete_symlink",
    ]


@pytest.mark.asyncio
async def test_vfs_maps_loop_and_dangling_errors():
    loop_client = _FakeClient({"storage.resolve_path": AUNError("ELOOP", code=-32031)})
    with pytest.raises(LoopError):
        await StorageVFS(loop_client, use_fs_rpc=False).stat("/loop", owner="alice.agentid.pub")

    dangling_client = _FakeClient({"storage.resolve_path": AUNError("dangling", code=-32032)})
    with pytest.raises(DanglingSymlinkError):
        await StorageVFS(dangling_client, use_fs_rpc=False).stat("/dangling", owner="alice.agentid.pub")
