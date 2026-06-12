import pytest

from aun_core.storage import NodeView, StorageVFS


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


def _node(path: str, node_type: str = "file", **extra):
    name = path.rstrip("/").rsplit("/", 1)[-1] or "/"
    return {
        "type": node_type,
        "path": path,
        "name": name,
        "owner_aid": "alice.agentid.pub",
        "bucket": "default",
        "mode": "0755" if node_type == "dir" else "0644",
        "version": 1,
        **extra,
    }


@pytest.mark.asyncio
async def test_vfs_defaults_to_fs_list_and_preserves_authoritative_mode():
    client = _FakeClient({
        "storage.fs.list": {"nodes": [_node("docs/a.txt", size=3)]},
    })
    vfs = StorageVFS(client)

    nodes = await vfs.list("/docs", owner="alice.agentid.pub", size=25, marker="m1", long=True)

    assert isinstance(nodes[0], NodeView)
    assert [(n.type, n.path, n.mode) for n in nodes] == [("file", "/docs/a.txt", "0644")]
    assert client.calls == [
        (
            "storage.fs.list",
            {
                "path": "docs",
                "page": 1,
                "size": 25,
                "marker": "m1",
                "owner_aid": "alice.agentid.pub",
                "bucket": "default",
            },
        )
    ]


@pytest.mark.asyncio
async def test_vfs_fs_stat_lstat_remove_mkdir_rename_copy_contracts():
    client = _FakeClient({
        "storage.fs.stat": _node("links/current.txt", "file", size=2),
        "storage.fs.lstat": _node("links/current.txt", "symlink", target="/private/v1.txt"),
        "storage.fs.remove": {"removed_count": 1},
        "storage.fs.mkdir": _node("docs/new", "dir"),
        "storage.fs.rename": _node("docs/b.txt", "file", size=3),
        "storage.fs.copy": _node("docs/c.txt", "file", size=3),
    })
    vfs = StorageVFS(client)

    stat = await vfs.stat("/links/current.txt", owner="alice.agentid.pub")
    lstat = await vfs.lstat("/links/current.txt", owner="alice.agentid.pub")
    removed = await vfs.remove("/links/current.txt", owner="alice.agentid.pub")
    folder = await vfs.mkdir("/docs/new", owner="alice.agentid.pub", parents=True)
    renamed = await vfs.rename("/docs/a.txt", "/docs/b.txt", owner="alice.agentid.pub", overwrite=True, expected_version=7)
    copied = await vfs.copy("/docs/b.txt", "/docs/c.txt", owner="alice.agentid.pub", overwrite=True, follow_symlinks=True)
    cross_owner = await vfs.copy("/docs/b.txt", "/inbox/c.txt", owner="alice.agentid.pub", dst_owner="bob.agentid.pub")

    assert stat.type == "file"
    assert lstat.type == "symlink"
    assert lstat.target == "/private/v1.txt"
    assert removed.removed_count == 1
    assert folder.type == "dir"
    assert renamed.path == "/docs/b.txt"
    assert copied.path == "/docs/c.txt"
    assert [method for method, _ in client.calls] == [
        "storage.fs.stat",
        "storage.fs.lstat",
        "storage.fs.remove",
        "storage.fs.mkdir",
        "storage.fs.rename",
        "storage.fs.copy",
        "storage.fs.copy",
    ]
    rename_params = client.calls[4][1]
    assert rename_params["src"] == "docs/a.txt"
    assert rename_params["dst"] == "docs/b.txt"
    assert "src_type" not in rename_params
    assert client.calls[5][1]["follow_symlinks"] is True
    assert cross_owner.path == "/docs/c.txt"
    assert client.calls[6][1]["owner_aid"] == "alice.agentid.pub"
    assert client.calls[6][1]["dst_owner_aid"] == "bob.agentid.pub"
    assert client.calls[6][1]["dst"] == "inbox/c.txt"


@pytest.mark.asyncio
async def test_vfs_fs_find_and_df_contracts():
    client = _FakeClient({
        "storage.fs.find": {"items": [_node("docs/a.txt", "file", size=5)]},
        "storage.fs.df": {"owner_aid": "alice.agentid.pub", "bucket": "default", "used_bytes": 5, "quota_bytes": 10, "object_count": 1},
    })
    vfs = StorageVFS(client)

    found = await vfs.find("/docs", owner="alice.agentid.pub", name="*.txt", node_type="f", size="+3", mtime="-7", page_size=50, token="tok")
    usage = await vfs.df(owner="alice.agentid.pub")

    assert [node.path for node in found] == ["/docs/a.txt"]
    assert usage.used_bytes == 5
    assert usage.avail_bytes == 5
    assert client.calls == [
        ("storage.fs.find", {"path": "docs", "name": "*.txt", "type": "f", "size": "+3", "mtime": "-7", "page": 1, "page_size": 50, "token": "tok", "owner_aid": "alice.agentid.pub", "bucket": "default"}),
        ("storage.fs.df", {"owner_aid": "alice.agentid.pub", "bucket": "default"}),
    ]


@pytest.mark.asyncio
async def test_vfs_can_fallback_to_p1_p2_paths_when_flag_disabled():
    client = _FakeClient({
        "storage.list_prefixes": {"prefixes": ["sub/"]},
        "storage.list_objects": {"items": [_node("docs/a.txt", size=3)]},
    })
    vfs = StorageVFS(client, use_fs_rpc=False)

    nodes = await vfs.list("/docs", owner="alice.agentid.pub")

    assert [(n.type, n.path) for n in nodes] == [("dir", "/docs/sub"), ("file", "/docs/a.txt")]
    assert [method for method, _ in client.calls] == ["storage.list_prefixes", "storage.list_objects"]
