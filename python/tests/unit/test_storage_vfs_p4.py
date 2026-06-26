import base64
import hashlib

import pytest

from aun_core.storage import StorageVFS
from aun_core.storage.errors import ExistsError


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
async def test_vfs_acl_and_token_methods_call_p4_rpc_contracts():
    client = _FakeClient({
        "storage.set_acl": {"acl_id": "acl-1"},
        "storage.remove_acl": {"removed": True},
        "storage.list_acl": {"acls": [{"grantee_aid": "bob.agentid.pub", "perms": "r"}]},
        "storage.set_visibility": {"type": "file", "path": "docs/a.txt", "is_private": False},
        "storage.check_access": {"allowed": True, "operation": "read", "path": "docs/a.txt"},
        "storage.issue_token": {"token": "tok_secret", "token_id": "tok-1"},
        "storage.revoke_token": {"revoked": True},
        "storage.list_tokens": {"tokens": [{"token_id": "tok-1", "read_count": 0}]},
    })
    vfs = StorageVFS(client)

    await vfs.set_acl("/docs", owner="alice.agentid.pub", grantee_aid="bob.agentid.pub", perms="r", expires_at=1, max_uses=2)
    await vfs.remove_acl("/docs", owner="alice.agentid.pub", grantee_aid="bob.agentid.pub")
    acls = await vfs.list_acl("/docs", owner="alice.agentid.pub")
    node = await vfs.set_visibility("/docs/a.txt", owner="alice.agentid.pub", visibility="private", allow_roles=["admin"])
    access = await vfs.check_access("/docs/a.txt", owner="alice.agentid.pub", operation="read")
    token = await vfs.issue_token("/docs/a.txt", owner="alice.agentid.pub", expires_at=3, max_reads=1)
    await vfs.revoke_token("/docs/a.txt", owner="alice.agentid.pub", token="tok_secret")
    tokens = await vfs.list_tokens("/docs/a.txt", owner="alice.agentid.pub")

    assert acls["acls"][0]["grantee_aid"] == "bob.agentid.pub"
    assert node.path == "/docs/a.txt"
    assert access["allowed"] is True
    assert token["token"] == "tok_secret"
    assert tokens["tokens"][0]["token_id"] == "tok-1"
    assert client.calls == [
        ("storage.set_acl", {"path": "docs", "grantee_aid": "bob.agentid.pub", "perms": "r", "expires_at": 1, "max_uses": 2, "owner_aid": "alice.agentid.pub", "bucket": "default"}),
        ("storage.remove_acl", {"path": "docs", "grantee_aid": "bob.agentid.pub", "owner_aid": "alice.agentid.pub", "bucket": "default"}),
        ("storage.list_acl", {"path": "docs", "owner_aid": "alice.agentid.pub", "bucket": "default"}),
        ("storage.set_visibility", {"path": "docs/a.txt", "visibility": "private", "allow_roles": ["admin"], "owner_aid": "alice.agentid.pub", "bucket": "default"}),
        ("storage.check_access", {"path": "docs/a.txt", "operation": "read", "follow_symlinks": True, "owner_aid": "alice.agentid.pub", "bucket": "default"}),
        ("storage.issue_token", {"path": "docs/a.txt", "expires_at": 3, "max_reads": 1, "owner_aid": "alice.agentid.pub", "bucket": "default"}),
        ("storage.revoke_token", {"path": "docs/a.txt", "token": "tok_secret", "owner_aid": "alice.agentid.pub", "bucket": "default"}),
        ("storage.list_tokens", {"path": "docs/a.txt", "owner_aid": "alice.agentid.pub", "bucket": "default"}),
    ]


@pytest.mark.asyncio
async def test_vfs_read_methods_forward_token_to_read_rpc_paths(tmp_path):
    client = _FakeClient({
        "storage.fs.list": {"nodes": []},
        "storage.fs.stat": {"type": "file", "path": "docs/a.txt", "name": "a.txt"},
        "storage.fs.lstat": {"type": "file", "path": "docs/a.txt", "name": "a.txt"},
        "storage.get_object": {"content": base64.b64encode(b"hello").decode("ascii")},
        "storage.create_download_ticket": {"download_url": "https://storage.agentid.pub/dl/1", "sha256": ""},
    })
    vfs = StorageVFS(client)

    async def _fake_http_get(_url, on_progress=None):
        if on_progress:
            on_progress(5, 5)
        return b"large"

    vfs.lowlevel.http_get = _fake_http_get

    await vfs.list("/docs", owner="alice.agentid.pub", token="tok")
    await vfs.stat("/docs/a.txt", owner="alice.agentid.pub", token="tok")
    await vfs.lstat("/docs/a.txt", owner="alice.agentid.pub", token="tok")
    data = await vfs.read_bytes("/docs/a.txt", owner="alice.agentid.pub", token="tok")
    await vfs.download_file("/docs/a.txt", str(tmp_path / "local.txt"), owner="alice.agentid.pub", token="tok")

    assert data == b"hello"
    assert client.calls[0] == ("storage.fs.list", {"path": "docs", "page": 1, "size": 100, "token": "tok", "owner_aid": "alice.agentid.pub", "bucket": "default"})
    assert client.calls[1] == ("storage.fs.stat", {"path": "docs/a.txt", "token": "tok", "owner_aid": "alice.agentid.pub", "bucket": "default"})
    assert client.calls[2] == ("storage.fs.lstat", {"path": "docs/a.txt", "token": "tok", "owner_aid": "alice.agentid.pub", "bucket": "default"})
    assert client.calls[3] == ("storage.get_object", {"object_key": "docs/a.txt", "token": "tok", "owner_aid": "alice.agentid.pub", "bucket": "default"})
    assert client.calls[4] == ("storage.create_download_ticket", {"object_key": "docs/a.txt", "token": "tok", "owner_aid": "alice.agentid.pub", "bucket": "default"})


@pytest.mark.asyncio
async def test_vfs_download_file_refuses_existing_local_file_unless_overwrite(tmp_path):
    body = b"fresh"
    client = _FakeClient({
        "storage.create_download_ticket": {
            "download_url": "https://storage.agentid.pub/dl/1",
            "sha256": hashlib.sha256(body).hexdigest(),
            "file_name": "a.txt",
        },
    })
    vfs = StorageVFS(client)
    http_calls = 0

    async def _fake_http_get(_url, on_progress=None):
        nonlocal http_calls
        http_calls += 1
        return body

    vfs.lowlevel.http_get = _fake_http_get
    target = tmp_path / "local.txt"
    target.write_bytes(b"old")

    with pytest.raises(ExistsError):
        await vfs.download_file("/docs/a.txt", str(target), owner="alice.agentid.pub")

    assert target.read_bytes() == b"old"
    assert http_calls == 0

    result = await vfs.download_file("/docs/a.txt", str(target), owner="alice.agentid.pub", overwrite=True)

    assert result.local_path == str(target)
    assert target.read_bytes() == body
    assert http_calls == 1


@pytest.mark.asyncio
async def test_vfs_read_bytes_forwards_range_options():
    client = _FakeClient({
        "storage.get_object": {"content": base64.b64encode(b"ell").decode("ascii")},
    })
    vfs = StorageVFS(client)

    data = await vfs.read_bytes("/docs/a.txt", owner="alice.agentid.pub", token="tok", offset=1, limit=3)

    assert data == b"ell"
    assert client.calls == [
        ("storage.get_object", {
            "object_key": "docs/a.txt",
            "token": "tok",
            "offset": 1,
            "limit": 3,
            "owner_aid": "alice.agentid.pub",
            "bucket": "default",
        })
    ]


@pytest.mark.asyncio
async def test_vfs_touch_calls_fs_touch_contract():
    client = _FakeClient({
        "storage.fs.touch": {"type": "file", "path": "docs/empty.txt", "name": "empty.txt", "size": 0},
    })
    vfs = StorageVFS(client)

    node = await vfs.touch("/docs/empty.txt", owner="alice.agentid.pub", parents=True, no_create=False, mtime=123)

    assert node.path == "/docs/empty.txt"
    assert client.calls == [
        (
            "storage.fs.touch",
            {
                "path": "docs/empty.txt",
                "parents": True,
                "no_create": False,
                "mtime": 123,
                "owner_aid": "alice.agentid.pub",
                "bucket": "default",
            },
        )
    ]


@pytest.mark.asyncio
async def test_vfs_du_aggregates_find_results_without_server_rpc():
    client = _FakeClient({
        "storage.fs.find": {
            "nodes": [
                {"type": "dir", "path": "docs/sub", "size": 0},
                {"type": "file", "path": "docs/a.txt", "size_bytes": 3},
                {"type": "file", "path": "docs/sub/b.txt", "size": 4},
                {"type": "symlink", "path": "docs/latest", "size": 0},
            ]
        },
    })
    vfs = StorageVFS(client)

    usage = await vfs.du("/docs", owner="alice.agentid.pub", max_depth=2)

    assert usage == {
        "path": "/docs",
        "size_bytes": 7,
        "file_count": 2,
        "dir_count": 1,
        "symlink_count": 1,
        "max_depth": 2,
        "truncated": False,
    }
    assert client.calls == [
        (
            "storage.fs.find",
            {
                "path": "docs",
                "page": 1,
                "page_size": 1000,
                "owner_aid": "alice.agentid.pub",
                "bucket": "default",
            },
        )
    ]
