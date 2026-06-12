import hashlib

import pytest

from aun_core.errors import AUNError
from aun_core.storage import NotFoundError, ObjectView, StorageVFS, normalize_path, path_to_key


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


def test_path_normalization():
    assert normalize_path("//a/../b") == "/b"
    assert normalize_path("docs/./a.txt") == "/docs/a.txt"
    assert path_to_key("/docs/a.txt") == "docs/a.txt"
    assert path_to_key("/") == ""


@pytest.mark.asyncio
async def test_upload_inline_dedup_skips_http_put(tmp_path):
    data = b"hello vfs"
    local = tmp_path / "hello.txt"
    local.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    client = _FakeClient({
        "storage.check_upload": {"skip_upload": True, "within_limit": True},
        "storage.complete_upload": lambda p: {
            "owner_aid": p["owner_aid"],
            "bucket": p["bucket"],
            "object_key": p["object_key"],
            "size_bytes": p["size_bytes"],
            "sha256": p["sha256"],
            "version": 2,
        },
    })
    vfs = StorageVFS(client, use_fs_rpc=False)
    put_calls = []

    async def fake_put(*args, **kwargs):
        put_calls.append((args, kwargs))

    vfs.lowlevel.http_put = fake_put

    result = await vfs.upload_file(str(local), "/docs/hello.txt", owner="alice.agentid.pub")

    assert isinstance(result, ObjectView)
    assert result.path == "/docs/hello.txt"
    assert result.sha256 == sha
    assert put_calls == []
    assert [m for m, _ in client.calls] == ["storage.check_upload", "storage.complete_upload"]
    _, complete = client.calls[-1]
    assert complete["skip_blob"] is True


@pytest.mark.asyncio
async def test_upload_large_uses_session_and_complete(tmp_path):
    data = b"x" * 100
    local = tmp_path / "large.bin"
    local.write_bytes(data)
    client = _FakeClient({
        "storage.check_upload": {"skip_upload": False, "within_limit": True},
        "storage.get_limits": {"max_inline_bytes": 50, "max_file_size_bytes": 1000},
        "storage.create_upload_session": {"upload_url": "https://storage.agentid.pub/upload/1", "session_id": "s1"},
        "storage.complete_upload": lambda p: {
            "owner_aid": p["owner_aid"],
            "bucket": p["bucket"],
            "object_key": p["object_key"],
            "size_bytes": p["size_bytes"],
            "sha256": p["sha256"],
            "version": 1,
        },
    })
    vfs = StorageVFS(client, use_fs_rpc=False)
    put_calls = []

    async def fake_put(url, body, headers=None, on_progress=None):
        put_calls.append((url, len(body), headers))

    vfs.lowlevel.http_put = fake_put

    result = await vfs.upload_file(str(local), "/docs/large.bin", owner="alice.agentid.pub")

    assert result.path == "/docs/large.bin"
    assert put_calls == [("https://storage.agentid.pub/upload/1", 100, {"Content-Type": "application/octet-stream"})]
    assert [m for m, _ in client.calls] == [
        "storage.check_upload",
        "storage.get_limits",
        "storage.create_upload_session",
        "storage.complete_upload",
    ]


@pytest.mark.asyncio
async def test_list_combines_objects_and_prefixes():
    client = _FakeClient({
        "storage.list_prefixes": {"prefixes": ["sub/"]},
        "storage.list_objects": {
            "items": [
                {"owner_aid": "alice.agentid.pub", "bucket": "default", "object_key": "docs/a.txt", "size_bytes": 3},
                {"owner_aid": "alice.agentid.pub", "bucket": "default", "object_key": "docs/sub/nested.txt", "size_bytes": 6},
            ]
        },
    })
    vfs = StorageVFS(client, use_fs_rpc=False)

    nodes = await vfs.list("/docs", owner="alice.agentid.pub")

    assert [(n.type, n.path) for n in nodes] == [("dir", "/docs/sub"), ("file", "/docs/a.txt")]
    assert client.calls[0] == ("storage.list_prefixes", {"prefix": "docs/", "size": 100, "owner_aid": "alice.agentid.pub", "bucket": "default"})
    assert client.calls[1][0] == "storage.list_objects"


@pytest.mark.asyncio
async def test_remove_recursive_uses_batch_delete():
    client = _FakeClient({
        "storage.resolve_path": {"type": "folder", "path": "tmp"},
        "storage.batch_delete": {"summary": {"deleted": 3, "errors": 0}},
    })
    vfs = StorageVFS(client, use_fs_rpc=False)

    result = await vfs.remove("/tmp", owner="alice.agentid.pub", recursive=True)

    assert result.removed_count == 3
    assert [m for m, _ in client.calls] == ["storage.resolve_path", "storage.batch_delete"]
    _, params = client.calls[-1]
    assert params["items"] == [{"type": "folder", "path": "tmp"}]
    assert params["recursive"] is True


@pytest.mark.asyncio
async def test_error_code_mapping_to_not_found():
    client = _FakeClient({
        "storage.resolve_path": AUNError("missing", code=-32008),
    })
    vfs = StorageVFS(client, use_fs_rpc=False)

    with pytest.raises(NotFoundError):
        await vfs.stat("/missing.txt", owner="alice.agentid.pub")
