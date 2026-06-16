import json

from typer.testing import CliRunner


class _FakeClient:
    """记录 RPC 调用并按方法名返回桩响应。"""

    def __init__(self, responses):
        self.calls = []
        self._responses = responses

    async def call(self, method, params=None):
        self.calls.append((method, params or {}))
        resp = self._responses.get(method)
        if callable(resp):
            return resp(params or {})
        return resp if resp is not None else {}


def _install_fake_session(monkeypatch, storage_commands, client):
    class _FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return client

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(storage_commands, "CLISession", _FakeSession)


def _invoke(args):
    from aun_cli.main import app
    return CliRunner().invoke(app, args)


def test_upload_small_file_uses_put_object(monkeypatch, tmp_path):
    from aun_cli.commands import storage as storage_commands

    f = tmp_path / "hello.txt"
    f.write_bytes(b"hello world")
    client = _FakeClient({
        "storage.get_limits": {"max_inline_bytes": 65536, "max_file_size_bytes": 10485760},
        "storage.put_object": lambda p: {"object_key": p["object_key"], "size_bytes": 11, "version": 1},
    })
    _install_fake_session(monkeypatch, storage_commands, client)

    result = _invoke(["--json", "storage", "upload", str(f), "--name", "docs/hello.txt"])

    assert result.exit_code == 0, result.output
    methods = [m for m, _ in client.calls]
    assert "storage.put_object" in methods
    assert "storage.create_upload_session" not in methods
    _, params = next((m, p) for m, p in client.calls if m == "storage.put_object")
    assert params["object_key"] == "docs/hello.txt"
    assert params["is_private"] is True  # 默认私有
    import base64
    assert base64.b64decode(params["content"]) == b"hello world"


def test_upload_large_file_uses_ticket_flow(monkeypatch, tmp_path):
    from aun_cli.commands import storage as storage_commands
    from aun_cli import storage_core

    big = b"x" * 100
    f = tmp_path / "big.bin"
    f.write_bytes(big)
    put_calls = []
    monkeypatch.setattr(
        storage_core, "_http_put",
        lambda url, data, content_type, verify_ssl=True: put_calls.append((url, len(data))) or 200,
    )
    client = _FakeClient({
        "storage.get_limits": {"max_inline_bytes": 50, "max_file_size_bytes": 10485760},
        "storage.create_upload_session": lambda p: {"upload_url": "https://storage.agentid.pub/upload/x"},
        "storage.complete_upload": lambda p: {"object_key": p["object_key"], "size_bytes": p["size_bytes"], "version": 1},
    })
    _install_fake_session(monkeypatch, storage_commands, client)

    result = _invoke(["--json", "storage", "upload", str(f), "--name", "docs/big.bin", "--public"])

    assert result.exit_code == 0, result.output
    methods = [m for m, _ in client.calls]
    assert methods == ["storage.get_limits", "storage.create_upload_session", "storage.complete_upload"]
    assert put_calls == [("https://storage.agentid.pub/upload/x", 100)]
    _, comp = next((m, p) for m, p in client.calls if m == "storage.complete_upload")
    import hashlib
    assert comp["sha256"] == hashlib.sha256(big).hexdigest()
    assert comp["size_bytes"] == 100
    assert comp["is_private"] is False  # --public


def test_download_uses_ticket_and_writes_file(monkeypatch, tmp_path):
    from aun_cli.commands import storage as storage_commands
    from aun_cli import storage_core

    out = tmp_path / "got.bin"
    monkeypatch.setattr(storage_core, "_http_get", lambda url, verify_ssl=True: b"DOWNLOADED-BYTES")
    client = _FakeClient({
        "storage.create_download_ticket": lambda p: {
            "download_url": "https://storage.agentid.pub/dl/x",
            "file_name": "got.bin",
            "size_bytes": 16,
        },
    })
    _install_fake_session(monkeypatch, storage_commands, client)

    result = _invoke(["storage", "download", "docs/legacy.bin", "--output", str(out)])

    assert result.exit_code == 0, result.output
    methods = [m for m, _ in client.calls]
    # 历史 folder-path 对象也必须能下载：统一走 create_download_ticket
    assert methods == ["storage.create_download_ticket"]
    _, params = client.calls[0]
    assert params["object_key"] == "docs/legacy.bin"
    assert out.read_bytes() == b"DOWNLOADED-BYTES"


def test_delete_calls_delete_object_with_object_key(monkeypatch):
    from aun_cli.commands import storage as storage_commands

    client = _FakeClient({"storage.delete_object": lambda p: {"deleted": True, "object_key": p["object_key"]}})
    _install_fake_session(monkeypatch, storage_commands, client)

    result = _invoke(["--json", "storage", "delete", "docs/old.bin"])

    assert result.exit_code == 0, result.output
    assert client.calls == [("storage.delete_object", {"object_key": "docs/old.bin"})]
    assert json.loads(result.output)["deleted"] is True


def test_list_calls_object_and_prefix_listing(monkeypatch):
    from aun_cli.commands import storage as storage_commands

    client = _FakeClient({
        "storage.list_objects": {
            "items": [{"object_key": "docs/a.txt", "size_bytes": 3, "content_type": "text/plain"}],
            "page": 2,
            "size": 10,
        },
        "storage.list_prefixes": {"prefixes": ["docs/sub/"]},
    })
    _install_fake_session(monkeypatch, storage_commands, client)

    result = _invoke(["--json", "storage", "list", "docs", "--page", "2", "--size", "10", "--marker", "m1"])

    assert result.exit_code == 0, result.output
    assert client.calls == [
        ("storage.list_objects", {"prefix": "docs", "page": 2, "size": 10, "marker": "m1"}),
        ("storage.list_prefixes", {"prefix": "docs", "size": 10}),
    ]
    payload = json.loads(result.output)
    assert payload["objects"]["items"][0]["object_key"] == "docs/a.txt"
    assert payload["prefixes"]["prefixes"] == ["docs/sub/"]


def test_info_calls_head_object(monkeypatch):
    from aun_cli.commands import storage as storage_commands

    client = _FakeClient({
        "storage.head_object": lambda p: {
            "object_key": p["object_key"],
            "size_bytes": 3,
            "content_type": "text/plain",
        }
    })
    _install_fake_session(monkeypatch, storage_commands, client)

    result = _invoke(["--json", "storage", "info", "/docs/a.txt"])

    assert result.exit_code == 0, result.output
    assert client.calls == [("storage.head_object", {"object_key": "docs/a.txt"})]
    assert json.loads(result.output)["object_key"] == "docs/a.txt"
