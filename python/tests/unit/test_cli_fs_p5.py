import json
import fnmatch

from typer.testing import CliRunner


class _FakeStorage:
    def __init__(self):
        self.calls = []
        self.nodes = [
            {"type": "file", "path": "/docs/a.txt", "name": "a.txt", "size": 42, "mtime": 1_000_000 - 40 * 86400},
            {"type": "file", "path": "/docs/b.md", "name": "b.md", "size": 5, "mtime": 1_000_000 - 5 * 86400},
            {"type": "dir", "path": "/docs/sub", "name": "sub", "size": 0, "mtime": 1_000_000 - 10 * 86400},
            {"type": "symlink", "path": "/docs/latest", "name": "latest", "size": 0, "mtime": 1_000_000 - 2 * 86400},
        ]

    async def list(self, path, **kwargs):
        self.calls.append(("list", path, kwargs))
        return list(self.nodes)

    async def find(self, path, **kwargs):
        self.calls.append(("find", path, kwargs))
        result = []
        for node in self.nodes:
            if kwargs.get("name") and not fnmatch.fnmatchcase(str(node.get("name") or ""), kwargs["name"]):
                continue
            node_type = kwargs.get("node_type")
            if node_type:
                mapping = {"f": "file", "d": "dir", "l": "symlink"}
                if node.get("type") != mapping.get(node_type, node_type):
                    continue
            size_expr = kwargs.get("size")
            if size_expr:
                raw = str(size_expr)
                op = raw[0] if raw[:1] in {"+", "-"} else ""
                threshold = int(raw[1:] if op else raw)
                size = int(node.get("size") or 0)
                if (op == "+" and size <= threshold) or (op == "-" and size >= threshold) or (not op and size != threshold):
                    continue
            mtime_expr = kwargs.get("mtime")
            if mtime_expr:
                raw = str(mtime_expr)
                op = raw[0] if raw[:1] in {"+", "-"} else ""
                threshold = int(raw[1:] if op else raw)
                age_days = int((1_000_000 - int(node.get("mtime") or 0)) // 86400)
                if (op == "+" and age_days <= threshold) or (op == "-" and age_days >= threshold) or (not op and age_days != threshold):
                    continue
            result.append(node)
        return result


class _FakeClient:
    def __init__(self):
        self.storage = _FakeStorage()


def _install_fake_session(monkeypatch, fs_commands, client):
    class _FakeSession:
        def __init__(self, ctx, **kwargs):
            self.kwargs = kwargs

        async def __aenter__(self):
            return client

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(fs_commands, "CLISession", _FakeSession)


def _invoke(args):
    from aun_cli.main import app

    return CliRunner().invoke(app, args)


def test_cli_fs_find_filters_name_type_and_size(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke(["--json", "fs", "find", "alice.agentid.pub:/docs", "--name", "*.txt", "--type", "f", "--size", "+10"])

    assert result.exit_code == 0, result.output
    assert client.storage.calls == [
        ("find", "/docs", {"owner": "alice.agentid.pub", "name": "*.txt", "node_type": "f", "size": "+10", "mtime": None, "page_size": 1000})
    ]
    payload = json.loads(result.output)
    assert [item["path"] for item in payload] == ["/docs/a.txt"]


def test_cli_fs_find_filters_mtime_and_symlink(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)
    monkeypatch.setattr(fs_commands.time, "time", lambda: 1_000_000)

    old = _invoke(["--json", "fs", "find", "alice.agentid.pub:/docs", "--mtime", "+30"])
    links = _invoke(["--json", "fs", "find", "alice.agentid.pub:/docs", "--type", "l"])

    assert old.exit_code == 0, old.output
    assert links.exit_code == 0, links.output
    assert [item["path"] for item in json.loads(old.output)] == ["/docs/a.txt"]
    assert [item["path"] for item in json.loads(links.output)] == ["/docs/latest"]


def test_cli_fs_find_no_match_returns_empty_json(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke(["--json", "fs", "find", "alice.agentid.pub:/docs", "--name", "*.pdf"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == []
