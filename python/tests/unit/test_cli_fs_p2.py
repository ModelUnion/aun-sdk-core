import json
from pathlib import Path

from typer.testing import CliRunner


class _FakeStorage:
    def __init__(self):
        self.calls = []

    async def list(self, path, **kwargs):
        self.calls.append(("list", path, kwargs))
        return [
            {
                "type": "symlink",
                "path": f"{path}/current.txt",
                "name": "current.txt",
                "owner": kwargs.get("owner"),
                "target": "/private/a.txt",
                "version": 1,
            }
        ]

    async def symlink(self, target, link_path, **kwargs):
        self.calls.append(("symlink", target, link_path, kwargs))
        return {
            "type": "symlink",
            "path": link_path,
            "name": Path(link_path).name,
            "owner": kwargs.get("owner"),
            "target": target,
            "version": 1,
        }

    async def repoint(self, path, new_target, **kwargs):
        self.calls.append(("repoint", path, new_target, kwargs))
        return {
            "type": "symlink",
            "path": path,
            "name": Path(path).name,
            "owner": kwargs.get("owner"),
            "target": new_target,
            "version": 2,
        }

    async def lstat(self, path, **kwargs):
        self.calls.append(("lstat", path, kwargs))
        return {
            "type": "symlink",
            "path": path,
            "name": Path(path).name,
            "owner": kwargs.get("owner"),
            "target": "/private/a.txt",
            "version": 1,
        }

    async def remove(self, path, **kwargs):
        self.calls.append(("remove", path, kwargs))
        return {"path": path, "removed_count": 1}


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


def test_cli_fs_ln_s_calls_vfs_symlink(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke([
        "--json",
        "fs",
        "ln",
        "-s",
        "alice.agentid.pub:/private/a.txt",
        "alice.agentid.pub:/public/current.txt",
    ])

    assert result.exit_code == 0, result.output
    assert client.storage.calls == [
        ("symlink", "/private/a.txt", "/public/current.txt", {"owner": "alice.agentid.pub", "overwrite": False})
    ]
    assert json.loads(result.output)["target"] == "/private/a.txt"


def test_cli_fs_ln_force_calls_vfs_repoint(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke([
        "--json",
        "fs",
        "ln",
        "-s",
        "-f",
        "--expected-version",
        "1",
        "alice.agentid.pub:/private/v2.txt",
        "alice.agentid.pub:/public/current.txt",
    ])

    assert result.exit_code == 0, result.output
    assert client.storage.calls == [
        (
            "repoint",
            "/public/current.txt",
            "/private/v2.txt",
            {"owner": "alice.agentid.pub", "expected_version": 1},
        )
    ]
    assert json.loads(result.output)["version"] == 2


def test_cli_fs_ls_long_shows_symlink_target(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke(["fs", "ls", "-l", "alice.agentid.pub:/public"])

    assert result.exit_code == 0, result.output
    assert "current.txt -> /private/a.txt" in result.output


def test_cli_fs_stat_symlink_includes_target(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke(["--json", "fs", "stat", "alice.agentid.pub:/public/current.txt"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["type"] == "symlink"
    assert payload["target"] == "/private/a.txt"
