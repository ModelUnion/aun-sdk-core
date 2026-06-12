from typer.testing import CliRunner


class _FakeStorage:
    def __init__(self):
        self.calls = []

    async def list(self, path, **kwargs):
        self.calls.append(("list", path, kwargs))
        return [
            {
                "type": "file",
                "path": f"{path}/a.txt",
                "name": "a.txt",
                "owner": kwargs.get("owner"),
                "mode": "0644",
                "size": 3,
                "mtime": 123,
            },
            {
                "type": "dir",
                "path": f"{path}/sub",
                "name": "sub",
                "owner": kwargs.get("owner"),
                "mode": "0755",
                "mtime": 124,
            },
        ]


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


def test_cli_fs_ls_long_prints_authoritative_mode(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke(["fs", "ls", "-l", "alice.agentid.pub:/docs"])

    assert result.exit_code == 0, result.output
    assert "0644" in result.output
    assert "0755" in result.output
    assert client.storage.calls == [
        ("list", "/docs", {"owner": "alice.agentid.pub", "page": 1, "size": 100, "marker": None, "long": True})
    ]
