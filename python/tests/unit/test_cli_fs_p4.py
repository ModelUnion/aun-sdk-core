import json

from typer.testing import CliRunner


class _FakeStorage:
    def __init__(self):
        self.calls = []

    async def set_visibility(self, path, **kwargs):
        self.calls.append(("set_visibility", path, kwargs))
        return {"type": "file", "path": path, "visibility": kwargs.get("visibility")}

    async def set_acl(self, path, **kwargs):
        self.calls.append(("set_acl", path, kwargs))
        return {"acl_id": "acl-1", **kwargs}

    async def remove_acl(self, path, **kwargs):
        self.calls.append(("remove_acl", path, kwargs))
        return {"removed": True}

    async def list_acl(self, path, **kwargs):
        self.calls.append(("list_acl", path, kwargs))
        return {"acls": [{"grantee_aid": "bob.agentid.pub", "perms": "r"}]}

    async def issue_token(self, path, **kwargs):
        self.calls.append(("issue_token", path, kwargs))
        return {"token": "tok_secret", "token_id": "tok-1"}

    async def revoke_token(self, path, **kwargs):
        self.calls.append(("revoke_token", path, kwargs))
        return {"revoked": True}

    async def list_tokens(self, path, **kwargs):
        self.calls.append(("list_tokens", path, kwargs))
        return {"tokens": [{"token_id": "tok-1"}]}

    async def stat(self, path, **kwargs):
        self.calls.append(("stat", path, kwargs))
        content_type = "application/octet-stream" if path.endswith(".bin") else "text/plain"
        return {"type": "file", "path": path, "name": path.rsplit("/", 1)[-1], "content_type": content_type, "size": 6}

    async def read_bytes(self, path, **kwargs):
        self.calls.append(("read_bytes", path, kwargs))
        if path.endswith(".bin"):
            return b"\0x"
        return b"secret"


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


def test_cli_fs_chmod_calls_set_visibility(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke(["--json", "fs", "chmod", "--visibility", "private", "--allow-roles", "admin,member", "alice.agentid.pub:/docs/a.txt"])

    assert result.exit_code == 0, result.output
    assert client.storage.calls == [
        ("set_visibility", "/docs/a.txt", {"owner": "alice.agentid.pub", "visibility": "private", "allow_roles": ["admin", "member"]})
    ]
    assert json.loads(result.output)["visibility"] == "private"


def test_cli_fs_setfacl_getfacl_and_remove(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    add_result = _invoke(["--json", "fs", "setfacl", "-m", "aid:bob.agentid.pub:r", "--max-uses", "2", "alice.agentid.pub:/docs"])
    list_result = _invoke(["--json", "fs", "getfacl", "alice.agentid.pub:/docs"])
    remove_result = _invoke(["--json", "fs", "setfacl", "-x", "aid:bob.agentid.pub", "alice.agentid.pub:/docs"])

    assert add_result.exit_code == 0, add_result.output
    assert list_result.exit_code == 0, list_result.output
    assert remove_result.exit_code == 0, remove_result.output
    assert client.storage.calls == [
        ("set_acl", "/docs", {"owner": "alice.agentid.pub", "grantee_aid": "bob.agentid.pub", "perms": "r", "expires_at": None, "max_uses": 2}),
        ("list_acl", "/docs", {"owner": "alice.agentid.pub"}),
        ("remove_acl", "/docs", {"owner": "alice.agentid.pub", "grantee_aid": "bob.agentid.pub"}),
    ]


def test_cli_fs_token_commands(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    issue = _invoke(["--json", "fs", "token", "issue", "--max-reads", "1", "alice.agentid.pub:/docs/a.txt"])
    listed = _invoke(["--json", "fs", "token", "ls", "alice.agentid.pub:/docs/a.txt"])
    revoked = _invoke(["--json", "fs", "token", "revoke", "--token", "tok_secret", "alice.agentid.pub:/docs/a.txt"])

    assert issue.exit_code == 0, issue.output
    assert listed.exit_code == 0, listed.output
    assert revoked.exit_code == 0, revoked.output
    assert client.storage.calls == [
        ("issue_token", "/docs/a.txt", {"owner": "alice.agentid.pub", "expires_at": None, "max_reads": 1}),
        ("list_tokens", "/docs/a.txt", {"owner": "alice.agentid.pub"}),
        ("revoke_token", "/docs/a.txt", {"owner": "alice.agentid.pub", "token": "tok_secret"}),
    ]
    assert json.loads(issue.output)["token"] == "tok_secret"


def test_cli_fs_cat_forwards_token(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke(["fs", "cat", "--token", "tok_secret", "alice.agentid.pub:/docs/a.txt"])

    assert result.exit_code == 0, result.output
    assert result.output.strip().splitlines()[-1] == "secret"
    assert client.storage.calls == [
        ("stat", "/docs/a.txt", {"owner": "alice.agentid.pub", "token": "tok_secret"}),
        ("read_bytes", "/docs/a.txt", {"owner": "alice.agentid.pub", "token": "tok_secret"}),
    ]


def test_cli_fs_cat_binary_reads_only_requested_head(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke(["--json", "fs", "cat", "--head-bytes", "2", "alice.agentid.pub:/docs/a.bin"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["binary"] is True
    assert payload["size"] == 6
    assert payload["head"]["bytes"] == 2
    assert client.storage.calls == [
        ("stat", "/docs/a.bin", {"owner": "alice.agentid.pub", "token": None}),
        ("read_bytes", "/docs/a.bin", {"owner": "alice.agentid.pub", "token": None, "offset": 0, "limit": 2}),
    ]
