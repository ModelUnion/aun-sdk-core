import json

from typer.testing import CliRunner


class _FakeStorage:
    def __init__(self):
        self.calls = []

    async def mount(self, source, mount_path, **kwargs):
        self.calls.append(("mount", source, mount_path, kwargs))
        return {
            "type": "mount",
            "path": mount_path,
            "name": mount_path.rsplit("/", 1)[-1],
            "owner": kwargs.get("owner"),
            "mount_source": source,
        }

    async def mount_volume(self, volume_id, mount_path, **kwargs):
        self.calls.append(("mount_volume", volume_id, mount_path, kwargs))
        return {
            "type": "mount",
            "path": mount_path,
            "name": mount_path.rsplit("/", 1)[-1],
            "owner": kwargs.get("owner"),
            "volume_id": volume_id,
        }

    async def unmount(self, mount_path, **kwargs):
        self.calls.append(("unmount", mount_path, kwargs))
        return {"path": mount_path, "removed_count": 1}

    async def approve_mount(self, mount_path, **kwargs):
        self.calls.append(("approve_mount", mount_path, kwargs))
        return {"approved": True, "path": mount_path}

    async def reject_mount(self, mount_path, **kwargs):
        self.calls.append(("reject_mount", mount_path, kwargs))
        return {"rejected": True, "path": mount_path}


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


def test_cli_fs_mount_source_calls_vfs_mount(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke([
        "--json",
        "fs",
        "mount",
        "--source",
        "alice.agentid.pub:/group-data/g",
        "--readwrite",
        "--require-approval",
        "--expires",
        "123456",
        "g-team.agentid.pub:/memberdata/alice",
    ])

    assert result.exit_code == 0, result.output
    assert client.storage.calls == [
        (
            "mount",
            "alice.agentid.pub:/group-data/g",
            "/memberdata/alice",
            {"owner": "g-team.agentid.pub", "readonly": False, "expires_at": 123456, "require_approval": True},
        )
    ]
    assert json.loads(result.output)["mount_source"] == "alice.agentid.pub:/group-data/g"


def test_cli_fs_mount_rejects_source_volume_mix(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke([
        "fs",
        "mount",
        "--source",
        "alice.agentid.pub:/group-data/g",
        "--volume",
        "vol-1",
        "g-team.agentid.pub:/memberdata/alice",
    ])

    assert result.exit_code == 2
    assert client.storage.calls == []


def test_cli_fs_mount_volume_calls_vfs_mount_volume(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke([
        "--json",
        "fs",
        "mount",
        "--volume",
        "vol-1",
        "--readonly",
        "alice.agentid.pub:/mnt/vol-1",
    ])

    assert result.exit_code == 0, result.output
    assert client.storage.calls == [
        (
            "mount_volume",
            "vol-1",
            "/mnt/vol-1",
            {"owner": "alice.agentid.pub", "readonly": True, "expires_at": None, "require_approval": False},
        )
    ]
    assert json.loads(result.output)["volume_id"] == "vol-1"


def test_cli_fs_umount_calls_vfs_unmount(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke(["--json", "fs", "umount", "g-team.agentid.pub:/memberdata/alice"])

    assert result.exit_code == 0, result.output
    assert client.storage.calls == [
        ("unmount", "/memberdata/alice", {"owner": "g-team.agentid.pub"})
    ]
    assert json.loads(result.output)["removed_count"] == 1


def test_cli_fs_approve_reject_calls_vfs_review_methods(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    approved = _invoke(["--json", "fs", "approve", "g-team.agentid.pub:/memberdata/alice"])
    rejected = _invoke(["--json", "fs", "reject", "g-team.agentid.pub:/memberdata/alice"])

    assert approved.exit_code == 0, approved.output
    assert rejected.exit_code == 0, rejected.output
    assert client.storage.calls == [
        ("approve_mount", "/memberdata/alice", {"owner": "g-team.agentid.pub"}),
        ("reject_mount", "/memberdata/alice", {"owner": "g-team.agentid.pub"}),
    ]
    assert json.loads(approved.output)["approved"] is True
    assert json.loads(rejected.output)["rejected"] is True


def test_cli_fs_approve_reject_pass_request_id(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    approved = _invoke(["--json", "fs", "approve", "--request-id", "mnt_1", "g-team.agentid.pub:/memberdata/alice"])
    rejected = _invoke(["--json", "fs", "reject", "--request-id", "mnt_2", "g-team.agentid.pub:/memberdata/alice"])

    assert approved.exit_code == 0, approved.output
    assert rejected.exit_code == 0, rejected.output
    assert client.storage.calls == [
        ("approve_mount", "/memberdata/alice", {"owner": "g-team.agentid.pub", "request_id": "mnt_1"}),
        ("reject_mount", "/memberdata/alice", {"owner": "g-team.agentid.pub", "request_id": "mnt_2"}),
    ]
