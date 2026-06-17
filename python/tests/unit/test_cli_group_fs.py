import json
from types import SimpleNamespace

from typer.testing import CliRunner


class _FakeGroupFS:
    def __init__(self):
        self.calls = []

    async def ls(self, path, **kwargs):
        self.calls.append(("ls", path, kwargs))
        return {"items": [{"type": "file", "name": "a.md", "path": f"{path.rstrip('/')}/a.md"}]}

    async def find(self, path, **kwargs):
        self.calls.append(("find", path, kwargs))
        return [{"type": "file", "name": "a.md", "path": f"{path.rstrip('/')}/a.md"}]

    async def stat(self, path, **kwargs):
        self.calls.append(("stat", path, kwargs))
        return {"type": "file", "path": path, "name": path.rsplit("/", 1)[-1]}

    async def lstat(self, path, **kwargs):
        self.calls.append(("lstat", path, kwargs))
        return {"type": "symlink", "path": path, "name": path.rsplit("/", 1)[-1]}

    async def mkdir(self, path, **kwargs):
        self.calls.append(("mkdir", path, kwargs))
        return {"type": "dir", "path": path}

    async def rm(self, path, **kwargs):
        self.calls.append(("rm", path, kwargs))
        return {"path": path, "removed_count": 1}

    async def cp(self, src, dst, **kwargs):
        self.calls.append(("cp", src, dst, kwargs))
        return {"type": "file", "path": dst}

    async def mv(self, src, dst, **kwargs):
        self.calls.append(("mv", src, dst, kwargs))
        return {"type": "file", "path": dst}

    async def df(self, path_or_group=None, **kwargs):
        self.calls.append(("df", path_or_group, kwargs))
        return {"quota_bytes": 100, "used_bytes": 3}

    async def mount(self, path, **kwargs):
        self.calls.append(("mount", path, kwargs))
        return {"type": "mount", "path": path}

    async def umount(self, path, **kwargs):
        self.calls.append(("umount", path, kwargs))
        return {"unmounted": True, "path": path}


class _FakeClient:
    def __init__(self):
        self.group_fs = _FakeGroupFS()
        self.group = SimpleNamespace(fs=self.group_fs)
        self.session_kwargs = []


def _write_profile_config(tmp_path, monkeypatch, *, active_group="group.agentid.pub/team"):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "group-fs")

    from aun_cli.config import load_config, save_config

    cfg = load_config()
    cfg["default"]["profile"] = "default"
    cfg["profiles"] = {
        "default": {
            "aid": "alice.agentid.pub",
            "gateway": "wss://gateway.example/aun",
            "active_group": active_group,
        }
    }
    save_config(cfg)


def _install_fake_session(monkeypatch, client):
    from aun_cli.commands import group as group_commands

    class _FakeSession:
        def __init__(self, ctx, **kwargs):
            self.kwargs = kwargs
            client.session_kwargs.append(kwargs)

        async def __aenter__(self):
            return client

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(group_commands, "CLISession", _FakeSession)
    return group_commands


def _invoke(args):
    from aun_cli.main import app

    return CliRunner().invoke(app, args)


def test_cli_group_fs_ls_uses_active_group_for_bare_path(monkeypatch, tmp_path):
    _write_profile_config(tmp_path, monkeypatch, active_group="group.agentid.pub/team")
    client = _FakeClient()
    _install_fake_session(monkeypatch, client)

    result = _invoke(["--json", "group", "fs", "ls", "/docs", "--page", "2", "--size", "5"])

    assert result.exit_code == 0, result.output
    assert client.group_fs.calls == [
        ("ls", "/docs", {"group_id": "group.agentid.pub/team", "page": 2, "size": 5, "long": False})
    ]
    assert json.loads(result.output)["items"][0]["name"] == "a.md"


def test_cli_group_fs_stat_keeps_explicit_group_uri(monkeypatch, tmp_path):
    _write_profile_config(tmp_path, monkeypatch)
    client = _FakeClient()
    _install_fake_session(monkeypatch, client)

    result = _invoke(["--json", "group", "fs", "stat", "team.agentid.pub:/docs/a.md"])

    assert result.exit_code == 0, result.output
    assert client.group_fs.calls == [("stat", "team.agentid.pub:/docs/a.md", {})]


def test_cli_group_fs_cp_local_to_active_group_when_source_exists(monkeypatch, tmp_path):
    _write_profile_config(tmp_path, monkeypatch, active_group="group.agentid.pub/team")
    local = tmp_path / "a.md"
    local.write_text("hello", encoding="utf-8")
    client = _FakeClient()
    _install_fake_session(monkeypatch, client)

    result = _invoke(["--json", "group", "fs", "cp", str(local), "docs/a.md", "--force"])

    assert result.exit_code == 0, result.output
    assert client.group_fs.calls == [
        (
            "cp",
            str(local),
            "/docs/a.md",
            {
                "dst_group_id": "group.agentid.pub/team",
                "force": True,
                "recursive": False,
                "parents": True,
                "content_type": None,
            },
        )
    ]


def test_cli_group_fs_write_can_sign_as_group_aid(monkeypatch, tmp_path):
    _write_profile_config(tmp_path, monkeypatch, active_group="group.agentid.pub/team")
    client = _FakeClient()
    _install_fake_session(monkeypatch, client)

    result = _invoke([
        "--json",
        "group",
        "fs",
        "mkdir",
        "--parents",
        "team.agentid.pub:/announce",
        "--as",
        "team.agentid.pub",
    ])

    assert result.exit_code == 0, result.output
    assert client.session_kwargs[-1].get("aid") is None
    assert client.group_fs.calls == [
        ("mkdir", "team.agentid.pub:/announce", {"parents": True, "sign_as": "team.agentid.pub"})
    ]


def test_cli_group_fs_cp_windows_drive_is_local(monkeypatch, tmp_path):
    _write_profile_config(tmp_path, monkeypatch, active_group="group.agentid.pub/team")
    client = _FakeClient()
    _install_fake_session(monkeypatch, client)

    result = _invoke(["--json", "group", "fs", "cp", "D:/tmp/a.md", "team.agentid.pub:/docs/a.md"])

    assert result.exit_code == 0, result.output
    assert client.group_fs.calls == [
        (
            "cp",
            "D:/tmp/a.md",
            "team.agentid.pub:/docs/a.md",
            {"force": False, "recursive": False, "parents": True, "content_type": None},
        )
    ]


def test_cli_group_fs_cp_active_group_to_local_when_destination_explicit_local(monkeypatch, tmp_path):
    _write_profile_config(tmp_path, monkeypatch, active_group="group.agentid.pub/team")
    target = tmp_path / "out.md"
    client = _FakeClient()
    _install_fake_session(monkeypatch, client)

    result = _invoke(["--json", "group", "fs", "cp", "docs/a.md", f"local:{target}"])

    assert result.exit_code == 0, result.output
    assert client.group_fs.calls == [
        (
            "cp",
            "/docs/a.md",
            str(target),
            {
                "src_group_id": "group.agentid.pub/team",
                "force": False,
                "recursive": False,
                "parents": True,
                "content_type": None,
            },
        )
    ]


def test_cli_group_fs_cp_explicit_group_to_posix_local_prefix(monkeypatch, tmp_path):
    _write_profile_config(tmp_path, monkeypatch, active_group="group.agentid.pub/team")
    client = _FakeClient()
    _install_fake_session(monkeypatch, client)

    result = _invoke(["--json", "group", "fs", "cp", "team.agentid.pub:/docs/a.md", "local:/tmp/out.md"])

    assert result.exit_code == 0, result.output
    assert client.group_fs.calls == [
        (
            "cp",
            "team.agentid.pub:/docs/a.md",
            "/tmp/out.md",
            {"force": False, "recursive": False, "parents": True, "content_type": None},
        )
    ]


def test_cli_group_fs_cp_bare_to_bare_defaults_group_to_group_when_source_missing(monkeypatch, tmp_path):
    _write_profile_config(tmp_path, monkeypatch, active_group="group.agentid.pub/team")
    client = _FakeClient()
    _install_fake_session(monkeypatch, client)

    result = _invoke(["--json", "group", "fs", "cp", "docs/a.md", "archive/a.md", "-r"])

    assert result.exit_code == 0, result.output
    assert client.group_fs.calls == [
        (
            "cp",
            "/docs/a.md",
            "/archive/a.md",
            {
                "src_group_id": "group.agentid.pub/team",
                "dst_group_id": "group.agentid.pub/team",
                "force": False,
                "recursive": True,
                "parents": True,
                "content_type": None,
            },
        )
    ]


def test_cli_group_fs_mv_rejects_local_path(monkeypatch, tmp_path):
    _write_profile_config(tmp_path, monkeypatch, active_group="group.agentid.pub/team")
    client = _FakeClient()
    _install_fake_session(monkeypatch, client)

    result = _invoke(["--json", "group", "fs", "mv", "D:/tmp/a.md", "docs/a.md"])

    assert result.exit_code == 2
    assert client.group_fs.calls == []


def test_cli_group_fs_mv_bare_paths_use_active_group(monkeypatch, tmp_path):
    _write_profile_config(tmp_path, monkeypatch, active_group="group.agentid.pub/team")
    client = _FakeClient()
    _install_fake_session(monkeypatch, client)

    result = _invoke(["--json", "group", "fs", "mv", "docs/a.md", "archive/a.md", "--force"])

    assert result.exit_code == 0, result.output
    assert client.group_fs.calls == [
        (
            "mv",
            "/docs/a.md",
            "/archive/a.md",
            {"group_id": "group.agentid.pub/team", "force": True},
        )
    ]


def test_cli_group_fs_mount_and_umount_use_active_group(monkeypatch, tmp_path):
    _write_profile_config(tmp_path, monkeypatch, active_group="group.agentid.pub/team")
    client = _FakeClient()
    _install_fake_session(monkeypatch, client)

    mount = _invoke(["--json", "group", "fs", "mount", "memberdata/alice.agentid.pub", "--readwrite"])
    umount = _invoke(["--json", "group", "fs", "umount", "memberdata/alice.agentid.pub"])

    assert mount.exit_code == 0, mount.output
    assert umount.exit_code == 0, umount.output
    assert client.group_fs.calls == [
        ("mount", "/memberdata/alice.agentid.pub", {"group_id": "group.agentid.pub/team", "readonly": False}),
        ("umount", "/memberdata/alice.agentid.pub", {"group_id": "group.agentid.pub/team"}),
    ]
