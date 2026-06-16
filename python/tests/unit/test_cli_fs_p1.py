import inspect
import json
from pathlib import Path

from typer.testing import CliRunner


class _FakeStorage:
    def __init__(self):
        self.calls = []

    async def list(self, path, **kwargs):
        self.calls.append(("list", path, kwargs))
        return [{"type": "file", "path": path + "/a.txt", "name": "a.txt", "owner": kwargs.get("owner"), "size": 3}]

    async def upload_file(self, local_path, remote_path, **kwargs):
        self.calls.append(("upload_file", local_path, remote_path, kwargs))
        return {"type": "file", "path": remote_path, "name": Path(remote_path).name, "owner": kwargs.get("owner"), "size": Path(local_path).stat().st_size}

    async def download_file(self, remote_path, local_path, **kwargs):
        self.calls.append(("download_file", remote_path, local_path, kwargs))
        Path(local_path).write_bytes(b"downloaded")
        return {"path": remote_path, "local_path": local_path, "size": 10, "sha256": "", "verified": True}

    async def remove(self, path, **kwargs):
        self.calls.append(("remove", path, kwargs))
        return {"path": path, "removed_count": 2}

    async def rename(self, src, dst, **kwargs):
        self.calls.append(("rename", src, dst, kwargs))
        return {"type": "file", "path": dst, "name": Path(dst).name, "owner": kwargs.get("owner")}

    async def copy(self, src, dst, **kwargs):
        self.calls.append(("copy", src, dst, kwargs))
        return {"type": "file", "path": dst, "name": Path(dst).name, "owner": kwargs.get("dst_owner") or kwargs.get("owner")}

    async def mkdir(self, path, **kwargs):
        self.calls.append(("mkdir", path, kwargs))
        return {"type": "dir", "path": path, "name": Path(path).name, "owner": kwargs.get("owner")}

    async def lstat(self, path, **kwargs):
        self.calls.append(("lstat", path, kwargs))
        return {"type": "file", "path": path, "name": Path(path).name, "owner": kwargs.get("owner"), "size": 3}

    async def stat(self, path, **kwargs):
        self.calls.append(("stat", path, kwargs))
        return {"type": "file", "path": path, "name": Path(path).name, "owner": kwargs.get("owner"), "size": 3, "content_type": "text/plain"}

    async def read_bytes(self, path, **kwargs):
        self.calls.append(("read_bytes", path, kwargs))
        return b"hello"

    async def get_usage(self, **kwargs):
        self.calls.append(("get_usage", kwargs))
        return {"owner": kwargs.get("owner"), "quota_bytes": 100, "used_bytes": 40, "avail_bytes": 60, "object_count": 2}

    async def df(self, **kwargs):
        self.calls.append(("df", kwargs))
        return {"owner": kwargs.get("owner"), "quota_bytes": 100, "used_bytes": 40, "avail_bytes": 60, "object_count": 2}


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


def test_cli_fs_ls_calls_vfs_list(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke(["--json", "fs", "ls", "alice.agentid.pub:/docs", "-l"])

    assert result.exit_code == 0, result.output
    assert client.storage.calls == [("list", "/docs", {"owner": "alice.agentid.pub", "page": 1, "size": 100, "marker": None, "long": True})]
    payload = json.loads(result.output)
    assert payload[0]["path"] == "/docs/a.txt"


def test_cli_fs_cp_upload_and_download(monkeypatch, tmp_path):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)
    src = tmp_path / "hello.txt"
    src.write_text("hello", encoding="utf-8")
    out = tmp_path / "out.txt"

    up = _invoke(["--json", "fs", "cp", str(src), "alice.agentid.pub:/docs/hello.txt"])
    down = _invoke(["--json", "fs", "cp", "alice.agentid.pub:/docs/hello.txt", str(out)])

    assert up.exit_code == 0, up.output
    assert down.exit_code == 0, down.output
    assert out.read_bytes() == b"downloaded"
    assert client.storage.calls[0][0] == "upload_file"
    assert client.storage.calls[0][2] == "/docs/hello.txt"
    assert client.storage.calls[1][0] == "download_file"
    assert client.storage.calls[1][3]["overwrite"] is False


def test_cli_fs_cp_upload_overwrite_follows_force(monkeypatch, tmp_path):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)
    src = tmp_path / "hello.txt"
    src.write_text("hello", encoding="utf-8")

    default_result = _invoke(["--json", "fs", "cp", str(src), "alice.agentid.pub:/docs/hello.txt"])
    forced_result = _invoke(["--json", "fs", "cp", "--force", str(src), "alice.agentid.pub:/docs/hello.txt"])

    assert default_result.exit_code == 0, default_result.output
    assert forced_result.exit_code == 0, forced_result.output
    assert client.storage.calls[0][3]["overwrite"] is False
    assert client.storage.calls[1][3]["overwrite"] is True


def test_cli_fs_cp_download_overwrite_follows_force(monkeypatch, tmp_path):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)
    out = tmp_path / "out.txt"

    default_result = _invoke(["--json", "fs", "cp", "alice.agentid.pub:/docs/hello.txt", str(out)])
    forced_result = _invoke(["--json", "fs", "cp", "--force", "alice.agentid.pub:/docs/hello.txt", str(out)])

    assert default_result.exit_code == 0, default_result.output
    assert forced_result.exit_code == 0, forced_result.output
    assert client.storage.calls[0][0] == "download_file"
    assert client.storage.calls[0][3]["overwrite"] is False
    assert client.storage.calls[1][0] == "download_file"
    assert client.storage.calls[1][3]["overwrite"] is True


def test_cli_fs_cp_remote_cross_owner_calls_vfs_copy(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke([
        "--json",
        "fs",
        "cp",
        "alice.agentid.pub:/docs/a.txt",
        "bob.agentid.pub:/inbox/a.txt",
    ])

    assert result.exit_code == 0, result.output
    assert client.storage.calls == [
        ("copy", "/docs/a.txt", "/inbox/a.txt", {"owner": "alice.agentid.pub", "dst_owner": "bob.agentid.pub", "overwrite": False, "recursive": False})
    ]


def test_cli_fs_cp_remote_recursive_passes_recursive(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    result = _invoke([
        "--json",
        "fs",
        "cp",
        "-r",
        "alice.agentid.pub:/docs",
        "bob.agentid.pub:/inbox/docs",
    ])

    assert result.exit_code == 0, result.output
    assert client.storage.calls == [
        ("copy", "/docs", "/inbox/docs", {"owner": "alice.agentid.pub", "dst_owner": "bob.agentid.pub", "overwrite": False, "recursive": True})
    ]


def test_cli_fs_rm_recursive_and_mkdir(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    rm = _invoke(["--json", "fs", "rm", "-r", "alice.agentid.pub:/tmp"])
    mkdir = _invoke(["--json", "fs", "mkdir", "-p", "alice.agentid.pub:/tmp/new"])

    assert rm.exit_code == 0, rm.output
    assert mkdir.exit_code == 0, mkdir.output
    assert client.storage.calls[0] == ("remove", "/tmp", {"owner": "alice.agentid.pub", "recursive": True})
    assert client.storage.calls[1] == ("mkdir", "/tmp/new", {"owner": "alice.agentid.pub", "parents": True})


def test_cli_fs_bare_paths_default_to_profile_aid(monkeypatch, tmp_path):
    from aun_cli.commands import fs as fs_commands
    from aun_cli.config import load_config, save_config

    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "fs-default-owner")
    cfg = load_config()
    cfg["default"]["profile"] = "default"
    cfg["profiles"] = {"default": {"aid": "yayi2001.agentid.pub"}}
    save_config(cfg)

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    mkdir = _invoke(["--json", "fs", "mkdir", "docs"])
    listed = _invoke(["--json", "fs", "ls", "/docs"])

    assert mkdir.exit_code == 0, mkdir.output
    assert listed.exit_code == 0, listed.output
    assert client.storage.calls == [
        ("mkdir", "/docs", {"owner": "yayi2001.agentid.pub", "parents": False}),
        ("list", "/docs", {"owner": "yayi2001.agentid.pub", "page": 1, "size": 100, "marker": None, "long": False}),
    ]


def test_cli_fs_cp_bare_remote_upload_and_download(monkeypatch, tmp_path):
    from aun_cli.commands import fs as fs_commands
    from aun_cli.config import load_config, save_config

    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "fs-cp-default-owner")
    cfg = load_config()
    cfg["default"]["profile"] = "default"
    cfg["profiles"] = {"default": {"aid": "yayi2001.agentid.pub"}}
    save_config(cfg)

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)
    src = tmp_path / "hello.txt"
    src.write_text("hello", encoding="utf-8")
    out = tmp_path / "out.txt"

    up = _invoke(["--json", "fs", "cp", str(src), "docs/hello.txt"])
    down = _invoke(["--json", "fs", "cp", "docs/hello.txt", str(out)])

    assert up.exit_code == 0, up.output
    assert down.exit_code == 0, down.output
    assert client.storage.calls[0][0] == "upload_file"
    assert client.storage.calls[0][2] == "/docs/hello.txt"
    assert client.storage.calls[0][3]["owner"] == "yayi2001.agentid.pub"
    assert client.storage.calls[1][0] == "download_file"
    assert client.storage.calls[1][1] == "/docs/hello.txt"
    assert client.storage.calls[1][3]["owner"] == "yayi2001.agentid.pub"


def test_cli_fs_stat_cat_df(monkeypatch):
    from aun_cli.commands import fs as fs_commands

    client = _FakeClient()
    _install_fake_session(monkeypatch, fs_commands, client)

    stat = _invoke(["--json", "fs", "stat", "alice.agentid.pub:/docs/a.txt"])
    cat = _invoke(["--json", "fs", "cat", "alice.agentid.pub:/docs/a.txt"])
    df = _invoke(["--json", "fs", "df", "alice.agentid.pub:"])

    assert stat.exit_code == 0, stat.output
    assert cat.exit_code == 0, cat.output
    assert df.exit_code == 0, df.output
    assert json.loads(cat.output)["content"] == "hello"
    assert json.loads(df.output)["avail_bytes"] == 60
    assert [call[0] for call in client.storage.calls] == ["lstat", "stat", "read_bytes", "df"]


def test_cli_fs_command_layer_has_no_storage_rpc_direct_call():
    from aun_cli.commands import fs as fs_commands

    source_path = inspect.getsourcefile(fs_commands)
    assert source_path is not None
    source = Path(source_path).read_text(encoding="utf-8")
    assert "client.call" not in source
    assert '"storage.' not in source


def test_cli_debug_output_does_not_pollute_stdout(capsys):
    from aun_cli.adapter import _print_debug

    _print_debug("[DEBUG][cli] sample")

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "[DEBUG][cli] sample" in captured.err
