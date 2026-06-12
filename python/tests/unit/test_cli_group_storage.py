import json
from pathlib import Path

from typer.testing import CliRunner


class _FakeStore:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _FakeResources:
    def __init__(self):
        self.calls = []
        self.pending_result = {
            "mode": "pending_ops",
            "group_id": "group.agentid.pub/team",
            "group_aid": "team.agentid.pub",
            "op_id": "op-put",
            "confirm_rpc": "group.resources.confirm",
            "confirm_params": {"group_id": "group.agentid.pub/team", "resource_path": "announce/a.txt"},
            "pending_ops": [],
        }

    async def initialize_namespace(self, **kwargs):
        self.calls.append(("initialize_namespace", kwargs))
        return {"namespace_ready": True, "group_id": kwargs.get("group_id"), "group_aid": kwargs.get("group_aid")}

    async def list(self, **kwargs):
        self.calls.append(("list", kwargs))
        return {"items": [{"resource_path": "announce/a.txt", "resource_type": "file"}]}

    async def get(self, **kwargs):
        self.calls.append(("get", kwargs))
        return {"resource": {"resource_path": kwargs.get("resource_path"), "resource_type": "file"}}

    async def get_df(self, **kwargs):
        self.calls.append(("get_df", kwargs))
        return {"group_id": kwargs.get("group_id"), "quota_bytes": 100, "used_bytes": 40}

    async def put(self, **kwargs):
        self.calls.append(("put", kwargs))
        return self.pending_result

    async def create_folder(self, **kwargs):
        self.calls.append(("create_folder", kwargs))
        return self.pending_result

    async def delete(self, **kwargs):
        self.calls.append(("delete", kwargs))
        return self.pending_result

    async def delete_memberdata_direct(self, **kwargs):
        self.calls.append(("delete", kwargs))
        return {"removed_count": 1, "deleted": True}

    async def rename(self, **kwargs):
        self.calls.append(("rename", kwargs))
        return self.pending_result

    async def move(self, **kwargs):
        self.calls.append(("move", kwargs))
        return self.pending_result

    async def mount_object(self, **kwargs):
        self.calls.append(("mount_object", kwargs))
        return self.pending_result

    async def unmount(self, **kwargs):
        self.calls.append(("unmount", kwargs))
        return {"unmounted": True, "mount_path": kwargs.get("mount_path")}

    async def get_access(self, **kwargs):
        self.calls.append(("get_access", kwargs))
        return {
            "group_id": kwargs.get("group_id"),
            "resource_path": kwargs.get("resource_path"),
            "download": {
                "download_url": "https://storage.agentid.pub/dl/grp",
                "file_name": "a.txt",
                "size_bytes": 5,
                "content_type": "text/plain",
            },
        }

    async def execute_pending_ops(self, pending, **kwargs):
        self.calls.append(("execute_pending_ops", pending, kwargs))
        return {"confirmed": {"resource": {"resource_path": "announce/a.txt"}}, "storage_results": {}}


class _FakeGroup:
    def __init__(self, resources):
        self.resources = resources
        self.calls = []

    async def set_role(self, **kwargs):
        self.calls.append(("set_role", kwargs))
        return self.resources.pending_result


class _FakeClient:
    def __init__(self):
        self.calls = []
        self.resources = _FakeResources()
        self.group = _FakeGroup(self.resources)

    async def call(self, method, params=None):
        payload = params or {}
        self.calls.append(("call", method, payload))
        if method == "group.info":
            return {"group": {"group_id": payload.get("group_id"), "group_aid": ""}}
        return {"method": method, **payload}

    async def create_group(self, params=None, **kwargs):
        payload = dict(params or {})
        payload.update(kwargs)
        payload["aid_store"] = kwargs.get("aid_store")
        self.calls.append(("create_group", payload))
        return {
            "group": {
                "group_id": "group.agentid.pub/team",
                "group_aid": "team.agentid.pub",
                "name": payload.get("name"),
            }
        }

    async def bind_group_aid(self, params=None, **kwargs):
        payload = dict(params or {})
        payload.update(kwargs)
        payload["aid_store"] = kwargs.get("aid_store")
        self.calls.append(("bind_group_aid", payload))
        return {"group": {"group_id": payload.get("group_id"), "group_aid": "team.agentid.pub"}}

    async def start_group_transfer(self, params=None, **kwargs):
        payload = dict(params or {})
        payload.update(kwargs)
        payload["aid_store"] = kwargs.get("aid_store")
        self.calls.append(("start_group_transfer", payload))
        return {"status": "pending_rekey", "group_id": payload.get("group_id"), "new_owner": payload.get("new_owner")}

    async def complete_group_transfer(self, params=None, **kwargs):
        payload = dict(params or {})
        payload.update(kwargs)
        payload["aid_store"] = kwargs.get("aid_store")
        self.calls.append(("complete_group_transfer", payload))
        return {"status": "transferred", "group": {"group_id": payload.get("group_id"), "group_aid": "team.agentid.pub"}}


def _install_fake_group_session(monkeypatch, group_commands, client, store=None):
    class _FakeSession:
        def __init__(self, ctx, **kwargs):
            self.kwargs = kwargs

        async def __aenter__(self):
            return client

        async def __aexit__(self, exc_type, exc, tb):
            return False

    fake_store = store or _FakeStore()
    monkeypatch.setattr(group_commands, "CLISession", _FakeSession)
    monkeypatch.setattr(group_commands, "make_aid_store", lambda resolved: fake_store)
    return fake_store


def _invoke(args):
    from aun_cli.main import app

    return CliRunner().invoke(app, args)


def test_cli_group_create_named_uses_high_level_identity_flow(monkeypatch):
    from aun_cli.commands import group as group_commands

    client = _FakeClient()
    store = _install_fake_group_session(monkeypatch, group_commands, client)

    result = _invoke(["--json", "group", "create", "Team", "--group-name", "team", "--members", "bob.agentid.pub"])

    assert result.exit_code == 0, result.output
    assert client.calls[0][0] == "create_group"
    assert client.calls[0][1]["name"] == "Team"
    assert client.calls[0][1]["group_name"] == "team"
    assert client.calls[0][1]["members"] == ["bob.agentid.pub"]
    assert client.calls[0][1]["aid_store"] is store
    assert store.closed is True
    assert json.loads(result.output)["group"]["group_aid"] == "team.agentid.pub"


def test_cli_group_bind_and_transfer_flows_use_group_storage_contract(monkeypatch):
    from aun_cli.commands import group as group_commands

    client = _FakeClient()
    store = _install_fake_group_session(monkeypatch, group_commands, client)

    bind = _invoke(["--json", "group", "bind", "group.agentid.pub/team"])
    transfer = _invoke(["--json", "group", "transfer", "group.agentid.pub/team", "alice.agentid.pub"])
    complete = _invoke(["--json", "group", "complete-transfer", "group.agentid.pub/team"])

    assert bind.exit_code == 0, bind.output
    assert transfer.exit_code == 0, transfer.output
    assert complete.exit_code == 0, complete.output
    assert client.calls[0] == (
        "call",
        "group.info",
        {"group_id": "group.agentid.pub/team"},
    )
    assert client.calls[1][0] == "bind_group_aid"
    assert client.calls[1][1]["group_id"] == "group.agentid.pub/team"
    assert client.calls[1][1]["aid_store"] is store
    assert client.calls[2][0] == "start_group_transfer"
    assert client.calls[2][1]["group_id"] == "group.agentid.pub/team"
    assert client.calls[2][1]["new_owner"] == "alice.agentid.pub"
    assert client.calls[2][1]["aid_store"] is store
    assert client.calls[3][0] == "complete_group_transfer"
    assert client.calls[3][1]["group_id"] == "group.agentid.pub/team"
    assert client.calls[3][1]["aid_store"] is store


def test_cli_group_resources_commands_use_facade_and_pending_executor(monkeypatch, tmp_path):
    from aun_cli.commands import group as group_commands

    client = _FakeClient()
    store = _install_fake_group_session(monkeypatch, group_commands, client)
    local_file = tmp_path / "a.txt"
    local_file.write_text("hello", encoding="utf-8")

    init = _invoke(["--json", "group", "resources", "init", "group.agentid.pub/team", "--group-aid", "team.agentid.pub"])
    ls = _invoke(["--json", "group", "resources", "ls", "group.agentid.pub/team", "announce"])
    put = _invoke([
        "--json",
        "group",
        "resources",
        "put",
        "group.agentid.pub/team",
        str(local_file),
        "announce/a.txt",
        "--content-type",
        "text/plain",
    ])
    get = _invoke(["--json", "group", "resources", "get", "group.agentid.pub/team", "announce/a.txt"])
    df = _invoke(["--json", "group", "resources", "df", "group.agentid.pub/team"])

    for result in [init, ls, put, get, df]:
        assert result.exit_code == 0, result.output

    assert client.resources.calls == [
        ("initialize_namespace", {"group_id": "group.agentid.pub/team", "group_aid": "team.agentid.pub", "aid_store": store}),
        ("list", {"group_id": "group.agentid.pub/team", "prefix": "announce", "page": 1, "size": 100, "include_status": False}),
        (
            "put",
                {
                    "group_id": "group.agentid.pub/team",
                    "resource_path": "announce/a.txt",
                    "content": "aGVsbG8=",
                    "content_encoding": "base64",
                    "content_type": "text/plain",
                    "size_bytes": 5,
                    "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                },
            ),
        ("execute_pending_ops", client.resources.pending_result, {"aid_store": store, "sign_as": "team.agentid.pub"}),
        ("get", {"group_id": "group.agentid.pub/team", "resource_path": "announce/a.txt", "include_status": False}),
        ("get_df", {"group_id": "group.agentid.pub/team"}),
    ]
    assert store.closed is True
    assert json.loads(put.output)["confirmed"]["resource"]["resource_path"] == "announce/a.txt"


def test_cli_group_resources_defaults_to_active_group(monkeypatch, tmp_path):
    from aun_cli.commands import group as group_commands
    from aun_cli.config import load_config, save_config

    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "group-storage")
    cfg = load_config()
    cfg["default"]["profile"] = "default"
    cfg["profiles"] = {"default": {"aid": "owner.agentid.pub", "active_group": "group.agentid.pub/team"}}
    save_config(cfg)
    client = _FakeClient()
    store = _install_fake_group_session(monkeypatch, group_commands, client)

    result = _invoke(["--json", "group", "resources", "df"])

    assert result.exit_code == 0, result.output
    assert client.resources.calls == [("get_df", {"group_id": "group.agentid.pub/team"})]


def test_cli_group_resources_rm_uses_pending_executor(monkeypatch):
    from aun_cli.commands import group as group_commands

    client = _FakeClient()
    store = _install_fake_group_session(monkeypatch, group_commands, client)

    result = _invoke(["--json", "group", "resources", "rm", "group.agentid.pub/team", "announce/a.txt"])

    assert result.exit_code == 0, result.output
    assert client.resources.calls == [
        ("delete", {"group_id": "group.agentid.pub/team", "resource_path": "announce/a.txt", "recursive": False}),
        ("execute_pending_ops", client.resources.pending_result, {"aid_store": store}),
    ]
    assert store.closed is True


def test_cli_group_resources_rm_memberdata_direct_result_skips_pending_executor(monkeypatch):
    from aun_cli.commands import group as group_commands

    client = _FakeClient()
    store = _install_fake_group_session(monkeypatch, group_commands, client)

    async def _direct_delete(**kwargs):
        client.resources.calls.append(("delete", kwargs))
        return {"removed_count": 1, "deleted": True}

    client.resources.delete = _direct_delete

    result = _invoke([
        "--json", "group", "resources", "rm",
        "group.agentid.pub/team", "memberdata/alice.agentid.pub/a.txt",
    ])

    assert result.exit_code == 0, result.output
    assert client.resources.calls == [
        ("delete", {
            "group_id": "group.agentid.pub/team",
            "resource_path": "memberdata/alice.agentid.pub/a.txt",
            "recursive": False,
        }),
    ]
    assert json.loads(result.output)["deleted"] is True
    assert store.closed is False


def test_cli_group_resources_mkdir_uses_pending_executor(monkeypatch):
    from aun_cli.commands import group as group_commands

    client = _FakeClient()
    store = _install_fake_group_session(monkeypatch, group_commands, client)

    result = _invoke(["--json", "group", "resources", "mkdir", "group.agentid.pub/team", "announce/sub"])

    assert result.exit_code == 0, result.output
    assert client.resources.calls == [
        ("create_folder", {"group_id": "group.agentid.pub/team", "resource_path": "announce/sub", "resource_type": "folder"}),
        ("execute_pending_ops", client.resources.pending_result, {"aid_store": store}),
    ]
    assert store.closed is True


def test_cli_group_resources_mv_uses_pending_executor(monkeypatch):
    from aun_cli.commands import group as group_commands

    client = _FakeClient()
    store = _install_fake_group_session(monkeypatch, group_commands, client)

    result = _invoke(["--json", "group", "resources", "mv", "group.agentid.pub/team", "announce/a.txt", "archive/a.txt"])

    assert result.exit_code == 0, result.output
    assert client.resources.calls == [
        ("move", {
            "group_id": "group.agentid.pub/team",
            "resource_path": "announce/a.txt",
            "dst_parent_path": "archive",
            "new_name": "a.txt",
        }),
        ("execute_pending_ops", client.resources.pending_result, {"aid_store": store}),
    ]
    assert store.closed is True


def test_cli_group_resources_rename_uses_pending_executor(monkeypatch):
    from aun_cli.commands import group as group_commands

    client = _FakeClient()
    store = _install_fake_group_session(monkeypatch, group_commands, client)

    result = _invoke(["--json", "group", "resources", "rename", "group.agentid.pub/team", "announce/a.txt", "b.txt"])

    assert result.exit_code == 0, result.output
    assert client.resources.calls == [
        ("rename", {"group_id": "group.agentid.pub/team", "resource_path": "announce/a.txt", "new_name": "b.txt"}),
        ("execute_pending_ops", client.resources.pending_result, {"aid_store": store}),
    ]
    assert store.closed is True


def test_cli_group_resources_download_uses_get_access(monkeypatch, tmp_path):
    from aun_cli.commands import group as group_commands
    from aun_cli import storage_core

    out = tmp_path / "got.txt"
    monkeypatch.setattr(storage_core, "_http_get", lambda url, verify_ssl=True: b"GROUP-FILE-BYTES")
    client = _FakeClient()
    store = _install_fake_group_session(monkeypatch, group_commands, client)

    result = _invoke(["group", "resources", "download", "group.agentid.pub/team", "announce/a.txt", "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert client.resources.calls == [
        ("get_access", {"group_id": "group.agentid.pub/team", "resource_path": "announce/a.txt"}),
    ]
    assert out.read_bytes() == b"GROUP-FILE-BYTES"


def test_cli_group_resources_mount_uses_pending_executor(monkeypatch):
    from aun_cli.commands import group as group_commands

    client = _FakeClient()
    store = _install_fake_group_session(monkeypatch, group_commands, client)

    result = _invoke([
        "--json", "group", "resources", "mount", "group.agentid.pub/team",
        "--source-path", "group-data/team", "--member-aid", "alice.agentid.pub",
    ])

    assert result.exit_code == 0, result.output
    assert client.resources.calls == [
        ("mount_object", {
            "group_id": "group.agentid.pub/team",
            "mount_path": "memberdata/alice.agentid.pub",
            "source_aid": "alice.agentid.pub",
            "source_path": "group-data/team",
            "readonly": False,
        }),
        ("execute_pending_ops", client.resources.pending_result, {"aid_store": store}),
    ]
    assert store.closed is True


def test_cli_group_resources_umount_calls_unmount(monkeypatch):
    from aun_cli.commands import group as group_commands

    client = _FakeClient()
    store = _install_fake_group_session(monkeypatch, group_commands, client)

    result = _invoke([
        "--json", "group", "resources", "umount", "group.agentid.pub/team",
        "--member-aid", "alice.agentid.pub",
    ])

    assert result.exit_code == 0, result.output
    assert client.resources.calls == [
        ("unmount", {"group_id": "group.agentid.pub/team", "resource_path": "memberdata/alice.agentid.pub"}),
    ]


def test_cli_group_resources_acl_commands_call_set_role_directly(monkeypatch):
    from aun_cli.commands import group as group_commands

    client = _FakeClient()
    store = _install_fake_group_session(monkeypatch, group_commands, client)

    setfacl = _invoke([
        "--json", "group", "resources", "setfacl", "group.agentid.pub/team",
        "alice.agentid.pub", "--perms", "rw",
    ])
    remove_acl = _invoke([
        "--json", "group", "resources", "remove_acl", "group.agentid.pub/team",
        "alice.agentid.pub",
    ])
    adopt = _invoke([
        "--json", "group", "resources", "adopt", "group.agentid.pub/team",
        "bob.agentid.pub",
    ])

    for result in [setfacl, remove_acl, adopt]:
        assert result.exit_code == 0, result.output
    assert client.group.calls == [
        ("set_role", {"group_id": "group.agentid.pub/team", "aid": "alice.agentid.pub", "role": "admin", "perms": "rw"}),
        ("set_role", {"group_id": "group.agentid.pub/team", "aid": "alice.agentid.pub", "role": "member"}),
        ("set_role", {"group_id": "group.agentid.pub/team", "aid": "bob.agentid.pub", "role": "admin", "perms": "rwx"}),
    ]
    assert client.resources.calls == [
        ("execute_pending_ops", client.resources.pending_result, {"aid_store": store}),
        ("execute_pending_ops", client.resources.pending_result, {"aid_store": store}),
        ("execute_pending_ops", client.resources.pending_result, {"aid_store": store}),
    ]
