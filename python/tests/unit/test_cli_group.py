import json
import asyncio
from types import SimpleNamespace


def _write_profile_config(tmp_path, monkeypatch, *, profile_name="default", aid="alice.agentid.pub", gateway="wss://gateway.example/aun", active_group="g-default.agentid.pub"):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "cli-sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "tab-group")

    from aun_cli.config import load_config, save_config

    cfg = load_config()
    cfg["default"]["profile"] = profile_name
    cfg["profiles"] = {
        profile_name: {
            "aid": aid,
            "gateway": gateway,
            "active_group": active_group,
        },
    }
    save_config(cfg)


def test_group_add_member_command_calls_rpc(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import group as group_commands
    from aun_cli.main import app

    calls = []

    class FakeClient:
        async def call(self, method, params):
            calls.append((method, params))
            return {"ok": True, "member": {"aid": params["aid"]}}

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(group_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "group",
            "add-member",
            "g-test.agentid.pub",
            "bob.agentid.pub",
            "--role",
            "admin",
            "--member-type",
            "ai",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"ok": True, "member": {"aid": "bob.agentid.pub"}}
    assert calls == [
        (
            "group.add_member",
            {
                "group_id": "g-test.agentid.pub",
                "aid": "bob.agentid.pub",
                "role": "admin",
                "member_type": "ai",
            },
        )
    ]


def test_group_members_uses_active_group(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import group as group_commands
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch, active_group="g-team.agentid.pub")

    calls = []

    class FakeClient:
        async def call(self, method, params):
            calls.append((method, params))
            return {"members": [{"aid": "bob.agentid.pub", "role": "member"}]}

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(group_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(app, ["--json", "group", "members"])

    assert result.exit_code == 0, result.output
    assert calls == [("group.get_members", {"group_id": "g-team.agentid.pub"})]


def test_group_send_uses_active_group_when_group_id_omitted(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import group as group_commands
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch, active_group="g-team.agentid.pub")

    calls = []

    class FakeClient:
        async def call(self, method, params):
            calls.append((method, params))
            return {"message_id": "m-1"}

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(group_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(app, ["--json", "group", "send", "hello"])

    assert result.exit_code == 0, result.output
    assert calls == [
        (
            "group.send",
            {
                "group_id": "g-team.agentid.pub",
                "payload": {"text": "hello"},
                "encrypt": True,
            },
        )
    ]


def test_group_kick_uses_active_group_when_group_id_omitted(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import group as group_commands
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch, active_group="g-team.agentid.pub")

    calls = []

    class FakeClient:
        async def call(self, method, params):
            calls.append((method, params))
            return {"ok": True}

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(group_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(app, ["--json", "group", "kick", "bob.agentid.pub"])

    assert result.exit_code == 0, result.output
    assert calls == [
        (
            "group.kick",
            {
                "group_id": "g-team.agentid.pub",
                "aid": "bob.agentid.pub",
            },
        )
    ]


def test_group_create_sets_active_group_from_nested_response(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import group as group_commands
    from aun_cli.config import load_config
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch, active_group="g-old.agentid.pub")

    class FakeClient:
        async def call(self, method, params):
            return {"group": {"group_id": "g-created.agentid.pub", "name": params["name"]}}

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(group_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(app, ["--json", "group", "create", "demo-group"])

    assert result.exit_code == 0, result.output
    cfg = load_config()
    assert cfg["profiles"]["default"]["active_group"] == "g-created.agentid.pub"


def test_group_list_calls_list_my_and_reads_items(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import group as group_commands
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch)
    calls = []

    class FakeClient:
        async def call(self, method, params):
            calls.append((method, params))
            return {
                "items": [
                    {
                        "group_id": "group.agentid.pub/11455",
                        "name": "demo",
                        "member_count": 1,
                        "role": "owner",
                    }
                ]
            }

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(group_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(app, ["--json", "group", "list"])

    assert result.exit_code == 0, result.output
    assert calls == [("group.list_my", {})]
    data = json.loads(result.output)
    assert data[0]["group_id"] == "group.agentid.pub/11455"


def test_group_info_displays_service_core_fields(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import group as group_commands
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch, active_group="group.agentid.pub/11455")
    calls = []

    class FakeClient:
        async def call(self, method, params):
            calls.append((method, params))
            return {
                "group_id": "group.agentid.pub/11455",
                "name": "yayi-test",
                "owner_aid": "yayi2000.agentid.pub",
                "visibility": "private",
                "status": "active",
                "description": "demo group",
                "member_count": 2,
                "message_seq": 7,
                "event_seq": 3,
                "state_version": 4,
                "state_hash": "state-hash-4",
                "key_epoch": 1,
                "created_at": 1779410000000,
                "updated_at": 1779410001000,
            }

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(group_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(app, ["group", "info"])

    assert result.exit_code == 0, result.output
    assert calls == [("group.info", {"group_id": "group.agentid.pub/11455"})]
    assert "Owner AID" in result.output
    assert "yayi2000.agentid.pub" in result.output
    assert "State Version" in result.output
    assert "  4" in result.output
    assert "Key Epoch" in result.output
    assert "  1" in result.output
    assert "State Hash" in result.output
    assert "Visibility" in result.output
    assert "Message Seq" in result.output
    assert "Event Seq" in result.output


def test_cli_prints_rpc_summary_on_exit(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch, aid="")

    class FakeTransport:
        async def call(self, method, params=None, *args, **kwargs):
            return {"groups": []}

    class FakeAuth:
        async def _short_rpc(self, gateway_url, method, params):
            return {}

    class FakeAUNClient:
        def __init__(self, config=None, debug=False):
            self._transport = FakeTransport()
            self._auth = FakeAuth()

        async def call(self, method, params=None, **kwargs):
            return await self._transport.call(method, params, **kwargs)

        async def close(self):
            return None

    import aun_core

    monkeypatch.setattr(aun_core, "AUNClient", FakeAUNClient)

    result = CliRunner().invoke(app, ["group", "list"])

    assert result.exit_code == 0, result.output
    assert "RPC summary: count=1" in result.output
    assert "group.list_my" in result.output
    assert "total=" in result.output
    assert "ms ok" in result.output


def test_rpc_summary_marks_background_and_prints_error_detail(capsys):
    from aun_cli.adapter import finish_cli_invocation, record_rpc_call, start_cli_invocation

    start_cli_invocation(json_mode=False)
    record_rpc_call("main.rpc", 3, "ok")
    record_rpc_call("bg.rpc", 5, "error", "boom", origin="background")
    finish_cli_invocation()

    output = capsys.readouterr().err
    assert "RPC summary: count=2" in output
    assert "1. main.rpc 3ms ok" in output
    assert "2. [bg] bg.rpc 5ms error" in output
    assert "error: boom" in output


def test_rpc_summary_skips_background_transport_closed_during_shutdown(capsys):
    from aun_cli.adapter import CLISession, finish_cli_invocation, start_cli_invocation

    async def _run():
        session = object.__new__(CLISession)
        session._foreground_task = asyncio.current_task()
        session._client = SimpleNamespace(is_closing=True)

        async def failing_rpc():
            raise ConnectionError("transport closed")

        async def background_call():
            try:
                await session._record_rpc_timing("group.v2.get_proposal", failing_rpc)
            except ConnectionError:
                pass

        await asyncio.create_task(background_call())

    start_cli_invocation(json_mode=False)
    asyncio.run(_run())
    finish_cli_invocation()

    output = capsys.readouterr().err
    assert "RPC summary" not in output
    assert "group.v2.get_proposal" not in output


def test_group_add_member_underscore_alias_calls_rpc(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import group as group_commands
    from aun_cli.main import app

    calls = []

    class FakeClient:
        async def call(self, method, params):
            calls.append((method, params))
            return {"ok": True}

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(group_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(
        app,
        ["--json", "group", "add_member", "g-test.agentid.pub", "bob.agentid.pub"],
    )

    assert result.exit_code == 0, result.output
    assert calls == [
        (
            "group.add_member",
            {
                "group_id": "g-test.agentid.pub",
                "aid": "bob.agentid.pub",
                "role": "member",
                "member_type": "human",
            },
        )
    ]
