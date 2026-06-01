import json


def _write_profile_config(
    tmp_path,
    monkeypatch,
    *,
    profile_name="default",
    aid="alice.agentid.pub",
    gateway="wss://gateway.example/aun",
):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "cli-sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "tab-agentmd")

    from aun_cli.config import load_config, save_config

    aun_path = str(tmp_path / "aun-profile")
    cfg = load_config()
    cfg["default"]["profile"] = profile_name
    cfg["profiles"] = {
        profile_name: {
            "aid": aid,
            "gateway": gateway,
            "aun_path": aun_path,
        },
    }
    save_config(cfg)
    return cfg["profiles"][profile_name]


def test_agentmd_upload_calls_sdk_method(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import agentmd as agentmd_commands
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch)
    calls = []

    class FakeClient:
        async def upload_agent_md(self):
            calls.append("upload_agent_md")
            return {"aid": "alice.agentid.pub", "etag": '"v1"', "agent_md_url": "https://alice.agentid.pub/agent.md"}

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(agentmd_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(app, ["--json", "agentmd", "upload_agent_md"])

    assert result.exit_code == 0, result.output
    assert calls == ["upload_agent_md"]
    assert json.loads(result.output)["etag"] == '"v1"'


def test_agentmd_download_calls_sdk_method(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import agentmd as agentmd_commands
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch)
    calls = []

    class FakeStore:
        async def download_agent_md(self, aid):
            calls.append(aid)
            from aun_core import result_ok
            return result_ok({
                "aid": aid,
                "content": "# Bob\n",
                "verification": {"status": "verified"},
                "cert_pem": "cert",
            })

        def close(self):
            pass

    monkeypatch.setattr(agentmd_commands, "make_aid_store", lambda resolved: FakeStore())

    result = CliRunner().invoke(app, ["--json", "agentmd", "download", "bobb.agentid.pub"])

    assert result.exit_code == 0, result.output
    assert calls == ["bobb.agentid.pub"]
    data = json.loads(result.output)
    assert data["aid"] == "bobb.agentid.pub"
    assert data["content"] == "# Bob\n"


def test_agentmd_check_calls_sdk_method(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import agentmd as agentmd_commands
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch)
    calls = []

    class FakeStore:
        async def check_agent_md(self, aid, ttl_days=1):
            calls.append((aid, ttl_days))
            from aun_core import result_ok
            return result_ok({"aid": aid, "local_found": True, "remote_found": True, "needs_update": False})

        def close(self):
            pass

    monkeypatch.setattr(agentmd_commands, "make_aid_store", lambda resolved: FakeStore())

    result = CliRunner().invoke(
        app,
        ["--json", "agentmd", "check_agent_md", "bobb.agentid.pub", "--max-unsynced-days", "3"],
    )

    assert result.exit_code == 0, result.output
    assert calls == [("bobb.agentid.pub", 3)]
    assert json.loads(result.output)["needs_update"] is False


def test_agentmd_check_defaults_to_one_day_cache_window(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import agentmd as agentmd_commands
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch)
    calls = []

    class FakeStore:
        async def check_agent_md(self, aid, ttl_days=1):
            calls.append((aid, ttl_days))
            from aun_core import result_ok
            return result_ok({"aid": aid, "local_found": False, "remote_found": False, "ttl_days": ttl_days})

        def close(self):
            pass

    monkeypatch.setattr(agentmd_commands, "make_aid_store", lambda resolved: FakeStore())

    result = CliRunner().invoke(app, ["--json", "agentmd", "check"])

    assert result.exit_code == 0, result.output
    assert calls == [("alice.agentid.pub", 1)]
