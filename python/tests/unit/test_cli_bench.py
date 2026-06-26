import asyncio
import json


def test_suppress_cli_summary_skips_invocation_rpc_summary(capsys):
    from aun_cli.adapter import finish_cli_invocation, record_rpc_call, start_cli_invocation, suppress_cli_summary

    start_cli_invocation(json_mode=False)
    record_rpc_call("message.send", 3, "ok")
    suppress_cli_summary()
    finish_cli_invocation()

    output = capsys.readouterr()
    assert "RPC summary" not in output.err


def test_bench_send_respects_count_and_concurrency(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench as bench_commands
    from aun_cli.main import app

    calls = []
    active = 0
    max_active = 0
    sessions = []

    class FakeClient:
        async def call(self, method, params):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            try:
                await asyncio.sleep(0.01)
                calls.append((method, params))
                return {"message_id": f"m-{len(calls)}"}
            finally:
                active -= 1

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            sessions.append(ctx.obj.get("trace"))

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(bench_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "send",
            "bob.agentid.pub",
            "--count",
            "5",
            "--concurrency",
            "2",
            "--size",
            "16",
            "--no-encrypt",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert len(sessions) == 1
    assert len(calls) == 5
    assert max_active <= 2
    assert max_active == 2
    assert data["method"] == "message.send"
    assert data["target"] == "bob.agentid.pub"
    assert data["count"] == 5
    assert data["concurrency"] == 2
    assert data["ok"] == 5
    assert data["failed"] == 0
    assert data["latency_ms"]["p95"] >= 0
    assert all(method == "message.send" for method, _ in calls)
    assert all(params["to"] == "bob.agentid.pub" for _, params in calls)
    assert all(params["encrypt"] is False for _, params in calls)
    assert all(len(params["payload"]["text"]) == 16 for _, params in calls)
    assert sessions[0] == "off"


def test_bench_group_send_nested_command_calls_group_send(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench as bench_commands
    from aun_cli.main import app

    calls = []

    class FakeClient:
        async def call(self, method, params):
            calls.append((method, params))
            return {"message_id": f"g-{len(calls)}"}

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(bench_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "group",
            "send",
            "g-team.agentid.pub",
            "--count",
            "3",
            "--concurrency",
            "2",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["method"] == "group.send"
    assert data["group_id"] == "g-team.agentid.pub"
    assert data["count"] == 3
    assert data["ok"] == 3
    assert data["failed"] == 0
    assert calls == [
        (
            "group.send",
            {
                "group_id": "g-team.agentid.pub",
                "payload": {"text": f"bench-{index}-" + ("x" * (64 - len(f"bench-{index}-")))},
                "encrypt": True,
            },
        )
        for index in range(3)
    ]


def test_bench_send_collects_rpc_failures(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench as bench_commands
    from aun_cli.main import app

    calls = 0

    class FakeClient:
        async def call(self, method, params):
            nonlocal calls
            calls += 1
            if calls in {2, 4}:
                raise RuntimeError("send failed")
            return {"message_id": f"m-{calls}"}

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(bench_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "send",
            "bob.agentid.pub",
            "--count",
            "4",
            "--concurrency",
            "2",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["ok"] == 2
    assert data["failed"] == 2
    assert data["errors"] == [{"message": "send failed", "count": 2}]
