import asyncio
import json


def test_recorder_ignores_historical_bench_id_for_current_run():
    from aun_cli.commands.bench_e2e import E2ERecorder

    async def run():
        recorder = E2ERecorder(expected=1, timeout_ms=1000)
        await recorder.start(
            "current-run-1",
            sent_at=1.0,
            sender="alice.agentid.pub",
            target="bob.agentid.pub",
        )
        assert recorder.resolve_bench_id({"payload": {"bench_id": "current-run-1"}}) == "current-run-1"
        assert recorder.resolve_bench_id({"payload": {"bench_id": "previous-run-1"}}) == ""

    asyncio.run(run())


def test_e2e_send_collects_delivery_without_receiver_ack_rpc(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    clients_by_aid = {}
    close_order = []
    store_resolved = []
    receiver_ack_calls = []

    class FakeStore:
        def __init__(self, resolved):
            self.resolved = resolved
            store_resolved.append(dict(resolved))

        def load(self, aid):
            class Result:
                ok = True
                data = {"aid": FakeAid(aid)}
                error = None

            return Result()

        def close(self):
            pass

    class FakeAid:
        def __init__(self, aid):
            self.aid = aid

    class FakeClient:
        def __init__(self, aid_obj=None):
            self.aid = aid_obj.aid if aid_obj else ""
            self.handlers = {}
            self.connected_options = None
            clients_by_aid[self.aid] = self

        async def authenticate(self):
            return {"gateway": "fake"}

        async def connect(self, options):
            self.connected_options = dict(options)

        def on(self, event, handler):
            self.handlers.setdefault(event, []).append(handler)

            class Subscription:
                def unsubscribe(self):
                    pass

            return Subscription()

        async def call(self, method, params):
            if method == "message.send":
                receiver = clients_by_aid["bob.agentid.pub"]
                message = {
                    "message_id": params["message_id"],
                    "from": self.aid,
                    "to": params["to"],
                    "seq": len(receiver.handlers.get("message.received", [])) + 1,
                    "payload": params["payload"],
                }
                raw_message = {
                    "message_id": params["message_id"],
                    "to": params["to"],
                    "seq": message["seq"],
                    "payload": {"type": "e2ee.p2p_encrypted"},
                }
                for handler in receiver.handlers.get("_raw.message.received", []):
                    await handler(raw_message)
                for handler in receiver.handlers.get("message.received", []):
                    await handler(message)
                return {"message_id": params["payload"]["bench_id"], "seq": message["seq"]}
            if method == "message.ack":
                receiver_ack_calls.append((self.aid, dict(params)))
                return {"success": True, "ack_seq": params.get("seq") or params.get("up_to_seq")}
            if method == "message.pull":
                return {"messages": [], "raw_count": 0, "has_more": False}
            raise AssertionError(method)

        async def close(self):
            close_order.append(self.aid)

    def fake_resolve(ctx):
        return {
            "profile_name": "default",
            "aid": "alice.agentid.pub",
            "aun_path": "fake",
            "debug": True,
            "timeout": 5,
            "encryption_seed": "",
            "trace": "diag",
            "active_group": None,
        }

    monkeypatch.setattr(bench_e2e, "resolve_profile_config", fake_resolve)
    monkeypatch.setattr(bench_e2e, "make_aid_store", lambda resolved: FakeStore(resolved))
    monkeypatch.setattr(bench_e2e, "_make_quiet_aid_store", lambda resolved: FakeStore(resolved))
    monkeypatch.setattr(bench_e2e, "AUNClientFactory", FakeClient)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "e2e",
            "send",
            "--senders",
            "alice.agentid.pub",
            "--receivers",
            "bob.agentid.pub",
            "--count",
            "3",
            "--concurrency",
            "2",
            "--no-encrypt",
            "--timeout-ms",
            "1000",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["scenario"] == "p2p-online"
    assert data["client_shape"] == "single_process_multi_connection"
    assert data["count"] == 3
    assert data["ok"] == 3
    assert data["raw_received"] == 3
    assert data["bench_handlers"]["published_seen"] == 3
    assert data["receiver_seq"]["drain"]["status"] == "drained"
    assert data["receiver_seq"]["drain"]["settle"]["status"] == "drained"
    assert data["raw_to_delivered_gap"] == 0
    assert data["delivered"] == 3
    assert data["acked"] == 0
    assert data["failed"] == 0
    assert data["latency_ms"]["send_rtt"]["p95"] >= 0
    assert data["latency_ms"]["delivery"]["p95"] >= 0
    assert data["latency_ms"]["ack"]["p95"] == 0.0
    assert receiver_ack_calls == []
    assert clients_by_aid["bob.agentid.pub"].connected_options["background_sync"] is True
    assert store_resolved
    assert all(item["debug"] is False for item in store_resolved)
    assert all(item["trace"] == "off" for item in store_resolved)
    assert close_order


def test_receiver_drain_does_not_mark_drained_when_ordered_pending(monkeypatch):
    from aun_cli.commands import bench_e2e

    class FakeSeqTracker:
        def get_contiguous_seq(self, ns):
            return 1

        def get_max_seen_seq(self, ns):
            return 3

    class FakeClient:
        def __init__(self):
            self._seq_tracker = FakeSeqTracker()
            self._ordered_gap_block_stats = {}
            self._push_processing_stats = {}
            self._auto_ack_stats = {}
            self.saved = 0

        async def call(self, method, params):
            assert method == "message.pull"
            return {
                "messages": [],
                "raw_count": 0,
                "cursor": {"current_seq": 1, "latest_seq": 1, "unread_count": 0},
            }

        def _pending_ordered(self):
            return {"p2p:bob.agentid.pub": {3: ("message.received", {"seq": 3})}}

        def _save_seq_tracker_state(self):
            self.saved += 1

    async def run():
        client = FakeClient()
        receiver = bench_e2e.BenchClientHandle(
            aid="bob.agentid.pub",
            client=client,
            store=None,
            role="receiver",
        )
        config = bench_e2e.E2EConfig(
            scenario="p2p-online",
            receiver_aids=["bob.agentid.pub"],
            drain_receivers=True,
            drain_timeout_ms=20,
            drain_limit=100,
            drain_max_pages=1,
        )
        result = await bench_e2e._drain_receivers_before_run([receiver], config, group=False)
        assert result["status"] == "timeout"
        assert client.saved > 0

    asyncio.run(run())


def test_e2e_send_auto_creates_inferred_receiver(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    registered = []
    clients_by_aid = {}

    class FakeError:
        code = "CERT_NOT_FOUND"
        message = "not found"

    class FakeStore:
        identities = {"yayi2001.agentid.pub"}

        def __init__(self, resolved):
            self.resolved = resolved

        def list(self):
            class Result:
                ok = True
                data = {"identities": [{"aid": "yayi2001.agentid.pub"}]}
                error = None

            return Result()

        def load(self, aid):
            if aid not in self.identities:
                class Missing:
                    ok = False
                    data = None
                    error = FakeError()

                return Missing()

            class Result:
                ok = True
                data = {"aid": FakeAid(aid)}
                error = None

            return Result()

        async def register(self, aid):
            registered.append(aid)
            self.identities.add(aid)

            class Result:
                ok = True
                data = {"registered": True}
                error = None

            return Result()

        def close(self):
            pass

    class FakeAid:
        def __init__(self, aid):
            self.aid = aid

    class FakeClient:
        def __init__(self, aid_obj=None):
            self.aid = aid_obj.aid if aid_obj else ""
            self.handlers = {}
            clients_by_aid[self.aid] = self

        async def authenticate(self):
            return {}

        async def connect(self, options):
            self.options = options

        def on(self, event, handler):
            self.handlers.setdefault(event, []).append(handler)

        async def call(self, method, params):
            if method == "message.send":
                receiver = clients_by_aid["yayi2002.agentid.pub"]
                message = {
                    "from": self.aid,
                    "to": params["to"],
                    "seq": 1,
                    "payload": params["payload"],
                }
                for handler in receiver.handlers.get("message.received", []):
                    await handler(message)
                return {"seq": 1, "message_id": params["payload"]["bench_id"]}
            if method == "message.ack":
                return {"success": True, "ack_seq": params["seq"]}
            if method == "message.pull":
                return {"messages": [], "raw_count": 0, "has_more": False}
            raise AssertionError(method)

        async def close(self):
            pass

    monkeypatch.setattr(
        bench_e2e,
        "resolve_profile_config",
        lambda ctx: {
            "profile_name": "yayi2001",
            "aid": "yayi2001.agentid.pub",
            "aun_path": "fake",
            "debug": False,
            "timeout": 5,
            "encryption_seed": "",
            "trace": "off",
            "active_group": None,
        },
    )
    monkeypatch.setattr(bench_e2e, "make_aid_store", lambda resolved: FakeStore(resolved))
    monkeypatch.setattr(bench_e2e, "_make_quiet_aid_store", lambda resolved: FakeStore(resolved))
    monkeypatch.setattr(bench_e2e, "AUNClientFactory", FakeClient)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "e2e",
            "send",
            "--count",
            "1",
            "--concurrency",
            "1",
            "--no-encrypt",
            "--timeout-ms",
            "1000",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["senders"] == ["yayi2001.agentid.pub"]
    assert data["receivers"] == ["yayi2002.agentid.pub"]
    assert data["delivered"] == 1
    assert data["acked"] == 0
    assert registered == ["yayi2002.agentid.pub"]


def test_autoscale_records_plateau_but_continues_to_max(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    async def fake_run_e2e_scenario(ctx, config, autoscale_config):
        rps_by_concurrency = {1: 10.0, 2: 18.0, 4: 19.0, 8: 19.1}
        return {
            "scenario": config.scenario,
            "count": config.count,
            "concurrency": config.concurrency,
            "ok": config.count,
            "failed": 0,
            "delivered": config.count,
            "acked": config.count,
            "rps": rps_by_concurrency[config.concurrency],
            "latency_ms": {
                "send_rtt": {"p99": 20.0},
                "delivery": {"p99": 30.0},
                "ack": {"p99": 40.0},
            },
            "errors": [],
            "backpressure": {"signals": []},
        }

    monkeypatch.setattr(bench_e2e, "_run_autoscale_stage", fake_run_e2e_scenario)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "autoscale",
            "send",
            "--senders",
            "alice.agentid.pub",
            "--receivers",
            "bob.agentid.pub",
            "--count",
            "10",
            "--step-seconds",
            "0.01",
            "--start",
            "1",
            "--max",
            "8",
            "--factor",
            "2",
            "--plateau-ratio",
            "0.1",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert [step["concurrency"] for step in data["steps"]] == [1, 2, 4, 8]
    assert data["mode"] == "continuous_ramp"
    assert data["stop_reason"] == "max_concurrency_reached"
    assert data["soft_knee"]["found"] is True
    assert data["soft_knee"]["reason"] == "rps_plateau"
    assert data["soft_knee"]["concurrency"] == 4
    assert data["soft_knee"]["condition"]["type"] == "rps_plateau"
    assert data["soft_knee"]["condition"]["observed_gain_ratio"] < 0.1
    assert data["knee"]["found"] is False
    assert data["peak"]["rps"] == 19.1
    assert data["summary"]["attempted"] == 40
    assert data["summary"]["ok"] == 40
    assert data["summary"]["success_rate"] == 1.0
    assert data["summary"]["delivery_rate"] == 1.0
    assert data["summary"]["peak_concurrency"] == 8
    assert data["steps"][1]["rates"]["success"] == 1.0
    assert data["steps"][2]["comparisons"]["rps_gain_ratio"] < 0.1


def test_autoscale_p99_spike_uses_baseline_floor(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    p99_by_concurrency = {1: 10.0, 2: 50.0, 4: 650.0}

    async def fake_run_e2e_scenario(ctx, config, autoscale_config):
        p99 = p99_by_concurrency[config.concurrency]
        return {
            "scenario": config.scenario,
            "count": config.count,
            "concurrency": config.concurrency,
            "ok": config.count,
            "failed": 0,
            "delivered": config.count,
            "acked": config.count,
            "rps": float(config.concurrency * 10),
            "latency_ms": {
                "send_rtt": {"p99": p99},
                "delivery": {"p99": p99},
                "ack": {"p99": p99},
            },
            "errors": [],
            "backpressure": {"signals": []},
        }

    monkeypatch.setattr(bench_e2e, "_run_autoscale_stage", fake_run_e2e_scenario)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "autoscale",
            "send",
            "--senders",
            "alice.agentid.pub",
            "--receivers",
            "bob.agentid.pub",
            "--count",
            "10",
            "--step-seconds",
            "0.01",
            "--start",
            "1",
            "--max",
            "4",
            "--factor",
            "2",
            "--p99-factor",
            "3",
            "--p99-baseline-ms",
            "200",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert [step["concurrency"] for step in data["steps"]] == [1, 2, 4]
    assert data["stop_reason"] == "p99_spike"
    assert data["steps"][1]["comparisons"]["baseline_p99_ms"] == 10.0
    assert data["steps"][1]["comparisons"]["effective_baseline_p99_ms"] == 200.0
    assert data["steps"][1]["comparisons"]["p99_factor"] == 0.25
    condition = data["knee"]["condition"]
    assert condition["type"] == "p99_spike"
    assert condition["baseline_p99_ms"] == 10.0
    assert condition["effective_baseline_p99_ms"] == 200.0
    assert condition["observed_factor"] == 3.25


def test_autoscale_default_p99_scope_ignores_delivery_backlog(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    async def fake_run_e2e_scenario(ctx, config, autoscale_config):
        delivery_p99 = 100.0 if config.concurrency == 1 else 5000.0
        return {
            "scenario": config.scenario,
            "count": config.count,
            "concurrency": config.concurrency,
            "ok": config.count,
            "failed": 0,
            "delivered": config.count,
            "acked": config.count,
            "rps": float(config.concurrency * 100),
            "latency_ms": {
                "send_rtt": {"p99": 110.0},
                "delivery": {"p99": delivery_p99},
                "ack": {"p99": 100.0},
            },
            "errors": [],
            "backpressure": {"signals": []},
        }

    monkeypatch.setattr(bench_e2e, "_run_autoscale_stage", fake_run_e2e_scenario)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "autoscale",
            "send",
            "--senders",
            "alice.agentid.pub",
            "--receivers",
            "bob.agentid.pub",
            "--count",
            "10",
            "--step-seconds",
            "0.01",
            "--start",
            "1",
            "--max",
            "2",
            "--factor",
            "2",
            "--p99-factor",
            "3",
            "--p99-baseline-ms",
            "200",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["stop_reason"] == "max_concurrency_reached"
    assert data["summary"]["p99_scope"] == "send"
    assert data["steps"][1]["comparisons"]["stage_p99_ms"] == 110.0
    assert data["steps"][1]["comparisons"]["p99_scope"] == "send"


def test_autoscale_p99_scope_max_keeps_legacy_delivery_spike_stop(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    async def fake_run_e2e_scenario(ctx, config, autoscale_config):
        delivery_p99 = 100.0 if config.concurrency == 1 else 5000.0
        return {
            "scenario": config.scenario,
            "count": config.count,
            "concurrency": config.concurrency,
            "ok": config.count,
            "failed": 0,
            "delivered": config.count,
            "acked": config.count,
            "rps": float(config.concurrency * 100),
            "latency_ms": {
                "send_rtt": {"p99": 110.0},
                "delivery": {"p99": delivery_p99},
                "ack": {"p99": 100.0},
            },
            "errors": [],
            "backpressure": {"signals": []},
        }

    monkeypatch.setattr(bench_e2e, "_run_autoscale_stage", fake_run_e2e_scenario)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "autoscale",
            "send",
            "--senders",
            "alice.agentid.pub",
            "--receivers",
            "bob.agentid.pub",
            "--count",
            "10",
            "--step-seconds",
            "0.01",
            "--start",
            "1",
            "--max",
            "2",
            "--factor",
            "2",
            "--p99-factor",
            "3",
            "--p99-baseline-ms",
            "200",
            "--p99-scope",
            "max",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["stop_reason"] == "p99_spike"
    assert data["knee"]["condition"]["p99_scope"] == "max"
    assert data["knee"]["condition"]["stage_p99_ms"] == 5000.0


def test_autoscale_can_stop_on_plateau_for_compat(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    async def fake_run_e2e_scenario(ctx, config, autoscale_config):
        rps_by_concurrency = {1: 10.0, 2: 18.0, 4: 19.0}
        return {
            "scenario": config.scenario,
            "count": config.count,
            "concurrency": config.concurrency,
            "ok": config.count,
            "failed": 0,
            "delivered": config.count,
            "acked": config.count,
            "rps": rps_by_concurrency[config.concurrency],
            "latency_ms": {
                "send_rtt": {"p99": 20.0},
                "delivery": {"p99": 30.0},
                "ack": {"p99": 40.0},
            },
            "errors": [],
            "backpressure": {"signals": []},
        }

    monkeypatch.setattr(bench_e2e, "_run_autoscale_stage", fake_run_e2e_scenario)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "autoscale",
            "send",
            "--senders",
            "alice.agentid.pub",
            "--receivers",
            "bob.agentid.pub",
            "--count",
            "10",
            "--step-seconds",
            "0.01",
            "--start",
            "1",
            "--max",
            "4",
            "--factor",
            "2",
            "--plateau-ratio",
            "0.1",
            "--stop-on-plateau",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert [step["concurrency"] for step in data["steps"]] == [1, 2, 4]
    assert data["stop_reason"] == "rps_plateau"
    assert data["knee"]["found"] is True
    assert data["knee"]["reason"] == "rps_plateau"
    assert data["soft_knee"]["found"] is True


def test_autoscale_summary_reports_raw_delivery_gap(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    async def fake_run_e2e_scenario(ctx, config, autoscale_config):
        return {
            "scenario": config.scenario,
            "count": 10,
            "concurrency": config.concurrency,
            "ok": 10,
            "failed": 0,
            "raw_received": 9,
            "delivered": 7,
            "acked": 7,
            "ok_to_raw_gap": 1,
            "raw_to_delivered_gap": 2,
            "lost": 3,
            "unacked": 3,
            "rps": 10.0,
            "delivered_rps": 7.0,
            "acked_rps": 7.0,
            "latency_ms": {
                "send_rtt": {"p99": 10.0},
                "raw_received": {"p99": 12.0},
                "raw_to_delivery": {"p99": 5.0},
                "delivery": {"p99": 17.0},
                "ack": {"p99": 20.0},
            },
            "errors": [],
            "backpressure": {"signals": [], "detected": False},
        }

    monkeypatch.setattr(bench_e2e, "_run_autoscale_stage", fake_run_e2e_scenario)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "autoscale",
            "send",
            "--senders",
            "alice.agentid.pub",
            "--receivers",
            "bob.agentid.pub",
            "--count",
            "10",
            "--step-seconds",
            "0.01",
            "--start",
            "1",
            "--max",
            "1",
            "--incomplete-rate",
            "0.5",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["summary"]["raw_received"] == 9
    assert data["summary"]["ok_to_raw_gap"] == 1
    assert data["summary"]["raw_to_delivered_gap"] == 2
    assert data["summary"]["raw_receive_rate"] == 0.9
    assert data["summary"]["raw_to_delivery_rate"] == 0.777778


def test_autoscale_summary_reports_receiver_ordered_gap_diagnostics(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    async def fake_run_e2e_scenario(ctx, config, autoscale_config):
        return {
            "scenario": config.scenario,
            "count": 10,
            "concurrency": config.concurrency,
            "ok": 10,
            "failed": 0,
            "raw_received": 10,
            "delivered": 6,
            "acked": 6,
            "ok_to_raw_gap": 0,
            "raw_to_delivered_gap": 4,
            "ordered_gap_blocked": 4,
            "receiver_seq": {
                "namespaces": [
                    {
                        "aid": "bob.agentid.pub",
                        "namespace": "p2p:bob.agentid.pub",
                        "contiguous_seq": 2,
                        "max_seen_seq": 10,
                        "pending_ordered_count": 4,
                        "pending_gap_count": 1,
                        "ordered_gap_blocked": 4,
                    }
                ],
                "totals": {
                    "pending_ordered_count": 4,
                    "pending_gap_count": 1,
                    "ordered_gap_blocked": 4,
                },
            },
            "lost": 4,
            "unacked": 4,
            "rps": 10.0,
            "delivered_rps": 6.0,
            "acked_rps": 6.0,
            "latency_ms": {"send_rtt": {"p99": 10.0}, "delivery": {"p99": 20.0}, "ack": {"p99": 20.0}},
            "errors": [],
            "backpressure": {"signals": [], "detected": False},
        }

    monkeypatch.setattr(bench_e2e, "_run_autoscale_stage", fake_run_e2e_scenario)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "autoscale",
            "send",
            "--senders",
            "alice.agentid.pub",
            "--receivers",
            "bob.agentid.pub",
            "--count",
            "10",
            "--step-seconds",
            "0.01",
            "--start",
            "1",
            "--max",
            "1",
            "--incomplete-rate",
            "0.5",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["summary"]["ordered_gap_blocked"] == 4
    assert data["summary"]["receiver_seq"]["totals"]["pending_ordered_count"] == 4
    assert data["steps"][0]["receiver_seq"]["namespaces"][0]["contiguous_seq"] == 2


def test_autoscale_uses_send_rps_for_peak_and_plateau(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    async def fake_run_e2e_scenario(ctx, config, autoscale_config):
        send_rps_by_concurrency = {1: 20.0, 2: 36.0, 4: 38.0}
        observed_rps_by_concurrency = {1: 10.0, 2: 18.0, 4: 19.0}
        return {
            "scenario": config.scenario,
            "count": 10,
            "concurrency": config.concurrency,
            "ok": 10,
            "failed": 0,
            "raw_received": 10,
            "delivered": 10,
            "acked": 10,
            "lost": 0,
            "unacked": 0,
            "send_rps": send_rps_by_concurrency[config.concurrency],
            "rps": observed_rps_by_concurrency[config.concurrency],
            "delivered_rps": observed_rps_by_concurrency[config.concurrency],
            "acked_rps": observed_rps_by_concurrency[config.concurrency],
            "latency_ms": {"send_rtt": {"p99": 10.0}, "delivery": {"p99": 20.0}, "ack": {"p99": 20.0}},
            "errors": [],
            "backpressure": {"signals": [], "detected": False},
        }

    monkeypatch.setattr(bench_e2e, "_run_autoscale_stage", fake_run_e2e_scenario)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "autoscale",
            "send",
            "--senders",
            "alice.agentid.pub",
            "--receivers",
            "bob.agentid.pub",
            "--count",
            "10",
            "--step-seconds",
            "0.01",
            "--start",
            "1",
            "--max",
            "4",
            "--factor",
            "2",
            "--plateau-ratio",
            "0.1",
            "--stop-on-plateau",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["peak"]["rps"] == 38.0
    assert data["peak"]["observed_rps"] == 19.0
    assert data["knee"]["condition"]["current_rps"] == 38.0
    assert data["summary"]["peak_send_rps"] == 38.0


def test_autoscale_does_not_stop_on_ack_incomplete_when_delivery_complete(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    async def fake_run_e2e_scenario(ctx, config, autoscale_config):
        return {
            "scenario": config.scenario,
            "count": 10,
            "concurrency": config.concurrency,
            "ok": 10,
            "failed": 0,
            "raw_received": 10,
            "delivered": 10,
            "acked": 0,
            "lost": 0,
            "unacked": 10,
            "send_rps": 10.0,
            "rps": 10.0,
            "delivered_rps": 10.0,
            "acked_rps": 0.0,
            "rates": {"success": 1.0, "failure": 0.0, "delivery": 1.0, "ack": 0.0},
            "latency_ms": {"send_rtt": {"p99": 10.0}, "delivery": {"p99": 20.0}, "ack": {"p99": 0.0}},
            "errors": [],
            "backpressure": {"signals": [], "detected": False},
        }

    monkeypatch.setattr(bench_e2e, "_run_autoscale_stage", fake_run_e2e_scenario)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "autoscale",
            "send",
            "--senders",
            "alice.agentid.pub",
            "--receivers",
            "bob.agentid.pub",
            "--count",
            "10",
            "--step-seconds",
            "0.01",
            "--start",
            "1",
            "--max",
            "1",
            "--incomplete-rate",
            "0.2",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["stop_reason"] == "max_concurrency_reached"
    assert data["knee"]["found"] is False


def test_autoscale_reports_backpressure_trigger_condition(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    async def fake_run_e2e_scenario(ctx, config, autoscale_config):
        if config.concurrency == 1:
            return {
                "scenario": config.scenario,
                "count": config.count,
                "concurrency": config.concurrency,
                "ok": config.count,
                "failed": 0,
                "delivered": config.count,
                "acked": config.count,
                "lost": 0,
                "unacked": 0,
                "rps": 10.0,
                "delivered_rps": 10.0,
                "acked_rps": 10.0,
                "latency_ms": {
                    "send_rtt": {"p99": 20.0},
                    "delivery": {"p99": 30.0},
                    "ack": {"p99": 40.0},
                },
                "errors": [],
                "backpressure": {"signals": [], "detected": False},
            }
        return {
            "scenario": config.scenario,
            "count": config.count,
            "concurrency": config.concurrency,
            "ok": config.count - 2,
            "failed": 2,
            "delivered": config.count - 2,
            "acked": config.count - 2,
            "lost": 0,
            "unacked": 0,
            "rps": 12.0,
            "delivered_rps": 12.0,
            "acked_rps": 12.0,
            "latency_ms": {
                "send_rtt": {"p99": 25.0},
                "delivery": {"p99": 35.0},
                "ack": {"p99": 45.0},
            },
            "errors": [{"message": "JSON-RPC -32429 service backpressure", "count": 2}],
            "backpressure": {
                "detected": True,
                "signals": [
                    {
                        "type": "server_backpressure",
                        "message": "JSON-RPC -32429 service backpressure",
                        "count": 2,
                    }
                ],
            },
        }

    monkeypatch.setattr(bench_e2e, "_run_autoscale_stage", fake_run_e2e_scenario)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "autoscale",
            "send",
            "--senders",
            "alice.agentid.pub",
            "--receivers",
            "bob.agentid.pub",
            "--count",
            "10",
            "--step-seconds",
            "0.01",
            "--start",
            "1",
            "--max",
            "2",
            "--factor",
            "2",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["knee"]["found"] is True
    assert data["knee"]["reason"] == "server_backpressure"
    assert data["stop_reason"] == "server_backpressure"
    assert data["knee"]["condition"]["type"] == "backpressure"
    assert data["knee"]["condition"]["signal_type"] == "server_backpressure"
    assert data["backpressure"]["detected"] is True
    assert data["backpressure"]["trigger_condition"]["signal_type"] == "server_backpressure"
    assert data["backpressure"]["signals"][0]["count"] == 2
    assert data["backpressure"]["signals"][0]["first_concurrency"] == 2


def test_autoscale_summarizes_send_perf_trace_from_logs(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    log_dir = tmp_path / "message" / "log"
    log_dir.mkdir(parents=True)
    log_path = log_dir / "latest.log"

    async def fake_run_e2e_scenario(ctx, config, autoscale_config):
        log_path.write_text(
            "\n".join(
                [
                    "[message] send_perf id=trace-1 stage=msg_seq_alloc_begin elapsed_ms=5 delta_ms=5",
                    "[message] send_perf id=trace-1 stage=msg_seq_alloc_done elapsed_ms=17 delta_ms=12",
                    "[message] send_perf id=trace-1 stage=msg_wal_backlog_wait_begin elapsed_ms=18 delta_ms=1",
                    "[message] send_perf id=trace-1 stage=msg_wal_backlog_wait_done elapsed_ms=23 delta_ms=5",
                    "[message] send_perf id=trace-1 stage=msg_wal_append_begin elapsed_ms=24 delta_ms=1",
                    "[message] send_perf id=trace-1 stage=msg_wal_append_done elapsed_ms=38 delta_ms=14",
                    "[message] send_perf id=trace-1 stage=msg_pending_enqueue_begin elapsed_ms=39 delta_ms=1",
                    "[message] send_perf id=trace-1 stage=msg_pending_enqueue_done elapsed_ms=42 delta_ms=3",
                    "[message] send_perf id=trace-1 stage=msg_push_dispatch_begin elapsed_ms=43 delta_ms=1",
                    "[message] send_perf id=trace-1 stage=msg_push_dispatch_recipient_done elapsed_ms=61 delta_ms=18",
                    "[message] send_perf id=trace-1 stage=msg_push_dispatch_self_done elapsed_ms=70 delta_ms=9",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return {
            "scenario": config.scenario,
            "count": config.count,
            "concurrency": config.concurrency,
            "ok": config.count,
            "failed": 0,
            "raw_received": config.count,
            "delivered": config.count,
            "acked": config.count,
            "lost": 0,
            "unacked": 0,
            "rps": 10.0,
            "send_rps": 10.0,
            "delivered_rps": 10.0,
            "acked_rps": 10.0,
            "latency_ms": {"send_rtt": {"p99": 10.0}, "delivery": {"p99": 20.0}, "ack": {"p99": 20.0}},
            "errors": [],
            "backpressure": {"signals": [], "detected": False},
        }

    monkeypatch.setattr(bench_e2e, "_run_autoscale_stage", fake_run_e2e_scenario)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "autoscale",
            "send",
            "--senders",
            "alice.agentid.pub",
            "--receivers",
            "bob.agentid.pub",
            "--count",
            "10",
            "--step-seconds",
            "0.01",
            "--start",
            "1",
            "--max",
            "1",
            "--perf-log-root",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    perf = data["steps"][0]["send_perf"]
    assert perf["available"] is True
    assert perf["trace_count"] == 1
    assert perf["total_elapsed_ms"]["p99"] == 70.0
    assert perf["stages"]["msg_seq_alloc"]["p99"] == 12.0
    assert perf["stages"]["msg_wal_append"]["p99"] == 14.0
    assert perf["stages"]["msg_push_dispatch"]["p99"] == 27.0
    assert perf["stages"]["msg_push_dispatch_self"]["p99"] == 9.0
    assert data["summary"]["send_perf"]["stages"]["msg_push_dispatch"]["p99_pct_of_total"] == 38.57


def test_e2e_offline_pull_marks_delivery_and_ack(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    delivered = []

    class FakeStore:
        def __init__(self, resolved):
            self.resolved = resolved

        def load(self, aid):
            class Result:
                ok = True
                data = {"aid": FakeAid(aid)}
                error = None

            return Result()

        def close(self):
            pass

    class FakeAid:
        def __init__(self, aid):
            self.aid = aid

    class FakeClient:
        def __init__(self, aid_obj=None):
            self.aid = aid_obj.aid if aid_obj else ""

        async def authenticate(self):
            return {}

        async def connect(self, options):
            self.options = options

        def on(self, event, handler):
            return None

        async def call(self, method, params):
            if method == "message.send":
                delivered.append({"from": self.aid, "to": params["to"], "seq": len(delivered) + 1, "payload": params["payload"]})
                return {"seq": len(delivered), "message_id": params["payload"]["bench_id"]}
            if method == "message.pull":
                return {"messages": list(delivered)}
            if method == "message.ack":
                return {"success": True, "ack_seq": params["seq"]}
            raise AssertionError(method)

        async def close(self):
            pass

    monkeypatch.setattr(
        bench_e2e,
        "resolve_profile_config",
        lambda ctx: {
            "profile_name": "default",
            "aid": "alice.agentid.pub",
            "aun_path": "fake",
            "debug": False,
            "timeout": 5,
            "encryption_seed": "",
            "trace": "off",
            "active_group": None,
        },
    )
    monkeypatch.setattr(bench_e2e, "make_aid_store", lambda resolved: FakeStore(resolved))
    monkeypatch.setattr(bench_e2e, "_make_quiet_aid_store", lambda resolved: FakeStore(resolved))
    monkeypatch.setattr(bench_e2e, "AUNClientFactory", FakeClient)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "e2e",
            "all",
            "--senders",
            "alice.agentid.pub",
            "--receivers",
            "bob.agentid.pub",
            "--count",
            "2",
            "--concurrency",
            "1",
            "--no-encrypt",
            "--timeout-ms",
            "100",
            "--scenarios",
            "p2p-offline-pull",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    offline = data["scenarios"][0]
    assert offline["status"] == "ok"
    assert offline["delivered"] == 2
    assert offline["acked"] == 2


def test_all_lists_planned_happy_path_scenarios(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    async def fake_run_e2e_scenario(ctx, config):
        return {
            "scenario": config.scenario,
            "status": "ok",
            "count": config.count,
            "ok": config.count,
            "failed": 0,
        }

    monkeypatch.setattr(bench_e2e, "run_e2e_scenario", fake_run_e2e_scenario)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "e2e",
            "all",
            "--senders",
            "alice.agentid.pub",
            "--receivers",
            "bob.agentid.pub",
            "--group-id",
            "group.agentid.pub/10042",
            "--count",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert [item["scenario"] for item in data["scenarios"]] == [
        "connect",
        "p2p-online",
        "group-online",
        "p2p-offline-pull",
        "group-offline-pull",
        "storage-vfs",
        "group-fs",
        "collab",
        "notify-online",
        "service-proxy",
        "federation-p2p",
        "federation-group",
    ]
    assert data["scenarios"][1]["status"] == "ok"
    assert data["scenarios"][2]["status"] == "ok"
    assert data["scenarios"][3]["status"] == "ok"
    assert data["scenarios"][4]["status"] == "ok"


def test_all_runs_non_message_happy_paths(monkeypatch):
    from typer.testing import CliRunner

    from aun_cli.commands import bench_e2e
    from aun_cli.main import app

    calls = []

    class FakeStore:
        def __init__(self, resolved):
            self.resolved = resolved

        def load(self, aid):
            class Result:
                ok = True
                data = {"aid": FakeAid(aid)}
                error = None

            return Result()

        def close(self):
            pass

    class FakeAid:
        def __init__(self, aid):
            self.aid = aid

    class FakeStorage:
        async def mkdir(self, path, **kwargs):
            calls.append(("storage.mkdir", path))
            return {"ok": True}

        async def write_bytes(self, path, data, **kwargs):
            calls.append(("storage.write_bytes", path, data))
            return {"ok": True}

        async def read_bytes(self, path, **kwargs):
            calls.append(("storage.read_bytes", path))
            return b"bench"

        async def stat(self, path, **kwargs):
            calls.append(("storage.stat", path))
            return {"ok": True}

        async def list(self, path, **kwargs):
            calls.append(("storage.list", path))
            return {"items": []}

        async def remove(self, path, **kwargs):
            calls.append(("storage.remove", path))
            return {"ok": True}

    class FakeGroupFS:
        async def mkdir(self, path, **kwargs):
            calls.append(("groupfs.mkdir", path))
            return {"ok": True}

        async def stat(self, path, **kwargs):
            calls.append(("groupfs.stat", path))
            return {"ok": True}

        async def ls(self, path, **kwargs):
            calls.append(("groupfs.ls", path))
            return {"items": []}

        async def rm(self, path, **kwargs):
            calls.append(("groupfs.rm", path))
            return {"ok": True}

    class FakeGroup:
        def __init__(self):
            self.fs = FakeGroupFS()

    class FakeCollab:
        async def create(self, root, doc, source):
            calls.append(("collab.create", root, doc, source))
            return {"version": 1}

        async def show(self, root, doc, rev=None):
            calls.append(("collab.show", root, doc, rev))
            return {"version": 1, "content": "bench"}

        async def commit(self, root, doc, source, onto, message=""):
            calls.append(("collab.commit", root, doc, source, onto))
            return {"version": 2}

        async def log(self, root, doc):
            calls.append(("collab.log", root, doc))
            return []

    class FakeClient:
        def __init__(self, aid_obj=None):
            self.aid = aid_obj.aid if aid_obj else ""
            self.storage = FakeStorage()
            self.group = FakeGroup()
            self.collab = FakeCollab()

        async def authenticate(self):
            return {}

        async def connect(self, options):
            pass

        def on(self, event, handler):
            return None

        async def notify(self, method, params=None, **kwargs):
            calls.append(("notify", method, params, kwargs))

        async def call(self, method, params):
            if method in {"message.send", "group.send"}:
                return {"seq": 1, "message_id": params["payload"]["bench_id"]}
            if method in {"message.pull", "group.pull"}:
                return {"messages": []}
            return {"ok": True}

        async def close(self):
            pass

    monkeypatch.setattr(
        bench_e2e,
        "resolve_profile_config",
        lambda ctx: {
            "profile_name": "default",
            "aid": "alice.agentid.pub",
            "aun_path": "fake",
            "debug": False,
            "timeout": 5,
            "encryption_seed": "",
            "trace": "off",
            "active_group": "group.agentid.pub/10042",
        },
    )
    monkeypatch.setattr(bench_e2e, "make_aid_store", lambda resolved: FakeStore(resolved))
    monkeypatch.setattr(bench_e2e, "_make_quiet_aid_store", lambda resolved: FakeStore(resolved))
    monkeypatch.setattr(bench_e2e, "AUNClientFactory", FakeClient)

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "bench",
            "e2e",
            "all",
            "--senders",
            "alice.agentid.pub",
            "--receivers",
            "bob.agentid.pub",
            "--group-id",
            "group.agentid.pub/10042",
            "--count",
            "1",
            "--timeout-ms",
            "50",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    statuses = {item["scenario"]: item["status"] for item in data["scenarios"]}
    assert statuses["storage-vfs"] == "ok"
    assert statuses["group-fs"] == "ok"
    assert statuses["collab"] == "ok"
    assert statuses["notify-online"] == "ok"
    assert statuses["service-proxy"] == "skipped"
    assert statuses["federation-p2p"] == "skipped"
    assert any(call[0] == "storage.write_bytes" for call in calls)
    assert any(call[0] == "groupfs.mkdir" for call in calls)
    assert any(call[0] == "collab.commit" for call in calls)
    assert any(call[0] == "notify" for call in calls)
