from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import typer

from aun_cli.adapter import (
    handle_error,
    make_aid_store,
    resolve_profile_config,
    run_async,
    suppress_cli_summary,
)
from aun_cli.output import is_json_mode, output_dict, output_json, set_json_mode
e2e_app = typer.Typer(name="e2e", help="真实 E2E happy path 压测", no_args_is_help=True)
autoscale_app = typer.Typer(name="autoscale", help="阶梯自动加压找拐点", no_args_is_help=True)


AUNClientFactory: Any = None

CLIENT_SHAPE = "single_process_multi_connection"
DEFAULT_SETTLE_DRAIN_TIMEOUT_MS = 60000
ALL_SCENARIOS = [
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


@dataclass(slots=True)
class E2EConfig:
    scenario: str
    count: int = 100
    concurrency: int = 1
    payload_size: int = 64
    encrypt: bool = True
    persist: bool = True
    prefix: str = "bench-e2e"
    sender_aids: list[str] | None = None
    receiver_aids: list[str] | None = None
    group_id: str | None = None
    timeout_ms: int = 5000
    ack_mode: str = "auto"
    drain_receivers: bool = False
    drain_timeout_ms: int | None = None
    drain_limit: int = 100
    drain_max_pages: int = 100
    settle_ms: int | None = None


@dataclass(slots=True)
class AutoscaleConfig:
    scenario: str
    count: int
    step_seconds: float
    start: int
    max_concurrency: int
    factor: int
    step: int
    plateau_ratio: float
    p99_factor: float
    p99_baseline_ms: float
    error_rate: float
    incomplete_rate: float
    stop_on_plateau: bool
    payload_size: int
    encrypt: bool
    persist: bool
    prefix: str
    sender_aids: list[str] | None
    receiver_aids: list[str] | None
    group_id: str | None
    timeout_ms: int
    p99_scope: str = "send"
    perf_trace: bool = True
    perf_log_root: str | None = None
    drain_receivers: bool = False
    drain_timeout_ms: int | None = None
    drain_limit: int = 100
    drain_max_pages: int = 100
    settle_ms: int | None = None


@dataclass(slots=True)
class SendPerfCollected:
    summary: dict[str, Any]
    stage_durations: dict[str, list[float]]
    trace_totals: list[float]
    trace_count: int
    event_count: int
    log_paths: list[str]


class BenchClientHandle:
    def __init__(self, *, aid: str, client: Any, store: Any, role: str) -> None:
        self.aid = aid
        self.client = client
        self.store = store
        self.role = role

    async def close(self) -> None:
        try:
            close = getattr(self.client, "close", None)
            if callable(close):
                result = close()
                if hasattr(result, "__await__"):
                    await result
        finally:
            store_close = getattr(self.store, "close", None)
            if callable(store_close):
                store_close()


def _run_bench_quiet(awaitable: Any) -> Any:
    with _suppress_debug_logging():
        return run_async(awaitable)


@contextlib.contextmanager
def _suppress_debug_logging():
    try:
        import logging
    except Exception:
        logging = None
    previous_disable = logging.root.manager.disable if logging is not None else None
    original_aun_debug = None
    try:
        from aun_core.logger import AUNLogger

        original_aun_debug = AUNLogger.debug
        AUNLogger.debug = lambda self, module, msg, *args: None
    except Exception:
        pass
    if logging is not None:
        logging.disable(logging.DEBUG)
    try:
        yield
    finally:
        if logging is not None and previous_disable is not None:
            logging.disable(previous_disable)
        if original_aun_debug is not None:
            try:
                from aun_core.logger import AUNLogger

                AUNLogger.debug = original_aun_debug
            except Exception:
                pass


class E2ERecorder:
    def __init__(self, *, expected: int, timeout_ms: int) -> None:
        self.expected = expected
        self.timeout_ms = timeout_ms
        self.records: dict[str, dict[str, Any]] = {}
        self._message_to_bench: dict[str, str] = {}
        self._seq_to_bench: dict[int, str] = {}
        self.handler_stats: dict[str, int] = {
            "raw_seen": 0,
            "raw_matched": 0,
            "raw_unmatched": 0,
            "delivered_seen": 0,
            "delivered_matched": 0,
            "delivered_unmatched": 0,
            "published_seen": 0,
            "published_matched": 0,
            "published_unmatched": 0,
        }
        self._trace = BenchMatchTrace.from_env()
        self.errors: list[str] = []
        self._condition = asyncio.Condition()

    def reset_handler_stats(self) -> None:
        for key in list(self.handler_stats.keys()):
            self.handler_stats[key] = 0

    async def start(self, bench_id: str, *, sent_at: float, sender: str, target: str) -> None:
        async with self._condition:
            self.records[bench_id] = {
                "bench_id": bench_id,
                "message_id": bench_id,
                "sender": sender,
                "target": target,
                "sent_at": sent_at,
            }
            self._message_to_bench[bench_id] = bench_id
            self._trace.write("start", bench_id=bench_id, sender=sender, target=target)

    async def mark_send_result(self, bench_id: str, *, ok: bool, at: float, ms: float, error: str = "", result: Any = None) -> None:
        async with self._condition:
            record = self.records.setdefault(bench_id, {"bench_id": bench_id})
            record["send_done_at"] = at
            record["send_rtt_ms"] = ms
            record["send_ok"] = ok
            if result is not None:
                record["send_result"] = result
                message_id = _extract_message_id(result)
                if message_id:
                    record["message_id"] = message_id
                    self._message_to_bench[message_id] = bench_id
                seq = _extract_seq(result)
                if seq > 0:
                    record["seq"] = seq
                    self._seq_to_bench[seq] = bench_id
                self._trace.write(
                    "send_result",
                    bench_id=bench_id,
                    ok=ok,
                    message_id=message_id,
                    seq=seq,
                    result_shape=_event_shape(result),
                )
            if error:
                record["error"] = error
                self.errors.append(error)
                self._trace.write("send_error", bench_id=bench_id, error=error)
            self._condition.notify_all()

    async def mark_raw_received(self, bench_id: str, payload: dict[str, Any], *, at: float) -> None:
        async with self._condition:
            record = self.records.setdefault(bench_id, {"bench_id": bench_id})
            sent_at = float(record.get("sent_at") or payload.get("t_send") or at)
            record["raw_received_at"] = at
            record["raw_received_ms"] = (at - sent_at) * 1000
            message_id = _extract_message_id(payload)
            if message_id:
                record["message_id"] = message_id
                self._message_to_bench[message_id] = bench_id
            seq = _extract_seq(payload)
            if seq > 0:
                record["seq"] = seq
                self._seq_to_bench[seq] = bench_id
            self._condition.notify_all()

    async def mark_delivered(self, bench_id: str, payload: dict[str, Any], *, at: float) -> None:
        async with self._condition:
            record = self.records.setdefault(bench_id, {"bench_id": bench_id})
            sent_at = float(record.get("sent_at") or payload.get("t_send") or at)
            record["delivered_at"] = at
            record["delivery_ms"] = (at - sent_at) * 1000
            if record.get("raw_received_at"):
                record["raw_to_delivery_ms"] = (at - float(record["raw_received_at"])) * 1000
            seq = _extract_seq(payload)
            if seq > 0:
                record["seq"] = seq
                self._seq_to_bench[seq] = bench_id
            self._condition.notify_all()

    def resolve_bench_id(self, event: Any) -> str:
        return self.resolve_bench_id_with_reason(event)[0]

    def resolve_bench_id_with_reason(self, event: Any) -> tuple[str, str]:
        bench_id = _extract_bench_id(event)
        if bench_id:
            if bench_id in self.records:
                return bench_id, "bench_id"
            return "", "bench_id_not_current_run"
        message_id = _extract_message_id(event)
        if message_id and message_id in self._message_to_bench:
            return self._message_to_bench[message_id], "message_id_map"
        seq = _extract_seq(event)
        if seq > 0 and seq in self._seq_to_bench:
            return self._seq_to_bench[seq], "seq_map"
        if message_id and message_id in self.records:
            return message_id, "message_id_record"
        if message_id:
            return "", "message_id_not_mapped"
        if seq > 0:
            return "", "seq_not_mapped"
        return "", "no_identity_fields"

    async def trace_handler_event(
        self,
        kind: str,
        event_name: str,
        event: Any,
        *,
        handle: BenchClientHandle | None = None,
        bench_id: str = "",
        reason: str = "",
    ) -> None:
        matched = bool(bench_id)
        async with self._condition:
            seen_key = f"{kind}_seen"
            matched_key = f"{kind}_matched"
            unmatched_key = f"{kind}_unmatched"
            self.handler_stats[seen_key] = int(self.handler_stats.get(seen_key) or 0) + 1
            self.handler_stats[matched_key if matched else unmatched_key] = (
                int(self.handler_stats.get(matched_key if matched else unmatched_key) or 0) + 1
            )
            if kind == "delivered":
                self.handler_stats["published_seen"] = int(self.handler_stats.get("published_seen") or 0) + 1
                published_key = "published_matched" if matched else "published_unmatched"
                self.handler_stats[published_key] = int(self.handler_stats.get(published_key) or 0) + 1
            known_message = _extract_message_id(event)
            known_seq = _extract_seq(event)
            self._trace.write(
                f"{kind}_{'matched' if matched else 'unmatched'}",
                event_name=event_name,
                receiver_aid=getattr(handle, "aid", ""),
                bench_id=bench_id,
                reason=reason,
                message_id=known_message,
                seq=known_seq,
                message_known=bool(known_message and known_message in self._message_to_bench),
                seq_known=bool(known_seq > 0 and known_seq in self._seq_to_bench),
                message_map_size=len(self._message_to_bench),
                seq_map_size=len(self._seq_to_bench),
                event_shape=_event_shape(event),
                event_sample=_event_sample(event),
            )

    async def mark_ack(self, bench_id: str, *, at: float, source: str = "event", result: Any = None) -> None:
        async with self._condition:
            record = self.records.setdefault(bench_id, {"bench_id": bench_id})
            sent_at = float(record.get("sent_at") or at)
            record["acked_at"] = at
            record["ack_ms"] = (at - sent_at) * 1000
            record["ack_source"] = source
            if result is not None:
                record["ack_result"] = result
            self._condition.notify_all()

    async def wait(self) -> None:
        deadline = time.perf_counter() + (self.timeout_ms / 1000)
        async with self._condition:
            while True:
                if self._done_enough():
                    return
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    return
                try:
                    await asyncio.wait_for(self._condition.wait(), timeout=remaining)
                except asyncio.TimeoutError:
                    return

    def _done_enough(self) -> bool:
        completed = 0
        for record in self.records.values():
            if record.get("send_ok") is False:
                completed += 1
            elif record.get("send_ok") and record.get("delivered_at"):
                completed += 1
        return completed >= self.expected


class BenchMatchTrace:
    def __init__(self, path: str = "", *, sample_limit: int = 200) -> None:
        self.path = path
        self.sample_limit = max(0, sample_limit)
        self._written = 0
        self._sampled = 0

    @classmethod
    def from_env(cls) -> "BenchMatchTrace":
        enabled = os.environ.get("AUN_BENCH_MATCH_TRACE", "").strip().lower()
        path = os.environ.get("AUN_BENCH_MATCH_TRACE_FILE", "").strip()
        if not path and enabled in {"1", "true", "yes", "on"}:
            path = str(Path.cwd() / f"aun-bench-match-trace-{int(time.time())}.jsonl")
        if not path:
            return cls("")
        try:
            sample_limit = int(os.environ.get("AUN_BENCH_MATCH_TRACE_SAMPLES", "200") or "200")
        except ValueError:
            sample_limit = 200
        return cls(path, sample_limit=sample_limit)

    def write(self, event: str, **fields: Any) -> None:
        if not self.path:
            return
        if event.endswith("_matched") and self.sample_limit and self._sampled >= self.sample_limit:
            return
        if event.endswith("_unmatched") or event.endswith("_matched"):
            self._sampled += 1
        record = {
            "t": round(time.time(), 6),
            "event": event,
            **fields,
        }
        try:
            path = Path(self.path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            self._written += 1
        except OSError:
            return


def _payload_text(prefix: str, index: int, size: int) -> str:
    base = f"{prefix}-{index}-"
    if size <= len(base):
        return base[:size]
    return base + ("x" * (size - len(base)))


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, int((percentile / 100) * len(ordered) + 0.999999))
    return ordered[min(rank - 1, len(ordered) - 1)]


def _round_ms(value: float) -> float:
    return round(value, 2)


_SEND_PERF_LINE_RE = re.compile(r"\[(?P<module>[^\]]+)\]\s+send_perf\s+(?P<fields>.*)")
_SEND_PERF_MODULES = ("gateway", "message", "group")
_SEND_PERF_PHASES: tuple[tuple[str, tuple[str, ...], tuple[str, ...], str], ...] = (
    ("gw_frontend", ("gw_client_parsed",), ("gw_dispatch_enter",), "first"),
    ("gw_backpressure", ("gw_signature_checked",), ("gw_service_backpressure_checked",), "first"),
    ("gw_dispatch", ("gw_dispatch_enter",), ("gw_dispatch_returned",), "first"),
    ("gw_service_write", ("gw_service_write_begin",), ("gw_service_write_done",), "first"),
    ("gw_service_wait", ("gw_service_write_done",), ("gw_response_received",), "first"),
    ("gw_response", ("gw_response_received",), ("gw_client_send_done",), "first"),
    ("msg_seq_alloc", ("msg_seq_alloc_begin",), ("msg_seq_alloc_done",), "first"),
    ("msg_wal_backlog_wait", ("msg_wal_backlog_wait_begin",), ("msg_wal_backlog_wait_done",), "first"),
    ("msg_wal_append", ("msg_wal_append_begin",), ("msg_wal_append_done",), "first"),
    ("msg_pending_reserve", ("msg_pending_reserve_begin",), ("msg_pending_reserve_done",), "first"),
    ("msg_pending_enqueue", ("msg_pending_enqueue_begin",), ("msg_pending_enqueue_done",), "first"),
    ("msg_push_dispatch", ("msg_push_dispatch_begin",), ("msg_push_dispatch_recipient_done", "msg_push_dispatch_self_done"), "last"),
    ("msg_push_dispatch_recipient", ("msg_push_dispatch_begin",), ("msg_push_dispatch_recipient_done",), "first"),
    ("msg_push_dispatch_self", ("msg_push_dispatch_recipient_done",), ("msg_push_dispatch_self_done",), "first"),
    ("msg_sync_insert_logical", ("msg_sync_insert_logical_begin",), ("msg_sync_insert_logical_done",), "first"),
    ("msg_sync_store_recipient", ("msg_sync_store_recipient_begin",), ("msg_sync_store_recipient_done",), "first"),
    ("msg_sync_store_self", ("msg_sync_store_self_begin",), ("msg_sync_store_self_done",), "first"),
)


class SendPerfLogTail:
    def __init__(self, root: str | None = None) -> None:
        self.root = str(root or "").strip() or None

    def snapshot(self) -> dict[str, int]:
        return {str(path): _safe_log_size(path) for path in _resolve_send_perf_log_paths(self.root)}

    def collect_since(self, snapshot: dict[str, int]) -> SendPerfCollected:
        paths = {str(path) for path in _resolve_send_perf_log_paths(self.root)}
        paths.update(str(path) for path in snapshot.keys())
        events: list[dict[str, Any]] = []
        log_paths = sorted(paths)
        for raw_path in log_paths:
            path = Path(raw_path)
            for line in _read_log_lines_since(path, int(snapshot.get(raw_path) or 0)):
                event = _parse_send_perf_line(line)
                if event is not None:
                    events.append(event)
        stage_durations, trace_totals, trace_count = _collect_send_perf_durations(events)
        summary = _build_send_perf_summary(
            stage_durations=stage_durations,
            trace_totals=trace_totals,
            trace_count=trace_count,
            event_count=len(events),
            log_paths=log_paths,
            enabled=True,
        )
        return SendPerfCollected(
            summary=summary,
            stage_durations=stage_durations,
            trace_totals=trace_totals,
            trace_count=trace_count,
            event_count=len(events),
            log_paths=log_paths,
        )


def _safe_log_size(path: Path) -> int:
    try:
        return int(path.stat().st_size)
    except OSError:
        return 0


def _resolve_send_perf_log_paths(root: str | None) -> list[Path]:
    roots = _send_perf_candidate_roots(root)
    paths: dict[str, Path] = {}
    for candidate in roots:
        for path in _send_perf_paths_under(candidate):
            try:
                key = str(path.resolve())
            except OSError:
                key = str(path)
            paths[key] = path
    return [paths[key] for key in sorted(paths)]


def _send_perf_candidate_roots(root: str | None) -> list[Path]:
    explicit = root or os.environ.get("AUN_BENCH_PERF_LOG_ROOT") or os.environ.get("AUN_BENCH_SEND_PERF_LOG_ROOT")
    if explicit:
        return [Path(explicit).expanduser()]

    roots: list[Path] = []
    instance_dir = os.environ.get("KITE_INSTANCE_DIR")
    if instance_dir:
        roots.append(Path(instance_dir).expanduser())
    module_data = os.environ.get("KITE_MODULE_DATA")
    if module_data:
        module_path = Path(module_data).expanduser()
        roots.append(module_path)
        roots.append(module_path.parent)

    workspace = os.environ.get("KITE_WORKSPACE")
    if workspace:
        roots.extend(_recent_kite_instance_roots(Path(workspace).expanduser()))
    roots.extend(_recent_kite_instance_roots(Path.home() / ".kite" / "workspace"))
    return _unique_paths(roots)


def _recent_kite_instance_roots(workspace: Path, *, limit: int = 5) -> list[Path]:
    if not workspace.exists() or not workspace.is_dir():
        return []
    scored: list[tuple[float, Path]] = []
    try:
        children = [path for path in workspace.iterdir() if path.is_dir()]
    except OSError:
        return []
    for child in children:
        latest_logs = []
        for module in _SEND_PERF_MODULES:
            latest_logs.extend((child / module / "log").glob("latest*.log"))
        if not latest_logs:
            continue
        try:
            score = max(path.stat().st_mtime for path in latest_logs)
        except OSError:
            score = 0.0
        scored.append((score, child))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [path for _, path in scored[:limit]]


def _unique_paths(paths: list[Path]) -> list[Path]:
    result: dict[str, Path] = {}
    for path in paths:
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        result[key] = path
    return list(result.values())


def _send_perf_paths_under(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    if not root.exists() or not root.is_dir():
        return []
    paths: list[Path] = []
    paths.extend(root.glob("latest*.log"))
    direct_log = root / "log"
    if direct_log.exists() and direct_log.is_dir():
        paths.extend(direct_log.glob("latest*.log"))
    for module in _SEND_PERF_MODULES:
        log_dir = root / module / "log"
        if log_dir.exists() and log_dir.is_dir():
            paths.extend(log_dir.glob("latest*.log"))
    return [path for path in _unique_paths(paths) if path.exists() and path.is_file()]


def _read_log_lines_since(path: Path, offset: int) -> list[str]:
    try:
        size = int(path.stat().st_size)
        start = offset if 0 <= offset <= size else 0
        with open(path, "rb") as handle:
            handle.seek(start)
            data = handle.read()
    except OSError:
        return []
    if not data:
        return []
    return data.decode("utf-8", errors="replace").splitlines()


def _parse_send_perf_line(line: str) -> dict[str, Any] | None:
    if "send_perf" not in line:
        return None
    match = _SEND_PERF_LINE_RE.search(line)
    if not match:
        return None
    fields: dict[str, str] = {}
    for item in str(match.group("fields") or "").split():
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        fields[key] = value
    trace_id = fields.get("id", "")
    stage = fields.get("stage", "")
    if not trace_id or not stage:
        return None
    elapsed_ms = _parse_float(fields.get("elapsed_ms"))
    delta_ms = _parse_float(fields.get("delta_ms"))
    return {
        "module": str(match.group("module") or ""),
        "id": trace_id,
        "stage": stage,
        "elapsed_ms": elapsed_ms,
        "delta_ms": delta_ms,
        "fields": fields,
    }


def _parse_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _collect_send_perf_durations(events: list[dict[str, Any]]) -> tuple[dict[str, list[float]], list[float], int]:
    by_trace: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        trace_id = str(event.get("id") or "")
        if trace_id:
            by_trace.setdefault(trace_id, []).append(event)

    stage_durations: dict[str, list[float]] = {}
    trace_totals: list[float] = []
    for trace_events in by_trace.values():
        ordered = sorted(trace_events, key=lambda item: float(item.get("elapsed_ms") or 0))
        max_elapsed = max((float(item.get("elapsed_ms") or 0) for item in ordered), default=0.0)
        if max_elapsed > 0:
            trace_totals.append(max_elapsed)
        for name, starts, ends, policy in _SEND_PERF_PHASES:
            durations = _pair_send_perf_phase_durations(ordered, starts=starts, ends=ends, policy=policy)
            if durations:
                stage_durations.setdefault(name, []).extend(durations)
    return stage_durations, trace_totals, len(by_trace)


def _pair_send_perf_phase_durations(
    events: list[dict[str, Any]],
    *,
    starts: tuple[str, ...],
    ends: tuple[str, ...],
    policy: str,
) -> list[float]:
    durations: list[float] = []
    for index, event in enumerate(events):
        if str(event.get("stage") or "") not in starts:
            continue
        start_ms = float(event.get("elapsed_ms") or 0)
        candidates = [
            (end_index, end_event)
            for end_index, end_event in enumerate(events[index + 1 :], start=index + 1)
            if str(end_event.get("stage") or "") in ends
            and float(end_event.get("elapsed_ms") or 0) >= start_ms
        ]
        if not candidates:
            continue
        end_index, end_event = candidates[-1] if policy == "last" else candidates[0]
        durations.append(max(0.0, float(end_event.get("elapsed_ms") or 0) - start_ms))
    return durations


def _build_send_perf_summary(
    *,
    stage_durations: dict[str, list[float]],
    trace_totals: list[float],
    trace_count: int,
    event_count: int,
    log_paths: list[str],
    enabled: bool,
    reason: str | None = None,
) -> dict[str, Any]:
    if not enabled:
        return {
            "enabled": False,
            "available": False,
            "reason": reason or "disabled",
            "trace_count": 0,
            "event_count": 0,
            "log_paths": [],
            "total_elapsed_ms": _latency_summary([]),
            "stages": {},
            "top_stages_by_p99": [],
        }
    total_stats = _latency_summary(trace_totals)
    stages: dict[str, dict[str, Any]] = {}
    for name, values in sorted(stage_durations.items()):
        stats: dict[str, Any] = dict(_latency_summary(values))
        stats["count"] = len(values)
        if total_stats.get("p50", 0) > 0:
            stats["p50_pct_of_total"] = round((float(stats["p50"]) / float(total_stats["p50"])) * 100, 2)
        if total_stats.get("p99", 0) > 0:
            stats["p99_pct_of_total"] = round((float(stats["p99"]) / float(total_stats["p99"])) * 100, 2)
        stages[name] = stats
    top = [
        {
            "stage": name,
            "p99": values.get("p99", 0),
            "p99_pct_of_total": values.get("p99_pct_of_total", 0),
            "count": values.get("count", 0),
        }
        for name, values in stages.items()
    ]
    top.sort(key=lambda item: (float(item.get("p99") or 0), int(item.get("count") or 0)), reverse=True)
    return {
        "enabled": True,
        "available": event_count > 0,
        "reason": reason or ("ok" if event_count > 0 else ("no_log_files" if not log_paths else "no_samples")),
        "trace_count": trace_count,
        "event_count": event_count,
        "log_paths": log_paths,
        "total_elapsed_ms": total_stats,
        "stages": stages,
        "top_stages_by_p99": top[:8],
    }


def _merge_send_perf_stage_values(target: dict[str, list[float]], source: dict[str, list[float]]) -> None:
    for name, values in source.items():
        target.setdefault(name, []).extend(float(value) for value in values)


def _format_send_perf_top(perf: Any) -> str:
    if not isinstance(perf, dict):
        return ""
    if not perf.get("enabled"):
        return "disabled"
    if not perf.get("available"):
        return str(perf.get("reason") or "no_samples")
    parts = []
    for item in perf.get("top_stages_by_p99", [])[:4]:
        parts.append(
            f"{item.get('stage')}={item.get('p99')}ms"
            f"({item.get('p99_pct_of_total', 0)}%)"
        )
    return ", ".join(parts)


def _validate_positive(name: str, value: int) -> None:
    if value < 1:
        raise typer.BadParameter(f"{name} 必须 >= 1")


def _validate_positive_float(name: str, value: float) -> None:
    if value <= 0:
        raise typer.BadParameter(f"{name} 必须 > 0")


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _resolve_aids(ctx: typer.Context, explicit_csv: str | None, *, role: str) -> list[str]:
    explicit = _split_csv(explicit_csv)
    if explicit:
        return explicit
    resolved = resolve_profile_config(ctx)
    current_aid = str(resolved.get("aid") or "").strip()
    if role == "sender" and current_aid:
        return [current_aid]
    identities = _list_local_identities(resolved)
    if role == "receiver":
        candidates = [aid for aid in identities if aid != current_aid]
        if candidates:
            return [candidates[0]]
        inferred = _infer_default_receiver_aid(current_aid)
        if inferred:
            return [inferred]
    raise typer.BadParameter(f"无法自动解析 {role} AID；请通过 --{role}s 指定")


def _infer_default_receiver_aid(current_aid: str) -> str:
    aid = str(current_aid or "").strip()
    if not aid:
        return ""
    if "@" in aid:
        name, suffix = aid.rsplit("@", 1)
        suffix = f"@{suffix}"
    elif "." in aid:
        name, suffix = aid.split(".", 1)
        suffix = f".{suffix}"
    else:
        name, suffix = aid, ""
    if not name:
        return ""
    match = re.match(r"^(.*?)(\d+)$", name)
    if match:
        prefix, digits = match.groups()
        return f"{prefix}{int(digits) + 1:0{len(digits)}d}{suffix}"
    return f"{name}-bench-receiver{suffix}"


def _list_local_identities(resolved: dict[str, Any]) -> list[str]:
    store = _make_quiet_aid_store(_bench_quiet_resolved(resolved))
    try:
        result = store.list()
        if not getattr(result, "ok", False) or not getattr(result, "data", None):
            return []
        identities = result.data.get("identities", []) if isinstance(result.data, dict) else []
        aids = []
        for item in identities:
            if isinstance(item, dict) and item.get("aid"):
                aids.append(str(item["aid"]))
        return aids
    finally:
        close = getattr(store, "close", None)
        if callable(close):
            close()


def _resolve_group_id(ctx: typer.Context, explicit: str | None) -> str:
    group_id = str(explicit or "").strip()
    if group_id:
        return group_id
    resolved = resolve_profile_config(ctx)
    group_id = str(resolved.get("active_group") or "").strip()
    if group_id:
        return group_id
    raise typer.BadParameter("无法自动解析 group_id；请先设置 active group 或通过 --group-id 指定")


async def _create_client(
    ctx: typer.Context,
    aid: str,
    *,
    role: str,
    background_sync: bool,
    on_created: Callable[[BenchClientHandle], None] | None = None,
) -> BenchClientHandle:
    resolved = _bench_quiet_resolved(resolve_profile_config(ctx))
    resolved["aid"] = aid
    store = _make_quiet_aid_store(resolved)
    loaded = store.load(aid)
    if (not getattr(loaded, "ok", False) or getattr(loaded, "data", None) is None) and _should_auto_register_receiver(ctx, aid, role):
        loaded = await _register_default_receiver_and_load(store, aid)
    if not getattr(loaded, "ok", False) or getattr(loaded, "data", None) is None:
        message = loaded.error.message if getattr(loaded, "error", None) else f"load identity failed: {aid}"
        raise RuntimeError(message)
    factory = AUNClientFactory
    if factory is None:
        from aun_core import AUNClient
        factory = AUNClient
    client = factory(loaded.data["aid"])
    _quiet_client_logger(client)
    setattr(client, "_aid_store", store)
    handle = BenchClientHandle(aid=aid, client=client, store=store, role=role)
    if on_created is not None:
        on_created(handle)
    await client.authenticate()
    options = {
        "auto_reconnect": background_sync,
        "background_sync": background_sync,
    }
    if not background_sync:
        options["heartbeat_interval"] = 0
    await asyncio.wait_for(client.connect(options), timeout=float(resolved.get("timeout") or 30))
    return handle


def _bench_quiet_resolved(resolved: dict[str, Any]) -> dict[str, Any]:
    quiet = dict(resolved)
    quiet["debug"] = False
    quiet["trace"] = "off"
    return quiet


def _make_quiet_aid_store(resolved: dict[str, Any]) -> Any:
    try:
        from aun_core import AIDStore
        from aun_core.logger import NullLogger

        return AIDStore(
            aun_path=resolved["aun_path"],
            encryption_seed=str(resolved.get("encryption_seed") or ""),
            debug=False,
            logger=NullLogger(),
        )
    except Exception:
        return make_aid_store(resolved)


def _quiet_client_logger(client: Any) -> None:
    try:
        from aun_core.logger import NullLogger

        setattr(client, "_log", NullLogger())
    except Exception:
        pass


def _should_auto_register_receiver(ctx: typer.Context, aid: str, role: str) -> bool:
    if role != "receiver":
        return False
    resolved = resolve_profile_config(ctx)
    inferred = _infer_default_receiver_aid(str(resolved.get("aid") or ""))
    return bool(inferred and aid == inferred)


async def _register_default_receiver_and_load(store: Any, aid: str) -> Any:
    register = getattr(store, "register", None)
    if not callable(register):
        return store.load(aid)
    registered = register(aid)
    if hasattr(registered, "__await__"):
        registered = await registered
    if not getattr(registered, "ok", False):
        error = getattr(registered, "error", None)
        code = str(getattr(error, "code", "") or "")
        if code == "IDENTITY_CONFLICT":
            raise RuntimeError(
                f"自动创建 receiver AID 失败: {aid} 已存在但本地无法加载私钥；请通过 --receivers 指定可用身份或先导入该身份"
            )
        message = getattr(error, "message", None) or f"register identity failed: {aid}"
        raise RuntimeError(f"自动创建 receiver AID 失败: {message}")
    return store.load(aid)


async def _build_fleet(
    ctx: typer.Context,
    config: E2EConfig,
    *,
    receiver_on_created: Callable[[BenchClientHandle], None] | None = None,
) -> tuple[list[BenchClientHandle], list[BenchClientHandle]]:
    senders = []
    receivers = []
    for aid in config.sender_aids or []:
        senders.append(await _create_client(ctx, aid, role="sender", background_sync=False))
    for aid in config.receiver_aids or []:
        receivers.append(await _create_client(ctx, aid, role="receiver", background_sync=True, on_created=receiver_on_created))
    return senders, receivers


async def run_e2e_scenario(ctx: typer.Context, config: E2EConfig) -> dict[str, Any]:
    if config.scenario == "connect":
        return await _run_connect_scenario(ctx, config)
    if config.scenario == "p2p-online":
        return await _run_message_scenario(ctx, config, group=False)
    if config.scenario == "group-online":
        return await _run_message_scenario(ctx, config, group=True)
    if config.scenario == "p2p-offline-pull":
        return await _run_offline_pull_scenario(ctx, config, group=False)
    if config.scenario == "group-offline-pull":
        return await _run_offline_pull_scenario(ctx, config, group=True)
    if config.scenario == "storage-vfs":
        return await _run_storage_vfs_scenario(ctx, config)
    if config.scenario == "group-fs":
        return await _run_group_fs_scenario(ctx, config)
    if config.scenario == "collab":
        return await _run_collab_scenario(ctx, config)
    if config.scenario == "notify-online":
        return await _run_notify_scenario(ctx, config)
    if config.scenario in {"service-proxy", "federation-p2p", "federation-group"}:
        return _skipped_external(config.scenario)
    return _not_implemented(config.scenario)


async def _run_connect_scenario(ctx: typer.Context, config: E2EConfig) -> dict[str, Any]:
    handles: list[BenchClientHandle] = []
    timings = []
    started_total = time.perf_counter()
    try:
        for aid in list(config.sender_aids or []):
            started = time.perf_counter()
            handles.append(await _create_client(ctx, aid, role="sender", background_sync=False))
            timings.append((time.perf_counter() - started) * 1000)
        for aid in list(config.receiver_aids or []):
            started = time.perf_counter()
            handles.append(await _create_client(ctx, aid, role="receiver", background_sync=False))
            timings.append((time.perf_counter() - started) * 1000)
        return {
            "scenario": "connect",
            "status": "ok",
            "client_shape": CLIENT_SHAPE,
            "connections": len(handles),
            "total_ms": int((time.perf_counter() - started_total) * 1000),
            "latency_ms": _latency_summary(timings),
        }
    finally:
        await _close_all(handles)


async def _run_receiver_drain_scenario(ctx: typer.Context, config: E2EConfig, *, group: bool) -> dict[str, Any]:
    receivers: list[BenchClientHandle] = []
    started_at = time.perf_counter()
    receiver_seq = _empty_receiver_seq_diagnostics()
    drain_result = _empty_receiver_drain_result(enabled=True)
    try:
        for aid in config.receiver_aids or []:
            receivers.append(await _create_client(ctx, aid, role="receiver", background_sync=False))
        drain_result = await _drain_receivers_before_run(receivers, config, group=group)
        receiver_seq = _collect_receiver_seq_diagnostics(
            receivers,
            group=group,
            group_id=config.group_id,
            handler_stats={},
            drain_result=drain_result,
        )
    finally:
        await _close_all(receivers)
    return {
        "scenario": "group-drain" if group else "p2p-drain",
        "method": "group.pull" if group else "message.pull",
        "status": str(drain_result.get("status") or "unknown"),
        "client_shape": CLIENT_SHAPE,
        "receivers": list(config.receiver_aids or []),
        "group_id": config.group_id,
        "total_ms": int((time.perf_counter() - started_at) * 1000),
        "receiver_seq": receiver_seq,
        "drain": drain_result,
    }


async def _run_message_scenario(ctx: typer.Context, config: E2EConfig, *, group: bool) -> dict[str, Any]:
    senders: list[BenchClientHandle] = []
    receivers: list[BenchClientHandle] = []
    recorder = E2ERecorder(expected=config.count, timeout_ms=config.timeout_ms)
    started_at = time.perf_counter()
    send_started_at = 0.0
    send_finished_at = 0.0
    receiver_seq = _empty_receiver_seq_diagnostics()
    drain_result = _empty_receiver_drain_result(enabled=config.drain_receivers)
    try:
        senders, receivers = await _build_fleet(
            ctx,
            config,
            receiver_on_created=lambda receiver: _install_receiver_handler(receiver, recorder, group=group),
        )
        _install_sender_ack_handlers(senders, recorder)
        drain_result = await _drain_receivers_before_run(receivers, config, group=group)
        recorder.reset_handler_stats()

        next_index = 0
        index_lock = asyncio.Lock()

        async def worker() -> None:
            nonlocal next_index
            while True:
                async with index_lock:
                    if next_index >= config.count:
                        return
                    index = next_index
                    next_index += 1
                sender = senders[index % len(senders)]
                if group:
                    target = str(config.group_id or "")
                    method = "group.send"
                else:
                    receiver = receivers[index % len(receivers)]
                    target = receiver.aid
                    method = "message.send"
                await _send_one(sender, recorder, config, index=index, method=method, target=target, group=group)

        worker_count = min(config.count, config.concurrency)
        send_started_at = time.perf_counter()
        await asyncio.gather(*(worker() for _ in range(worker_count)))
        send_finished_at = time.perf_counter()
        await recorder.wait()
        settle_result = await _settle_receivers_after_send(receivers, config, group=group)
        await recorder.wait()
        receiver_seq = _collect_receiver_seq_diagnostics(
            receivers,
            group=group,
            group_id=config.group_id,
            handler_stats=recorder.handler_stats,
            drain_result=_combine_drain_results(drain_result, settle_result),
        )
    finally:
        await _close_all(senders + receivers)

    result = _summarize_e2e(
        scenario=config.scenario,
        method="group.send" if group else "message.send",
        config=config,
        started_at=started_at,
        records=list(recorder.records.values()),
        errors=recorder.errors,
        receiver_seq=receiver_seq,
    )
    if send_started_at and send_finished_at:
        send_seconds = max(send_finished_at - send_started_at, 0.000001)
        ok_count = int(result.get("ok") or 0)
        delivered_count = int(result.get("delivered") or 0)
        acked_count = int(result.get("acked") or 0)
        result["send_window_seconds"] = round(send_seconds, 3)
        result["send_rps"] = round(ok_count / send_seconds, 2)
        result["delivered_rps"] = round(delivered_count / send_seconds, 2)
        result["acked_rps"] = round(acked_count / send_seconds, 2)
    return result


async def _run_message_load_stage(
    ctx: typer.Context,
    config: E2EConfig,
    *,
    group: bool,
    step_seconds: float,
) -> dict[str, Any]:
    senders: list[BenchClientHandle] = []
    receivers: list[BenchClientHandle] = []
    recorder = E2ERecorder(expected=config.count, timeout_ms=config.timeout_ms)
    started_at = time.perf_counter()
    sent_count = 0
    send_started_at = 0.0
    send_finished_at = 0.0
    stop_at = started_at + max(0.001, step_seconds)
    receiver_seq = _empty_receiver_seq_diagnostics()
    drain_result = _empty_receiver_drain_result(enabled=config.drain_receivers)
    try:
        senders, receivers = await _build_fleet(
            ctx,
            config,
            receiver_on_created=lambda receiver: _install_receiver_handler(receiver, recorder, group=group),
        )
        _install_sender_ack_handlers(senders, recorder)
        drain_result = await _drain_receivers_before_run(receivers, config, group=group)
        recorder.reset_handler_stats()

        next_index = 0
        index_lock = asyncio.Lock()

        async def worker() -> None:
            nonlocal next_index, sent_count
            while True:
                async with index_lock:
                    if next_index >= config.count or time.perf_counter() >= stop_at:
                        return
                    index = next_index
                    next_index += 1
                    sent_count = next_index
                sender = senders[index % len(senders)]
                if group:
                    target = str(config.group_id or "")
                    method = "group.send"
                else:
                    receiver = receivers[index % len(receivers)]
                    target = receiver.aid
                    method = "message.send"
                await _send_one(sender, recorder, config, index=index, method=method, target=target, group=group)

        worker_count = max(1, config.concurrency)
        send_started_at = time.perf_counter()
        await asyncio.gather(*(worker() for _ in range(worker_count)))
        send_finished_at = time.perf_counter()
        recorder.expected = sent_count
        await recorder.wait()
        settle_result = await _settle_receivers_after_send(receivers, config, group=group)
        await recorder.wait()
        receiver_seq = _collect_receiver_seq_diagnostics(
            receivers,
            group=group,
            group_id=config.group_id,
            handler_stats=recorder.handler_stats,
            drain_result=_combine_drain_results(drain_result, settle_result),
        )
    finally:
        await _close_all(senders + receivers)

    stage_config = E2EConfig(
        scenario=config.scenario,
        count=sent_count,
        concurrency=config.concurrency,
        payload_size=config.payload_size,
        encrypt=config.encrypt,
        prefix=config.prefix,
        sender_aids=config.sender_aids,
        receiver_aids=config.receiver_aids,
        group_id=config.group_id,
        timeout_ms=config.timeout_ms,
        ack_mode=config.ack_mode,
    )
    result = _summarize_e2e(
        scenario=config.scenario,
        method="group.send" if group else "message.send",
        config=stage_config,
        started_at=started_at,
        records=list(recorder.records.values()),
        errors=recorder.errors,
        receiver_seq=receiver_seq,
    )
    send_seconds = max(send_finished_at - send_started_at, 0.000001) if send_started_at and send_finished_at else max(step_seconds, 0.000001)
    result["send_window_seconds"] = round(send_seconds, 3)
    result["send_rps"] = round(sent_count / send_seconds, 2)
    result["observed_rps"] = result.get("rps", 0)
    result["stage_seconds"] = round(max(time.perf_counter() - started_at, 0.0), 3)
    result["load_window_seconds"] = round(step_seconds, 3)
    result["count_limit"] = config.count
    return result


async def _run_offline_pull_scenario(ctx: typer.Context, config: E2EConfig, *, group: bool) -> dict[str, Any]:
    senders: list[BenchClientHandle] = []
    receivers: list[BenchClientHandle] = []
    recorder = E2ERecorder(expected=config.count, timeout_ms=config.timeout_ms)
    started_at = time.perf_counter()
    try:
        for aid in config.sender_aids or []:
            senders.append(await _create_client(ctx, aid, role="sender", background_sync=False))
        next_index = 0
        index_lock = asyncio.Lock()

        async def worker() -> None:
            nonlocal next_index
            while True:
                async with index_lock:
                    if next_index >= config.count:
                        return
                    index = next_index
                    next_index += 1
                sender = senders[index % len(senders)]
                if group:
                    target = str(config.group_id or "")
                    method = "group.send"
                else:
                    receiver_aids = config.receiver_aids or []
                    target = receiver_aids[index % len(receiver_aids)]
                    method = "message.send"
                await _send_one(sender, recorder, config, index=index, method=method, target=target, group=group)

        await asyncio.gather(*(worker() for _ in range(min(config.count, config.concurrency))))

        for aid in config.receiver_aids or []:
            receivers.append(await _create_client(ctx, aid, role="receiver", background_sync=False))
        await _pull_until_seen(receivers, recorder, config, group=group)
        await recorder.wait()
    finally:
        await _close_all(senders + receivers)

    return _summarize_e2e(
        scenario=config.scenario,
        method="group.pull" if group else "message.pull",
        config=config,
        started_at=started_at,
        records=list(recorder.records.values()),
        errors=recorder.errors,
    )


async def _pull_until_seen(
    receivers: list[BenchClientHandle],
    recorder: E2ERecorder,
    config: E2EConfig,
    *,
    group: bool,
) -> None:
    deadline = time.perf_counter() + (config.timeout_ms / 1000)
    while time.perf_counter() < deadline:
        progressed = False
        for receiver in receivers:
            if group:
                result = await receiver.client.call("group.pull", {"group_id": config.group_id, "limit": 100})
            else:
                result = await receiver.client.call("message.pull", {"limit": 100})
            messages = _extract_messages(result)
            for message in messages:
                bench_id = _extract_bench_id(message)
                if not bench_id:
                    continue
                await recorder.mark_delivered(bench_id, message if isinstance(message, dict) else {}, at=time.perf_counter())
                seq = _extract_seq(message)
                if seq > 0:
                    if group:
                        ack_result = await receiver.client.call("group.ack_messages", {"group_id": config.group_id, "msg_seq": seq})
                    else:
                        ack_result = await receiver.client.call("message.ack", {"seq": seq})
                    await recorder.mark_ack(bench_id, at=time.perf_counter(), source="pull_ack_rpc", result=ack_result)
                progressed = True
        if recorder._done_enough():
            return
        if not progressed:
            await asyncio.sleep(0.05)


async def _settle_receivers_after_send(
    receivers: list[BenchClientHandle],
    config: E2EConfig,
    *,
    group: bool,
) -> dict[str, Any]:
    settle_ms = DEFAULT_SETTLE_DRAIN_TIMEOUT_MS if config.settle_ms is None else config.settle_ms
    if settle_ms <= 0:
        return _empty_receiver_drain_result(enabled=False)
    return await _drain_receivers_before_run(
        receivers,
        config,
        group=group,
        enabled=True,
        timeout_ms=settle_ms,
        purpose="settle",
    )


def _combine_drain_results(pre: dict[str, Any], settle: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(pre, dict):
        pre = _empty_receiver_drain_result(enabled=False)
    if not isinstance(settle, dict):
        settle = _empty_receiver_drain_result(enabled=False)
    combined = dict(settle if settle.get("enabled") else pre)
    combined["pre"] = dict(pre)
    combined["settle"] = dict(settle)
    combined["enabled"] = bool(pre.get("enabled") or settle.get("enabled"))
    if pre.get("status") == "timeout" or settle.get("status") == "timeout":
        combined["status"] = "timeout"
    elif settle.get("enabled"):
        combined["status"] = settle.get("status", combined.get("status", ""))
    else:
        combined["status"] = pre.get("status", combined.get("status", ""))
    for key in ("duration_ms", "pages", "raw_count", "published_count"):
        combined[key] = int(pre.get(key) or 0) + int(settle.get(key) or 0)
    receivers = []
    if isinstance(pre.get("receivers"), list):
        receivers.extend(pre["receivers"])
    if isinstance(settle.get("receivers"), list):
        receivers.extend(settle["receivers"])
    combined["receivers"] = receivers
    return combined


def _empty_receiver_drain_result(*, enabled: bool = True) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "status": "skipped" if not enabled else "not_started",
        "duration_ms": 0,
        "pages": 0,
        "raw_count": 0,
        "published_count": 0,
        "receivers": [],
    }


async def _drain_receivers_before_run(
    receivers: list[BenchClientHandle],
    config: E2EConfig,
    *,
    group: bool,
    enabled: bool | None = None,
    timeout_ms: int | None = None,
    purpose: str = "pre",
) -> dict[str, Any]:
    drain_enabled = config.drain_receivers if enabled is None else enabled
    if not drain_enabled:
        return _empty_receiver_drain_result(enabled=False)
    started = time.perf_counter()
    effective_timeout_ms = config.drain_timeout_ms if timeout_ms is None else timeout_ms
    deadline = (
        started + max(0.001, effective_timeout_ms / 1000)
        if effective_timeout_ms is not None and effective_timeout_ms > 0
        else None
    )
    per_receiver: dict[str, dict[str, Any]] = {
        receiver.aid: {
            "aid": receiver.aid,
            "pages": 0,
            "raw_count": 0,
            "published_count": 0,
            "last_raw_count": 0,
            "server_remaining": False,
            "server_current_seq": 0,
            "server_latest_seq": 0,
            "server_unread_count": 0,
            "purpose": purpose,
            "before": _receiver_seq_namespace_diagnostics(receiver, _drain_namespace(receiver, config, group=group)),
            "after": {},
        }
        for receiver in receivers
    }
    if not receivers:
        result = _empty_receiver_drain_result(enabled=True)
        result["status"] = "empty"
        return result

    status = "drained"
    while deadline is None or time.perf_counter() < deadline:
        progressed = False
        for receiver in receivers:
            params: dict[str, Any]
            if group:
                params = {
                    "group_id": config.group_id,
                    "limit": config.drain_limit,
                    "max_pages": config.drain_max_pages,
                }
                method = "group.pull"
            else:
                params = {
                    "limit": config.drain_limit,
                    "max_pages": config.drain_max_pages,
                }
                method = "message.pull"
            result = await receiver.client.call(method, params)
            messages = _extract_messages(result)
            raw_count = _extract_raw_count(result, messages)
            published_count = len(messages)
            item = per_receiver[receiver.aid]
            item["pages"] = int(item.get("pages") or 0) + 1
            item["raw_count"] = int(item.get("raw_count") or 0) + raw_count
            item["published_count"] = int(item.get("published_count") or 0) + published_count
            item["last_raw_count"] = raw_count
            _update_drain_server_state(item, result)
            if raw_count > 0 or published_count > 0 or bool(item.get("server_remaining")):
                progressed = True
        for receiver in receivers:
            _force_save_seq_tracker(receiver.client)
        if _all_receivers_drain_complete(receivers, per_receiver, config, group=group):
            status = "drained"
            break
        await asyncio.sleep(0 if progressed else 0.05)
    else:
        status = "timeout"

    for receiver in receivers:
        ns = _drain_namespace(receiver, config, group=group)
        per_receiver[receiver.aid]["after"] = _receiver_seq_namespace_diagnostics(receiver, ns)
    return {
        "enabled": True,
        "purpose": purpose,
        "status": status,
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "pages": sum(int(item.get("pages") or 0) for item in per_receiver.values()),
        "raw_count": sum(int(item.get("raw_count") or 0) for item in per_receiver.values()),
        "published_count": sum(int(item.get("published_count") or 0) for item in per_receiver.values()),
        "receivers": list(per_receiver.values()),
    }


def _extract_raw_count(result: Any, messages: list[Any]) -> int:
    if isinstance(result, dict):
        for key in ("raw_count", "count"):
            try:
                value = int(result.get(key) or 0)
            except (TypeError, ValueError):
                value = 0
            if value > 0:
                return value
    return len(messages)


def _pull_has_more(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    if result.get("has_more") is True:
        return True
    cursor = result.get("cursor")
    if isinstance(cursor, dict):
        if cursor.get("has_more") is True:
            return True
        unread = _safe_int(cursor.get("unread_count"))
        current = _safe_int(cursor.get("current_seq") or cursor.get("ack_seq"))
        latest = _safe_int(cursor.get("latest_seq"))
        if unread > 0:
            return True
        if latest > 0 and current > 0 and latest > current:
            return True
    latest = _safe_int(result.get("latest_seq"))
    server_ack = _safe_int(result.get("server_ack_seq") or result.get("ack_seq"))
    return latest > 0 and server_ack > 0 and latest > server_ack


def _update_drain_server_state(item: dict[str, Any], result: Any) -> None:
    if not isinstance(result, dict):
        item["server_remaining"] = False
        return
    cursor = result.get("cursor")
    if isinstance(cursor, dict):
        item["server_current_seq"] = _safe_int(cursor.get("current_seq") or cursor.get("ack_seq"))
        item["server_latest_seq"] = _safe_int(cursor.get("latest_seq"))
        item["server_unread_count"] = _safe_int(cursor.get("unread_count"))
    else:
        item["server_current_seq"] = _safe_int(result.get("server_ack_seq") or result.get("ack_seq"))
        item["server_latest_seq"] = _safe_int(result.get("latest_seq"))
        item["server_unread_count"] = 0
    item["server_remaining"] = _pull_has_more(result)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return default


def _drain_namespace(receiver: BenchClientHandle, config: E2EConfig, *, group: bool) -> str:
    return f"group:{config.group_id}" if group and config.group_id else f"p2p:{receiver.aid}"


def _all_receivers_drain_complete(
    receivers: list[BenchClientHandle],
    per_receiver: dict[str, dict[str, Any]],
    config: E2EConfig,
    *,
    group: bool,
) -> bool:
    for receiver in receivers:
        if bool(per_receiver.get(receiver.aid, {}).get("server_remaining")):
            return False
        ns = _drain_namespace(receiver, config, group=group)
        item = _receiver_seq_namespace_diagnostics(receiver, ns)
        contiguous = int(item.get("contiguous_seq") or 0)
        max_seen = int(item.get("max_seen_seq") or 0)
        pending_ordered = int(item.get("pending_ordered_count") or 0)
        pending_gaps = int(item.get("pending_gap_count") or 0)
        if pending_ordered > 0 or pending_gaps > 0:
            return False
        if max_seen > 0 and contiguous < max_seen:
            return False
    return True


def _force_save_seq_tracker(client: Any) -> None:
    save = getattr(client, "_save_seq_tracker_state", None)
    if not callable(save):
        return
    try:
        save()
    except Exception:
        return


def _extract_messages(result: Any) -> list[Any]:
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        messages = result.get("messages")
        if isinstance(messages, list):
            return messages
        items = result.get("items")
        if isinstance(items, list):
            return items
    return []


async def _run_storage_vfs_scenario(ctx: typer.Context, config: E2EConfig) -> dict[str, Any]:
    handles = []
    ops: list[dict[str, Any]] = []
    started_at = time.perf_counter()
    try:
        handles.append(await _create_client(ctx, (config.sender_aids or [""])[0], role="storage", background_sync=False))
        client = handles[0].client
        root = f"/bench/e2e/{uuid.uuid4().hex}"
        file_path = f"{root}/payload.txt"
        payload = b"bench"
        await _timed_op(ops, "storage.mkdir", lambda: client.storage.mkdir(root, parents=True))
        await _timed_op(ops, "storage.write_bytes", lambda: client.storage.write_bytes(file_path, payload, overwrite=True))
        await _timed_op(ops, "storage.read_bytes", lambda: client.storage.read_bytes(file_path))
        await _timed_op(ops, "storage.stat", lambda: client.storage.stat(file_path))
        await _timed_op(ops, "storage.list", lambda: client.storage.list(root))
        await _timed_op(ops, "storage.remove", lambda: client.storage.remove(root, recursive=True))
    finally:
        await _close_all(handles)
    return _summarize_ops("storage-vfs", started_at, ops)


async def _run_group_fs_scenario(ctx: typer.Context, config: E2EConfig) -> dict[str, Any]:
    if not config.group_id:
        return {"scenario": "group-fs", "status": "skipped", "reason": "missing group_id"}
    handles = []
    ops: list[dict[str, Any]] = []
    started_at = time.perf_counter()
    try:
        handles.append(await _create_client(ctx, (config.sender_aids or [""])[0], role="group-fs", background_sync=False))
        client = handles[0].client
        root = f"/bench/e2e/{uuid.uuid4().hex}"
        await _timed_op(ops, "group.fs.mkdir", lambda: client.group.fs.mkdir(root, parents=True, group_id=config.group_id))
        await _timed_op(ops, "group.fs.stat", lambda: client.group.fs.stat(root, group_id=config.group_id))
        await _timed_op(ops, "group.fs.ls", lambda: client.group.fs.ls(root, group_id=config.group_id))
        await _timed_op(ops, "group.fs.rm", lambda: client.group.fs.rm(root, recursive=True, force=True, group_id=config.group_id))
    finally:
        await _close_all(handles)
    return _summarize_ops("group-fs", started_at, ops)


async def _run_collab_scenario(ctx: typer.Context, config: E2EConfig) -> dict[str, Any]:
    handles = []
    ops: list[dict[str, Any]] = []
    started_at = time.perf_counter()
    try:
        sender_aid = (config.sender_aids or [""])[0]
        handles.append(await _create_client(ctx, sender_aid, role="collab", background_sync=False))
        client = handles[0].client
        root = f"{sender_aid}:/bench/e2e/collab-{uuid.uuid4().hex}"
        doc = "bench.md"
        await _timed_op(ops, "collab.create", lambda: client.collab.create(root, doc, "bench"))
        show = await _timed_op(ops, "collab.show", lambda: client.collab.show(root, doc))
        onto = 1
        if isinstance(show, dict):
            try:
                onto = int(show.get("version") or 1)
            except (TypeError, ValueError):
                onto = 1
        await _timed_op(ops, "collab.commit", lambda: client.collab.commit(root, doc, "bench update", onto, message="bench"))
        await _timed_op(ops, "collab.log", lambda: client.collab.log(root, doc))
    finally:
        await _close_all(handles)
    return _summarize_ops("collab", started_at, ops)


async def _run_notify_scenario(ctx: typer.Context, config: E2EConfig) -> dict[str, Any]:
    handles = []
    ops: list[dict[str, Any]] = []
    started_at = time.perf_counter()
    try:
        sender_aid = (config.sender_aids or [""])[0]
        target_aid = (config.receiver_aids or [""])[0]
        handles.append(await _create_client(ctx, sender_aid, role="notify-sender", background_sync=False))
        if target_aid:
            handles.append(await _create_client(ctx, target_aid, role="notify-receiver", background_sync=True))
        client = handles[0].client
        payload = {"type": "bench.notify", "bench_id": f"notify-{uuid.uuid4().hex}", "t_send": time.perf_counter()}
        await _timed_op(
            ops,
            "notify.online",
            lambda: client.notify("event/app.bench", payload, to=target_aid or None, group_id=None if target_aid else config.group_id, ttl_ms=5000),
        )
    finally:
        await _close_all(handles)
    return _summarize_ops("notify-online", started_at, ops)


async def _timed_op(ops: list[dict[str, Any]], name: str, call: Callable[[], Any]) -> Any:
    started = time.perf_counter()
    try:
        result = call()
        if hasattr(result, "__await__"):
            result = await result
        ops.append({"name": name, "ok": True, "ms": (time.perf_counter() - started) * 1000})
        return result
    except Exception as exc:
        ops.append({"name": name, "ok": False, "ms": (time.perf_counter() - started) * 1000, "error": str(exc) or type(exc).__name__})
        raise


def _summarize_ops(scenario: str, started_at: float, ops: list[dict[str, Any]]) -> dict[str, Any]:
    ok = [op for op in ops if op.get("ok")]
    failed = [op for op in ops if not op.get("ok")]
    latencies = [float(op.get("ms") or 0) for op in ok]
    return {
        "scenario": scenario,
        "status": "ok" if not failed else "failed",
        "client_shape": CLIENT_SHAPE,
        "ok": len(ok),
        "failed": len(failed),
        "total_ms": int((time.perf_counter() - started_at) * 1000),
        "latency_ms": _latency_summary(latencies),
        "operations": ops,
        "errors": [{"message": str(op.get("error")), "operation": op.get("name")} for op in failed],
    }


def _skipped_external(scenario: str) -> dict[str, Any]:
    env_key = {
        "service-proxy": "AUN_BENCH_SERVICE_PROXY",
        "federation-p2p": "AUN_BENCH_FEDERATION",
        "federation-group": "AUN_BENCH_FEDERATION",
    }.get(scenario, "")
    if env_key and os.environ.get(env_key):
        return _not_implemented(scenario)
    return {
        "scenario": scenario,
        "status": "skipped",
        "reason": "需要额外 holder/visitor 或双域 federation 环境；设置对应环境后在后续阶段接入",
    }


async def _send_one(
    sender: BenchClientHandle,
    recorder: E2ERecorder,
    config: E2EConfig,
    *,
    index: int,
    method: str,
    target: str,
    group: bool,
) -> None:
    bench_id = f"{config.prefix}-{uuid.uuid4().hex}-{index}"
    sent_at = time.perf_counter()
    payload = {
        "type": "bench.e2e",
        "bench_id": bench_id,
        "bench_scenario": config.scenario,
        "index": index,
        "t_send": sent_at,
        "text": _payload_text(config.prefix, index, config.payload_size),
    }
    await recorder.start(bench_id, sent_at=sent_at, sender=sender.aid, target=target)
    params: dict[str, Any]
    if group:
        params = {"group_id": target, "payload": payload, "encrypt": config.encrypt, "message_id": bench_id}
    else:
        params = {"to": target, "payload": payload, "encrypt": config.encrypt, "message_id": bench_id}
    if not config.persist:
        # 临时消息：persist_required=False，但保持 delivery_mode=fanout
        # 这样消息会缓存到 EphemeralBuffer，可以 pull，但不写数据库
        params["persist_required"] = False
        # 注意：不设置 delivery_mode="queue"，因为 queue 模式需要接收端在线
    started = time.perf_counter()
    try:
        result = await sender.client.call(method, params)
        await recorder.mark_send_result(
            bench_id,
            ok=True,
            at=time.perf_counter(),
            ms=(time.perf_counter() - started) * 1000,
            result=result,
        )
    except Exception as exc:
        await recorder.mark_send_result(
            bench_id,
            ok=False,
            at=time.perf_counter(),
            ms=(time.perf_counter() - started) * 1000,
            error=str(exc) or type(exc).__name__,
        )


def _install_receiver_handlers(receivers: list[BenchClientHandle], recorder: E2ERecorder, *, group: bool) -> None:
    for receiver in receivers:
        _install_receiver_handler(receiver, recorder, group=group)


def _install_receiver_handler(receiver: BenchClientHandle, recorder: E2ERecorder, *, group: bool) -> None:
    event_name = "group.message_created" if group else "message.received"
    raw_event_names = (
        ("_raw.group.message_created", "_raw.group.v2.message_created")
        if group
        else ("_raw.message.received", "_raw.peer.v2.message_received")
    )

    async def raw_handler(event: Any, *, handle: BenchClientHandle = receiver, raw_event_name: str = "") -> None:
        bench_id, reason = recorder.resolve_bench_id_with_reason(event)
        await recorder.trace_handler_event("raw", raw_event_name, event, handle=handle, bench_id=bench_id, reason=reason)
        if not bench_id:
            return
        await recorder.mark_raw_received(bench_id, event if isinstance(event, dict) else {}, at=time.perf_counter())

    for raw_event_name in raw_event_names:
        async def bound_raw_handler(event: Any, *, handle: BenchClientHandle = receiver, name: str = raw_event_name) -> None:
            await raw_handler(event, handle=handle, raw_event_name=name)

        receiver.client.on(raw_event_name, bound_raw_handler)

    async def handler(event: Any, *, handle: BenchClientHandle = receiver) -> None:
        bench_id, reason = recorder.resolve_bench_id_with_reason(event)
        await recorder.trace_handler_event("delivered", event_name, event, handle=handle, bench_id=bench_id, reason=reason)
        if not bench_id:
            return
        await recorder.mark_delivered(bench_id, event if isinstance(event, dict) else {}, at=time.perf_counter())

    receiver.client.on(event_name, handler)


def _install_sender_ack_handlers(senders: list[BenchClientHandle], recorder: E2ERecorder) -> None:
    for sender in senders:
        async def handler(event: Any) -> None:
            bench_id = _extract_bench_id(event)
            if bench_id:
                await recorder.mark_ack(bench_id, at=time.perf_counter(), source="sender_event", result=event)

        sender.client.on("message.ack", handler)


def _extract_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    payload = value.get("payload")
    if isinstance(payload, dict):
        return payload
    return value


def _extract_bench_id(value: Any) -> str:
    payload = _extract_payload(value)
    for container in (payload, value if isinstance(value, dict) else {}):
        raw = container.get("bench_id") if isinstance(container, dict) else None
        if raw:
            return str(raw)
    return _find_bench_id(value, depth=4)


def _extract_message_id(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    for container in (
        value,
        value.get("payload") if isinstance(value.get("payload"), dict) else {},
        value.get("aad") if isinstance(value.get("aad"), dict) else {},
    ):
        if not isinstance(container, dict):
            continue
        for key in ("message_id", "logical_message_id", "mid", "id"):
            raw = container.get(key)
            if raw:
                return str(raw)
    return ""


def _find_bench_id(value: Any, *, depth: int) -> str:
    if depth <= 0:
        return ""
    if isinstance(value, dict):
        raw = value.get("bench_id")
        if raw:
            return str(raw)
        for key in ("payload", "aad", "plaintext", "message", "data", "envelope"):
            found = _find_bench_id(value.get(key), depth=depth - 1)
            if found:
                return found
        for item in value.values():
            found = _find_bench_id(item, depth=depth - 1)
            if found:
                return found
    elif isinstance(value, list):
        for item in value[:8]:
            found = _find_bench_id(item, depth=depth - 1)
            if found:
                return found
    return ""


def _extract_seq(value: Any) -> int:
    if not isinstance(value, dict):
        return 0
    for key in ("seq", "msg_seq", "ack_seq", "up_to_seq"):
        try:
            parsed = int(value.get(key) or 0)
        except (TypeError, ValueError):
            parsed = 0
        if parsed > 0:
            return parsed
    return 0


def _event_shape(value: Any, *, depth: int = 2) -> Any:
    if depth <= 0:
        return type(value).__name__
    if isinstance(value, dict):
        shape: dict[str, Any] = {"type": "dict", "keys": sorted(str(key) for key in value.keys())[:40]}
        for key in ("payload", "aad", "envelope", "message", "data"):
            nested = value.get(key)
            if isinstance(nested, (dict, list)):
                shape[key] = _event_shape(nested, depth=depth - 1)
        return shape
    if isinstance(value, list):
        return {
            "type": "list",
            "len": len(value),
            "first": _event_shape(value[0], depth=depth - 1) if value else None,
        }
    return type(value).__name__


def _event_sample(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"type": type(value).__name__}
    sample: dict[str, Any] = {}
    for key in (
        "message_id", "logical_message_id", "id",
        "seq", "msg_seq", "up_to_seq", "ack_seq",
        "from", "from_aid", "sender_aid", "to", "to_aid",
        "group_id", "device_id", "slot_id", "encrypted", "version", "type",
    ):
        if key in value:
            sample[key] = _short_value(value.get(key))
    for nested_key in ("payload", "aad"):
        nested = value.get(nested_key)
        if isinstance(nested, dict):
            nested_sample = {}
            for key in (
                "bench_id", "message_id", "logical_message_id", "id",
                "seq", "type", "version", "from", "to", "group_id",
            ):
                if key in nested:
                    nested_sample[key] = _short_value(nested.get(key))
            nested_sample["_keys"] = sorted(str(key) for key in nested.keys())[:30]
            sample[nested_key] = nested_sample
    envelope_json = value.get("envelope_json")
    if isinstance(envelope_json, str) and envelope_json:
        sample["envelope_json_len"] = len(envelope_json)
        try:
            envelope = json.loads(envelope_json)
        except (json.JSONDecodeError, TypeError):
            envelope = None
        if isinstance(envelope, dict):
            sample["envelope_json"] = _event_sample(envelope)
    return sample


def _short_value(value: Any) -> Any:
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    text = str(value)
    if len(text) <= 160:
        return text
    return text[:157] + "..."


def _latency_summary(values: list[float]) -> dict[str, float]:
    return {
        "min": _round_ms(min(values)) if values else 0.0,
        "avg": _round_ms(sum(values) / len(values)) if values else 0.0,
        "p50": _round_ms(_percentile(values, 50)),
        "p95": _round_ms(_percentile(values, 95)),
        "p99": _round_ms(_percentile(values, 99)),
        "max": _round_ms(max(values)) if values else 0.0,
    }


def _summarize_e2e(
    *,
    scenario: str,
    method: str,
    config: E2EConfig,
    started_at: float,
    records: list[dict[str, Any]],
    errors: list[str],
    receiver_seq: dict[str, Any] | None = None,
) -> dict[str, Any]:
    total_seconds = max(time.perf_counter() - started_at, 0.000001)
    ok_records = [r for r in records if r.get("send_ok") is True]
    failed_records = [r for r in records if r.get("send_ok") is False]
    raw_records = [r for r in ok_records if r.get("raw_received_at")]
    delivered_records = [r for r in ok_records if r.get("delivered_at")]
    acked_records = [r for r in ok_records if r.get("acked_at")]
    error_counts = Counter(str(r.get("error") or "unknown error") for r in failed_records)
    error_counts.update(str(e) for e in errors)
    send_latencies = [float(r["send_rtt_ms"]) for r in ok_records if "send_rtt_ms" in r]
    raw_latencies = [float(r["raw_received_ms"]) for r in raw_records if "raw_received_ms" in r]
    raw_to_delivery_latencies = [float(r["raw_to_delivery_ms"]) for r in delivered_records if "raw_to_delivery_ms" in r]
    delivery_latencies = [float(r["delivery_ms"]) for r in delivered_records if "delivery_ms" in r]
    ack_latencies = [float(r["ack_ms"]) for r in acked_records if "ack_ms" in r]
    signals = _backpressure_signals(error_counts)
    acked_rps = round(len(acked_records) / total_seconds, 2)
    receiver_seq = receiver_seq if isinstance(receiver_seq, dict) else _empty_receiver_seq_diagnostics()
    receiver_seq_totals = receiver_seq.get("totals", {}) if isinstance(receiver_seq.get("totals"), dict) else {}
    handler_stats = receiver_seq.get("bench_handlers", {}) if isinstance(receiver_seq.get("bench_handlers"), dict) else {}
    ordered_gap_blocked = int(receiver_seq_totals.get("ordered_gap_blocked") or 0)
    ok_count = len(ok_records)
    delivered_count = len(delivered_records)
    acked_count = len(acked_records)
    observed_rps = round(ok_count / total_seconds, 2)
    return {
        "scenario": scenario,
        "method": method,
        "status": "ok" if not failed_records else "degraded",
        "client_shape": CLIENT_SHAPE,
        "count": config.count,
        "concurrency": config.concurrency,
        "senders": config.sender_aids or [],
        "receivers": config.receiver_aids or [],
        "group_id": config.group_id,
        "payload_size": config.payload_size,
        "encrypt": config.encrypt,
        "ok": ok_count,
        "failed": len(failed_records),
        "raw_received": len(raw_records),
        "delivered": delivered_count,
        "acked": acked_count,
        "raw_to_delivered_gap": max(0, len(raw_records) - delivered_count),
        "ordered_gap_blocked": ordered_gap_blocked,
        "receiver_seq": receiver_seq,
        "bench_handlers": handler_stats,
        "ok_to_raw_gap": max(0, len(ok_records) - len(raw_records)),
        "lost": max(0, ok_count - delivered_count),
        "unacked": max(0, ok_count - acked_count),
        "total_ms": int(total_seconds * 1000),
        "rps": observed_rps,
        "observed_rps": observed_rps,
        "send_rps": observed_rps,
        "delivered_rps": round(delivered_count / total_seconds, 2),
        "acked_rps": acked_rps,
        "rates": _rates(
            attempted=config.count,
            ok=len(ok_records),
            failed=len(failed_records),
            delivered=len(delivered_records),
            acked=len(acked_records),
            lost=max(0, len(ok_records) - len(delivered_records)),
            unacked=max(0, len(ok_records) - len(acked_records)),
        ),
        "latency_ms": {
            "send_rtt": _latency_summary(send_latencies),
            "raw_received": _latency_summary(raw_latencies),
            "raw_to_delivery": _latency_summary(raw_to_delivery_latencies),
            "delivery": _latency_summary(delivery_latencies),
            "ack": _latency_summary(ack_latencies),
        },
        "errors": [
            {"message": message, "count": error_counts[message]}
            for message in sorted(error_counts, key=lambda item: (-error_counts[item], item))[:5]
        ],
        "backpressure": {
            "signals": signals,
            "detected": bool(signals),
        },
    }


def _backpressure_signals(error_counts: Counter[str]) -> list[dict[str, Any]]:
    signals = []
    for message, count in error_counts.items():
        lowered = message.lower()
        kind = ""
        if "-32429" in lowered or "backpressure" in lowered or "queue full" in lowered:
            kind = "server_backpressure"
        elif "rate_limit" in lowered or "rate limit" in lowered or "too many" in lowered:
            kind = "rate_limit"
        elif "rpc queue timeout" in lowered:
            kind = "client_rpc_queue"
        elif "timeout" in lowered:
            kind = "timeout"
        if kind:
            signals.append({"type": kind, "message": message, "count": count})
    return signals


def _rates(
    *,
    attempted: int,
    ok: int,
    failed: int,
    delivered: int,
    acked: int,
    lost: int,
    unacked: int,
) -> dict[str, float]:
    total = max(1, attempted)
    ok_total = max(1, ok)
    return {
        "success": round(ok / total, 6),
        "failure": round(failed / total, 6),
        "delivery": round(delivered / ok_total, 6),
        "ack": round(acked / ok_total, 6),
        "loss": round(lost / ok_total, 6),
        "unacked": round(unacked / ok_total, 6),
    }


def _not_implemented(scenario: str) -> dict[str, Any]:
    return {
        "scenario": scenario,
        "status": "not_implemented",
        "reason": "该 happy path 场景将在后续阶段接入同一 runner",
    }


async def _close_all(handles: list[BenchClientHandle]) -> None:
    await asyncio.gather(*(handle.close() for handle in handles), return_exceptions=True)


def _empty_receiver_seq_diagnostics() -> dict[str, Any]:
    return {
        "namespaces": [],
        "totals": {
            "pending_ordered_count": 0,
            "pending_gap_count": 0,
            "received_seq_count": 0,
            "ordered_gap_blocked": 0,
        },
        "push_processing": {},
        "auto_ack": {},
        "bench_handlers": {},
        "drain": _empty_receiver_drain_result(enabled=True),
    }


def _collect_receiver_seq_diagnostics(
    receivers: list[BenchClientHandle],
    *,
    group: bool,
    group_id: str | None,
    handler_stats: dict[str, int] | None = None,
    drain_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for handle in receivers:
        client = handle.client
        namespaces = [f"group:{group_id}"] if group and group_id else [f"p2p:{handle.aid}"]
        for ns in namespaces:
            items.append(_receiver_seq_namespace_diagnostics(handle, ns))
    totals = {
        "pending_ordered_count": sum(int(item.get("pending_ordered_count") or 0) for item in items),
        "pending_gap_count": sum(int(item.get("pending_gap_count") or 0) for item in items),
        "received_seq_count": sum(int(item.get("received_seq_count") or 0) for item in items),
        "ordered_gap_blocked": sum(int(item.get("ordered_gap_blocked") or 0) for item in items),
    }
    push_processing = _merge_push_processing_stats(receivers)
    auto_ack = _merge_auto_ack_stats(receivers)
    return {
        "namespaces": items,
        "totals": totals,
        "push_processing": push_processing,
        "auto_ack": auto_ack,
        "bench_handlers": _copy_int_stats(handler_stats or {}),
        "drain": dict(drain_result) if isinstance(drain_result, dict) else _empty_receiver_drain_result(enabled=True),
    }


def _receiver_seq_namespace_diagnostics(handle: BenchClientHandle, ns: str) -> dict[str, Any]:
    client = handle.client
    seq_tracker = getattr(client, "_seq_tracker", None)
    pending_map = _safe_call(getattr(client, "_pending_ordered", None), default={})
    if not isinstance(pending_map, dict):
        pending_map = {}
    pending = pending_map.get(ns) if isinstance(pending_map.get(ns), dict) else {}
    stats = getattr(client, "_ordered_gap_block_stats", {})
    gap_stats = stats.get(ns, {}) if isinstance(stats, dict) else {}
    state = getattr(seq_tracker, "_trackers", {}).get(ns) if seq_tracker is not None else None
    pending_gaps = getattr(state, "pending_gaps", {}) if state is not None else {}
    received_seqs = getattr(state, "received_seqs", set()) if state is not None else set()
    pending_keys = sorted(int(key) for key in pending.keys()) if pending else []
    return {
        "aid": handle.aid,
        "role": handle.role,
        "namespace": ns,
        "contiguous_seq": _safe_call(getattr(seq_tracker, "get_contiguous_seq", None), ns, default=0),
        "max_seen_seq": _safe_call(getattr(seq_tracker, "get_max_seen_seq", None), ns, default=0),
        "pending_ordered_count": len(pending_keys),
        "pending_ordered_min": pending_keys[0] if pending_keys else 0,
        "pending_ordered_max": pending_keys[-1] if pending_keys else 0,
        "pending_gap_count": len(pending_gaps) if isinstance(pending_gaps, dict) else 0,
        "pending_gaps_sample": [
            {"start": int(start), "end": int(end)}
            for start, end in list(pending_gaps.keys())[:3]
        ] if isinstance(pending_gaps, dict) else [],
        "received_seq_count": len(received_seqs) if isinstance(received_seqs, set) else 0,
        "ordered_gap_blocked": int(gap_stats.get("count") or 0) if isinstance(gap_stats, dict) else 0,
        "last_blocked_seq": int(gap_stats.get("last_seq") or 0) if isinstance(gap_stats, dict) else 0,
        "last_blocked_contiguous_seq": int(gap_stats.get("last_contiguous_seq") or 0) if isinstance(gap_stats, dict) else 0,
        "push_processing": _copy_push_processing_stats(getattr(client, "_push_processing_stats", {})),
        "auto_ack": _copy_int_stats(getattr(client, "_auto_ack_stats", {})),
    }


def _merge_push_processing_stats(handles: list[BenchClientHandle]) -> dict[str, dict[str, int]]:
    merged: dict[str, dict[str, int]] = {}
    for handle in handles:
        stats = _copy_push_processing_stats(getattr(handle.client, "_push_processing_stats", {}))
        for scope, values in stats.items():
            target = merged.setdefault(scope, {})
            for key, value in values.items():
                target[key] = int(target.get(key) or 0) + int(value or 0)
    return merged


def _copy_push_processing_stats(value: Any) -> dict[str, dict[str, int]]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, dict[str, int]] = {}
    for scope, section in value.items():
        if not isinstance(section, dict):
            continue
        result[str(scope)] = {str(key): int(val or 0) for key, val in section.items()}
    return result


def _merge_auto_ack_stats(handles: list[BenchClientHandle]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for handle in handles:
        stats = _copy_int_stats(getattr(handle.client, "_auto_ack_stats", {}))
        for key, value in stats.items():
            merged[key] = int(merged.get(key) or 0) + int(value or 0)
    return merged


def _copy_int_stats(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    return {str(key): int(val or 0) for key, val in value.items()}


def _safe_call(func: Any, *args: Any, default: Any = None) -> Any:
    if not callable(func):
        return default
    try:
        return func(*args)
    except Exception:
        return default


async def run_autoscale(ctx: typer.Context, config: AutoscaleConfig) -> dict[str, Any]:
    steps = []
    baseline_p99: float | None = None
    previous_rps: float | None = None
    knee: dict[str, Any] = {"found": False}
    soft_knee: dict[str, Any] = {"found": False}
    concurrency = config.start
    perf_tail = SendPerfLogTail(config.perf_log_root) if config.perf_trace else None
    perf_stage_totals: dict[str, list[float]] = {}
    perf_trace_totals: list[float] = []
    perf_event_count = 0
    perf_trace_count = 0
    perf_log_paths: set[str] = set()
    while concurrency <= config.max_concurrency:
        scenario_config = E2EConfig(
            scenario=config.scenario,
            count=config.count,
            concurrency=concurrency,
            payload_size=config.payload_size,
            encrypt=config.encrypt,
            prefix=config.prefix,
            sender_aids=config.sender_aids,
            receiver_aids=config.receiver_aids,
            group_id=config.group_id,
            timeout_ms=config.timeout_ms,
            drain_receivers=config.drain_receivers,
            drain_timeout_ms=config.drain_timeout_ms,
            drain_limit=config.drain_limit,
            drain_max_pages=config.drain_max_pages,
            settle_ms=config.settle_ms,
        )
        perf_snapshot = perf_tail.snapshot() if perf_tail is not None else {}
        result = await _run_autoscale_stage(ctx, scenario_config, config)
        step = dict(result)
        if perf_tail is not None:
            collected = perf_tail.collect_since(perf_snapshot)
            step["send_perf"] = collected.summary
            _merge_send_perf_stage_values(perf_stage_totals, collected.stage_durations)
            perf_trace_totals.extend(collected.trace_totals)
            perf_event_count += collected.event_count
            perf_trace_count += collected.trace_count
            perf_log_paths.update(collected.log_paths)
        else:
            step["send_perf"] = _build_send_perf_summary(
                stage_durations={},
                trace_totals=[],
                trace_count=0,
                event_count=0,
                log_paths=[],
                enabled=False,
            )
        step["concurrency"] = concurrency
        _enrich_autoscale_step(step, previous_rps=previous_rps, baseline_p99=baseline_p99, config=config)
        steps.append(step)
        soft_condition = _soft_knee_condition(step, previous_rps=previous_rps, config=config)
        if soft_condition and not soft_knee.get("found"):
            soft_knee = {
                "found": True,
                "reason": str(soft_condition.get("reason") or "rps_plateau"),
                "concurrency": concurrency,
                "rps": step.get("send_rps", step.get("rps", 0)),
                "observed_rps": step.get("observed_rps", step.get("rps", 0)),
                "p99_ms": _stage_p99(step, scope=config.p99_scope),
                "condition": soft_condition,
            }
        hard_condition = _hard_stop_condition(step, baseline_p99=baseline_p99, config=config)
        condition = hard_condition or (soft_condition if config.stop_on_plateau else None)
        p99 = _stage_p99(step, scope=config.p99_scope)
        if baseline_p99 is None and p99 > 0:
            baseline_p99 = p99
        if condition:
            reason = str(condition.get("reason") or condition.get("type") or "knee")
            knee = {
                "found": True,
                "reason": reason,
                "concurrency": concurrency,
                "rps": step.get("send_rps", step.get("rps", 0)),
                "observed_rps": step.get("observed_rps", step.get("rps", 0)),
                "p99_ms": p99,
                "condition": condition,
            }
            break
        previous_rps = _step_send_rps(step)
        if config.factor > 1:
            concurrency *= config.factor
        else:
            concurrency += max(1, config.step)
    peak = max(steps, key=_step_send_rps, default={})
    stop_reason = str(knee.get("reason") or "") if knee.get("found") else "max_concurrency_reached"
    summary = _autoscale_summary(steps, p99_scope=config.p99_scope)
    summary["send_perf"] = _build_send_perf_summary(
        stage_durations=perf_stage_totals,
        trace_totals=perf_trace_totals,
        trace_count=perf_trace_count,
        event_count=perf_event_count,
        log_paths=sorted(perf_log_paths),
        enabled=config.perf_trace,
    )
    return {
        "scenario": config.scenario,
        "client_shape": CLIENT_SHAPE,
        "mode": "continuous_ramp",
        "stop_reason": stop_reason,
        "steps": steps,
        "summary": summary,
        "soft_knee": soft_knee,
        "knee": knee,
        "peak": {
            "concurrency": peak.get("concurrency", 0),
            "rps": peak.get("send_rps", peak.get("rps", 0)),
            "send_rps": peak.get("send_rps", peak.get("rps", 0)),
            "observed_rps": peak.get("observed_rps", peak.get("rps", 0)),
            "delivered_rps": peak.get("delivered_rps", 0),
            "acked_rps": peak.get("acked_rps", 0),
            "p99_ms": _stage_p99(peak, scope=config.p99_scope),
            "p99_scope": config.p99_scope,
        },
        "backpressure": _autoscale_backpressure(steps, knee),
    }


async def _run_autoscale_stage(ctx: typer.Context, scenario_config: E2EConfig, config: AutoscaleConfig) -> dict[str, Any]:
    if config.scenario == "p2p-online":
        return await _run_message_load_stage(ctx, scenario_config, group=False, step_seconds=config.step_seconds)
    if config.scenario == "group-online":
        return await _run_message_load_stage(ctx, scenario_config, group=True, step_seconds=config.step_seconds)
    return await run_e2e_scenario(ctx, scenario_config)


def _stage_p99(step: dict[str, Any], *, scope: str = "max") -> float:
    latency = step.get("latency_ms") if isinstance(step, dict) else {}
    if not isinstance(latency, dict):
        return 0.0
    if scope == "send":
        keys = ("send_rtt",)
    elif scope == "delivery":
        keys = ("delivery",)
    elif scope == "ack":
        keys = ("ack",)
    else:
        keys = ("ack", "delivery", "send_rtt")
    candidates = []
    for key in keys:
        section = latency.get(key)
        if isinstance(section, dict):
            try:
                candidates.append(float(section.get("p99") or 0))
            except (TypeError, ValueError):
                pass
    return max(candidates) if candidates else 0.0


def _step_send_rps(step: dict[str, Any]) -> float:
    try:
        return float(step.get("send_rps", step.get("rps", 0)) or 0)
    except (TypeError, ValueError):
        return 0.0


def _enrich_autoscale_step(
    step: dict[str, Any],
    *,
    previous_rps: float | None,
    baseline_p99: float | None,
    config: AutoscaleConfig,
) -> None:
    attempted = int(step.get("count") or 0)
    ok = int(step.get("ok") or 0)
    failed = int(step.get("failed") or 0)
    delivered = int(step.get("delivered") or 0)
    acked = int(step.get("acked") or 0)
    lost = int(step.get("lost") or max(0, ok - delivered))
    unacked = int(step.get("unacked") or max(0, ok - acked))
    step["rates"] = _rates(
        attempted=attempted,
        ok=ok,
        failed=failed,
        delivered=delivered,
        acked=acked,
        lost=lost,
        unacked=unacked,
    )
    current_rps = _step_send_rps(step)
    p99 = _stage_p99(step, scope=config.p99_scope)
    comparisons: dict[str, Any] = {
        "stage_p99_ms": p99,
        "p99_scope": config.p99_scope,
        "plateau_threshold": config.plateau_ratio,
        "p99_factor_threshold": config.p99_factor,
        "p99_baseline_floor_ms": config.p99_baseline_ms,
        "error_rate_threshold": config.error_rate,
        "incomplete_rate_threshold": config.incomplete_rate,
        "stop_on_plateau": config.stop_on_plateau,
    }
    if previous_rps is not None and previous_rps > 0:
        comparisons["previous_rps"] = round(previous_rps, 6)
        comparisons["rps_gain_ratio"] = round((current_rps - previous_rps) / previous_rps, 6)
    else:
        comparisons["previous_rps"] = None
        comparisons["rps_gain_ratio"] = None
    if baseline_p99 is not None and baseline_p99 > 0:
        effective_baseline = max(baseline_p99, config.p99_baseline_ms)
        comparisons["baseline_p99_ms"] = round(baseline_p99, 2)
        comparisons["effective_baseline_p99_ms"] = round(effective_baseline, 2)
        comparisons["p99_factor"] = round(p99 / effective_baseline, 6) if effective_baseline > 0 else None
    else:
        comparisons["baseline_p99_ms"] = None
        comparisons["effective_baseline_p99_ms"] = None
        comparisons["p99_factor"] = None
    step["comparisons"] = comparisons


def _hard_stop_condition(
    step: dict[str, Any],
    *,
    baseline_p99: float | None,
    config: AutoscaleConfig,
) -> dict[str, Any] | None:
    signals = step.get("backpressure", {}).get("signals", []) if isinstance(step.get("backpressure"), dict) else []
    if signals:
        signal = signals[0]
        return {
            "type": "backpressure",
            "reason": str(signal.get("type") or "backpressure"),
            "signal_type": str(signal.get("type") or "backpressure"),
            "message": str(signal.get("message") or ""),
            "count": int(signal.get("count") or 0),
            "concurrency": step.get("concurrency", 0),
        }
    failed = int(step.get("failed") or 0)
    total = max(1, int(step.get("count") or 1))
    failure_rate = failed / total
    if failure_rate >= config.error_rate:
        return {
            "type": "error_rate",
            "reason": "error_rate",
            "metric": "failed/count",
            "operator": ">=",
            "threshold": config.error_rate,
            "observed": round(failure_rate, 6),
            "failed": failed,
            "count": total,
        }
    rates = step.get("rates") if isinstance(step.get("rates"), dict) else {}
    delivery_incomplete = 1.0 - float(rates.get("delivery") or 0)
    if delivery_incomplete >= config.incomplete_rate:
        return {
            "type": "delivery_incomplete",
            "reason": "delivery_incomplete",
            "metric": "1-delivery_rate",
            "operator": ">=",
            "threshold": config.incomplete_rate,
            "observed": round(delivery_incomplete, 6),
            "delivered": int(step.get("delivered") or 0),
            "ok": int(step.get("ok") or 0),
        }
    p99 = _stage_p99(step, scope=config.p99_scope)
    if baseline_p99 and baseline_p99 > 0:
        effective_baseline = max(baseline_p99, config.p99_baseline_ms)
    else:
        effective_baseline = 0.0
    if effective_baseline > 0 and p99 > effective_baseline * config.p99_factor:
        return {
            "type": "p99_spike",
            "reason": "p99_spike",
            "metric": "stage_p99_ms/effective_baseline_p99_ms",
            "operator": ">",
            "threshold": config.p99_factor,
            "observed_factor": round(p99 / effective_baseline, 6),
            "baseline_p99_ms": round(baseline_p99, 2),
            "effective_baseline_p99_ms": round(effective_baseline, 2),
            "p99_baseline_floor_ms": round(config.p99_baseline_ms, 2),
            "p99_scope": config.p99_scope,
            "stage_p99_ms": round(p99, 2),
        }
    return None


def _soft_knee_condition(
    step: dict[str, Any],
    *,
    previous_rps: float | None,
    config: AutoscaleConfig,
) -> dict[str, Any] | None:
    current_rps = _step_send_rps(step)
    if previous_rps and previous_rps > 0:
        gain = (current_rps - previous_rps) / previous_rps
        if gain < config.plateau_ratio:
            return {
                "type": "rps_plateau",
                "reason": "rps_plateau",
                "metric": "rps_gain_ratio",
                "operator": "<",
                "threshold": config.plateau_ratio,
                "observed_gain_ratio": round(gain, 6),
                "previous_rps": round(previous_rps, 6),
                "current_rps": round(current_rps, 6),
            }
    return None


def _knee_condition(
    step: dict[str, Any],
    *,
    previous_rps: float | None,
    baseline_p99: float | None,
    config: AutoscaleConfig,
) -> dict[str, Any] | None:
    return _hard_stop_condition(step, baseline_p99=baseline_p99, config=config) or _soft_knee_condition(
        step,
        previous_rps=previous_rps,
        config=config,
    )


def _knee_reason(
    step: dict[str, Any],
    *,
    previous_rps: float | None,
    baseline_p99: float | None,
    config: AutoscaleConfig,
) -> str:
    condition = _knee_condition(step, previous_rps=previous_rps, baseline_p99=baseline_p99, config=config)
    return str((condition or {}).get("reason") or "")


def _autoscale_summary(steps: list[dict[str, Any]], *, p99_scope: str = "max") -> dict[str, Any]:
    attempted = sum(int(step.get("count") or 0) for step in steps)
    ok = sum(int(step.get("ok") or 0) for step in steps)
    failed = sum(int(step.get("failed") or 0) for step in steps)
    raw_received = sum(int(step.get("raw_received") or 0) for step in steps)
    delivered = sum(int(step.get("delivered") or 0) for step in steps)
    acked = sum(int(step.get("acked") or 0) for step in steps)
    ordered_gap_blocked = sum(int(step.get("ordered_gap_blocked") or 0) for step in steps)
    ok_to_raw_gap = sum(int(step.get("ok_to_raw_gap") or max(0, int(step.get("ok") or 0) - int(step.get("raw_received") or 0))) for step in steps)
    raw_to_delivered_gap = sum(int(step.get("raw_to_delivered_gap") or max(0, int(step.get("raw_received") or 0) - int(step.get("delivered") or 0))) for step in steps)
    lost = sum(int(step.get("lost") or max(0, int(step.get("ok") or 0) - int(step.get("delivered") or 0))) for step in steps)
    unacked = sum(int(step.get("unacked") or max(0, int(step.get("ok") or 0) - int(step.get("acked") or 0))) for step in steps)
    peak = max(steps, key=_step_send_rps, default={})
    return {
        "steps": len(steps),
        "attempted": attempted,
        "ok": ok,
        "failed": failed,
        "raw_received": raw_received,
        "delivered": delivered,
        "acked": acked,
        "ordered_gap_blocked": ordered_gap_blocked,
        "receiver_seq": _merge_receiver_seq_diagnostics(steps),
        "bench_handlers": _merge_step_bench_handler_stats(steps),
        "ok_to_raw_gap": ok_to_raw_gap,
        "raw_to_delivered_gap": raw_to_delivered_gap,
        "lost": lost,
        "unacked": unacked,
        "success_rate": _ratio(ok, attempted),
        "failure_rate": _ratio(failed, attempted),
        "raw_receive_rate": _ratio(raw_received, ok),
        "delivery_rate": _ratio(delivered, ok),
        "raw_to_delivery_rate": _ratio(delivered, raw_received),
        "ack_rate": _ratio(acked, ok),
        "loss_rate": _ratio(lost, ok),
        "unacked_rate": _ratio(unacked, ok),
        "peak_concurrency": peak.get("concurrency", 0),
        "peak_rps": peak.get("send_rps", peak.get("rps", 0)),
        "peak_send_rps": peak.get("send_rps", peak.get("rps", 0)),
        "peak_observed_rps": peak.get("observed_rps", peak.get("rps", 0)),
        "peak_delivered_rps": peak.get("delivered_rps", 0),
        "peak_acked_rps": peak.get("acked_rps", 0),
        "peak_p99_ms": _stage_p99(peak, scope=p99_scope),
        "p99_scope": p99_scope,
        "last_concurrency": steps[-1].get("concurrency", 0) if steps else 0,
    }


def _ratio(numerator: int | float, denominator: int | float) -> float:
    try:
        bottom = float(denominator)
    except (TypeError, ValueError):
        bottom = 0.0
    if bottom <= 0:
        return 0.0
    return round(float(numerator) / bottom, 6)


def _merge_receiver_seq_diagnostics(steps: list[dict[str, Any]]) -> dict[str, Any]:
    if not steps:
        return _empty_receiver_seq_diagnostics()
    latest = steps[-1].get("receiver_seq")
    merged = latest if isinstance(latest, dict) else _empty_receiver_seq_diagnostics()
    totals = merged.get("totals", {}) if isinstance(merged.get("totals"), dict) else {}
    totals = dict(totals)
    totals["ordered_gap_blocked"] = sum(
        int(
            (
                (step.get("receiver_seq") or {}).get("totals", {}).get("ordered_gap_blocked")
                if isinstance(step.get("receiver_seq"), dict)
                else step.get("ordered_gap_blocked")
            )
            or 0
        )
        for step in steps
    )
    merged = dict(merged)
    merged["push_processing"] = _merge_step_push_processing_stats(steps)
    merged["auto_ack"] = _merge_step_auto_ack_stats(steps)
    merged["bench_handlers"] = _merge_step_bench_handler_stats(steps)
    merged["drain"] = _merge_step_receiver_drain_stats(steps)
    merged["totals"] = totals
    return merged


def _merge_step_push_processing_stats(steps: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    merged: dict[str, dict[str, int]] = {}
    for step in steps:
        receiver_seq = step.get("receiver_seq")
        stats = receiver_seq.get("push_processing", {}) if isinstance(receiver_seq, dict) else {}
        stats = _copy_push_processing_stats(stats)
        for scope, values in stats.items():
            target = merged.setdefault(scope, {})
            for key, value in values.items():
                target[key] = int(target.get(key) or 0) + int(value or 0)
    return merged


def _merge_step_auto_ack_stats(steps: list[dict[str, Any]]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for step in steps:
        receiver_seq = step.get("receiver_seq")
        stats = receiver_seq.get("auto_ack", {}) if isinstance(receiver_seq, dict) else {}
        stats = _copy_int_stats(stats)
        for key, value in stats.items():
            merged[key] = int(merged.get(key) or 0) + int(value or 0)
    return merged


def _merge_step_bench_handler_stats(steps: list[dict[str, Any]]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for step in steps:
        receiver_seq = step.get("receiver_seq")
        stats = receiver_seq.get("bench_handlers", {}) if isinstance(receiver_seq, dict) else step.get("bench_handlers", {})
        stats = _copy_int_stats(stats)
        for key, value in stats.items():
            merged[key] = int(merged.get(key) or 0) + int(value or 0)
    return merged


def _merge_step_receiver_drain_stats(steps: list[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "enabled": False,
        "status": "",
        "duration_ms": 0,
        "pages": 0,
        "raw_count": 0,
        "published_count": 0,
    }
    for step in steps:
        receiver_seq = step.get("receiver_seq")
        stats = receiver_seq.get("drain", {}) if isinstance(receiver_seq, dict) else {}
        if not isinstance(stats, dict):
            continue
        merged["enabled"] = bool(merged.get("enabled") or stats.get("enabled"))
        if stats.get("status"):
            merged["status"] = str(stats.get("status"))
        for key in ("duration_ms", "pages", "raw_count", "published_count"):
            merged[key] = int(merged.get(key) or 0) + int(stats.get(key) or 0)
    return merged


def _autoscale_backpressure(steps: list[dict[str, Any]], knee: dict[str, Any]) -> dict[str, Any]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for step in steps:
        concurrency = step.get("concurrency", 0)
        backpressure = step.get("backpressure") if isinstance(step.get("backpressure"), dict) else {}
        for signal in backpressure.get("signals", []) if isinstance(backpressure, dict) else []:
            key = (str(signal.get("type") or "backpressure"), str(signal.get("message") or ""))
            item = merged.setdefault(
                key,
                {
                    "type": key[0],
                    "message": key[1],
                    "count": 0,
                    "first_concurrency": concurrency,
                    "last_concurrency": concurrency,
                },
            )
            item["count"] += int(signal.get("count") or 0)
            item["last_concurrency"] = concurrency
    signals = sorted(merged.values(), key=lambda item: (-int(item.get("count") or 0), str(item.get("type") or "")))
    trigger = None
    condition = knee.get("condition") if isinstance(knee, dict) else None
    if isinstance(condition, dict) and condition.get("type") == "backpressure":
        trigger = condition
    return {
        "detected": bool(signals),
        "signals": signals,
        "trigger_condition": trigger,
    }


def _print_result(result: dict[str, Any]) -> None:
    if is_json_mode():
        output_json(result)
        return
    if result.get("steps"):
        summary = result.get("summary", {}) if isinstance(result.get("summary"), dict) else {}
        knee = result.get("knee", {}) if isinstance(result.get("knee"), dict) else {}
        soft_knee = result.get("soft_knee", {}) if isinstance(result.get("soft_knee"), dict) else {}
        condition = knee.get("condition", {}) if isinstance(knee.get("condition"), dict) else {}
        soft_condition = soft_knee.get("condition", {}) if isinstance(soft_knee.get("condition"), dict) else {}
        backpressure = result.get("backpressure", {}) if isinstance(result.get("backpressure"), dict) else {}
        trigger = backpressure.get("trigger_condition") if isinstance(backpressure, dict) else None
        push_stats = _p2p_push_stats(summary.get("receiver_seq"))
        auto_ack = _auto_ack_stats(summary.get("receiver_seq"))
        handler_stats = _bench_handler_stats(summary.get("receiver_seq"))
        drain_stats = _receiver_drain_stats(summary.get("receiver_seq"))
        output_dict({
            "Scenario": result.get("scenario", ""),
            "Client Shape": result.get("client_shape", ""),
            "Mode": result.get("mode", ""),
            "Stop Reason": result.get("stop_reason", ""),
            "Steps": len(result.get("steps", [])),
            "Attempted": summary.get("attempted", ""),
            "OK": summary.get("ok", ""),
            "Failed": summary.get("failed", ""),
            "Raw Received": summary.get("raw_received", ""),
            "Raw Push Seen": handler_stats.get("raw_seen", ""),
            "Raw Push Unmatched": handler_stats.get("raw_unmatched", ""),
            "Published Seen": handler_stats.get("published_seen", handler_stats.get("delivered_seen", "")),
            "Published Matched": handler_stats.get("published_matched", handler_stats.get("delivered_matched", "")),
            "Published Unmatched": handler_stats.get("published_unmatched", handler_stats.get("delivered_unmatched", "")),
            "Delivered": summary.get("delivered", ""),
            "Delivered Seen": handler_stats.get("delivered_seen", ""),
            "Delivered Unmatched": handler_stats.get("delivered_unmatched", ""),
            "Acked": summary.get("acked", ""),
            "OK->Raw Gap": summary.get("ok_to_raw_gap", ""),
            "Raw->Delivered Gap": summary.get("raw_to_delivered_gap", ""),
            "Ordered Gap Blocked": summary.get("ordered_gap_blocked", ""),
            "Pending Ordered": (summary.get("receiver_seq", {}).get("totals", {}) if isinstance(summary.get("receiver_seq"), dict) else {}).get("pending_ordered_count", ""),
            "Pending Gaps": (summary.get("receiver_seq", {}).get("totals", {}) if isinstance(summary.get("receiver_seq"), dict) else {}).get("pending_gap_count", ""),
            "Push Started": push_stats.get("started", ""),
            "Push Filtered": push_stats.get("instance_filtered", ""),
            "Decrypt OK": push_stats.get("decrypt_ok", ""),
            "Decrypt Fail": push_stats.get("decrypt_fail", ""),
            "App Published": push_stats.get("app_published", ""),
            "Undecryptable Published": push_stats.get("undecryptable_published", ""),
            "Auto Ack Scheduled": auto_ack.get("scheduled", ""),
            "Auto Ack OK": auto_ack.get("ok", ""),
            "Auto Ack Failed": auto_ack.get("failed", ""),
            "Receiver Drain": drain_stats.get("status", ""),
            "Drain Raw": drain_stats.get("raw_count", ""),
            "Drain Published": drain_stats.get("published_count", ""),
            "Drain Duration Ms": drain_stats.get("duration_ms", ""),
            "Success Rate": summary.get("success_rate", ""),
            "Raw Receive Rate": summary.get("raw_receive_rate", ""),
            "Delivery Rate": summary.get("delivery_rate", ""),
            "Raw->Delivery Rate": summary.get("raw_to_delivery_rate", ""),
            "Ack Rate": summary.get("ack_rate", ""),
            "Soft Knee": soft_knee.get("reason", "not found") if soft_knee.get("found") else "not found",
            "Soft Knee Condition": _format_condition(soft_condition) if soft_condition else "",
            "Hard Stop": knee.get("reason", "not found") if knee.get("found") else "not found",
            "Hard Stop Condition": _format_condition(condition) if condition else "",
            "Peak RPS": result.get("peak", {}).get("rps", 0),
            "Peak Delivered RPS": result.get("peak", {}).get("delivered_rps", 0),
            "Peak Acked RPS": result.get("peak", {}).get("acked_rps", 0),
            "Backpressure": "yes" if backpressure.get("detected") else "no",
            "Backpressure Trigger": _format_condition(trigger) if isinstance(trigger, dict) else "",
            "Send Perf Top": _format_send_perf_top(summary.get("send_perf")),
        })
        return
    if result.get("scenario") in {"p2p-drain", "group-drain"}:
        drain_stats = result.get("drain") if isinstance(result.get("drain"), dict) else _receiver_drain_stats(result.get("receiver_seq"))
        receiver_items = drain_stats.get("receivers", []) if isinstance(drain_stats, dict) else []
        first = receiver_items[-1] if receiver_items else {}
        after = first.get("after", {}) if isinstance(first, dict) and isinstance(first.get("after"), dict) else {}
        output_dict({
            "Scenario": result.get("scenario", ""),
            "Method": result.get("method", ""),
            "Status": result.get("status", ""),
            "Receivers": ",".join(result.get("receivers", []) or []),
            "Group ID": result.get("group_id", "") or "",
            "Drain Raw": drain_stats.get("raw_count", "") if isinstance(drain_stats, dict) else "",
            "Drain Published": drain_stats.get("published_count", "") if isinstance(drain_stats, dict) else "",
            "Drain Pages": drain_stats.get("pages", "") if isinstance(drain_stats, dict) else "",
            "Drain Duration Ms": drain_stats.get("duration_ms", "") if isinstance(drain_stats, dict) else "",
            "Server Current Seq": first.get("server_current_seq", "") if isinstance(first, dict) else "",
            "Server Latest Seq": first.get("server_latest_seq", "") if isinstance(first, dict) else "",
            "Server Unread": first.get("server_unread_count", "") if isinstance(first, dict) else "",
            "Contiguous Seq": after.get("contiguous_seq", ""),
            "Max Seen Seq": after.get("max_seen_seq", ""),
        })
        return
    latency = result.get("latency_ms", {})
    push_stats = _p2p_push_stats(result.get("receiver_seq"))
    auto_ack = _auto_ack_stats(result.get("receiver_seq"))
    handler_stats = _bench_handler_stats(result.get("receiver_seq"))
    drain_stats = _receiver_drain_stats(result.get("receiver_seq"))
    output_dict({
        "Scenario": result.get("scenario", ""),
        "Method": result.get("method", ""),
        "Client Shape": result.get("client_shape", ""),
        "Count": result.get("count", ""),
        "Concurrency": result.get("concurrency", ""),
        "OK": result.get("ok", ""),
        "Failed": result.get("failed", ""),
        "Raw Received": result.get("raw_received", ""),
        "Raw Push Seen": handler_stats.get("raw_seen", ""),
        "Raw Push Unmatched": handler_stats.get("raw_unmatched", ""),
        "Published Seen": handler_stats.get("published_seen", handler_stats.get("delivered_seen", "")),
        "Published Matched": handler_stats.get("published_matched", handler_stats.get("delivered_matched", "")),
        "Published Unmatched": handler_stats.get("published_unmatched", handler_stats.get("delivered_unmatched", "")),
        "Delivered": result.get("delivered", ""),
        "Delivered Seen": handler_stats.get("delivered_seen", ""),
        "Delivered Unmatched": handler_stats.get("delivered_unmatched", ""),
        "Acked": result.get("acked", ""),
        "OK->Raw Gap": result.get("ok_to_raw_gap", ""),
        "Raw->Delivered Gap": result.get("raw_to_delivered_gap", ""),
        "Ordered Gap Blocked": result.get("ordered_gap_blocked", ""),
        "Pending Ordered": (result.get("receiver_seq", {}).get("totals", {}) if isinstance(result.get("receiver_seq"), dict) else {}).get("pending_ordered_count", ""),
        "Pending Gaps": (result.get("receiver_seq", {}).get("totals", {}) if isinstance(result.get("receiver_seq"), dict) else {}).get("pending_gap_count", ""),
        "Push Started": push_stats.get("started", ""),
        "Push Filtered": push_stats.get("instance_filtered", ""),
        "Decrypt OK": push_stats.get("decrypt_ok", ""),
        "Decrypt Fail": push_stats.get("decrypt_fail", ""),
        "App Published": push_stats.get("app_published", ""),
        "Undecryptable Published": push_stats.get("undecryptable_published", ""),
        "Auto Ack Scheduled": auto_ack.get("scheduled", ""),
        "Auto Ack OK": auto_ack.get("ok", ""),
        "Auto Ack Failed": auto_ack.get("failed", ""),
        "Receiver Drain": drain_stats.get("status", ""),
        "Drain Raw": drain_stats.get("raw_count", ""),
        "Drain Published": drain_stats.get("published_count", ""),
        "Drain Duration Ms": drain_stats.get("duration_ms", ""),
        "RPS": result.get("rps", ""),
        "Raw p99": (latency.get("raw_received") or {}).get("p99", ""),
        "Raw->Delivery p99": (latency.get("raw_to_delivery") or {}).get("p99", ""),
        "Delivery p99": (latency.get("delivery") or {}).get("p99", ""),
        "Ack p99": (latency.get("ack") or {}).get("p99", ""),
    })


def _p2p_push_stats(receiver_seq: Any) -> dict[str, int]:
    if not isinstance(receiver_seq, dict):
        return {}
    stats = receiver_seq.get("push_processing")
    if not isinstance(stats, dict):
        return {}
    p2p = stats.get("p2p")
    if not isinstance(p2p, dict):
        return {}
    return {str(key): int(value or 0) for key, value in p2p.items()}


def _auto_ack_stats(receiver_seq: Any) -> dict[str, int]:
    if not isinstance(receiver_seq, dict):
        return {}
    stats = receiver_seq.get("auto_ack")
    if not isinstance(stats, dict):
        return {}
    return {str(key): int(value or 0) for key, value in stats.items()}


def _bench_handler_stats(receiver_seq: Any) -> dict[str, int]:
    if not isinstance(receiver_seq, dict):
        return {}
    stats = receiver_seq.get("bench_handlers")
    if not isinstance(stats, dict):
        return {}
    return {str(key): int(value or 0) for key, value in stats.items()}


def _receiver_drain_stats(receiver_seq: Any) -> dict[str, Any]:
    if not isinstance(receiver_seq, dict):
        return {}
    stats = receiver_seq.get("drain")
    return stats if isinstance(stats, dict) else {}


def _format_condition(condition: dict[str, Any]) -> str:
    kind = str(condition.get("type") or "")
    if kind == "backpressure":
        return (
            f"{condition.get('signal_type', 'backpressure')} "
            f"at concurrency={condition.get('concurrency', '')}, "
            f"count={condition.get('count', '')}, "
            f"message={condition.get('message', '')}"
        )
    if kind == "rps_plateau":
        return (
            f"rps_gain_ratio {condition.get('operator', '<')} {condition.get('threshold', '')}, "
            f"observed={condition.get('observed_gain_ratio', '')}"
        )
    if kind == "p99_spike":
        return (
            f"p99_scope={condition.get('p99_scope', '')}, "
            f"p99_factor {condition.get('operator', '>')} {condition.get('threshold', '')}, "
            f"observed={condition.get('observed_factor', '')}, "
            f"baseline={condition.get('baseline_p99_ms', '')}ms, "
            f"effective_baseline={condition.get('effective_baseline_p99_ms', '')}ms, "
            f"stage_p99={condition.get('stage_p99_ms', '')}ms"
        )
    if kind == "error_rate":
        return (
            f"error_rate {condition.get('operator', '>=')} {condition.get('threshold', '')}, "
            f"observed={condition.get('observed', '')}"
        )
    return str(condition)


def _common_config(
    ctx: typer.Context,
    *,
    scenario: str,
    senders: str | None,
    receivers: str | None,
    group_id: str | None,
    count: int,
    concurrency: int,
    size: int,
    no_encrypt: bool,
    prefix: str,
    timeout_ms: int,
    drain_receivers: bool = False,
    drain_timeout_ms: int | None = None,
    drain_limit: int = 100,
    drain_max_pages: int = 100,
    settle_ms: int | None = None,
) -> E2EConfig:
    _validate_positive("--count", count)
    _validate_positive("--concurrency", concurrency)
    if size < 0:
        raise typer.BadParameter("--size 必须 >= 0")
    sender_aids = _resolve_aids(ctx, senders, role="sender")
    receiver_aids = _resolve_aids(ctx, receivers, role="receiver")
    resolved_group_id = _resolve_group_id(ctx, group_id) if scenario == "group-online" else group_id
    return E2EConfig(
        scenario=scenario,
        count=count,
        concurrency=concurrency,
        payload_size=size,
        encrypt=not no_encrypt,
        prefix=prefix,
        sender_aids=sender_aids,
        receiver_aids=receiver_aids,
        group_id=resolved_group_id,
        timeout_ms=timeout_ms,
        drain_receivers=drain_receivers,
        drain_timeout_ms=drain_timeout_ms,
        drain_limit=drain_limit,
        drain_max_pages=drain_max_pages,
        settle_ms=settle_ms,
    )


@e2e_app.command("connect")
def e2e_connect(
    ctx: typer.Context,
    senders: str | None = typer.Option(None, "--senders", help="发送端 AID，逗号分隔；默认当前 profile"),
    receivers: str | None = typer.Option(None, "--receivers", help="接收端 AID，逗号分隔；默认本地其他身份"),
) -> None:
    """压测认证、连接、ready 时间"""
    set_json_mode(ctx.obj.get("json", False))
    suppress_cli_summary()
    try:
        config = E2EConfig(
            scenario="connect",
            sender_aids=_resolve_aids(ctx, senders, role="sender"),
            receiver_aids=_resolve_aids(ctx, receivers, role="receiver"),
        )
        result = _run_bench_quiet(run_e2e_scenario(ctx, config))
    except Exception as exc:
        handle_error(exc)
        return
    _print_result(result)


@e2e_app.command("drain")
def e2e_drain(
    ctx: typer.Context,
    receivers: str | None = typer.Option(None, "--receivers", help="接收端 AID，逗号分隔；默认本地其他身份"),
    limit: int = typer.Option(100, "--limit", help="每页拉取条数"),
    max_pages: int = typer.Option(100, "--max-pages", help="单次 pull 最大页数"),
) -> None:
    """P2P receiver 上线并持续 pull，直到服务端 cursor 为空。"""
    set_json_mode(ctx.obj.get("json", False))
    suppress_cli_summary()
    try:
        config = E2EConfig(
            scenario="p2p-drain",
            receiver_aids=_resolve_aids(ctx, receivers, role="receiver"),
            drain_receivers=True,
            drain_timeout_ms=None,
            drain_limit=limit,
            drain_max_pages=max_pages,
            settle_ms=0,
        )
        result = _run_bench_quiet(_run_receiver_drain_scenario(ctx, config, group=False))
    except Exception as exc:
        handle_error(exc)
        return
    _print_result(result)


@e2e_app.command("group-drain")
def e2e_group_drain(
    ctx: typer.Context,
    group_id: str | None = typer.Option(None, "--group-id", help="群组 ID；默认 active group"),
    receivers: str | None = typer.Option(None, "--receivers", help="接收端 AID，逗号分隔；默认本地其他身份"),
    limit: int = typer.Option(100, "--limit", help="每页拉取条数"),
    max_pages: int = typer.Option(100, "--max-pages", help="单次 pull 最大页数"),
) -> None:
    """Group receiver 上线并持续 pull，直到服务端 cursor 为空。"""
    set_json_mode(ctx.obj.get("json", False))
    suppress_cli_summary()
    try:
        config = E2EConfig(
            scenario="group-drain",
            receiver_aids=_resolve_aids(ctx, receivers, role="receiver"),
            group_id=_resolve_group_id(ctx, group_id),
            drain_receivers=True,
            drain_timeout_ms=None,
            drain_limit=limit,
            drain_max_pages=max_pages,
            settle_ms=0,
        )
        result = _run_bench_quiet(_run_receiver_drain_scenario(ctx, config, group=True))
    except Exception as exc:
        handle_error(exc)
        return
    _print_result(result)


@e2e_app.command("send")
def e2e_send(
    ctx: typer.Context,
    senders: str | None = typer.Option(None, "--senders", help="发送端 AID，逗号分隔；默认当前 profile"),
    receivers: str | None = typer.Option(None, "--receivers", help="接收端 AID，逗号分隔；默认本地其他身份"),
    count: int = typer.Option(100, "--count", "-n", help="发送条数"),
    concurrency: int = typer.Option(1, "--concurrency", "-c", help="跨连接活跃发送并发"),
    size: int = typer.Option(64, "--size", help="payload.text 目标字符数"),
    no_encrypt: bool = typer.Option(False, "--no-encrypt", help="不加密"),
    prefix: str = typer.Option("bench-e2e", "--prefix", help="消息内容前缀"),
    timeout_ms: int = typer.Option(5000, "--timeout-ms", help="等待 delivery/ack 的毫秒数"),
    drain_receivers: bool = typer.Option(False, "--drain-receivers/--no-drain-receivers", help="开始发送前先让 receiver 拉完历史积压"),
    drain_timeout_ms: int | None = typer.Option(None, "--drain-timeout-ms", help="receiver 历史积压清空最长等待毫秒数；不设置则不限时"),
    drain_limit: int = typer.Option(100, "--drain-limit", help="receiver drain 每页拉取条数"),
    drain_max_pages: int = typer.Option(100, "--drain-max-pages", help="receiver drain 单次 pull 最大页数"),
    settle_ms: int | None = typer.Option(None, "--settle-ms", help="停止发送后等待 receiver drain 到空的毫秒数；默认 60000，0 表示不等待"),
) -> None:
    """P2P 在线 E2E：A 发 B，B 在线收到、解密、ack"""
    set_json_mode(ctx.obj.get("json", False))
    suppress_cli_summary()
    try:
        config = _common_config(
            ctx,
            scenario="p2p-online",
            senders=senders,
            receivers=receivers,
            group_id=None,
            count=count,
            concurrency=concurrency,
            size=size,
            no_encrypt=no_encrypt,
            prefix=prefix,
            timeout_ms=timeout_ms,
            drain_receivers=drain_receivers,
            drain_timeout_ms=drain_timeout_ms,
            drain_limit=drain_limit,
            drain_max_pages=drain_max_pages,
            settle_ms=settle_ms,
        )
        result = _run_bench_quiet(run_e2e_scenario(ctx, config))
    except Exception as exc:
        handle_error(exc)
        return
    _print_result(result)


@e2e_app.command("group")
def e2e_group(
    ctx: typer.Context,
    group_id: str | None = typer.Option(None, "--group-id", help="群组 ID；默认 active group"),
    senders: str | None = typer.Option(None, "--senders", help="发送端 AID，逗号分隔；默认当前 profile"),
    receivers: str | None = typer.Option(None, "--receivers", help="接收端 AID，逗号分隔；默认本地其他身份"),
    count: int = typer.Option(100, "--count", "-n", help="发送条数"),
    concurrency: int = typer.Option(1, "--concurrency", "-c", help="跨连接活跃发送并发"),
    size: int = typer.Option(64, "--size", help="payload.text 目标字符数"),
    no_encrypt: bool = typer.Option(False, "--no-encrypt", help="不加密"),
    prefix: str = typer.Option("bench-e2e", "--prefix", help="消息内容前缀"),
    timeout_ms: int = typer.Option(5000, "--timeout-ms", help="等待 delivery/ack 的毫秒数"),
    drain_receivers: bool = typer.Option(False, "--drain-receivers/--no-drain-receivers", help="开始发送前先让 receiver 拉完历史积压"),
    drain_timeout_ms: int | None = typer.Option(None, "--drain-timeout-ms", help="receiver 历史积压清空最长等待毫秒数；不设置则不限时"),
    drain_limit: int = typer.Option(100, "--drain-limit", help="receiver drain 每页拉取条数"),
    drain_max_pages: int = typer.Option(100, "--drain-max-pages", help="receiver drain 单次 pull 最大页数"),
    settle_ms: int | None = typer.Option(None, "--settle-ms", help="停止发送后等待 receiver drain 到空的毫秒数；默认 60000，0 表示不等待"),
) -> None:
    """群在线 E2E：A 发群，在线成员收到、解密、ack"""
    set_json_mode(ctx.obj.get("json", False))
    suppress_cli_summary()
    try:
        config = _common_config(
            ctx,
            scenario="group-online",
            senders=senders,
            receivers=receivers,
            group_id=group_id,
            count=count,
            concurrency=concurrency,
            size=size,
            no_encrypt=no_encrypt,
            prefix=prefix,
            timeout_ms=timeout_ms,
            drain_receivers=drain_receivers,
            drain_timeout_ms=drain_timeout_ms,
            drain_limit=drain_limit,
            drain_max_pages=drain_max_pages,
            settle_ms=settle_ms,
        )
        result = _run_bench_quiet(run_e2e_scenario(ctx, config))
    except Exception as exc:
        handle_error(exc)
        return
    _print_result(result)


def _run_single_scenario_command(
    ctx: typer.Context,
    *,
    scenario: str,
    senders: str | None,
    receivers: str | None,
    group_id: str | None,
    count: int,
    concurrency: int,
    no_encrypt: bool,
    timeout_ms: int,
) -> None:
    set_json_mode(ctx.obj.get("json", False))
    suppress_cli_summary()
    try:
        sender_aids = _resolve_aids(ctx, senders, role="sender")
        if scenario in {
            "p2p-online",
            "p2p-offline-pull",
            "group-online",
            "group-offline-pull",
            "notify-online",
        }:
            receiver_aids = _resolve_aids(ctx, receivers, role="receiver")
        else:
            receiver_aids = _split_csv(receivers)
        resolved_group_id = group_id
        if scenario in {"group-online", "group-offline-pull", "group-fs"}:
            resolved_group_id = _resolve_group_id(ctx, group_id)
        config = E2EConfig(
            scenario=scenario,
            count=count,
            concurrency=concurrency,
            encrypt=not no_encrypt,
            sender_aids=sender_aids,
            receiver_aids=receiver_aids,
            group_id=resolved_group_id,
            timeout_ms=timeout_ms,
        )
        result = _run_bench_quiet(run_e2e_scenario(ctx, config))
    except Exception as exc:
        handle_error(exc)
        return
    _print_result(result)


@e2e_app.command("p2p-offline-pull")
def e2e_p2p_offline_pull(
    ctx: typer.Context,
    senders: str | None = typer.Option(None, "--senders", help="发送端 AID，逗号分隔；默认当前 profile"),
    receivers: str | None = typer.Option(None, "--receivers", help="接收端 AID，逗号分隔；默认本地其他身份"),
    count: int = typer.Option(100, "--count", "-n", help="发送条数"),
    concurrency: int = typer.Option(1, "--concurrency", "-c", help="发送并发"),
    no_encrypt: bool = typer.Option(False, "--no-encrypt", help="不加密"),
    timeout_ms: int = typer.Option(5000, "--timeout-ms", help="等待 pull/ack 的毫秒数"),
) -> None:
    """P2P 离线 E2E：A 发离线 B，B 上线 pull、解密、ack"""
    _run_single_scenario_command(
        ctx,
        scenario="p2p-offline-pull",
        senders=senders,
        receivers=receivers,
        group_id=None,
        count=count,
        concurrency=concurrency,
        no_encrypt=no_encrypt,
        timeout_ms=timeout_ms,
    )


@e2e_app.command("group-offline-pull")
def e2e_group_offline_pull(
    ctx: typer.Context,
    group_id: str | None = typer.Option(None, "--group-id", help="群组 ID；默认 active group"),
    senders: str | None = typer.Option(None, "--senders", help="发送端 AID，逗号分隔；默认当前 profile"),
    receivers: str | None = typer.Option(None, "--receivers", help="接收端 AID，逗号分隔；默认本地其他身份"),
    count: int = typer.Option(100, "--count", "-n", help="发送条数"),
    concurrency: int = typer.Option(1, "--concurrency", "-c", help="发送并发"),
    no_encrypt: bool = typer.Option(False, "--no-encrypt", help="不加密"),
    timeout_ms: int = typer.Option(5000, "--timeout-ms", help="等待 pull/ack 的毫秒数"),
) -> None:
    """群离线 E2E：成员离线后 pull 消费积压"""
    _run_single_scenario_command(
        ctx,
        scenario="group-offline-pull",
        senders=senders,
        receivers=receivers,
        group_id=group_id,
        count=count,
        concurrency=concurrency,
        no_encrypt=no_encrypt,
        timeout_ms=timeout_ms,
    )


@e2e_app.command("storage-vfs")
def e2e_storage_vfs(
    ctx: typer.Context,
    senders: str | None = typer.Option(None, "--senders", help="执行身份 AID；默认当前 profile"),
    receivers: str | None = typer.Option(None, "--receivers", help="保留参数，用于 all 配置兼容"),
) -> None:
    """Storage VFS：mkdir/write/read/stat/list/remove happy path"""
    _run_single_scenario_command(
        ctx,
        scenario="storage-vfs",
        senders=senders,
        receivers=receivers,
        group_id=None,
        count=1,
        concurrency=1,
        no_encrypt=True,
        timeout_ms=5000,
    )


@e2e_app.command("group-fs")
def e2e_group_fs(
    ctx: typer.Context,
    group_id: str | None = typer.Option(None, "--group-id", help="群组 ID；默认 active group"),
    senders: str | None = typer.Option(None, "--senders", help="执行身份 AID；默认当前 profile"),
    receivers: str | None = typer.Option(None, "--receivers", help="保留参数，用于 all 配置兼容"),
) -> None:
    """Group FS：mkdir/stat/ls/rm happy path"""
    _run_single_scenario_command(
        ctx,
        scenario="group-fs",
        senders=senders,
        receivers=receivers,
        group_id=group_id,
        count=1,
        concurrency=1,
        no_encrypt=True,
        timeout_ms=5000,
    )


@e2e_app.command("collab")
def e2e_collab(
    ctx: typer.Context,
    senders: str | None = typer.Option(None, "--senders", help="执行身份 AID；默认当前 profile"),
    receivers: str | None = typer.Option(None, "--receivers", help="保留参数，用于 all 配置兼容"),
) -> None:
    """Collab：create/show/commit/log happy path"""
    _run_single_scenario_command(
        ctx,
        scenario="collab",
        senders=senders,
        receivers=receivers,
        group_id=None,
        count=1,
        concurrency=1,
        no_encrypt=True,
        timeout_ms=5000,
    )


@e2e_app.command("notify-online")
def e2e_notify_online(
    ctx: typer.Context,
    group_id: str | None = typer.Option(None, "--group-id", help="可选群组 ID；未指定 receiver 时使用"),
    senders: str | None = typer.Option(None, "--senders", help="发送端 AID；默认当前 profile"),
    receivers: str | None = typer.Option(None, "--receivers", help="接收端 AID；默认本地其他身份"),
) -> None:
    """Notify：在线轻量通知发送 happy path"""
    _run_single_scenario_command(
        ctx,
        scenario="notify-online",
        senders=senders,
        receivers=receivers,
        group_id=group_id,
        count=1,
        concurrency=1,
        no_encrypt=True,
        timeout_ms=5000,
    )


@e2e_app.command("service-proxy")
def e2e_service_proxy(ctx: typer.Context) -> None:
    """Service Proxy：holder/visitor 环境下的 happy path 占位"""
    set_json_mode(ctx.obj.get("json", False))
    suppress_cli_summary()
    _print_result(_skipped_external("service-proxy"))


@e2e_app.command("federation-p2p")
def e2e_federation_p2p(ctx: typer.Context) -> None:
    """跨域 P2P happy path 占位"""
    set_json_mode(ctx.obj.get("json", False))
    suppress_cli_summary()
    _print_result(_skipped_external("federation-p2p"))


@e2e_app.command("federation-group")
def e2e_federation_group(ctx: typer.Context) -> None:
    """跨域群消息 happy path 占位"""
    set_json_mode(ctx.obj.get("json", False))
    suppress_cli_summary()
    _print_result(_skipped_external("federation-group"))


@e2e_app.command("all")
def e2e_all(
    ctx: typer.Context,
    group_id: str | None = typer.Option(None, "--group-id", help="群组 ID；默认 active group"),
    senders: str | None = typer.Option(None, "--senders", help="发送端 AID，逗号分隔；默认当前 profile"),
    receivers: str | None = typer.Option(None, "--receivers", help="接收端 AID，逗号分隔；默认本地其他身份"),
    count: int = typer.Option(10, "--count", "-n", help="每个已实现场景发送条数"),
    concurrency: int = typer.Option(1, "--concurrency", "-c", help="每个已实现场景并发"),
    scenarios: str | None = typer.Option(None, "--scenarios", help="只运行指定场景，逗号分隔"),
    no_encrypt: bool = typer.Option(False, "--no-encrypt", help="不加密"),
    timeout_ms: int = typer.Option(5000, "--timeout-ms", help="等待 delivery/ack 的毫秒数"),
) -> None:
    """按 happy path 清单运行完整 E2E suite"""
    set_json_mode(ctx.obj.get("json", False))
    suppress_cli_summary()
    try:
        sender_aids = _resolve_aids(ctx, senders, role="sender")
        receiver_aids = _resolve_aids(ctx, receivers, role="receiver")
        resolved_group_id = group_id or _try_resolve_group_id(ctx)

        async def _run_all() -> dict[str, Any]:
            items = []
            runnable = {
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
            }
            selected = _split_csv(scenarios) or list(ALL_SCENARIOS)
            for scenario in selected:
                if scenario not in ALL_SCENARIOS:
                    items.append({"scenario": scenario, "status": "skipped", "reason": "unknown scenario"})
                    continue
                if scenario in runnable:
                    config = E2EConfig(
                        scenario=scenario,
                        count=count,
                        concurrency=concurrency,
                        encrypt=not no_encrypt,
                        sender_aids=sender_aids,
                        receiver_aids=receiver_aids,
                        group_id=resolved_group_id,
                        timeout_ms=timeout_ms,
                    )
                    if scenario in {"group-online", "group-offline-pull", "group-fs"} and not resolved_group_id:
                        items.append({"scenario": scenario, "status": "skipped", "reason": "missing group_id"})
                    else:
                        items.append(await run_e2e_scenario(ctx, config))
                else:
                    items.append(_not_implemented(scenario))
            return {
                "suite": "happy-path",
                "client_shape": CLIENT_SHAPE,
                "scenarios": items,
            }

        result = _run_bench_quiet(_run_all())
    except Exception as exc:
        handle_error(exc)
        return
    _print_result(result) if not is_json_mode() else output_json(result)


def _try_resolve_group_id(ctx: typer.Context) -> str | None:
    try:
        return _resolve_group_id(ctx, None)
    except Exception:
        return None


def _autoscale_common_config(
    ctx: typer.Context,
    *,
    scenario: str,
    senders: str | None,
    receivers: str | None,
    group_id: str | None,
    count: int,
    step_seconds: float,
    start: int,
    max_concurrency: int,
    factor: int,
    step: int,
    plateau_ratio: float,
    p99_factor: float,
    p99_baseline_ms: float,
    error_rate: float,
    incomplete_rate: float,
    stop_on_plateau: bool,
    size: int,
    no_encrypt: bool,
    no_persist: bool,
    prefix: str,
    timeout_ms: int,
    p99_scope: str,
    perf_trace: bool,
    perf_log_root: str | None,
    drain_receivers: bool = False,
    drain_timeout_ms: int | None = None,
    drain_limit: int = 100,
    drain_max_pages: int = 100,
    settle_ms: int | None = None,
) -> AutoscaleConfig:
    _validate_positive("--count", count)
    _validate_positive_float("--step-seconds", step_seconds)
    _validate_positive("--start", start)
    _validate_positive("--max", max_concurrency)
    if p99_baseline_ms < 0:
        raise typer.BadParameter("--p99-baseline-ms 必须 >= 0")
    normalized_p99_scope = str(p99_scope or "send").strip().lower()
    if normalized_p99_scope not in {"send", "delivery", "ack", "max"}:
        raise typer.BadParameter("--p99-scope 只能是 send/delivery/ack/max")
    sender_aids = _resolve_aids(ctx, senders, role="sender")
    receiver_aids = _resolve_aids(ctx, receivers, role="receiver")
    resolved_group_id = _resolve_group_id(ctx, group_id) if scenario == "group-online" else group_id
    return AutoscaleConfig(
        scenario=scenario,
        count=count,
        step_seconds=step_seconds,
        start=start,
        max_concurrency=max_concurrency,
        factor=factor,
        step=step,
        plateau_ratio=plateau_ratio,
        p99_factor=p99_factor,
        p99_baseline_ms=p99_baseline_ms,
        error_rate=error_rate,
        incomplete_rate=incomplete_rate,
        stop_on_plateau=stop_on_plateau,
        payload_size=size,
        encrypt=not no_encrypt,
        persist=not no_persist,
        prefix=prefix,
        sender_aids=sender_aids,
        receiver_aids=receiver_aids,
        group_id=resolved_group_id,
        timeout_ms=timeout_ms,
        p99_scope=normalized_p99_scope,
        perf_trace=perf_trace,
        perf_log_root=perf_log_root,
        drain_receivers=drain_receivers,
        drain_timeout_ms=drain_timeout_ms,
        drain_limit=drain_limit,
        drain_max_pages=drain_max_pages,
        settle_ms=settle_ms,
    )


@autoscale_app.command("send")
def autoscale_send(
    ctx: typer.Context,
    senders: str | None = typer.Option(None, "--senders", help="发送端 AID，逗号分隔；默认当前 profile"),
    receivers: str | None = typer.Option(None, "--receivers", help="接收端 AID，逗号分隔；默认本地其他身份"),
    count: int = typer.Option(10000, "--count", "-n", help="每个台阶最多发送条数；实际按 --step-seconds 持续加压"),
    step_seconds: float = typer.Option(30.0, "--step-seconds", help="每个台阶持续加压秒数"),
    start: int = typer.Option(1, "--start", help="起始并发"),
    max_concurrency: int = typer.Option(256, "--max", help="最大并发"),
    factor: int = typer.Option(2, "--factor", help="并发倍增因子；<=1 时使用 --step"),
    step: int = typer.Option(1, "--step", help="线性步进"),
    plateau_ratio: float = typer.Option(0.1, "--plateau-ratio", help="RPS 增幅低于该比例记录 soft knee"),
    p99_factor: float = typer.Option(3.0, "--p99-factor", help="p99 超过有效基线倍数判定硬停止"),
    p99_baseline_ms: float = typer.Option(200.0, "--p99-baseline-ms", help="p99 倍数硬停的基线下限毫秒数"),
    error_rate: float = typer.Option(0.01, "--error-rate", help="失败率超过该比例判定硬停止"),
    incomplete_rate: float = typer.Option(0.01, "--incomplete-rate", help="delivery/ack 未完成率超过该比例判定硬停止"),
    stop_on_plateau: bool = typer.Option(False, "--stop-on-plateau", help="兼容旧行为：RPS 平台即停止"),
    size: int = typer.Option(64, "--size", help="payload.text 目标字符数"),
    no_encrypt: bool = typer.Option(False, "--no-encrypt", help="不加密"),
    no_persist: bool = typer.Option(False, "--no-persist", help="不持久化（临时消息，不写数据库）"),
    prefix: str = typer.Option("bench-autoscale", "--prefix", help="消息内容前缀"),
    timeout_ms: int = typer.Option(5000, "--timeout-ms", help="等待 delivery/ack 的毫秒数"),
    p99_scope: str = typer.Option("send", "--p99-scope", help="p99 判定范围：send/delivery/ack/max；默认只看发送 RPC RTT"),
    perf_trace: bool = typer.Option(True, "--perf-trace/--no-perf-trace", help="聚合服务端 send_perf 阶段耗时"),
    perf_log_root: str | None = typer.Option(None, "--perf-log-root", help="Kite 实例目录或日志根目录"),
    drain_receivers: bool = typer.Option(False, "--drain-receivers/--no-drain-receivers", help="每个台阶发送前先让 receiver 拉完历史积压"),
    drain_timeout_ms: int | None = typer.Option(None, "--drain-timeout-ms", help="receiver 历史积压清空最长等待毫秒数；不设置则不限时"),
    drain_limit: int = typer.Option(100, "--drain-limit", help="receiver drain 每页拉取条数"),
    drain_max_pages: int = typer.Option(100, "--drain-max-pages", help="receiver drain 单次 pull 最大页数"),
    settle_ms: int | None = typer.Option(None, "--settle-ms", help="每个台阶停止发送后等待 receiver drain 到空的毫秒数；默认 60000，0 表示不等待"),
) -> None:
    """P2P 在线阶梯加压找膝点"""
    set_json_mode(ctx.obj.get("json", False))
    suppress_cli_summary()
    try:
        config = _autoscale_common_config(
            ctx,
            scenario="p2p-online",
            senders=senders,
            receivers=receivers,
            group_id=None,
            count=count,
            step_seconds=step_seconds,
            start=start,
            max_concurrency=max_concurrency,
            factor=factor,
            step=step,
            plateau_ratio=plateau_ratio,
            p99_factor=p99_factor,
            p99_baseline_ms=p99_baseline_ms,
            error_rate=error_rate,
            incomplete_rate=incomplete_rate,
            stop_on_plateau=stop_on_plateau,
            size=size,
            no_encrypt=no_encrypt,
            no_persist=no_persist,
            prefix=prefix,
            timeout_ms=timeout_ms,
            p99_scope=p99_scope,
            perf_trace=perf_trace,
            perf_log_root=perf_log_root,
            drain_receivers=drain_receivers,
            drain_timeout_ms=drain_timeout_ms,
            drain_limit=drain_limit,
            drain_max_pages=drain_max_pages,
            settle_ms=settle_ms,
        )
        result = _run_bench_quiet(run_autoscale(ctx, config))
    except Exception as exc:
        handle_error(exc)
        return
    _print_result(result)


@autoscale_app.command("group")
def autoscale_group(
    ctx: typer.Context,
    group_id: str | None = typer.Option(None, "--group-id", help="群组 ID；默认 active group"),
    senders: str | None = typer.Option(None, "--senders", help="发送端 AID，逗号分隔；默认当前 profile"),
    receivers: str | None = typer.Option(None, "--receivers", help="接收端 AID，逗号分隔；默认本地其他身份"),
    count: int = typer.Option(10000, "--count", "-n", help="每个台阶最多发送条数；实际按 --step-seconds 持续加压"),
    step_seconds: float = typer.Option(30.0, "--step-seconds", help="每个台阶持续加压秒数"),
    start: int = typer.Option(1, "--start", help="起始并发"),
    max_concurrency: int = typer.Option(256, "--max", help="最大并发"),
    factor: int = typer.Option(2, "--factor", help="并发倍增因子；<=1 时使用 --step"),
    step: int = typer.Option(1, "--step", help="线性步进"),
    plateau_ratio: float = typer.Option(0.1, "--plateau-ratio", help="RPS 增幅低于该比例记录 soft knee"),
    p99_factor: float = typer.Option(3.0, "--p99-factor", help="p99 超过有效基线倍数判定硬停止"),
    p99_baseline_ms: float = typer.Option(200.0, "--p99-baseline-ms", help="p99 倍数硬停的基线下限毫秒数"),
    error_rate: float = typer.Option(0.01, "--error-rate", help="失败率超过该比例判定硬停止"),
    incomplete_rate: float = typer.Option(0.01, "--incomplete-rate", help="delivery/ack 未完成率超过该比例判定硬停止"),
    stop_on_plateau: bool = typer.Option(False, "--stop-on-plateau", help="兼容旧行为：RPS 平台即停止"),
    size: int = typer.Option(64, "--size", help="payload.text 目标字符数"),
    no_encrypt: bool = typer.Option(False, "--no-encrypt", help="不加密"),
    no_persist: bool = typer.Option(False, "--no-persist", help="不持久化（临时消息，不写数据库）"),
    prefix: str = typer.Option("bench-autoscale", "--prefix", help="消息内容前缀"),
    timeout_ms: int = typer.Option(5000, "--timeout-ms", help="等待 delivery/ack 的毫秒数"),
    p99_scope: str = typer.Option("send", "--p99-scope", help="p99 判定范围：send/delivery/ack/max；默认只看发送 RPC RTT"),
    perf_trace: bool = typer.Option(True, "--perf-trace/--no-perf-trace", help="聚合服务端 send_perf 阶段耗时"),
    perf_log_root: str | None = typer.Option(None, "--perf-log-root", help="Kite 实例目录或日志根目录"),
    drain_receivers: bool = typer.Option(False, "--drain-receivers/--no-drain-receivers", help="每个台阶发送前先让 receiver 拉完历史积压"),
    drain_timeout_ms: int | None = typer.Option(None, "--drain-timeout-ms", help="receiver 历史积压清空最长等待毫秒数；不设置则不限时"),
    drain_limit: int = typer.Option(100, "--drain-limit", help="receiver drain 每页拉取条数"),
    drain_max_pages: int = typer.Option(100, "--drain-max-pages", help="receiver drain 单次 pull 最大页数"),
    settle_ms: int | None = typer.Option(None, "--settle-ms", help="每个台阶停止发送后等待 receiver drain 到空的毫秒数；默认 60000，0 表示不等待"),
) -> None:
    """群在线阶梯加压找膝点"""
    set_json_mode(ctx.obj.get("json", False))
    suppress_cli_summary()
    try:
        config = _autoscale_common_config(
            ctx,
            scenario="group-online",
            senders=senders,
            receivers=receivers,
            group_id=group_id,
            count=count,
            step_seconds=step_seconds,
            start=start,
            max_concurrency=max_concurrency,
            factor=factor,
            step=step,
            plateau_ratio=plateau_ratio,
            p99_factor=p99_factor,
            p99_baseline_ms=p99_baseline_ms,
            error_rate=error_rate,
            incomplete_rate=incomplete_rate,
            stop_on_plateau=stop_on_plateau,
            size=size,
            no_encrypt=no_encrypt,
            no_persist=no_persist,
            prefix=prefix,
            timeout_ms=timeout_ms,
            p99_scope=p99_scope,
            perf_trace=perf_trace,
            perf_log_root=perf_log_root,
            drain_receivers=drain_receivers,
            drain_timeout_ms=drain_timeout_ms,
            drain_limit=drain_limit,
            drain_max_pages=drain_max_pages,
            settle_ms=settle_ms,
        )
        result = _run_bench_quiet(run_autoscale(ctx, config))
    except Exception as exc:
        handle_error(exc)
        return
    _print_result(result)
