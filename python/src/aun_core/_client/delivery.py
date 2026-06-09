from __future__ import annotations

import asyncio
import base64
import json
import time
from typing import Any

from ..config import slot_isolation_key
from ..group_id import normalize_group_id as _normalize_group_id
from ..seq_tracker import SeqTracker
from ..types import ConnectionState
from .runtime import ClientRuntime


_PUSHED_SEQS_LIMIT = 50000
_PENDING_ORDERED_LIMIT = 50000
_GROUP_RECALL_SEEN_LIMIT = 10000
_ONLINE_UNREAD_HINT_INITIAL_DELAY = 0.75
_ONLINE_UNREAD_HINT_INTERVAL = 0.05


_APP_MESSAGE_ENVELOPE_KEYS = (
    "module_id", "message_type", "type", "kind", "version",
    "from", "from_aid", "sender_aid", "to", "to_aid", "group_id",
    "timestamp", "created_at", "encrypted",
    "context", "protected_headers", "headers", "payload_type",
)

_APP_GROUP_EVENT_ENVELOPE_KEYS = (
    "module_id", "event_id", "event_seq", "seq", "event_type", "action", "group_id",
    "actor_aid", "sender_aid", "member_aid", "target_aid", "operator_aid",
    "created_at", "timestamp", "t_server", "status", "device_id", "slot_id",
)

_APP_SEND_ENVELOPE_METHODS = {
    "message.send",
    "group.send",
    "message.thought.put",
    "group.thought.put",
}


class MessageDeliveryEngine:
    """消息推送、拉取、有序投递、补洞与 ack 协调器。"""

    def __init__(self, runtime: Any) -> None:
        self.runtime = ClientRuntime.coerce(runtime)
        self.client = self.runtime.client

    async def postprocess_result(self, method: str, params: dict[str, Any], result: Any) -> Any:
        if method == "message.pull" and isinstance(result, dict):
            self._postprocess_message_pull(method, params, result)
        if method == "group.pull" and isinstance(result, dict):
            self._postprocess_group_pull(method, params, result)
        return result

    def _postprocess_message_pull(self, method: str, params: dict[str, Any], result: dict[str, Any]) -> None:
        client = self.client
        ns = f"p2p:{client._aid}" if client._aid else ""
        messages = result.get("messages")
        if isinstance(messages, list):
            for msg in messages:
                client._log_message_debug("pull-raw", method, "message.received", msg)
        contig_before = client._seq_tracker.get_contiguous_seq(ns) if client._aid and getattr(client, "_seq_tracker", None) is not None else 0
        if isinstance(messages, list) and messages and client._aid and getattr(client, "_seq_tracker", None) is not None:
            client._seq_tracker.on_pull_result(ns, messages, after_seq=int((params or {}).get("after_seq", 0) or 0))
        if client._aid and getattr(client, "_seq_tracker", None) is not None:
            server_ack = int(result.get("server_ack_seq") or 0)
            if server_ack > 0:
                contig = client._seq_tracker.get_contiguous_seq(ns)
                if contig < server_ack:
                    client._log.info("client",
                        "message.pull retention-floor 推进: ns=%s contiguous=%d -> server_ack_seq=%d",
                        ns, contig, server_ack,
                    )
                    client._seq_tracker.force_contiguous_seq(ns, server_ack)
            contig = client._seq_tracker.get_contiguous_seq(ns)
            if contig != contig_before:
                client._persist_seq(ns)
            # auto-ack 延迟到 publish 完成后（由 _fill_p2p_gap 负责）
            result["_contig_before"] = contig_before

    def _postprocess_group_pull(self, method: str, params: dict[str, Any], result: dict[str, Any]) -> None:
        client = self.client
        messages = result.get("messages")
        if isinstance(messages, list):
            for msg in messages:
                client._log_message_debug("pull-raw", method, "group.message_created", msg)
        gid = (params or {}).get("group_id", "")
        ns = f"group:{gid}" if gid else ""
        contig_before = client._seq_tracker.get_contiguous_seq(ns) if gid and getattr(client, "_seq_tracker", None) is not None else 0
        if isinstance(messages, list) and messages and gid and getattr(client, "_seq_tracker", None) is not None:
            client._seq_tracker.on_pull_result(ns, messages, after_seq=int((params or {}).get("after_seq", 0) or 0))
        if gid and getattr(client, "_seq_tracker", None) is not None:
            cursor = result.get("cursor")
            if isinstance(cursor, dict):
                server_ack = int(cursor.get("current_seq") or 0)
                if server_ack > 0:
                    contig = client._seq_tracker.get_contiguous_seq(ns)
                    if contig < server_ack:
                        client._log.info("client",
                            "group.pull retention-floor 推进: ns=%s contiguous=%d -> cursor.current_seq=%d",
                            ns, contig, server_ack,
                        )
                        client._seq_tracker.force_contiguous_seq(ns, server_ack)
            contig = client._seq_tracker.get_contiguous_seq(ns)
            if contig != contig_before:
                client._persist_seq(ns)
            # auto-ack 延迟到 publish 完成后（由 _fill_group_gap / _fill_p2p_gap 负责）
            result["_contig_before"] = contig_before

    def mark_published_seq(self, ns: str, seq: int) -> None:
        """记录已发布到应用层的 seq，供 push/pull/补洞路径统一去重。"""
        client = self.client
        pushed = getattr(client, "_pushed_seqs", None)
        if pushed is None:
            pushed = {}
            client._pushed_seqs = pushed
        pushed.setdefault(ns, set()).add(seq)
        client._enforce_pushed_seqs_limit(ns)

    def is_published_seq(self, ns: str, seq: int) -> bool:
        """republish guard：同一 namespace + seq 在应用层只发布一次。"""
        pushed = getattr(self.client, "_pushed_seqs", None)
        if pushed is None:
            return False
        return seq in pushed.get(ns, set())

    def is_pending_ordered_seq(self, ns: str, seq: int) -> bool:
        """同一 namespace + seq 已解密并等待有序发布。"""
        return seq in self.client._pending_ordered().get(ns, {})

    def pending_ordered(self) -> dict[str, dict[int, tuple[str, Any]]]:
        return self.runtime.delivery.pending_ordered

    def enqueue_ordered_message(self, ns: str, event: str, seq: int, payload: Any) -> None:
        pending = self.client._pending_ordered()
        queue = pending.setdefault(ns, {})
        queue[seq] = (event, payload)
        if len(queue) > _PENDING_ORDERED_LIMIT:
            for old_seq in sorted(queue)[: len(queue) - _PENDING_ORDERED_LIMIT]:
                queue.pop(old_seq, None)

    @staticmethod
    def is_group_event_namespace(ns: str) -> bool:
        return ns.startswith("group_event:")

    async def publish_ordered_queue_item(self, ns: str, event: str, seq: int, payload: Any, *, source: str) -> None:
        client = self.client
        if event == "group.changed" and self.is_group_event_namespace(ns):
            await self.publish_ordered_group_changed(payload, source=source)
            return
        await client._publish_app_event(event, payload, source=source)

    async def publish_ordered_group_changed(self, payload: Any, *, source: str = "ordered") -> None:
        client = self.client
        if isinstance(payload, dict):
            client._group_state().handle_group_changed_v2_membership(payload)
            if payload.get("action") == "dissolved":
                group_id = str(payload.get("group_id") or "").strip()
                if group_id:
                    client._cleanup_dissolved_group(group_id)
        await client._publish_app_event("group.changed", payload, source=source)

    async def handle_group_changed_event(self, data: dict[str, Any], group_id: str) -> None:
        """按 group_event:{group_id} 对 group.changed 做 SDK 内部消费和应用发布保序。"""
        client = self.client
        raw_event_seq = data.get("event_seq")
        try:
            event_seq = int(raw_event_seq)
        except (TypeError, ValueError) as exc:
            client._log.debug(
                "client",
                "group.changed event_seq parse failed: group=%s event_seq=%r err=%s",
                group_id, raw_event_seq, exc,
            )
            await self.publish_ordered_group_changed(data, source="legacy")
            return

        if event_seq <= 0 or not group_id:
            await self.publish_ordered_group_changed(data, source="legacy")
            return

        ns = f"group_event:{group_id}"
        if self.is_self_join_group_changed(data):
            contig = client._seq_tracker.get_contiguous_seq(ns)
            max_seen = client._seq_tracker.get_max_seen_seq(ns)
            if contig == 0 and max_seen == 0 and event_seq > 1:
                client._log.debug(
                    "client",
                    "group.changed self-join baseline: group=%s event_seq=%d baseline=%d",
                    group_id, event_seq, event_seq - 1,
                )
                client._seq_tracker.force_contiguous_seq(ns, event_seq - 1)
        contig_before = client._seq_tracker.get_contiguous_seq(ns)
        if event_seq <= contig_before or client._is_published_seq(ns, event_seq):
            client._log.debug(
                "client",
                "group.changed skipped duplicate/stale: group=%s event_seq=%d contiguous=%d",
                group_id, event_seq, contig_before,
            )
            return

        client._enqueue_ordered_message(ns, "group.changed", event_seq, data)
        need_pull = client._seq_tracker.on_message_seq(ns, event_seq)
        ack_contig = client._seq_tracker.get_contiguous_seq(ns)
        ack_max_seen = client._seq_tracker.get_max_seen_seq(ns)
        await client._drain_ordered_messages(ns)

        if ack_contig > 0 and ack_contig != contig_before:
            if getattr(client, "_aid", "") and data.get("action") != "dissolved":
                client._persist_seq(ns)
            if getattr(client, "_transport", None) is not None:
                ack_seq = min(ack_contig, ack_max_seen or ack_contig)
                client._fire_ack("group.ack_events", {
                    "group_id": group_id,
                    "event_seq": ack_seq,
                    "device_id": getattr(client, "_device_id", ""),
                    "slot_id": getattr(client, "_slot_id", ""),
                }, "group event push")

        if need_pull and not data.get("_from_gap_fill"):
            client._log.debug(
                "client",
                "group.changed event gap detected, triggering gap fill: group=%s event_seq=%s",
                group_id, raw_event_seq,
            )
            loop = getattr(client, "_loop", None) or asyncio.get_running_loop()
            loop.create_task(client._fill_group_event_gap(group_id))

    def is_self_join_group_changed(self, data: dict[str, Any]) -> bool:
        action = str(data.get("action") or "").strip()
        join_actions = {"member_added", "joined", "join_approved", "invite_code_used"}
        if action not in join_actions:
            return False
        self_aid = str(getattr(self.client, "_aid", "") or "").strip()
        if not self_aid:
            return False
        joined_aid = str(data.get("joined_aid") or data.get("member_aid") or data.get("aid") or "").strip()
        if joined_aid == self_aid:
            return True
        actor_aid = str(data.get("actor_aid") or "").strip()
        return not joined_aid and action in {"joined", "invite_code_used"} and actor_aid == self_aid

    @staticmethod
    def is_instance_scoped_message_event(event: str) -> bool:
        return event in {
            "message.received",
            "message.recalled",
            "message.undecryptable",
            "group.message_created",
            "group.message_recalled",
            "group.message_undecryptable",
        }

    def attach_current_instance_context(self, payload: Any) -> Any:
        client = self.client
        if not isinstance(payload, dict):
            return payload
        result = dict(payload)
        if "device_id" not in result:
            result["device_id"] = client._device_id
        if client._slot_id and not str(result.get("slot_id") or "").strip():
            result["slot_id"] = client._slot_id
        return result

    def normalize_published_message_payload(self, event: str, payload: Any) -> Any:
        if self.client._is_instance_scoped_message_event(event):
            normalized = self.strip_internal_sender_device_fields(
                self.client._attach_current_instance_context(payload)
            )
            return self.attach_app_message_envelope(normalized)
        if self.is_group_scoped_event(event):
            normalized = self.client._attach_current_instance_context(payload)
            return self.attach_app_group_event_envelope(normalized)
        return payload

    @staticmethod
    def envelope_metadata(value: Any) -> dict[str, Any] | None:
        to_dict = getattr(value, "to_dict", None)
        if callable(to_dict):
            value = to_dict()
        if not isinstance(value, dict):
            return None
        result = {key: item for key, item in value.items() if str(key) != "_auth"}
        return result if result else None

    @classmethod
    def app_message_envelope(cls, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            return {}
        body = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}
        envelope: dict[str, Any] = {}

        def first_value(*values: Any) -> Any:
            for value in values:
                if value is None:
                    continue
                if isinstance(value, str) and not value.strip():
                    continue
                return value
            return None

        def set_if_present(key: str, value: Any) -> None:
            if value is None:
                return
            if isinstance(value, str) and not value.strip():
                return
            envelope[key] = value

        set_if_present("from", first_value(payload.get("from"), payload.get("from_aid"), payload.get("sender_aid")))
        set_if_present("to", first_value(payload.get("to"), payload.get("to_aid")))
        set_if_present("group_id", payload.get("group_id"))
        set_if_present("type", first_value(body.get("type"), payload.get("type"), payload.get("message_type"), payload.get("payload_type")))
        set_if_present("kind", first_value(body.get("kind"), payload.get("kind")))
        set_if_present("version", first_value(body.get("version"), payload.get("version")))
        set_if_present("timestamp", first_value(payload.get("timestamp"), payload.get("created_at"), payload.get("t_server")))
        if "encrypted" in payload:
            envelope["encrypted"] = bool(payload.get("encrypted"))
        context = cls.envelope_metadata(payload.get("context"))
        if context:
            envelope["context"] = context
        protected_headers = cls.envelope_metadata(payload.get("protected_headers")) or cls.envelope_metadata(payload.get("headers"))
        if protected_headers:
            envelope["protected_headers"] = protected_headers
        set_if_present("payload_type", first_value(payload.get("payload_type"), (protected_headers or {}).get("payload_type")))
        return envelope

    @staticmethod
    def is_group_scoped_event(event: str) -> bool:
        return event in {"group.changed"}

    @staticmethod
    def app_group_event_envelope(payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            return {}
        return {key: payload[key] for key in _APP_GROUP_EVENT_ENVELOPE_KEYS if key in payload}

    @classmethod
    def attach_app_message_envelope(cls, payload: Any) -> Any:
        if not isinstance(payload, dict):
            return payload
        result = dict(payload)
        # 兼容期保留顶层信封字段；下一个大版本 0.5.* 将移除这些顶层别名，请通过 envelope.* 访问。
        result["envelope"] = cls.app_message_envelope(result)
        return result

    def send_result_envelope(self, method: str, params: dict[str, Any], result: Any, *, encrypted: bool) -> dict[str, Any]:
        if method not in _APP_SEND_ENVELOPE_METHODS:
            return {}
        body = params.get("payload") if isinstance(params.get("payload"), dict) else {}
        result_map = result if isinstance(result, dict) else {}
        envelope: dict[str, Any] = {}

        def first_value(*values: Any) -> Any:
            for value in values:
                if value is None:
                    continue
                if isinstance(value, str) and not value.strip():
                    continue
                return value
            return None

        def set_if_present(key: str, value: Any) -> None:
            if value is None:
                return
            if isinstance(value, str) and not value.strip():
                return
            envelope[key] = value

        set_if_present("from", getattr(self.client, "_aid", ""))
        if method.startswith("message."):
            set_if_present("to", params.get("to"))
        else:
            set_if_present("group_id", params.get("group_id"))
        set_if_present("type", first_value(body.get("type"), params.get("type"), params.get("message_type"), params.get("payload_type")))
        set_if_present("kind", first_value(body.get("kind"), params.get("kind")))
        set_if_present("version", first_value(body.get("version"), params.get("version")))
        set_if_present(
            "timestamp",
            first_value(
                params.get("timestamp"),
                result_map.get("timestamp"),
                result_map.get("created_at"),
                result_map.get("t_server"),
                int(time.time() * 1000),
            ),
        )
        envelope["encrypted"] = bool(encrypted)
        context = self.envelope_metadata(params.get("context"))
        if context:
            envelope["context"] = context
        protected_headers = self.envelope_metadata(params.get("protected_headers")) or self.envelope_metadata(params.get("headers")) or {}
        if protected_headers:
            envelope["protected_headers"] = protected_headers
        set_if_present("payload_type", first_value(params.get("payload_type"), protected_headers.get("payload_type"), body.get("type")))
        return envelope

    def attach_send_result_envelope(self, method: str, params: dict[str, Any], result: Any, *, encrypted: bool) -> Any:
        if method not in _APP_SEND_ENVELOPE_METHODS or not isinstance(result, dict):
            return result
        out = dict(result)
        out["envelope"] = self.send_result_envelope(method, params, out, encrypted=encrypted)
        if "payload" in params:
            out["payload"] = params.get("payload")
        elif "content" in params:
            out["payload"] = params.get("content")
        return out

    @classmethod
    def attach_app_group_event_envelope(cls, payload: Any) -> Any:
        if not isinstance(payload, dict):
            return payload
        result = dict(payload)
        # 兼容期保留顶层群事件信封字段；下一个大版本 0.5.* 将移除这些顶层别名，请通过 envelope.* 访问。
        result["envelope"] = cls.app_group_event_envelope(result)
        return result

    @staticmethod
    def strip_internal_sender_device_fields(payload: Any) -> Any:
        if not isinstance(payload, dict):
            return payload
        result = dict(payload)
        for key in ("sender_device_id", "_sender_device_id", "from_device_id", "from_device"):
            result.pop(key, None)
        return result

    @staticmethod
    def recall_event_from_message(message: Any) -> dict[str, Any] | None:
        """把 pull 返回的 recall tombstone 归一化为应用层 message.recalled payload。"""
        if not isinstance(message, dict):
            return None
        payload = message.get("payload")
        payload_dict = payload if isinstance(payload, dict) else {}
        msg_type = str(message.get("type") or "").strip()
        payload_type = str(payload_dict.get("type") or payload_dict.get("kind") or "").strip()
        if msg_type != "message.recalled" and payload_type != "message.recalled":
            return None
        event = dict(payload_dict)
        for key in _APP_MESSAGE_ENVELOPE_KEYS:
            if key in message and key not in event:
                event[key] = message[key]
        raw_ids = event.get("message_ids")
        if isinstance(raw_ids, list):
            message_ids = [str(item or "").strip() for item in raw_ids if str(item or "").strip()]
        else:
            message_ids = []
        if not message_ids:
            for key in ("recalled_message_id", "target_message_id", "original_message_id"):
                value = str(event.get(key) or "").strip()
                if value:
                    message_ids = [value]
                    break
        event["type"] = "message.recalled"
        event["kind"] = "message.recalled"
        event["message_ids"] = message_ids
        event.setdefault("from", message.get("from") or message.get("from_aid") or "")
        event.setdefault("to", message.get("to") or message.get("to_aid") or "")
        event.setdefault("timestamp", message.get("timestamp") or message.get("t_server") or event.get("recalled_at") or 0)
        if "seq" in message:
            event.setdefault("seq", message.get("seq"))
        if "message_id" in message:
            event["message_id"] = message.get("message_id")
            event.setdefault("tombstone_message_id", message.get("message_id"))
        if "device_id" in message:
            event.setdefault("device_id", message.get("device_id"))
        if "slot_id" in message:
            event.setdefault("slot_id", message.get("slot_id"))
        return event

    def p2p_app_event_for_message(self, message: Any) -> tuple[str, Any]:
        recall = self.recall_event_from_message(message)
        if recall is not None:
            return "message.recalled", recall
        return "message.received", message

    @staticmethod
    def recall_event_from_group_message(message: Any) -> dict[str, Any] | None:
        """把 pull / push 收到的群撤回 tombstone 归一化为 group.message_recalled payload。

        识别条件：顶层 type / kind 或 payload.type / payload.kind == "group.message_recalled"。
        占位 tombstone（原 seq）与通知 tombstone（新 seq）都满足此条件，统一归一化，
        由 publish_group_recall_tombstone 负责按 (group_id, original_message_id) 去重。
        """
        if not isinstance(message, dict):
            return None
        payload = message.get("payload")
        payload_dict = payload if isinstance(payload, dict) else {}
        msg_type = str(message.get("type") or message.get("kind") or message.get("message_type") or "").strip()
        payload_type = str(payload_dict.get("type") or payload_dict.get("kind") or "").strip()
        if msg_type != "group.message_recalled" and payload_type != "group.message_recalled":
            return None
        event = dict(payload_dict)
        for key in _APP_MESSAGE_ENVELOPE_KEYS:
            if key in message and key not in event:
                event[key] = message[key]
        raw_ids = event.get("message_ids")
        if isinstance(raw_ids, list):
            message_ids = [str(item or "").strip() for item in raw_ids if str(item or "").strip()]
        else:
            message_ids = []
        if not message_ids:
            for key in ("recalled_message_id", "target_message_id", "original_message_id"):
                value = str(event.get(key) or "").strip()
                if value:
                    message_ids = [value]
                    break
        event["type"] = "group.message_recalled"
        event["kind"] = "group.message_recalled"
        event["message_ids"] = message_ids
        event.setdefault("group_id", message.get("group_id") or "")
        event.setdefault(
            "timestamp",
            message.get("timestamp") or message.get("t_server") or event.get("recalled_at") or 0,
        )
        if "seq" in message:
            event["seq"] = message.get("seq")
        if "message_id" in message:
            event["message_id"] = message.get("message_id")
            event.setdefault("tombstone_message_id", message.get("message_id"))
        return event

    @staticmethod
    def group_recall_dedup_key(group_id: str, payload: dict[str, Any]) -> str:
        """群撤回去重键：group_id + 排序后的 message_ids。

        一条消息只能被撤回一次（服务端 group_message_recalls uk_recall_msg_id 唯一约束），
        (group_id, sorted message_ids) 已能唯一标识一次撤回。
        去重键不含 recalled_at：占位/通知 tombstone（pull）与在线 push 三条通道对同一次撤回
        可能携带不同来源的时间戳（push 在事务后重取），纳入 recalled_at 会使去重失效、回调多次。
        """
        ids = payload.get("message_ids")
        if isinstance(ids, list):
            id_part = ",".join(sorted(str(i or "").strip() for i in ids if str(i or "").strip()))
        else:
            id_part = str(ids or "")
        return f"{group_id}|{id_part}"

    async def publish_group_recall_tombstone(self, group_id: str, seq: Any, message: Any) -> bool:
        """把群撤回 tombstone 归一化并按去重键发布一次 group.message_recalled。

        返回 True 表示本次实际发布了事件；False 表示被去重抑制或不是撤回 tombstone。
        """
        client = self.client
        event_payload = self.recall_event_from_group_message(message)
        if event_payload is None:
            return False
        dedup_key = self.group_recall_dedup_key(group_id, event_payload)
        seen = getattr(client, "_group_recall_seen", None)
        if seen is None:
            seen = {}
            try:
                client._group_recall_seen = seen
            except Exception:
                seen = {}
        if dedup_key in seen:
            client._log.debug(
                "client",
                "group.message_recalled 去重抑制: group=%s seq=%s key=%s",
                group_id, seq, dedup_key,
            )
            return False
        seen[dedup_key] = time.time()
        # 限制去重表大小，避免长期运行无限增长。
        if len(seen) > _GROUP_RECALL_SEEN_LIMIT:
            for old_key in sorted(seen, key=lambda k: seen[k])[: len(seen) - _GROUP_RECALL_SEEN_LIMIT]:
                seen.pop(old_key, None)
        await client._publish_app_event("group.message_recalled", event_payload, source="group-recall")
        client._log.debug(
            "client",
            "group.message_recalled 发布: group=%s seq=%s message_ids=%s",
            group_id, seq, event_payload.get("message_ids"),
        )
        return True

    @staticmethod
    def debug_json_default(value: Any) -> Any:
        if isinstance(value, (bytes, bytearray)):
            raw = bytes(value)
            return {
                "_type": "bytes",
                "len": len(raw),
                "base64": base64.b64encode(raw).decode("ascii"),
            }
        return str(value)

    @classmethod
    def debug_json(cls, value: Any) -> str:
        try:
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=cls.debug_json_default)
        except Exception:
            return str(value)

    @staticmethod
    def message_payload_for_debug(message: Any) -> Any:
        if not isinstance(message, dict):
            return message
        if "payload" in message:
            return message.get("payload")
        if "content" in message:
            return message.get("content")
        if "envelope_json" in message:
            raw = message.get("envelope_json")
            if isinstance(raw, str):
                try:
                    return json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    return raw
            return raw
        legacy = message.get("legacy_v1")
        if isinstance(legacy, dict):
            if "payload" in legacy:
                return legacy.get("payload")
            if "content" in legacy:
                return legacy.get("content")
        return None

    @staticmethod
    def message_envelope_fields_for_debug(message: Any) -> Any:
        if not isinstance(message, dict):
            return {"value_type": type(message).__name__}
        keys = (
            "message_id", "id", "from", "from_aid", "sender_aid", "to", "to_aid",
            "group_id", "seq", "msg_seq", "type", "version", "timestamp", "t_server",
            "device_id", "slot_id", "encrypted", "dispatch_mode", "dispatch",
            "e2ee", "headers", "protected_headers", "context", "status",
        )
        return {key: message[key] for key in keys if key in message}

    def log_message_debug(
        self,
        stage: str,
        source: str,
        event: str,
        message: Any,
        *,
        payload_override: Any = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "stage": stage,
            "source": source,
            "event": event,
            "envelope": self.client._message_envelope_fields_for_debug(message),
            "payload": payload_override if payload_override is not None else self.client._message_payload_for_debug(message),
        }
        if extra:
            record["extra"] = extra
        self.client._log.debug("client", "message.debug %s", self.client._debug_json(record))

    def log_app_message_publish(self, event: str, payload: Any, source: str) -> None:
        if event not in ("message.received", "group.message_created"):
            return
        self.client._log_message_debug("publish", source, event, payload)

    async def publish_app_event(self, event: str, payload: Any, *, source: str = "direct") -> None:
        client = self.client
        if event in ("message.received", "group.message_created") and isinstance(payload, dict):
            client._maybe_append_echo_trace_receive(payload)
            client._log_app_message_publish(event, payload, source)
        # 注入本地/远端 agent.md etag，让应用层判断版本一致性；失败不影响业务。
        if isinstance(payload, dict):
            try:
                snapshot = client._agent_md_manager.event_snapshot()
                if snapshot:
                    payload.setdefault("_agent_md", snapshot)
            except Exception as exc:
                client._log.debug("client", "agent_md etag inject skipped: %s", exc)
        await client._dispatcher.publish(
            event,
            client._normalize_published_message_payload(event, payload),
        )

    def message_targets_current_instance(self, message: Any) -> bool:
        client = self.client
        if not isinstance(message, dict):
            return True
        if "device_id" in message:
            target_device_id = str(message.get("device_id") or "").strip()
            if target_device_id != client._device_id:
                return False
        target_slot_id = str(message.get("slot_id") or "").strip()
        if target_slot_id and client._slot_id and slot_isolation_key(target_slot_id) != slot_isolation_key(client._slot_id):
            return False
        return True

    async def drain_ordered_messages(self, ns: str, *, before_seq: int | None = None) -> None:
        """把已经落在 contiguous_seq 内的挂起消息按 seq 升序放行。"""
        client = self.client
        pending = client._pending_ordered().get(ns)
        if not pending:
            return
        contig = client._seq_tracker.get_contiguous_seq(ns)
        ready = sorted(
            seq for seq in pending
            if seq <= contig and (before_seq is None or seq < before_seq)
        )
        for seq in ready:
            event, payload = pending.pop(seq)
            if client._is_published_seq(ns, seq):
                client._log.debug("client", "publish ordered drain skipped duplicate: ns=%s seq=%d event=%s", ns, seq, event)
                continue
            await self.publish_ordered_queue_item(ns, event, seq, payload, source="ordered-drain")
            client._mark_published_seq(ns, seq)
            client._log.debug("client", "publish ordered drain delivered: ns=%s seq=%d event=%s", ns, seq, event)
        if not pending:
            client._pending_ordered().pop(ns, None)

    async def publish_ordered_message(self, event: str, ns: str, seq: Any, payload: Any) -> bool:
        """按 contiguous_seq 对应用层事件做有序放行。"""
        client = self.client
        try:
            seq_i = int(seq)
        except (TypeError, ValueError):
            client._log.debug("client", "publish ordered direct(no-seq): event=%s ns=%s seq=%s", event, ns or "<none>", seq)
            await self.publish_ordered_queue_item(ns, event, 0, payload, source="ordered")
            return True
        if seq_i <= 0:
            client._log.debug("client", "publish ordered direct(no-seq): event=%s ns=%s seq=%s", event, ns or "<none>", seq_i)
            await self.publish_ordered_queue_item(ns, event, seq_i, payload, source="ordered")
            return True
        if client._is_published_seq(ns, seq_i):
            # 如果同 seq 也曾挂起，顺手清理，避免后续 drain 重复处理。
            client._log.debug(
                "client",
                "publish ordered skipped already published: ns=%s seq=%d",
                ns, seq_i,
            )
            pending = client._pending_ordered().get(ns)
            if pending:
                pending.pop(seq_i, None)
                if not pending:
                    client._pending_ordered().pop(ns, None)
            return False

        contig = client._seq_tracker.get_contiguous_seq(ns)
        if seq_i > contig:
            client._log.debug(
                "client",
                "publish ordered enqueue gap: ns=%s seq=%d contig=%d",
                ns, seq_i, contig,
            )
            client._enqueue_ordered_message(ns, event, seq_i, payload)
            return False

        await client._drain_ordered_messages(ns, before_seq=seq_i)
        if client._is_published_seq(ns, seq_i):
            return False
        pending = client._pending_ordered().get(ns)
        if pending:
            pending.pop(seq_i, None)
            if not pending:
                client._pending_ordered().pop(ns, None)
        await self.publish_ordered_queue_item(ns, event, seq_i, payload, source="ordered")
        client._mark_published_seq(ns, seq_i)
        client._log.debug("client", "publish ordered delivered: event=%s ns=%s seq=%d", event, ns, seq_i)
        await client._drain_ordered_messages(ns)
        return True

    async def publish_pulled_message(self, event: str, ns: str, seq: Any, payload: Any) -> bool:
        """发布 pull 批中的消息，只按 namespace+seq 去重，不受批内部空洞阻塞。"""
        client = self.client
        try:
            seq_i = int(seq)
        except (TypeError, ValueError):
            client._log.debug("client", "publish pulled direct(no-seq): event=%s ns=%s seq=%s", event, ns or "<none>", seq)
            await client._publish_app_event(event, payload, source="pull")
            return True
        if seq_i <= 0 or not ns:
            client._log.debug("client", "publish pulled direct(no-seq): event=%s ns=%s seq=%s", event, ns or "<none>", seq_i)
            await client._publish_app_event(event, payload, source="pull")
            return True
        if client._is_published_seq(ns, seq_i):
            client._log.debug("client", "publish pulled skipped duplicate: event=%s ns=%s seq=%d", event, ns, seq_i)
            pending = client._pending_ordered().get(ns)
            if pending:
                pending.pop(seq_i, None)
                if not pending:
                    client._pending_ordered().pop(ns, None)
            return False
        pending = client._pending_ordered().get(ns)
        if pending:
            pending.pop(seq_i, None)
            if not pending:
                client._pending_ordered().pop(ns, None)
        await client._publish_app_event(event, payload, source="pull")
        client._mark_published_seq(ns, seq_i)
        client._log.debug("client", "publish pulled delivered: event=%s ns=%s seq=%d", event, ns, seq_i)
        return True

    def prune_pushed_seqs(self, ns: str) -> None:
        """维护已发布 seq 集合的内存上限。"""
        pushed = self.client._pushed_seqs.get(ns)
        if not pushed:
            return
        self.client._enforce_pushed_seqs_limit(ns)

    def enforce_pushed_seqs_limit(self, ns: str) -> None:
        """pushed_seqs 超过硬上限时清理最旧条目。"""
        client = self.client
        pushed = client._pushed_seqs.get(ns)
        if not pushed or len(pushed) <= _PUSHED_SEQS_LIMIT:
            return
        # 保留最大（最新）的 _PUSHED_SEQS_LIMIT 个条目
        sorted_seqs = sorted(pushed)
        keep = set(sorted_seqs[-_PUSHED_SEQS_LIMIT:])
        client._pushed_seqs[ns] = keep

    def fire_ack(self, method: str, params: dict[str, Any], label: str = "") -> None:
        """将 ack RPC 以 fire-and-forget 方式发送，不阻塞消息事件分发。"""
        client = self.client
        params = client._clamp_ack_params(method, params) if isinstance(params, dict) else params
        loop = getattr(client, "_loop", None) or asyncio.get_running_loop()
        loop.create_task(client._safe_ack(method, params, label))

    async def await_ack(self, method: str, params: dict[str, Any], label: str = "") -> None:
        """等待 ack RPC 完成，用于显式 pull 返回前收敛服务端游标。"""
        client = self.client
        params = client._clamp_ack_params(method, params) if isinstance(params, dict) else params
        await client._safe_ack(method, params, label)

    def clamp_ack_params(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """ack 参数边界保护：clamp 到 [0, max_seen_seq]。"""
        client = self.client

        def _clamp_field(p: dict, field: str, ns: str) -> dict:
            value = p.get(field)
            if not isinstance(value, (int, float)):
                return p
            ivalue = int(value)
            new_value = ivalue
            if ivalue < 0:
                new_value = 0
            if ns:
                max_seen = client._seq_tracker.get_max_seen_seq(ns)
                if max_seen > 0 and new_value > max_seen:
                    client._log.warn(
                        "client",
                        "ack clamp: method=%s %s=%d > max_seen=%d, clamp",
                        method, field, ivalue, max_seen,
                    )
                    new_value = max_seen
            if new_value != ivalue:
                return {**p, field: new_value}
            return p

        if method == "message.v2.ack":
            ns = f"p2p:{client._aid}" if client._aid else ""
            return _clamp_field(params, "up_to_seq", ns)
        if method == "message.ack":
            ns = f"p2p:{client._aid}" if client._aid else ""
            return _clamp_field(params, "seq", ns)
        # Group ack: ns 来自 group_id
        if method in ("group.v2.ack", "group.ack_messages", "group.ack_events"):
            group_id = str(params.get("group_id") or "").strip()
            if method == "group.v2.ack":
                ns = f"group:{group_id}" if group_id else ""
                return _clamp_field(params, "up_to_seq", ns)
            if method == "group.ack_messages":
                ns = f"group:{group_id}" if group_id else ""
                return _clamp_field(params, "msg_seq", ns)
            if method == "group.ack_events":
                ns = f"group_event:{group_id}" if group_id else ""
                return _clamp_field(params, "event_seq", ns)
        return params

    async def safe_ack(self, method: str, params: dict[str, Any], label: str = "") -> None:
        """安全执行 ack RPC，失败仅记录日志。"""
        client = self.client
        try:
            params = dict(params)
            if method in client._SIGNED_METHODS:
                client._sign_client_operation(method, params)
            client._log.debug("client", "%s auto-ack send: method=%s params=%s", label or method, method, params)
            result = await client._transport.call(method, params)
            client._log.debug("client", "%s auto-ack ok: method=%s result=%s", label or method, method, result)
        except Exception as exc:
            client._log.debug("client", "%s auto-ack failed: %s", label or method, exc)

    async def on_raw_message_received(self, data: Any) -> None:
        """处理 transport 层推送的原始消息：解密后 re-publish 给用户。"""
        client = self.client
        t_start = time.time()
        if isinstance(data, dict):
            client._log_message_debug("server-push", "_raw.message.received", "message.received", data)
            client._log.debug(
                "client",
                "_on_raw_message_received enter: message_id=%s seq=%s from=%s",
                data.get("message_id", "-"), data.get("seq", "-"), data.get("from", "-"),
            )
        else:
            client._log.debug("client", "_on_raw_message_received enter (non-dict): type=%s", type(data).__name__)
        loop = getattr(client, "_loop", None) or asyncio.get_running_loop()
        loop.create_task(client._process_and_publish_message(data))
        client._log.debug("client", "_on_raw_message_received exit: elapsed=%.3fs", time.time() - t_start)

    async def process_and_publish_message(self, data: Any) -> None:
        """实际处理 P2P 推送消息的异步任务。"""
        client = self.client
        ns_key = ""
        if isinstance(data, dict) and data.get("seq") is not None and client._aid:
            ns_key = f"p2p:{client._aid}"
        if ns_key:
            async with client._get_ns_lock(ns_key):
                await client._process_and_publish_message_inner(data)
        else:
            await client._process_and_publish_message_inner(data)

    async def process_and_publish_message_inner(self, data: Any) -> None:
        """P2P push 处理内部实现（在 ns lock 保护下调用）。"""
        client = self.client
        try:
            if not isinstance(data, dict):
                await client._publish_app_event("message.received", data)
                return
            msg = dict(data)
            client._log.debug(
                "client",
                "_process_and_publish_message enter: message_id=%s seq=%s from=%s device_id=%s slot_id=%s",
                msg.get("message_id"), msg.get("seq"), msg.get("from"),
                msg.get("device_id"), msg.get("slot_id"),
            )
            if not client._message_targets_current_instance(msg):
                client._log.debug(
                    "client",
                    "_process_and_publish_message filtered (instance mismatch): "
                    "msg_device=%s self_device=%s msg_slot=%s self_slot=%s",
                    msg.get("device_id"), client._device_id,
                    msg.get("slot_id"), client._slot_id,
                )
                return

            # P2P 空洞检测
            seq = msg.get("seq")
            encrypted_push = client._is_encrypted_push_message(msg)
            if seq is not None and client._aid:
                ns = f"p2p:{client._aid}"
                # Push 修上界：先更新 max_seen_seq，让上界反映服务端状态（即使后续被去重/旁路）
                seq_int = int(seq) if isinstance(seq, (int, float)) else 0
                if seq_int > 0:
                    client._seq_tracker.update_max_seen(ns, seq_int)
                old_contig = client._seq_tracker.get_contiguous_seq(ns)
                need_pull = client._seq_tracker.on_message_seq(ns, seq_int)
                new_contig = client._seq_tracker.get_contiguous_seq(ns)
                client._log.debug("client", "P2P push seq tracking: seq=%d contig=%d->%d need_pull=%s",
                                  seq_int, old_contig, new_contig, need_pull)
                client._persist_seq(ns)
                if need_pull:
                    loop = getattr(client, "_loop", None) or asyncio.get_running_loop()
                    loop.create_task(client._fill_p2p_gap())

            # 明文消息直接透传（V2 加密消息走 _on_v2_push_notification）
            if seq is not None and client._aid:
                client._log.debug(
                    "client",
                    "publish ordered: ns=%s seq=%s message_id=%s",
                    ns, seq, msg.get("message_id", "?"),
                )
                if encrypted_push:
                    await client._publish_encrypted_push_message(
                        "message.received", "message.undecryptable", ns, seq, msg, group=False,
                    )
                else:
                    await client._publish_ordered_message("message.received", ns, seq, msg)
            else:
                if encrypted_push:
                    await client._publish_encrypted_push_message(
                        "message.received", "message.undecryptable", "", seq, msg, group=False,
                    )
                    return
                client._log.debug(
                    "client",
                    "publish app event (no seq): message_id=%s",
                    msg.get("message_id", "?"),
                )
                await client._publish_app_event("message.received", msg, source="push")

            # auto-ack push 消息：ack contiguous_seq（连续确认到的最高位置，避免空洞时跳跃推进）
            if seq is not None and client._aid:
                contig = client._seq_tracker.get_contiguous_seq(ns)
                if contig > 0:
                    client._fire_ack("message.ack", {
                        "seq": contig, "device_id": client._device_id, "slot_id": client._slot_id,
                    }, "P2P auto-ack")
        except Exception as exc:
            client._log.warn("client", "P2P push processing failed: %s", exc)
            if isinstance(data, dict) and data.get("seq") is not None and client._aid:
                exc_ns = f"p2p:{client._aid}"
                exc_contig = client._seq_tracker.get_contiguous_seq(exc_ns)
                if exc_contig > 0:
                    client._fire_ack("message.ack", {
                        "seq": exc_contig, "device_id": client._device_id, "slot_id": client._slot_id,
                    }, "P2P auto-ack（异常路径）")
            # 解密失败不再投递原始密文 payload，改为发布安全的 message.undecryptable 事件。
            if isinstance(data, dict):
                safe_event = {
                    "message_id": data.get("message_id"),
                    "from": data.get("from"),
                    "to": data.get("to"),
                    "seq": data.get("seq"),
                    "timestamp": data.get("timestamp"),
                    "_decrypt_error": str(exc),
                }
                client._attach_v2_envelope_metadata_from_source(safe_event, data)
                await client._publish_app_event("message.undecryptable", safe_event)

    async def on_raw_group_message_created(self, data: Any) -> None:
        """处理 group.message_created 推送。"""
        client = self.client
        if not isinstance(data, dict):
            await client._publish_app_event("group.message_created", data, source="group-push")
            return
        group_id = str(data.get("group_id") or "").strip()
        if group_id:
            ns_key = f"group:{group_id}"
            async with client._get_ns_lock(ns_key):
                await client._on_raw_group_message_created_inner(data)
        else:
            await client._on_raw_group_message_created_inner(data)

    async def on_raw_group_message_recalled(self, data: Any) -> None:
        """处理 group.message_recalled 在线推送。

        在线 push 是实时通道，与 pull 兜底的双 tombstone 互补。push 携带的 seq 是通知
        tombstone 的 notice_seq；必须像普通群消息 push 一样推进 seq_tracker + mark_published +
        auto-ack，否则该 seq 在本地 contiguous 序列留洞，后续 pull/reconnect 会重复拉到并
        重复处理。publish_group_recall_tombstone 内部再按 (group_id, message_ids) 去重，
        确保应用层只回调一次。
        """
        client = self.client
        if not isinstance(data, dict):
            return
        group_id = str(data.get("group_id") or "").strip()
        # push 事件 data 本身是 recall payload；包成 recall_event_from_group_message 可识别的形状。
        wrapped = dict(data)
        wrapped.setdefault("type", "group.message_recalled")
        if "payload" not in wrapped:
            wrapped["payload"] = {
                "type": "group.message_recalled",
                "message_ids": data.get("message_ids") or [],
                "target_message_seqs": data.get("target_message_seqs") or [],
                "sender_aid": data.get("sender_aid") or "",
                "recalled_by": data.get("recalled_by") or "",
                "recalled_at": data.get("recalled_at") or data.get("timestamp") or 0,
                "reason": data.get("reason") or "",
                "group_id": group_id,
            }
        seq = data.get("seq")
        if not group_id:
            await self.publish_group_recall_tombstone(group_id, seq, wrapped)
            return
        async with client._get_ns_lock(f"group:{group_id}"):
            await self._apply_group_recall_push(group_id, seq, wrapped)

    async def _apply_group_recall_push(self, group_id: str, seq: Any, wrapped: dict) -> None:
        """在 ns lock 内推进 notice_seq 的 seq/ack 并发布撤回（与普通群消息 push 对齐）。"""
        client = self.client
        ns = f"group:{group_id}"
        if seq is not None:
            seq_i = int(seq)
            if seq_i > 0:
                client._seq_tracker.update_max_seen(ns, seq_i)
                if client._seq_tracker.get_contiguous_seq(ns) == seq_i:
                    # 已覆盖（pull 先到并推进过），仍走去重发布兜底，不重复推进 seq。
                    await self.publish_group_recall_tombstone(group_id, seq, wrapped)
                    return
                client._repair_push_contiguous_bound(
                    ns, seq_i, has_payload=True, label="_raw.group.message_recalled",
                )
            if client._is_published_seq(ns, seq_i) or client._is_pending_ordered_seq(ns, seq_i):
                # 该 notice_seq 已由 pull 路径处理过，去重发布兜底后返回。
                await self.publish_group_recall_tombstone(group_id, seq, wrapped)
                return
            client._seq_tracker.on_message_seq(ns, seq_i)
            client._persist_seq(ns)
            await self.publish_group_recall_tombstone(group_id, seq, wrapped)
            client._mark_published_seq(ns, seq_i)
            contig = client._seq_tracker.get_contiguous_seq(ns)
            if contig > 0:
                client._fire_ack("group.ack_messages", {
                    "group_id": group_id, "msg_seq": contig,
                    "device_id": client._device_id,
                    "slot_id": client._slot_id,
                }, f"群撤回 auto-ack group={group_id}")
        else:
            await self.publish_group_recall_tombstone(group_id, seq, wrapped)

    async def on_raw_group_message_created_inner(self, data: Any) -> None:
        """群消息 push 内部实现（在 ns lock 保护下调用）。"""
        client = self.client
        client._log_message_debug("server-push", "_raw.group.message_created", "group.message_created", data)
        group_id = data.get("group_id", "")
        seq = data.get("seq")
        if group_id:
            client._group_synced.add(group_id)
        payload = data.get("payload")
        has_payload = payload is not None and not (isinstance(payload, dict) and not payload)
        encrypted_push = client._is_encrypted_push_message(data) if has_payload else False

        if encrypted_push:
            if group_id and seq is not None:
                ns = f"group:{group_id}"
                seq_i = int(seq)
                if seq_i > 0:
                    client._seq_tracker.update_max_seen(ns, seq_i)
                    if client._seq_tracker.get_contiguous_seq(ns) == seq_i:
                        client._log.debug(
                            "client",
                            "_raw.group.message_created encrypted push already covered: group=%s seq=%d",
                            group_id, seq_i,
                        )
                        return
                    client._repair_push_contiguous_bound(
                        ns, seq_i, has_payload=True, label="_raw.group.message_created.encrypted",
                    )
                if client._is_published_seq(ns, seq_i) or client._is_pending_ordered_seq(ns, seq_i):
                    return
                client._seq_tracker.on_message_seq(ns, seq_i)
                client._persist_seq(ns)
                await client._publish_encrypted_push_message(
                    "group.message_created", "group.message_undecryptable", ns, seq, data, group=True,
                )
                contig = client._seq_tracker.get_contiguous_seq(ns)
                if contig > 0:
                    client._fire_ack("group.ack_messages", {
                        "group_id": group_id, "msg_seq": contig,
                        "device_id": client._device_id,
                        "slot_id": client._slot_id,
                    }, f"群消息 auto-ack group={group_id}")
            else:
                await client._publish_encrypted_push_message(
                    "group.message_created", "group.message_undecryptable", "", seq, data, group=True,
                )
            return

        # V2-only 模式：明文历史推送不带 payload 时，也通过 group.v2.pull 获取完整消息。
        if getattr(client, "_v2_session", None) and group_id and seq is not None:
            ns = f"group:{group_id}"
            seq_i = int(seq)
            if seq_i > 0:
                client._seq_tracker.update_max_seen(ns, seq_i)
                if client._seq_tracker.get_contiguous_seq(ns) == seq_i:
                    client._log.debug(
                        "client",
                        "_raw.group.message_created duplicate push already covered: group=%s seq=%d",
                        group_id, seq_i,
                    )
                    return
                client._repair_push_contiguous_bound(
                    ns, seq_i, has_payload=False, label="_raw.group.message_created",
                )
            if client._is_published_seq(ns, seq_i) or client._is_pending_ordered_seq(ns, seq_i):
                return

            async def _pull_and_publish() -> None:
                async with client._get_ns_lock(ns):
                    try:
                        dedup_key = f"group_pull:{ns}"
                        if dedup_key in client._gap_fill_done:
                            return
                        client._gap_fill_done[dedup_key] = time.time()
                        try:
                            contig = client._seq_tracker.get_contiguous_seq(ns)
                            after_seq = max(0, contig)
                            await client._pull_group_v2_internal({"group_id": group_id, "after_seq": after_seq, "limit": 50})
                        finally:
                            client._gap_fill_done.pop(dedup_key, None)
                    except Exception as exc:
                        client._log.warn("client", "_on_raw_group_message_created v2 pull failed group=%s: %s", group_id, exc)

            loop = getattr(client, "_loop", None) or asyncio.get_running_loop()
            loop.create_task(_pull_and_publish())
            return

        # 明文 payload 推送路径。
        if group_id and seq is not None:
            ns = f"group:{group_id}"
            seq_i = int(seq)
            if seq_i > 0:
                client._seq_tracker.update_max_seen(ns, seq_i)
                if client._seq_tracker.get_contiguous_seq(ns) == seq_i:
                    client._log.debug(
                        "client",
                        "_raw.group.message_created payload push already covered: group=%s seq=%d",
                        group_id, seq_i,
                    )
                    return
                client._repair_push_contiguous_bound(
                    ns, seq_i, has_payload=True, label="_raw.group.message_created",
                )
            if client._is_published_seq(ns, seq_i) or client._is_pending_ordered_seq(ns, seq_i):
                return
            client._seq_tracker.on_message_seq(ns, seq_i)
            client._persist_seq(ns)
            # 群撤回 tombstone（占位 / 通知）经普通明文推送路径到达时，归一化为 group.message_recalled。
            if self.recall_event_from_group_message(data) is not None:
                await self.publish_group_recall_tombstone(group_id, seq, data)
                client._mark_published_seq(ns, seq_i)
            else:
                await client._publish_ordered_message("group.message_created", ns, seq, data)
            contig = client._seq_tracker.get_contiguous_seq(ns)
            if contig > 0:
                client._fire_ack("group.ack_messages", {
                    "group_id": group_id, "msg_seq": contig,
                    "device_id": client._device_id,
                    "slot_id": client._slot_id,
                }, f"群消息 auto-ack group={group_id}")
        else:
            await client._publish_app_event("group.message_created", data, source="group-push")

    async def on_raw_group_v2_message_created(self, data: Any) -> None:
        """处理 V2 群消息推送：自动 group.v2.pull + 解密 + 转发。"""
        client = self.client
        t_start = time.time()
        if not isinstance(data, dict):
            client._log.debug("client", "_on_raw_group_v2_message_created skipped (non-dict): type=%s", type(data).__name__)
            return
        client._log_message_debug("server-push", "_raw.group.v2.message_created", "group.message_created", data)
        group_id = str(data.get("group_id") or "").strip()
        seq = int(data.get("seq", 0) or 0)
        message_id = str(data.get("message_id") or "").strip()
        sender_aid = str(data.get("sender_aid") or "").strip()
        event_kind = str(data.get("kind") or "").strip()
        client._log.debug(
            "client",
            "_on_raw_group_v2_message_created group=%s seq=%d message_id=%s sender=%s",
            group_id, seq, message_id, sender_aid,
        )
        if not group_id or seq <= 0:
            client._log.debug("client", "_on_raw_group_v2_message_created skipped: missing group_id or seq")
            return
        if not getattr(client, "_v2_session", None):
            client._log.debug("client", "_on_raw_group_v2_message_created skipped: V2 session not initialized")
            return
        if event_kind == "group.online_unread_hint" and not data.get("_online_hint_drained"):
            if not client._session_options.get("background_sync", True):
                client._log.debug(
                    "client",
                    "_on_raw_group_v2_message_created skipped online unread hint: group=%s background_sync=false",
                    group_id,
                )
                return
            client._enqueue_online_unread_hint(data)
            return

        ns_for_max = f"group:{group_id}"
        client._seq_tracker.update_max_seen(ns_for_max, seq)
        if client._seq_tracker.get_contiguous_seq(ns_for_max) == seq:
            client._log.debug(
                "client",
                "_on_raw_group_v2_message_created duplicate push already covered: group=%s seq=%d",
                group_id, seq,
            )
            return
        client._repair_push_contiguous_bound(
            ns_for_max, seq, has_payload=False, label="_raw.group.v2.message_created",
        )

        async def _pull_and_publish() -> None:
            ns = f"group:{group_id}"
            async with client._get_ns_lock(ns):
                try:
                    dedup_key = f"group_pull:{ns}"
                    if dedup_key in client._gap_fill_done:
                        return
                    client._gap_fill_done[dedup_key] = time.time()
                    try:
                        contig = client._seq_tracker.get_contiguous_seq(ns)
                        after_seq = max(0, contig)
                        pull_params = {"group_id": group_id, "after_seq": after_seq, "limit": 50}
                        client._log.debug(
                            "client",
                            "_on_raw_group_v2_message_created -> group.v2.pull group=%s after_seq=%d",
                            group_id, after_seq,
                        )
                        pulled = await client._pull_group_v2_internal(pull_params)
                        msgs = pulled.get("messages", []) if isinstance(pulled, dict) else []
                        client._log.debug(
                            "client",
                            "_on_raw_group_v2_message_created pulled %d msgs for group=%s",
                            len(msgs), group_id,
                        )
                    finally:
                        client._gap_fill_done.pop(dedup_key, None)
                except Exception as exc:
                    client._log.warn(
                        "client",
                        "_on_raw_group_v2_message_created pull failed group=%s: %s", group_id, exc,
                    )

        if data.get("_online_hint_drained"):
            await _pull_and_publish()
        else:
            loop = getattr(client, "_loop", None) or asyncio.get_running_loop()
            loop.create_task(_pull_and_publish())
        client._log.debug("client", "_on_raw_group_v2_message_created exit: elapsed=%.3fs", time.time() - t_start)

    def enqueue_online_unread_hint(self, data: dict[str, Any]) -> None:
        client = self.client
        group_id = str(data.get("group_id") or "").strip()
        if not group_id:
            return
        client._online_unread_hint_queue[group_id] = dict(data)
        task = client._online_unread_hint_task
        if task is not None and not task.done():
            return
        loop = getattr(client, "_loop", None) or asyncio.get_running_loop()
        self.runtime.delivery.set_online_unread_hint_task(loop.create_task(client._drain_online_unread_hints()))

    async def drain_online_unread_hints(self) -> None:
        client = self.client
        try:
            delay = max(0.0, float(getattr(client, "_online_unread_hint_initial_delay", _ONLINE_UNREAD_HINT_INITIAL_DELAY) or 0.0))
            if delay:
                await asyncio.sleep(delay)
            while client._online_unread_hint_queue:
                if client._public_state != ConnectionState.READY:
                    return
                if not client._session_options.get("background_sync", True):
                    return
                group_id = next(iter(client._online_unread_hint_queue))
                payload = client._online_unread_hint_queue.pop(group_id)
                payload["_online_hint_drained"] = True
                await client._on_raw_group_v2_message_created(payload)
                interval = max(0.0, float(getattr(client, "_online_unread_hint_interval", _ONLINE_UNREAD_HINT_INTERVAL) or 0.0))
                if interval:
                    await asyncio.sleep(interval)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            client._log.debug("client", "online unread hint drain failed: %s", exc)
        finally:
            self.runtime.delivery.set_online_unread_hint_task(None)

    async def fill_p2p_gap(self) -> None:
        """后台补齐 P2P 消息空洞。"""
        client = self.client
        if client._state != "connected" or client._closing:
            return
        if not client._aid:
            return
        ns = f"p2p:{client._aid}"
        # P2P namespace 锁：与 push 串行
        async with client._get_ns_lock(ns):
            await client._fill_p2p_gap_inner(ns)

    async def fill_p2p_gap_inner(self, ns: str) -> None:
        """P2P gap fill 内部实现（在 ns lock 保护下调用）。"""
        client = self.client
        if client._state != "connected" or client._closing:
            return
        after_seq = client._seq_tracker.get_contiguous_seq(ns)
        dedup_key = f"p2p_pull:{ns}"
        if dedup_key in client._gap_fill_done:
            return
        client._gap_fill_done[dedup_key] = time.time()
        # S1: try/finally 保证 dedup 键在所有出口清理
        try:
            client._log.info("client", "P2P message gap fill start: after_seq=%d device_id=%s", after_seq, client._device_id)
            self.runtime.delivery.set_gap_fill_active(True)
            try:
                result = await client.call("message.pull", {
                    "after_seq": after_seq,
                    "limit": 50,
                })
            finally:
                self.runtime.delivery.set_gap_fill_active(False)
            if isinstance(result, dict):
                messages = result.get("messages", [])
                if isinstance(messages, list):
                    # 统计解密成功/失败
                    ok_count = sum(1 for m in messages if isinstance(m, dict) and m.get("encrypted"))
                    fail_count = len(messages) - ok_count
                    seq_list = [int(m.get("seq") or 0) for m in messages if isinstance(m, dict)]
                    client._log.info("client", "P2P message gap fill done: after_seq=%d pulled=%d decrypt_ok=%d decrypt_fail=%d seq_range=%s",
                                     after_seq, len(messages), ok_count, fail_count,
                                     f"{min(seq_list)}~{max(seq_list)}" if seq_list else "empty")
                    ns_key = f"p2p:{client._aid}"
                    pushed = client._pushed_seqs.get(ns_key)
                    # seq_tracker 在 call() 中自动处理；ack 由 push 路径负责
                    for msg in messages:
                        if isinstance(msg, dict):
                            s = msg.get("seq")
                            if pushed and s is not None and int(s) in pushed:
                                continue  # 已发布到应用层，跳过重复投递
                            event_name, event_payload = client._delivery().p2p_app_event_for_message(msg)
                            if s is not None:
                                await client._publish_pulled_message(event_name, ns_key, s, event_payload)
                            else:
                                await client._publish_app_event(event_name, event_payload, source="pull")
                            # 每条消息处理后让出事件循环，避免大量历史消息解密阻塞 ws 握手等 IO
                            await asyncio.sleep(0)
                    # 维护 republish guard 上限
                    client._prune_pushed_seqs(ns_key)
                    # publish 完成后 auto-ack
                    contig_before = int(result.get("_contig_before", 0) or 0)
                    contig = client._seq_tracker.get_contiguous_seq(ns_key)
                    if contig > 0 and contig != contig_before:
                        try:
                            await client._transport.call("message.ack", {
                                "seq": contig, "device_id": client._device_id, "slot_id": client._slot_id,
                            })
                        except Exception as ack_exc:
                            client._log.debug("client", "P2P gap fill auto-ack failed: %s", ack_exc)
        except Exception as exc:
            client._log.warn("client", "P2P message gap fill failed: after_seq=%d error=%s", after_seq, exc)
        finally:
            client._gap_fill_done.pop(dedup_key, None)
            client._schedule_pending_p2p_pull_if_needed(ns, reason="gap-fill-complete")

    async def fill_group_event_gap(self, group_id: str) -> None:
        """后台补齐群事件空洞。"""
        client = self.client
        if client._state != "connected" or client._closing:
            return
        ns = f"group_event:{group_id}"
        async with client._get_ns_lock(ns):
            await client._fill_group_event_gap_inner(group_id, ns)

    async def fill_group_event_gap_inner(self, group_id: str, ns: str) -> None:
        """群事件 gap fill 内部实现（在 ns lock 保护下调用）。"""
        client = self.client
        if client._state != "connected" or client._closing:
            return
        after_seq = client._seq_tracker.get_contiguous_seq(ns)
        dedup_key = f"group_event_pull:{ns}"
        if dedup_key in client._gap_fill_done:
            return
        client._gap_fill_done[dedup_key] = time.time()
        try:
            next_after_seq = after_seq
            max_pages = 100
            page_count = 0
            while page_count < max_pages:
                page_count += 1
                client._log.info("client", "group event gap fill start: group=%s after_seq=%d", group_id, next_after_seq)
                result = await client.call("group.pull_events", {
                    "group_id": group_id,
                    "after_event_seq": next_after_seq,
                    "device_id": client._device_id,
                    "limit": 50,
                })
                if not isinstance(result, dict):
                    return
                events = result.get("events", [])
                if not isinstance(events, list):
                    return

                client._log.info(
                    "client",
                    "group event gap fill page done: group=%s after_seq=%d pulled=%d",
                    group_id, next_after_seq, len(events),
                )
                page_contig_before = client._seq_tracker.get_contiguous_seq(ns)
                if events:
                    client._seq_tracker.on_pull_result(ns, events, after_seq=next_after_seq)

                cursor = result.get("cursor")
                server_ack = int(cursor.get("current_seq") or 0) if isinstance(cursor, dict) else 0
                if server_ack > 0:
                    contig_before_floor = client._seq_tracker.get_contiguous_seq(ns)
                    if contig_before_floor < server_ack:
                        client._log.info(
                            "client",
                            "group.pull_events retention-floor 推进: ns=%s contiguous=%d -> cursor.current_seq=%d",
                            ns, contig_before_floor, server_ack,
                        )
                        client._seq_tracker.force_contiguous_seq(ns, server_ack)

                event_seqs: list[int] = []
                has_dissolved_event = False
                for evt in events:
                    if isinstance(evt, dict):
                        try:
                            es = int(evt.get("event_seq") or 0)
                        except (TypeError, ValueError):
                            es = 0
                        if es > 0:
                            event_seqs.append(es)
                        evt["_from_gap_fill"] = True
                        if evt.get("action") == "dissolved":
                            has_dissolved_event = True
                        et = evt.get("event_type", "")
                        if et == "group.message_created":
                            continue
                        cs = evt.get("client_signature")
                        if cs and isinstance(cs, dict):
                            if client._should_skip_event_signature(evt):
                                evt.pop("client_signature", None)
                            else:
                                evt["_verified"] = await client._verify_event_signature(evt, cs)
                        if es > 0 and not client._is_published_seq(ns, es):
                            client._enqueue_ordered_message(ns, "group.changed", es, evt)

                ack_contig = client._seq_tracker.get_contiguous_seq(ns)
                ack_max_seen = client._seq_tracker.get_max_seen_seq(ns)
                await client._drain_ordered_messages(ns)

                if ack_contig != page_contig_before and not has_dissolved_event:
                    client._persist_seq(ns)
                if events and ack_contig > 0 and ack_contig != page_contig_before:
                    ack_seq = min(ack_contig, ack_max_seen) if ack_max_seen > 0 else ack_contig
                    try:
                        await client._transport.call("group.ack_events", {
                            "group_id": group_id, "event_seq": ack_seq,
                            "device_id": client._device_id,
                            "slot_id": client._slot_id,
                        })
                    except Exception as ack_exc:
                        client._log.debug("client", "group event auto-ack failed: group=%s %s", group_id, ack_exc)

                next_after = max(max(event_seqs) if event_seqs else next_after_seq, next_after_seq)
                if not events or next_after <= next_after_seq or result.get("has_more") is False:
                    break
                next_after_seq = next_after
            if page_count >= max_pages:
                client._log.warn(
                    "client",
                    "group event gap fill reached max_pages=%d group=%s after_seq=%d",
                    max_pages, group_id, next_after_seq,
                )
        except Exception as exc:
            client._log.warn("client", "group event gap fill failed: group=%s after_seq=%d error=%s", group_id, after_seq, exc)
        finally:
            client._gap_fill_done.pop(dedup_key, None)

    def record_pending_p2p_pull(self, ns: str, seq: int) -> None:
        client = self.client
        if not ns or seq <= 0:
            return
        pending = self.runtime.delivery.pending_p2p_pull_upper
        previous = int(pending.get(ns, 0) or 0)
        if seq > previous:
            pending[ns] = seq
        client._log.debug(
            "client",
            "P2P pending pull upper recorded: ns=%s seq=%d previous=%d contiguous=%d",
            ns, seq, previous, client._seq_tracker.get_contiguous_seq(ns),
        )

    def schedule_pending_p2p_pull_if_needed(self, ns: str, *, reason: str) -> bool:
        client = self.client
        if not ns:
            return False
        pending = getattr(client, "_pending_p2p_pull_upper", None)
        if not pending:
            return False
        upper_seq = int(pending.get(ns, 0) or 0)
        if upper_seq <= 0:
            pending.pop(ns, None)
            return False
        contig = client._seq_tracker.get_contiguous_seq(ns)
        if upper_seq <= contig:
            pending.pop(ns, None)
            client._log.debug(
                "client",
                "P2P pending pull upper already covered: ns=%s upper_seq=%d contiguous=%d reason=%s",
                ns, upper_seq, contig, reason,
            )
            return False
        if client._state != "connected" or client._closing:
            client._log.debug(
                "client",
                "P2P pending pull postponed: ns=%s upper_seq=%d contiguous=%d state=%s closing=%s reason=%s",
                ns, upper_seq, contig, client._state, client._closing, reason,
            )
            return False
        dedup_key = f"p2p_pull:{ns}"
        if dedup_key in client._gap_fill_done:
            return False
        pending.pop(ns, None)
        loop = getattr(client, "_loop", None) or asyncio.get_running_loop()
        client._log.info(
            "client",
            "P2P pending push follow-up pull scheduled: ns=%s upper_seq=%d contiguous=%d reason=%s",
            ns, upper_seq, contig, reason,
        )
        loop.create_task(client._fill_p2p_gap())
        return True

    def restore_seq_tracker_state(self) -> None:
        """从 keystore seq_tracker 表按行恢复 SeqTracker 状态。"""
        client = self.client
        if not client._aid:
            return
        try:
            loader = getattr(client._token_store, "load_all_seqs", None)
            if callable(loader):
                state = loader(client._aid, client._device_id, client._slot_id)
                if state:
                    state = client._migrate_seq_state_group_ids(state)
                    client._seq_tracker.restore_state(state)
                    client._log.info("client", "SeqTracker restored: %d namespaces", len(state))
                else:
                    client._log.info("client", "SeqTracker no persisted state, starting from zero")
            else:
                # 旧版 fallback：从 instance_state 的 seq_tracker_state 字段读
                inst_loader = getattr(client._token_store, "load_instance_state", None)
                if callable(inst_loader):
                    instance_state = inst_loader(client._aid, client._device_id, client._slot_id)
                    if isinstance(instance_state, dict):
                        state = instance_state.get("seq_tracker_state")
                        if isinstance(state, dict):
                            state = client._migrate_seq_state_group_ids(state)
                            client._seq_tracker.restore_state(state)
                            client._log.info("client", "SeqTracker restored from legacy instance_state: %d namespaces", len(state))
        except Exception as exc:
            client._log.warn("client", "failed to restore SeqTracker state: %s", exc)

    def migrate_seq_state_group_ids(self, state: dict[str, int]) -> dict[str, int]:
        """把 seq_tracker state 里老/污染 group_id 归一化。冲突取 max。"""
        client = self.client
        if not isinstance(state, dict) or not state:
            return state
        rename_map: dict[str, str] = {}  # old_ns -> new_ns
        for ns in list(state.keys()):
            if not isinstance(ns, str):
                continue
            for prefix in ("group_event:", "group_msg:"):
                if ns.startswith(prefix):
                    old_gid = ns[len(prefix):]
                    # 迁移不对无域输入强行补域，避免误伤
                    new_gid = _normalize_group_id(old_gid)
                    if new_gid and new_gid != old_gid:
                        rename_map[ns] = f"{prefix}{new_gid}"
                    break
        if not rename_map:
            return state

        new_state: dict[str, int] = dict(state)
        for old_ns, new_ns in rename_map.items():
            old_val = int(new_state.pop(old_ns, 0) or 0)
            cur_val = int(new_state.get(new_ns, 0) or 0)
            new_state[new_ns] = max(old_val, cur_val)

        client._log.info(
            "client",
            "SeqTracker group_id migration: %d namespaces rewritten -> %s",
            len(rename_map),
            {k: rename_map[k] for k in list(rename_map)[:3]},
        )

        # 落盘：删老 ns，写新 ns。删除接口缺失时只写新不删老（下次启动仍会再跑一次，幂等）
        deleter = getattr(client._token_store, "delete_seq", None)
        saver = getattr(client._token_store, "save_seq", None)
        if callable(saver):
            for old_ns, new_ns in rename_map.items():
                if callable(deleter):
                    try:
                        deleter(client._aid, client._device_id, client._slot_id, old_ns)
                    except Exception as exc:
                        client._log.debug("client", "delete old seq ns failed: ns=%s err=%s", old_ns, exc)
                try:
                    saver(client._aid, client._device_id, client._slot_id, new_ns, new_state[new_ns])
                except Exception as exc:
                    client._log.debug("client", "write new seq ns failed: ns=%s err=%s", new_ns, exc)
        return new_state

    def current_seq_tracker_context(self) -> tuple[str, str, str] | None:
        client = self.client
        aid = str(client._aid or "").strip()
        if not aid:
            return None
        return (aid, client._device_id, client._slot_id)

    def reset_seq_tracking_state(self) -> None:
        client = self.client
        self.runtime.delivery.reset_seq_tracking_state(reset_context=True)

    def refresh_seq_tracking_context(self) -> None:
        client = self.client
        next_context = client._current_seq_tracker_context()
        if next_context == client._seq_tracker_context:
            return
        prev = client._seq_tracker_context
        old_state = client._seq_tracker.export_state() if prev else {}
        client._log.info("client",
            "SeqTracker 上下文切换 %s -> %s, 旧 state=%s",
            prev, next_context, old_state,
        )
        self.runtime.delivery.reset_seq_tracking_state(next_context=next_context)

    def persist_seq(self, ns: str, *, force_seq: int | None = None) -> None:
        """即时持久化单个 namespace 的 seq（行级写入）。"""
        client = self.client
        if not client._aid:
            return
        seq = force_seq if force_seq is not None else client._seq_tracker.get_contiguous_seq(ns)
        if seq <= 0:
            return
        client._log.debug("client", "persist_seq: ns=%s seq=%d (force=%s)", ns, seq, force_seq is not None)
        if force_seq is not None:
            # 同时更新内存中的 SeqTracker
            client._seq_tracker.restore_state({ns: seq})
        try:
            saver = getattr(client._token_store, "save_seq", None)
            if callable(saver):
                saver(client._aid, client._device_id, client._slot_id, ns, seq)
        except Exception as seq_exc:
            client._log.debug("client", "save seq failed: %s", seq_exc)

    def persist_repaired_seq(self, ns: str) -> None:
        """持久化倒退修复后的 seq；修复到 0 时删除旧落盘游标。"""
        client = self.client
        if not client._aid:
            return
        seq = client._seq_tracker.get_contiguous_seq(ns)
        if seq > 0:
            client._persist_seq(ns)
            return
        deleter = getattr(client._token_store, "delete_seq", None)
        if callable(deleter):
            try:
                deleter(client._aid, client._device_id, client._slot_id, ns)
            except Exception as exc:
                client._log.debug("client", "delete repaired seq failed: ns=%s err=%s", ns, exc)

    def repair_push_contiguous_bound(self, ns: str, push_seq: int, *, has_payload: bool, label: str) -> int:
        """按 push 类型修复异常过高的 contiguous_seq，并返回修复后的值。"""
        client = self.client
        if not ns or push_seq <= 0:
            return client._seq_tracker.get_contiguous_seq(ns) if ns else 0
        contig = client._seq_tracker.get_contiguous_seq(ns)
        should_repair = contig > push_seq
        if not should_repair:
            return contig
        repaired_to = max(0, push_seq - 1)
        client._seq_tracker.repair_contiguous_seq(ns, repaired_to)
        repaired = client._seq_tracker.get_contiguous_seq(ns)
        client._persist_repaired_seq(ns)
        client._log.warn(
            "client",
            "%s push repaired contiguous_seq: ns=%s payload=%s push_seq=%d contiguous=%d->%d",
            label, ns, has_payload, push_seq, contig, repaired,
        )
        return repaired

    def save_seq_tracker_state(self) -> None:
        """将 SeqTracker 状态按行保存到 keystore seq_tracker 表。"""
        client = self.client
        if not client._aid:
            return
        state = client._seq_tracker.export_state()
        if not state:
            return
        try:
            saver = getattr(client._token_store, "save_seq", None)
            if callable(saver):
                for ns, seq in state.items():
                    if isinstance(seq, int) and seq > 0:
                        saver(client._aid, client._device_id, client._slot_id, ns, seq)
            else:
                # 旧版 fallback
                updater = getattr(client._token_store, "update_instance_state", None)
                if callable(updater):
                    def _merge_seq(m: dict) -> dict:
                        m["seq_tracker_state"] = state
                        return m
                    updater(client._aid, client._device_id, client._slot_id, _merge_seq)
        except Exception as exc:
            client._log.warn("client", "failed to save SeqTracker state: %s", exc)

    async def on_v2_push_notification(self, data: Any) -> None:
        """处理 V2 P2P push 通知：自动 pull + decrypt + emit。"""
        client = self.client
        client._log_message_debug("server-push", "_raw.peer.v2.message_received", "message.received", data)
        if not client._v2_session:
            client._log.debug("client", "_on_v2_push_notification skipped: no v2_session")
            return

        # 提取 push 通知中的元数据
        push_seq = data.get("seq") if isinstance(data, dict) else None
        push_from = data.get("from_aid") if isinstance(data, dict) else None
        push_msg_id = data.get("message_id") if isinstance(data, dict) else None
        envelope_json = data.get("envelope_json") if isinstance(data, dict) else None

        ns = f"p2p:{client._aid}" if client._aid else ""
        contig_before = client._seq_tracker.get_contiguous_seq(ns) if ns else 0
        dedup_key = f"p2p_pull:{ns}"
        pull_in_flight = dedup_key in client._gap_fill_done

        client._log.debug(
            "client",
            "_on_v2_push_notification: push_seq=%s push_from=%s push_msg_id=%s has_payload=%s contiguous_seq=%d pull_in_flight=%s",
            push_seq, push_from, push_msg_id, bool(envelope_json), contig_before, pull_in_flight,
        )

        push_seq_int = int(push_seq) if push_seq and isinstance(push_seq, (int, float)) and push_seq > 0 else 0

        # Push 修上界：只更新 max_seen_seq，不动 contiguous_seq。
        if push_seq_int > 0 and ns:
            client._seq_tracker.update_max_seen(ns, push_seq_int)
            if contig_before == push_seq_int:
                client._log.debug(
                    "client",
                    "_on_v2_push_notification: push seq=%d already covered by contiguous_seq=%d, ignore duplicate push",
                    push_seq_int, contig_before,
                )
                return
            contig_before = client._repair_push_contiguous_bound(
                ns, push_seq_int, has_payload=bool(envelope_json), label="_raw.peer.v2.message_received",
            )

        # 带 payload 的 push：尝试就地解密。
        if envelope_json and push_seq_int > 0 and ns:
            try:
                decrypted = await client._decrypt_v2_message(data)
                if decrypted is not None:
                    # 解密成功：把 push_seq 加入 received_seqs，让 _try_advance 自然推进。
                    need_pull = client._seq_tracker.on_message_seq(ns, push_seq_int)
                    published = await client._publish_ordered_message("message.received", ns, push_seq_int, decrypted)
                    new_contig = client._seq_tracker.get_contiguous_seq(ns)
                    if new_contig != contig_before:
                        client._persist_seq(ns)
                    if new_contig > 0 and new_contig != contig_before:
                        # ack clamp：永远不发送超过 max_seen_seq 的 up_to_seq
                        max_seen = client._seq_tracker.get_max_seen_seq(ns)
                        ack_seq = min(new_contig, max_seen) if max_seen > 0 else new_contig
                        client._fire_ack("message.v2.ack", {"up_to_seq": ack_seq}, "V2 P2P push-ack")
                    client._log.debug(
                        "client",
                        "_on_v2_push_notification: push 带 payload 解密成功, contiguous_seq=%d->%d push_seq=%d",
                        contig_before, new_contig, push_seq_int,
                    )
                    if not need_pull and (published or new_contig >= push_seq_int or push_seq_int <= contig_before):
                        return
                    client._log.debug(
                        "client",
                        "_on_v2_push_notification: payload push seq=%d 因空洞挂起，继续 pull 补齐 after_seq=%d",
                        push_seq_int, new_contig,
                    )
                    if pull_in_flight:
                        client._record_pending_p2p_pull(ns, push_seq_int)
                        client._log.debug(
                            "client",
                            "_on_v2_push_notification: payload push seq=%d 已挂起，复用进行中的 pull",
                            push_seq_int,
                        )
                        return
            except Exception as exc:
                client._log.debug("client", "_on_v2_push_notification: push payload 解密失败, fallback to pull: %s", exc)

        # 不带 payload 或解密失败：触发 pull。
        if push_seq_int > 0 and ns:
            client._log.debug(
                "client",
                "_on_v2_push_notification: 纯通知 push_seq=%d > contiguous_seq=%d, 触发 pull(after_seq=%d)",
                push_seq_int, contig_before, contig_before,
            )
            if pull_in_flight:
                client._record_pending_p2p_pull(ns, push_seq_int)
                client._log.debug(
                    "client",
                    "_on_v2_push_notification: pull 已在进行中，仅记录上界 push_seq=%d",
                    push_seq_int,
                )
                return

        client._gap_fill_done[dedup_key] = time.time()

        try:
            await client._pull_v2_internal({})
            new_contig = client._seq_tracker.get_contiguous_seq(ns) if ns else -1
            client._log.debug(
                "client",
                "_on_v2_push_notification pull done: contiguous_seq=%d->%d (push_seq=%s)",
                contig_before, new_contig, push_seq,
            )
        except Exception as exc:
            client._log.warn("client", "V2 push auto-pull failed: %s", exc)
        finally:
            client._gap_fill_done.pop(dedup_key, None)
            client._schedule_pending_p2p_pull_if_needed(ns, reason="push-auto-pull-complete")
