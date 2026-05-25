#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
import traceback
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import aiohttp


@dataclass(frozen=True)
class ClientEndpoint:
    name: str
    url: str


def _now_ms() -> int:
    return int(time.time() * 1000)


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value, ensure_ascii=False)
        return value
    except TypeError:
        if isinstance(value, dict):
            return {str(k): _json_safe(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_json_safe(v) for v in value]
        return str(value)


class CrossSdkRunner:
    def __init__(self) -> None:
        self.clients = self._load_clients()
        self.case_file = Path(os.environ.get("CROSS_SDK_CASES", "/cross-sdk/cases.single-domain.json"))
        self.artifact_dir = Path(os.environ.get("ARTIFACT_DIR", "/artifacts"))
        self.wait_timeout_ms = int(os.environ.get("CROSS_SDK_WAIT_TIMEOUT_MS", "90000"))
        self.results: list[dict[str, Any]] = []

    @staticmethod
    def _load_clients() -> dict[str, ClientEndpoint]:
        raw_clients = os.environ.get("CROSS_SDK_CLIENTS", "python,ts,go,cpp")
        names = [item.strip().lower() for item in raw_clients.split(",") if item.strip()]
        if not names:
            raise ValueError("CROSS_SDK_CLIENTS must contain at least one client")
        legacy_env = {
            "python": ["PY_CLIENT_URL", "PYTHON_CLIENT_URL"],
            "py": ["PY_CLIENT_URL", "PYTHON_CLIENT_URL"],
            "ts": ["TS_CLIENT_URL"],
        }
        clients: dict[str, ClientEndpoint] = {}
        for name in names:
            env_prefix = re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")
            candidates = [*legacy_env.get(name, []), f"{env_prefix}_CLIENT_URL"]
            url = ""
            for env_name in candidates:
                url = os.environ.get(env_name, "").strip()
                if url:
                    break
            if not url:
                url = f"http://cross-sdk-{name}:9001"
            clients[name] = ClientEndpoint(name, url.rstrip("/"))
        return clients

    def _client(self, name: str) -> ClientEndpoint:
        client = self.clients.get(name)
        if client is None:
            enabled = ", ".join(sorted(self.clients))
            raise AssertionError(f"unknown or disabled cross-sdk client: {name}; enabled={enabled}")
        return client

    async def run(self) -> int:
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        cases_doc = self._load_cases()
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=40)) as session:
            await self._wait_all_ready(session)
            identities = await self._load_identities(session)
            for case in cases_doc.get("cases", []):
                started = _now_ms()
                case_id = str(case.get("id") or f"case-{uuid.uuid4().hex[:8]}")
                try:
                    if case.get("type") == "health":
                        detail = await self._run_health_case(session)
                    elif case.get("type") == "p2p":
                        detail = await self._run_p2p_case(session, case, identities)
                    elif case.get("type") == "p2p_roundtrip":
                        detail = await self._run_p2p_roundtrip_case(session, case, identities)
                    elif case.get("type") == "group":
                        detail = await self._run_group_case(session, case, identities)
                    elif case.get("type") == "group_roundtrip":
                        detail = await self._run_group_roundtrip_case(session, case, identities)
                    elif case.get("type") == "group_mixed":
                        detail = await self._run_group_mixed_case(session, case, identities)
                    elif case.get("type") == "group_matrix":
                        detail = await self._run_group_matrix_case(session, case, identities)
                    else:
                        raise AssertionError(f"unsupported case type: {case.get('type')}")
                    self._record(case_id, "passed", started, detail)
                    print(f"[PASS] {case_id}", flush=True)
                except Exception as exc:
                    detail = {
                        "error_code": exc.__class__.__name__,
                        "error_message": str(exc),
                        "traceback": traceback.format_exc(),
                    }
                    self._record(case_id, "failed", started, detail)
                    print(f"[FAIL] {case_id}: {exc}", flush=True)
        self._write_results()
        failed = [r for r in self.results if r["status"] != "passed"]
        return 1 if failed else 0

    def _load_cases(self) -> dict[str, Any]:
        with self.case_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
            raise ValueError(f"invalid cases file: {self.case_file}")
        return data

    async def _wait_all_ready(self, session: aiohttp.ClientSession) -> None:
        deadline = time.monotonic() + self.wait_timeout_ms / 1000
        last: dict[str, Any] = {}
        while time.monotonic() < deadline:
            all_ready = True
            for client in self.clients.values():
                try:
                    health = await self._get(session, client, "/health")
                except Exception as exc:
                    health = {"ok": False, "error": str(exc)}
                last[client.name] = health
                if not health.get("ok") or not health.get("agent_ready"):
                    all_ready = False
            if all_ready:
                return
            await asyncio.sleep(1)
        raise TimeoutError(f"clients not ready before timeout: {last}")

    async def _load_identities(self, session: aiohttp.ClientSession) -> dict[str, dict[str, Any]]:
        result = {}
        for client in self.clients.values():
            identity = await self._get(session, client, "/identity")
            aid = str(identity.get("aid") or "")
            if not aid:
                raise AssertionError(f"{client.name} identity missing aid: {identity}")
            result[client.name] = identity
        return result

    async def _run_health_case(self, session: aiohttp.ClientSession) -> dict[str, Any]:
        return {name: await self._get(session, client, "/health") for name, client in self.clients.items()}

    async def _run_p2p_case(
        self,
        session: aiohttp.ClientSession,
        case: dict[str, Any],
        identities: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        sender_name = str(case.get("from") or "")
        receiver_name = str(case.get("to") or "")
        sender = self._client(sender_name)
        receiver = self._client(receiver_name)
        receiver_aid = str(identities[receiver_name].get("aid") or "")
        base_text = str(case.get("text") or case.get("id") or "cross-sdk message")
        e2ee = bool(case.get("e2ee", True))
        count = int(case.get("count") or 1)
        trace_id = f"{case.get('id')}-{uuid.uuid4().hex[:8]}"

        await self._post(session, sender, "/reset", {"trace_id": trace_id})
        await self._post(session, receiver, "/reset", {"trace_id": trace_id})

        expected_texts = []
        send_results = []
        for index in range(count):
            text = base_text if count == 1 else f"{base_text} #{index + 1}"
            expected_texts.append(text)
            send_result = await self._post(
                session,
                sender,
                "/send",
                {
                    "to": receiver_aid,
                    "text": text,
                    "e2ee": e2ee,
                    "trace_id": trace_id,
                    "case_id": str(case.get("id") or trace_id),
                    "message_id": f"{trace_id}-{index + 1}",
                    "timeout_ms": int(case.get("timeout_ms") or 30000),
                },
            )
            if not send_result.get("ok"):
                raise AssertionError(f"send failed: {send_result}")
            send_results.append(send_result)

        inbox = await self._wait_inbox(session, receiver, trace_id, expected_texts, e2ee)
        ack_result = None
        if bool(case.get("ack", False)):
            ack_result = await self._ack_p2p(session, receiver, inbox, expected_texts)
        sender_trace = await self._get(session, sender, f"/traces/{trace_id}")
        receiver_trace = await self._get(session, receiver, f"/traces/{trace_id}")
        return {
            "trace_id": trace_id,
            "from": sender_name,
            "to": receiver_name,
            "to_aid": receiver_aid,
            "e2ee": e2ee,
            "send_results": send_results,
            "inbox": inbox,
            "ack_result": ack_result,
            "sender_trace": sender_trace,
            "receiver_trace": receiver_trace,
        }

    async def _run_p2p_roundtrip_case(
        self,
        session: aiohttp.ClientSession,
        case: dict[str, Any],
        identities: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        first_name = str(case.get("from") or "")
        second_name = str(case.get("to") or "")
        first = self._client(first_name)
        second = self._client(second_name)
        first_aid = str(identities[first_name].get("aid") or "")
        second_aid = str(identities[second_name].get("aid") or "")
        e2ee = bool(case.get("e2ee", True))
        trace_id = f"{case.get('id')}-{uuid.uuid4().hex[:8]}"
        first_text = str(case.get("text") or f"{case.get('id')} request")
        reply_text = str(case.get("reply_text") or f"{case.get('id')} reply")

        await self._post(session, first, "/reset", {"trace_id": trace_id})
        await self._post(session, second, "/reset", {"trace_id": trace_id})

        first_send = await self._post(
            session,
            first,
            "/send",
            {
                "to": second_aid,
                "text": first_text,
                "e2ee": e2ee,
                "trace_id": trace_id,
                "case_id": str(case.get("id") or trace_id),
                "message_id": f"{trace_id}-1",
            },
        )
        if not first_send.get("ok"):
            raise AssertionError(f"first roundtrip send failed: {first_send}")
        second_inbox = await self._wait_inbox(session, second, trace_id, [first_text], e2ee)
        second_ack = await self._ack_p2p(session, second, second_inbox, [first_text]) if bool(case.get("ack", False)) else None

        reply_send = await self._post(
            session,
            second,
            "/send",
            {
                "to": first_aid,
                "text": reply_text,
                "e2ee": e2ee,
                "trace_id": trace_id,
                "case_id": str(case.get("id") or trace_id),
                "message_id": f"{trace_id}-2",
            },
        )
        if not reply_send.get("ok"):
            raise AssertionError(f"reply roundtrip send failed: {reply_send}")
        first_inbox = await self._wait_inbox(session, first, trace_id, [reply_text], e2ee)
        first_ack = await self._ack_p2p(session, first, first_inbox, [reply_text]) if bool(case.get("ack", False)) else None

        return {
            "trace_id": trace_id,
            "from": first_name,
            "to": second_name,
            "from_aid": first_aid,
            "to_aid": second_aid,
            "e2ee": e2ee,
            "send_results": [first_send, reply_send],
            "inboxes": {
                first_name: first_inbox,
                second_name: second_inbox,
            },
            "ack_results": {
                first_name: first_ack,
                second_name: second_ack,
            },
            "traces": {
                first_name: await self._get(session, first, f"/traces/{trace_id}"),
                second_name: await self._get(session, second, f"/traces/{trace_id}"),
            },
        }

    async def _run_group_case(
        self,
        session: aiohttp.ClientSession,
        case: dict[str, Any],
        identities: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        sender_name = str(case.get("from") or "")
        receiver_name = str(case.get("to") or "")
        sender = self._client(sender_name)
        receiver = self._client(receiver_name)
        sender_aid = str(identities[sender_name].get("aid") or "")
        receiver_aid = str(identities[receiver_name].get("aid") or "")
        base_text = str(case.get("text") or case.get("id") or "cross-sdk group message")
        e2ee = bool(case.get("e2ee", True))
        count = int(case.get("count") or 1)
        trace_id = f"{case.get('id')}-{uuid.uuid4().hex[:8]}"

        await self._post(session, sender, "/reset", {"trace_id": trace_id})
        await self._post(session, receiver, "/reset", {"trace_id": trace_id})

        create_result = await self._post(
            session,
            sender,
            "/group/create",
            {
                "trace_id": trace_id,
                "name": f"cross-sdk-{case.get('id')}-{uuid.uuid4().hex[:8]}",
                "visibility": str(case.get("visibility") or "private"),
                "members": [receiver_aid],
            },
        )
        if not create_result.get("ok"):
            raise AssertionError(f"group.create failed: {create_result}")
        group_id = str(create_result.get("group_id") or "")
        if not group_id:
            raise AssertionError(f"group.create missing group_id: {create_result}")

        await self._wait_group_ready(session, sender, group_id, [sender_aid, receiver_aid])
        await self._wait_group_ready(session, receiver, group_id, [receiver_aid])

        expected_texts = []
        send_results = []
        for index in range(count):
            text = base_text if count == 1 else f"{base_text} #{index + 1}"
            expected_texts.append(text)
            send_result = await self._post(
                session,
                sender,
                "/group/send",
                {
                    "group_id": group_id,
                    "text": text,
                    "e2ee": e2ee,
                    "trace_id": trace_id,
                    "case_id": str(case.get("id") or trace_id),
                    "message_id": f"{trace_id}-{index + 1}",
                    "timeout_ms": int(case.get("timeout_ms") or 30000),
                },
            )
            if not send_result.get("ok"):
                raise AssertionError(f"group.send failed: {send_result}")
            send_results.append(send_result)

        inbox = await self._wait_group_inbox(session, receiver, group_id, trace_id, expected_texts, e2ee)
        ack_result = None
        if bool(case.get("ack", False)):
            ack_result = await self._ack_group(session, receiver, group_id, inbox, expected_texts)
        sender_trace = await self._get(session, sender, f"/traces/{trace_id}")
        receiver_trace = await self._get(session, receiver, f"/traces/{trace_id}")
        return {
            "trace_id": trace_id,
            "group_id": group_id,
            "from": sender_name,
            "to": receiver_name,
            "from_aid": sender_aid,
            "to_aid": receiver_aid,
            "e2ee": e2ee,
            "create_result": create_result,
            "send_results": send_results,
            "inbox": inbox,
            "ack_result": ack_result,
            "sender_trace": sender_trace,
            "receiver_trace": receiver_trace,
        }

    async def _run_group_roundtrip_case(
        self,
        session: aiohttp.ClientSession,
        case: dict[str, Any],
        identities: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        first_name = str(case.get("from") or "")
        second_name = str(case.get("to") or "")
        e2ee = bool(case.get("e2ee", True))
        trace_id = f"{case.get('id')}-{uuid.uuid4().hex[:8]}"
        first_text = str(case.get("text") or f"{case.get('id')} group request")
        reply_text = str(case.get("reply_text") or f"{case.get('id')} group reply")

        group_context = await self._create_two_member_group(session, case, identities, trace_id, first_name, second_name)
        first = self._client(first_name)
        second = self._client(second_name)
        group_id = group_context["group_id"]

        first_send = await self._post(
            session,
            first,
            "/group/send",
            {
                "group_id": group_id,
                "text": first_text,
                "e2ee": e2ee,
                "trace_id": trace_id,
                "case_id": str(case.get("id") or trace_id),
                "message_id": f"{trace_id}-1",
            },
        )
        if not first_send.get("ok"):
            raise AssertionError(f"group first send failed: {first_send}")
        second_inbox = await self._wait_group_inbox(session, second, group_id, trace_id, [first_text], e2ee)
        second_ack = await self._ack_group(session, second, group_id, second_inbox, [first_text]) if bool(case.get("ack", False)) else None

        reply_send = await self._post(
            session,
            second,
            "/group/send",
            {
                "group_id": group_id,
                "text": reply_text,
                "e2ee": e2ee,
                "trace_id": trace_id,
                "case_id": str(case.get("id") or trace_id),
                "message_id": f"{trace_id}-2",
            },
        )
        if not reply_send.get("ok"):
            raise AssertionError(f"group reply send failed: {reply_send}")
        first_inbox = await self._wait_group_inbox(session, first, group_id, trace_id, [reply_text], e2ee)
        first_ack = await self._ack_group(session, first, group_id, first_inbox, [reply_text]) if bool(case.get("ack", False)) else None

        return {
            **group_context,
            "trace_id": trace_id,
            "e2ee": e2ee,
            "send_results": [first_send, reply_send],
            "inboxes": {
                first_name: first_inbox,
                second_name: second_inbox,
            },
            "ack_results": {
                first_name: first_ack,
                second_name: second_ack,
            },
            "traces": {
                first_name: await self._get(session, first, f"/traces/{trace_id}"),
                second_name: await self._get(session, second, f"/traces/{trace_id}"),
            },
        }

    async def _run_group_mixed_case(
        self,
        session: aiohttp.ClientSession,
        case: dict[str, Any],
        identities: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        first_name = str(case.get("from") or "python")
        second_name = str(case.get("to") or "ts")
        trace_id = f"{case.get('id')}-{uuid.uuid4().hex[:8]}"
        group_context = await self._create_two_member_group(session, case, identities, trace_id, first_name, second_name)
        group_id = group_context["group_id"]
        messages = case.get("messages") if isinstance(case.get("messages"), list) else []
        if not messages:
            raise AssertionError("group_mixed requires non-empty messages")

        expected_by_receiver: dict[str, list[tuple[str, bool]]] = {first_name: [], second_name: []}
        send_results = []
        inboxes: dict[str, dict[str, Any]] = {}
        ack_results: dict[str, list[dict[str, Any]]] = {first_name: [], second_name: []}
        for index, raw_message in enumerate(messages):
            if not isinstance(raw_message, dict):
                raise AssertionError(f"group_mixed message #{index + 1} is not an object")
            sender_name = str(raw_message.get("from") or "").strip()
            if sender_name not in self.clients:
                raise AssertionError(f"unknown group_mixed sender: {sender_name}")
            receiver_name = second_name if sender_name == first_name else first_name
            sender = self._client(sender_name)
            receiver = self._client(receiver_name)
            e2ee = bool(raw_message.get("e2ee", True))
            text = str(raw_message.get("text") or f"{case.get('id')} message #{index + 1}")
            send_result = await self._post(
                session,
                sender,
                "/group/send",
                {
                    "group_id": group_id,
                    "text": text,
                    "e2ee": e2ee,
                    "trace_id": trace_id,
                    "case_id": str(case.get("id") or trace_id),
                    "message_id": f"{trace_id}-{index + 1}",
                },
            )
            if not send_result.get("ok"):
                raise AssertionError(f"group_mixed send #{index + 1} failed: {send_result}")
            send_results.append(send_result)
            expected_by_receiver[receiver_name].append((text, e2ee))
            inbox = await self._wait_group_inbox(session, receiver, group_id, trace_id, [text], e2ee)
            inboxes[receiver_name] = inbox
            if bool(case.get("ack", False)):
                ack_results[receiver_name].append(await self._ack_group(session, receiver, group_id, inbox, [text]))

        for receiver_name, expected in expected_by_receiver.items():
            if not expected:
                continue
            receiver = self._client(receiver_name)
            for e2ee in sorted({item[1] for item in expected}):
                expected_texts = [text for text, encrypted in expected if encrypted is e2ee]
                inboxes[receiver_name] = await self._wait_group_inbox(session, receiver, group_id, trace_id, expected_texts, e2ee)

        return {
            **group_context,
            "trace_id": trace_id,
            "send_results": send_results,
            "inboxes": inboxes,
            "ack_results": ack_results,
            "traces": {
                first_name: await self._get(session, self._client(first_name), f"/traces/{trace_id}"),
                second_name: await self._get(session, self._client(second_name), f"/traces/{trace_id}"),
            },
        }

    async def _run_group_matrix_case(
        self,
        session: aiohttp.ClientSession,
        case: dict[str, Any],
        identities: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        raw_participants = case.get("participants") if isinstance(case.get("participants"), list) else []
        participant_names = [str(item).strip() for item in raw_participants if str(item).strip()]
        if not participant_names:
            participant_names = list(self.clients.keys())
        participant_names = list(dict.fromkeys(participant_names))
        if len(participant_names) < 3:
            raise AssertionError("group_matrix requires at least 3 participants")
        for name in participant_names:
            self._client(name)
            if name not in identities:
                raise AssertionError(f"group_matrix identity missing: {name}")

        owner_name = str(case.get("owner") or participant_names[0]).strip()
        if owner_name not in participant_names:
            raise AssertionError(f"group_matrix owner must be a participant: {owner_name}")
        owner = self._client(owner_name)
        all_aids = {name: str(identities[name].get("aid") or "") for name in participant_names}
        if any(not aid for aid in all_aids.values()):
            raise AssertionError(f"group_matrix participant missing aid: {all_aids}")

        e2ee = bool(case.get("e2ee", True))
        ack = bool(case.get("ack", False))
        base_text = str(case.get("text") or case.get("id") or "cross-sdk group matrix")
        trace_id = f"{case.get('id')}-{uuid.uuid4().hex[:8]}"

        for name in participant_names:
            await self._post(session, self._client(name), "/reset", {"trace_id": trace_id})

        member_aids = [aid for name, aid in all_aids.items() if name != owner_name]
        create_result = await self._post(
            session,
            owner,
            "/group/create",
            {
                "trace_id": trace_id,
                "name": f"cross-sdk-{case.get('id')}-{uuid.uuid4().hex[:8]}",
                "visibility": str(case.get("visibility") or "private"),
                "members": member_aids,
            },
        )
        if not create_result.get("ok"):
            raise AssertionError(f"group_matrix group.create failed: {create_result}")
        group_id = str(create_result.get("group_id") or "")
        if not group_id:
            raise AssertionError(f"group_matrix group.create missing group_id: {create_result}")

        expected_members = list(all_aids.values())
        ready_results = {}
        for name in participant_names:
            ready_results[name] = await self._wait_group_ready(session, self._client(name), group_id, expected_members)

        send_results = []
        inboxes: dict[str, list[dict[str, Any]]] = {name: [] for name in participant_names}
        ack_results: dict[str, list[dict[str, Any]]] = {name: [] for name in participant_names}
        for index, sender_name in enumerate(participant_names):
            sender = self._client(sender_name)
            text = f"{base_text} from {sender_name}"
            send_result = await self._post(
                session,
                sender,
                "/group/send",
                {
                    "group_id": group_id,
                    "text": text,
                    "e2ee": e2ee,
                    "trace_id": trace_id,
                    "case_id": str(case.get("id") or trace_id),
                    "message_id": f"{trace_id}-{index + 1}",
                    "timeout_ms": int(case.get("timeout_ms") or 30000),
                },
            )
            if not send_result.get("ok"):
                raise AssertionError(f"group_matrix send from {sender_name} failed: {send_result}")
            send_results.append(send_result)

            for receiver_name in participant_names:
                if receiver_name == sender_name:
                    continue
                receiver = self._client(receiver_name)
                inbox = await self._wait_group_inbox(session, receiver, group_id, trace_id, [text], e2ee)
                inboxes[receiver_name].append(inbox)
                if ack:
                    ack_results[receiver_name].append(await self._ack_group(session, receiver, group_id, inbox, [text]))

        return {
            "trace_id": trace_id,
            "group_id": group_id,
            "participants": participant_names,
            "participant_aids": all_aids,
            "owner": owner_name,
            "e2ee": e2ee,
            "create_result": create_result,
            "ready_results": ready_results,
            "send_results": send_results,
            "inboxes": inboxes,
            "ack_results": ack_results,
            "traces": {
                name: await self._get(session, self._client(name), f"/traces/{trace_id}")
                for name in participant_names
            },
        }

    async def _create_two_member_group(
        self,
        session: aiohttp.ClientSession,
        case: dict[str, Any],
        identities: dict[str, dict[str, Any]],
        trace_id: str,
        owner_name: str,
        member_name: str,
    ) -> dict[str, Any]:
        owner = self._client(owner_name)
        member = self._client(member_name)
        owner_aid = str(identities[owner_name].get("aid") or "")
        member_aid = str(identities[member_name].get("aid") or "")

        await self._post(session, owner, "/reset", {"trace_id": trace_id})
        await self._post(session, member, "/reset", {"trace_id": trace_id})

        create_result = await self._post(
            session,
            owner,
            "/group/create",
            {
                "trace_id": trace_id,
                "name": f"cross-sdk-{case.get('id')}-{uuid.uuid4().hex[:8]}",
                "visibility": str(case.get("visibility") or "private"),
                "members": [member_aid],
            },
        )
        if not create_result.get("ok"):
            raise AssertionError(f"group.create failed: {create_result}")
        group_id = str(create_result.get("group_id") or "")
        if not group_id:
            raise AssertionError(f"group.create missing group_id: {create_result}")

        await self._wait_group_ready(session, owner, group_id, [owner_aid, member_aid])
        await self._wait_group_ready(session, member, group_id, [owner_aid, member_aid])
        return {
            "group_id": group_id,
            "from": owner_name,
            "to": member_name,
            "from_aid": owner_aid,
            "to_aid": member_aid,
            "create_result": create_result,
        }

    async def _wait_group_ready(
        self,
        session: aiohttp.ClientSession,
        client: ClientEndpoint,
        group_id: str,
        members: list[str],
    ) -> dict[str, Any]:
        deadline = time.monotonic() + 45
        last: dict[str, Any] = {}
        members_q = quote(",".join(members), safe="")
        group_q = quote(group_id, safe="")
        while time.monotonic() < deadline:
            try:
                ready = await self._get(session, client, f"/group/ready?group_id={group_q}&members={members_q}")
            except Exception as exc:
                ready = {"ok": False, "ready": False, "error": str(exc)}
            last = ready
            if ready.get("ok") and ready.get("ready"):
                return ready
            await asyncio.sleep(1)
        raise TimeoutError(f"group not ready for {client.name}: group_id={group_id} members={members} last={last}")

    async def _wait_inbox(
        self,
        session: aiohttp.ClientSession,
        receiver: ClientEndpoint,
        trace_id: str,
        expected_texts: list[str],
        e2ee: bool,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + 30
        last: dict[str, Any] = {}
        expected = set(expected_texts)
        while time.monotonic() < deadline:
            try:
                await self._post(session, receiver, "/pull", {"after_seq": 0, "limit": 100})
            except Exception:
                pass
            inbox = await self._get(session, receiver, f"/inbox?trace_id={trace_id}&limit=50")
            last = inbox
            items = inbox.get("items") if isinstance(inbox.get("items"), list) else []
            texts = {str(item.get("text") or "") for item in items if isinstance(item, dict)}
            matched = [item for item in items if isinstance(item, dict) and str(item.get("text") or "") in expected]
            decrypted_ok = all(bool(item.get("decrypted")) for item in matched)
            encrypted_ok = all(bool(item.get("encrypted")) is e2ee for item in matched)
            if expected.issubset(texts) and decrypted_ok and encrypted_ok:
                if e2ee:
                    self._assert_envelope_metadata(matched, expected)
                return inbox
            await asyncio.sleep(0.5)
        raise TimeoutError(f"receiver inbox did not contain expected messages: expected={sorted(expected)} last={last}")

    async def _wait_group_inbox(
        self,
        session: aiohttp.ClientSession,
        receiver: ClientEndpoint,
        group_id: str,
        trace_id: str,
        expected_texts: list[str],
        e2ee: bool,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + 45
        last: dict[str, Any] = {}
        expected = set(expected_texts)
        trace_q = quote(trace_id, safe="")
        group_q = quote(group_id, safe="")
        while time.monotonic() < deadline:
            try:
                await self._post(session, receiver, "/group/pull", {"group_id": group_id, "after_seq": 0, "limit": 100})
            except Exception:
                pass
            inbox = await self._get(session, receiver, f"/group/inbox?group_id={group_q}&trace_id={trace_q}&limit=100")
            last = inbox
            items = inbox.get("items") if isinstance(inbox.get("items"), list) else []
            texts = {str(item.get("text") or "") for item in items if isinstance(item, dict)}
            matched = [item for item in items if isinstance(item, dict) and str(item.get("text") or "") in expected]
            decrypted_ok = all(bool(item.get("decrypted")) for item in matched)
            encrypted_ok = all(bool(item.get("encrypted")) is e2ee for item in matched)
            if expected.issubset(texts) and decrypted_ok and encrypted_ok:
                if e2ee:
                    self._assert_envelope_metadata(matched, expected)
                return inbox
            await asyncio.sleep(0.5)
        raise TimeoutError(f"group receiver inbox did not contain expected messages: expected={sorted(expected)} last={last}")

    @staticmethod
    def _assert_envelope_metadata(items: list[dict[str, Any]], expected_texts: set[str]) -> None:
        missing: list[dict[str, Any]] = []
        for item in items:
            if str(item.get("text") or "") not in expected_texts:
                continue
            protected_headers = item.get("protected_headers")
            payload_type = str(item.get("payload_type") or "").strip()
            protected_payload_type = ""
            sdk_lang = ""
            sdk_vesion = ""
            if isinstance(protected_headers, dict):
                protected_payload_type = str(protected_headers.get("payload_type") or "").strip()
                sdk_lang = str(protected_headers.get("sdk_lang") or "").strip()
                sdk_vesion = str(protected_headers.get("sdk_vesion") or "").strip()
            if (
                payload_type != "text"
                or not isinstance(protected_headers, dict)
                or protected_payload_type != "text"
                or sdk_lang not in {"python", "typescript", "go", "cpp"}
                or not sdk_vesion
            ):
                missing.append(
                    {
                        "text": item.get("text"),
                        "message_id": item.get("message_id"),
                        "payload_type": item.get("payload_type"),
                        "protected_headers": protected_headers,
                        "encrypted": item.get("encrypted"),
                        "decrypted": item.get("decrypted"),
                    }
                )
        if missing:
            raise AssertionError(f"E2EE envelope metadata missing or invalid: {missing}")

    @staticmethod
    def _max_seq_for_texts(inbox: dict[str, Any], expected_texts: list[str]) -> int:
        expected = set(expected_texts)
        items = inbox.get("items") if isinstance(inbox.get("items"), list) else []
        seqs = [
            int(item.get("seq") or 0)
            for item in items
            if isinstance(item, dict) and str(item.get("text") or "") in expected and int(item.get("seq") or 0) > 0
        ]
        return max(seqs) if seqs else 0

    async def _ack_p2p(
        self,
        session: aiohttp.ClientSession,
        client: ClientEndpoint,
        inbox: dict[str, Any],
        expected_texts: list[str],
    ) -> dict[str, Any]:
        seq = self._max_seq_for_texts(inbox, expected_texts)
        result = await self._post(session, client, "/ack", {"seq": seq})
        if not result.get("ok"):
            raise AssertionError(f"p2p ack failed: {result}")
        return result

    async def _ack_group(
        self,
        session: aiohttp.ClientSession,
        client: ClientEndpoint,
        group_id: str,
        inbox: dict[str, Any],
        expected_texts: list[str],
    ) -> dict[str, Any]:
        seq = self._max_seq_for_texts(inbox, expected_texts)
        result = await self._post(session, client, "/group/ack", {"group_id": group_id, "seq": seq})
        if not result.get("ok"):
            raise AssertionError(f"group ack failed: {result}")
        return result

    async def _get(self, session: aiohttp.ClientSession, client: ClientEndpoint, path: str) -> dict[str, Any]:
        async with session.get(client.url + path) as resp:
            data = await resp.json(content_type=None)
            if resp.status >= 400:
                raise RuntimeError(f"GET {client.name}{path} failed status={resp.status} body={data}")
            return data

    async def _post(self, session: aiohttp.ClientSession, client: ClientEndpoint, path: str, body: dict[str, Any]) -> dict[str, Any]:
        async with session.post(client.url + path, json=body) as resp:
            data = await resp.json(content_type=None)
            if resp.status >= 400:
                raise RuntimeError(f"POST {client.name}{path} failed status={resp.status} body={data}")
            return data

    def _record(self, case_id: str, status: str, started: int, detail: dict[str, Any]) -> None:
        self.results.append(
            {
                "case_id": case_id,
                "status": status,
                "started_at_ms": started,
                "ended_at_ms": _now_ms(),
                "detail": _json_safe(detail),
            }
        )

    def _write_results(self) -> None:
        result_path = self.artifact_dir / "results.json"
        jsonl_path = self.artifact_dir / "results.jsonl"
        with result_path.open("w", encoding="utf-8") as f:
            json.dump({"results": self.results}, f, ensure_ascii=False, indent=2)
        with jsonl_path.open("w", encoding="utf-8") as f:
            for item in self.results:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        print(f"results written: {result_path}", flush=True)


async def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
    runner = CrossSdkRunner()
    return await runner.run()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
