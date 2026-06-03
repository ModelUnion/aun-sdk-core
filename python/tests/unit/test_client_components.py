import asyncio
import json

import pytest

from aun_core._client import (
    GroupStateCoordinator,
    MessageDeliveryEngine,
    RpcPipeline,
    V2E2EECoordinator,
)


class _NoopLog:
    def debug(self, *args, **kwargs):
        pass

    def warn(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass


def test_rpc_pipeline_merges_instance_protected_headers():
    class FakeClient:
        _instance_protected_headers = {"tenant": "global", "trace": "root"}

        def _protected_headers_from_params(self, params):
            return params.get("protected_headers")

    params = {"protected_headers": {"trace": "local", "payload_type": "chat"}}

    result = RpcPipeline(FakeClient()).merge_instance_protected_headers("message.send", params)

    assert result["protected_headers"] == {
        "tenant": "global",
        "trace": "local",
        "payload_type": "chat",
    }


def test_message_delivery_attaches_instance_context_and_filters_target():
    class FakeClient:
        _device_id = "dev-1"
        _slot_id = "slot-a"

    engine = MessageDeliveryEngine(FakeClient())

    payload = engine.attach_current_instance_context({"message_id": "m1"})
    assert payload["device_id"] == "dev-1"
    assert payload["slot_id"] == "slot-a"
    assert engine.message_targets_current_instance({"device_id": "dev-1", "slot_id": "slot-a"})
    assert not engine.message_targets_current_instance({"device_id": "dev-2", "slot_id": "slot-a"})


def test_message_delivery_maps_recall_tombstone_to_app_event():
    class FakeClient:
        _device_id = "dev-1"
        _slot_id = "slot-a"

    engine = MessageDeliveryEngine(FakeClient())
    event, payload = engine.p2p_app_event_for_message({
        "message_id": "recall-1",
        "from": "alice.agentid.pub",
        "to": "bob.agentid.pub",
        "seq": 9,
        "type": "message.recalled",
        "payload": {
            "kind": "message.recalled",
            "message_ids": ["m-1"],
            "recalled_at": 123,
        },
    })

    assert event == "message.recalled"
    assert payload["message_ids"] == ["m-1"]
    assert payload["tombstone_message_id"] == "recall-1"
    assert payload["seq"] == 9


def test_v2_e2ee_metadata_filters_auth_fields_and_attaches_public_fields():
    envelope = {
        "suite": "AUN-P256",
        "protected_headers": {"payload_type": "chat", "topic": "t1", "_auth": "drop"},
        "context": {"type": "message", "id": "m1", "_auth": "drop"},
        "agent_md": {"etag": "e1", "_auth": "drop"},
    }

    meta = V2E2EECoordinator(object()).v2_thought_e2ee_metadata(envelope)
    message = {}
    V2E2EECoordinator.attach_v2_envelope_metadata(message, meta)

    assert meta["version"] == "v2"
    assert meta["payload_type"] == "chat"
    assert meta["protected_headers"] == {"payload_type": "chat", "topic": "t1"}
    assert meta["context"] == {"type": "message", "id": "m1"}
    assert meta["agent_md"] == {"etag": "e1"}
    assert message["payload_type"] == "chat"
    assert message["protected_headers"] == {"payload_type": "chat", "topic": "t1"}
    assert message["agent_md"] == {"etag": "e1"}


def test_v2_e2ee_encrypted_push_envelope_accepts_payload_or_json():
    class FakeClient:
        _is_encrypted_envelope_payload = staticmethod(V2E2EECoordinator.is_encrypted_envelope_payload)

    coordinator = V2E2EECoordinator(FakeClient())
    envelope = {"type": "e2ee.p2p_encrypted", "version": "v2"}

    assert coordinator.encrypted_push_envelope({"payload": envelope}) == envelope
    assert coordinator.encrypted_push_envelope({"envelope_json": json.dumps(envelope)}) == envelope
    assert coordinator.encrypted_push_envelope({"payload": {"type": "text"}}) is None


@pytest.mark.asyncio
async def test_group_state_lazy_propose_is_deduplicated():
    calls = []

    class FakeClient:
        _v2_auto_state_management_enabled = True
        _v2_lazy_propose_triggered = {}
        _loop = None

        async def _v2_auto_propose_state(self, group_id, *, leader_delay=False):
            calls.append((group_id, leader_delay))

    coordinator = GroupStateCoordinator(FakeClient())

    coordinator.maybe_trigger_auto_propose("group.agentid.pub/g1")
    coordinator.maybe_trigger_auto_propose("group.agentid.pub/g1")
    await asyncio.sleep(0)

    assert calls == [("group.agentid.pub/g1", True)]


@pytest.mark.asyncio
async def test_group_state_membership_change_updates_cache_and_spk_path():
    events = []

    class FakeClient:
        _aid = "alice.agentid.pub"
        _v2_session = object()
        _v2_bootstrap_cache = {"group:group.agentid.pub/g1": ("cached",)}
        _loop = None

        def _schedule_group_spk_registration(self, group_id, *, reason):
            events.append(("register", group_id, reason))

        def _schedule_group_spk_rotation(self, group_id, *, reason):
            events.append(("rotate", group_id, reason))

        async def _v2_auto_propose_state(self, group_id, *, leader_delay=False):
            events.append(("propose", group_id, leader_delay))

    client = FakeClient()
    coordinator = GroupStateCoordinator(client)

    coordinator.handle_group_changed_v2_membership({
        "group_id": "group.agentid.pub/g1",
        "action": "member_added",
        "joined_aid": "alice.agentid.pub",
    })
    await asyncio.sleep(0)

    assert "group:group.agentid.pub/g1" not in client._v2_bootstrap_cache
    assert ("register", "group.agentid.pub/g1", "group.changed:member_added") in events
    assert ("propose", "group.agentid.pub/g1", True) in events
