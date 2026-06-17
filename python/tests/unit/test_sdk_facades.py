import pytest

from aun_core import (
    AUNClient,
    GroupFacade,
    MessageFacade,
    StreamFacade,
)


class _FakeClient:
    def __init__(self):
        self.calls = []

    async def call(self, method, params=None):
        self.calls.append((method, params or {}))
        return {"method": method, "params": params or {}}


@pytest.mark.asyncio
async def test_facades_accept_dict_and_omit_none():
    client = _FakeClient()
    group = GroupFacade(client)

    await group.get({"group_id": "g1", "resource_id": None}, include_status=None)
    await group.send({"group_id": "g1", "payload": {"text": "hi"}, "encrypt": None})

    assert client.calls == [
        ("group.get", {"group_id": "g1"}),
        ("group.send", {"group_id": "g1", "payload": {"text": "hi"}}),
    ]


@pytest.mark.asyncio
async def test_message_group_stream_facades_use_client_call():
    client = _FakeClient()
    message = MessageFacade(client)
    group = GroupFacade(client)
    stream = StreamFacade(client)

    await message.send(to="bob.agentid.pub", payload={"text": "hi"})
    await message.pull(limit=10)
    await message.ack(seq=12)
    await message.recall(message_ids=["m1"])
    await message.query_online(aids=["bob.agentid.pub"])
    await message.thought.put(to="bob.agentid.pub", thought_id="t1", payload={"x": 1})
    await message.thought.get(to="bob.agentid.pub", thought_id="t1")
    await group.create(name="team")
    await group.bind_aid(group_id="g1")
    await group.bind_group_aid(group_id="g2")
    await group.get_info(group_id="g1")
    await group.list()
    await group.info(group_id="g1", include=["stats"])
    await group.check_membership(group_id="g1", requester_aid="alice.agentid.pub")
    await group.transfer_owner(group_id="g1", aid="bob.agentid.pub")
    await group.complete_transfer(group_id="g1", public_key="PUB")
    await group.send(group_id="g1", payload={"text": "hi"})
    await group.pull(group_id="g1", limit=20)
    await group.ack_messages(group_id="g1", up_to_seq=3)
    await group.ack_events(group_id="g1", up_to_event_seq=4)
    await group.thought.put(group_id="g1", thought_id="t2", payload={"x": 2})
    await stream.create(content_type="text/plain")
    await stream.get_info(stream_id="s1")
    await stream.list_active()
    await stream.close(stream_id="s1")

    assert [method for method, _ in client.calls] == [
        "message.send",
        "message.pull",
        "message.ack",
        "message.recall",
        "message.query_online",
        "message.thought.put",
        "message.thought.get",
        "group.create",
        "group.bind_group_aid",
        "group.bind_group_aid",
        "group.get_info",
        "group.list",
        "group.info",
        "group.check_membership",
        "group.transfer_owner",
        "group.complete_transfer",
        "group.send",
        "group.pull",
        "group.ack_messages",
        "group.ack_events",
        "group.thought.put",
        "stream.create",
        "stream.get_info",
        "stream.list_active",
        "stream.close",
    ]
    assert client.calls[0][1]["to"] == "bob.agentid.pub"
    assert client.calls[16][1]["group_id"] == "g1"
    assert not hasattr(group, "get_state")
    assert not hasattr(group, "commit_state")
    assert not hasattr(group, "get_cursor")


def test_aun_client_exposes_cached_namespace_facades():
    client = AUNClient()

    assert isinstance(client.message, MessageFacade)
    assert isinstance(client.group, GroupFacade)
    assert isinstance(client.stream, StreamFacade)
    assert client.message is client.message
    assert client.group is client.group
    assert client.stream is client.stream


@pytest.mark.asyncio
async def test_low_level_group_rpcs_remain_accessible_through_call():
    client = _FakeClient()

    await client.call("group.get_state", {"group_id": "g1"})
    await client.call("group.commit_state", {"group_id": "g1", "state_version": 1})

    assert client.calls == [
        ("group.get_state", {"group_id": "g1"}),
        ("group.commit_state", {"group_id": "g1", "state_version": 1}),
    ]
