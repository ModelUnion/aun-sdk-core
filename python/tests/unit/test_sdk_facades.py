import pytest

from aun_core import (
    AUNClient,
    GroupFacade,
    GroupResourcesFacade,
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
async def test_group_resources_facade_maps_all_public_methods():
    client = _FakeClient()
    resources = GroupResourcesFacade(client)

    await resources.put(group_id="g1", resource_path="docs/a.txt", storage_ref={"owner_aid": "alice.agentid.pub"})
    await resources.create_folder(group_id="g1", path="docs", mkdirs=True)
    await resources.list_children(group_id="g1", path="docs", size=20)
    await resources.rename(group_id="g1", resource_id="r1", new_name="b.txt")
    await resources.move(group_id="g1", resource_id="r1", dst_parent_path="archive")
    await resources.mount_object(group_id="g1", path="docs/a.txt", storage_ref={"object_key": "a.txt"})
    await resources.unmount(group_id="g1", resource_id="r1")
    await resources.resolve_path(group_id="g1", path="docs/a.txt")
    await resources.get(group_id="g1", resource_id="r1")
    await resources.list(group_id="g1", prefix="docs")
    await resources.update(group_id="g1", resource_id="r1", title="A")
    await resources.get_access(group_id="g1", resource_id="r1")
    await resources.resolve_access_ticket(access_ticket="ticket-1")
    await resources.delete(group_id="g1", resource_id="r1", recursive=True)
    await resources.namespace_ready(group_id="g1", folder_ids={"announce": "folder-announce"})
    await resources.confirm(group_id="g1", op_id="op1")
    await resources.confirm_mount(group_id="g1", mount_id="mnt1")
    await resources.get_df(group_id="g1")

    assert [method for method, _ in client.calls] == [
        "group.resources.put",
        "group.resources.create_folder",
        "group.resources.list_children",
        "group.resources.rename",
        "group.resources.move",
        "group.resources.mount_object",
        "group.resources.unmount",
        "group.resources.resolve_path",
        "group.resources.get",
        "group.resources.list",
        "group.resources.update",
        "group.resources.get_access",
        "group.resources.resolve_access_ticket",
        "group.resources.delete",
        "group.resources.namespace_ready",
        "group.resources.confirm",
        "group.resources.confirm_mount",
        "group.resources.get_df",
    ]
    assert client.calls[0][1] == {
        "group_id": "g1",
        "resource_path": "docs/a.txt",
        "storage_ref": {"owner_aid": "alice.agentid.pub"},
    }
    assert client.calls[1][1]["mkdirs"] is True
    assert client.calls[13][1]["recursive"] is True
    for removed in [
        "list_refs_by_storage",
        "cleanup_by_storage_ref",
        "request_mount_object",
        "request_add",
        "direct_add",
        "list_pending",
        "approve_request",
        "reject_request",
    ]:
        assert not hasattr(resources, removed)


@pytest.mark.asyncio
async def test_facades_accept_dict_and_omit_none():
    client = _FakeClient()
    group = GroupFacade(client)

    await group.resources.get({"group_id": "g1", "resource_id": None}, resource_path="docs/a.txt", include_status=None)
    await group.send({"group_id": "g1", "payload": {"text": "hi"}, "encrypt": None})

    assert client.calls == [
        ("group.resources.get", {"group_id": "g1", "resource_path": "docs/a.txt"}),
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
    assert isinstance(client.group.resources, GroupResourcesFacade)
    assert isinstance(client.stream, StreamFacade)
    assert client.message is client.message
    assert client.group is client.group
    assert client.group.resources is client.group.resources
    assert client.stream is client.stream
    assert not hasattr(client, "group_resources")


@pytest.mark.asyncio
async def test_low_level_group_rpcs_remain_accessible_through_call():
    client = _FakeClient()

    await client.call("group.get_state", {"group_id": "g1"})
    await client.call("group.commit_state", {"group_id": "g1", "state_version": 1})

    assert client.calls == [
        ("group.get_state", {"group_id": "g1"}),
        ("group.commit_state", {"group_id": "g1", "state_version": 1}),
    ]
