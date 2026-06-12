"""memberdata 透明路由：成员对自己挂载区的写操作映射到自己 storage 空间。

协议约定（group-storage 重构设计 §4.4/§5.3）：
- 成员挂载区 memberdata/{aid}/ 的源固定指向成员自己空间的 {aid}/{group_aid}（成员为这个群开的目录）。
- 成员写 memberdata/{self_aid}/{rest} 时，SDK 透明映射为对成员自己 storage 的
  storage.* 操作：owner_aid={self_aid}, object_key={self_aid}/{group_aid}/{rest}，成员自己 AID 签名。
- 服务端拒绝 memberdata 路径走 group_storage 模式，因此写操作必须由 SDK 路由到成员自己存储。
- 读操作（get/list/download）走现有 group.resources 路径，由服务端经 mount 解析到成员存储。
"""
import pytest

from aun_core import GroupResourcesFacade


class _FakeClient:
    def __init__(self, aid="alice.agentid.pub"):
        self.aid = aid
        self.calls = []

    async def call(self, method, params=None):
        self.calls.append((method, params or {}))
        if method == "group.get":
            return {"group": {"group_id": (params or {}).get("group_id"), "group_aid": "team.agentid.pub"}}
        return {"method": method, "params": params or {}}


def _facade(aid="alice.agentid.pub"):
    client = _FakeClient(aid)
    return GroupResourcesFacade(client), client


def test_resolve_memberdata_target_maps_self_slot():
    facade, _ = _facade("alice.agentid.pub")
    target = facade._resolve_memberdata_target("g-team.agentid.pub/team", "memberdata/alice.agentid.pub/docs/x.txt")
    assert target == ("alice.agentid.pub", "alice.agentid.pub/g-team.agentid.pub/team/docs/x.txt")


def test_resolve_memberdata_target_root_of_slot():
    facade, _ = _facade("alice.agentid.pub")
    target = facade._resolve_memberdata_target("g-team.agentid.pub/team", "memberdata/alice.agentid.pub")
    assert target == ("alice.agentid.pub", "alice.agentid.pub/g-team.agentid.pub/team")


def test_resolve_memberdata_target_returns_none_for_group_own_area():
    facade, _ = _facade("alice.agentid.pub")
    assert facade._resolve_memberdata_target("g-team.agentid.pub/team", "announce/a.txt") is None


def test_resolve_memberdata_target_returns_none_for_other_member_slot():
    """他人槽位不路由到本地 storage（无法以他人 AID 签名；读走群层 mount 解析）。"""
    facade, _ = _facade("alice.agentid.pub")
    assert facade._resolve_memberdata_target("g-team.agentid.pub/team", "memberdata/bob.agentid.pub/x") is None


def test_resolve_memberdata_target_case_insensitive_aid():
    facade, _ = _facade("Alice.AgentID.pub")
    target = facade._resolve_memberdata_target("g-team.agentid.pub/team", "memberdata/alice.agentid.pub/x")
    assert target is not None
    assert target[1] == "Alice.AgentID.pub/g-team.agentid.pub/team/x"


@pytest.mark.asyncio
async def test_put_routes_memberdata_self_to_storage_put_object():
    facade, client = _facade("alice.agentid.pub")

    await facade.put(
        group_id="g-team.agentid.pub/team",
        resource_path="memberdata/alice.agentid.pub/docs/x.txt",
        content="aGVsbG8=",
        content_encoding="base64",
        content_type="text/plain",
        size_bytes=5,
    )

    assert client.calls[0] == ("group.get", {"group_id": "g-team.agentid.pub/team"})
    method, params = client.calls[1]
    assert method == "storage.put_object"
    assert params["owner_aid"] == "alice.agentid.pub"
    assert params["object_key"] == "alice.agentid.pub/team.agentid.pub/docs/x.txt"
    assert params["content"] == "aGVsbG8="
    assert params["content_type"] == "text/plain"


@pytest.mark.asyncio
async def test_put_group_own_area_still_calls_group_resources_put():
    facade, client = _facade("alice.agentid.pub")

    await facade.put(
        group_id="g-team.agentid.pub/team",
        resource_path="announce/a.txt",
        content="aGVsbG8=",
    )

    assert client.calls[0][0] == "group.resources.put"


@pytest.mark.asyncio
async def test_delete_routes_memberdata_self_to_storage():
    facade, client = _facade("alice.agentid.pub")

    await facade.delete(
        group_id="g-team.agentid.pub/team",
        resource_path="memberdata/alice.agentid.pub/docs/x.txt",
    )

    method, params = client.calls[1]
    assert method == "storage.fs.remove"
    assert params["owner_aid"] == "alice.agentid.pub"
    assert params["path"] == "alice.agentid.pub/team.agentid.pub/docs/x.txt"


@pytest.mark.asyncio
async def test_create_folder_routes_memberdata_self_to_storage_mkdir():
    facade, client = _facade("alice.agentid.pub")

    await facade.create_folder(
        group_id="g-team.agentid.pub/team",
        resource_path="memberdata/alice.agentid.pub/docs",
        resource_type="folder",
    )

    method, params = client.calls[1]
    assert method == "storage.fs.mkdir"
    assert params["owner_aid"] == "alice.agentid.pub"
    assert params["path"] == "alice.agentid.pub/team.agentid.pub/docs"


@pytest.mark.asyncio
async def test_put_routes_memberdata_prefix_case_insensitively():
    facade, client = _facade("alice.agentid.pub")

    await facade.put(
        group_id="g-team.agentid.pub/team",
        resource_path="MemberData/alice.agentid.pub/docs/x.txt",
        content="aGVsbG8=",
    )

    method, params = client.calls[1]
    assert method == "storage.put_object"
    assert params["object_key"] == "alice.agentid.pub/team.agentid.pub/docs/x.txt"
