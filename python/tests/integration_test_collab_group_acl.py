"""测试群协作的读权限模型：非群成员但有 ACL 授权时应可读"""
import pytest


@pytest.mark.asyncio
async def test_collab_read_non_member_with_acl(docker_client_factory):
    """非群成员但有 storage ACL 授权时应该可以读取协作文档"""
    alice = await docker_client_factory("alice.agentid.pub")
    bob = await docker_client_factory("bob.agentid.pub")
    charlie = await docker_client_factory("charlie.agentid.pub")

    # Alice 创建群和协作根
    group = await alice.create_group("test-group")
    group_aid = group["group_aid"]

    # Bob 加入群
    await alice.group.add_members(group_aid, [bob.aid])
    await bob.group.accept_invite(group_aid)

    # Alice 在群内创建协作文档
    collab_root = f"{alice.aid}:/collab-test"
    await alice.storage.vfs.mkdir(collab_root.split(":")[1], group_aid=group_aid)
    await alice.collab.create(collab_root, "doc1.md", f"{alice.aid}:/tmp/source.md")

    # Alice 给 Charlie 读权限（但 Charlie 不是群成员）
    await alice.storage.vfs.share(
        collab_root.split(":")[1],
        charlie.aid,
        permission="read",
        group_aid=group_aid
    )

    # Charlie 应该可以读取（有 ACL 授权，虽然不是群成员）
    result = await charlie.collab.read(collab_root, "doc1.md")
    assert result is not None
    assert result.get("content") is not None

    await alice.close()
    await bob.close()
    await charlie.close()


@pytest.mark.asyncio
async def test_collab_read_non_member_without_acl(docker_client_factory):
    """非群成员且无 ACL 授权时应该被拒绝"""
    alice = await docker_client_factory("alice.agentid.pub")
    bob = await docker_client_factory("bob.agentid.pub")
    charlie = await docker_client_factory("charlie.agentid.pub")

    # Alice 创建群和协作根
    group = await alice.create_group("test-group")
    group_aid = group["group_aid"]

    # Bob 加入群
    await alice.group.add_members(group_aid, [bob.aid])
    await bob.group.accept_invite(group_aid)

    # Alice 在群内创建协作文档
    collab_root = f"{alice.aid}:/collab-test"
    await alice.storage.vfs.mkdir(collab_root.split(":")[1], group_aid=group_aid)
    await alice.collab.create(collab_root, "doc1.md", f"{alice.aid}:/tmp/source.md")

    # Charlie 无授权，应该被拒绝
    with pytest.raises(Exception) as exc_info:
        await charlie.collab.read(collab_root, "doc1.md")

    # 应该是权限错误，不是群成员错误
    assert "permission" in str(exc_info.value).lower() or "forbidden" in str(exc_info.value).lower()

    await alice.close()
    await bob.close()
    await charlie.close()
