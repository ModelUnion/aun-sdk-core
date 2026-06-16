"""测试 collab.reset 功能"""
import pytest


@pytest.mark.asyncio
async def test_reset_to_version(docker_client_factory):
    """reset 到指定版本应该创建新提交"""
    alice = await docker_client_factory("alice.agentid.pub")

    group = await alice.create_group("test-reset")
    group_aid = group["group_aid"]

    collab_root = f"{alice.aid}:/reset-test"
    await alice.storage.vfs.mkdir("/reset-test", group_aid=group_aid)

    # 创建 v1
    await alice.collab.create(collab_root, "doc.md", f"{alice.aid}:/tmp/v1.md")

    # 提交 v2, v3, v4
    await alice.collab.submit(collab_root, "doc.md", f"{alice.aid}:/tmp/v2.md", 1, "v2")
    await alice.collab.submit(collab_root, "doc.md", f"{alice.aid}:/tmp/v3.md", 2, "v3")
    await alice.collab.submit(collab_root, "doc.md", f"{alice.aid}:/tmp/v4.md", 3, "v4")

    # 当前版本应该是 v4
    current = await alice.collab.read(collab_root, "doc.md")
    assert current["version"] == 4

    # reset 到 v2（应该创建 v5，内容是 v2 的）
    result = await alice.collab.reset(collab_root, "doc.md", version=2, message="Reset to v2")
    assert result["version"] == 5

    # 验证 v5 内容与 v2 相同
    v2 = await alice.collab.get(collab_root, "doc.md", 2)
    v5 = await alice.collab.get(collab_root, "doc.md", 5)
    assert v2["content"] == v5["content"]

    # history 应该有 5 个版本
    history = await alice.collab.history(collab_root, "doc.md")
    assert len(history) == 5
    assert history[0]["message"] == "Reset to v2"

    await alice.close()


@pytest.mark.asyncio
async def test_reset_version_not_found(docker_client_factory):
    """reset 到不存在的版本应该报错"""
    alice = await docker_client_factory("alice.agentid.pub")

    group = await alice.create_group("test-reset-err")
    group_aid = group["group_aid"]

    collab_root = f"{alice.aid}:/reset-test"
    await alice.storage.vfs.mkdir("/reset-test", group_aid=group_aid)

    await alice.collab.create(collab_root, "doc.md", f"{alice.aid}:/tmp/v1.md")

    # reset 到不存在的版本
    with pytest.raises(Exception) as exc_info:
        await alice.collab.reset(collab_root, "doc.md", version=99)

    assert "not found" in str(exc_info.value).lower() or "不存在" in str(exc_info.value)

    await alice.close()
