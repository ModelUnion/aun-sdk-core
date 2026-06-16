"""测试 collab.gc 垃圾回收功能"""
import pytest


@pytest.mark.asyncio
async def test_gc_dry_run_basic(docker_client_factory):
    """gc dry_run 模式应该只统计，不删除"""
    alice = await docker_client_factory("alice.agentid.pub")

    # 创建协作根和文档
    group = await alice.create_group("test-group")
    group_aid = group["group_aid"]

    collab_root = f"{alice.aid}:/gc-test"
    await alice.storage.vfs.mkdir(collab_root.split(":")[1], group_aid=group_aid)

    # 创建 v1
    await alice.collab.create(collab_root, "doc1.md", f"{alice.aid}:/tmp/v1.md")

    # 创建 v2（v1 仍然在 ledger 中，不是垃圾）
    await alice.collab.submit(collab_root, "doc1.md", f"{alice.aid}:/tmp/v2.md", base_version=1, message="v2")

    # 执行 gc dry_run
    result = await alice.collab.gc(collab_root, dry_run=True)

    # 验证返回字段
    assert "scanned" in result
    assert "reachable" in result
    assert "garbage" in result
    assert "deleted" in result
    assert result["deleted"] == 0  # dry_run 不删除

    # 验证对象仍然存在
    history = await alice.collab.history(collab_root, "doc1.md")
    assert len(history) == 2  # v1 和 v2 都在

    await alice.close()


@pytest.mark.asyncio
async def test_gc_cleans_orphans(docker_client_factory):
    """gc 应该清理孤儿对象（CAS 失败的残留）"""
    alice = await docker_client_factory("alice.agentid.pub")

    group = await alice.create_group("test-group")
    group_aid = group["group_aid"]

    collab_root = f"{alice.aid}:/gc-test"
    await alice.storage.vfs.mkdir(collab_root.split(":")[1], group_aid=group_aid)

    # 创建 v1
    await alice.collab.create(collab_root, "doc1.md", f"{alice.aid}:/tmp/v1.md")

    # 模拟孤儿：直接写一个对象但不在 ledger 中
    orphan_path = f"{collab_root.split(':')[1]}/.collab-versions/doc1.md/{alice.aid}/orphan.md"
    await alice.storage.put_object(
        orphan_path,
        content="orphan content",
        group_aid=group_aid
    )

    # dry_run 应该发现孤儿
    result = await alice.collab.gc(collab_root, dry_run=True)
    assert result["garbage"] >= 1
    assert result["deleted"] == 0

    # 实际清理
    result = await alice.collab.gc(collab_root, dry_run=False)
    assert result["deleted"] >= 1

    # 再次 gc 应该没有垃圾
    result = await alice.collab.gc(collab_root, dry_run=True)
    assert result["garbage"] == 0

    await alice.close()


@pytest.mark.asyncio
async def test_gc_preserves_ledger_references(docker_client_factory):
    """gc 应该保留 ledger 中引用的所有版本"""
    alice = await docker_client_factory("alice.agentid.pub")

    group = await alice.create_group("test-group")
    group_aid = group["group_aid"]

    collab_root = f"{alice.aid}:/gc-test"
    await alice.storage.vfs.mkdir(collab_root.split(":")[1], group_aid=group_aid)

    # 创建多个版本
    await alice.collab.create(collab_root, "doc1.md", f"{alice.aid}:/tmp/v1.md")
    await alice.collab.submit(collab_root, "doc1.md", f"{alice.aid}:/tmp/v2.md", 1, "v2")
    await alice.collab.submit(collab_root, "doc1.md", f"{alice.aid}:/tmp/v3.md", 2, "v3")

    # gc 不应该删除任何版本
    result = await alice.collab.gc(collab_root, dry_run=False)
    assert result["garbage"] == 0
    assert result["deleted"] == 0

    # 验证所有版本仍可读
    v1 = await alice.collab.get(collab_root, "doc1.md", 1)
    v2 = await alice.collab.get(collab_root, "doc1.md", 2)
    v3 = await alice.collab.get(collab_root, "doc1.md", 3)
    assert v1 is not None
    assert v2 is not None
    assert v3 is not None

    await alice.close()


@pytest.mark.asyncio
async def test_gc_preserves_snapshot_references(docker_client_factory):
    """gc 应该保留 snapshot 引用的对象"""
    alice = await docker_client_factory("alice.agentid.pub")

    group = await alice.create_group("test-group")
    group_aid = group["group_aid"]

    collab_root = f"{alice.aid}:/gc-test"
    await alice.storage.vfs.mkdir(collab_root.split(":")[1], group_aid=group_aid)

    # 创建文档
    await alice.collab.create(collab_root, "doc1.md", f"{alice.aid}:/tmp/v1.md")

    # 创建快照
    await alice.collab.snapshot.create(collab_root, message="Snapshot 1")

    # 更新到 v2
    await alice.collab.submit(collab_root, "doc1.md", f"{alice.aid}:/tmp/v2.md", 1, "v2")

    # gc 不应该删除 v1（被 snapshot 引用）
    result = await alice.collab.gc(collab_root, dry_run=False)
    assert result["garbage"] == 0

    # 验证快照仍然有效
    snapshots = await alice.collab.snapshot.list(collab_root)
    assert len(snapshots) > 0

    await alice.close()
