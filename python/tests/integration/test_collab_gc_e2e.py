"""测试 collab.gc E2E"""
import asyncio
import base64
import tempfile
import shutil
import pytest
from aun_core import AUNClient


@pytest.mark.asyncio
async def test_gc_basic_dry_run():
    """gc dry_run 基础测试"""
    aun_path = tempfile.mkdtemp(prefix="test-gc-")
    alice = AUNClient(debug=False)
    alice.init(aun_path=aun_path)
    await alice.register("alice.agentid.pub")
    await alice.connect("wss://gateway.agentid.pub:9500", verify_ssl=False)

    try:
        # 创建群和协作根
        group = await alice.create_group("test-gc-group")
        group_aid = group["group_aid"]

        collab_root = f"{alice.aid}:/gc-test"
        await alice.storage.vfs.mkdir("/gc-test", group_aid=group_aid)

        # 创建文档
        content_b64 = base64.b64encode(b"test content").decode()
        await alice.collab.create(collab_root, "doc1.md", f"data:text/plain;base64,{content_b64}")

        # 运行 gc dry_run
        result = await alice.collab.gc(collab_root, dry_run=True)

        # 验证返回字段
        assert "scanned" in result
        assert "reachable" in result
        assert "garbage" in result
        assert "deleted" in result
        assert result["deleted"] == 0  # dry_run 不删除

        print(f"✓ gc dry_run: scanned={result['scanned']}, reachable={result['reachable']}, garbage={result['garbage']}")

    finally:
        await alice.close()
        shutil.rmtree(aun_path, ignore_errors=True)


@pytest.mark.asyncio
async def test_gc_cleans_orphans():
    """gc 清理孤儿对象"""
    aun_path = tempfile.mkdtemp(prefix="test-gc-orphans-")
    alice = AUNClient(debug=False)
    alice.init(aun_path=aun_path)
    await alice.register("alice.agentid.pub")
    await alice.connect("wss://gateway.agentid.pub:9500", verify_ssl=False)

    try:
        # 创建群和协作根
        group = await alice.create_group("test-gc-orphans")
        group_aid = group["group_aid"]

        collab_root = f"{alice.aid}:/gc-orphan-test"
        await alice.storage.vfs.mkdir("/gc-orphan-test", group_aid=group_aid)

        # 创建文档 v1
        content_b64 = base64.b64encode(b"v1").decode()
        await alice.collab.create(collab_root, "doc1.md", f"data:text/plain;base64,{content_b64}")

        # 模拟孤儿：直接写一个对象到 .collab-versions/ 但不在 ledger 中
        orphan_content = base64.b64encode(b"orphan content").decode()
        orphan_path = f"/gc-orphan-test/.collab-versions/doc1.md/{alice.aid}/orphan-99.md"
        await alice.storage.put_object(
            orphan_path,
            content=orphan_content,
            group_aid=group_aid
        )

        # dry_run 应该发现孤儿
        result_dry = await alice.collab.gc(collab_root, dry_run=True)
        assert result_dry["garbage"] >= 1, f"应该发现至少1个孤儿，实际: {result_dry}"
        assert result_dry["deleted"] == 0

        # 实际清理
        result_clean = await alice.collab.gc(collab_root, dry_run=False)
        assert result_clean["deleted"] >= 1, f"应该删除至少1个对象，实际: {result_clean}"

        # 再次 gc 应该没有垃圾
        result_final = await alice.collab.gc(collab_root, dry_run=True)
        assert result_final["garbage"] == 0, f"清理后应该无垃圾，实际: {result_final}"

        print(f"✓ gc 清理孤儿: 删除了 {result_clean['deleted']} 个对象")

    finally:
        await alice.close()
        shutil.rmtree(aun_path, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(test_gc_basic_dry_run())
    asyncio.run(test_gc_cleans_orphans())
    print("\n✓ 所有 gc E2E 测试通过")
