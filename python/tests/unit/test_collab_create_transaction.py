"""测试 collab.create 的事务补偿机制（单元测试，mock storage primitives）"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
async def test_create_cleans_up_object_on_version_failure():
    """当 create_version 失败时，应该清理已写的 v1 对象"""
    from aun_core.collab.orchestrator import CollabOrchestrator

    # Mock storage primitives
    mock_primitives = MagicMock()
    mock_primitives.put_object = AsyncMock()
    mock_primitives.create_version = AsyncMock(side_effect=Exception("DB error"))
    mock_primitives.delete_object = AsyncMock()
    mock_primitives.check_access = AsyncMock(return_value={"has_access": True})
    mock_primitives.resolve_group_for_path = AsyncMock(return_value=None)
    mock_primitives.get_object = AsyncMock(return_value={"content": "dGVzdA=="})  # base64("test")

    orchestrator = CollabOrchestrator(mock_primitives, group_manager=None)

    # 尝试 create，预期失败
    with pytest.raises(Exception, match="DB error"):
        await orchestrator.create(
            "alice.aid.com",
            "alice.aid.com:/proj",
            "doc1.md",
            "alice.aid.com:/tmp/source.md"
        )

    # 验证调用顺序：put_object -> create_version(失败) -> delete_object(清理)
    assert mock_primitives.put_object.call_count == 1
    assert mock_primitives.create_version.call_count == 1
    assert mock_primitives.delete_object.call_count == 1

    # 验证 delete_object 的参数
    delete_call = mock_primitives.delete_object.call_args
    assert delete_call[0][1]["object_key"].endswith("/alice.aid.com/1.md")


@pytest.mark.asyncio
async def test_snapshot_create_cleans_up_manifest_on_symlink_failure():
    """当首次 snapshot 的 create_symlink 失败时，应该清理已写的 manifest 对象"""
    from aun_core.collab.orchestrator import CollabOrchestrator

    # Mock storage primitives
    mock_primitives = MagicMock()
    mock_primitives.put_object = AsyncMock()
    mock_primitives.create_symlink = AsyncMock(side_effect=Exception("Symlink conflict"))
    mock_primitives.delete_object = AsyncMock()
    mock_primitives.check_access = AsyncMock(return_value={"has_access": True})
    mock_primitives.resolve_group_for_path = AsyncMock(return_value=None)
    mock_primitives.list_objects = AsyncMock(return_value={"items": [], "has_more": False})
    mock_primitives.readlink = AsyncMock(side_effect=Exception("Not found"))  # 没有 @snapshot

    orchestrator = CollabOrchestrator(mock_primitives, group_manager=None)

    # Mock ls 返回空（无变更会抛 CollabNoChange，所以给一个假条目）
    with patch.object(orchestrator, 'ls', new_callable=AsyncMock) as mock_ls:
        mock_ls.return_value = [{"doc": "doc1.md", "version": 1, "author": "alice.aid.com", "current_target": "alice.aid.com:/proj/.collab-versions/doc1.md/alice.aid.com/1.md"}]

        # 尝试 snapshot_create，预期失败
        with pytest.raises(Exception, match="Symlink conflict"):
            await orchestrator.snapshot_create(
                "alice.aid.com",
                "alice.aid.com:/proj",
                message="first snapshot",
                major=False
            )

    # 验证调用顺序：put_object(manifest) -> create_symlink(失败) -> delete_object(清理)
    assert mock_primitives.put_object.call_count == 1
    assert mock_primitives.create_symlink.call_count == 1
    assert mock_primitives.delete_object.call_count == 1

    # 验证 delete_object 清理的是 manifest
    delete_call = mock_primitives.delete_object.call_args
    assert ".collab-snapshots/" in delete_call[0][1]["object_key"]
