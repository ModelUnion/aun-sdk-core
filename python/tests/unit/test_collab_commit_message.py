"""测试 collab.commit 支持 message 参数"""
import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_commit_with_message():
    """commit 应该接受 message 参数并记录到 ledger"""
    from aun_core.collab.client import CollabClient

    mock_client = MagicMock()
    mock_client.call = AsyncMock(return_value={
        "ok": True,
        "version": 2,
        "current_target": "alice.aid.com:/proj/.collab-versions/doc1.md/alice.aid.com/2.md"
    })

    collab = CollabClient(mock_client)

    result = await collab.commit(
        "alice.aid.com:/proj",
        "doc1.md",
        "alice.aid.com:/tmp/new.md",
        onto=1,
        message="Fix typo in introduction"
    )

    # 验证调用参数包含 message
    assert mock_client.call.called
    call_args = mock_client.call.call_args
    assert call_args[0][0] == "collab.commit"
    params = call_args[0][1]
    assert params["message"] == "Fix typo in introduction"
    assert params["onto"] == 1

    # 验证返回结果
    assert result["ok"] is True
    assert result["version"] == 2


@pytest.mark.asyncio
async def test_commit_without_message_defaults_empty():
    """commit 不传 message 时应该默认为空字符串"""
    from aun_core.collab.client import CollabClient

    mock_client = MagicMock()
    mock_client.call = AsyncMock(return_value={
        "ok": True,
        "version": 2,
        "current_target": "alice.aid.com:/proj/.collab-versions/doc1.md/alice.aid.com/2.md"
    })

    collab = CollabClient(mock_client)

    result = await collab.commit(
        "alice.aid.com:/proj",
        "doc1.md",
        "alice.aid.com:/tmp/new.md",
        onto=1
    )

    # 验证默认 message 为空字符串
    call_args = mock_client.call.call_args
    params = call_args[0][1]
    assert params["message"] == ""


@pytest.mark.asyncio
async def test_log_returns_message():
    """log 应该返回每个版本的 message"""
    from aun_core.collab.client import CollabClient

    mock_client = MagicMock()
    mock_client.call = AsyncMock(return_value=[
        {
            "version": 1,
            "author": "alice.aid.com",
            "target": "alice.aid.com:/proj/.collab-versions/doc1.md/alice.aid.com/1.md",
            "time": 1702800000000,
            "message": "Initial version"
        },
        {
            "version": 2,
            "author": "bob.aid.com",
            "target": "alice.aid.com:/proj/.collab-versions/doc1.md/bob.aid.com/1.md",
            "time": 1702800100000,
            "message": "Fix typo"
        }
    ])

    collab = CollabClient(mock_client)

    history = await collab.log("alice.aid.com:/proj", "doc1.md")

    # 验证 message 字段存在
    assert len(history) == 2
    assert history[0]["message"] == "Initial version"
    assert history[1]["message"] == "Fix typo"
