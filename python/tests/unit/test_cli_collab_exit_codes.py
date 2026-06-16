"""测试 CLI collab 命令的退出码映射"""
import pytest
from aun_core.errors import AUNError
from aun_cli.commands.collab import _is_collab_user_error


def test_collab_no_change_is_user_error():
    """CollabNoChange (-32010) 应该被识别为用户错误，返回退出码 3"""
    # -32010 是 CollabNoChange 错误码
    exc = AUNError(message="No changes", code=-32010)
    assert _is_collab_user_error(exc), "CollabNoChange (-32010) 应该是用户错误"


def test_collab_conflict_is_user_error():
    """CollabConflict (-32009) 应该被识别为用户错误"""
    exc = AUNError(message="Conflict", code=-32009)
    assert _is_collab_user_error(exc), "CollabConflict (-32009) 应该是用户错误"


def test_collab_not_found_is_user_error():
    """CollabNotFound (-32008) 应该被识别为用户错误"""
    exc = AUNError(message="Not found", code=-32008)
    assert _is_collab_user_error(exc), "CollabNotFound (-32008) 应该是用户错误"


def test_collab_forbidden_is_user_error():
    """CollabForbidden (-32004) 应该被识别为用户错误"""
    exc = AUNError(message="Forbidden", code=-32004)
    assert _is_collab_user_error(exc), "CollabForbidden (-32004) 应该是用户错误"


def test_collab_internal_error_is_not_user_error():
    """内部错误 (-32603) 不应该被识别为用户错误"""
    exc = AUNError(message="Internal error", code=-32603)
    assert not _is_collab_user_error(exc), "内部错误不应该是用户错误"


def test_collab_user_error_codes():
    """验证所有应该是用户错误的错误码"""
    user_error_codes = [
        -32600,  # Invalid Request
        -32601,  # Method not found
        -32602,  # Invalid params
        -32001,  # Parse error
        -32004,  # Permission denied / CollabForbidden
        -32008,  # CollabNotFound
        -32009,  # CollabConflict
        -32010,  # CollabNoChange
        4000,    # Bad request
        403,     # Forbidden
        4030,    # Forbidden variant
        404,     # Not found
        4040,    # Not found variant
    ]

    for code in user_error_codes:
        exc = AUNError(message=f"Test error {code}", code=code)
        assert _is_collab_user_error(exc), f"错误码 {code} 应该是用户错误"
