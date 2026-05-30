"""
set_protected_headers 校验逻辑单元测试

覆盖：
- _auth 保留键被过滤
- 不符合 [a-z0-9_-] 规则的 key 被静默跳过
- 合法 key 保留，值强转 str
"""
from aun_core import AUNClient


def test_auth_key_filtered():
    """_auth 保留键必须被过滤掉"""
    client = AUNClient()
    client.set_protected_headers({"_auth": "secret", "trace_id": "abc"})
    result = client.get_protected_headers()
    assert "_auth" not in result
    assert result["trace_id"] == "abc"


def test_invalid_key_uppercase_filtered():
    """大写字母 key（如 X-App）必须被静默过滤"""
    client = AUNClient()
    client.set_protected_headers({"X-App": "val", "trace_id": "abc"})
    result = client.get_protected_headers()
    assert "X-App" not in result
    assert result["trace_id"] == "abc"


def test_invalid_key_space_filtered():
    """含空格的 key 必须被静默过滤"""
    client = AUNClient()
    client.set_protected_headers({"a b": "val", "ok_key": "1"})
    result = client.get_protected_headers()
    assert "a b" not in result
    assert result["ok_key"] == "1"


def test_valid_keys_preserved():
    """合法 key（小写字母、数字、_、-）全部保留"""
    client = AUNClient()
    client.set_protected_headers({"trace-id": "t1", "app_name": "x", "v2": "yes"})
    result = client.get_protected_headers()
    assert result == {"trace-id": "t1", "app_name": "x", "v2": "yes"}


def test_value_coerced_to_str():
    """值必须强转为 str"""
    client = AUNClient()
    client.set_protected_headers({"count": 42, "flag": True})
    result = client.get_protected_headers()
    assert result["count"] == "42"
    assert result["flag"] == "True"


def test_all_invalid_returns_none():
    """全部 key 非法时返回 None"""
    client = AUNClient()
    client.set_protected_headers({"_auth": "x", "Bad-Key": "y"})
    assert client.get_protected_headers() is None


def test_none_input():
    """传 None 清空"""
    client = AUNClient()
    client.set_protected_headers({"trace_id": "abc"})
    client.set_protected_headers(None)
    assert client.get_protected_headers() is None
