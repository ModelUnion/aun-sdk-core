"""
AUN E2EE V2 Conformance: canonical_json

规范引用: §10.2 Canonical JSON
规则:
- 键递归字典序排序
- UTF-8 直出（不转义非 ASCII）
- 数值无前导零、不科学计数法
- 字符串最小转义（仅 \"\\\\\\b\\f\\n\\r\\t，其它控制字符 \\u00XX）
- 无空格分隔
- null / true / false 字面
- 数组顺序保留
"""
import json
import pytest

# ── 从 V2 实现导入 ──
from aun_core.v2.crypto.canonical import canonical_json


# ══════════════════════════════════════════════════════════════
# 测试用例（Red 阶段：全部 fail，因为 canonical_json 未实现）
# ══════════════════════════════════════════════════════════════


class TestCanonicalBasic:
    """基础序列化"""

    def test_empty_object(self):
        assert canonical_json({}) == b"{}"

    def test_empty_array(self):
        assert canonical_json([]) == b"[]"

    def test_null(self):
        assert canonical_json(None) == b"null"

    def test_true(self):
        assert canonical_json(True) == b"true"

    def test_false(self):
        assert canonical_json(False) == b"false"

    def test_integer_zero(self):
        assert canonical_json(0) == b"0"

    def test_integer_negative(self):
        assert canonical_json(-1) == b"-1"

    def test_integer_large(self):
        assert canonical_json(1710504000000) == b"1710504000000"

    def test_float_no_scientific(self):
        # 规范要求不使用科学计数法
        # 0.5 应输出 "0.5" 而非 "5e-1"
        assert canonical_json(0.5) == b"0.5"

    def test_string_simple(self):
        assert canonical_json("hello") == b'"hello"'

    def test_string_empty(self):
        assert canonical_json("") == b'""'


class TestCanonicalKeyOrder:
    """键排序"""

    def test_two_keys_sorted(self):
        result = canonical_json({"b": 1, "a": 2})
        assert result == b'{"a":2,"b":1}'

    def test_three_keys_sorted(self):
        result = canonical_json({"c": 3, "a": 1, "b": 2})
        assert result == b'{"a":1,"b":2,"c":3}'

    def test_nested_keys_sorted(self):
        result = canonical_json({"z": {"b": 2, "a": 1}, "a": 0})
        assert result == b'{"a":0,"z":{"a":1,"b":2}}'

    def test_deeply_nested(self):
        obj = {"c": {"z": {"y": 1, "x": 2}, "a": 3}, "b": 4}
        result = canonical_json(obj)
        assert result == b'{"b":4,"c":{"a":3,"z":{"x":2,"y":1}}}'


class TestCanonicalArrayOrder:
    """数组顺序保留（不排序）"""

    def test_array_preserves_order(self):
        result = canonical_json([3, 1, 2])
        assert result == b"[3,1,2]"

    def test_array_of_objects(self):
        result = canonical_json([{"b": 1, "a": 2}, {"d": 3, "c": 4}])
        assert result == b'[{"a":2,"b":1},{"c":4,"d":3}]'


class TestCanonicalStringEscaping:
    """字符串转义"""

    def test_unicode_no_escape(self):
        # UTF-8 直出，不转义非 ASCII
        result = canonical_json("中文")
        assert result == '"中文"'.encode("utf-8")

    def test_emoji_no_escape(self):
        result = canonical_json("😀")
        assert result == '"😀"'.encode("utf-8")

    def test_backslash_escape(self):
        result = canonical_json("a\\b")
        assert result == b'"a\\\\b"'

    def test_quote_escape(self):
        result = canonical_json('a"b')
        assert result == b'"a\\"b"'

    def test_newline_escape(self):
        result = canonical_json("a\nb")
        assert result == b'"a\\nb"'

    def test_tab_escape(self):
        result = canonical_json("a\tb")
        assert result == b'"a\\tb"'

    def test_control_char_u00xx(self):
        # 控制字符 0x01 应转义为 
        result = canonical_json("a\x01b")
        assert result == b'"a\\u0001b"'

    def test_null_char(self):
        result = canonical_json("a\x00b")
        assert result == b'"a\\u0000b"'


class TestCanonicalNoSpaces:
    """无空格分隔"""

    def test_object_no_spaces(self):
        result = canonical_json({"a": 1, "b": 2})
        assert b" " not in result

    def test_array_no_spaces(self):
        result = canonical_json([1, 2, 3])
        assert b" " not in result


class TestCanonicalComplex:
    """复杂结构（模拟 V2 协议真实数据）"""

    def test_aad_structure(self):
        aad = {
            "group_id": "g-abc.agentid.pub",
            "from": "alice.agentid.pub",
            "from_device": "dev-uuid-A",
            "message_id": "gm-550e8400",
            "timestamp": 1710504000000,
            "suite": "P256_HKDF_SHA256_AES_256_GCM",
            "epoch": 12,
            "state_commitment": "a" * 64,
            "wrap_protocol": "3DH",
        }
        result = canonical_json(aad)
        # 验证键排序
        parsed = json.loads(result)
        keys = list(json.loads(result).keys())
        assert keys == sorted(keys)
        # 验证无空格
        assert b" " not in result

    def test_recipients_row(self):
        row = [
            "bob.agentid.pub",
            "dev-uuid-1",
            "member",
            "group_device_prekey",
            "sha256:abcdef0123456789",
            "sha256:spkfp0123456789",
            "base64nonce12345",
            "base64wrappedkey",
        ]
        result = canonical_json(row)
        # 数组顺序保留
        assert b'"bob.agentid.pub"' in result

    def test_recipients_full(self):
        recipients = [
            ["alice.aid", "dev-1", "member", "group_device_prekey", "sha256:fp1", "sha256:spk1", "nonce1", "wrap1"],
            ["bob.aid", "dev-2", "member", "group_device", "sha256:fp2", "", "nonce2", "wrap2"],
            ["audit.aid", "", "audit", "aid_master", "sha256:fp3", "", "nonce3", "wrap3"],
        ]
        result = canonical_json(recipients)
        # 行按 (aid asc, device_id asc, role asc) 排序是调用方责任，canonical_json 只保留数组顺序
        assert result is not None
