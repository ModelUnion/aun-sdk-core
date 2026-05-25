"""
AUN E2EE V2: Canonical JSON 序列化

规范引用: §10.2
规则:
- 键递归按 Unicode code point 排序
- UTF-8 直出（不转义非 ASCII）
- 数值无前导零、不科学计数法
- 字符串最小转义（仅 " \\ \\b \\f \\n \\r \\t，其它控制字符 \\u00XX）
- 无空格分隔（紧凑格式）
- null / true / false 字面
- 数组顺序保留（不排序）

输出: UTF-8 编码的 bytes
"""
from __future__ import annotations

import math

_MAX_SAFE_JSON_INTEGER = 9007199254740991


def canonical_json(obj) -> bytes:
    """将 Python 对象序列化为 Canonical JSON bytes。

    与标准 json.dumps 的区别：
    - 键递归排序
    - 无空格
    - UTF-8 直出（非 ASCII 不转义）
    - 数值不使用科学计数法
    - 控制字符用 \\uXXXX 转义
    """
    return _serialize(obj).encode("utf-8")


def _serialize(obj) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int) and not isinstance(obj, bool):
        return _serialize_int(obj)
    if isinstance(obj, float):
        return _serialize_float(obj)
    if isinstance(obj, str):
        return _serialize_string(obj)
    if isinstance(obj, (list, tuple)):
        return _serialize_array(obj)
    if isinstance(obj, dict):
        return _serialize_object(obj)
    raise TypeError(f"canonical_json: unsupported type {type(obj).__name__}")


def _serialize_int(n: int) -> str:
    if abs(n) > _MAX_SAFE_JSON_INTEGER:
        raise ValueError(f"canonical_json: integer outside safe range {n}")
    return str(n)


def _serialize_float(f: float) -> str:
    if math.isinf(f) or math.isnan(f):
        raise ValueError("canonical_json: Infinity and NaN not allowed")
    if f == 0:
        return "0"
    # 与 JS/TS 收敛：整数值 float 统一为整数 token。
    if f.is_integer():
        i = int(f)
        if abs(i) > _MAX_SAFE_JSON_INTEGER:
            raise ValueError(f"canonical_json: integer outside safe range {i}")
        return str(i)

    s = repr(f)
    if "e" in s or "E" in s:
        s = _expand_exponent(s)
    return s


def _expand_exponent(s: str) -> str:
    mantissa, exp_text = s.lower().split("e", 1)
    exp = int(exp_text)
    sign = ""
    if mantissa.startswith("-"):
        sign = "-"
        mantissa = mantissa[1:]
    if "." in mantissa:
        int_part, frac_part = mantissa.split(".", 1)
    else:
        int_part, frac_part = mantissa, ""
    digits = int_part + frac_part
    point = len(int_part) + exp
    if point <= 0:
        return sign + "0." + ("0" * (-point)) + digits
    if point >= len(digits):
        return sign + digits + ("0" * (point - len(digits)))
    return sign + digits[:point] + "." + digits[point:]


def _serialize_string(s: str) -> str:
    parts = ['"']
    for ch in s:
        code = ord(ch)
        if ch == '"':
            parts.append('\\"')
        elif ch == '\\':
            parts.append('\\\\')
        elif ch == '\b':
            parts.append('\\b')
        elif ch == '\f':
            parts.append('\\f')
        elif ch == '\n':
            parts.append('\\n')
        elif ch == '\r':
            parts.append('\\r')
        elif ch == '\t':
            parts.append('\\t')
        elif code < 0x20:
            # 其它控制字符用 \u00XX
            parts.append(f"\\u{code:04x}")
        else:
            # 非 ASCII 直出（UTF-8 直出）
            parts.append(ch)
    parts.append('"')
    return "".join(parts)


def _serialize_array(arr) -> str:
    items = [_serialize(item) for item in arr]
    return "[" + ",".join(items) + "]"


def _serialize_object(obj: dict) -> str:
    # Python 字符串排序按 Unicode code point，与 TS/JS/C++ canonical 规则一致。
    sorted_keys = sorted(obj.keys())
    pairs = []
    for key in sorted_keys:
        if not isinstance(key, str):
            raise TypeError(f"canonical_json: dict key must be str, got {type(key).__name__}")
        pairs.append(_serialize_string(key) + ":" + _serialize(obj[key]))
    return "{" + ",".join(pairs) + "}"
