"""
AUN E2EE V2: Canonical JSON 序列化

规范引用: §10.2
规则:
- 键递归字典序排序
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
    return str(n)


def _serialize_float(f: float) -> str:
    if math.isinf(f) or math.isnan(f):
        raise ValueError("canonical_json: Infinity and NaN not allowed")
    # 不使用科学计数法
    # 如果是整数值的 float（如 1.0），输出 "1.0" 还是 "1"？
    # JSON 规范中 1.0 和 1 是不同的 token。保留小数点。
    # 但如果值恰好是整数且无小数部分，Python repr 会输出 "1.0"
    # 我们用 repr 然后确保不含 'e'/'E'
    s = repr(f)
    if "e" in s or "E" in s:
        # 科学计数法 → 转为定点
        s = f"{f:.20f}".rstrip("0")
        if s.endswith("."):
            s += "0"
    return s


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
    # 键递归字典序排序
    sorted_keys = sorted(obj.keys())
    pairs = []
    for key in sorted_keys:
        if not isinstance(key, str):
            raise TypeError(f"canonical_json: dict key must be str, got {type(key).__name__}")
        pairs.append(_serialize_string(key) + ":" + _serialize(obj[key]))
    return "{" + ",".join(pairs) + "}"
