"""
AID 和 Group ID 格式校验工具。

确保发送到服务端的目标标识符符合 AUN 协议规范，拒绝不合法的格式。
"""

from __future__ import annotations

import re
from typing import Any

from .errors import ValidationError
from .group_id import convert_to_group_aid


# AID name 规范：4-64 字符，仅 [a-z0-9_-]，首字符不为 -，不以 guest 开头
_AID_NAME_RE = re.compile(r'^[a-z0-9_][a-z0-9_-]{3,63}$')

# Group ID 格式（基于服务端实际实现）
# Legacy 格式：g- 后接 4-32 位小写字母数字
_GROUP_ID_LEGACY_PATTERN = re.compile(r'^g-[a-z0-9]{4,32}$')
# 新格式 base：5 到 64 位小写字母数字
_GROUP_ID_NEW_BASE_PATTERN = re.compile(r'^[a-z0-9]{5,64}$')
# Group name 格式：4-64 字符，首字符 [a-z0-9]，可包含 _-
_GROUP_NAME_PATTERN = re.compile(r'^[a-z0-9][a-z0-9_-]{3,63}$')

# 域名基本格式（简化版，不做完整 DNS 校验）
_DOMAIN_RE = re.compile(r'^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$')


def validate_aid_format(aid: Any, *, param_name: str = "aid") -> str:
    """
    校验 AID 格式是否合法。

    格式规范：{name}.{issuer}
    - name: 4-64 字节，仅 [a-z0-9_-]，首字符不能是 -，不能以 guest 开头
    - issuer: 合法的可注册域名

    Args:
        aid: 待校验的 AID（可能是任意类型）
        param_name: 参数名称（用于错误消息）

    Returns:
        规范化后的 AID（转小写、去空格）

    Raises:
        ValidationError: AID 格式不合法
    """
    if aid is None or (isinstance(aid, str) and not aid.strip()):
        raise ValidationError(f"{param_name} cannot be empty")

    aid_str = str(aid).strip().lower()

    # 检查是否包含点号（必须有 issuer）
    if "." not in aid_str:
        raise ValidationError(
            f"Invalid {param_name} '{aid}': must be in format '{{name}}.{{issuer}}'"
        )

    # 分离 name 和 issuer
    parts = aid_str.split(".", 1)
    if len(parts) != 2:
        raise ValidationError(
            f"Invalid {param_name} '{aid}': must be in format '{{name}}.{{issuer}}'"
        )

    name, issuer = parts

    # 校验 name 部分
    if not name:
        raise ValidationError(f"Invalid {param_name} '{aid}': name part cannot be empty")

    if not _AID_NAME_RE.match(name):
        raise ValidationError(
            f"Invalid {param_name} '{aid}': name '{name}' must be 4-64 characters, "
            f"only [a-z0-9_-], cannot start with '-'"
        )

    if name.startswith("guest"):
        raise ValidationError(
            f"Invalid {param_name} '{aid}': name cannot start with 'guest'"
        )

    # 校验 issuer 部分
    if not issuer:
        raise ValidationError(f"Invalid {param_name} '{aid}': issuer part cannot be empty")

    if not _DOMAIN_RE.match(issuer):
        raise ValidationError(
            f"Invalid {param_name} '{aid}': issuer '{issuer}' is not a valid domain"
        )

    return aid_str


def _validate_group_aid_parts(raw: Any, group_aid: str, *, param_name: str) -> None:
    """校验转换后的 group_aid 中的 base 和 issuer。"""
    base = ""
    domain = ""

    if "." in group_aid:
        base, _, domain = group_aid.partition(".")
        base = base.strip(".")
        domain = domain.strip(".")
    else:
        base = group_aid

    if not base:
        raise ValidationError(f"Invalid {param_name} '{raw}': base part cannot be empty")

    is_valid_base = (
        _GROUP_ID_LEGACY_PATTERN.fullmatch(base) or
        _GROUP_ID_NEW_BASE_PATTERN.fullmatch(base) or
        _GROUP_NAME_PATTERN.fullmatch(base)
    )

    if not is_valid_base:
        raise ValidationError(
            f"Invalid {param_name} '{raw}': base '{base}' must be one of: "
            f"legacy format 'g-[a-z0-9]{{4,32}}', new format '[a-z0-9]{{5,64}}', "
            f"or group name format '[a-z0-9][a-z0-9_-]{{3,63}}'"
        )

    if domain and not _DOMAIN_RE.match(domain):
        raise ValidationError(
            f"Invalid {param_name} '{raw}': domain '{domain}' is not a valid domain"
        )


def validate_group_aid_format(
    group_aid: Any,
    *,
    param_name: str = "group_aid",
    local_issuer: str = "",
) -> str:
    """
    校验群组标识并返回目标态 group_aid。

    兼容历史输入格式：``group.{issuer}/{base}``、``{base}@{issuer}``、
    ``{base}.{issuer}`` 和本域短格式。短格式只有在传入 ``local_issuer``
    时才会补齐 issuer。
    """
    if group_aid is None or (isinstance(group_aid, str) and not group_aid.strip()):
        raise ValidationError(f"{param_name} cannot be empty")

    raw_text = str(group_aid).strip()
    if "//" in raw_text:
        raise ValidationError(f"Invalid {param_name} '{group_aid}': empty path segment is not allowed")

    group_aid_str = convert_to_group_aid(raw_text, local_issuer=local_issuer)
    if not group_aid_str:
        raise ValidationError(f"{param_name} cannot be empty")

    _validate_group_aid_parts(group_aid, group_aid_str, param_name=param_name)
    return group_aid_str


def validate_group_id_format(
    group_id: Any,
    *,
    param_name: str = "group_id",
    local_issuer: str = "",
) -> str:
    """
    校验 Group ID 格式是否合法。

    接受的 base 格式（不含域名部分）：
    1. Legacy 格式：g-[a-z0-9]{4,32} — 以 g- 开头，后接 4 到 32 位小写字母或数字
    2. 新格式：[a-z0-9]{5,64} — 5 到 64 位小写字母或数字
    3. Group name 格式：[a-z0-9][a-z0-9_-]{3,63} — 4 到 64 个字符，可包含 _-

    完整格式：
    - group.{issuer}/{base} (canonical)
    - {base}.{issuer} (旧格式)
    - {base}@{issuer} (兼容格式)
    - {base} (本域简写)

    Args:
        group_id: 待校验的 Group ID（可能是任意类型）
        param_name: 参数名称（用于错误消息）

    Returns:
        规范化后的 Group ID（转小写、去空格）

    Raises:
        ValidationError: Group ID 格式不合法
    """
    return validate_group_aid_format(
        group_id,
        param_name=param_name,
        local_issuer=local_issuer,
    )


__all__ = [
    "validate_aid_format",
    "validate_group_aid_format",
    "validate_group_id_format",
]
