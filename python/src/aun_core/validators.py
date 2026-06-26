"""
AID 和 Group ID 格式校验工具。

确保发送到服务端的目标标识符符合 AUN 协议规范，拒绝不合法的格式。
"""

from __future__ import annotations

import re
from typing import Any

from .errors import ValidationError


# AID name 规范：4-64 字符，仅 [a-z0-9_-]，首字符不为 -，不以 guest 开头
_AID_NAME_RE = re.compile(r'^[a-z0-9_][a-z0-9_-]{3,63}$')

# Group ID 格式（基于服务端实际实现）
# Legacy 格式：g- 后接 4-32 位小写字母数字
_GROUP_ID_LEGACY_PATTERN = re.compile(r'^g-[a-z0-9]{4,32}$')
# 新格式 base：5 位或更多小写字母数字
_GROUP_ID_NEW_BASE_PATTERN = re.compile(r'^[a-z0-9]{5,}$')
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


def validate_group_id_format(group_id: Any, *, param_name: str = "group_id") -> str:
    """
    校验 Group ID 格式是否合法。

    接受的 base 格式（不含域名部分）：
    1. Legacy 格式：g-[a-z0-9]{4,32} — 以 g- 开头，后接 4 到 32 位小写字母或数字
    2. 新格式：[a-z0-9]{5,} — 5 位或更多小写字母或数字
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
    if group_id is None or (isinstance(group_id, str) and not group_id.strip()):
        raise ValidationError(f"{param_name} cannot be empty")

    gid_str = str(group_id).strip().lower()

    # 解析 base 和 domain
    base = ""
    domain = ""

    # 情况1: group.{issuer}/{base} (canonical)
    if gid_str.startswith("group.") and "/" in gid_str:
        issuer_and_base = gid_str[6:]  # 去掉 "group."
        parts = issuer_and_base.split("/", 1)
        if len(parts) == 2:
            domain, base = parts[0].strip("."), parts[1].strip(".")
            # 处理污染格式 group.{A}/{base}@{B}
            if "@" in base:
                base_part, _, b_domain = base.partition("@")
                base = base_part.strip(".")
                domain = f"{b_domain.strip('.')}.{domain}" if domain else b_domain.strip(".")
    # 情况2: {base}@{issuer}
    elif "@" in gid_str:
        base, _, domain = gid_str.partition("@")
        base = base.strip(".")
        domain = domain.strip(".")
    # 情况3: {base}.{issuer} 或 {base} (需要区分)
    elif "." in gid_str:
        # 如果是 g- 开头，点号后是域名
        if gid_str.startswith("g-"):
            rest = gid_str[2:]
            if "." in rest:
                slug, _, domain = rest.partition(".")
                base = f"g-{slug}"
                domain = domain.strip(".")
            else:
                base = gid_str
        else:
            # 尝试判断是 {base}.{domain} 还是单个 base
            # 这里简化处理：如果有点号就认为后面是域名
            parts = gid_str.split(".", 1)
            if len(parts) == 2:
                base, domain = parts[0], parts[1].strip(".")
            else:
                base = gid_str
    else:
        # 情况4: 纯 {base}（本域简写）
        base = gid_str

    # 校验 base 部分
    if not base:
        raise ValidationError(f"Invalid {param_name} '{group_id}': base part cannot be empty")

    # 检查 base 是否符合任一格式
    is_valid_base = (
        _GROUP_ID_LEGACY_PATTERN.fullmatch(base) or
        _GROUP_ID_NEW_BASE_PATTERN.fullmatch(base) or
        _GROUP_NAME_PATTERN.fullmatch(base)
    )

    if not is_valid_base:
        raise ValidationError(
            f"Invalid {param_name} '{group_id}': base '{base}' must be one of: "
            f"legacy format 'g-[a-z0-9]{{4,32}}', new format '[a-z0-9]{{5,}}', "
            f"or group name format '[a-z0-9][a-z0-9_-]{{3,63}}'"
        )

    # 如果有 domain，校验 domain 部分
    if domain:
        if not _DOMAIN_RE.match(domain):
            raise ValidationError(
                f"Invalid {param_name} '{group_id}': domain '{domain}' is not a valid domain"
            )

    return gid_str


__all__ = [
    "validate_aid_format",
    "validate_group_id_format",
]
