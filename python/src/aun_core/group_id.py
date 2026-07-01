"""
group_id/group_aid 兼容转换工具。

目标态群组主标识是 group_aid，格式为 ``{base}.{issuer}``。历史
``group_id`` 字段名继续保留，但旧函数名也返回 group_aid，不能再
返回 ``group.{issuer}/{base}``。
"""

from __future__ import annotations


def _trim_dots(value: str) -> str:
    return str(value or "").strip(".")


def convert_to_group_aid(raw: str, *, local_issuer: str = "") -> str:
    """把任意历史群标识转换为标准 group_aid。"""
    value = str(raw or "").strip().strip("/").lower()
    if not value:
        return ""

    if value.startswith("group.") and "/" in value:
        issuer_and_base = value[6:]
        domain, _, base_tail = issuer_and_base.partition("/")
        domain = _trim_dots(domain)
        base_tail = base_tail.strip("/")
        if "@" in base_tail:
            base, _, suffix_domain = base_tail.partition("@")
            base = _trim_dots(base)
            suffix_domain = _trim_dots(suffix_domain)
            if base and suffix_domain:
                merged = f"{suffix_domain}.{domain}" if domain else suffix_domain
                return f"{base}.{merged}"
        base = _trim_dots(base_tail)
        if base and domain:
            return f"{base}.{domain}"
        return value

    if "@" in value:
        base, _, domain = value.partition("@")
        base = _trim_dots(base)
        domain = _trim_dots(domain)
        if base and domain:
            return f"{base}.{domain}"
        return value

    if "." in value:
        return value

    issuer = _trim_dots(str(local_issuer or "").strip().lower())
    if issuer:
        return f"{value}.{issuer}"
    return value


def normalize_group_aid(raw: str, *, local_issuer: str = "") -> str:
    """目标态命名：返回标准 group_aid。"""
    return convert_to_group_aid(raw, local_issuer=local_issuer)


def normalize_group_id(raw: str, *, local_issuer: str = "") -> str:
    """兼容旧函数名：返回标准 group_aid。"""
    return convert_to_group_aid(raw, local_issuer=local_issuer)


def split_group_id(raw: str) -> tuple[str, str]:
    """返回 (base, issuer)。对旧格式输入也先转换为 group_aid。"""
    group_aid = convert_to_group_aid(raw)
    if "." not in group_aid:
        return group_aid.strip("."), ""
    base, _, domain = group_aid.partition(".")
    return base.strip("."), domain.strip(".")


def build_discovery_host(raw: str) -> str:
    """构造 federation 发现 host。群服务发现走 issuer 域。"""
    _base, domain = split_group_id(raw)
    return domain
