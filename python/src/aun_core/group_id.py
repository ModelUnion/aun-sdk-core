"""
group_id 归一化工具。

AUN 协议规定的 canonical 格式为 `group.{domain}/{base}`，例如
`group.agentid.pub/g-xxxx`、`group.agentid.pub/10086`。

历史上出现过四种老/脏格式：
  1. {base}.{domain}            例如 g-xxx.agentid.pub / 10086.agentid.pub
  2. g-{slug}.{domain}          （属于 1 的一种）
  3. {base}@{domain}            例如 g-xxx@agentid.pub
  4. group.{A}/{base}@{B}       旧版服务端迁移脚本未识别 @ 导致的污染数据
                                真实语义：group.{B}.{A}/{base}

此模块与服务端 group.service._split_group_id_domain /
extensions/services/group/repository._canonicalize_group_id 的逻辑保持等价，
但零代码共享（各语言 SDK 自行实现）。
"""

from __future__ import annotations


def normalize_group_id(raw: str, *, local_issuer: str = "") -> str:
    """把任意历史格式 group_id 归一化为 canonical 形式。

    local_issuer 不为空时，对无域前缀的本域简写 ("abc12"、"g-xxx") 补全为
    group.{local_issuer}/{base}；为空时原样返回。
    空串原样返回空串。
    """
    value = str(raw or "").strip().lower()
    if not value:
        return ""

    # 情况 4：已迁移但 base 位置残留 @issuer 尾巴 → 以 @ 右侧为最终 domain 还原
    if value.startswith("group.") and "/" in value:
        issuer_and_base = value[6:]
        parts = issuer_and_base.split("/", 1)
        if len(parts) == 2 and parts[0] and parts[1]:
            a_domain = parts[0].strip(".")
            base_tail = parts[1]
            if "@" in base_tail:
                base, _, b_domain = base_tail.partition("@")
                base = base.strip(".")
                b_domain = b_domain.strip(".")
                if base and b_domain:
                    merged = f"{b_domain}.{a_domain}" if a_domain else b_domain
                    return f"group.{merged}/{base}"
            return f"group.{a_domain}/{base_tail.strip('.')}" if a_domain else value
        return value

    # 情况 3：base@domain / g-{slug}@domain
    if "@" in value:
        base, _, domain = value.partition("@")
        base = base.strip(".")
        domain = domain.strip(".")
        if base and domain:
            return f"group.{domain}/{base}"
        return value

    # 情况 1/2：base.domain / g-{slug}.domain
    if value.startswith("g-"):
        rest = value[2:]
        slug, _, domain = rest.partition(".")
        if slug and domain:
            return f"group.{domain.strip('.')}/g-{slug}"
        # 无域后缀
        issuer = (local_issuer or "").strip().strip(".").lower()
        if issuer:
            return f"group.{issuer}/g-{slug}" if slug else value
        return value
    base, _, domain = value.partition(".")
    if base and domain:
        return f"group.{domain.strip('.')}/{base}"
    # 无域后缀
    issuer = (local_issuer or "").strip().strip(".").lower()
    if issuer and base:
        return f"group.{issuer}/{base}"
    return value


def split_group_id(raw: str) -> tuple[str, str]:
    """返回 (base, domain)。对污染格式也能还原出正确 (base, domain)。"""
    canonical = normalize_group_id(raw)
    if canonical.startswith("group.") and "/" in canonical:
        issuer_and_base = canonical[6:]
        domain, _, base = issuer_and_base.partition("/")
        return base.strip("."), domain.strip(".")
    # 无域兜底
    return canonical.strip("."), ""


def build_discovery_host(raw: str) -> str:
    """构造 federation 发现 host：{base}.{domain}。

    group.agentid.pub/g-xxx  → g-xxx.agentid.pub
    group.agentid.pub/10086  → 10086.agentid.pub
    空或无域时返回空串。
    """
    base, domain = split_group_id(raw)
    if not base or not domain:
        return ""
    return f"{base}.{domain}"
