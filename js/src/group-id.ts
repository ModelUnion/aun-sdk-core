/**
 * group_id 归一化工具。
 *
 * AUN 协议规定的 canonical 格式为 `group.{domain}/{base}`。
 *
 * 历史上出现过四种老/脏格式：
 *   1. {base}.{domain}            例如 g-xxx.agentid.pub / 10086.agentid.pub
 *   2. g-{slug}.{domain}          （属于 1 的一种）
 *   3. {base}@{domain}            例如 g-xxx@agentid.pub
 *   4. group.{A}/{base}@{B}       旧版服务端迁移脚本未识别 @ 导致的污染数据
 *                                 真实语义：group.{B}.{A}/{base}
 *
 * 与 Python SDK aun_core.group_id 和服务端
 * extensions/services/group/service._split_group_id_domain 保持等价，零代码共享。
 */

export function normalizeGroupId(raw: unknown, opts?: { localIssuer?: string }): string {
  const value = String(raw ?? '').trim().toLowerCase();
  if (!value) return '';

  // 情况 4：已迁移但 base 位置残留 @issuer 尾巴
  if (value.startsWith('group.') && value.includes('/')) {
    const issuerAndBase = value.slice(6);
    const slashIdx = issuerAndBase.indexOf('/');
    if (slashIdx > 0 && slashIdx < issuerAndBase.length - 1) {
      const aDomain = issuerAndBase.slice(0, slashIdx).replace(/^\.+|\.+$/g, '');
      const baseTail = issuerAndBase.slice(slashIdx + 1);
      if (baseTail.includes('@')) {
        const atIdx = baseTail.indexOf('@');
        const base = baseTail.slice(0, atIdx).replace(/^\.+|\.+$/g, '');
        const bDomain = baseTail.slice(atIdx + 1).replace(/^\.+|\.+$/g, '');
        if (base && bDomain) {
          const merged = aDomain ? `${bDomain}.${aDomain}` : bDomain;
          return `group.${merged}/${base}`;
        }
      }
      return aDomain
        ? `group.${aDomain}/${baseTail.replace(/^\.+|\.+$/g, '')}`
        : value;
    }
    return value;
  }

  // 情况 3：base@domain / g-{slug}@domain
  if (value.includes('@')) {
    const atIdx = value.indexOf('@');
    const base = value.slice(0, atIdx).replace(/^\.+|\.+$/g, '');
    const domain = value.slice(atIdx + 1).replace(/^\.+|\.+$/g, '');
    if (base && domain) return `group.${domain}/${base}`;
    return value;
  }

  // 情况 1/2：base.domain / g-{slug}.domain
  const localIssuer = (opts?.localIssuer ?? '').trim().replace(/^\.+|\.+$/g, '').toLowerCase();
  if (value.startsWith('g-')) {
    const rest = value.slice(2);
    const dotIdx = rest.indexOf('.');
    if (dotIdx > 0) {
      const slug = rest.slice(0, dotIdx);
      const domain = rest.slice(dotIdx + 1).replace(/^\.+|\.+$/g, '');
      if (slug && domain) return `group.${domain}/g-${slug}`;
    }
    if (localIssuer) return `group.${localIssuer}/g-${rest}`;
    return value;
  }
  const dotIdx = value.indexOf('.');
  if (dotIdx > 0) {
    const base = value.slice(0, dotIdx);
    const domain = value.slice(dotIdx + 1).replace(/^\.+|\.+$/g, '');
    if (base && domain) return `group.${domain}/${base}`;
  }
  if (localIssuer) return `group.${localIssuer}/${value}`;
  return value;
}

export function splitGroupId(raw: unknown): { base: string; domain: string } {
  const canonical = normalizeGroupId(raw);
  if (canonical.startsWith('group.') && canonical.includes('/')) {
    const issuerAndBase = canonical.slice(6);
    const slashIdx = issuerAndBase.indexOf('/');
    const domain = issuerAndBase.slice(0, slashIdx).replace(/^\.+|\.+$/g, '');
    const base = issuerAndBase.slice(slashIdx + 1).replace(/^\.+|\.+$/g, '');
    return { base, domain };
  }
  return { base: canonical.replace(/^\.+|\.+$/g, ''), domain: '' };
}

export function buildDiscoveryHost(raw: unknown): string {
  const { base, domain } = splitGroupId(raw);
  if (!base || !domain) return '';
  return `${base}.${domain}`;
}
