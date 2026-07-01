/**
 * group_id/group_aid 兼容转换工具。
 *
 * 目标态群组主标识是 group_aid，格式为 `{base}.{issuer}`。
 * 历史 group_id 字段名继续保留，但旧函数名也返回 group_aid。
 */

function trimDots(value: string): string {
  return value.replace(/^\.+|\.+$/g, '');
}

export function convertToGroupAid(raw: unknown, opts?: { localIssuer?: string }): string {
  const value = String(raw ?? '').trim().replace(/^\/+|\/+$/g, '').toLowerCase();
  if (!value) return '';

  if (value.startsWith('group.') && value.includes('/')) {
    const issuerAndBase = value.slice(6);
    const slashIdx = issuerAndBase.indexOf('/');
    if (slashIdx > 0 && slashIdx < issuerAndBase.length - 1) {
      const domain = trimDots(issuerAndBase.slice(0, slashIdx));
      const baseTail = issuerAndBase.slice(slashIdx + 1).replace(/^\/+|\/+$/g, '');
      if (baseTail.includes('@')) {
        const atIdx = baseTail.indexOf('@');
        const base = trimDots(baseTail.slice(0, atIdx));
        const suffixDomain = trimDots(baseTail.slice(atIdx + 1));
        if (base && suffixDomain) {
          const merged = domain ? `${suffixDomain}.${domain}` : suffixDomain;
          return `${base}.${merged}`;
        }
      }
      const base = trimDots(baseTail);
      if (base && domain) return `${base}.${domain}`;
      return value;
    }
    return value;
  }

  if (value.includes('@')) {
    const atIdx = value.indexOf('@');
    const base = trimDots(value.slice(0, atIdx));
    const domain = trimDots(value.slice(atIdx + 1));
    if (base && domain) return `${base}.${domain}`;
    return value;
  }

  if (value.includes('.')) return value;

  const localIssuer = trimDots((opts?.localIssuer ?? '').trim().toLowerCase());
  if (localIssuer) return `${value}.${localIssuer}`;
  return value;
}

export function normalizeGroupAid(raw: unknown, opts?: { localIssuer?: string }): string {
  return convertToGroupAid(raw, opts);
}

export function normalizeGroupId(raw: unknown, opts?: { localIssuer?: string }): string {
  return convertToGroupAid(raw, opts);
}

export function splitGroupId(raw: unknown): { base: string; domain: string } {
  const groupAid = convertToGroupAid(raw);
  const dotIdx = groupAid.indexOf('.');
  if (dotIdx > 0) {
    return {
      base: trimDots(groupAid.slice(0, dotIdx)),
      domain: trimDots(groupAid.slice(dotIdx + 1)),
    };
  }
  return { base: trimDots(groupAid), domain: '' };
}

export function buildDiscoveryHost(raw: unknown): string {
  const { domain } = splitGroupId(raw);
  return domain;
}
