/**
 * AID 和 Group ID 格式校验工具。
 *
 * 确保发送到服务端的目标标识符符合 AUN 协议规范，拒绝不合法的格式。
 *
 * 与 Python SDK aun_core.validators 保持等价（零代码共享，仅规范对齐）。
 */

import { ValidationError } from './errors.js';

// AID name 规范：4-64 字符，仅 [a-z0-9_-]，首字符不为 -，不以 guest 开头
const AID_NAME_RE = /^[a-z0-9_][a-z0-9_-]{3,63}$/;

// Group ID 格式（基于服务端实际实现）
// Legacy 格式：g- 后接 4-32 位小写字母数字
const GROUP_ID_LEGACY_PATTERN = /^g-[a-z0-9]{4,32}$/;
// 新格式 base：5 位或更多小写字母数字
const GROUP_ID_NEW_BASE_PATTERN = /^[a-z0-9]{5,}$/;
// Group name 格式：4-64 字符，首字符 [a-z0-9]，可包含 _-
const GROUP_NAME_PATTERN = /^[a-z0-9][a-z0-9_-]{3,63}$/;

// 域名基本格式（简化版，不做完整 DNS 校验）
const DOMAIN_RE = /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/;

/**
 * 校验 AID 格式是否合法。
 *
 * 格式规范：{name}.{issuer}
 * - name: 4-64 字节，仅 [a-z0-9_-]，首字符不能是 -，不能以 guest 开头
 * - issuer: 合法的可注册域名
 *
 * @param aid 待校验的 AID（可能是任意类型）
 * @param paramName 参数名称（用于错误消息）
 * @returns 规范化后的 AID（转小写、去空格）
 * @throws ValidationError AID 格式不合法
 */
export function validateAIDFormat(aid: unknown, paramName = 'aid'): string {
  if (aid === null || aid === undefined || (typeof aid === 'string' && aid.trim() === '')) {
    throw new ValidationError(`${paramName} cannot be empty`);
  }

  const aidStr = String(aid).trim().toLowerCase();

  // 检查是否包含点号（必须有 issuer）
  if (!aidStr.includes('.')) {
    throw new ValidationError(
      `Invalid ${paramName} '${String(aid)}': must be in format '{name}.{issuer}'`,
    );
  }

  // 分离 name 和 issuer（仅在第一个点号处分割）
  const dotIdx = aidStr.indexOf('.');
  const name = aidStr.slice(0, dotIdx);
  const issuer = aidStr.slice(dotIdx + 1);

  // 校验 name 部分
  if (!name) {
    throw new ValidationError(`Invalid ${paramName} '${String(aid)}': name part cannot be empty`);
  }

  if (!AID_NAME_RE.test(name)) {
    throw new ValidationError(
      `Invalid ${paramName} '${String(aid)}': name '${name}' must be 4-64 characters, `
      + `only [a-z0-9_-], cannot start with '-'`,
    );
  }

  if (name.startsWith('guest')) {
    throw new ValidationError(
      `Invalid ${paramName} '${String(aid)}': name cannot start with 'guest'`,
    );
  }

  // 校验 issuer 部分
  if (!issuer) {
    throw new ValidationError(`Invalid ${paramName} '${String(aid)}': issuer part cannot be empty`);
  }

  if (!DOMAIN_RE.test(issuer)) {
    throw new ValidationError(
      `Invalid ${paramName} '${String(aid)}': issuer '${issuer}' is not a valid domain`,
    );
  }

  return aidStr;
}

/**
 * 校验 Group ID 格式是否合法。
 *
 * 接受的 base 格式（不含域名部分）：
 *   1. Legacy 格式：g-[a-z0-9]{4,32} — 以 g- 开头，后接 4 到 32 位小写字母或数字
 *   2. 新格式：[a-z0-9]{5,} — 5 位或更多小写字母或数字
 *   3. Group name 格式：[a-z0-9][a-z0-9_-]{3,63} — 4 到 64 个字符，可包含 _-
 *
 * 完整格式：
 *   - group.{issuer}/{base} (canonical)
 *   - {base}.{issuer} (旧格式)
 *   - {base}@{issuer} (兼容格式)
 *   - {base} (本域简写)
 *
 * @param groupId 待校验的 Group ID（可能是任意类型）
 * @param paramName 参数名称（用于错误消息）
 * @returns 规范化后的 Group ID（转小写、去空格）
 * @throws ValidationError Group ID 格式不合法
 */
export function validateGroupIDFormat(groupId: unknown, paramName = 'group_id'): string {
  if (
    groupId === null || groupId === undefined
    || (typeof groupId === 'string' && groupId.trim() === '')
  ) {
    throw new ValidationError(`${paramName} cannot be empty`);
  }

  const gidStr = String(groupId).trim().toLowerCase();

  // 解析 base 和 domain
  let base = '';
  let domain = '';

  const stripDots = (s: string): string => s.replace(/^\.+|\.+$/g, '');

  if (gidStr.startsWith('group.') && gidStr.includes('/')) {
    // 情况1: group.{issuer}/{base} (canonical)
    const issuerAndBase = gidStr.slice(6); // 去掉 "group."
    const slashIdx = issuerAndBase.indexOf('/');
    if (slashIdx >= 0) {
      domain = stripDots(issuerAndBase.slice(0, slashIdx));
      base = stripDots(issuerAndBase.slice(slashIdx + 1));
      // 处理污染格式 group.{A}/{base}@{B}
      if (base.includes('@')) {
        const atIdx = base.indexOf('@');
        const basePart = stripDots(base.slice(0, atIdx));
        const bDomain = stripDots(base.slice(atIdx + 1));
        base = basePart;
        domain = domain ? `${bDomain}.${domain}` : bDomain;
      }
    }
  } else if (gidStr.includes('@')) {
    // 情况2: {base}@{issuer}
    const atIdx = gidStr.indexOf('@');
    base = stripDots(gidStr.slice(0, atIdx));
    domain = stripDots(gidStr.slice(atIdx + 1));
  } else if (gidStr.includes('.')) {
    // 情况3: {base}.{issuer} 或 {base}（需要区分）
    if (gidStr.startsWith('g-')) {
      const rest = gidStr.slice(2);
      if (rest.includes('.')) {
        const dotIdx = rest.indexOf('.');
        const slug = rest.slice(0, dotIdx);
        domain = stripDots(rest.slice(dotIdx + 1));
        base = `g-${slug}`;
      } else {
        base = gidStr;
      }
    } else {
      // 简化处理：如果有点号就认为后面是域名
      const dotIdx = gidStr.indexOf('.');
      base = gidStr.slice(0, dotIdx);
      domain = stripDots(gidStr.slice(dotIdx + 1));
    }
  } else {
    // 情况4: 纯 {base}（本域简写）
    base = gidStr;
  }

  // 校验 base 部分
  if (!base) {
    throw new ValidationError(
      `Invalid ${paramName} '${String(groupId)}': base part cannot be empty`,
    );
  }

  // 检查 base 是否符合任一格式
  const isValidBase = (
    GROUP_ID_LEGACY_PATTERN.test(base)
    || GROUP_ID_NEW_BASE_PATTERN.test(base)
    || GROUP_NAME_PATTERN.test(base)
  );

  if (!isValidBase) {
    throw new ValidationError(
      `Invalid ${paramName} '${String(groupId)}': base '${base}' must be one of: `
      + `legacy format 'g-[a-z0-9]{4,32}', new format '[a-z0-9]{5,}', `
      + `or group name format '[a-z0-9][a-z0-9_-]{3,63}'`,
    );
  }

  // 如果有 domain，校验 domain 部分
  if (domain && !DOMAIN_RE.test(domain)) {
    throw new ValidationError(
      `Invalid ${paramName} '${String(groupId)}': domain '${domain}' is not a valid domain`,
    );
  }

  return gidStr;
}
