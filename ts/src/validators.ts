/**
 * AID 和 Group ID 格式校验工具。
 *
 * 确保发送到服务端的目标标识符符合 AUN 协议规范，拒绝不合法的格式。
 */

import { ValidationError } from './errors.js';

// AID name 规范：4-64 字符，仅 [a-z0-9_-]，首字符不为 -，不以 guest 开头
// 注意：{3,63} 表示后续3-63个字符，加上首字符共4-64个
const AID_NAME_RE = /^[a-z0-9_][a-z0-9_-]{2,62}$/;

// Group ID 格式（基于服务端实际实现）
// Legacy 格式：g- 后接 4-32 位小写字母数字
const GROUP_ID_LEGACY_PATTERN = /^g-[a-z0-9]{4,32}$/;
// 新格式 base：5 位或更多小写字母数字
const GROUP_ID_NEW_BASE_PATTERN = /^[a-z0-9]{5,}$/;
// Group name 格式：4-64 字符，首字符 [a-z0-9]，可包含 _-
const GROUP_NAME_PATTERN = /^[a-z0-9][a-z0-9_-]{3,63}$/;

// 域名基本格式（简化版，不做完整 DNS 校验）
// 不能以点号或连字符开头/结尾
const DOMAIN_RE = /^[a-z0-9]+([a-z0-9._-]*[a-z0-9]+)?$/;

/**
 * 校验 AID 格式是否合法。
 *
 * 格式规范：{name}.{issuer}
 * - name: 4-64 字节，仅 [a-z0-9_-]，首字符不能是 -，不能以 guest 开头
 * - issuer: 合法的可注册域名
 *
 * @param aid 待校验的 AID
 * @param paramName 参数名称（用于错误消息）
 * @returns 规范化后的 AID（转小写、去空格）
 * @throws ValidationError AID 格式不合法
 */
export function validateAIDFormat(aid: unknown, paramName = 'aid'): string {
  if (aid === null || aid === undefined || (typeof aid === 'string' && !aid.trim())) {
    throw new ValidationError(`${paramName} cannot be empty`);
  }

  const aidStr = String(aid).trim().toLowerCase();

  // 检查是否包含点号（必须有 issuer）
  if (!aidStr.includes('.')) {
    throw new ValidationError(
      `Invalid ${paramName} '${aid}': must be in format '{name}.{issuer}'`
    );
  }

  // 分离 name 和 issuer
  const dotIndex = aidStr.indexOf('.');
  if (dotIndex === -1 || dotIndex === 0 || dotIndex === aidStr.length - 1) {
    throw new ValidationError(
      `Invalid ${paramName} '${aid}': must be in format '{name}.{issuer}'`
    );
  }

  const name = aidStr.substring(0, dotIndex);
  const issuer = aidStr.substring(dotIndex + 1);

  // 校验 name 部分
  if (!name) {
    throw new ValidationError(`Invalid ${paramName} '${aid}': name part cannot be empty`);
  }

  if (!AID_NAME_RE.test(name)) {
    throw new ValidationError(
      `Invalid ${paramName} '${aid}': name '${name}' must be 4-64 characters, ` +
      `only [a-z0-9_-], cannot start with '-'`
    );
  }

  if (name.startsWith('guest')) {
    throw new ValidationError(
      `Invalid ${paramName} '${aid}': name cannot start with 'guest'`
    );
  }

  // 校验 issuer 部分
  if (!issuer) {
    throw new ValidationError(`Invalid ${paramName} '${aid}': issuer part cannot be empty`);
  }

  if (!DOMAIN_RE.test(issuer)) {
    throw new ValidationError(
      `Invalid ${paramName} '${aid}': issuer '${issuer}' is not a valid domain`
    );
  }

  return aidStr;
}

/**
 * 校验 Group ID 格式是否合法。
 *
 * 接受的 base 格式（不含域名部分）：
 * 1. Legacy 格式：g-[a-z0-9]{4,32} — 以 g- 开头，后接 4 到 32 位小写字母或数字
 * 2. 新格式：[a-z0-9]{5,} — 5 位或更多小写字母或数字
 * 3. Group name 格式：[a-z0-9][a-z0-9_-]{3,63} — 4 到 64 个字符，可包含 _-
 *
 * 完整格式：
 * - group.{issuer}/{base} (canonical)
 * - {base}.{issuer} (旧格式)
 * - {base}@{issuer} (兼容格式)
 * - {base} (本域简写)
 *
 * @param groupId 待校验的 Group ID
 * @param paramName 参数名称（用于错误消息）
 * @returns 规范化后的 Group ID（转小写、去空格）
 * @throws ValidationError Group ID 格式不合法
 */
export function validateGroupIDFormat(groupId: unknown, paramName = 'group_id'): string {
  if (groupId === null || groupId === undefined || (typeof groupId === 'string' && !groupId.trim())) {
    throw new ValidationError(`${paramName} cannot be empty`);
  }

  const gidStr = String(groupId).trim().toLowerCase();

  // 解析 base 和 domain
  let base = '';
  let domain = '';

  // 情况1: group.{issuer}/{base} (canonical)
  if (gidStr.startsWith('group.') && gidStr.includes('/')) {
    const issuerAndBase = gidStr.substring(6); // 去掉 "group."
    const slashIndex = issuerAndBase.indexOf('/');
    if (slashIndex !== -1) {
      domain = issuerAndBase.substring(0, slashIndex).replace(/^\.+|\.+$/g, '');
      base = issuerAndBase.substring(slashIndex + 1).replace(/^\.+|\.+$/g, '');
      // 处理污染格式 group.{A}/{base}@{B}
      if (base.includes('@')) {
        const atIndex = base.indexOf('@');
        const basePart = base.substring(0, atIndex).replace(/^\.+|\.+$/g, '');
        const bDomain = base.substring(atIndex + 1).replace(/^\.+|\.+$/g, '');
        base = basePart;
        domain = domain ? `${bDomain}.${domain}` : bDomain;
      }
    }
  }
  // 情况2: {base}@{issuer}
  else if (gidStr.includes('@')) {
    const atIndex = gidStr.indexOf('@');
    base = gidStr.substring(0, atIndex).replace(/^\.+|\.+$/g, '');
    domain = gidStr.substring(atIndex + 1).replace(/^\.+|\.+$/g, '');
  }
  // 情况3: {base}.{issuer} 或 {base} (需要区分)
  else if (gidStr.includes('.')) {
    // 如果是 g- 开头，点号后是域名
    if (gidStr.startsWith('g-')) {
      const rest = gidStr.substring(2);
      if (rest.includes('.')) {
        const dotIndex = rest.indexOf('.');
        const slug = rest.substring(0, dotIndex);
        base = `g-${slug}`;
        domain = rest.substring(dotIndex + 1).replace(/^\.+|\.+$/g, '');
      } else {
        base = gidStr;
      }
    } else {
      // 尝试判断是 {base}.{domain} 还是单个 base
      // 这里简化处理：如果有点号就认为后面是域名
      const dotIndex = gidStr.indexOf('.');
      base = gidStr.substring(0, dotIndex);
      domain = gidStr.substring(dotIndex + 1).replace(/^\.+|\.+$/g, '');
    }
  } else {
    // 情况4: 纯 {base}（本域简写）
    base = gidStr;
  }

  // 校验 base 部分
  if (!base) {
    throw new ValidationError(`Invalid ${paramName} '${groupId}': base part cannot be empty`);
  }

  // 检查 base 是否符合任一格式
  const isValidBase =
    GROUP_ID_LEGACY_PATTERN.test(base) ||
    GROUP_ID_NEW_BASE_PATTERN.test(base) ||
    GROUP_NAME_PATTERN.test(base);

  if (!isValidBase) {
    throw new ValidationError(
      `Invalid ${paramName} '${groupId}': base '${base}' must be one of: ` +
      `legacy format 'g-[a-z0-9]{4,32}', new format '[a-z0-9]{5,}', ` +
      `or group name format '[a-z0-9][a-z0-9_-]{3,63}'`
    );
  }

  // 如果有 domain，校验 domain 部分
  if (domain) {
    if (!DOMAIN_RE.test(domain)) {
      throw new ValidationError(
        `Invalid ${paramName} '${groupId}': domain '${domain}' is not a valid domain`
      );
    }
  }

  return gidStr;
}
