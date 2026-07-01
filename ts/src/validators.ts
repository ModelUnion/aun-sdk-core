/**
 * AID 和 Group ID 格式校验工具。
 *
 * 确保发送到服务端的目标标识符符合 AUN 协议规范，拒绝不合法的格式。
 */

import { ValidationError } from './errors.js';
import { convertToGroupAid } from './group-id.js';

// AID name 规范：4-64 字符，仅 [a-z0-9_-]，首字符不为 -，不以 guest 开头
// 注意：{3,63} 表示后续3-63个字符，加上首字符共4-64个
const AID_NAME_RE = /^[a-z0-9_][a-z0-9_-]{3,63}$/;

// Group ID 格式（基于服务端实际实现）
// Legacy 格式：g- 后接 4-32 位小写字母数字
const GROUP_ID_LEGACY_PATTERN = /^g-[a-z0-9]{4,32}$/;
// 新格式 base：5 到 64 位小写字母数字
const GROUP_ID_NEW_BASE_PATTERN = /^[a-z0-9]{5,64}$/;
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

export interface GroupAIDValidationOptions {
  localIssuer?: string;
  paramName?: string;
}

function resolveGroupValidationArgs(
  defaultParamName: string,
  paramNameOrOptions?: string | GroupAIDValidationOptions,
  maybeOptions?: GroupAIDValidationOptions,
): { paramName: string; localIssuer: string } {
  if (typeof paramNameOrOptions === 'string') {
    return {
      paramName: paramNameOrOptions || defaultParamName,
      localIssuer: maybeOptions?.localIssuer ?? '',
    };
  }

  return {
    paramName: paramNameOrOptions?.paramName ?? defaultParamName,
    localIssuer: paramNameOrOptions?.localIssuer ?? '',
  };
}

function validateGroupAidParts(raw: unknown, groupAid: string, paramName: string): void {
  const dotIndex = groupAid.indexOf('.');
  const base = dotIndex >= 0 ? groupAid.substring(0, dotIndex).replace(/^\.+|\.+$/g, '') : groupAid;
  const domain = dotIndex >= 0 ? groupAid.substring(dotIndex + 1).replace(/^\.+|\.+$/g, '') : '';

  if (!base) {
    throw new ValidationError(`Invalid ${paramName} '${groupAid}': base part cannot be empty`);
  }

  const isValidBase =
    GROUP_ID_LEGACY_PATTERN.test(base) ||
    GROUP_ID_NEW_BASE_PATTERN.test(base) ||
    GROUP_NAME_PATTERN.test(base);

  if (!isValidBase) {
    throw new ValidationError(
      `Invalid ${paramName} '${raw}': base '${base}' must be one of: ` +
      `legacy format 'g-[a-z0-9]{4,32}', new format '[a-z0-9]{5,64}', ` +
      `or group name format '[a-z0-9][a-z0-9_-]{3,63}'`
    );
  }

  if (domain && !DOMAIN_RE.test(domain)) {
    throw new ValidationError(
      `Invalid ${paramName} '${raw}': domain '${domain}' is not a valid domain`
    );
  }
}

/**
 * 校验群组标识并返回目标态 group_aid。
 */
export function validateGroupAIDFormat(
  groupId: unknown,
  paramNameOrOptions: string | GroupAIDValidationOptions = 'group_aid',
  maybeOptions?: GroupAIDValidationOptions,
): string {
  const { paramName, localIssuer } = resolveGroupValidationArgs(
    'group_aid',
    paramNameOrOptions,
    maybeOptions,
  );

  if (groupId === null || groupId === undefined || (typeof groupId === 'string' && !groupId.trim())) {
    throw new ValidationError(`${paramName} cannot be empty`);
  }

  const rawText = String(groupId).trim();
  if (rawText.includes('//')) {
    throw new ValidationError(`Invalid ${paramName} '${String(groupId)}': empty path segment is not allowed`);
  }

  const groupAid = convertToGroupAid(rawText, { localIssuer });
  if (!groupAid) {
    throw new ValidationError(`${paramName} cannot be empty`);
  }

  validateGroupAidParts(groupId, groupAid, paramName);
  return groupAid;
}

/**
 * 校验 Group ID 格式是否合法。
 *
 * 旧函数名保留兼容，但返回目标态 group_aid。
 */
export function validateGroupIDFormat(
  groupId: unknown,
  paramNameOrOptions: string | GroupAIDValidationOptions = 'group_id',
  maybeOptions?: GroupAIDValidationOptions,
): string {
  const { paramName, localIssuer } = resolveGroupValidationArgs(
    'group_id',
    paramNameOrOptions,
    maybeOptions,
  );
  return validateGroupAIDFormat(groupId, paramName, { localIssuer });
}
