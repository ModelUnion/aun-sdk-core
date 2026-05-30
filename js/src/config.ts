// ── AUN 配置 ──────────────────────────────────────────────

import { ValidationError } from './errors.js';
import type { ModuleLogger } from './logger.js';
import type { JsonObject } from './types.js';


const _noopLog: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };

const INSTANCE_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;
// slot_id 允许额外包含 / : 空格作为分隔符，但不允许出现在首字符
const SLOT_ID_PATTERN = /^[A-Za-z0-9._-][A-Za-z0-9._/ :-]{0,127}$/;

function readString(value: JsonObject[keyof JsonObject], fallback: string): string {
  return typeof value === 'string' ? value : fallback;
}

function readOptionalString(value: JsonObject[keyof JsonObject], fallback: string | null): string | null {
  return typeof value === 'string' ? value : fallback;
}

function readOptionalNumber(value: JsonObject[keyof JsonObject], fallback: number | null): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function readBoolean(value: JsonObject[keyof JsonObject], fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

export function normalizeInstanceId(
  value: unknown,
  field: string,
  opts: { allowEmpty?: boolean } = {},
): string {
  const text = String(value ?? '').trim();
  if (!text) {
    if (opts.allowEmpty) return '';
    throw new ValidationError(`${field} must be a non-empty string`);
  }
  if (!INSTANCE_ID_PATTERN.test(text)) {
    throw new ValidationError(`${field} contains unsupported characters`);
  }
  return text;
}

export function normalizeSlotId(value: unknown, defaultValue = 'default'): string {
  const raw = String(value ?? '');
  const text = raw || defaultValue;
  if (!SLOT_ID_PATTERN.test(text)) {
    throw new ValidationError('slot_id contains unsupported characters');
  }
  return text;
}

/** 提取 slot_id 的隔离键：第一个分隔符（/ : 空格）之前的部分。 */
export function slotIsolationKey(slotId: string): string {
  const m = slotId.match(/^[^/ :]+/);
  return m ? m[0] : slotId;
}

/**
 * 获取设备稳定 ID（浏览器环境使用 localStorage）。
 * 首次调用时自动生成 UUID 并持久化，后续返回同一值。
 */
export function getDeviceId(): string {
  const STORAGE_KEY = 'aun_device_id';
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) return normalizeInstanceId(stored, 'device_id');
  } catch {
    // localStorage 不可用（隐私模式等）
  }

  const newId = normalizeInstanceId(crypto.randomUUID(), 'device_id');
  try {
    localStorage.setItem(STORAGE_KEY, newId);
  } catch {
    // 写入失败时仍返回生成的 ID（本次会话内有效）
  }
  return newId;
}

/** AUN SDK 配置接口 */
export interface AUNConfig {
  aunPath: string;
  rootCaPem: string | null;
  seedPassword: string | null;
  groupE2ee: boolean;
  verifySsl: boolean;
  requireForwardSecrecy: boolean;
  replayWindowSeconds: number;
  discoveryPort: number | null;
}

/** AUN 配置默认值 */
const DEFAULTS: AUNConfig = {
  aunPath: 'aun',
  rootCaPem: null,
  seedPassword: null,
  groupE2ee: true,
  verifySsl: true,
  requireForwardSecrecy: true,
  replayWindowSeconds: 300,
  discoveryPort: null,
};

type AUNConfigInput = Partial<AUNConfig> & JsonObject;

/** 从字典创建 AUNConfig（兼容 snake_case 和 camelCase） */
export function createConfig(raw?: AUNConfigInput | null): AUNConfig {
  const data = (raw ?? {}) as AUNConfigInput;
  if (data.verifySsl === false || data.verifySSL === false || data.verify_ssl === false) {
    // 浏览器环境不支持跳过 SSL 验证，发出警告但不抛错（与 Python 对齐）
    // 配置阶段尚无 logger 实例，直接走 console.warn（这是仅有的例外）
    console.warn(
      '[aun_core.config] verify_ssl=false 在浏览器环境中不受支持，' +
      'SSL 证书验证将保持启用。浏览器 fetch API 不提供跳过证书验证的选项。',
    );
  }
  return {
    aunPath: readString(data.aunPath ?? data.aun_path, DEFAULTS.aunPath),
    rootCaPem: readOptionalString(data.rootCaPem ?? data.root_ca_pem ?? data.root_ca_path, DEFAULTS.rootCaPem),
    seedPassword: readOptionalString(
      data.seedPassword ?? data.seed_password ?? data.encryptionSeed ?? data.encryption_seed,
      DEFAULTS.seedPassword,
    ),
    groupE2ee: true,
    verifySsl: DEFAULTS.verifySsl,
    requireForwardSecrecy: readBoolean(data.requireForwardSecrecy ?? data.require_forward_secrecy, DEFAULTS.requireForwardSecrecy),
    replayWindowSeconds: readOptionalNumber(data.replayWindowSeconds ?? data.replay_window_seconds, DEFAULTS.replayWindowSeconds) ?? DEFAULTS.replayWindowSeconds,
    discoveryPort: readOptionalNumber(data.discoveryPort ?? data.discovery_port, DEFAULTS.discoveryPort),
  };
}
