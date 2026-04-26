/**
 * AUN SDK 配置管理
 *
 * 提供设备 ID 获取、配置接口定义、默认值与构建逻辑。
 */

import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { ValidationError } from './errors.js';
import type { JsonObject } from './types.js';

// ── 设备 ID ──────────────────────────────────────────────────

const INSTANCE_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;
const DEV_ENV_VALUES = new Set(['development', 'dev', 'local']);

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

/**
 * 获取本设备的稳定 ID。
 *
 * 存储在 ~/.aun/.device_id（或 aunRoot/.device_id）。
 * 首次调用时自动生成并持久化，后续调用返回同一值。
 * 同一台机器上所有 SDK 实例共享同一个 device_id。
 */
export function getDeviceId(aunRoot?: string): string {
  const root = aunRoot ?? join(homedir(), '.aun');
  mkdirSync(root, { recursive: true });
  const deviceIdPath = join(root, '.device_id');

  if (existsSync(deviceIdPath)) {
    try {
      const stored = readFileSync(deviceIdPath, 'utf-8').trim();
      if (stored) return normalizeInstanceId(stored, 'device_id');
    } catch {
      // 平台兼容 fallback
    }
  }

  const newId = normalizeInstanceId(randomUUID(), 'device_id');
  try {
    writeFileSync(deviceIdPath, newId, 'utf-8');
    if (process.platform !== 'win32') {
      try {
        chmodSync(deviceIdPath, 0o600);
      } catch {
        // 平台兼容 fallback
      }
    }
  } catch {
    // 平台兼容 fallback
  }
  return newId;
}

// ── 配置接口 ─────────────────────────────────────────────────

export interface AUNConfig {
  /** AUN 数据根目录（默认 ~/.aun） */
  aunPath: string;
  /** 根证书路径 */
  rootCaPath: string | null;
  /** 私钥加密口令（用于本地密钥派生） */
  seedPassword: string | null;
  /** Gateway 发现端口 */
  discoveryPort: number | null;
  /** 是否启用群组 E2EE */
  groupE2ee: boolean;
  /** epoch 自动轮换间隔（秒，0 表示不自动轮换） */
  epochAutoRotateInterval: number;
  /** 旧 epoch 保留时长（秒，默认 7 天） */
  oldEpochRetentionSeconds: number;
  /** 是否验证 TLS 证书 */
  verifySsl: boolean;
  /** 是否要求前向保密 */
  requireForwardSecrecy: boolean;
  /** 防重放窗口（秒） */
  replayWindowSeconds: number;
}

function readOptionalNumber(value: unknown, fallback: number | null): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function readBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function resolveVerifySslFromEnv(): boolean {
  for (const key of ['AUN_ENV', 'KITE_ENV'] as const) {
    const raw = process.env[key];
    if (typeof raw !== 'string') continue;
    const value = raw.trim().toLowerCase();
    if (!value) continue;
    return !DEV_ENV_VALUES.has(value);
  }
  return true;
}

// ── 默认配置 ─────────────────────────────────────────────────

/** 返回默认配置 */
export function defaultConfig(): AUNConfig {
  return {
    aunPath: join(homedir(), '.aun'),
    rootCaPath: null,
    seedPassword: null,
    discoveryPort: null,
    groupE2ee: true,
    epochAutoRotateInterval: 0,
    oldEpochRetentionSeconds: 604800,
    verifySsl: resolveVerifySslFromEnv(),
    requireForwardSecrecy: true,
    replayWindowSeconds: 300,
  };
}

// ── 从字典构建配置 ───────────────────────────────────────────

/** 从原始键值对构建配置（与 Python SDK 的 from_dict 对齐） */
export function configFromMap(raw: JsonObject): AUNConfig {
  const def = defaultConfig();
  const aunPath = raw.aun_path ?? raw.aunPath;

  return {
    aunPath: aunPath ? String(aunPath) : def.aunPath,
    rootCaPath: raw.root_ca_path != null ? String(raw.root_ca_path) : (raw.rootCaPath != null ? String(raw.rootCaPath) : null),
    seedPassword:
      raw.seed_password != null ? String(raw.seed_password)
      : (raw.seedPassword != null ? String(raw.seedPassword)
      : (raw.encryption_seed != null ? String(raw.encryption_seed)
      : (raw.encryptionSeed != null ? String(raw.encryptionSeed) : null))),
    discoveryPort: readOptionalNumber(raw.discovery_port ?? raw.discoveryPort, def.discoveryPort),
    groupE2ee: true,  // 必备能力，不可配置
    epochAutoRotateInterval: readOptionalNumber(raw.epoch_auto_rotate_interval ?? raw.epochAutoRotateInterval, def.epochAutoRotateInterval) ?? def.epochAutoRotateInterval,
    oldEpochRetentionSeconds: readOptionalNumber(raw.old_epoch_retention_seconds ?? raw.oldEpochRetentionSeconds, def.oldEpochRetentionSeconds) ?? def.oldEpochRetentionSeconds,
    verifySsl: readBoolean(raw.verify_ssl ?? raw.verifySSL ?? raw.verifySsl, def.verifySsl),
    requireForwardSecrecy: readBoolean(raw.require_forward_secrecy ?? raw.requireForwardSecrecy, def.requireForwardSecrecy),
    replayWindowSeconds: readOptionalNumber(raw.replay_window_seconds ?? raw.replayWindowSeconds, def.replayWindowSeconds) ?? def.replayWindowSeconds,
  };
}
