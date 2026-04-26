/**
 * 配置模块单元测试
 */

import { afterEach, describe, it, expect, vi } from 'vitest';
import { defaultConfig, configFromMap, normalizeInstanceId } from '../../src/config.js';
import { ValidationError } from '../../src/errors.js';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { JsonObject } from '../../src/types.js';

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('defaultConfig', () => {
  it('返回正确的默认值', () => {
    vi.stubEnv('AUN_ENV', 'production');
    const cfg = defaultConfig();
    expect(cfg.aunPath).toBe(join(homedir(), '.aun'));
    expect(cfg.rootCaPath).toBeNull();
    expect(cfg.seedPassword).toBeNull();
    expect(cfg.discoveryPort).toBeNull();
    expect(cfg.groupE2ee).toBe(true);
    expect(cfg.epochAutoRotateInterval).toBe(0);
    expect(cfg.oldEpochRetentionSeconds).toBe(604800);
    expect(cfg.verifySsl).toBe(true);
    expect(cfg.requireForwardSecrecy).toBe(true);
    expect(cfg.replayWindowSeconds).toBe(300);
  });
});

describe('configFromMap', () => {
  it('解析已支持的 snake_case 字段', () => {
    vi.stubEnv('AUN_ENV', 'development');
    const cfg = configFromMap({
      aun_path: '/tmp/my-aun',
      root_ca_path: '/ca/root.pem',
      encryption_seed: 's3cret',
      discovery_port: 20001,
      group_e2ee: false,
      epoch_auto_rotate_interval: 3600,
      old_epoch_retention_seconds: 86400,
      verify_ssl: false,
      require_forward_secrecy: false,
      replay_window_seconds: 600,
    });
    expect(cfg.aunPath).toBe('/tmp/my-aun');
    expect(cfg.rootCaPath).toBe('/ca/root.pem');
    expect(cfg.seedPassword).toBe('s3cret');
    expect(cfg.discoveryPort).toBe(20001);
    expect(cfg.groupE2ee).toBe(true); // 必备能力，不可关闭
    expect(cfg.epochAutoRotateInterval).toBe(3600);
    expect(cfg.oldEpochRetentionSeconds).toBe(86400);
    expect(cfg.verifySsl).toBe(false);
    expect(cfg.requireForwardSecrecy).toBe(false);
    expect(cfg.replayWindowSeconds).toBe(600);
  });

  it('支持 camelCase 风格的键名', () => {
    vi.stubEnv('AUN_ENV', 'production');
    const cfg = configFromMap({
      aunPath: '/tmp/camel',
      rootCaPath: '/ca/camel.pem',
      encryptionSeed: 'camelSeed',
      discoveryPort: 21001,
      groupE2EE: false,
      epochAutoRotateInterval: 120,
      oldEpochRetentionSeconds: 30,
      verifySSL: false,
      requireForwardSecrecy: false,
      replayWindowSeconds: 42,
    });
    expect(cfg.aunPath).toBe('/tmp/camel');
    expect(cfg.rootCaPath).toBe('/ca/camel.pem');
    expect(cfg.seedPassword).toBe('camelSeed');
    expect(cfg.discoveryPort).toBe(21001);
    expect(cfg.groupE2ee).toBe(true); // 必备能力，不可关闭
    expect(cfg.epochAutoRotateInterval).toBe(120);
    expect(cfg.oldEpochRetentionSeconds).toBe(30);
    expect(cfg.verifySsl).toBe(false);
    expect(cfg.requireForwardSecrecy).toBe(false);
    expect(cfg.replayWindowSeconds).toBe(42);
  });

  it('忽略未知键', () => {
    vi.stubEnv('AUN_ENV', 'production');
    const cfg = configFromMap({
      aun_path: '/tmp/test',
      delivery_mode: 'queue',
      queue_routing: 'sender_affinity',
      affinity_ttl_ms: 15000,
      gateway: 'ws://localhost:20001/aun',
      auto_reconnect: true,
      some_random_key: 42,
    });
    expect(cfg.aunPath).toBe('/tmp/test');
    // 未知键不应出现在配置中
    expect((cfg as JsonObject).deliveryMode).toBeUndefined();
    expect((cfg as JsonObject).queueRouting).toBeUndefined();
    expect((cfg as JsonObject).affinityTtlMs).toBeUndefined();
    expect((cfg as JsonObject).gateway).toBeUndefined();
    expect((cfg as JsonObject).auto_reconnect).toBeUndefined();
  });

  it('normalizeInstanceId 校验非法字符', () => {
    expect(() => normalizeInstanceId('slot with space', 'slot_id')).toThrow(ValidationError);
  });

  it('生产环境默认启用 verifySsl', () => {
    vi.stubEnv('AUN_ENV', 'production');
    expect(defaultConfig().verifySsl).toBe(true);
  });

  it('开发环境默认关闭 verifySsl', () => {
    vi.stubEnv('AUN_ENV', 'development');
    expect(defaultConfig().verifySsl).toBe(false);
  });
});
