/**
 * 配置模块单元测试
 */

import { describe, it, expect } from 'vitest';
import { defaultConfig, configFromMap } from '../../src/config.js';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { JsonObject } from '../../src/types.js';

describe('defaultConfig', () => {
  it('返回正确的默认值', () => {
    const cfg = defaultConfig();
    expect(cfg.aunPath).toBe(join(homedir(), '.aun'));
    expect(cfg.rootCaPath).toBeNull();
    expect(cfg.encryptionSeed).toBeNull();
    expect(cfg.discoveryPort).toBeNull();
    expect(cfg.groupE2ee).toBe(true);
    expect(cfg.rotateOnJoin).toBe(false);
    expect(cfg.epochAutoRotateInterval).toBe(0);
    expect(cfg.oldEpochRetentionSeconds).toBe(604800);
    expect(cfg.verifySsl).toBe(true);
    expect(cfg.requireForwardSecrecy).toBe(true);
    expect(cfg.replayWindowSeconds).toBe(300);
  });
});

describe('configFromMap', () => {
  it('使用自定义值覆盖默认值', () => {
    const cfg = configFromMap({
      aun_path: '/tmp/my-aun',
      root_ca_path: '/ca/root.pem',
      encryption_seed: 's3cret',
      discovery_port: 20001,
      group_e2ee: false,
      verify_ssl: false,
    });
    expect(cfg.aunPath).toBe('/tmp/my-aun');
    expect(cfg.rootCaPath).toBe('/ca/root.pem');
    expect(cfg.encryptionSeed).toBe('s3cret');
    expect(cfg.discoveryPort).toBe(20001);
    expect(cfg.groupE2ee).toBe(false);
    expect(cfg.verifySsl).toBe(false);
    // 未设置的保持默认
    expect(cfg.requireForwardSecrecy).toBe(true);
    expect(cfg.replayWindowSeconds).toBe(300);
  });

  it('支持 camelCase 风格的键名', () => {
    const cfg = configFromMap({
      aunPath: '/tmp/camel',
      rootCaPath: '/ca/camel.pem',
      encryptionSeed: 'camelSeed',
    });
    expect(cfg.aunPath).toBe('/tmp/camel');
    expect(cfg.rootCaPath).toBe('/ca/camel.pem');
    expect(cfg.encryptionSeed).toBe('camelSeed');
  });

  it('忽略未知键', () => {
    const cfg = configFromMap({
      aun_path: '/tmp/test',
      gateway: 'ws://localhost:20001/aun',
      auto_reconnect: true,
      some_random_key: 42,
    });
    expect(cfg.aunPath).toBe('/tmp/test');
    // 未知键不应出现在配置中
    expect((cfg as JsonObject).gateway).toBeUndefined();
    expect((cfg as JsonObject).auto_reconnect).toBeUndefined();
  });
});
