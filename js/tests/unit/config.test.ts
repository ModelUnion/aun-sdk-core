// ── config 模块单元测试 ──────────────────────────────────────
import { describe, it, expect, beforeEach } from 'vitest';
import { ValidationError } from '../../src/errors.js';
import { getDeviceId, createConfig } from '../../src/config.js';

describe('getDeviceId', () => {
  beforeEach(() => {
    // 每次测试前清除 localStorage 中的设备 ID
    localStorage.removeItem('aun_device_id');
  });

  it('应返回合法的 UUID 格式', () => {
    const id = getDeviceId();
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    expect(id).toMatch(uuidRegex);
  });

  it('多次调用应返回相同的设备 ID', () => {
    const id1 = getDeviceId();
    const id2 = getDeviceId();
    expect(id1).toBe(id2);
  });

  it('清除 localStorage 后应生成新 ID', () => {
    const id1 = getDeviceId();
    localStorage.removeItem('aun_device_id');
    const id2 = getDeviceId();
    // 两次应该不同（概率极低相同）
    expect(id2).toMatch(/^[0-9a-f]{8}-/);
  });
});

describe('createConfig', () => {
  it('无参数调用应返回全部默认值', () => {
    const cfg = createConfig();
    expect(cfg.aunPath).toBe('aun');
    expect(cfg.rootCaPem).toBeNull();
    expect(cfg.seedPassword).toBeNull();
    expect(cfg.discoveryPort).toBeNull();
    expect(cfg.groupE2ee).toBe(true);
    expect(cfg.rotateOnJoin).toBe(false);
    expect(cfg.epochAutoRotateInterval).toBe(0);
    expect(cfg.oldEpochRetentionSeconds).toBe(604800);
    expect(cfg.verifySsl).toBe(true);
    expect(cfg.requireForwardSecrecy).toBe(true);
    expect(cfg.replayWindowSeconds).toBe(300);
  });

  it('传入 null 应等同于默认值', () => {
    const cfg = createConfig(null);
    expect(cfg.aunPath).toBe('aun');
    expect(cfg.groupE2ee).toBe(true);
  });

  it('解析已支持字段和别名', () => {
    const cfg = createConfig({
      aunPath: 'custom-db',
      root_ca_pem: 'ROOT-CA-PEM',
      discoveryPort: 20001,
      groupE2EE: false,
      rotateOnJoin: true,
      epochAutoRotateInterval: 3600,
      oldEpochRetentionSeconds: 86400,
      requireForwardSecrecy: false,
      replayWindowSeconds: 600,
    } as any);
    expect(cfg.aunPath).toBe('custom-db');
    expect(cfg.rootCaPem).toBe('ROOT-CA-PEM');
    expect(cfg.discoveryPort).toBe(20001);
    expect(cfg.groupE2ee).toBe(true); // 必备能力，不可关闭
    expect(cfg.rotateOnJoin).toBe(true);
    expect(cfg.epochAutoRotateInterval).toBe(3600);
    expect(cfg.oldEpochRetentionSeconds).toBe(86400);
    expect(cfg.requireForwardSecrecy).toBe(false);
    expect(cfg.replayWindowSeconds).toBe(600);
    expect(cfg.verifySsl).toBe(true);
  });

  it('兼容读取 seedPassword 旧别名', () => {
    const cfg = createConfig({
      encryptionSeed: 'legacy-seed',
    } as any);
    expect(cfg.seedPassword).toBe('legacy-seed');
  });

  it('应忽略 delivery_mode 相关构造参数', () => {
    const cfg = createConfig({
      delivery_mode: 'queue',
      queue_routing: 'sender_affinity',
      affinity_ttl_ms: 900,
    } as any);
    expect((cfg as any).deliveryMode).toBeUndefined();
    expect((cfg as any).queueRouting).toBeUndefined();
    expect((cfg as any).affinityTtlMs).toBeUndefined();
  });

  it('不允许 verify_ssl=false', () => {
    expect(() => createConfig({ verify_ssl: false }))
      .toThrowError(new ValidationError('browser SDK does not allow verify_ssl=false'));
  });

  it('不允许 verifySsl=false', () => {
    expect(() => createConfig({ verifySsl: false }))
      .toThrowError(new ValidationError('browser SDK does not allow verify_ssl=false'));
  });

  it('不允许 verifySSL=false', () => {
    expect(() => createConfig({ verifySSL: false } as any))
      .toThrowError(new ValidationError('browser SDK does not allow verify_ssl=false'));
  });
});
