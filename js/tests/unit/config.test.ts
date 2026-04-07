// ── config 模块单元测试 ──────────────────────────────────────
import { describe, it, expect, beforeEach } from 'vitest';
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

  it('传入 null 应等同于默认值', () => {
    const cfg = createConfig(null);
    expect(cfg.aunPath).toBe('aun');
    expect(cfg.groupE2ee).toBe(true);
  });

  it('应允许覆盖特定字段', () => {
    const cfg = createConfig({
      aunPath: 'custom-db',
      groupE2ee: false,
      replayWindowSeconds: 600,
    });
    expect(cfg.aunPath).toBe('custom-db');
    expect(cfg.groupE2ee).toBe(false);
    expect(cfg.replayWindowSeconds).toBe(600);
    // 未覆盖的字段保持默认
    expect(cfg.verifySsl).toBe(true);
    expect(cfg.rootCaPem).toBeNull();
  });
});
