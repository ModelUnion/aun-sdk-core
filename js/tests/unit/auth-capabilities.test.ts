// ── auth.connect 能力声明 / extra_info 单元测试 ──────────────
// 与 Python `auth.py:511` 行为对齐：
// - 默认 capabilities 含 supported_p2p_e2ee / supported_group_e2ee
// - extra_info 中 _ 前缀字段不透传到服务端

import 'fake-indexeddb/auto';
import { describe, it, expect, vi } from 'vitest';
import { AUNClient } from '../../src/client.js';

describe('auth.connect 能力声明 + extra_info', () => {
  it('默认 capabilities 含 supported_p2p_e2ee 与 supported_group_e2ee', async () => {
    const client = new AUNClient();
    const mockTransport = { call: vi.fn().mockResolvedValue({ status: 'ok' }) };
    const auth = (client as any)._auth;
    await (auth as any)._initializeSession(mockTransport, 'nonce123', 'mytoken', {
      deviceId: 'dev1',
      slotId: '',
      deliveryMode: { mode: 'fanout' },
      connectionKind: 'long',
      shortTtlMs: 0,
    });
    const args = mockTransport.call.mock.calls[0][1] as Record<string, any>;
    expect(args.capabilities).toBeDefined();
    expect(args.capabilities.e2ee).toBe(true);
    expect(args.capabilities.group_e2ee).toBe(true);
    expect(args.capabilities.supported_p2p_e2ee).toEqual(['e2ee_v2']);
    expect(args.capabilities.supported_group_e2ee).toEqual(['group_e2ee_v2']);
  });

  it('extra_info 中 _ 前缀字段不透传到服务端', async () => {
    const client = new AUNClient();
    const mockTransport = { call: vi.fn().mockResolvedValue({ status: 'ok' }) };
    const auth = (client as any)._auth;
    await (auth as any)._initializeSession(mockTransport, 'nonce', 'tok', {
      deviceId: 'd', slotId: '',
      extraInfo: { _internal: 'hidden', visible: 'yes' },
    });
    const args = mockTransport.call.mock.calls[0][1] as Record<string, any>;
    expect(args.extra_info).toEqual({ visible: 'yes' });
  });

  it('空 extra_info 不应在请求中生成 extra_info 字段', async () => {
    const client = new AUNClient();
    const mockTransport = { call: vi.fn().mockResolvedValue({ status: 'ok' }) };
    const auth = (client as any)._auth;
    await (auth as any)._initializeSession(mockTransport, 'nonce', 'tok', {
      deviceId: 'd', slotId: '',
      extraInfo: { _internal: 'only_underscored' },
    });
    const args = mockTransport.call.mock.calls[0][1] as Record<string, any>;
    expect(args.extra_info).toBeUndefined();
  });
});
