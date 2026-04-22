import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { AUNClient } from '../../src/client.js';
import { ValidationError } from '../../src/errors.js';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('CustodyNamespace', () => {
  it('sendCode 绑定场景应携带 Bearer token', async () => {
    const client = new AUNClient({
      custodyUrl: 'https://custody.example.com',
    });
    (client as any)._identity = { access_token: 'tok-1' };

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ request_id: 'req-1' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await client.custody.sendCode({ phone: '+8613800138000' });

    expect(result).toEqual({ request_id: 'req-1' });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://custody.example.com/custody/accounts/send-code',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          Authorization: 'Bearer tok-1',
          'Content-Type': 'application/json',
        }),
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it('sendCode 恢复场景传 aid 时不应要求 token', async () => {
    const client = new AUNClient();
    client.custody.setUrl('https://custody.example.com');

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ request_id: 'req-2' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(client.custody.sendCode({
      phone: '+8613800138000',
      aid: 'alice.agentid.pub',
    })).resolves.toEqual({ request_id: 'req-2' });
  });

  it('bindPhone 缺少 token 时应抛错', async () => {
    const client = new AUNClient({ custodyUrl: 'https://custody.example.com' });

    await expect(client.custody.bindPhone({
      phone: '+8613800138000',
      code: '123456',
      cert: 'CERT',
      key: 'KEY',
    })).rejects.toThrow(new ValidationError('no access_token available: call auth.authenticate() first'));
  });

  it('restorePhone 应匿名提交恢复请求', async () => {
    const client = new AUNClient({ custodyUrl: 'https://custody.example.com' });
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ aid: 'alice.agentid.pub', cert_pem: 'CERT' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await client.custody.restorePhone({
      phone: '+8613800138000',
      code: '123456',
      aid: 'alice.agentid.pub',
    });

    expect(result).toEqual({ aid: 'alice.agentid.pub', cert_pem: 'CERT' });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://custody.example.com/custody/accounts/restore-phone',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: expect.any(AbortSignal),
      }),
    );
  });
});
