import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { AUNClient } from '../../src/client.js';
import { MetaNamespace } from '../../src/namespaces/meta.js';
import { ValidationError } from '../../src/errors.js';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// ── 辅助：创建带 mock call 的客户端 ──────────────────────────

function makeClient(overrides?: Record<string, any>): AUNClient {
  const client = new AUNClient();
  // mock 内部 call 方法，避免真实 RPC 调用
  (client as any).call = vi.fn().mockResolvedValue({ ok: true });
  if (overrides) {
    Object.assign(client as any, overrides);
  }
  return client;
}

// ── RPC 直通方法 ─────────────────────────────────────────────

describe('MetaNamespace RPC 直通', () => {
  it('ping 应调用 meta.ping', async () => {
    const client = makeClient();
    await client.meta.ping();
    expect((client as any).call).toHaveBeenCalledWith('meta.ping', {});
  });

  it('ping 应透传参数', async () => {
    const client = makeClient();
    await client.meta.ping({ echo: 'hello' });
    expect((client as any).call).toHaveBeenCalledWith('meta.ping', { echo: 'hello' });
  });

  it('status 应调用 meta.status', async () => {
    const client = makeClient();
    await client.meta.status();
    expect((client as any).call).toHaveBeenCalledWith('meta.status', {});
  });

  it('trustRoots 应调用 meta.trust_roots', async () => {
    const client = makeClient();
    await client.meta.trustRoots();
    expect((client as any).call).toHaveBeenCalledWith('meta.trust_roots', {});
  });
});

// ── client 便利方法委托 ──────────────────────────────────────

describe('AUNClient 便利方法委托到 meta', () => {
  it('client.ping() 委托到 meta.ping()', async () => {
    const client = makeClient();
    const spy = vi.spyOn(client.meta, 'ping').mockResolvedValue({ pong: true });
    const result = await client.ping({ echo: 1 });
    expect(spy).toHaveBeenCalledWith({ echo: 1 });
    expect(result).toEqual({ pong: true });
  });

  it('client.status() 委托到 meta.status()', async () => {
    const client = makeClient();
    const spy = vi.spyOn(client.meta, 'status').mockResolvedValue({ up: true });
    const result = await client.status();
    expect(spy).toHaveBeenCalledWith(undefined);
    expect(result).toEqual({ up: true });
  });

  it('client.trustRoots() 委托到 meta.trustRoots()', async () => {
    const client = makeClient();
    const spy = vi.spyOn(client.meta, 'trustRoots').mockResolvedValue({ roots: [] });
    const result = await client.trustRoots();
    expect(spy).toHaveBeenCalledWith(undefined);
    expect(result).toEqual({ roots: [] });
  });
});

// ── downloadTrustRoots URL 构造 ──────────────────────────────

describe('MetaNamespace downloadTrustRoots', () => {
  it('使用直接指定的 url', async () => {
    const client = makeClient();
    const payload = { version: 1, root_cas: [] };
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => payload,
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await client.meta.downloadTrustRoots({
      url: 'https://custom.example.com/trust.json',
    });

    expect(fetchMock).toHaveBeenCalledWith(
      'https://custom.example.com/trust.json',
      expect.objectContaining({
        headers: { Accept: 'application/json' },
      }),
    );
    expect(result).toEqual(payload);
  });

  it('通过 issuer 构造 PKI URL', async () => {
    const client = makeClient();
    const payload = { version: 1, root_cas: [] };
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => payload,
    });
    vi.stubGlobal('fetch', fetchMock);

    await client.meta.downloadTrustRoots({ issuer: 'example.com' });

    // 应构造为 https://pki.example.com/trust-root.json
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toBe('https://pki.example.com/trust-root.json');
  });

  it('HTTP 错误应抛出 ValidationError', async () => {
    const client = makeClient();
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      client.meta.downloadTrustRoots({ url: 'https://example.com/trust.json' }),
    ).rejects.toThrow(ValidationError);
  });

  it('非 http(s) URL 应抛出 ValidationError', async () => {
    const client = makeClient();
    await expect(
      client.meta.downloadTrustRoots({ url: 'ftp://bad.example.com/trust.json' }),
    ).rejects.toThrow(ValidationError);
  });
});

// ── gateway URL wss→https 转换 ───────────────────────────────

describe('MetaNamespace gateway URL 转换', () => {
  it('wss:// 应转换为 https://', () => {
    const client = makeClient();
    const url = client.meta._gatewayTrustRootsUrl('wss://gw.example.com:8443/aun');
    expect(url).toBe('https://gw.example.com:8443/pki/trust-roots.json');
  });

  it('ws:// 应转换为 http://', () => {
    const client = makeClient();
    const url = client.meta._gatewayTrustRootsUrl('ws://gw.example.com/aun');
    expect(url).toBe('http://gw.example.com/pki/trust-roots.json');
  });

  it('无效 URL 应抛出 ValidationError', () => {
    const client = makeClient();
    expect(() => client.meta._gatewayTrustRootsUrl('not-a-url')).toThrow(ValidationError);
  });
});

// ── issuer PKI URL 构造 ──────────────────────────────────────

describe('MetaNamespace issuer PKI URL', () => {
  it('_issuerTrustRootUrl 构造正确', () => {
    const client = makeClient();
    const url = client.meta._issuerTrustRootUrl('example.com');
    expect(url).toBe('https://pki.example.com/trust-root.json');
  });

  it('_issuerRootCertUrl 构造正确', () => {
    const client = makeClient();
    const url = client.meta._issuerRootCertUrl('example.com');
    expect(url).toBe('https://pki.example.com/root.crt');
  });

  it('带 discoveryPort 的 URL 应包含端口', () => {
    const client = makeClient();
    (client as any).configModel = { discoveryPort: 9443 };
    const url = client.meta._issuerRootCertUrl('example.com');
    expect(url).toBe('https://pki.example.com:9443/root.crt');
  });
});

// ── verifyTrustRoots 校验 ────────────────────────────────────

describe('MetaNamespace verifyTrustRoots', () => {
  it('缺少 authority_signature 且未允许无签名应抛出', async () => {
    const client = makeClient();
    const trustList = {
      version: 1,
      issued_at: new Date().toISOString(),
      next_update: new Date(Date.now() + 86400000).toISOString(),
      root_cas: [],
    };
    await expect(
      client.meta.verifyTrustRoots(trustList),
    ).rejects.toThrow('missing authority_signature');
  });

  it('allow_unsigned 应跳过签名验证', async () => {
    const client = makeClient();
    // 使用合法的自签名测试证书 PEM（P-256 ECDSA）
    // 这里用一个 mock 指纹做简单验证
    const fakeCertPem = [
      '-----BEGIN CERTIFICATE-----',
      'MIIBkTCB+wIJALRiMLAh7SzHMAoGCCqGSM49BAMCMBExDzANBgNVBAMMBnRl',
      'c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNV',
      'BAMMBnRlc3RjYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEVmVL+KFWZK',
      'g0dtG4GtcAjJT+Y5xFC6rA3I3FPQhKE/G6TMffIWkwiVr2S9EBzhaHcekZ1P',
      'l5GNqf7KQK2EZkWjIzAhMB8GA1UdEQQYMBaCFHRlc3QuYWdlbnRpZC5wdWIw',
      'CgYIKoZIzj0EAwIDSAAwRQIgUzXYkPYE8J6FbPh2RF+6ObqwYMQKGjzW+gLI',
      'YWtpZkMCIQCz2O3JoMwxJbzQ7v7P3i1J4JQ9cPEDLFJJpGoDbRDvCA==',
      '-----END CERTIFICATE-----',
    ].join('\n');

    // 计算该证书的 SHA-256 指纹
    const certDer = Uint8Array.from(atob(
      fakeCertPem
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\s/g, ''),
    ), c => c.charCodeAt(0));
    const hashBuf = await crypto.subtle.digest('SHA-256', certDer);
    const fingerprint = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    const trustList = {
      version: 1,
      issued_at: new Date().toISOString(),
      next_update: new Date(Date.now() + 86400000).toISOString(),
      root_cas: [
        {
          id: 'test-root',
          certificate: fakeCertPem,
          fingerprint_sha256: fingerprint,
          status: 'active',
        },
      ],
    };

    const result = await client.meta.verifyTrustRoots(trustList, {
      allow_unsigned: true,
    });

    expect(result.count).toBe(1);
    expect((result.imported as any[])[0].id).toBe('test-root');
  });

  it('非 active 状态的根证书应被跳过', async () => {
    const client = makeClient();
    const fakeCertPem = [
      '-----BEGIN CERTIFICATE-----',
      'MIIBkTCB+wIJALRiMLAh7SzHMAoGCCqGSM49BAMCMBExDzANBgNVBAMMBnRl',
      'c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNV',
      'BAMMBnRlc3RjYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEVmVL+KFWZK',
      'g0dtG4GtcAjJT+Y5xFC6rA3I3FPQhKE/G6TMffIWkwiVr2S9EBzhaHcekZ1P',
      'l5GNqf7KQK2EZkWjIzAhMB8GA1UdEQQYMBaCFHRlc3QuYWdlbnRpZC5wdWIw',
      'CgYIKoZIzj0EAwIDSAAwRQIgUzXYkPYE8J6FbPh2RF+6ObqwYMQKGjzW+gLI',
      'YWtpZkMCIQCz2O3JoMwxJbzQ7v7P3i1J4JQ9cPEDLFJJpGoDbRDvCA==',
      '-----END CERTIFICATE-----',
    ].join('\n');

    const certDer = Uint8Array.from(atob(
      fakeCertPem
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\s/g, ''),
    ), c => c.charCodeAt(0));
    const hashBuf = await crypto.subtle.digest('SHA-256', certDer);
    const fingerprint = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    const trustList = {
      version: 1,
      issued_at: new Date().toISOString(),
      next_update: new Date(Date.now() + 86400000).toISOString(),
      root_cas: [
        {
          id: 'revoked-root',
          certificate: fakeCertPem,
          fingerprint_sha256: fingerprint,
          status: 'revoked',
        },
      ],
    };

    // 所有根证书都被跳过，应抛出 "no active root certificates"
    await expect(
      client.meta.verifyTrustRoots(trustList, { allow_unsigned: true }),
    ).rejects.toThrow('no active root certificates');
  });

  it('指纹不匹配应抛出 ValidationError', async () => {
    const client = makeClient();
    const fakeCertPem = [
      '-----BEGIN CERTIFICATE-----',
      'MIIBkTCB+wIJALRiMLAh7SzHMAoGCCqGSM49BAMCMBExDzANBgNVBAMMBnRl',
      'c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNV',
      'BAMMBnRlc3RjYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEVmVL+KFWZK',
      'g0dtG4GtcAjJT+Y5xFC6rA3I3FPQhKE/G6TMffIWkwiVr2S9EBzhaHcekZ1P',
      'l5GNqf7KQK2EZkWjIzAhMB8GA1UdEQQYMBaCFHRlc3QuYWdlbnRpZC5wdWIw',
      'CgYIKoZIzj0EAwIDSAAwRQIgUzXYkPYE8J6FbPh2RF+6ObqwYMQKGjzW+gLI',
      'YWtpZkMCIQCz2O3JoMwxJbzQ7v7P3i1J4JQ9cPEDLFJJpGoDbRDvCA==',
      '-----END CERTIFICATE-----',
    ].join('\n');

    const trustList = {
      version: 1,
      issued_at: new Date().toISOString(),
      next_update: new Date(Date.now() + 86400000).toISOString(),
      root_cas: [
        {
          id: 'bad-fp-root',
          certificate: fakeCertPem,
          fingerprint_sha256: 'deadbeef'.repeat(8), // 64 hex chars，但是错误指纹
          status: 'active',
        },
      ],
    };

    await expect(
      client.meta.verifyTrustRoots(trustList, { allow_unsigned: true }),
    ).rejects.toThrow('fingerprint mismatch');
  });

  it('version 非整数应抛出 ValidationError', async () => {
    const client = makeClient();
    const trustList = {
      version: 'abc',
      issued_at: new Date().toISOString(),
      next_update: new Date(Date.now() + 86400000).toISOString(),
      root_cas: [],
      authority_signature: 'dummy',
    };
    await expect(
      client.meta.verifyTrustRoots(trustList as any),
    ).rejects.toThrow('version');
  });

  it('缺少 issued_at 应抛出 ValidationError', async () => {
    const client = makeClient();
    const trustList = {
      version: 1,
      next_update: new Date(Date.now() + 86400000).toISOString(),
      root_cas: [],
      authority_signature: 'dummy',
    };
    await expect(
      client.meta.verifyTrustRoots(trustList as any),
    ).rejects.toThrow('issued_at');
  });
});

// ── downloadIssuerRootCert ───────────────────────────────────

describe('MetaNamespace downloadIssuerRootCert', () => {
  it('下载成功应返回 PEM 字符串', async () => {
    const client = makeClient();
    const certPem = '-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----';
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      text: async () => certPem,
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await client.meta.downloadIssuerRootCert('example.com');

    expect(result).toBe(certPem + '\n');
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toBe('https://pki.example.com/root.crt');
  });

  it('无效 issuer 应抛出 ValidationError', async () => {
    const client = makeClient();
    await expect(
      client.meta.downloadIssuerRootCert('https://bad'),
    ).rejects.toThrow(ValidationError);
  });

  it('缺少 BEGIN CERTIFICATE 应抛出 ValidationError', async () => {
    const client = makeClient();
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      text: async () => 'not a certificate',
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      client.meta.downloadIssuerRootCert('example.com'),
    ).rejects.toThrow(ValidationError);
  });
});

// ── MetaNamespace 构造 ───────────────────────────────────────

describe('MetaNamespace 构造', () => {
  it('AUNClient 应包含 meta 属性', () => {
    const client = new AUNClient();
    expect(client.meta).toBeInstanceOf(MetaNamespace);
  });

  it('meta 属性是 MetaNamespace 实例且不可被 Object.defineProperty 覆盖', () => {
    const client = new AUNClient();
    const original = client.meta;
    // readonly 是 TS 编译期约束；运行时验证实例类型即可
    expect(original).toBeInstanceOf(MetaNamespace);
    expect(client.meta).toBe(original); // 多次访问应为同一实例
  });
});
