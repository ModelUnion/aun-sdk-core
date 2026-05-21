/**
 * MetaNamespace 单元测试
 *
 * 覆盖：ping/status/trustRoots RPC 直通 + 信任根管理方法
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as crypto from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { AUNClient } from '../../src/client.js';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// ── 辅助：生成自签名 CA 证书 ──────────────────────────────────────

function generateSelfSignedCA(): { certPem: string; keyPem: string; fingerprint: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-384',
  });
  const cert = new crypto.X509Certificate(
    // 使用 openssl 风格的自签名证书不可行，用 node:crypto 的 createCertificate (Node 22+)
    // 这里用简化方式：直接构造 PEM
    '' // placeholder
  );
  // Node 22.16+ 没有 createCertificate，用 spawn openssl 也不合适
  // 改用预生成的测试证书
  return _generateTestCA();
}

function _generateTestCA(): { certPem: string; keyPem: string; fingerprint: string } {
  // 使用 node:crypto 生成 EC P-384 密钥对
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-384',
  });
  const keyPem = privateKey.export({ type: 'sec1', format: 'pem' }) as string;
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;

  // 为测试目的，我们 mock 证书验证逻辑
  // 生成一个假的 PEM 证书（实际测试中 mock 掉验证）
  const fakeCertPem = [
    '-----BEGIN CERTIFICATE-----',
    Buffer.from('FAKE_CA_CERT_FOR_TESTING_' + Date.now()).toString('base64'),
    '-----END CERTIFICATE-----',
  ].join('\n');

  const der = Buffer.from(
    fakeCertPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''),
    'base64',
  );
  const fingerprint = crypto.createHash('sha256').update(der).digest('hex');

  return { certPem: fakeCertPem, keyPem, fingerprint };
}

describe('MetaNamespace', () => {
  describe('RPC 直通方法', () => {
    it('ping() 应调用 meta.ping', async () => {
      const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-meta-')) });
      const callSpy = vi.spyOn(client, 'call').mockResolvedValue({ pong: true });

      const result = await client.meta.ping();
      expect(callSpy).toHaveBeenCalledWith('meta.ping', {});
      expect(result).toEqual({ pong: true });
    });

    it('status() 应调用 meta.status', async () => {
      const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-meta-')) });
      const callSpy = vi.spyOn(client, 'call').mockResolvedValue({ connected: true });

      const result = await client.meta.status();
      expect(callSpy).toHaveBeenCalledWith('meta.status', {});
      expect(result).toEqual({ connected: true });
    });

    it('trustRoots() 应调用 meta.trust_roots', async () => {
      const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-meta-')) });
      const callSpy = vi.spyOn(client, 'call').mockResolvedValue({ roots: [] });

      const result = await client.meta.trustRoots();
      expect(callSpy).toHaveBeenCalledWith('meta.trust_roots', {});
      expect(result).toEqual({ roots: [] });
    });
  });

  describe('downloadTrustRoots', () => {
    it('应从指定 URL 下载信任根列表', async () => {
      const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-meta-')) });
      const mockPayload = { version: 1, root_cas: [] };

      // mock node:https
      const httpsMock = vi.fn((_url: any, _opts: any, cb: any) => {
        const res = {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          on: (event: string, handler: any) => {
            if (event === 'data') handler(JSON.stringify(mockPayload));
            if (event === 'end') handler();
            return res;
          },
        };
        cb(res);
        return { on: () => {}, setTimeout: () => {}, destroy: () => {} };
      });
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockPayload,
      }));

      const result = await client.meta.downloadTrustRoots({
        url: 'https://pki.example.com/trust-root.json',
      });
      expect(result).toEqual(mockPayload);
    });

    it('应基于 issuer 构造 PKI URL', async () => {
      const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-meta-')) });
      const mockPayload = { version: 1, root_cas: [] };

      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockPayload,
      });
      vi.stubGlobal('fetch', fetchMock);

      await client.meta.downloadTrustRoots({ issuer: 'aid.com' });
      expect(fetchMock).toHaveBeenCalledWith(
        'https://pki.aid.com/trust-root.json',
        expect.anything(),
      );
    });

    it('应基于 gateway_url 构造镜像 URL', async () => {
      const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-meta-')) });
      const mockPayload = { version: 1, root_cas: [] };

      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockPayload,
      });
      vi.stubGlobal('fetch', fetchMock);

      await client.meta.downloadTrustRoots({ gateway_url: 'wss://gw.aid.com/aun' });
      expect(fetchMock).toHaveBeenCalledWith(
        'https://gw.aid.com/pki/trust-roots.json',
        expect.anything(),
      );
    });
  });

  describe('verifyTrustRoots', () => {
    it('应拒绝无签名的信任根列表（默认）', () => {
      const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-meta-')) });
      const trustList = { version: 1, issued_at: new Date().toISOString(), next_update: new Date(Date.now() + 86400000).toISOString(), root_cas: [] };

      expect(() => client.meta.verifyTrustRoots(trustList)).toThrow(
        /missing authority_signature/,
      );
    });

    it('应拒绝版本回滚', () => {
      const aunPath = mkdtempSync(join(tmpdir(), 'aun-meta-'));
      const client = new AUNClient({ aun_path: aunPath });

      // 写入已有的 trust-roots.json（version=5）
      const trustDir = join(aunPath, 'CA', 'root');
      mkdirSync(trustDir, { recursive: true });
      writeFileSync(join(trustDir, 'trust-roots.json'), JSON.stringify({ version: 5 }));

      // 构造一个 version=3 的列表（低于已有的 version=5）
      // importTrustRoots 先调 verifyTrustRoots，再调 _enforceMonotonicVersion
      // 为了让 verifyTrustRoots 通过，需要有效的 root_cas
      // 但 _enforceMonotonicVersion 在 verifyTrustRoots 之后调用
      // 直接测试内部方法
      const trustList = { version: 3 };
      expect(() => (client.meta as any)._enforceMonotonicVersion(trustList)).toThrow(
        /version rollback/,
      );
    });
  });

  describe('gateway trust roots URL', () => {
    it('wss:// 应转换为 https://', () => {
      const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-meta-')) });
      // 访问内部静态方法
      const MetaNS = (client.meta as any).constructor;
      const url = (client.meta as any)._gatewayTrustRootsUrl('wss://gw.aid.com/aun');
      expect(url).toBe('https://gw.aid.com/pki/trust-roots.json');
    });

    it('https:// 应保持 https://', () => {
      const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-meta-')) });
      const url = (client.meta as any)._gatewayTrustRootsUrl('https://gw.aid.com/aun');
      expect(url).toBe('https://gw.aid.com/pki/trust-roots.json');
    });
  });

  describe('issuer PKI URLs', () => {
    it('_issuerTrustRootUrl 应生成正确 URL', () => {
      const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-meta-')) });
      const url = (client.meta as any)._issuerTrustRootUrl('aid.com');
      expect(url).toBe('https://pki.aid.com/trust-root.json');
    });

    it('_issuerRootCertUrl 应生成正确 URL', () => {
      const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-meta-')) });
      const url = (client.meta as any)._issuerRootCertUrl('aid.com');
      expect(url).toBe('https://pki.aid.com/root.crt');
    });
  });
});

