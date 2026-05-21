import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import crypto from 'node:crypto';

import { AUNClient } from '../../src/client.js';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function derLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  if (len < 0x100) return Buffer.from([0x81, len]);
  return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function derTag(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function derSequence(content: Buffer): Buffer {
  return derTag(0x30, content);
}

function derSet(content: Buffer): Buffer {
  return derTag(0x31, content);
}

function derInteger(value: Buffer): Buffer {
  if (value[0] & 0x80) {
    value = Buffer.concat([Buffer.from([0x00]), value]);
  }
  return derTag(0x02, value);
}

function derBitString(content: Buffer): Buffer {
  return derTag(0x03, Buffer.concat([Buffer.from([0x00]), content]));
}

function derOctetString(content: Buffer): Buffer {
  return derTag(0x04, content);
}

function derUtf8String(content: Buffer): Buffer {
  return derTag(0x0c, content);
}

function derUtcTime(date: Date): Buffer {
  const year = date.getUTCFullYear() % 100;
  const parts = [
    String(year).padStart(2, '0'),
    String(date.getUTCMonth() + 1).padStart(2, '0'),
    String(date.getUTCDate()).padStart(2, '0'),
    String(date.getUTCHours()).padStart(2, '0'),
    String(date.getUTCMinutes()).padStart(2, '0'),
    String(date.getUTCSeconds()).padStart(2, '0'),
    'Z',
  ];
  return derTag(0x17, Buffer.from(parts.join(''), 'utf8'));
}

function derContextConstructed(tagNumber: number, content: Buffer): Buffer {
  return derTag(0xa0 + tagNumber, content);
}

function makeSelfSignedCert(privateKey: crypto.KeyObject, cn: string): string {
  const publicKeyDer = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }) as Buffer;
  const serialBytes = crypto.randomBytes(16);
  const notBefore = new Date(Date.now() - 60_000);
  const notAfter = new Date(Date.now() + 3600_000);
  const sigAlgOid = Buffer.from([
    0x30, 0x0a, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
  ]);

  const cnBytes = Buffer.from(cn, 'utf8');
  const name = derSequence(Buffer.concat([
    derSet(Buffer.concat([
      derSequence(Buffer.concat([
        Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]),
        derUtf8String(cnBytes),
      ])),
    ])),
  ]));

  const validity = derSequence(Buffer.concat([
    derUtcTime(notBefore),
    derUtcTime(notAfter),
  ]));

  const basicConstraintsExt = derSequence(Buffer.concat([
    Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x13]),
    Buffer.from([0x01, 0x01, 0xff]),
    derOctetString(derSequence(Buffer.from([0x01, 0x01, 0xff]))),
  ]));

  const extensions = derContextConstructed(3, derSequence(basicConstraintsExt));

  const tbs = derSequence(Buffer.concat([
    derContextConstructed(0, derInteger(Buffer.from([0x02]))),
    derInteger(serialBytes),
    sigAlgOid,
    name,
    validity,
    name,
    publicKeyDer,
    extensions,
  ]));

  const signer = crypto.createSign('SHA256');
  signer.update(tbs);
  signer.end();
  const sigDer = signer.sign(privateKey);

  const certDer = derSequence(Buffer.concat([
    tbs,
    sigAlgOid,
    derBitString(sigDer),
  ]));
  const b64 = certDer.toString('base64');
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}

function makeIdentity(aid: string): { aid: string; private_key_pem: string; cert: string } {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    aid,
    private_key_pem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    cert: makeSelfSignedCert(privateKey, aid),
  };
}

describe('AuthNamespace agent.md', () => {
  it('底层 AuthFlow 兼容 loadIdentityOrNone 命名', async () => {
    const client = new AUNClient();
    const result = await (client as any)._auth.loadIdentityOrNone();
    expect(result).toBeNull();
  });

  it('uploadAgentMd 应复用缓存 access_token', async () => {
    const client = new AUNClient();
    client.gatewayUrl = 'ws://gateway.agentid.pub/aun';
    (client as any)._aid = 'alice.agentid.pub';
    (client as any)._auth.loadIdentityOrNone = vi.fn().mockResolvedValue({
      aid: 'alice.agentid.pub',
      access_token: 'cached-token',
      access_token_expires_at: Date.now() / 1000 + 3600,
    });

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => ({ aid: 'alice.agentid.pub', etag: '"etag-1"' }),
      text: async () => '',
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await client.auth.uploadAgentMd('# Alice\n');

    expect(result).toEqual({ aid: 'alice.agentid.pub', etag: '"etag-1"' });
    expect(fetchMock).toHaveBeenCalledWith(
      'http://alice.agentid.pub/agent.md',
      expect.objectContaining({
        method: 'PUT',
        body: '# Alice\n',
        headers: expect.objectContaining({
          Authorization: 'Bearer cached-token',
          'Content-Type': 'text/markdown; charset=utf-8',
        }),
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it('uploadAgentMd 在 token 缺失时应回退 authenticate', async () => {
    const client = new AUNClient();
    client.gatewayUrl = 'ws://gateway.agentid.pub/aun';
    (client as any)._aid = 'alice.agentid.pub';
    (client as any)._auth.loadIdentityOrNone = vi.fn().mockResolvedValue({
      aid: 'alice.agentid.pub',
    });

    const authSpy = vi.spyOn(client.auth, 'authenticate').mockResolvedValue({
      aid: 'alice.agentid.pub',
      access_token: 'fresh-token',
      gateway: 'ws://gateway.agentid.pub/aun',
    });
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ aid: 'alice.agentid.pub', etag: '"etag-2"' }),
      text: async () => '',
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await client.auth.uploadAgentMd('# Alice\n');

    expect(result).toEqual({ aid: 'alice.agentid.pub', etag: '"etag-2"' });
    expect(authSpy).toHaveBeenCalledWith({ aid: 'alice.agentid.pub' });
    expect(fetchMock).toHaveBeenCalledWith(
      'http://alice.agentid.pub/agent.md',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer fresh-token',
        }),
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it('downloadAgentMd 应匿名下载', async () => {
    const client = new AUNClient();
    (client as any).configModel.discoveryPort = 18443;
    client.gatewayUrl = 'wss://gateway.agentid.pub/aun';

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => '# Bob\n',
      headers: new Headers(),
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await client.auth.downloadAgentMd('bob.agentid.pub');

    expect(result).toBe('# Bob\n');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://bob.agentid.pub:18443/agent.md',
      expect.objectContaining({
        method: 'GET',
        headers: { Accept: 'text/markdown' },
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it('downloadAgentMd 超时应抛明确错误', async () => {
    vi.useFakeTimers();
    const client = new AUNClient();
    client.gatewayUrl = 'wss://gateway.agentid.pub/aun';

    const fetchMock = vi.fn().mockImplementation(async (_url, init?: RequestInit) => (
      await new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      })
    ));
    vi.stubGlobal('fetch', fetchMock);

    const promise = client.auth.downloadAgentMd('bob.agentid.pub');
    const assertion = expect(promise).rejects.toThrow('agent.md request timed out');
    await vi.advanceTimersByTimeAsync(30_000);

    await assertion;
    vi.useRealTimers();
  });

  it('signAgentMd 应在尾部追加签名块并保留原 payload', async () => {
    const client = new AUNClient();
    const identity = makeIdentity('alice.agentid.pub');
    (client as any)._aid = identity.aid;
    (client as any)._auth.loadIdentityOrNone = vi.fn().mockResolvedValue(identity);

    const signed = await client.auth.signAgentMd(
      '---\naid: "alice.agentid.pub"\nname: "Alice"\n---\n\n# Alice\n',
    );

    expect(signed.startsWith('---\naid: "alice.agentid.pub"\n')).toBe(true);
    expect(signed).toContain('<!-- AUN-SIGNATURE');
    expect(signed).toMatch(/signature: [A-Za-z0-9+/=]+/);
    expect(signed).toMatch(/-->\s*$/);
  });

  it('verifyAgentMd 应返回 unsigned / verified / invalid 三态', async () => {
    const client = new AUNClient();
    const identity = makeIdentity('alice.agentid.pub');
    (client as any)._aid = identity.aid;
    (client as any)._auth.loadIdentityOrNone = vi.fn().mockResolvedValue(identity);

    const payload = '---\naid: "alice.agentid.pub"\nname: "Alice"\n---\n\n# Alice\n';
    const signed = await client.auth.signAgentMd(payload);

    const unsigned = await client.auth.verifyAgentMd(payload);
    expect(unsigned.status).toBe('unsigned');
    expect(unsigned.verified).toBe(false);

    const verified = await client.auth.verifyAgentMd(signed, {
      aid: identity.aid,
      certPem: identity.cert,
    });
    expect(verified.status).toBe('verified');
    expect(verified.verified).toBe(true);
    expect(verified.payload).toBe(payload);

    const tampered = signed.replace('Alice', 'Mallory');
    const invalid = await client.auth.verifyAgentMd(tampered, {
      aid: identity.aid,
      certPem: identity.cert,
    });
    expect(invalid.status).toBe('invalid');
    expect(invalid.verified).toBe(false);
  });

  it('signAgentMd 重新签名时应替换已有签名块', async () => {
    const client = new AUNClient();
    const identity = makeIdentity('alice.agentid.pub');
    (client as any)._aid = identity.aid;
    (client as any)._auth.loadIdentityOrNone = vi.fn().mockResolvedValue(identity);

    const payload = '---\naid: "alice.agentid.pub"\nname: "Alice"\n---\n\n# Alice\n';
    const signedOnce = await client.auth.signAgentMd(payload);
    const signedTwice = await client.auth.signAgentMd(signedOnce);

    expect((signedTwice.match(/<!-- AUN-SIGNATURE/g) ?? []).length).toBe(1);
    expect(signedTwice.startsWith(payload)).toBe(true);
  });
});
