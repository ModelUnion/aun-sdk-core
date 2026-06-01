import 'fake-indexeddb/auto';
import crypto from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { AIDStore, IndexedDBIdentityStore } from '../../src/index.js';

function derLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  if (len < 0x100) return Buffer.from([0x81, len]);
  return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
}
function derTag(tag: number, content: Buffer): Buffer { return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]); }
function derSequence(content: Buffer): Buffer { return derTag(0x30, content); }
function derSet(content: Buffer): Buffer { return derTag(0x31, content); }
function derInteger(value: Buffer): Buffer {
  if (value[0]! & 0x80) value = Buffer.concat([Buffer.from([0x00]), value]);
  return derTag(0x02, value);
}
function derBitString(content: Buffer): Buffer { return derTag(0x03, Buffer.concat([Buffer.from([0x00]), content])); }
function derOctetString(content: Buffer): Buffer { return derTag(0x04, content); }
function derUtf8String(content: Buffer): Buffer { return derTag(0x0c, content); }
function derUtcTime(date: Date): Buffer {
  const text = [
    String(date.getUTCFullYear() % 100).padStart(2, '0'),
    String(date.getUTCMonth() + 1).padStart(2, '0'),
    String(date.getUTCDate()).padStart(2, '0'),
    String(date.getUTCHours()).padStart(2, '0'),
    String(date.getUTCMinutes()).padStart(2, '0'),
    String(date.getUTCSeconds()).padStart(2, '0'),
    'Z',
  ].join('');
  return derTag(0x17, Buffer.from(text, 'utf8'));
}
function derContextConstructed(tagNumber: number, content: Buffer): Buffer { return derTag(0xa0 + tagNumber, content); }

function makeIdentity(aid: string): { aid: string; private_key_pem: string; public_key_der_b64: string; curve: string; cert: string } {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicKeyDer = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }) as Buffer;
  const sigAlgOid = Buffer.from([0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
  const name = derSequence(derSet(derSequence(Buffer.concat([
    Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]),
    derUtf8String(Buffer.from(aid, 'utf8')),
  ]))));
  const tbs = derSequence(Buffer.concat([
    derContextConstructed(0, derInteger(Buffer.from([0x02]))),
    derInteger(crypto.randomBytes(16)),
    sigAlgOid,
    name,
    derSequence(Buffer.concat([derUtcTime(new Date(Date.now() - 60_000)), derUtcTime(new Date(Date.now() + 3600_000))])),
    name,
    publicKeyDer,
    derContextConstructed(3, derSequence(derSequence(Buffer.concat([
      Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x13]),
      Buffer.from([0x01, 0x01, 0xff]),
      derOctetString(derSequence(Buffer.from([0x01, 0x01, 0xff]))),
    ])))),
  ]));
  const signer = crypto.createSign('SHA256');
  signer.update(tbs);
  signer.end();
  const certDer = derSequence(Buffer.concat([tbs, sigAlgOid, derBitString(signer.sign(privateKey))]));
  const b64 = certDer.toString('base64');
  return {
    aid,
    private_key_pem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    public_key_der_b64: publicKeyDer.toString('base64'),
    curve: 'P-256',
    cert: `-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n`,
  };
}

async function storeWithIdentity(aid: string): Promise<{ store: AIDStore; identity: ReturnType<typeof makeIdentity> }> {
  const identity = makeIdentity(aid);
  const keyStore = new IndexedDBIdentityStore({ encryptionSeed: 'network-seed' });
  await keyStore.saveIdentity(aid, identity);
  return { store: new AIDStore({ aunPath: 'browser-aun-network', encryptionSeed: 'network-seed' }), identity };
}

function response(body: BodyInit | null, init: ResponseInit): Response {
  return new Response(body, init);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('浏览器 AIDStore 阶段2联网方法', () => {
  it('register / exists / diagnose 使用 gateway discovery 和 PKI HEAD', async () => {
    const { store } = await storeWithIdentity('alice.agentid.pub');
    vi.spyOn(store as any, '_resolveGateway').mockResolvedValue('wss://gateway.agentid.pub/aun');
    const registerSpy = vi.spyOn((store as any)._registerFlow, 'registerAid').mockResolvedValue({ aid: 'alice.agentid.pub' });
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response('', { status: 200 }));

    const registered = await store.register('alice.agentid.pub');
    expect(registered.ok && registered.data.registered).toBe(true);
    expect(registerSpy).toHaveBeenCalledWith('wss://gateway.agentid.pub/aun', 'alice.agentid.pub');

    const exists = await store.exists('alice.agentid.pub');
    expect(exists.ok && exists.data.exists).toBe(true);
    expect(fetchSpy).toHaveBeenCalledWith(
      'https://gateway.agentid.pub/pki/cert/alice.agentid.pub',
      expect.objectContaining({ method: 'HEAD' }),
    );

    vi.spyOn(store, 'exists').mockResolvedValue({ ok: true, data: { exists: true } });
    const diagnosed = await store.diagnose('alice.agentid.pub');
    expect(diagnosed.ok && diagnosed.data.status).toBe('ready');
    expect(diagnosed.ok && (diagnosed.data as any).remote_registered).toBe(true);
  });

  it('resolve / downloadAgentMd / checkAgentMd 完成证书缓存和 agent.md 验签', async () => {
    const aid = 'boba.agentid.pub';
    const { store, identity } = await storeWithIdentity(aid);
    const loaded = await store.load(aid);
    expect(loaded.ok).toBe(true);
    const signed = loaded.ok ? await loaded.data.aid.signAgentMd(`---\naid: "${aid}"\n---\n# Bob\n`) : null;
    expect(signed?.ok).toBe(true);
    const remoteEtag = signed?.ok
      ? `"${crypto.createHash('sha256').update(signed.data.signed, 'utf8').digest('hex')}"`
      : '"bob-etag"';

    vi.spyOn(store as any, '_resolveGateway').mockResolvedValue('wss://gateway.agentid.pub/aun');
    vi.spyOn((store as any)._registerFlow, 'fetchPeerCert').mockResolvedValue(identity.cert);
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init?: RequestInit) => {
      const method = String(init?.method ?? 'GET').toUpperCase();
      if (method === 'HEAD') {
        return response('', {
          status: 200,
          headers: {
            ETag: remoteEtag,
            'Last-Modified': 'Fri, 29 May 2026 10:00:00 GMT',
            'Content-Length': String(signed?.ok ? signed.data.signed.length : 0),
          },
        });
      }
      return response(signed?.ok ? signed.data.signed : '', {
        status: 200,
        headers: {
          ETag: remoteEtag,
          'Last-Modified': 'Fri, 29 May 2026 10:00:00 GMT',
        },
      });
    });

    const resolved = await store.resolve(aid, { forceRefresh: true });
    expect(resolved.ok).toBe(true);
    expect(resolved.ok && (resolved.data.agent_md as any).verification.status).toBe('verified');
    expect(resolved.ok && (resolved.data.source as any).cert_from_cache).toBe(false);

    const fetched = await store.downloadAgentMd(aid);
    expect(fetched.ok && (fetched.data.verification as any).status).toBe('verified');
    expect(fetched.ok && fetched.data.etag).toBe(remoteEtag);

    const checked = await store.checkAgentMd(aid);
    expect(checked.ok && checked.data.needs_update).toBe(false);
    expect(checked.ok && checked.data.local_found).toBe(true);
  });

  it('downloadAgentMd 收到 304 且无正文缓存时应无条件 GET 重试', async () => {
    const aid = 'bobb.agentid.pub';
    const { store } = await storeWithIdentity(aid);
    const loaded = await store.load(aid);
    expect(loaded.ok).toBe(true);
    const signed = loaded.ok ? await loaded.data.aid.signAgentMd(`---\naid: "${aid}"\n---\n# Bob\n`) : null;
    expect(signed?.ok).toBe(true);

    vi.spyOn(store as any, '_resolveGateway').mockResolvedValue('wss://gateway.agentid.pub/aun');
    await (store as any)._agentMdManager.saveRecord(aid, { remote_etag: '"head-only"' });
    const calls: Array<Record<string, string>> = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init?: RequestInit) => {
      calls.push(Object.fromEntries(new Headers(init?.headers).entries()));
      if (calls.length === 1) return response(null, { status: 304, headers: { ETag: '"head-only"' } });
      return response(signed?.ok ? signed.data.signed : '', { status: 200, headers: { ETag: '"head-only"' } });
    });

    const fetched = await store.downloadAgentMd(aid);

    expect(fetched.ok && fetched.data.content).toBe(signed?.ok ? signed.data.signed : '');
    expect(calls).toHaveLength(2);
    expect(calls[0]?.['if-none-match']).toBeUndefined();
    expect(calls[0]?.['if-modified-since']).toBeUndefined();
    expect(calls[1]?.['if-none-match']).toBeUndefined();
    expect(calls[1]?.['if-modified-since']).toBeUndefined();
  });

  it('renewCert / rekey 使用私钥签名挑战并写回新证书材料', async () => {
    const aid = 'carol.agentid.pub';
    const { store, identity } = await storeWithIdentity(aid);
    vi.spyOn(store as any, '_resolveGateway').mockResolvedValue('wss://gateway.agentid.pub/aun');

    const renewRpc = vi.fn(async (_url: string, method: string) => {
      if (method === 'auth.aid_login1') return { request_id: 'renew-1', nonce: 'nonce-renew' };
      return { cert: identity.cert };
    });
    vi.spyOn((store as any)._registerFlow, 'shortRpc').mockImplementation(renewRpc as any);
    vi.spyOn((store as any)._registerFlow, 'verifyPhase1Response').mockResolvedValue(undefined);

    const renewed = await store.renewCert(aid);
    expect(renewed.ok && renewed.data.renewed).toBe(true);
    expect(renewRpc).toHaveBeenCalledWith(
      'wss://gateway.agentid.pub/aun',
      'auth.renew_cert',
      expect.objectContaining({ aid, request_id: 'renew-1', nonce: 'nonce-renew' }),
    );

    const nextIdentity = makeIdentity(aid);
    vi.spyOn((store as any)._registerFlow, 'generateIdentity').mockResolvedValue(nextIdentity);
    const rekeyRpc = vi.fn(async (_url: string, method: string) => {
      if (method === 'auth.aid_login1') return { request_id: 'rekey-1', nonce: 'nonce-rekey' };
      return { cert: nextIdentity.cert };
    });
    vi.spyOn((store as any)._registerFlow, 'shortRpc').mockImplementation(rekeyRpc as any);

    const rekeyed = await store.rekey(aid);
    expect(rekeyed.ok && rekeyed.data.rekeyed).toBe(true);
    expect(rekeyRpc).toHaveBeenCalledWith(
      'wss://gateway.agentid.pub/aun',
      'auth.rekey',
      expect.objectContaining({
        aid,
        request_id: 'rekey-1',
        nonce: 'nonce-rekey',
        new_public_key: nextIdentity.public_key_der_b64,
      }),
    );
  });
});
