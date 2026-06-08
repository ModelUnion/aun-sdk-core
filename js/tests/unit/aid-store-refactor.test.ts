import 'fake-indexeddb/auto';
import crypto from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

import { AID, AIDStore, AUNClient, ConnectionState, IndexedDBIdentityStore, resultErr, resultOk } from '../../src/index.js';

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
  const parts = [
    String(date.getUTCFullYear() % 100).padStart(2, '0'),
    String(date.getUTCMonth() + 1).padStart(2, '0'),
    String(date.getUTCDate()).padStart(2, '0'),
    String(date.getUTCHours()).padStart(2, '0'),
    String(date.getUTCMinutes()).padStart(2, '0'),
    String(date.getUTCSeconds()).padStart(2, '0'),
    'Z',
  ];
  return derTag(0x17, Buffer.from(parts.join(''), 'utf8'));
}
function derContextConstructed(tagNumber: number, content: Buffer): Buffer { return derTag(0xa0 + tagNumber, content); }

function makeIdentity(aid: string): { aid: string; private_key_pem: string; public_key_der_b64: string; cert: string } {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicKeyDer = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }) as Buffer;
  const sigAlgOid = Buffer.from([0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
  const name = derSequence(derSet(derSequence(Buffer.concat([Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]), derUtf8String(Buffer.from(aid, 'utf8'))]))));
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
  const cert = `-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n`;
  return {
    aid,
    private_key_pem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    public_key_der_b64: publicKeyDer.toString('base64'),
    cert,
  };
}

async function createStoredAid(aid = 'alice.agentid.pub'): Promise<AID> {
  const identity = makeIdentity(aid);
  const keyStore = new IndexedDBIdentityStore({ encryptionSeed: 'test-seed' });
  await keyStore.saveIdentity(aid, identity);
  const store = new AIDStore({ aunPath: 'browser-aun', encryptionSeed: 'test-seed' });
  const loaded = await store.load(aid);
  expect(loaded.ok).toBe(true);
  return loaded.ok ? loaded.data.aid : (null as never);
}

describe('浏览器 SDK v4 三主体 API', () => {
  it('入口导出 Result / AID / AIDStore，并支持 AID 签验 agent.md', async () => {
    expect(resultOk({ value: 1 }).ok).toBe(true);
    expect(resultErr('X', 'failed').ok).toBe(false);
    const aid = await createStoredAid();
    const signed = await aid.signAgentMd('---\naid: "alice.agentid.pub"\n---\n# Alice\n');
    expect(signed.ok).toBe(true);
    const verified = signed.ok ? await aid.verifyAgentMd(signed.data.signed) : resultErr('X', 'no signed');
    expect(verified.ok && verified.data.status).toBe('verified');
  });

  it('AUNClient(AID) 初始为 standby，并暴露 capability getter', async () => {
    const aid = await createStoredAid('bob.agentid.pub');
    const client = new AUNClient(aid);
    expect(client.state).toBe(ConnectionState.STANDBY);
    expect(client.currentAid?.aid).toBe('bob.agentid.pub');
    expect(client.hasIdentity).toBe(true);
    expect(client.canSign).toBe(true);
    expect(client.canConnect).toBe(true);
    expect(client.canSend).toBe(false);
  });

  it('loadIdentity 使用 AIDStore 写入的运行上下文重绑定 client 内部组件', async () => {
    const aid = await createStoredAid('ctx.agentid.pub');
    const client = new AUNClient();

    client.loadIdentity(aid);

    expect(client.aunPath).toBe(aid.aunPath);
    expect((client as any).configModel.aunPath).toBe(aid.aunPath);
    expect((client as any)._deviceId).toBe(aid.deviceId);
    expect((client as any)._slotId).toBe(aid.slotId);
    expect((client as any)._auth._deviceId).toBe(aid.deviceId);
    expect((client as any)._auth._slotId).toBe(aid.slotId);
  });

  it('AIDStore 注册持久化路径应保留私钥材料', async () => {
    const aidStr = 'reg-persist.agentid.pub';
    const identity = makeIdentity(aidStr);
    const keyStore = new IndexedDBIdentityStore({ encryptionSeed: 'reg-persist-seed' });
    await keyStore.saveKeyPair(aidStr, {
      private_key_pem: identity.private_key_pem,
      public_key_der_b64: identity.public_key_der_b64,
    });
    await keyStore.saveCert(aidStr, identity.cert);

    const store = new AIDStore({ aunPath: 'browser-aun-reg', encryptionSeed: 'reg-persist-seed' });
    const loaded = await store.load(aidStr);

    expect(loaded.ok).toBe(true);
    expect(loaded.ok ? loaded.data.aid.isPrivateKeyValid() : false).toBe(true);
  });

  it('构造函数只接受 AID 对象或无参，不接受旧配置对象', () => {
    expect(() => new (AUNClient as any)('alice.agentid.pub')).toThrow(/AID object/);
    expect(() => new (AUNClient as any)({})).toThrow(/AID object/);
    expect(() => new (AUNClient as any)({ aun_path: '/tmp/aun' })).toThrow(/AID object/);
    expect(() => new (AUNClient as any)({ aid: 'alice.agentid.pub' })).toThrow(/AID object/);
  });

  it('实例级 protected_headers 只合并到消息类 RPC', async () => {
    const aid = await createStoredAid('dave.agentid.pub');
    const client = new (AUNClient as any)(aid);
    client.setProtectedHeaders({ app: 'sdk-test', priority: 1 });
    (client as unknown as { _state: string })._state = 'connected';
    const calls: Array<{ method: string; params: Record<string, unknown> }> = [];
    (client as unknown as { _transport: { call: (method: string, params: Record<string, unknown>) => Promise<Record<string, unknown>> } })._transport = {
      call: vi.fn(async (method: string, params: Record<string, unknown>) => {
        calls.push({ method, params });
        return { ok: true };
      }),
    };
    await client.call('meta.ping', {});
    await client.call('message.send', { to: 'peer.agentid.pub', payload: { text: 'hi' }, encrypt: false, protected_headers: { priority: 2 } });
    await client.call('group.send', { group_id: 'group.agentid.pub/g1', payload: { text: 'hi' }, encrypt: false, headers: { priority: 3, payload_type: 'text' } });
    expect(calls[0]!.params.protected_headers).toBeUndefined();
    expect(calls[1]!.params.protected_headers).toEqual({ app: 'sdk-test', priority: 2 });
    expect(calls[2]!.params.protected_headers).toEqual({ app: 'sdk-test', priority: 3, payload_type: 'text' });
  });
});

// ── 证书元数据属性测试 ────────────────────────────────────────────

describe('AID 证书元数据属性', () => {
  it('load 后 certSubject 非空且等于 aid', async () => {
    const aid = await createStoredAid('meta-test.agentid.pub');
    expect(typeof aid.certSubject).toBe('string');
    expect(aid.certSubject).toBe('meta-test.agentid.pub');
  });

  it('load 后 certNotBefore 是 Date 且在过去', async () => {
    const aid = await createStoredAid('meta-nb.agentid.pub');
    expect(aid.certNotBefore).toBeInstanceOf(Date);
    expect(aid.certNotBefore.getTime()).toBeLessThan(Date.now());
  });

  it('load 后 certNotAfter 是 Date 且在未来', async () => {
    const aid = await createStoredAid('meta-na.agentid.pub');
    expect(aid.certNotAfter).toBeInstanceOf(Date);
    expect(aid.certNotAfter.getTime()).toBeGreaterThan(Date.now());
  });

  it('load 后 certIssuer 非空', async () => {
    const aid = await createStoredAid('meta-issuer.agentid.pub');
    expect(typeof aid.certIssuer).toBe('string');
    expect(aid.certIssuer.length).toBeGreaterThan(0);
  });
});

describe('AIDStore.list() AIDInfo 元数据字段', () => {
  it('list() 返回的 AIDInfo 包含 certNotAfter 和 certIssuer', async () => {
    const aidStr = 'list-meta.agentid.pub';
    const identity = makeIdentity(aidStr);
    const keyStore = new IndexedDBIdentityStore({ encryptionSeed: 'list-meta-seed' });
    await keyStore.saveIdentity(aidStr, identity);
    const store = new AIDStore({ aunPath: 'browser-aun-list', encryptionSeed: 'list-meta-seed' });
    const result = await store.list();
    expect(result.ok).toBe(true);
    const info = result.ok ? result.data.identities.find(i => i.aid === aidStr) : undefined;
    expect(info).toBeDefined();
    expect(info!.certNotAfter).toBeInstanceOf(Date);
    expect(info!.certNotAfter.getTime()).toBeGreaterThan(Date.now());
    expect(typeof info!.certIssuer).toBe('string');
    expect(info!.certIssuer.length).toBeGreaterThan(0);
  });
});
