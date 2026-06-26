import 'fake-indexeddb/auto';
import crypto from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

import { AID, AIDStore, AUNClient, ConnectionState, CryptoProvider, IndexedDBIdentityStore, resultErr, resultOk } from '../../src/index.js';

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
    await client.call('group.send', { group_id: 'group.agentid.pub/grp01', payload: { text: 'hi' }, encrypt: false, headers: { priority: 3, payload_type: 'text' } });
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

describe('AIDStore 群身份导入', () => {
  it('importGroupIdentity 校验证书和公钥后落盘，重新 load 后可签名', async () => {
    const groupAid = 'team-import.agentid.pub';
    const identity = makeIdentity(groupAid);
    const store = new AIDStore({ aunPath: 'browser-aun-group-import', encryptionSeed: 'group-seed' });

    const imported = await store.importGroupIdentity(groupAid, {
      private_key_pem: identity.private_key_pem,
      public_key_der_b64: identity.public_key_der_b64,
      curve: 'P-256',
      cert_pem: identity.cert,
    });

    expect(imported.ok).toBe(true);
    const loaded = await store.load(groupAid);
    expect(loaded.ok).toBe(true);
    const sign = loaded.ok ? await loaded.data.aid.sign('group-fs-probe') : resultErr('X', 'not loaded');
    expect(sign.ok).toBe(true);
  });

  it('importGroupIdentity 拒绝 CN 与 aid 不一致的证书', async () => {
    const identity = makeIdentity('other.agentid.pub');
    const store = new AIDStore({ aunPath: 'browser-aun-group-cn', encryptionSeed: 'group-seed' });

    const imported = await store.importGroupIdentity('team-cn.agentid.pub', {
      private_key_pem: identity.private_key_pem,
      public_key_der_b64: identity.public_key_der_b64,
      cert_pem: identity.cert,
    });

    expect(imported.ok).toBe(false);
    expect((imported as any).error.code).toBe('CERT_CHAIN_BROKEN');
  });

  it('importGroupIdentity 拒绝证书公钥与 public_key_der_b64 不一致', async () => {
    const groupAid = 'team-pub.agentid.pub';
    const certIdentity = makeIdentity(groupAid);
    const otherIdentity = makeIdentity(groupAid);
    const store = new AIDStore({ aunPath: 'browser-aun-group-pub', encryptionSeed: 'group-seed' });

    const imported = await store.importGroupIdentity(groupAid, {
      private_key_pem: certIdentity.private_key_pem,
      public_key_der_b64: otherIdentity.public_key_der_b64,
      cert_pem: certIdentity.cert,
    });

    expect(imported.ok).toBe(false);
    expect((imported as any).error.code).toBe('KEYPAIR_MISMATCH');
  });

  it('importGroupIdentity 拒绝证书与私钥不匹配', async () => {
    const groupAid = 'team-priv.agentid.pub';
    const certIdentity = makeIdentity(groupAid);
    const otherIdentity = makeIdentity(groupAid);
    const store = new AIDStore({ aunPath: 'browser-aun-group-priv', encryptionSeed: 'group-seed' });

    const imported = await store.importGroupIdentity(groupAid, {
      private_key_pem: otherIdentity.private_key_pem,
      public_key_der_b64: certIdentity.public_key_der_b64,
      cert_pem: certIdentity.cert,
    });

    expect(imported.ok).toBe(false);
    expect((imported as any).error.code).toBe('KEYPAIR_MISMATCH');
  });
});

describe('AUNClient.createGroup 高层编排', () => {
  it('有 group_name 时生成群密钥，传 public_key/curve，并导入 group_aid 身份', async () => {
    const ownerAid = await createStoredAid('owner-create.agentid.pub');
    const groupAid = 'named-team.agentid.pub';
    const identity = makeIdentity(groupAid);
    const generateSpy = vi.spyOn(CryptoProvider.prototype, 'generateIdentity').mockResolvedValue({
      private_key_pem: identity.private_key_pem,
      public_key_der_b64: identity.public_key_der_b64,
      curve: 'P-256',
    });
    const client = new AUNClient(ownerAid);
    const callSpy = vi.fn(async (method: string, params: Record<string, unknown>) => {
      expect(method).toBe('group.create');
      expect(params.group_name).toBe('named-team');
      expect(params.public_key).toBe(identity.public_key_der_b64);
      expect(params.curve).toBe('P-256');
      return {
        group: { group_id: 'group.agentid.pub/10001', group_aid: groupAid },
        aid_cert: { cert: identity.cert, curve: 'P-256' },
      };
    });
    (client as any)._rpcPipeline.call = callSpy;

    try {
      const result = await client.createGroup({ group_name: 'named-team', visibility: 'private' });

      expect((result as any).group.group_aid).toBe(groupAid);
      expect(callSpy).toHaveBeenCalledTimes(1);
      const groupStore = new AIDStore({ aunPath: ownerAid.aunPath, encryptionSeed: '' });
      const loaded = await groupStore.load(groupAid);
      expect(loaded.ok).toBe(true);
      expect(loaded.ok ? (await loaded.data.aid.sign('group-fs-probe')).ok : false).toBe(true);
    } finally {
      generateSpy.mockRestore();
    }
  });

  it('无 group_name 时原样透传 group.create', async () => {
    const ownerAid = await createStoredAid('owner-plain.agentid.pub');
    const client = new AUNClient(ownerAid);
    const callSpy = vi.fn(async (_method: string, params: Record<string, unknown>) => ({ group: { group_id: 'group.agentid.pub/10002' }, params }));
    (client as any)._rpcPipeline.call = callSpy;

    const result = await client.createGroup({ name: 'plain-team' });

    expect(callSpy).toHaveBeenCalledWith('group.create', { name: 'plain-team' });
    expect((result as any).params.public_key).toBeUndefined();
  });
});

describe('AUNClient.bindGroupAid 高层编排', () => {
  it('匿名群升级生成群密钥，调用 group.bind_group_aid，并按服务端 group_aid 导入', async () => {
    const ownerAid = await createStoredAid('owner-bind.agentid.pub');
    const groupAid = 'bound-anon.agentid.pub';
    const identity = makeIdentity(groupAid);
    const generateSpy = vi.spyOn(CryptoProvider.prototype, 'generateIdentity').mockResolvedValue({
      private_key_pem: identity.private_key_pem,
      public_key_der_b64: identity.public_key_der_b64,
      curve: 'P-256',
    });
    const client = new AUNClient(ownerAid);
    const groupStore = new AIDStore({ aunPath: ownerAid.aunPath, encryptionSeed: 'test-seed' });
    const callSpy = vi.fn(async (method: string, params: Record<string, unknown>) => {
      expect(method).toBe('group.bind_group_aid');
      expect(params.group_id).toBe('group.agentid.pub/10003');
      expect(Object.prototype.hasOwnProperty.call(params, 'group_name')).toBe(false);
      expect(params.public_key).toBe(identity.public_key_der_b64);
      expect(params.curve).toBe('P-256');
      return {
        group: { group_id: 'group.agentid.pub/10003', group_aid: groupAid },
        aid_cert: { cert: identity.cert, curve: 'P-256' },
      };
    });
    (client as any)._rpcPipeline.call = callSpy;

    try {
      const result = await client.bindGroupAid({ group_id: 'group.agentid.pub/10003' }, { aidStore: groupStore });

      expect((result as any).group.group_aid).toBe(groupAid);
      expect(callSpy).toHaveBeenCalledTimes(1);
      const loaded = await groupStore.load(groupAid);
      expect(loaded.ok).toBe(true);
      expect(loaded.ok ? (await loaded.data.aid.sign('group-fs-bind-probe')).ok : false).toBe(true);
    } finally {
      generateSpy.mockRestore();
      groupStore.close();
    }
  });

  it('缺少 aidStore 时拒绝且不发 RPC', async () => {
    const ownerAid = await createStoredAid('owner-bind-no-store.agentid.pub');
    const client = new AUNClient(ownerAid);
    const callSpy = vi.fn();
    (client as any)._rpcPipeline.call = callSpy;

    await expect(client.bindGroupAid({ group_id: 'group.agentid.pub/10004' })).rejects.toThrow(/aidStore/);
    expect(callSpy).not.toHaveBeenCalled();
  });
});

describe('AUNClient.completeGroupTransfer 高层编排', () => {
  it('新群主生成群密钥，调用 group.complete_transfer，并导入新的 group_aid 身份', async () => {
    const ownerAid = await createStoredAid('owner-transfer.agentid.pub');
    const groupAid = 'transferred-team.agentid.pub';
    const identity = makeIdentity(groupAid);
    const generateSpy = vi.spyOn(CryptoProvider.prototype, 'generateIdentity').mockResolvedValue({
      private_key_pem: identity.private_key_pem,
      public_key_der_b64: identity.public_key_der_b64,
      curve: 'P-256',
    });
    const client = new AUNClient(ownerAid);
    const groupStore = new AIDStore({ aunPath: ownerAid.aunPath, encryptionSeed: 'test-seed' });
    const callSpy = vi.fn(async (method: string, params: Record<string, unknown>) => {
      if (method === 'group.get') {
        expect(params).toEqual({ group_id: 'group.agentid.pub/10005' });
        return { group: { group_id: 'group.agentid.pub/10005', group_aid: groupAid } };
      }
      expect(method).toBe('group.complete_transfer');
      expect(params.group_id).toBe('group.agentid.pub/10005');
      expect(params.group_aid).toBe(groupAid);
      expect(params.public_key).toBe(identity.public_key_der_b64);
      expect(params.curve).toBe('P-256');
      expect((params.transfer_accept as any)?.signature).toEqual(expect.any(String));
      return {
        status: 'transferred',
        group: { group_id: 'group.agentid.pub/10005', group_aid: groupAid },
        aid_cert: { cert: identity.cert, curve: 'P-256', key_purpose: 'group_identity' },
      };
    });
    (client as any)._rpcPipeline.call = callSpy;

    try {
      const result = await client.completeGroupTransfer({ group_id: 'group.agentid.pub/10005' }, { aidStore: groupStore });

      expect((result as any).group.group_aid).toBe(groupAid);
      expect(callSpy).toHaveBeenCalledTimes(2);
      const loaded = await groupStore.load(groupAid);
      expect(loaded.ok).toBe(true);
      expect(loaded.ok ? (await loaded.data.aid.sign('group-fs-transfer-probe')).ok : false).toBe(true);
    } finally {
      generateSpy.mockRestore();
      groupStore.close();
    }
  });

  it('缺少 aidStore 时拒绝且不发 RPC', async () => {
    const ownerAid = await createStoredAid('owner-transfer-no-store.agentid.pub');
    const client = new AUNClient(ownerAid);
    const callSpy = vi.fn();
    (client as any)._rpcPipeline.call = callSpy;

    await expect(client.completeGroupTransfer({ group_id: 'group.agentid.pub/10006' })).rejects.toThrow(/aidStore/);
    expect(callSpy).not.toHaveBeenCalled();
  });
});

describe('AUNClient.startGroupTransfer 高层编排', () => {
  it('group_aid 只有证书无私钥时拒绝且不发 transfer RPC', async () => {
    const ownerAid = await createStoredAid('owner-start-no-key.agentid.pub');
    const groupAid = 'start-no-key.agentid.pub';
    const identity = makeIdentity(groupAid);
    const keyStore = new IndexedDBIdentityStore({ encryptionSeed: 'test-seed' });
    await keyStore.saveCert(groupAid, identity.cert);
    const groupStore = new AIDStore({ aunPath: 'browser-aun-start-no-key', encryptionSeed: 'test-seed' });
    const client = new AUNClient(ownerAid);
    const callSpy = vi.fn(async (method: string) => {
      if (method === 'group.get') return { group: { group_id: 'group.agentid.pub/10007', group_aid: groupAid } };
      return { ok: true };
    });
    (client as any)._rpcPipeline.call = callSpy;

    await expect(client.startGroupTransfer(
      { group_id: 'group.agentid.pub/10007', new_owner: 'new-owner.agentid.pub' },
      { aidStore: groupStore },
    )).rejects.toThrow(/private key not found/);

    expect(callSpy).toHaveBeenCalledTimes(1);
    expect(callSpy).toHaveBeenCalledWith('group.get', { group_id: 'group.agentid.pub/10007' });
    groupStore.close();
  });
});
