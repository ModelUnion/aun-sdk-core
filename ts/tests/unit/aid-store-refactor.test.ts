import { describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AID, AIDStore, AUNClient, ConnectionState, CryptoProvider, LocalIdentityStore, resultErr, resultOk } from '../../src/index.js';
import { buildIdentity, generateECKeypair, makeSelfSignedCert } from './helpers.js';

function createStoredAid(aid = 'alice.agentid.pub'): { aid: AID; aunPath: string } {
  const aunPath = mkdtempSync(join(tmpdir(), 'aun-ts-refactor-'));
  const { privateKey } = generateECKeypair();
  const identity = buildIdentity(aid, privateKey);
  const keyStore = new LocalIdentityStore(aunPath, { encryptionSeed: 'test-seed' });
  keyStore.saveIdentity(aid, identity);

  const store = new AIDStore({ aunPath, encryptionSeed: 'test-seed', verifySsl: true });
  const loaded = store.load(aid);
  expect(loaded.ok).toBe(true);
  return { aid: loaded.ok ? loaded.data.aid : (null as never), aunPath };
}

describe('AUN SDK v4 三主体 API', () => {
  it('入口导出 Result / AID / AIDStore，并支持 AID 签验 agent.md', () => {
    expect(resultOk({ value: 1 }).ok).toBe(true);
    expect(resultErr('X', 'failed').ok).toBe(false);

    const { aid } = createStoredAid();
    const signed = aid.signAgentMd('---\naid: "alice.agentid.pub"\n---\n# Alice\n');
    expect(signed.ok).toBe(true);
    const verified = signed.ok ? aid.verifyAgentMd(signed.data.signed) : resultErr('X', 'no signed');
    expect(verified.ok && verified.data.status).toBe('verified');
  });

  it('AUNClient(AID) 初始为 standby，并暴露 capability getter', () => {
    const { aid } = createStoredAid('bob.agentid.pub');
    const client = new AUNClient(aid);
    expect(client.state).toBe(ConnectionState.STANDBY);
    expect(client.currentAid?.aid).toBe('bob.agentid.pub');
    expect(client.hasIdentity).toBe(true);
    expect(client.canSign).toBe(true);
    expect(client.canConnect).toBe(true);
    expect(client.canSend).toBe(false);
    expect(client.aunPath).toBe(aid.aunPath);
    expect((client as any).auth).toBeUndefined();
    expect((client as any).meta).toBeUndefined();
    expect((client as any).custody).toBeUndefined();
  });

  it('loadIdentity 仅允许 no_identity/closed 状态', async () => {
    const { aid } = createStoredAid('carol.agentid.pub');
    const client = new AUNClient();
    expect(client.state).toBe(ConnectionState.NO_IDENTITY);
    client.loadIdentity(aid);
    expect(client.state).toBe(ConnectionState.STANDBY);
    expect(() => client.loadIdentity(aid)).toThrow(/not allowed/);
    await client.close();
    client.loadIdentity(aid);
    expect(client.state).toBe(ConnectionState.STANDBY);
  });

  it('loadIdentity 使用 AIDStore 写入的运行上下文重绑定 client 内部组件', () => {
    const { aid, aunPath } = createStoredAid('ctx.agentid.pub');
    const client = new AUNClient();

    client.loadIdentity(aid);

    expect(client.aunPath).toBe(aunPath);
    expect((client as any)._configModel.aunPath).toBe(aunPath);
    expect((client as any)._deviceId).toBe(aid.deviceId);
    expect((client as any)._slotId).toBe(aid.slotId);
    expect((client as any)._tokenStore._root).toBe(aunPath);
    expect((client as any)._auth._deviceId).toBe(aid.deviceId);
    expect((client as any)._auth._slotId).toBe(aid.slotId);
  });

  it('构造函数只接受 AID 对象或无参，不接受旧配置对象', () => {
    expect(() => new (AUNClient as any)('alice.agentid.pub')).toThrow(/AID object/);
    expect(() => new (AUNClient as any)({})).toThrow(/AID object/);
    expect(() => new (AUNClient as any)({ aun_path: '/tmp/aun' })).toThrow(/AID object/);
    expect(() => new (AUNClient as any)({ aid: 'alice.agentid.pub' })).toThrow(/AID object/);
  });

  it('connect 只接受 options，不接受旧版 aid/token 参数', async () => {
    const { aid } = createStoredAid('erin.agentid.pub');
    const client = new AUNClient(aid);
    await expect(client.connect({ access_token: 'tok', gateway: 'ws://localhost/aun' } as any)).rejects.toThrow(/unsupported field\(s\): access_token, gateway/);
    await expect(client.connect({ aid: 'erin.agentid.pub' } as any)).rejects.toThrow(/unsupported field\(s\): aid/);
  });

  it('gateway 发现应使用完整 issuer 域名并持久化 gateway_url', async () => {
    const { aid } = createStoredAid('frank.agentid.pub');
    const client = new AUNClient(aid);
    const discover = vi.fn(async () => 'wss://gateway.agentid.pub/aun');
    (client as any)._discovery.discover = discover;

    const gateway = await (client as any)._resolveGatewayForAid(aid.aid);

    expect(gateway).toBe('wss://gateway.agentid.pub/aun');
    expect(discover).toHaveBeenCalledWith('https://frank.agentid.pub/.well-known/aun-gateway');
    expect(((client as any)._tokenStore.loadMetadata(aid.aid) ?? {}).gateway_url).toBe('wss://gateway.agentid.pub/aun');

    const store = new AIDStore({ aunPath: aid.aunPath, encryptionSeed: 'test-seed' });
    const storeDiscover = vi.fn(async () => 'wss://gateway.agentid.pub/aun');
    (store as any)._discovery.discover = storeDiscover;
    await (store as any)._resolveGateway(aid.aid);
    expect(storeDiscover).toHaveBeenCalledWith('https://gateway.agentid.pub/.well-known/aun-gateway');
  });

  it('实例级 protected_headers 只合并到消息类 RPC', async () => {
    const { aid } = createStoredAid('dave.agentid.pub');
    const client = new AUNClient(aid);
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

    expect(calls[0].params.protected_headers).toBeUndefined();
    expect(calls[1].params.protected_headers).toEqual({ app: 'sdk-test', priority: 2 });
    expect(calls[2].params.protected_headers).toEqual({ app: 'sdk-test', priority: 3, payload_type: 'text' });
    expect(client.getProtectedHeaders()).toEqual({ app: 'sdk-test', priority: '1' });
  });
});

describe('AIDStore 私钥自检', () => {
  it('证书与私钥不匹配且 key.json 缺 public_key_der_b64 时 load() 返回 KEYPAIR_MISMATCH', () => {
    const aid = 'mismatch.agentid.pub';
    const aunPath = mkdtempSync(join(tmpdir(), 'aun-ts-mismatch-'));

    // 用 keyA 生成证书（CN=aid），但只存入 keyB 的私钥 —— 错配
    const { privateKey: keyA } = generateECKeypair();
    const { privateKey: keyB } = generateECKeypair();
    const certPem = makeSelfSignedCert(keyA, aid);
    const privBPem = keyB.export({ type: 'pkcs8', format: 'pem' }) as string;

    // 故意不写 public_key_der_b64 字段：这正是死代码无法检出错配的场景
    const keyStore = new LocalIdentityStore(aunPath, { encryptionSeed: 'test-seed' });
    keyStore.saveIdentity(aid, {
      private_key_pem: privBPem,
      cert: certPem,
    });

    const store = new AIDStore({ aunPath, encryptionSeed: 'test-seed' });
    const result = store.load(aid);

    expect(result.ok).toBe(false);
    expect((result as any).error?.code).toBe('KEYPAIR_MISMATCH');
  });
});

describe('AIDStore 群身份导入', () => {
  it('importGroupIdentity 校验证书和公钥后落盘，重新 load 后可签名', () => {
    const groupAid = 'team-import.agentid.pub';
    const aunPath = mkdtempSync(join(tmpdir(), 'aun-ts-group-import-'));
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity(groupAid, privateKey);
    const store = new AIDStore({ aunPath, encryptionSeed: 'group-seed' });

    const imported = store.importGroupIdentity(groupAid, {
      private_key_pem: identity.private_key_pem,
      public_key_der_b64: identity.public_key_der_b64,
      curve: 'P-256',
      cert_pem: identity.cert,
    });

    expect(imported.ok).toBe(true);
    const loaded = store.load(groupAid);
    expect(loaded.ok).toBe(true);
    const sign = loaded.ok ? loaded.data.aid.sign('group-fs-probe') : resultErr('X', 'not loaded');
    expect(sign.ok).toBe(true);
  });

  it('importGroupIdentity 拒绝 CN 与 aid 不一致的证书', () => {
    const groupAid = 'team-cn.agentid.pub';
    const aunPath = mkdtempSync(join(tmpdir(), 'aun-ts-group-cn-'));
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity('other.agentid.pub', privateKey);
    const store = new AIDStore({ aunPath, encryptionSeed: 'group-seed' });

    const imported = store.importGroupIdentity(groupAid, {
      private_key_pem: identity.private_key_pem,
      public_key_der_b64: identity.public_key_der_b64,
      cert_pem: identity.cert,
    });

    expect(imported.ok).toBe(false);
    expect((imported as any).error.code).toBe('CERT_CHAIN_BROKEN');
  });

  it('importGroupIdentity 拒绝证书公钥与 public_key_der_b64 不一致', () => {
    const groupAid = 'team-pub.agentid.pub';
    const aunPath = mkdtempSync(join(tmpdir(), 'aun-ts-group-pub-'));
    const { privateKey: certKey } = generateECKeypair();
    const { privateKey: otherKey } = generateECKeypair();
    const certIdentity = buildIdentity(groupAid, certKey);
    const otherIdentity = buildIdentity(groupAid, otherKey);
    const store = new AIDStore({ aunPath, encryptionSeed: 'group-seed' });

    const imported = store.importGroupIdentity(groupAid, {
      private_key_pem: certIdentity.private_key_pem,
      public_key_der_b64: otherIdentity.public_key_der_b64,
      cert_pem: certIdentity.cert,
    });

    expect(imported.ok).toBe(false);
    expect((imported as any).error.code).toBe('KEYPAIR_MISMATCH');
  });

  it('importGroupIdentity 拒绝证书与私钥不匹配', () => {
    const groupAid = 'team-priv.agentid.pub';
    const aunPath = mkdtempSync(join(tmpdir(), 'aun-ts-group-priv-'));
    const { privateKey: certKey } = generateECKeypair();
    const { privateKey: otherKey } = generateECKeypair();
    const certIdentity = buildIdentity(groupAid, certKey);
    const otherIdentity = buildIdentity(groupAid, otherKey);
    const store = new AIDStore({ aunPath, encryptionSeed: 'group-seed' });

    const imported = store.importGroupIdentity(groupAid, {
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
    const { aid: ownerAid, aunPath } = createStoredAid('owner-create.agentid.pub');
    const groupAid = 'named-team.agentid.pub';
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity(groupAid, privateKey);
    const generateSpy = vi.spyOn(CryptoProvider.prototype, 'generateIdentity').mockReturnValue({
      private_key_pem: identity.private_key_pem!,
      public_key_der_b64: identity.public_key_der_b64!,
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
      const groupStore = new AIDStore({ aunPath, encryptionSeed: '' });
      const loaded = groupStore.load(groupAid);
      expect(loaded.ok).toBe(true);
      expect(loaded.ok ? loaded.data.aid.sign('group-fs-probe').ok : false).toBe(true);
    } finally {
      generateSpy.mockRestore();
    }
  });

  it('无 group_name 时原样透传 group.create', async () => {
    const { aid } = createStoredAid('owner-plain.agentid.pub');
    const client = new AUNClient(aid);
    const callSpy = vi.fn(async (_method: string, params: Record<string, unknown>) => ({ group: { group_id: 'group.agentid.pub/10002' }, params }));
    (client as any)._rpcPipeline.call = callSpy;

    const result = await client.createGroup({ name: 'plain-team' });

    expect(callSpy).toHaveBeenCalledWith('group.create', { name: 'plain-team' });
    expect((result as any).params.public_key).toBeUndefined();
  });
});

describe('AUNClient.bindGroupAid 高层编排', () => {
  it('匿名群升级生成群密钥，调用 group.bind_group_aid，并按服务端 group_aid 导入', async () => {
    const { aid: ownerAid, aunPath } = createStoredAid('owner-bind.agentid.pub');
    const groupAid = 'bound-anon.agentid.pub';
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity(groupAid, privateKey);
    const generateSpy = vi.spyOn(CryptoProvider.prototype, 'generateIdentity').mockReturnValue({
      private_key_pem: identity.private_key_pem!,
      public_key_der_b64: identity.public_key_der_b64!,
      curve: 'P-256',
    });
    const client = new AUNClient(ownerAid);
    const groupStore = new AIDStore({ aunPath, encryptionSeed: 'test-seed' });
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
      const loaded = groupStore.load(groupAid);
      expect(loaded.ok).toBe(true);
      expect(loaded.ok ? loaded.data.aid.sign('group-fs-bind-probe').ok : false).toBe(true);
    } finally {
      generateSpy.mockRestore();
      groupStore.close();
    }
  });

  it('缺少 aidStore 时拒绝且不发 RPC', async () => {
    const { aid } = createStoredAid('owner-bind-no-store.agentid.pub');
    const client = new AUNClient(aid);
    const callSpy = vi.fn();
    (client as any)._rpcPipeline.call = callSpy;

    await expect(client.bindGroupAid({ group_id: 'group.agentid.pub/10004' })).rejects.toThrow(/aidStore/);
    expect(callSpy).not.toHaveBeenCalled();
  });
});

describe('AUNClient.completeGroupTransfer 高层编排', () => {
  it('新群主生成群密钥，调用 group.complete_transfer，并导入新的 group_aid 身份', async () => {
    const { aid: ownerAid, aunPath } = createStoredAid('owner-transfer.agentid.pub');
    const groupAid = 'transferred-team.agentid.pub';
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity(groupAid, privateKey);
    const generateSpy = vi.spyOn(CryptoProvider.prototype, 'generateIdentity').mockReturnValue({
      private_key_pem: identity.private_key_pem!,
      public_key_der_b64: identity.public_key_der_b64!,
      curve: 'P-256',
    });
    const client = new AUNClient(ownerAid);
    const groupStore = new AIDStore({ aunPath, encryptionSeed: 'test-seed' });
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
      const loaded = groupStore.load(groupAid);
      expect(loaded.ok).toBe(true);
      expect(loaded.ok ? loaded.data.aid.sign('group-fs-transfer-probe').ok : false).toBe(true);
    } finally {
      generateSpy.mockRestore();
      groupStore.close();
    }
  });

  it('缺少 aidStore 时拒绝且不发 RPC', async () => {
    const { aid } = createStoredAid('owner-transfer-no-store.agentid.pub');
    const client = new AUNClient(aid);
    const callSpy = vi.fn();
    (client as any)._rpcPipeline.call = callSpy;

    await expect(client.completeGroupTransfer({ group_id: 'group.agentid.pub/10006' })).rejects.toThrow(/aidStore/);
    expect(callSpy).not.toHaveBeenCalled();
  });
});

describe('AUNClient.startGroupTransfer 高层编排', () => {
  it('group_aid 只有证书无私钥时拒绝且不发 transfer RPC', async () => {
    const { aid: ownerAid, aunPath } = createStoredAid('owner-start-no-key.agentid.pub');
    const groupAid = 'start-no-key.agentid.pub';
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity(groupAid, privateKey);
    const keyStore = new LocalIdentityStore(aunPath, { encryptionSeed: 'test-seed' });
    keyStore.saveCert(groupAid, identity.cert);
    const groupStore = new AIDStore({ aunPath, encryptionSeed: 'test-seed' });
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
