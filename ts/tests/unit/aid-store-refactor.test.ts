import { describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AID, AIDStore, AUNClient, ConnectionState, FileKeyStore, resultErr, resultOk } from '../../src/index.js';
import { buildIdentity, generateECKeypair, makeSelfSignedCert } from './helpers.js';

function createStoredAid(aid = 'alice.agentid.pub'): { aid: AID; aunPath: string } {
  const aunPath = mkdtempSync(join(tmpdir(), 'aun-ts-refactor-'));
  const { privateKey } = generateECKeypair();
  const identity = buildIdentity(aid, privateKey);
  const keyStore = new FileKeyStore(aunPath, { encryptionSeed: 'test-seed' });
  keyStore.saveIdentity(aid, identity);

  const store = new AIDStore({ aunPath, encryptionSeed: 'test-seed' });
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

  it('构造函数不接受字符串 AID', () => {
    expect(() => new (AUNClient as any)('alice.agentid.pub')).toThrow(/AID object/);
  });

  it('connect 只接受 options，不接受旧版 aid/token 参数', async () => {
    const { aid } = createStoredAid('erin.agentid.pub');
    const client = new AUNClient(aid);
    await expect(client.connect({ access_token: 'tok', gateway: 'ws://localhost/aun' } as any)).rejects.toThrow(/must not include/);
    await expect(client.connect({ aid: 'erin.agentid.pub' } as any)).rejects.toThrow(/must not include/);
  });

  it('gateway 发现应使用完整 issuer 域名并持久化 gateway_url', async () => {
    const { aid } = createStoredAid('frank.agentid.pub');
    const client = new AUNClient(aid);
    const discover = vi.fn(async () => 'wss://gateway.agentid.pub/aun');
    (client as any)._discovery.discover = discover;

    const gateway = await (client as any)._resolveGatewayForAid(aid.aid);

    expect(gateway).toBe('wss://gateway.agentid.pub/aun');
    expect(discover).toHaveBeenCalledWith('https://frank.agentid.pub/.well-known/aun-gateway');
    expect(((client as any)._keystore.loadMetadata(aid.aid) ?? {}).gateway_url).toBe('wss://gateway.agentid.pub/aun');

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

    expect(calls[0].params.protected_headers).toBeUndefined();
    expect(calls[1].params.protected_headers).toEqual({ app: 'sdk-test', priority: 2 });
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
    const keyStore = new FileKeyStore(aunPath, { encryptionSeed: 'test-seed' });
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
