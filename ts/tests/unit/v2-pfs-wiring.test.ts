/**
 * V2 PFS 接线单元测试
 *
 * 验证 client 的 _pullV2Internal / _ackV2Internal 正确驱动 V2Session 的
 * trackOldSPKMaxSeq + maybeDestroyOldSPKs（PFS 三重条件）。
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createRequire } from 'node:module';
import { AUNClient } from '../../src/client.js';
import { AID } from '../../src/aid.js';
import {
  V2KeyStore,
  V2Session,
  DESTROY_DELAY_MS,
  RECENT_GENERATIONS,
  type CallFn,
} from '../../src/v2/session/index.js';
import { generateP256Keypair } from '../../src/v2/crypto/ecdh.js';

type NodeDatabaseSync = import('node:sqlite').DatabaseSync;
type NodeDatabaseSyncOptions = import('node:sqlite').DatabaseSyncOptions;
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as {
  DatabaseSync: new (path: string, options?: NodeDatabaseSyncOptions) => NodeDatabaseSync;
};

function makeMockAid(aunPath: string): AID {
  return {
    aid: 'test.aid.com', aunPath, certPem: '', publicKey: '', certSubject: '',
    certNotBefore: new Date(), certNotAfter: new Date(Date.now() + 86400000),
    certIssuer: '', certFingerprint: '', deviceId: 'default', slotId: 'default',
    verifySsl: true, rootCaPath: null, debug: false,
    isCertValid: () => true, isPrivateKeyValid: () => true,
    sign: () => ({ ok: true, data: { signature: '' } }),
    verify: () => ({ ok: true, data: { valid: true } }),
    signAgentMd: () => ({ ok: true, data: { signed: '' } }),
    verifyAgentMd: () => ({ ok: true, data: { status: 'verified' as const, payload: '' } }),
  } as unknown as AID;
}

interface ClientFixture {
  client: AUNClient;
  session: V2Session;
  store: V2KeyStore;
}

function makeClientWithSession(): ClientFixture {
  const tmpDir = mkdtempSync(join(tmpdir(), 'aun-pfs-'));
  const client = new AUNClient(makeMockAid(tmpDir));
  const db = new DatabaseSync(':memory:');
  const store = new V2KeyStore(db);
  const [ikPriv, ikPub] = generateP256Keypair();
  const session = new V2Session(store, 'dev-1', 'alice.aid', ikPriv, ikPub);
  // 设置已连接 + 已注入 V2 session
  (client as any)._state = 'connected';
  (client as any)._aid = 'alice.aid';
  (client as any)._v2Session = session;
  return { client, session, store };
}

describe('V2 PFS 接线 - _ackV2Internal 触发 maybeDestroyOldSPKs', () => {
  let fixture: ClientFixture;

  beforeEach(() => {
    fixture = makeClientWithSession();
  });

  it('ack 调用后 V2Session.maybeDestroyOldSPKs 被触发', async () => {
    const { client, session } = fixture;
    const noopFn: CallFn = async () => ({});
    await session.ensureRegistered(noopFn);

    const spy = vi.spyOn(session, 'maybeDestroyOldSPKs');
    (client as any)._transport.call = vi.fn().mockResolvedValue({ acked: 5 });

    await client.call('message.ack', { seq: 5 });

    expect(spy).toHaveBeenCalledWith(5);
  });

  it('ack 推进后符合三重条件的旧 SPK 私钥被销毁', async () => {
    const { client, session, store } = fixture;
    const noopFn: CallFn = async () => ({});
    await session.ensureRegistered(noopFn);
    const oldSpkId = session.currentSpkId;

    // rotate 多次让 oldSpkId 退出最近 7 代窗口
    for (let i = 0; i < RECENT_GENERATIONS + 1; i++) {
      await session.rotateSPK(noopFn);
    }

    let now = Date.now();
    session._setNowFn(() => now);
    session.trackOldSPKMaxSeq(oldSpkId, 100);
    // 推进时间超过 7 天安全窗口
    now += DESTROY_DELAY_MS + 1000;

    expect(store.loadSPK('dev-1', oldSpkId)).not.toBeNull();

    (client as any)._transport.call = vi.fn().mockResolvedValue({ acked: 100 });
    await client.call('message.ack', { seq: 100 });

    // 验证：旧 SPK 私钥已从 store 销毁
    expect(store.loadSPK('dev-1', oldSpkId)).toBeNull();
  });

  it('ack seq 不足以覆盖旧 SPK 引用最大 seq → 不销毁', async () => {
    const { client, session, store } = fixture;
    const noopFn: CallFn = async () => ({});
    await session.ensureRegistered(noopFn);
    const oldSpkId = session.currentSpkId;
    for (let i = 0; i < RECENT_GENERATIONS + 1; i++) {
      await session.rotateSPK(noopFn);
    }
    let now = Date.now();
    session._setNowFn(() => now);
    session.trackOldSPKMaxSeq(oldSpkId, 100);
    now += DESTROY_DELAY_MS + 1000;

    (client as any)._transport.call = vi.fn().mockResolvedValue({ acked: 50 });
    await client.call('message.ack', { seq: 50 });

    // contig_seq=50 < 100 → 不销毁
    expect(store.loadSPK('dev-1', oldSpkId)).not.toBeNull();
  });

  it('seq <= 0 直接返回 acked:0 不触发销毁', async () => {
    const { client, session } = fixture;
    const spy = vi.spyOn(session, 'maybeDestroyOldSPKs');
    (client as any)._transport.call = vi.fn();

    const result = await client.call('message.ack', { seq: 0 });
    expect((result as any).acked).toBe(0);
    expect(spy).not.toHaveBeenCalled();
  });
});

describe('V2 PFS 接线 - _pullV2Internal 调用 trackOldSPKMaxSeq', () => {
  it('pull 返回的消息 spk_id 被追踪到 V2Session', async () => {
    const { client, session } = makeClientWithSession();
    const noopFn: CallFn = async () => ({});
    await session.ensureRegistered(noopFn);

    const oldSpkId = 'sha256:olderspkid01234';
    const spy = vi.spyOn(session, 'trackOldSPKMaxSeq');

    // mock _transport.call: pull 返回带 spk_id 的消息（envelope_json 解密会失败但不影响追踪）
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'message.v2.pull') {
        return {
          messages: [
            { seq: 7, spk_id: oldSpkId, envelope_json: '{"invalid":true}', from_aid: 'bob.aid' },
          ],
        };
      }
      return {};
    });

    await client.call('message.pull', { after_seq: 0, limit: 10 });

    // 验证：trackOldSPKMaxSeq(oldSpkId, 7) 被调用（旧 SPK 不等于当前 SPK）
    expect(spy).toHaveBeenCalledWith(oldSpkId, 7);
  });

  it('当前 SPK 不被追踪（isCurrentSPK 命中跳过）', async () => {
    const { client, session } = makeClientWithSession();
    const noopFn: CallFn = async () => ({});
    await session.ensureRegistered(noopFn);
    const currentSpkId = session.currentSpkId;
    const spy = vi.spyOn(session, 'trackOldSPKMaxSeq');

    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'message.v2.pull') {
        return {
          messages: [
            { seq: 7, spk_id: currentSpkId, envelope_json: '{"x":1}', from_aid: 'bob.aid' },
          ],
        };
      }
      return {};
    });

    await client.call('message.pull', { after_seq: 0, limit: 10 });

    expect(spy).not.toHaveBeenCalled();
  });
});
