import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import {
  V2KeyStore,
  V2Session,
  PEER_KEY_CACHE_TTL_MS,
  DESTROY_DELAY_MS,
  RECENT_GENERATIONS,
  type CallFn,
} from '../../src/v2/session/index.js';
import { generateP256Keypair } from '../../src/v2/crypto/ecdh.js';
import { ecdsaVerifyRaw } from '../../src/v2/crypto/ecdsa.js';

type NodeDatabaseSync = import('node:sqlite').DatabaseSync;
type NodeDatabaseSyncOptions = import('node:sqlite').DatabaseSyncOptions;
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as {
  DatabaseSync: new (path: string, options?: NodeDatabaseSyncOptions) => NodeDatabaseSync;
};

interface SessionFixture {
  session: V2Session;
  store: V2KeyStore;
  ikPriv: Uint8Array;
  ikPub: Uint8Array;
}

function newSession(deviceId = 'dev-1', aid = 'alice.aid.com'): SessionFixture {
  const db = new DatabaseSync(':memory:');
  const store = new V2KeyStore(db);
  const [ikPriv, ikPub] = generateP256Keypair();
  const session = new V2Session(store, deviceId, aid, ikPriv, ikPub);
  return { session, store, ikPriv, ikPub };
}

function keyIdForPub(pubDer: Uint8Array): string {
  return `sha256:${createHash('sha256').update(Buffer.from(pubDer)).digest('hex').slice(0, 16)}`;
}
function captureCallFn(): { calls: Array<{ method: string; params: Record<string, unknown> }>; fn: CallFn } {
  const calls: Array<{ method: string; params: Record<string, unknown> }> = [];
  const fn: CallFn = async (method, params) => {
    calls.push({ method, params });
    return {};
  };
  return { calls, fn };
}

describe('V2Session 构造', () => {
  it('缺少 IK 抛错', () => {
    const db = new DatabaseSync(':memory:');
    const store = new V2KeyStore(db);
    expect(() => new V2Session(store, 'd', 'a', null as unknown as Uint8Array, new Uint8Array(1))).toThrow();
    expect(() => new V2Session(store, 'd', 'a', new Uint8Array(1), null as unknown as Uint8Array)).toThrow();
  });
});

describe('V2Session.ensureKeys', () => {
  it('首次调用生成 SPK 并写入 store', () => {
    const { session, store } = newSession();
    expect(session.currentSpkId).toBe('');
    session.ensureKeys();
    const spkId = session.currentSpkId;
    expect(spkId).toMatch(/^sha256:[0-9a-f]{16}$/);
    const cur = store.loadCurrentSPK('dev-1');
    expect(cur?.spkId).toBe(spkId);
  });

  it('重复调用复用已有 SPK', () => {
    const { session } = newSession();
    session.ensureKeys();
    const first = session.currentSpkId;
    session.ensureKeys();
    expect(session.currentSpkId).toBe(first);
  });

  it('已有 store 数据时复用而非重新生成', () => {
    const db = new DatabaseSync(':memory:');
    const store = new V2KeyStore(db);
    const [ikPriv, ikPub] = generateP256Keypair();
    // 第一个 session 生成 SPK
    const sess1 = new V2Session(store, 'dev-1', 'a.aid', ikPriv, ikPub);
    sess1.ensureKeys();
    const spkId = sess1.currentSpkId;
    // 第二个 session 应加载已有 SPK
    const sess2 = new V2Session(store, 'dev-1', 'a.aid', ikPriv, ikPub);
    sess2.ensureKeys();
    expect(sess2.currentSpkId).toBe(spkId);
  });
});

describe('V2Session.ensureRegistered / rotateSPK', () => {
  it('ensureRegistered 调用 message.v2.put_peer_pk 并签名 SPK', async () => {
    const { session, ikPub } = newSession();
    const { calls, fn } = captureCallFn();
    await session.ensureRegistered(fn);
    expect(calls).toHaveLength(1);
    const c = calls[0]!;
    expect(c.method).toBe('message.v2.put_peer_pk');
    expect(c.params.peer_aid).toBe('alice.aid.com');
    expect(c.params.key_source).toBe('peer_device_prekey');
    expect(c.params.spk_id).toBe(session.currentSpkId);
    // 校验签名
    const spkPkB64 = c.params.spk_pk as string;
    const sigB64 = c.params.spk_signature as string;
    const ts = c.params.spk_timestamp as number;
    const spkPk = Buffer.from(spkPkB64, 'base64');
    const sig = Buffer.from(sigB64, 'base64');
    const signData = Buffer.concat([spkPk, Buffer.from(session.currentSpkId, 'utf-8'), Buffer.from(String(ts), 'utf-8')]);
    expect(ecdsaVerifyRaw(ikPub, sig, signData)).toBe(true);
  });

  it('ensureRegistered 幂等（重复调用只注册一次）', async () => {
    const { session } = newSession();
    const { calls, fn } = captureCallFn();
    await session.ensureRegistered(fn);
    await session.ensureRegistered(fn);
    expect(calls).toHaveLength(1);
  });

  it('rotateSPK 生成新 SPK 并再次注册', async () => {
    const { session, store } = newSession();
    const { calls, fn } = captureCallFn();
    await session.ensureRegistered(fn);
    const oldSpkId = session.currentSpkId;
    await session.rotateSPK(fn);
    expect(session.currentSpkId).not.toBe(oldSpkId);
    expect(calls).toHaveLength(2);
    expect(calls[1]!.params.spk_id).toBe(session.currentSpkId);
    // 旧 SPK 仍在 store 中（用于解密历史消息）
    expect(store.loadSPK('dev-1', oldSpkId)).not.toBeNull();
  });

  it('ensureRegistered 从本地 uploaded marker 恢复时不再 RPC', async () => {
    const { session, store, ikPriv, ikPub } = newSession();
    const { calls, fn } = captureCallFn();
    await session.ensureRegistered(fn);
    const uploadedSpkId = session.currentSpkId;
    expect(calls).toHaveLength(1);

    const sess2 = new V2Session(store, 'dev-1', 'alice.aid.com', ikPriv, ikPub);
    const { calls: calls2, fn: fn2 } = captureCallFn();
    await sess2.ensureRegistered(fn2);

    expect(calls2).toHaveLength(0);
    expect(sess2.isLastUploadedSPK(uploadedSpkId)).toBe(true);
  });

  it('ensureGroupRegistered 从本地 uploaded marker 恢复时不再 RPC', async () => {
    const { session, store, ikPriv, ikPub } = newSession();
    const { calls, fn } = captureCallFn();
    const groupId = 'group.aid/marker';
    await session.ensureGroupRegistered(groupId, fn);
    const uploadedSpkId = calls[0]!.params.spk_id as string;
    expect(calls).toHaveLength(1);
    expect(store.loadCurrentGroupSPK('dev-1', groupId)?.spkId).toBe(uploadedSpkId);
    expect(store.loadLatestUploadedGroupSPKId('dev-1', groupId)).toBe(uploadedSpkId);

    const sess2 = new V2Session(store, 'dev-1', 'alice.aid.com', ikPriv, ikPub);
    const { calls: calls2, fn: fn2 } = captureCallFn();
    await sess2.ensureGroupRegistered(groupId, fn2);

    expect(calls2).toHaveLength(0);
    expect(sess2.isLastUploadedGroupSPK(groupId, uploadedSpkId)).toBe(true);
  });
});

describe('V2Session.getDecryptKeys', () => {
  it('spkId 为空 → 仅 IK（1DH）', () => {
    const { session } = newSession();
    session.ensureKeys();
    const r1 = session.getDecryptKeys('');
    expect(r1.spkPriv).toBeUndefined();
    const r2 = session.getDecryptKeys(null);
    expect(r2.spkPriv).toBeUndefined();
    const r3 = session.getDecryptKeys(undefined);
    expect(r3.spkPriv).toBeUndefined();
  });

  it('spkId 命中当前 SPK → 当前 spkPriv', () => {
    const { session } = newSession();
    session.ensureKeys();
    const r = session.getDecryptKeys(session.currentSpkId);
    expect(r.spkPriv).toBeInstanceOf(Uint8Array);
    expect(r.spkPriv!.length).toBe(32);
  });

  it('spkId 是历史 SPK → 从 store 加载', async () => {
    const { session } = newSession();
    const { fn } = captureCallFn();
    await session.ensureRegistered(fn);
    const oldSpkId = session.currentSpkId;
    await session.rotateSPK(fn);
    const r = session.getDecryptKeys(oldSpkId);
    expect(r.spkPriv).toBeInstanceOf(Uint8Array);
    // 当前 SPK 也能查到
    const rCur = session.getDecryptKeys(session.currentSpkId);
    expect(Array.from(rCur.spkPriv!)).not.toEqual(Array.from(r.spkPriv!));
  });

  it('spkId 已被销毁 → 显式报 spk_missing', () => {
    const { session } = newSession();
    session.ensureKeys();
    expect(() => session.getDecryptKeys('sha256:nonexistent_id')).toThrow(/spk_missing/);
  });

  it('spkId 命中 IK 指纹 → 返回 IK 作为 SPK 私钥', () => {
    const { session, ikPub } = newSession();
    session.ensureKeys();
    const r = session.getDecryptKeys(keyIdForPub(ikPub));
    expect(Array.from(r.spkPriv!)).toEqual(Array.from(r.ikPriv));
  });

  it('group spkId 命中 IK 指纹 → 返回 IK 作为 SPK 私钥', () => {
    const { session, ikPub } = newSession();
    session.ensureKeys();
    const r = session.getGroupDecryptKeys('group.aid/1', keyIdForPub(ikPub));
    expect(Array.from(r.spkPriv!)).toEqual(Array.from(r.ikPriv));
  });

  it('group spkId 命中 device SPK → 返回 device SPK 私钥', () => {
    const { session } = newSession();
    session.ensureKeys();
    const r = session.getGroupDecryptKeys('group.aid/1', session.currentSpkId);
    const p2p = session.getDecryptKeys(session.currentSpkId);
    expect(Array.from(r.spkPriv!)).toEqual(Array.from(p2p.spkPriv!));
  });

  it('group spkId 兼容旧 composite 格式，同时新格式直接查询', () => {
    const { session, store } = newSession();
    session.ensureKeys();
    const groupId = 'group.aid/legacy';
    const spkId = 'sha256:legacy_group';
    const [groupPriv, groupPub] = generateP256Keypair();
    store.saveGroupSPK('dev-1', groupId, spkId, groupPriv, groupPub);

    const direct = session.getGroupDecryptKeys(groupId, spkId);
    const legacy = session.getGroupDecryptKeys(groupId, `${groupId}\0${spkId}`);

    expect(Array.from(direct.spkPriv!)).toEqual(Array.from(groupPriv));
    expect(Array.from(legacy.spkPriv!)).toEqual(Array.from(groupPriv));
    (session as unknown as { _lastUploadedGroupSPKIds: Map<string, string> })
      ._lastUploadedGroupSPKIds.set(groupId, spkId);
    expect(session.isLastUploadedGroupSPK(groupId, `${groupId}\0${spkId}`)).toBe(true);
  });

  it('group SPK 和 legacy P2P SPK 都找不到 → 显式报 spk_missing', () => {
    const { session } = newSession();
    session.ensureKeys();
    expect(() => session.getGroupDecryptKeys('group.aid/1', 'sha256:nonexistent_id')).toThrow(/spk_missing/);
  });
});

describe('V2Session.isCurrentSPK', () => {
  it('命中返回 true', () => {
    const { session } = newSession();
    session.ensureKeys();
    expect(session.isCurrentSPK(session.currentSpkId)).toBe(true);
  });

  it('未命中或空返回 false', () => {
    const { session } = newSession();
    session.ensureKeys();
    expect(session.isCurrentSPK('other')).toBe(false);
    expect(session.isCurrentSPK('')).toBe(false);
    expect(session.isCurrentSPK(null)).toBe(false);
    expect(session.isCurrentSPK(undefined)).toBe(false);
  });
});

describe('V2Session.trackOldSPKMaxSeq', () => {
  it('忽略当前 SPK', () => {
    const { session } = newSession();
    session.ensureKeys();
    session.trackOldSPKMaxSeq(session.currentSpkId, 100);
    // 销毁判定不应触发任何动作
    expect(session.maybeDestroyOldSPKs(100)).toEqual([]);
  });

  it('忽略空 spkId', () => {
    const { session } = newSession();
    session.trackOldSPKMaxSeq('', 100);
    expect(session.maybeDestroyOldSPKs(100)).toEqual([]);
  });
});

describe('V2Session.maybeDestroyOldSPKs（PFS 三重条件）', () => {
  it('三个条件都不满足 → 不销毁', async () => {
    const { session, store } = newSession();
    const { fn } = captureCallFn();
    await session.ensureRegistered(fn);
    const oldSpkId = session.currentSpkId;
    await session.rotateSPK(fn);

    let now = Date.now();
    session._setNowFn(() => now);

    session.trackOldSPKMaxSeq(oldSpkId, 100);
    // contig_seq 不够 → 不销毁
    expect(session.maybeDestroyOldSPKs(50)).toEqual([]);
    expect(store.loadSPK('dev-1', oldSpkId)).not.toBeNull();
  });

  it('contig_seq 够但时间不够 → 不销毁', async () => {
    const { session, store } = newSession();
    const { fn } = captureCallFn();
    await session.ensureRegistered(fn);
    const oldSpkId = session.currentSpkId;
    await session.rotateSPK(fn);

    let now = Date.now();
    session._setNowFn(() => now);

    session.trackOldSPKMaxSeq(oldSpkId, 100);
    expect(session.maybeDestroyOldSPKs(100)).toEqual([]);
    expect(store.loadSPK('dev-1', oldSpkId)).not.toBeNull();
  });

  it('contig_seq + 时间满足，但在最近 7 代窗口内 → 不销毁', async () => {
    const { session, store } = newSession();
    const { fn } = captureCallFn();
    await session.ensureRegistered(fn);
    const oldSpkId = session.currentSpkId;
    // rotate 2 次（包括 oldSpkId 共 3 代，仍在 7 代窗口内）
    await session.rotateSPK(fn);
    await session.rotateSPK(fn);

    let now = Date.now();
    session._setNowFn(() => now);
    session.trackOldSPKMaxSeq(oldSpkId, 100);
    // 推进时间超过 7 天
    now += DESTROY_DELAY_MS + 1000;
    expect(session.maybeDestroyOldSPKs(100)).toEqual([]);
    expect(store.loadSPK('dev-1', oldSpkId)).not.toBeNull();
  });

  it('三重条件都满足 → 销毁', async () => {
    const { session, store } = newSession();
    const { fn } = captureCallFn();
    await session.ensureRegistered(fn);
    const oldSpkId = session.currentSpkId;
    // rotate 多次让 oldSpkId 退出最近 7 代窗口
    for (let i = 0; i < RECENT_GENERATIONS + 1; i++) {
      await session.rotateSPK(fn);
    }

    let now = Date.now();
    session._setNowFn(() => now);
    session.trackOldSPKMaxSeq(oldSpkId, 100);
    now += DESTROY_DELAY_MS + 1000;

    const destroyed = session.maybeDestroyOldSPKs(100);
    expect(destroyed).toContain(oldSpkId);
    expect(store.loadSPK('dev-1', oldSpkId)).toBeNull();
    // 重复调用不再返回（已从内存表清理）
    expect(session.maybeDestroyOldSPKs(100)).toEqual([]);
  });

  it('多次 trackOldSPKMaxSeq 取最大 seq', async () => {
    const { session, store } = newSession();
    const { fn } = captureCallFn();
    await session.ensureRegistered(fn);
    const oldSpkId = session.currentSpkId;
    for (let i = 0; i < RECENT_GENERATIONS + 1; i++) {
      await session.rotateSPK(fn);
    }
    let now = Date.now();
    session._setNowFn(() => now);
    session.trackOldSPKMaxSeq(oldSpkId, 50);
    session.trackOldSPKMaxSeq(oldSpkId, 200);
    session.trackOldSPKMaxSeq(oldSpkId, 100); // 不应降级
    now += DESTROY_DELAY_MS + 1000;
    // contig_seq=150 < 200 → 不销毁
    expect(session.maybeDestroyOldSPKs(150)).toEqual([]);
    expect(store.loadSPK('dev-1', oldSpkId)).not.toBeNull();
    // contig_seq=200 → 销毁
    expect(session.maybeDestroyOldSPKs(200)).toContain(oldSpkId);
  });
});

describe('V2Session 对端 IK 缓存', () => {
  it('cachePeerIK + getPeerIK 命中', () => {
    const { session } = newSession();
    const pub = new Uint8Array([1, 2, 3]);
    session.cachePeerIK('bob.aid', 'dev-b', pub);
    const got = session.getPeerIK('bob.aid', 'dev-b');
    expect(got).not.toBeNull();
    expect(Array.from(got!)).toEqual([1, 2, 3]);
  });

  it('未缓存返回 null', () => {
    const { session } = newSession();
    expect(session.getPeerIK('x', 'y')).toBeNull();
  });

  it('TTL 过期返回 null 并清除条目', () => {
    const { session } = newSession();
    let now = 1_000_000;
    session._setNowFn(() => now);
    session.cachePeerIK('bob.aid', 'dev-b', new Uint8Array([9]));
    expect(session.getPeerIK('bob.aid', 'dev-b')).not.toBeNull();
    now += PEER_KEY_CACHE_TTL_MS; // 恰好 TTL 边界视为过期
    expect(session.getPeerIK('bob.aid', 'dev-b')).toBeNull();
    // 再次查询仍为 null（已被清除）
    expect(session.getPeerIK('bob.aid', 'dev-b')).toBeNull();
  });

  it('不同 (peerAid, deviceId) 隔离', () => {
    const { session } = newSession();
    session.cachePeerIK('a.aid', 'd1', new Uint8Array([1]));
    session.cachePeerIK('a.aid', 'd2', new Uint8Array([2]));
    session.cachePeerIK('b.aid', 'd1', new Uint8Array([3]));
    expect(Array.from(session.getPeerIK('a.aid', 'd1')!)).toEqual([1]);
    expect(Array.from(session.getPeerIK('a.aid', 'd2')!)).toEqual([2]);
    expect(Array.from(session.getPeerIK('b.aid', 'd1')!)).toEqual([3]);
  });
});

describe('V2Session 对端 SPK 验证标记', () => {
  it('未标记前为 false', () => {
    const { session } = newSession();
    expect(session.isPeerSPKVerified('bob', 'd', 'spk-x')).toBe(false);
  });

  it('mark 后为 true', () => {
    const { session } = newSession();
    session.markPeerSPKVerified('bob', 'd', 'spk-x');
    expect(session.isPeerSPKVerified('bob', 'd', 'spk-x')).toBe(true);
    // 不同 spk_id 不会被影响
    expect(session.isPeerSPKVerified('bob', 'd', 'spk-y')).toBe(false);
  });
});

describe('V2Session.getSenderIdentity', () => {
  it('返回完整 sender 结构', () => {
    const { session, ikPub } = newSession('dev-x', 'alice.aid');
    const sender = session.getSenderIdentity();
    expect(sender.aid).toBe('alice.aid');
    expect(sender.deviceId).toBe('dev-x');
    expect(sender.ikPriv.length).toBe(32);
    expect(Array.from(sender.ikPubDer)).toEqual(Array.from(ikPub));
  });
});
