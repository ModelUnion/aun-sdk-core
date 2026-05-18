/**
 * V2Session（浏览器版，全 async）单元测试。
 *
 * 与 TS / Python SDK 的 v2-session 测试覆盖一致：构造、ensureKeys、
 * ensureRegistered、rotateSPK、getDecryptKeys、isCurrentSPK、
 * trackOldSPKMaxSeq、maybeDestroyOldSPKs（PFS 三重条件）、
 * 对端 IK 缓存（TTL）、对端 SPK 验证标记、getSenderIdentity。
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  V2KeyStore,
  V2Session,
  PEER_KEY_CACHE_TTL_MS,
  DESTROY_DELAY_MS,
  RECENT_GENERATIONS,
  V2_DB_NAME,
  type CallFn,
} from '../../src/v2/session';
import { generateP256Keypair, ecdsaVerifyRaw } from '../../src/v2/crypto';

const opened: V2KeyStore[] = [];

async function openStore(name: string = V2_DB_NAME): Promise<V2KeyStore> {
  const s = await V2KeyStore.open(name);
  opened.push(s);
  return s;
}

async function deleteDb(name: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const req = indexedDB.deleteDatabase(name);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
}

interface SessionFixture {
  session: V2Session;
  store: V2KeyStore;
  ikPub: Uint8Array;
}

async function newSession(
  deviceId = 'dev-1',
  aid = 'alice.aid.com',
): Promise<SessionFixture> {
  const store = await openStore();
  const [ikPriv, ikPub] = await generateP256Keypair();
  const session = new V2Session(store, deviceId, aid, ikPriv, ikPub);
  return { session, store, ikPub };
}

function captureCallFn(): {
  calls: Array<{ method: string; params: Record<string, unknown> }>;
  fn: CallFn;
} {
  const calls: Array<{ method: string; params: Record<string, unknown> }> = [];
  const fn: CallFn = async (method, params) => {
    calls.push({ method, params });
    return {};
  };
  return { calls, fn };
}

function bytesFromBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

beforeEach(async () => {
  await deleteDb(V2_DB_NAME);
});

afterEach(() => {
  while (opened.length) {
    try {
      opened.pop()!.close();
    } catch {
      // ignore
    }
  }
});

describe('V2Session 构造', () => {
  it('缺少 IK 抛错', async () => {
    const store = await openStore();
    expect(
      () => new V2Session(store, 'd', 'a', null as unknown as Uint8Array, new Uint8Array(1)),
    ).toThrow();
    expect(
      () => new V2Session(store, 'd', 'a', new Uint8Array(1), null as unknown as Uint8Array),
    ).toThrow();
  });
});

describe('V2Session.ensureKeys', () => {
  it('首次调用生成 SPK 并写入 store', async () => {
    const { session, store } = await newSession();
    expect(session.currentSpkId).toBe('');
    await session.ensureKeys();
    const spkId = session.currentSpkId;
    expect(spkId).toMatch(/^sha256:[0-9a-f]{16}$/);
    const cur = await store.loadCurrentSPK('dev-1');
    expect(cur?.spkId).toBe(spkId);
  });

  it('重复调用复用已有 SPK', async () => {
    const { session } = await newSession();
    await session.ensureKeys();
    const first = session.currentSpkId;
    await session.ensureKeys();
    expect(session.currentSpkId).toBe(first);
  });

  it('已有 store 数据时复用而非重新生成', async () => {
    const store = await openStore();
    const [ikPriv, ikPub] = await generateP256Keypair();

    const sess1 = new V2Session(store, 'dev-1', 'a.aid', ikPriv, ikPub);
    await sess1.ensureKeys();
    const spkId = sess1.currentSpkId;

    const sess2 = new V2Session(store, 'dev-1', 'a.aid', ikPriv, ikPub);
    await sess2.ensureKeys();
    expect(sess2.currentSpkId).toBe(spkId);
  });
});

describe('V2Session.ensureRegistered / rotateSPK', () => {
  it('ensureRegistered 调用 message.v2.put_peer_pk 并签名 SPK', async () => {
    const { session, ikPub } = await newSession();
    const { calls, fn } = captureCallFn();
    await session.ensureRegistered(fn);
    expect(calls).toHaveLength(1);
    const c = calls[0]!;
    expect(c.method).toBe('message.v2.put_peer_pk');
    expect(c.params.peer_aid).toBe('alice.aid.com');
    expect(c.params.key_source).toBe('peer_device_prekey');
    expect(c.params.spk_id).toBe(session.currentSpkId);

    const spkPk = bytesFromBase64(c.params.spk_pk as string);
    const sig = bytesFromBase64(c.params.spk_signature as string);
    const ts = c.params.spk_timestamp as number;
    const spkIdBytes = new TextEncoder().encode(session.currentSpkId);
    const tsBytes = new TextEncoder().encode(String(ts));
    const signData = new Uint8Array(spkPk.length + spkIdBytes.length + tsBytes.length);
    signData.set(spkPk, 0);
    signData.set(spkIdBytes, spkPk.length);
    signData.set(tsBytes, spkPk.length + spkIdBytes.length);

    expect(await ecdsaVerifyRaw(ikPub, sig, signData)).toBe(true);
  });

  it('ensureRegistered 幂等（重复调用只注册一次）', async () => {
    const { session } = await newSession();
    const { calls, fn } = captureCallFn();
    await session.ensureRegistered(fn);
    await session.ensureRegistered(fn);
    expect(calls).toHaveLength(1);
  });

  it('rotateSPK 生成新 SPK 并再次注册，旧 SPK 保留', async () => {
    const { session, store } = await newSession();
    const { calls, fn } = captureCallFn();
    await session.ensureRegistered(fn);
    const oldSpkId = session.currentSpkId;
    await session.rotateSPK(fn);
    expect(session.currentSpkId).not.toBe(oldSpkId);
    expect(calls).toHaveLength(2);
    expect(calls[1]!.params.spk_id).toBe(session.currentSpkId);
    expect(await store.loadSPK('dev-1', oldSpkId)).not.toBeNull();
  });
});

describe('V2Session.getDecryptKeys', () => {
  it('spkId 为空 → 仅 IK（1DH）', async () => {
    const { session } = await newSession();
    await session.ensureKeys();
    expect((await session.getDecryptKeys('')).spkPriv).toBeUndefined();
    expect((await session.getDecryptKeys(null)).spkPriv).toBeUndefined();
    expect((await session.getDecryptKeys(undefined)).spkPriv).toBeUndefined();
  });

  it('spkId 命中当前 SPK → 当前 spkPriv', async () => {
    const { session } = await newSession();
    await session.ensureKeys();
    const r = await session.getDecryptKeys(session.currentSpkId);
    expect(r.spkPriv).toBeInstanceOf(Uint8Array);
    expect(r.spkPriv!.length).toBe(32);
  });

  it('spkId 是历史 SPK → 从 store 加载', async () => {
    const { session } = await newSession();
    const { fn } = captureCallFn();
    await session.ensureRegistered(fn);
    const oldSpkId = session.currentSpkId;
    await session.rotateSPK(fn);
    const r = await session.getDecryptKeys(oldSpkId);
    expect(r.spkPriv).toBeInstanceOf(Uint8Array);
    const rCur = await session.getDecryptKeys(session.currentSpkId);
    expect(Array.from(rCur.spkPriv!)).not.toEqual(Array.from(r.spkPriv!));
  });

  it('spkId 已被销毁 → spkPriv undefined（不抛错）', async () => {
    const { session } = await newSession();
    await session.ensureKeys();
    const r = await session.getDecryptKeys('sha256:nonexistent_id');
    expect(r.spkPriv).toBeUndefined();
    expect(r.ikPriv).toBeInstanceOf(Uint8Array);
  });
});

describe('V2Session.isCurrentSPK', () => {
  it('命中返回 true', async () => {
    const { session } = await newSession();
    await session.ensureKeys();
    expect(session.isCurrentSPK(session.currentSpkId)).toBe(true);
  });

  it('未命中或空返回 false', async () => {
    const { session } = await newSession();
    await session.ensureKeys();
    expect(session.isCurrentSPK('other')).toBe(false);
    expect(session.isCurrentSPK('')).toBe(false);
    expect(session.isCurrentSPK(null)).toBe(false);
    expect(session.isCurrentSPK(undefined)).toBe(false);
  });
});

describe('V2Session.trackOldSPKMaxSeq', () => {
  it('忽略当前 SPK', async () => {
    const { session } = await newSession();
    await session.ensureKeys();
    session.trackOldSPKMaxSeq(session.currentSpkId, 100);
    expect(await session.maybeDestroyOldSPKs(100)).toEqual([]);
  });

  it('忽略空 spkId', async () => {
    const { session } = await newSession();
    session.trackOldSPKMaxSeq('', 100);
    expect(await session.maybeDestroyOldSPKs(100)).toEqual([]);
  });
});

describe('V2Session.maybeDestroyOldSPKs（PFS 三重条件）', () => {
  it('contig_seq 不够 → 不销毁', async () => {
    const { session, store } = await newSession();
    const { fn } = captureCallFn();
    await session.ensureRegistered(fn);
    const oldSpkId = session.currentSpkId;
    await session.rotateSPK(fn);

    let now = Date.now();
    session._setNowFn(() => now);

    session.trackOldSPKMaxSeq(oldSpkId, 100);
    expect(await session.maybeDestroyOldSPKs(50)).toEqual([]);
    expect(await store.loadSPK('dev-1', oldSpkId)).not.toBeNull();
  });

  it('contig_seq 够但时间不够 → 不销毁', async () => {
    const { session, store } = await newSession();
    const { fn } = captureCallFn();
    await session.ensureRegistered(fn);
    const oldSpkId = session.currentSpkId;
    await session.rotateSPK(fn);

    let now = Date.now();
    session._setNowFn(() => now);
    session.trackOldSPKMaxSeq(oldSpkId, 100);
    expect(await session.maybeDestroyOldSPKs(100)).toEqual([]);
    expect(await store.loadSPK('dev-1', oldSpkId)).not.toBeNull();
  });

  it('contig_seq + 时间满足，但在最近 7 代窗口内 → 不销毁', async () => {
    const { session, store } = await newSession();
    const { fn } = captureCallFn();
    await session.ensureRegistered(fn);
    const oldSpkId = session.currentSpkId;
    await session.rotateSPK(fn);
    await session.rotateSPK(fn);

    let now = Date.now();
    session._setNowFn(() => now);
    session.trackOldSPKMaxSeq(oldSpkId, 100);
    now += DESTROY_DELAY_MS + 1000;

    expect(await session.maybeDestroyOldSPKs(100)).toEqual([]);
    expect(await store.loadSPK('dev-1', oldSpkId)).not.toBeNull();
  });

  it('三重条件都满足 → 销毁', async () => {
    const { session, store } = await newSession();
    const { fn } = captureCallFn();
    await session.ensureRegistered(fn);
    const oldSpkId = session.currentSpkId;
    for (let i = 0; i < RECENT_GENERATIONS + 1; i++) {
      await session.rotateSPK(fn);
    }

    let now = Date.now();
    session._setNowFn(() => now);
    session.trackOldSPKMaxSeq(oldSpkId, 100);
    now += DESTROY_DELAY_MS + 1000;

    const destroyed = await session.maybeDestroyOldSPKs(100);
    expect(destroyed).toContain(oldSpkId);
    expect(await store.loadSPK('dev-1', oldSpkId)).toBeNull();
    expect(await session.maybeDestroyOldSPKs(100)).toEqual([]);
  });

  it('多次 trackOldSPKMaxSeq 取最大 seq', async () => {
    const { session, store } = await newSession();
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

    expect(await session.maybeDestroyOldSPKs(150)).toEqual([]);
    expect(await store.loadSPK('dev-1', oldSpkId)).not.toBeNull();
    expect(await session.maybeDestroyOldSPKs(200)).toContain(oldSpkId);
  });
});

describe('V2Session 对端 IK 缓存', () => {
  it('cachePeerIK + getPeerIK 命中', async () => {
    const { session } = await newSession();
    const pub = new Uint8Array([1, 2, 3]);
    session.cachePeerIK('bob.aid', 'dev-b', pub);
    const got = session.getPeerIK('bob.aid', 'dev-b');
    expect(got).not.toBeNull();
    expect(Array.from(got!)).toEqual([1, 2, 3]);
  });

  it('未缓存返回 null', async () => {
    const { session } = await newSession();
    expect(session.getPeerIK('x', 'y')).toBeNull();
  });

  it('TTL 过期返回 null 并清除条目', async () => {
    const { session } = await newSession();
    let now = 1_000_000;
    session._setNowFn(() => now);
    session.cachePeerIK('bob.aid', 'dev-b', new Uint8Array([9]));
    expect(session.getPeerIK('bob.aid', 'dev-b')).not.toBeNull();
    now += PEER_KEY_CACHE_TTL_MS;
    expect(session.getPeerIK('bob.aid', 'dev-b')).toBeNull();
    expect(session.getPeerIK('bob.aid', 'dev-b')).toBeNull();
  });

  it('不同 (peerAid, deviceId) 隔离', async () => {
    const { session } = await newSession();
    session.cachePeerIK('a.aid', 'd1', new Uint8Array([1]));
    session.cachePeerIK('a.aid', 'd2', new Uint8Array([2]));
    session.cachePeerIK('b.aid', 'd1', new Uint8Array([3]));
    expect(Array.from(session.getPeerIK('a.aid', 'd1')!)).toEqual([1]);
    expect(Array.from(session.getPeerIK('a.aid', 'd2')!)).toEqual([2]);
    expect(Array.from(session.getPeerIK('b.aid', 'd1')!)).toEqual([3]);
  });
});

describe('V2Session 对端 SPK 验证标记', () => {
  it('未标记前为 false', async () => {
    const { session } = await newSession();
    expect(session.isPeerSPKVerified('bob', 'd', 'spk-x')).toBe(false);
  });

  it('mark 后为 true', async () => {
    const { session } = await newSession();
    session.markPeerSPKVerified('bob', 'd', 'spk-x');
    expect(session.isPeerSPKVerified('bob', 'd', 'spk-x')).toBe(true);
    expect(session.isPeerSPKVerified('bob', 'd', 'spk-y')).toBe(false);
  });
});

describe('V2Session.getSenderIdentity', () => {
  it('返回完整 sender 结构', async () => {
    const { session, ikPub } = await newSession('dev-x', 'alice.aid');
    const sender = await session.getSenderIdentity();
    expect(sender.aid).toBe('alice.aid');
    expect(sender.deviceId).toBe('dev-x');
    expect(sender.ikPriv.length).toBe(32);
    expect(Array.from(sender.ikPubDer)).toEqual(Array.from(ikPub));
  });
});
