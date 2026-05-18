/**
 * V2KeyStore（IndexedDB）单元测试。
 *
 * 依赖 fake-indexeddb（在 tests/setup.ts 中通过 'fake-indexeddb/auto' 已全局注入）。
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  V2KeyStore,
  V2_DB_NAME,
} from '../../src/v2/session/keystore';

const opened: V2KeyStore[] = [];

/** 打开 store 并跟踪以便测试结束后关闭，否则 deleteDatabase 会因 open connection 阻塞。 */
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

beforeEach(async () => {
  await deleteDb(V2_DB_NAME);
});

afterEach(() => {
  while (opened.length) {
    try {
      opened.pop()!.close();
    } catch {
      // 忽略测试清理时的关闭错误
    }
  }
});

describe('V2KeyStore - SPK', () => {
  it('saveSPK + loadSPK roundtrip', async () => {
    const s = await openStore();
    const priv = new Uint8Array([1, 2, 3, 4, 5]);
    const pub = new Uint8Array([10, 20, 30]);
    await s.saveSPK('dev1', 'spk-1', priv, pub);

    const loaded = await s.loadSPK('dev1', 'spk-1');
    expect(loaded).not.toBeNull();
    expect(Array.from(loaded!)).toEqual([1, 2, 3, 4, 5]);
  });

  it('loadSPK returns null when not found', async () => {
    const s = await openStore();
    const loaded = await s.loadSPK('dev1', 'missing');
    expect(loaded).toBeNull();
  });

  it('loadCurrentSPK returns latest by created_at', async () => {
    const s = await openStore();
    await s.saveSPK('dev1', 'spk-1', new Uint8Array([1]), new Uint8Array([2]));
    // 用 setTimeout 让 created_at 单调递增（IndexedDB Date.now ms 粒度）
    await new Promise((r) => setTimeout(r, 5));
    await s.saveSPK('dev1', 'spk-2', new Uint8Array([3]), new Uint8Array([4]));
    await new Promise((r) => setTimeout(r, 5));
    await s.saveSPK('dev1', 'spk-3', new Uint8Array([5]), new Uint8Array([6]));

    const cur = await s.loadCurrentSPK('dev1');
    expect(cur?.spkId).toBe('spk-3');
    expect(Array.from(cur!.priv)).toEqual([5]);
    expect(Array.from(cur!.pubDer)).toEqual([6]);
  });

  it('loadCurrentSPK returns null when device has none', async () => {
    const s = await openStore();
    const cur = await s.loadCurrentSPK('dev1');
    expect(cur).toBeNull();
  });

  it('loadCurrentSPK is per-device', async () => {
    const s = await openStore();
    await s.saveSPK('devA', 'spk-A', new Uint8Array([1]), new Uint8Array([2]));
    await new Promise((r) => setTimeout(r, 5));
    await s.saveSPK('devB', 'spk-B', new Uint8Array([3]), new Uint8Array([4]));

    const a = await s.loadCurrentSPK('devA');
    const b = await s.loadCurrentSPK('devB');
    expect(a?.spkId).toBe('spk-A');
    expect(b?.spkId).toBe('spk-B');
  });

  it('deleteSPK destroys', async () => {
    const s = await openStore();
    await s.saveSPK('dev1', 'spk-1', new Uint8Array([1]), new Uint8Array([2]));
    await s.saveSPK('dev1', 'spk-2', new Uint8Array([3]), new Uint8Array([4]));

    await s.deleteSPK('dev1', 'spk-1');
    expect(await s.loadSPK('dev1', 'spk-1')).toBeNull();
    expect(await s.loadSPK('dev1', 'spk-2')).not.toBeNull();
  });

  it('listRecentSPKIds returns N latest in DESC order', async () => {
    const s = await openStore();
    await s.saveSPK('dev1', 'spk-1', new Uint8Array([1]), new Uint8Array([2]));
    await new Promise((r) => setTimeout(r, 5));
    await s.saveSPK('dev1', 'spk-2', new Uint8Array([3]), new Uint8Array([4]));
    await new Promise((r) => setTimeout(r, 5));
    await s.saveSPK('dev1', 'spk-3', new Uint8Array([5]), new Uint8Array([6]));
    await new Promise((r) => setTimeout(r, 5));
    await s.saveSPK('dev1', 'spk-4', new Uint8Array([7]), new Uint8Array([8]));

    expect(await s.listRecentSPKIds('dev1', 2)).toEqual(['spk-4', 'spk-3']);
    expect(await s.listRecentSPKIds('dev1', 4)).toEqual([
      'spk-4',
      'spk-3',
      'spk-2',
      'spk-1',
    ]);
    expect(await s.listRecentSPKIds('dev1', 10)).toEqual([
      'spk-4',
      'spk-3',
      'spk-2',
      'spk-1',
    ]);
  });

  it('listRecentSPKIds with n<=0 returns empty', async () => {
    const s = await openStore();
    await s.saveSPK('dev1', 'spk-1', new Uint8Array([1]), new Uint8Array([2]));
    expect(await s.listRecentSPKIds('dev1', 0)).toEqual([]);
    expect(await s.listRecentSPKIds('dev1', -3)).toEqual([]);
  });

  it('saveSPK overwrite same key_id (INSERT OR REPLACE)', async () => {
    const s = await openStore();
    await s.saveSPK('dev1', 'spk-1', new Uint8Array([1]), new Uint8Array([2]));
    await s.saveSPK('dev1', 'spk-1', new Uint8Array([9, 9]), new Uint8Array([8, 8]));

    const loaded = await s.loadSPK('dev1', 'spk-1');
    expect(Array.from(loaded!)).toEqual([9, 9]);
  });
});

describe('V2KeyStore - IK', () => {
  it('saveIK + loadIK roundtrip', async () => {
    const s = await openStore();
    const priv = new Uint8Array([1, 2, 3]);
    const pub = new Uint8Array([4, 5, 6, 7]);
    await s.saveIK('dev1', priv, pub);

    const loaded = await s.loadIK('dev1');
    expect(loaded).not.toBeNull();
    expect(Array.from(loaded!.priv)).toEqual([1, 2, 3]);
    expect(Array.from(loaded!.pubDer)).toEqual([4, 5, 6, 7]);
  });

  it('loadIK returns null when missing', async () => {
    const s = await openStore();
    expect(await s.loadIK('dev1')).toBeNull();
  });

  it('IK and SPK do not collide on key_id="" / key_type', async () => {
    const s = await openStore();
    await s.saveIK('dev1', new Uint8Array([1]), new Uint8Array([2]));
    await s.saveSPK('dev1', '', new Uint8Array([3]), new Uint8Array([4]));

    const ik = await s.loadIK('dev1');
    const spk = await s.loadSPK('dev1', '');
    expect(Array.from(ik!.priv)).toEqual([1]);
    expect(Array.from(spk!)).toEqual([3]);
  });
});

describe('V2KeyStore - persistence', () => {
  it('data persists across reopen', async () => {
    const s1 = await openStore();
    await s1.saveSPK('dev1', 'spk-X', new Uint8Array([42]), new Uint8Array([43]));
    s1.close();

    const s2 = await openStore();
    const cur = await s2.loadCurrentSPK('dev1');
    expect(cur?.spkId).toBe('spk-X');
    expect(Array.from(cur!.priv)).toEqual([42]);
  });
});
