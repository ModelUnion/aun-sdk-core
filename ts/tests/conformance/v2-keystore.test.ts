import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';
import { V2KeyStore } from '../../src/v2/session/keystore.js';

type NodeDatabaseSync = import('node:sqlite').DatabaseSync;
type NodeDatabaseSyncOptions = import('node:sqlite').DatabaseSyncOptions;
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as {
  DatabaseSync: new (path: string, options?: NodeDatabaseSyncOptions) => NodeDatabaseSync;
};

function newStore(): { store: V2KeyStore; db: NodeDatabaseSync } {
  const db = new DatabaseSync(':memory:');
  return { store: new V2KeyStore(db), db };
}

describe('V2KeyStore', () => {
  it('saveSPK + loadSPK 往返一致', () => {
    const { store } = newStore();
    const priv = new Uint8Array([1, 2, 3, 4]);
    const pub = new Uint8Array([5, 6, 7, 8]);
    store.saveSPK('dev1', 'spk-1', priv, pub);
    const got = store.loadSPK('dev1', 'spk-1');
    expect(got).not.toBeNull();
    expect(Array.from(got!)).toEqual([1, 2, 3, 4]);
  });

  it('loadSPK 不存在返回 null', () => {
    const { store } = newStore();
    expect(store.loadSPK('dev1', 'nope')).toBeNull();
  });

  it('saveIK + loadIK 往返一致', () => {
    const { store } = newStore();
    const priv = new Uint8Array([10, 20, 30]);
    const pub = new Uint8Array([40, 50, 60, 70]);
    store.saveIK('dev1', priv, pub);
    const got = store.loadIK('dev1');
    expect(got).not.toBeNull();
    expect(Array.from(got!.priv)).toEqual([10, 20, 30]);
    expect(Array.from(got!.pubDer)).toEqual([40, 50, 60, 70]);
  });

  it('loadCurrentSPK 返回最新（按 created_at 降序）', async () => {
    const { store } = newStore();
    store.saveSPK('dev1', 'spk-1', new Uint8Array([1]), new Uint8Array([2]));
    await new Promise((r) => setTimeout(r, 20));
    store.saveSPK('dev1', 'spk-2', new Uint8Array([3]), new Uint8Array([4]));
    const cur = store.loadCurrentSPK('dev1');
    expect(cur?.spkId).toBe('spk-2');
    expect(Array.from(cur!.priv)).toEqual([3]);
    expect(Array.from(cur!.pubDer)).toEqual([4]);
  });

  it('loadCurrentSPK 无 SPK 时返回 null', () => {
    const { store } = newStore();
    expect(store.loadCurrentSPK('dev1')).toBeNull();
  });

  it('deleteSPK 销毁后 loadSPK 返回 null', () => {
    const { store } = newStore();
    store.saveSPK('dev1', 'spk-old', new Uint8Array([1]), new Uint8Array([2]));
    store.deleteSPK('dev1', 'spk-old');
    expect(store.loadSPK('dev1', 'spk-old')).toBeNull();
  });

  it('listRecentSPKIds 按 created_at 降序返回 N 条', async () => {
    const { store } = newStore();
    for (let i = 0; i < 10; i++) {
      store.saveSPK('dev1', `spk-${i}`, new Uint8Array([i]), new Uint8Array([i]));
      await new Promise((r) => setTimeout(r, 5));
    }
    const ids = store.listRecentSPKIds('dev1', 3);
    expect(ids).toHaveLength(3);
    expect(ids[0]).toBe('spk-9');
    expect(ids[1]).toBe('spk-8');
    expect(ids[2]).toBe('spk-7');
  });

  it('listRecentSPKIds n<=0 返回空数组', () => {
    const { store } = newStore();
    store.saveSPK('dev1', 'spk-1', new Uint8Array([1]), new Uint8Array([2]));
    expect(store.listRecentSPKIds('dev1', 0)).toEqual([]);
    expect(store.listRecentSPKIds('dev1', -1)).toEqual([]);
  });

  it('saveSPK INSERT OR REPLACE 同 spkId 覆盖', () => {
    const { store } = newStore();
    store.saveSPK('dev1', 'spk-1', new Uint8Array([1]), new Uint8Array([2]));
    store.saveSPK('dev1', 'spk-1', new Uint8Array([9]), new Uint8Array([8]));
    const got = store.loadSPK('dev1', 'spk-1');
    expect(Array.from(got!)).toEqual([9]);
  });

  it('不同 deviceId 隔离', () => {
    const { store } = newStore();
    store.saveSPK('devA', 'spk-1', new Uint8Array([1]), new Uint8Array([2]));
    store.saveSPK('devB', 'spk-1', new Uint8Array([3]), new Uint8Array([4]));
    expect(Array.from(store.loadSPK('devA', 'spk-1')!)).toEqual([1]);
    expect(Array.from(store.loadSPK('devB', 'spk-1')!)).toEqual([3]);
    expect(store.listRecentSPKIds('devA', 5)).toEqual(['spk-1']);
    expect(store.listRecentSPKIds('devB', 5)).toEqual(['spk-1']);
  });
});
