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

  it('migrates legacy nullable uploaded markers without blocking V2 init', () => {
    const db = new DatabaseSync(':memory:');
    db.exec(`CREATE TABLE v2_device_keys (
      device_id TEXT NOT NULL,
      key_type TEXT NOT NULL,
      key_id TEXT NOT NULL DEFAULT '',
      private_key BLOB,
      public_key BLOB,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (device_id, key_type, key_id)
    )`);
    const insert = db.prepare(
      `INSERT INTO v2_device_keys (device_id, key_type, key_id, private_key, public_key, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    );
    insert.run('dev1', 'spk', 'spk-1', Buffer.from([1]), Buffer.from([2]), 1);
    insert.run('dev1', 'spk_uploaded', 'spk-1', null, null, 2);
    insert.run('dev1', 'group_spk', 'group-1\0gspk-1', Buffer.from([3]), Buffer.from([4]), 3);
    insert.run('dev1', 'group_spk_uploaded', 'group-1\0gspk-1', null, null, 4);

    const store = new V2KeyStore(db);
    expect(store.loadLatestUploadedSPKId('dev1')).toBe('spk-1');
    expect(store.loadLatestUploadedGroupSPKId('dev1', 'group-1')).toBe('gspk-1');
    const rows = db.prepare(
      `SELECT group_id, key_id FROM v2_device_keys WHERE key_type IN ('group_spk', 'group_spk_uploaded')`,
    ).all() as Array<{ group_id: string; key_id: string }>;
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row.group_id).toBe('group-1');
      expect(row.key_id).toBe('gspk-1');
      expect(row.key_id.includes('\0')).toBe(false);
    }
  });

  it('migrates legacy empty uploaded marker blobs to non-empty marker blobs', () => {
    const db = new DatabaseSync(':memory:');
    db.exec(`CREATE TABLE v2_device_keys (
      device_id TEXT NOT NULL,
      key_type TEXT NOT NULL,
      key_id TEXT NOT NULL DEFAULT '',
      private_key BLOB NOT NULL,
      public_key BLOB NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (device_id, key_type, key_id)
    )`);
    const insert = db.prepare(
      `INSERT INTO v2_device_keys (device_id, key_type, key_id, private_key, public_key, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    );
    insert.run('dev1', 'spk', 'spk-1', Buffer.from([1]), Buffer.from([2]), 1);
    insert.run('dev1', 'spk_uploaded', 'spk-1', Buffer.alloc(0), Buffer.alloc(0), 2);
    insert.run('dev1', 'group_spk', 'group-1\0gspk-1', Buffer.from([3]), Buffer.from([4]), 3);
    insert.run('dev1', 'group_spk_uploaded', 'group-1\0gspk-1', Buffer.alloc(0), Buffer.alloc(0), 4);

    const store = new V2KeyStore(db);
    expect(store.loadLatestUploadedSPKId('dev1')).toBe('spk-1');
    expect(store.loadLatestUploadedGroupSPKId('dev1', 'group-1')).toBe('gspk-1');
    const markers = db.prepare(
      `SELECT length(private_key) AS priv_len, length(public_key) AS pub_len
       FROM v2_device_keys WHERE key_type IN ('spk_uploaded', 'group_spk_uploaded')`,
    ).all() as Array<{ priv_len: number; pub_len: number }>;
    expect(markers).toHaveLength(2);
    for (const row of markers) {
      expect(row.priv_len).toBeGreaterThan(0);
      expect(row.pub_len).toBeGreaterThan(0);
    }
  });

  it('stores new group SPK records without legacy NUL composite key', () => {
    const { store, db } = newStore();
    store.saveGroupSPK('dev1', 'group-1', 'gspk-1', new Uint8Array([1]), new Uint8Array([2]));
    store.markGroupSPKUploaded('dev1', 'group-1', 'gspk-1');

    const rows = db.prepare(
      `SELECT group_id, key_id FROM v2_device_keys WHERE key_type IN ('group_spk', 'group_spk_uploaded')`,
    ).all() as Array<{ group_id: string; key_id: string }>;
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row.group_id).toBe('group-1');
      expect(row.key_id).toBe('gspk-1');
      expect(row.key_id.includes('\0')).toBe(false);
    }
  });

  it('stores uploaded markers as non-empty blobs', () => {
    const { store, db } = newStore();
    store.saveSPK('dev1', 'spk-1', new Uint8Array([1]), new Uint8Array([2]));
    store.markSPKUploaded('dev1', 'spk-1');
    store.saveGroupSPK('dev1', 'group-1', 'gspk-1', new Uint8Array([3]), new Uint8Array([4]));
    store.markGroupSPKUploaded('dev1', 'group-1', 'gspk-1');

    expect(store.loadLatestUploadedSPKId('dev1')).toBe('spk-1');
    expect(store.loadLatestUploadedGroupSPKId('dev1', 'group-1')).toBe('gspk-1');
    const markers = db.prepare(
      `SELECT typeof(private_key) AS priv_type, length(private_key) AS priv_len,
              typeof(public_key) AS pub_type, length(public_key) AS pub_len
       FROM v2_device_keys WHERE key_type IN ('spk_uploaded', 'group_spk_uploaded')`,
    ).all() as Array<{ priv_type: string; priv_len: number; pub_type: string; pub_len: number }>;
    expect(markers).toHaveLength(2);
    for (const row of markers) {
      expect(row.priv_type).toBe('blob');
      expect(row.pub_type).toBe('blob');
      expect(row.priv_len).toBeGreaterThan(0);
      expect(row.pub_len).toBeGreaterThan(0);
    }
  });
});
