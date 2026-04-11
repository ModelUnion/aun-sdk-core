// ── keystore 模块单元测试 ──────────────────────────────────
// IndexedDB 测试使用 fake-indexeddb 模拟。
import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach } from 'vitest';
import { IndexedDBKeyStore } from '../../src/keystore/indexeddb.js';
import { IndexedDBSecretStore } from '../../src/secret-store/indexeddb-store.js';
import type { JsonObject, MetadataRecord, PrekeyMap } from '../../src/types.js';

const hasSubtleCrypto = typeof globalThis.crypto?.subtle?.generateKey === 'function';
const KEYSTORE_DB_NAME = 'aun-keystore';
const KEYSTORE_DB_VERSION = 2;

async function withStore<T>(
  storeName: string,
  mode: IDBTransactionMode,
  action: (store: IDBObjectStore, resolve: (value: T) => void, reject: (error: Error) => void) => void,
): Promise<T> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(KEYSTORE_DB_NAME, KEYSTORE_DB_VERSION);
    request.onupgradeneeded = () => {
      const upgradedDb = request.result;
      for (const name of ['key_pairs', 'certs', 'metadata', 'prekeys', 'group_current', 'group_old_epochs']) {
        if (!upgradedDb.objectStoreNames.contains(name)) {
          upgradedDb.createObjectStore(name);
        }
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('打开测试数据库失败'));
  });

  return new Promise<T>((resolve, reject) => {
    const tx = db.transaction(storeName, mode);
    const store = tx.objectStore(storeName);
    action(store, resolve, reject);
    tx.oncomplete = () => db.close();
    tx.onerror = () => {
      db.close();
      reject(tx.error ?? new Error(`访问 ${storeName} 失败`));
    };
    tx.onabort = () => {
      db.close();
      reject(tx.error ?? new Error(`访问 ${storeName} 被中止`));
    };
  });
}

async function readStoreRecord(storeName: string, key: string): Promise<JsonObject | null> {
  return withStore(storeName, 'readonly', (store, resolve, reject) => {
    const request = store.get(key);
    request.onsuccess = () => resolve(request.result ?? null);
    request.onerror = () => reject(request.error ?? new Error(`读取 ${storeName}/${key} 失败`));
  });
}

async function readStoreItems(storeName: string): Promise<Array<{ key: string; value: JsonObject | null }>> {
  return withStore(storeName, 'readonly', (store, resolve, reject) => {
    const valuesReq = store.getAll();
    const keysReq = store.getAllKeys();
    valuesReq.onerror = () => reject(valuesReq.error ?? new Error(`读取 ${storeName} values 失败`));
    keysReq.onerror = () => reject(keysReq.error ?? new Error(`读取 ${storeName} keys 失败`));
    Promise.all([
      new Promise<void>((done) => { valuesReq.onsuccess = () => done(); }),
      new Promise<void>((done) => { keysReq.onsuccess = () => done(); }),
    ]).then(() => {
      const values = valuesReq.result ?? [];
      const keys = keysReq.result ?? [];
      resolve(keys.map((rawKey, index) => ({
        key: typeof rawKey === 'string' ? rawKey : String(rawKey),
        value: values[index],
      })));
    }).catch(reject);
  });
}

async function writeStoreRecord(storeName: string, key: string, value: JsonObject): Promise<void> {
  await withStore<void>(storeName, 'readwrite', (store, resolve, reject) => {
    const request = store.put(value, key);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error ?? new Error(`写入 ${storeName}/${key} 失败`));
  });
}

async function clearStore(storeName: string): Promise<void> {
  await withStore<void>(storeName, 'readwrite', (store, resolve, reject) => {
    const request = store.clear();
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error ?? new Error(`清空 ${storeName} 失败`));
  });
}

async function resetKeystoreDb(): Promise<void> {
  for (const storeName of ['key_pairs', 'certs', 'metadata', 'prekeys', 'group_current', 'group_old_epochs']) {
    await clearStore(storeName);
  }
}

// ── IndexedDBKeyStore 测试 ──────────────────────────────

describe('IndexedDBKeyStore', () => {
  let ks: IndexedDBKeyStore;

  beforeEach(async () => {
    await resetKeystoreDb();
    ks = new IndexedDBKeyStore();
  });

  // ── 密钥对 CRUD ──────────────────────────────────

  it('保存和加载密钥对', async () => {
    const kp = {
      private_key_pem: '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----',
      public_key_der_b64: 'base64pubkey',
      curve: 'P-256',
    };
    await ks.saveKeyPair('alice.test', kp);

    const loaded = await ks.loadKeyPair('alice.test');
    expect(loaded).not.toBeNull();
    expect(loaded!.private_key_pem).toBe(kp.private_key_pem);
    expect(loaded!.public_key_der_b64).toBe(kp.public_key_der_b64);
    expect(loaded!.curve).toBe('P-256');
  });

  it('加载不存在的密钥对应返回 null', async () => {
    const loaded = await ks.loadKeyPair('nonexistent');
    expect(loaded).toBeNull();
  });

  // ── 证书 CRUD ──────────────────────────────────────

  it('保存和加载证书 PEM', async () => {
    const certPem = '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----';
    await ks.saveCert('bob.test', certPem);

    const loaded = await ks.loadCert('bob.test');
    expect(loaded).toBe(certPem);
  });

  it('加载不存在的证书应返回 null', async () => {
    expect(await ks.loadCert('nonexistent')).toBeNull();
  });

  // ── Metadata CRUD ──────────────────────────────────

  it('保存和加载 metadata', async () => {
    const md = { session_id: 'sess-1', e2ee_prekeys: { pk1: { created_at: 1000 } } };
    await ks.saveMetadata('alice', md);

    const loaded = await ks.loadMetadata('alice');
    expect(loaded).not.toBeNull();
    expect(loaded!.session_id).toBe('sess-1');
    expect(loaded!.e2ee_prekeys).toEqual({ pk1: { created_at: 1000 } });
  });

  it('saveMetadata 应保护关键字段不被覆盖', async () => {
    // 先保存含 e2ee_prekeys 的 metadata
    await ks.saveMetadata('alice', {
      e2ee_prekeys: { pk1: { key: 'data' } },
      session_id: 'old',
    });

    // 再保存不含 e2ee_prekeys 的新数据
    await ks.saveMetadata('alice', { session_id: 'new' });

    const loaded = await ks.loadMetadata('alice');
    expect(loaded!.session_id).toBe('new');
    // e2ee_prekeys 应被自动合并保留
    expect(loaded!.e2ee_prekeys).toEqual({ pk1: { key: 'data' } });
  });

  it('saveMetadata 只在结构化 store 保存 prekeys 和 group_secrets', async () => {
    await ks.saveMetadata('alice', {
      session_id: 'sess-1',
      e2ee_prekeys: {
        pk1: { private_key_pem: 'PK1', created_at: 1700000000000 },
      },
      group_secrets: {
        'group-1': {
          epoch: 2,
          secret: 'secret-v2',
          updated_at: 1700000000000,
          old_epochs: [
            { epoch: 1, secret: 'secret-v1', updated_at: 1699999999000 },
          ],
        },
      },
    });

    const rawMetadata = await readStoreRecord('metadata', 'alice');
    expect(rawMetadata).toEqual({ session_id: 'sess-1' });

    const prekeyItems = await readStoreItems('prekeys');
    expect(prekeyItems).toHaveLength(1);
    expect(prekeyItems[0].value).toMatchObject({
      prekey_id: 'pk1',
      private_key_pem: 'PK1',
    });

    const currentGroupItems = await readStoreItems('group_current');
    expect(currentGroupItems).toHaveLength(1);
    expect(currentGroupItems[0].value).toMatchObject({
      group_id: 'group-1',
      epoch: 2,
      secret: 'secret-v2',
    });

    const oldGroupItems = await readStoreItems('group_old_epochs');
    expect(oldGroupItems).toHaveLength(1);
    expect(oldGroupItems[0].value).toMatchObject({
      group_id: 'group-1',
      epoch: 1,
      secret: 'secret-v1',
    });
  });

  it('updateMetadata 在并发调用下应保留两个 prekey', async () => {
    await Promise.all([
      ks.updateMetadata('alice', metadata => {
        const prekeys = (metadata.e2ee_prekeys ?? {});
        metadata.e2ee_prekeys = { ...prekeys, pk1: { private_key_pem: 'PK1' } };
        return metadata;
      }),
      ks.updateMetadata('alice', metadata => {
        const prekeys = (metadata.e2ee_prekeys ?? {});
        metadata.e2ee_prekeys = { ...prekeys, pk2: { private_key_pem: 'PK2' } };
        return metadata;
      }),
    ]);

    const loaded = await ks.loadMetadata('alice');
    expect((loaded!.e2ee_prekeys as PrekeyMap).pk1?.private_key_pem).toBe('PK1');
    expect((loaded!.e2ee_prekeys as PrekeyMap).pk2?.private_key_pem).toBe('PK2');
  });

  it('saveIdentity 更新 token 时不应覆盖已有 prekey', async () => {
    await ks.saveMetadata('identity.aid', {
      e2ee_prekeys: {
        pk1: { private_key_pem: 'KEEP_ME' },
      },
    });

    await ks.saveIdentity('identity.aid', {
      aid: 'identity.aid',
      access_token: 'tok-new',
      refresh_token: 'rt-new',
    });

    const loaded = await ks.loadMetadata('identity.aid');
    const prekeys = loaded!.e2ee_prekeys as PrekeyMap;
    expect(loaded!.access_token).toBe('tok-new');
    expect(loaded!.refresh_token).toBe('rt-new');
    expect(prekeys.pk1.private_key_pem).toBe('KEEP_ME');
  });

  it('loadMetadata 应迁移旧 metadata 中的结构化字段且仅回收未过期数据', async () => {
    const now = Date.now();
    await writeStoreRecord('metadata', 'legacy-aid', {
      session_id: 'legacy-session',
      e2ee_prekeys: {
        keep: { private_key_pem: 'KEEP', created_at: now - 1000 },
        expired: { private_key_pem: 'DROP', created_at: now - (8 * 24 * 3600 * 1000) },
      },
      group_secrets: {
        'group-1': {
          epoch: 2,
          secret: 'group-secret-v2',
          updated_at: now - 1000,
          old_epochs: [
            { epoch: 1, secret: 'group-secret-v1', updated_at: now - 2000 },
          ],
        },
        'group-expired': {
          epoch: 1,
          secret: 'expired-group-secret',
          updated_at: now - (8 * 24 * 3600 * 1000),
        },
      },
    });

    const loaded = await ks.loadMetadata('legacy-aid');
    expect(loaded).not.toBeNull();
    expect(loaded!.session_id).toBe('legacy-session');
    expect(loaded!.e2ee_prekeys).toEqual({
      keep: { private_key_pem: 'KEEP', created_at: now - 1000 },
    });
    expect(loaded!.group_secrets).toEqual({
      'group-1': {
        epoch: 2,
        secret: 'group-secret-v2',
        updated_at: now - 1000,
        old_epochs: [
          { epoch: 1, secret: 'group-secret-v1', updated_at: now - 2000 },
        ],
      },
    });

    const rawMetadata = await readStoreRecord('metadata', 'legacy-aid');
    expect(rawMetadata).toEqual({ session_id: 'legacy-session' });

    expect(await ks.loadE2EEPrekeys('legacy-aid')).toEqual({
      keep: { private_key_pem: 'KEEP', created_at: now - 1000 },
    });
    expect(await ks.loadAllGroupSecretStates('legacy-aid')).toEqual({
      'group-1': {
        epoch: 2,
        secret: 'group-secret-v2',
        updated_at: now - 1000,
        old_epochs: [
          { epoch: 1, secret: 'group-secret-v1', updated_at: now - 2000 },
        ],
      },
    });
  });

  it('cleanupE2EEPrekeys 应仅清理超过 7 天且不在最新 7 个里的 prekey', async () => {
    const now = Date.now();
    const cutoffMs = now - (7 * 24 * 3600 * 1000);

    for (let i = 0; i < 8; i += 1) {
      await ks.saveE2EEPrekey('cleanup-aid', `old-${i}`, {
        private_key_pem: `OLD-${i}`,
        created_at: cutoffMs - 1000 - (8 - i),
      });
    }
    await ks.saveE2EEPrekey('cleanup-aid', 'current', {
      private_key_pem: 'CURRENT',
      created_at: now,
    });

    const removed = await ks.cleanupE2EEPrekeys('cleanup-aid', cutoffMs, 7);
    expect(removed.sort()).toEqual(['old-0', 'old-1']);

    const prekeys = await ks.loadE2EEPrekeys('cleanup-aid');
    expect(Object.keys(prekeys)).toHaveLength(7);
    expect(prekeys['old-0']).toBeUndefined();
    expect(prekeys['old-1']).toBeUndefined();
    expect(prekeys.current.private_key_pem).toBe('CURRENT');
  });

  it('加载不存在的 metadata 应返回 null', async () => {
    expect(await ks.loadMetadata('nonexistent')).toBeNull();
  });

  // ── 身份组合操作 ──────────────────────────────────

  it('saveIdentity 应拆分保存到各仓库', async () => {
    const identity = {
      private_key_pem: 'pk-pem',
      public_key_der_b64: 'pub-b64',
      curve: 'P-256',
      cert: '-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----',
      session_id: 'sess-abc',
      access_token: 'token-123',
    };
    await ks.saveIdentity('alice', identity);

    // 密钥对应独立保存
    const kp = await ks.loadKeyPair('alice');
    expect(kp!.private_key_pem).toBe('pk-pem');

    // 证书应独立保存
    const cert = await ks.loadCert('alice');
    expect(cert).toContain('cert');

    // metadata 应包含非密钥/非证书字段
    const md = await ks.loadMetadata('alice');
    expect(md!.session_id).toBe('sess-abc');
    expect(md!.access_token).toBe('token-123');
    // metadata 不应包含密钥字段
    expect(md!.private_key_pem).toBeUndefined();
    expect(md!.cert).toBeUndefined();
  });

  it('loadIdentity 应合并所有仓库数据', async () => {
    await ks.saveKeyPair('alice', { private_key_pem: 'pk', public_key_der_b64: 'pub', curve: 'P-256' });
    await ks.saveCert('alice', 'cert-pem');
    await ks.saveMetadata('alice', { session_id: 'sess' });

    const identity = await ks.loadIdentity('alice');
    expect(identity).not.toBeNull();
    expect(identity!.private_key_pem).toBe('pk');
    expect(identity!.cert).toBe('cert-pem');
    expect(identity!.session_id).toBe('sess');
  });

  it('加载不存在的身份应返回 null', async () => {
    expect(await ks.loadIdentity('nonexistent')).toBeNull();
  });

  // ── AID 安全化 ──────────────────────────────────────

  it('AID 中的特殊字符应被安全处理', async () => {
    const aid = 'alice/test:path\\back';
    await ks.saveKeyPair(aid, { key: 'val' });
    const loaded = await ks.loadKeyPair(aid);
    expect(loaded).not.toBeNull();
    expect(loaded!.key).toBe('val');
  });
});

// ── IndexedDBSecretStore 测试 ──────────────────────────

describe('IndexedDBSecretStore', () => {
  it.skipIf(!hasSubtleCrypto)(
    'protect → reveal 往返应还原原始数据',
    async () => {
      const store = new IndexedDBSecretStore('test-seed-12345');
      const plaintext = new TextEncoder().encode('super-secret');
      const record = await store.protect('scope1', 'name1', plaintext);

      expect(record.scheme).toBe('indexeddb_aes_gcm');
      expect(record.name).toBe('name1');
      expect(record.persisted).toBe(true);
      expect(record.iv).toBeDefined();
      expect(record.ciphertext).toBeDefined();

      const revealed = await store.reveal('scope1', 'name1', record);
      expect(revealed).not.toBeNull();
      expect(new TextDecoder().decode(revealed!)).toBe('super-secret');
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    '不同种子应无法解密',
    async () => {
      const store1 = new IndexedDBSecretStore('seed-1');
      const store2 = new IndexedDBSecretStore('seed-2');
      const plaintext = new TextEncoder().encode('secret');
      const record = await store1.protect('s', 'k', plaintext);

      // store2 使用不同种子，解密应失败
      const revealed = await store2.reveal('s', 'k', record);
      expect(revealed).toBeNull();
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    'reveal 使用错误 scheme 应返回 null',
    async () => {
      const store = new IndexedDBSecretStore('test-seed');
      const result = await store.reveal('s', 'k', { scheme: 'wrong', name: 'k' });
      expect(result).toBeNull();
    },
  );

});
