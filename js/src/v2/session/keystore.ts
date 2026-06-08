/**
 * AUN E2EE V2: 设备密钥存储（IndexedDB 持久化）
 *
 * 与 Python `aun_core.v2.keystore.V2KeyStore` 行为对齐：
 * - 每个 `(device_id)` 持有一对 IK 与若干 SPK（按 spk_id 索引）
 * - SPK 按 created_at 排序，支持 `loadCurrentSPK` / `listRecentSPKIds(n)`
 *
 * 浏览器目标：所有 IO 是 async（IndexedDB 事务）。
 */

export const V2_DB_NAME = 'aun_v2';
export const V2_DB_VERSION = 3;
export const V2_STORE_NAME = 'v2_device_keys';
export const V2_INDEX_BY_DEVICE_TYPE_CREATED = 'by_device_type_created';

type KeyType = 'ik' | 'spk' | 'group_spk' | 'group_identity' | 'spk_uploaded' | 'group_spk_uploaded';

interface V2KeyRecord {
  device_id: string;
  key_type: KeyType;
  group_id: string;
  key_id: string; // IK 主记录用空串，IK fallback alias 用 sha256:<16hex>
  private_key: Uint8Array;
  public_key: Uint8Array;
  created_at: number; // ms
}

async function spkIdForPubDer(pubDer: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', pubDer.slice().buffer);
  const arr = new Uint8Array(buf);
  let hex = '';
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, '0');
  return `sha256:${hex.slice(0, 16)}`;
}

function migrateRecord(raw: Partial<V2KeyRecord>): V2KeyRecord {
  let groupId = String(raw.group_id ?? '');
  let keyId = String(raw.key_id ?? '');
  if ((raw.key_type === 'group_spk' || raw.key_type === 'group_spk_uploaded') && !groupId && keyId.includes('\0')) {
    const parts = keyId.split('\0');
    groupId = parts[0] ?? '';
    keyId = parts.slice(1).join('\0');
  }
  return {
    device_id: String(raw.device_id ?? ''),
    key_type: raw.key_type as KeyType,
    group_id: groupId,
    key_id: keyId,
    private_key: new Uint8Array(raw.private_key ?? new Uint8Array()),
    public_key: new Uint8Array(raw.public_key ?? new Uint8Array()),
    created_at: Number(raw.created_at ?? Date.now()),
  };
}

function createV2Store(db: IDBDatabase): IDBObjectStore {
  const store = db.createObjectStore(V2_STORE_NAME, {
    keyPath: ['device_id', 'key_type', 'group_id', 'key_id'],
  });
  store.createIndex(
    V2_INDEX_BY_DEVICE_TYPE_CREATED,
    ['device_id', 'key_type', 'group_id', 'created_at'],
  );
  return store;
}

function recreateScopeCreatedIndex(store: IDBObjectStore): void {
  if (store.indexNames.contains(V2_INDEX_BY_DEVICE_TYPE_CREATED)) {
    store.deleteIndex(V2_INDEX_BY_DEVICE_TYPE_CREATED);
  }
  store.createIndex(
    V2_INDEX_BY_DEVICE_TYPE_CREATED,
    ['device_id', 'key_type', 'group_id', 'created_at'],
  );
}

/**
 * V2 设备密钥持久化存储。复合主键 [device_id, key_type, group_id, key_id]。
 *
 * 使用 IndexedDB；在浏览器内置 indexedDB 不可用时（如 jsdom）请提前安装
 * `fake-indexeddb/auto` 作为 polyfill（见 `tests/setup.ts`）。
 */
export class V2KeyStore {
  constructor(private readonly db: IDBDatabase) {}

  /** 打开/创建 V2 keystore 数据库。 */
  static async open(dbName: string = V2_DB_NAME): Promise<V2KeyStore> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(dbName, V2_DB_VERSION);
      req.onupgradeneeded = (event) => {
        const db = req.result;
        if (!db.objectStoreNames.contains(V2_STORE_NAME)) {
          createV2Store(db);
          return;
        }
        if (event.oldVersion < 2) {
          const tx = req.transaction;
          if (!tx) throw new Error('V2KeyStore.open: missing upgrade transaction');
          const oldStore = tx.objectStore(V2_STORE_NAME);
          const getAllReq = oldStore.getAll();
          getAllReq.onsuccess = () => {
            const records = (getAllReq.result as Array<Partial<V2KeyRecord>>).map(migrateRecord);
            db.deleteObjectStore(V2_STORE_NAME);
            const store = createV2Store(db);
            for (const record of records) store.put(record);
          };
          getAllReq.onerror = () => reject(getAllReq.error);
        } else if (event.oldVersion < 3) {
          const tx = req.transaction;
          if (!tx) throw new Error('V2KeyStore.open: missing upgrade transaction');
          recreateScopeCreatedIndex(tx.objectStore(V2_STORE_NAME));
        }
      };
      req.onsuccess = () => resolve(new V2KeyStore(req.result));
      req.onerror = () => reject(req.error);
      req.onblocked = () => reject(new Error('V2KeyStore.open: blocked'));
    });
  }

  /** 关闭数据库连接（测试或释放资源时使用）。 */
  close(): void {
    this.db.close();
  }

  private store(mode: IDBTransactionMode): IDBObjectStore {
    return this.db.transaction(V2_STORE_NAME, mode).objectStore(V2_STORE_NAME);
  }


  private async _listRecordsByTypeNewestFirst(
    deviceId: string,
    keyType: KeyType,
    groupId: string,
  ): Promise<V2KeyRecord[]> {
    return new Promise((resolve, reject) => {
      const idx = this.store('readonly').index(V2_INDEX_BY_DEVICE_TYPE_CREATED);
      const range = IDBKeyRange.bound(
        [deviceId, keyType, groupId, -Infinity],
        [deviceId, keyType, groupId, Infinity],
      );
      const req = idx.openCursor(range, 'prev');
      const out: V2KeyRecord[] = [];
      req.onsuccess = () => {
        const cursor = req.result;
        if (cursor) {
          out.push(cursor.value as V2KeyRecord);
          cursor.continue();
        } else {
          resolve(out);
        }
      };
      req.onerror = () => reject(req.error);
    });
  }

  // ---------- SPK ----------

  async saveSPK(
    deviceId: string,
    spkId: string,
    priv: Uint8Array,
    pubDer: Uint8Array,
  ): Promise<void> {
    const record: V2KeyRecord = {
      device_id: deviceId,
      key_type: 'spk',
      group_id: '',
      key_id: spkId,
      private_key: priv,
      public_key: pubDer,
      created_at: Date.now(),
    };
    return new Promise((resolve, reject) => {
      const req = this.store('readwrite').put(record);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async loadSPK(deviceId: string, spkId: string): Promise<Uint8Array | null> {
    return new Promise((resolve, reject) => {
      const req = this.store('readonly').get([deviceId, 'spk', '', spkId]);
      req.onsuccess = () => {
        const r = req.result as V2KeyRecord | undefined;
        // 用 new Uint8Array(...) 拷贝，规避 fake-indexeddb / 跨 realm 实例对象
        resolve(r ? new Uint8Array(r.private_key) : null);
      };
      req.onerror = () => reject(req.error);
    });
  }

  /** 取最新 SPK（按 created_at DESC LIMIT 1）。 */
  async loadCurrentSPK(
    deviceId: string,
  ): Promise<{ spkId: string; priv: Uint8Array; pubDer: Uint8Array } | null> {
    return new Promise((resolve, reject) => {
      const idx = this.store('readonly').index(V2_INDEX_BY_DEVICE_TYPE_CREATED);
      const range = IDBKeyRange.bound(
        [deviceId, 'spk', '', -Infinity],
        [deviceId, 'spk', '', Infinity],
      );
      const req = idx.openCursor(range, 'prev');
      req.onsuccess = () => {
        const cursor = req.result;
        if (!cursor) {
          resolve(null);
          return;
        }
        const r = cursor.value as V2KeyRecord;
        resolve({
          spkId: r.key_id,
          priv: new Uint8Array(r.private_key),
          pubDer: new Uint8Array(r.public_key),
        });
      };
      req.onerror = () => reject(req.error);
    });
  }

  async deleteSPK(deviceId: string, spkId: string): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const req = this.store('readwrite').delete([deviceId, 'spk', '', spkId]);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
    await new Promise<void>((resolve, reject) => {
      const req = this.store('readwrite').delete([deviceId, 'spk_uploaded', '', spkId]);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async markSPKUploaded(deviceId: string, spkId: string): Promise<void> {
    const record: V2KeyRecord = {
      device_id: deviceId,
      key_type: 'spk_uploaded',
      group_id: '',
      key_id: spkId,
      private_key: new Uint8Array(),
      public_key: new Uint8Array(),
      created_at: Date.now(),
    };
    return new Promise((resolve, reject) => {
      const req = this.store('readwrite').put(record);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async loadLatestUploadedSPKId(deviceId: string): Promise<string | null> {
    const records = await this._listRecordsByTypeNewestFirst(deviceId, 'spk_uploaded', '');
    for (const record of records) {
      const spkId = record.key_id;
      if (await this.loadSPK(deviceId, spkId)) return spkId;
    }
    return null;
  }

  /** 返回最近 N 代 SPK 的 spk_id（按 created_at DESC）。 */
  async listRecentSPKIds(deviceId: string, n: number): Promise<string[]> {
    if (n <= 0) return [];
    return new Promise((resolve, reject) => {
      const idx = this.store('readonly').index(V2_INDEX_BY_DEVICE_TYPE_CREATED);
      const range = IDBKeyRange.bound(
        [deviceId, 'spk', '', -Infinity],
        [deviceId, 'spk', '', Infinity],
      );
      const req = idx.openCursor(range, 'prev');
      const out: string[] = [];
      req.onsuccess = () => {
        const cursor = req.result;
        if (cursor && out.length < n) {
          out.push((cursor.value as V2KeyRecord).key_id);
          cursor.continue();
        } else {
          resolve(out);
        }
      };
      req.onerror = () => reject(req.error);
    });
  }

  async listExpiredSPKIds(deviceId: string, maxAgeMs: number): Promise<string[]> {
    const cutoff = Date.now() - maxAgeMs;
    return new Promise((resolve, reject) => {
      const idx = this.store('readonly').index(V2_INDEX_BY_DEVICE_TYPE_CREATED);
      const range = IDBKeyRange.bound(
        [deviceId, 'spk', '', -Infinity],
        [deviceId, 'spk', '', cutoff],
        false, true,
      );
      const req = idx.openCursor(range);
      const out: string[] = [];
      req.onsuccess = () => {
        const cursor = req.result;
        if (cursor) {
          out.push((cursor.value as V2KeyRecord).key_id);
          cursor.continue();
        } else {
          resolve(out);
        }
      };
      req.onerror = () => reject(req.error);
    });
  }

  // ---------- Group SPK ----------

  async saveGroupSPK(
    deviceId: string,
    groupId: string,
    spkId: string,
    priv: Uint8Array,
    pubDer: Uint8Array,
  ): Promise<void> {
    const record: V2KeyRecord = {
      device_id: deviceId,
      key_type: 'group_spk',
      group_id: groupId,
      key_id: spkId,
      private_key: priv,
      public_key: pubDer,
      created_at: Date.now(),
    };
    return new Promise((resolve, reject) => {
      const req = this.store('readwrite').put(record);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async loadGroupSPK(
    deviceId: string,
    groupId: string,
    spkId: string,
  ): Promise<Uint8Array | null> {
    return new Promise((resolve, reject) => {
      const req = this.store('readonly').get([deviceId, 'group_spk', groupId, spkId]);
      req.onsuccess = () => {
        const r = req.result as V2KeyRecord | undefined;
        resolve(r ? new Uint8Array(r.private_key) : null);
      };
      req.onerror = () => reject(req.error);
    });
  }

  /** 取指定群最新 group SPK（按 created_at DESC）。 */
  async loadCurrentGroupSPK(
    deviceId: string,
    groupId: string,
  ): Promise<{ spkId: string; priv: Uint8Array; pubDer: Uint8Array } | null> {
    return new Promise((resolve, reject) => {
      const idx = this.store('readonly').index(V2_INDEX_BY_DEVICE_TYPE_CREATED);
      const range = IDBKeyRange.bound(
        [deviceId, 'group_spk', groupId, -Infinity],
        [deviceId, 'group_spk', groupId, Infinity],
      );
      const req = idx.openCursor(range, 'prev');
      req.onsuccess = () => {
        const cursor = req.result;
        if (!cursor) {
          resolve(null);
          return;
        }
        const r = cursor.value as V2KeyRecord;
        resolve({
          spkId: r.key_id,
          priv: new Uint8Array(r.private_key),
          pubDer: new Uint8Array(r.public_key),
        });
      };
      req.onerror = () => reject(req.error);
    });
  }

  async saveGroupIdentity(
    deviceId: string,
    groupAid: string,
    privateKeyPem: string,
    pubDer: Uint8Array,
  ): Promise<void> {
    const record: V2KeyRecord = {
      device_id: deviceId,
      key_type: 'group_identity',
      group_id: groupAid,
      key_id: '',
      private_key: new TextEncoder().encode(privateKeyPem),
      public_key: pubDer,
      created_at: Date.now(),
    };
    return new Promise((resolve, reject) => {
      const req = this.store('readwrite').put(record);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async loadGroupIdentity(
    deviceId: string,
    groupAid: string,
  ): Promise<{ privateKeyPem: string; pubDer: Uint8Array } | null> {
    return new Promise((resolve, reject) => {
      const req = this.store('readonly').get([deviceId, 'group_identity', groupAid, '']);
      req.onsuccess = () => {
        const r = req.result as V2KeyRecord | undefined;
        resolve(r ? {
          privateKeyPem: new TextDecoder().decode(r.private_key),
          pubDer: new Uint8Array(r.public_key),
        } : null);
      };
      req.onerror = () => reject(req.error);
    });
  }

  async markGroupSPKUploaded(deviceId: string, groupId: string, spkId: string): Promise<void> {
    const record: V2KeyRecord = {
      device_id: deviceId,
      key_type: 'group_spk_uploaded',
      group_id: groupId,
      key_id: spkId,
      private_key: new Uint8Array(),
      public_key: new Uint8Array(),
      created_at: Date.now(),
    };
    return new Promise((resolve, reject) => {
      const req = this.store('readwrite').put(record);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async loadLatestUploadedGroupSPKId(deviceId: string, groupId: string): Promise<string | null> {
    const records = await this._listRecordsByTypeNewestFirst(deviceId, 'group_spk_uploaded', groupId);
    for (const record of records) {
      const spkId = record.key_id;
      if (await this.loadGroupSPK(deviceId, groupId, spkId)) return spkId;
    }
    return null;
  }
  // ---------- IK ----------

  async saveIK(deviceId: string, priv: Uint8Array, pubDer: Uint8Array): Promise<void> {
    const record: V2KeyRecord = {
      device_id: deviceId,
      key_type: 'ik',
      group_id: '',
      key_id: '',
      private_key: priv,
      public_key: pubDer,
      created_at: Date.now(),
    };
    const aliasKeyId = await spkIdForPubDer(pubDer);
    const alias: V2KeyRecord = {
      ...record,
      key_id: aliasKeyId,
    };
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(V2_STORE_NAME, 'readwrite');
      const store = tx.objectStore(V2_STORE_NAME);
      store.put(record);
      store.put(alias);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async loadIK(
    deviceId: string,
  ): Promise<{ priv: Uint8Array; pubDer: Uint8Array } | null> {
    return new Promise((resolve, reject) => {
      const req = this.store('readonly').get([deviceId, 'ik', '', '']);
      req.onsuccess = () => {
        const r = req.result as V2KeyRecord | undefined;
        resolve(
          r ? { priv: new Uint8Array(r.private_key), pubDer: new Uint8Array(r.public_key) } : null,
        );
      };
      req.onerror = () => reject(req.error);
    });
  }

  async loadIKSPK(
    deviceId: string,
    spkId: string,
  ): Promise<{ priv: Uint8Array; pubDer: Uint8Array } | null> {
    return new Promise((resolve, reject) => {
      const req = this.store('readonly').get([deviceId, 'ik', '', spkId]);
      req.onsuccess = () => {
        const r = req.result as V2KeyRecord | undefined;
        resolve(
          r ? { priv: new Uint8Array(r.private_key), pubDer: new Uint8Array(r.public_key) } : null,
        );
      };
      req.onerror = () => reject(req.error);
    });
  }

  // ---------- 测试用 ----------

  /** 测试用：清空 store。 */
  async _clear(): Promise<void> {
    return new Promise((resolve, reject) => {
      const req = this.store('readwrite').clear();
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }
}
