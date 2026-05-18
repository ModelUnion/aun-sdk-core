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
export const V2_DB_VERSION = 1;
export const V2_STORE_NAME = 'v2_device_keys';
export const V2_INDEX_BY_DEVICE_TYPE_CREATED = 'by_device_type_created';

type KeyType = 'ik' | 'spk';

interface V2KeyRecord {
  device_id: string;
  key_type: KeyType;
  key_id: string; // IK 用空串
  private_key: Uint8Array;
  public_key: Uint8Array;
  created_at: number; // ms
}

/**
 * V2 设备密钥持久化存储。复合主键 [device_id, key_type, key_id]。
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
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(V2_STORE_NAME)) {
          const store = db.createObjectStore(V2_STORE_NAME, {
            keyPath: ['device_id', 'key_type', 'key_id'],
          });
          store.createIndex(
            V2_INDEX_BY_DEVICE_TYPE_CREATED,
            ['device_id', 'key_type', 'created_at'],
          );
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
      const req = this.store('readonly').get([deviceId, 'spk', spkId]);
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
        [deviceId, 'spk', -Infinity],
        [deviceId, 'spk', Infinity],
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
    return new Promise((resolve, reject) => {
      const req = this.store('readwrite').delete([deviceId, 'spk', spkId]);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  /** 返回最近 N 代 SPK 的 spk_id（按 created_at DESC）。 */
  async listRecentSPKIds(deviceId: string, n: number): Promise<string[]> {
    if (n <= 0) return [];
    return new Promise((resolve, reject) => {
      const idx = this.store('readonly').index(V2_INDEX_BY_DEVICE_TYPE_CREATED);
      const range = IDBKeyRange.bound(
        [deviceId, 'spk', -Infinity],
        [deviceId, 'spk', Infinity],
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

  // ---------- IK ----------

  async saveIK(deviceId: string, priv: Uint8Array, pubDer: Uint8Array): Promise<void> {
    const record: V2KeyRecord = {
      device_id: deviceId,
      key_type: 'ik',
      key_id: '',
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

  async loadIK(
    deviceId: string,
  ): Promise<{ priv: Uint8Array; pubDer: Uint8Array } | null> {
    return new Promise((resolve, reject) => {
      const req = this.store('readonly').get([deviceId, 'ik', '']);
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
