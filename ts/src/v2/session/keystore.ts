/**
 * V2 E2EE 设备密钥存储。
 *
 * 每个 (aid, device_id) 持有一对 IK 和若干 SPK（按 spk_id 索引）。
 * 表结构与 Python / Go SDK 完全一致（v2_device_keys）。
 *
 * 实现说明：
 * - TS SDK 统一使用 Node 22+ 内置的 `node:sqlite`（与 `keystore/aid-db.ts` 保持一致）
 * - 接受任意 sqlite-like 句柄（exec / prepare），便于复用 AIDDatabase 的连接
 * - BLOB 字段返回 Uint8Array（node:sqlite 默认行为）
 */

interface SqliteStatement {
  run(...params: unknown[]): unknown;
  get(...params: unknown[]): unknown;
  all(...params: unknown[]): unknown;
}

export interface SqliteLike {
  exec(sql: string): unknown;
  prepare(sql: string): SqliteStatement;
}

export const V2_DEVICE_KEYS_DDL = `
CREATE TABLE IF NOT EXISTS v2_device_keys (
    device_id TEXT NOT NULL,
    key_type TEXT NOT NULL,
    key_id TEXT NOT NULL DEFAULT '',
    private_key BLOB NOT NULL,
    public_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, key_type, key_id)
)`;

function asBuffer(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (Buffer.isBuffer(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (Array.isArray(value)) return new Uint8Array(value as number[]);
  throw new Error(`unexpected blob type: ${typeof value}`);
}

/** node:sqlite 不接受裸 Uint8Array，需要 Buffer 包装才会绑定为 BLOB。 */
function toSqliteBlob(value: Uint8Array): Buffer {
  return Buffer.isBuffer(value) ? value : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

export class V2KeyStore {
  private db: SqliteLike;

  constructor(db: SqliteLike) {
    this.db = db;
    this.db.exec(V2_DEVICE_KEYS_DDL);
  }

  saveIK(deviceId: string, priv: Uint8Array, pubDer: Uint8Array): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, key_id, private_key, public_key, created_at)
         VALUES (?, 'ik', '', ?, ?, ?)`,
      )
      .run(deviceId, toSqliteBlob(priv), toSqliteBlob(pubDer), Date.now());
  }

  loadIK(deviceId: string): { priv: Uint8Array; pubDer: Uint8Array } | null {
    const row = this.db
      .prepare(
        `SELECT private_key, public_key FROM v2_device_keys WHERE device_id=? AND key_type='ik' AND key_id=''`,
      )
      .get(deviceId) as { private_key: unknown; public_key: unknown } | undefined;
    if (!row) return null;
    return { priv: asBuffer(row.private_key), pubDer: asBuffer(row.public_key) };
  }

  saveSPK(deviceId: string, spkId: string, priv: Uint8Array, pubDer: Uint8Array): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, key_id, private_key, public_key, created_at)
         VALUES (?, 'spk', ?, ?, ?, ?)`,
      )
      .run(deviceId, spkId, toSqliteBlob(priv), toSqliteBlob(pubDer), Date.now());
  }

  loadSPK(deviceId: string, spkId: string): Uint8Array | null {
    const row = this.db
      .prepare(
        `SELECT private_key FROM v2_device_keys WHERE device_id=? AND key_type='spk' AND key_id=?`,
      )
      .get(deviceId, spkId) as { private_key: unknown } | undefined;
    return row ? asBuffer(row.private_key) : null;
  }

  loadCurrentSPK(deviceId: string): { spkId: string; priv: Uint8Array; pubDer: Uint8Array } | null {
    const row = this.db
      .prepare(
        `SELECT key_id, private_key, public_key FROM v2_device_keys
         WHERE device_id=? AND key_type='spk' ORDER BY created_at DESC, key_id DESC LIMIT 1`,
      )
      .get(deviceId) as { key_id: string; private_key: unknown; public_key: unknown } | undefined;
    if (!row) return null;
    return {
      spkId: row.key_id,
      priv: asBuffer(row.private_key),
      pubDer: asBuffer(row.public_key),
    };
  }

  deleteSPK(deviceId: string, spkId: string): void {
    this.db
      .prepare(`DELETE FROM v2_device_keys WHERE device_id=? AND key_type='spk' AND key_id=?`)
      .run(deviceId, spkId);
  }

  listRecentSPKIds(deviceId: string, n: number): string[] {
    if (n <= 0) return [];
    const rows = this.db
      .prepare(
        `SELECT key_id FROM v2_device_keys
         WHERE device_id=? AND key_type='spk' ORDER BY created_at DESC, key_id DESC LIMIT ?`,
      )
      .all(deviceId, n) as Array<{ key_id: string }>;
    return rows.map((r) => r.key_id);
  }

  listExpiredSPKIds(deviceId: string, maxAgeMs: number): string[] {
    const cutoff = Date.now() / 1000 - maxAgeMs / 1000;
    const rows = this.db
      .prepare(
        `SELECT key_id FROM v2_device_keys
         WHERE device_id=? AND key_type='spk' AND created_at < ?`,
      )
      .all(deviceId, cutoff) as Array<{ key_id: string }>;
    return rows.map((r) => r.key_id);
  }
}
