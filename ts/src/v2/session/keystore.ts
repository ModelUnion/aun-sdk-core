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

import { createHash } from 'node:crypto';

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
    group_id TEXT NOT NULL DEFAULT '',
    key_id TEXT NOT NULL DEFAULT '',
    private_key BLOB NOT NULL,
    public_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, key_type, group_id, key_id)
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
function ikSpkId(pubDer: Uint8Array): string {
  const hashHex = createHash('sha256').update(pubDer).digest('hex');
  return `sha256:${hashHex.substring(0, 16)}`;
}

function isUploadedMarkerKeyType(keyType: string): boolean {
  return keyType === 'spk_uploaded' || keyType === 'group_spk_uploaded';
}

const UPLOADED_MARKER_BLOB = Buffer.from([0]);

function decodeLegacyTextHex(value: unknown): string {
  const hex = String(value ?? '');
  return Buffer.from(hex, 'hex').toString('utf8');
}

function normalizeLegacyBlob(value: unknown, keyType: string): Buffer {
  if (value === null || value === undefined) {
    if (isUploadedMarkerKeyType(keyType)) return UPLOADED_MARKER_BLOB;
    throw new Error(`missing v2 key blob for key_type=${keyType}`);
  }
  const blob = toSqliteBlob(asBuffer(value));
  if (blob.length === 0 && isUploadedMarkerKeyType(keyType)) return UPLOADED_MARKER_BLOB;
  return blob;
}

export class V2KeyStore {
  private db: SqliteLike;

  constructor(db: SqliteLike) {
    this.db = db;
    this.db.exec(V2_DEVICE_KEYS_DDL);
    this._migrateSchema();
  }

  private _migrateSchema(): void {
    const rows = this.db.prepare('PRAGMA table_info(v2_device_keys)').all() as Array<{ name: string; pk: number }>;
    const hasGroupId = rows.some((r) => r.name === 'group_id');
    const pkCols = rows.filter((r) => Number(r.pk) > 0).sort((a, b) => Number(a.pk) - Number(b.pk)).map((r) => r.name);
    const pkOk = JSON.stringify(pkCols) === JSON.stringify(['device_id', 'key_type', 'group_id', 'key_id']);
    if (hasGroupId && pkOk) {
      this.db.exec(
        'CREATE INDEX IF NOT EXISTS idx_v2_device_keys_scope_created ON v2_device_keys(device_id, key_type, group_id, created_at)',
      );
      return;
    }

    this.db.exec('BEGIN');
    try {
      this.db.exec('ALTER TABLE v2_device_keys RENAME TO v2_device_keys_legacy');
      this.db.exec(`
        CREATE TABLE v2_device_keys (
          device_id TEXT NOT NULL,
          key_type TEXT NOT NULL,
          group_id TEXT NOT NULL DEFAULT '',
          key_id TEXT NOT NULL DEFAULT '',
          private_key BLOB NOT NULL,
          public_key BLOB NOT NULL,
          created_at INTEGER NOT NULL,
          PRIMARY KEY (device_id, key_type, group_id, key_id)
        )`);
      const selectSql = hasGroupId
        ? 'SELECT device_id, key_type, group_id, hex(key_id) AS key_id_hex, private_key, public_key, created_at FROM v2_device_keys_legacy'
        : "SELECT device_id, key_type, '' AS group_id, hex(key_id) AS key_id_hex, private_key, public_key, created_at FROM v2_device_keys_legacy";
      const legacyRows = this.db.prepare(selectSql).all() as Array<{
        device_id: string;
        key_type: string;
        group_id: string;
        key_id_hex: string;
        private_key: unknown;
        public_key: unknown;
        created_at: number;
      }>;
      const insert = this.db.prepare(
        `INSERT OR REPLACE INTO v2_device_keys
         (device_id, key_type, group_id, key_id, private_key, public_key, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      );
      for (const row of legacyRows) {
        let groupId = String(row.group_id ?? '');
        let keyId = decodeLegacyTextHex(row.key_id_hex);
        if (row.key_type === 'group_spk' || row.key_type === 'group_spk_uploaded') {
          const keyIdBytes = Buffer.from(String(row.key_id_hex ?? ''), 'hex');
          const sep = keyIdBytes.indexOf(0);
          if (sep >= 0) {
            groupId = keyIdBytes.subarray(0, sep).toString('utf8');
            keyId = keyIdBytes.subarray(sep + 1).toString('utf8');
          }
        }
        let privateKey: Buffer;
        let publicKey: Buffer;
        try {
          privateKey = normalizeLegacyBlob(row.private_key, row.key_type);
          publicKey = normalizeLegacyBlob(row.public_key, row.key_type);
        } catch {
          continue;
        }
        insert.run(
          row.device_id,
          row.key_type,
          groupId,
          keyId,
          privateKey,
          publicKey,
          row.created_at,
        );
      }
      this.db.exec('DROP TABLE v2_device_keys_legacy');
      this.db.exec(
        'CREATE INDEX IF NOT EXISTS idx_v2_device_keys_scope_created ON v2_device_keys(device_id, key_type, group_id, created_at)',
      );
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  saveIK(deviceId: string, priv: Uint8Array, pubDer: Uint8Array): void {
    const stmt = this.db.prepare(
      `INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at)
       VALUES (?, 'ik', '', ?, ?, ?, ?)`,
    );
    const now = Date.now();
    stmt.run(deviceId, '', toSqliteBlob(priv), toSqliteBlob(pubDer), now);
    stmt.run(deviceId, ikSpkId(pubDer), toSqliteBlob(priv), toSqliteBlob(pubDer), now);
  }

  loadIK(deviceId: string): { priv: Uint8Array; pubDer: Uint8Array } | null {
    const row = this.db
      .prepare(
        `SELECT private_key, public_key FROM v2_device_keys WHERE device_id=? AND key_type='ik' AND group_id='' AND key_id=''`,
      )
      .get(deviceId) as { private_key: unknown; public_key: unknown } | undefined;
    if (!row) return null;
    return { priv: asBuffer(row.private_key), pubDer: asBuffer(row.public_key) };
  }

  loadIKSPK(deviceId: string, spkId: string): { priv: Uint8Array; pubDer: Uint8Array } | null {
    const row = this.db
      .prepare(
        `SELECT private_key, public_key FROM v2_device_keys WHERE device_id=? AND key_type='ik' AND group_id='' AND key_id=?`,
      )
      .get(deviceId, spkId) as { private_key: unknown; public_key: unknown } | undefined;
    if (!row) return null;
    return { priv: asBuffer(row.private_key), pubDer: asBuffer(row.public_key) };
  }

  saveSPK(deviceId: string, spkId: string, priv: Uint8Array, pubDer: Uint8Array): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at)
         VALUES (?, 'spk', '', ?, ?, ?, ?)`,
      )
      .run(deviceId, spkId, toSqliteBlob(priv), toSqliteBlob(pubDer), Date.now());
  }

  loadSPK(deviceId: string, spkId: string): Uint8Array | null {
    const row = this.db
      .prepare(
        `SELECT private_key FROM v2_device_keys WHERE device_id=? AND key_type='spk' AND group_id='' AND key_id=?`,
      )
      .get(deviceId, spkId) as { private_key: unknown } | undefined;
    return row ? asBuffer(row.private_key) : null;
  }

  loadCurrentSPK(deviceId: string): { spkId: string; priv: Uint8Array; pubDer: Uint8Array } | null {
    const row = this.db
      .prepare(
        `SELECT key_id, private_key, public_key FROM v2_device_keys
         WHERE device_id=? AND key_type='spk' AND group_id='' ORDER BY created_at DESC, key_id DESC LIMIT 1`,
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
      .prepare(`DELETE FROM v2_device_keys WHERE device_id=? AND key_type='spk' AND group_id='' AND key_id=?`)
      .run(deviceId, spkId);
    this.db
      .prepare(`DELETE FROM v2_device_keys WHERE device_id=? AND key_type='spk_uploaded' AND group_id='' AND key_id=?`)
      .run(deviceId, spkId);
  }

  markSPKUploaded(deviceId: string, spkId: string): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at)
         VALUES (?, 'spk_uploaded', '', ?, ?, ?, ?)`,
      )
      .run(deviceId, spkId, UPLOADED_MARKER_BLOB, UPLOADED_MARKER_BLOB, Date.now());
  }

  loadLatestUploadedSPKId(deviceId: string): string | null {
    const row = this.db
      .prepare(
        `SELECT marker.key_id FROM v2_device_keys AS marker
         WHERE marker.device_id=? AND marker.key_type='spk_uploaded' AND marker.group_id=''
           AND EXISTS (
             SELECT 1 FROM v2_device_keys AS key
             WHERE key.device_id=marker.device_id AND key.key_type='spk' AND key.group_id='' AND key.key_id=marker.key_id
           )
         ORDER BY marker.created_at DESC LIMIT 1`,
      )
      .get(deviceId) as { key_id: string } | undefined;
    return row ? row.key_id : null;
  }

  listRecentSPKIds(deviceId: string, n: number): string[] {
    if (n <= 0) return [];
    const rows = this.db
      .prepare(
        `SELECT key_id FROM v2_device_keys
         WHERE device_id=? AND key_type='spk' AND group_id='' ORDER BY created_at DESC, key_id DESC LIMIT ?`,
      )
      .all(deviceId, n) as Array<{ key_id: string }>;
    return rows.map((r) => r.key_id);
  }

  listExpiredSPKIds(deviceId: string, maxAgeMs: number): string[] {
    const cutoff = Date.now() - maxAgeMs;
    const rows = this.db
      .prepare(
        `SELECT key_id FROM v2_device_keys
         WHERE device_id=? AND key_type='spk' AND group_id='' AND created_at < ?`,
      )
      .all(deviceId, cutoff) as Array<{ key_id: string }>;
    return rows.map((r) => r.key_id);
  }

  // ── Group SPK ──────────────────────────────────────────────────

  saveGroupSPK(deviceId: string, groupId: string, spkId: string, priv: Uint8Array, pubDer: Uint8Array): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at)
         VALUES (?, 'group_spk', ?, ?, ?, ?, ?)`,
      )
      .run(deviceId, groupId, spkId, toSqliteBlob(priv), toSqliteBlob(pubDer), Date.now());
  }

  loadGroupSPK(deviceId: string, groupId: string, spkId: string): Uint8Array | null {
    const row = this.db
      .prepare(
        `SELECT private_key FROM v2_device_keys
         WHERE device_id=? AND key_type='group_spk' AND group_id=? AND key_id=?`,
      )
      .get(deviceId, groupId, spkId) as { private_key: unknown } | undefined;
    return row ? asBuffer(row.private_key) : null;
  }

  loadCurrentGroupSPK(deviceId: string, groupId: string): { spkId: string; priv: Uint8Array; pubDer: Uint8Array } | null {
    const row = this.db
      .prepare(
        `SELECT key_id, private_key, public_key FROM v2_device_keys
         WHERE device_id=? AND key_type='group_spk' AND group_id=?
         ORDER BY created_at DESC, key_id DESC LIMIT 1`,
      )
      .get(deviceId, groupId) as { key_id: string; private_key: unknown; public_key: unknown } | undefined;
    if (!row) return null;
    return {
      spkId: row.key_id,
      priv: asBuffer(row.private_key),
      pubDer: asBuffer(row.public_key),
    };
  }

  saveGroupIdentity(deviceId: string, groupAid: string, privateKeyPem: string, pubDer: Uint8Array): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at)
         VALUES (?, 'group_identity', ?, '', ?, ?, ?)`,
      )
      .run(deviceId, groupAid, Buffer.from(privateKeyPem, 'utf-8'), toSqliteBlob(pubDer), Date.now());
  }

  loadGroupIdentity(deviceId: string, groupAid: string): { privateKeyPem: string; pubDer: Uint8Array } | null {
    const row = this.db
      .prepare(
        `SELECT private_key, public_key FROM v2_device_keys
         WHERE device_id=? AND key_type='group_identity' AND group_id=? AND key_id=''`,
      )
      .get(deviceId, groupAid) as { private_key: unknown; public_key: unknown } | undefined;
    if (!row) return null;
    return {
      privateKeyPem: Buffer.from(asBuffer(row.private_key)).toString('utf-8'),
      pubDer: asBuffer(row.public_key),
    };
  }

  markGroupSPKUploaded(deviceId: string, groupId: string, spkId: string): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO v2_device_keys (device_id, key_type, group_id, key_id, private_key, public_key, created_at)
         VALUES (?, 'group_spk_uploaded', ?, ?, ?, ?, ?)`,
      )
      .run(deviceId, groupId, spkId, UPLOADED_MARKER_BLOB, UPLOADED_MARKER_BLOB, Date.now());
  }

  loadLatestUploadedGroupSPKId(deviceId: string, groupId: string): string | null {
    const row = this.db
      .prepare(
        `SELECT marker.key_id FROM v2_device_keys AS marker
         WHERE marker.device_id=? AND marker.key_type='group_spk_uploaded' AND marker.group_id=?
           AND EXISTS (
             SELECT 1 FROM v2_device_keys AS key
             WHERE key.device_id=marker.device_id AND key.key_type='group_spk' AND key.group_id=marker.group_id AND key.key_id=marker.key_id
           )
         ORDER BY marker.created_at DESC, marker.key_id DESC LIMIT 1`,
      )
      .get(deviceId, groupId) as { key_id: string } | undefined;
    return row ? row.key_id : null;
  }
}
