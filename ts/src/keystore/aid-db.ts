/**
 * Per-AID SQLite 数据库（对标 Python sqlcipher_db.py / Go aid_db.go）
 *
 * 每个 AID 一个独立的 aun_{deviceId}.db，表结构与 Python 完全一致。
 * DB 中敏感字段存明文（无 SQLCipher，与 Python 降级行为一致）。
 */

import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const SCHEMA_VERSION = 1;

// 全局 per-path 单例缓存：同一个 db 文件路径在整个进程中只创建一个 Database 实例
const _dbPool = new Map<string, { db: Database.Database; refCount: number }>();

const DDL_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS _schema_version (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS tokens (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS prekeys (
    prekey_id TEXT NOT NULL,
    device_id TEXT NOT NULL DEFAULT '',
    private_key_enc TEXT NOT NULL DEFAULT '',
    data TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER,
    PRIMARY KEY (prekey_id, device_id)
  )`,
  `CREATE INDEX IF NOT EXISTS idx_prekeys_device ON prekeys (device_id, created_at)`,
  `CREATE TABLE IF NOT EXISTS group_current (
    group_id TEXT PRIMARY KEY,
    epoch INTEGER NOT NULL,
    secret_enc TEXT NOT NULL DEFAULT '',
    data TEXT NOT NULL DEFAULT '{}',
    updated_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS group_old_epochs (
    group_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    secret_enc TEXT NOT NULL DEFAULT '',
    data TEXT NOT NULL DEFAULT '{}',
    updated_at INTEGER NOT NULL,
    expires_at INTEGER,
    PRIMARY KEY (group_id, epoch)
  )`,
  `CREATE INDEX IF NOT EXISTS idx_group_old_expires ON group_old_epochs (group_id, expires_at)`,
  `CREATE TABLE IF NOT EXISTS e2ee_sessions (
    session_id TEXT PRIMARY KEY,
    data_enc TEXT NOT NULL DEFAULT '{}',
    updated_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS instance_state (
    device_id TEXT NOT NULL,
    slot_id TEXT NOT NULL DEFAULT '_singleton',
    data TEXT NOT NULL DEFAULT '{}',
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, slot_id)
  )`,
  `CREATE TABLE IF NOT EXISTS seq_tracker (
    device_id TEXT NOT NULL,
    slot_id TEXT NOT NULL DEFAULT '_singleton',
    namespace TEXT NOT NULL,
    contiguous_seq INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, slot_id, namespace)
  )`,
  `CREATE TABLE IF NOT EXISTS metadata_kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  )`,
];

export class AIDDatabase {
  private _db: Database.Database;
  private _dbPath: string;

  constructor(dbPath: string) {
    mkdirSync(dirname(dbPath), { recursive: true });
    const absPath = resolve(dbPath);
    this._dbPath = absPath;
    const cached = _dbPool.get(absPath);
    if (cached) {
      cached.refCount++;
      this._db = cached.db;
    } else {
      this._db = new Database(dbPath);
      this._db.pragma('journal_mode = WAL');
      this._db.pragma('busy_timeout = 5000');
      _dbPool.set(absPath, { db: this._db, refCount: 1 });
    }
    this._initSchema();
  }

  close(): void {
    const cached = _dbPool.get(this._dbPath);
    if (cached) {
      cached.refCount--;
      if (cached.refCount <= 0) {
        _dbPool.delete(this._dbPath);
        this._db.close();
      }
    } else {
      this._db.close();
    }
  }

  private _initSchema(): void {
    for (const ddl of DDL_STATEMENTS) {
      this._db.exec(ddl);
    }
    const row = this._db.prepare('SELECT version FROM _schema_version WHERE id = 1').get() as { version: number } | undefined;
    if (!row) {
      this._db.prepare('INSERT INTO _schema_version (id, version) VALUES (1, ?)').run(SCHEMA_VERSION);
    }
  }

  // ── Tokens ───────────────────────────────────────────────

  getToken(key: string): string | null {
    const row = this._db.prepare('SELECT value FROM tokens WHERE key = ?').get(key) as { value: string } | undefined;
    return row?.value ?? null;
  }

  setToken(key: string, value: string): void {
    this._db.prepare(
      'INSERT INTO tokens (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at',
    ).run(key, value, Date.now());
  }

  deleteToken(key: string): void {
    this._db.prepare('DELETE FROM tokens WHERE key = ?').run(key);
  }

  getAllTokens(): Record<string, string> {
    const rows = this._db.prepare('SELECT key, value FROM tokens').all() as Array<{ key: string; value: string }>;
    const result: Record<string, string> = {};
    for (const r of rows) result[r.key] = r.value;
    return result;
  }

  // ── Prekeys ──────────────────────────────────────────────

  savePrekey(prekeyId: string, privateKeyPem: string, deviceId = '', createdAt?: number, expiresAt?: number, extraData?: Record<string, unknown>): void {
    const now = Date.now();

    const dataJson = JSON.stringify(extraData ?? {});
    this._db.prepare(
      `INSERT INTO prekeys (prekey_id, device_id, private_key_enc, data, created_at, updated_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(prekey_id, device_id) DO UPDATE SET
         private_key_enc=excluded.private_key_enc, data=excluded.data,
         updated_at=excluded.updated_at, expires_at=excluded.expires_at`,
    ).run(prekeyId, deviceId, privateKeyPem, dataJson, createdAt ?? now, now, expiresAt ?? null);
  }

  loadPrekeys(deviceId = ''): Record<string, Record<string, unknown>> {
    const rows = this._db.prepare(
      'SELECT prekey_id, private_key_enc, data, created_at, updated_at, expires_at FROM prekeys WHERE device_id = ?',
    ).all(deviceId) as Array<{ prekey_id: string; private_key_enc: string; data: string; created_at: number | null; updated_at: number | null; expires_at: number | null }>;
    const result: Record<string, Record<string, unknown>> = {};
    for (const row of rows) {
      const entry: Record<string, unknown> = {
        private_key_pem: row.private_key_enc,
      };
      if (row.created_at != null) entry.created_at = row.created_at;
      if (row.updated_at != null) entry.updated_at = row.updated_at;
      if (row.expires_at != null) entry.expires_at = row.expires_at;
      try {
        const extra = JSON.parse(row.data);
        if (extra && typeof extra === 'object') Object.assign(entry, extra);
      } catch { /* ignore */ }
      result[row.prekey_id] = entry;
    }
    return result;
  }

  deletePrekey(prekeyId: string, deviceId = ''): void {
    this._db.prepare('DELETE FROM prekeys WHERE prekey_id = ? AND device_id = ?').run(prekeyId, deviceId);
  }

  cleanupPrekeys(deviceId: string, cutoffMs: number, keepLatest: number): string[] {
    const rows = this._db.prepare(
      'SELECT prekey_id, created_at FROM prekeys WHERE device_id = ? ORDER BY created_at DESC',
    ).all(deviceId) as Array<{ prekey_id: string; created_at: number | null }>;
    const latestIds = new Set(rows.slice(0, keepLatest).map((r) => r.prekey_id));
    const toDelete = rows
      .filter((r) => !latestIds.has(r.prekey_id) && r.created_at != null && r.created_at < cutoffMs)
      .map((r) => r.prekey_id);
    if (toDelete.length > 0) {
      const del = this._db.prepare('DELETE FROM prekeys WHERE device_id = ? AND prekey_id = ?');
      const txn = this._db.transaction(() => {
        for (const id of toDelete) del.run(deviceId, id);
      });
      txn();
    }
    return toDelete;
  }

  // ── Group Current ────────────────────────────────────────

  saveGroupCurrent(groupId: string, epoch: number, secret: string, data: Record<string, unknown>): void {
    this._db.prepare(
      `INSERT INTO group_current (group_id, epoch, secret_enc, data, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(group_id) DO UPDATE SET epoch=excluded.epoch, secret_enc=excluded.secret_enc, data=excluded.data, updated_at=excluded.updated_at`,
    ).run(groupId, epoch, secret, JSON.stringify(data), Date.now());
  }

  loadGroupCurrent(groupId: string): Record<string, unknown> | null {
    const row = this._db.prepare('SELECT epoch, secret_enc, data, updated_at FROM group_current WHERE group_id = ?').get(groupId) as
      { epoch: number; secret_enc: string; data: string; updated_at: number } | undefined;
    if (!row) return null;
    const result: Record<string, unknown> = {
      group_id: groupId, epoch: row.epoch,
      secret: row.secret_enc,
      updated_at: row.updated_at,
    };
    try { Object.assign(result, JSON.parse(row.data)); } catch { /* ignore */ }
    return result;
  }

  loadAllGroupCurrent(): Record<string, Record<string, unknown>> {
    const rows = this._db.prepare('SELECT group_id, epoch, secret_enc, data, updated_at FROM group_current').all() as
      Array<{ group_id: string; epoch: number; secret_enc: string; data: string; updated_at: number }>;
    const result: Record<string, Record<string, unknown>> = {};
    for (const row of rows) {
      const entry: Record<string, unknown> = {
        group_id: row.group_id, epoch: row.epoch,
        secret: row.secret_enc,
        updated_at: row.updated_at,
      };
      try { Object.assign(entry, JSON.parse(row.data)); } catch { /* ignore */ }
      result[row.group_id] = entry;
    }
    return result;
  }

  deleteGroupCurrent(groupId: string): void {
    this._db.prepare('DELETE FROM group_current WHERE group_id = ?').run(groupId);
  }

  // ── Group Old Epochs ─────────────────────────────────────

  saveGroupOldEpoch(groupId: string, epoch: number, secret: string, data: Record<string, unknown>, updatedAt?: number, expiresAt?: number): void {
    this._db.prepare(
      `INSERT INTO group_old_epochs (group_id, epoch, secret_enc, data, updated_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(group_id, epoch) DO UPDATE SET secret_enc=excluded.secret_enc, data=excluded.data, updated_at=excluded.updated_at, expires_at=excluded.expires_at`,
    ).run(groupId, epoch, secret, JSON.stringify(data), updatedAt ?? Date.now(), expiresAt ?? null);
  }

  loadGroupOldEpochs(groupId: string): Array<Record<string, unknown>> {
    const rows = this._db.prepare(
      'SELECT epoch, secret_enc, data, updated_at, expires_at FROM group_old_epochs WHERE group_id = ? ORDER BY epoch ASC',
    ).all(groupId) as Array<{ epoch: number; secret_enc: string; data: string; updated_at: number; expires_at: number | null }>;
    return rows.map((row) => {
      const entry: Record<string, unknown> = {
        epoch: row.epoch,
        secret: row.secret_enc,
        updated_at: row.updated_at,
      };
      if (row.expires_at != null) entry.expires_at = row.expires_at;
      try { Object.assign(entry, JSON.parse(row.data)); } catch { /* ignore */ }
      return entry;
    });
  }

  deleteAllGroupOldEpochs(groupId: string): void {
    this._db.prepare('DELETE FROM group_old_epochs WHERE group_id = ?').run(groupId);
  }

  loadAllGroupIdsWithOldEpochs(): string[] {
    const rows = this._db.prepare('SELECT DISTINCT group_id FROM group_old_epochs').all() as Array<{ group_id: string }>;
    return rows.map((row) => row.group_id);
  }

  cleanupGroupOldEpochs(groupId: string, cutoffMs: number): number {
    const result = this._db.prepare(
      'DELETE FROM group_old_epochs WHERE group_id = ? AND (CASE WHEN expires_at IS NOT NULL THEN expires_at ELSE updated_at END) < ?',
    ).run(groupId, cutoffMs);
    return result.changes;
  }

  // ── E2EE Sessions ────────────────────────────────────────

  saveSession(sessionId: string, data: Record<string, unknown>): void {
    const dataJson = JSON.stringify(data);
    this._db.prepare(
      'INSERT INTO e2ee_sessions (session_id, data_enc, updated_at) VALUES (?, ?, ?) ON CONFLICT(session_id) DO UPDATE SET data_enc=excluded.data_enc, updated_at=excluded.updated_at',
    ).run(sessionId, dataJson, Date.now());
  }

  loadAllSessions(): Array<Record<string, unknown>> {
    const rows = this._db.prepare('SELECT session_id, data_enc, updated_at FROM e2ee_sessions').all() as
      Array<{ session_id: string; data_enc: string; updated_at: number }>;
    return rows.map((row) => {
      const plain = row.data_enc;
      let entry: Record<string, unknown> = {};
      try { entry = JSON.parse(plain); } catch { /* ignore */ }
      entry.session_id = row.session_id;
      entry.updated_at = row.updated_at;
      return entry;
    });
  }

  deleteSession(sessionId: string): void {
    this._db.prepare('DELETE FROM e2ee_sessions WHERE session_id = ?').run(sessionId);
  }

  // ── Instance State ───────────────────────────────────────

  saveInstanceState(deviceId: string, slotId: string, state: Record<string, unknown>): void {
    const slot = slotId || '_singleton';
    this._db.prepare(
      'INSERT INTO instance_state (device_id, slot_id, data, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(device_id, slot_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at',
    ).run(deviceId, slot, JSON.stringify(state), Date.now());
  }

  loadInstanceState(deviceId: string, slotId = ''): Record<string, unknown> | null {
    const slot = slotId || '_singleton';
    const row = this._db.prepare('SELECT data FROM instance_state WHERE device_id = ? AND slot_id = ?').get(deviceId, slot) as { data: string } | undefined;
    if (!row) return null;
    try { return JSON.parse(row.data); } catch { return null; }
  }

  // ── Seq Tracker ────────────────────────────────────────────

  saveSeq(deviceId: string, slotId: string, namespace: string, contiguousSeq: number): void {
    const slot = slotId || '_singleton';
    this._db.prepare(
      'INSERT INTO seq_tracker (device_id, slot_id, namespace, contiguous_seq, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(device_id, slot_id, namespace) DO UPDATE SET contiguous_seq=excluded.contiguous_seq, updated_at=excluded.updated_at',
    ).run(deviceId, slot, namespace, contiguousSeq, Date.now());
  }

  loadSeq(deviceId: string, slotId: string, namespace: string): number {
    const slot = slotId || '_singleton';
    const row = this._db.prepare(
      'SELECT contiguous_seq FROM seq_tracker WHERE device_id = ? AND slot_id = ? AND namespace = ?',
    ).get(deviceId, slot, namespace) as { contiguous_seq: number } | undefined;
    return row?.contiguous_seq ?? 0;
  }

  loadAllSeqs(deviceId: string, slotId: string): Record<string, number> {
    const slot = slotId || '_singleton';
    const rows = this._db.prepare(
      'SELECT namespace, contiguous_seq FROM seq_tracker WHERE device_id = ? AND slot_id = ?',
    ).all(deviceId, slot) as Array<{ namespace: string; contiguous_seq: number }>;
    const result: Record<string, number> = {};
    for (const r of rows) result[r.namespace] = r.contiguous_seq;
    return result;
  }

  // ── Metadata KV ──────────────────────────────────────────

  getMetadata(key: string): string | null {
    const row = this._db.prepare('SELECT value FROM metadata_kv WHERE key = ?').get(key) as { value: string } | undefined;
    return row?.value ?? null;
  }

  setMetadata(key: string, value: string): void {
    this._db.prepare(
      'INSERT INTO metadata_kv (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at',
    ).run(key, value, Date.now());
  }

  deleteMetadata(key: string): void {
    this._db.prepare('DELETE FROM metadata_kv WHERE key = ?').run(key);
  }

  getAllMetadata(): Record<string, string> {
    const rows = this._db.prepare('SELECT key, value FROM metadata_kv').all() as Array<{ key: string; value: string }>;
    const result: Record<string, string> = {};
    for (const r of rows) result[r.key] = r.value;
    return result;
  }
}
