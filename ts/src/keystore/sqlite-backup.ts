/**
 * SQLite 备份层 + 结构化主存。
 *
 * 语义对齐 Python:
 * - metadata 仍作为兼容备份；
 * - prekeys / group_current / group_old_epochs 作为结构化主存；
 * - 业务层优先读取结构化主存，metadata 仅作为兼容视图和未过期回捞来源。
 */

import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { JsonObject } from '../types.js';

const SCHEMA_VERSION = 2;

type JsonMap = JsonObject;
type SQLiteParam = string | number | boolean | null | Buffer;

function toNumber(value: string | number | boolean | null | undefined | object): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.trunc(value);
  return null;
}

function defaultNumber(...values: Array<string | number | boolean | null | undefined | object>): number {
  for (const value of values) {
    const num = toNumber(value);
    if (num !== null) return num;
  }
  return 0;
}

export class SQLiteBackup {
  private _db: Database.Database | null = null;
  private _available = false;

  constructor(dbPath?: string) {
    if (!dbPath) {
      const dir = join(process.cwd(), '.aun_backup');
      try {
        mkdirSync(dir, { recursive: true });
      } catch { /* ignore */ }
      dbPath = join(dir, 'aun_backup.db');
    } else {
      try {
        mkdirSync(dirname(dbPath), { recursive: true });
      } catch { /* ignore */ }
    }
    try {
      this._db = new Database(dbPath);
      this._db.pragma('journal_mode = WAL');
      this._db.pragma('busy_timeout = 3000');
      this._initTables();
      this._available = true;
    } catch (err) {
      console.warn(`SQLite 备份初始化失败，降级为无备份模式: ${err}`);
    }
  }

  get available(): boolean {
    return this._available;
  }

  close(): void {
    this._db?.close();
  }

  backupSeed(seed: Buffer): void {
    this._exec('INSERT OR REPLACE INTO seed_backup (id, seed, updated_at) VALUES (1, ?, ?)', seed, Date.now());
  }

  restoreSeed(): Buffer | null {
    const row = this._queryOne<{ seed: Buffer }>('SELECT seed FROM seed_backup WHERE id = 1');
    return row ? Buffer.from(row.seed) : null;
  }

  backupDeviceId(deviceId: string): void {
    this._exec('INSERT OR REPLACE INTO device_id_backup (id, device_id, updated_at) VALUES (1, ?, ?)', deviceId, Date.now());
  }

  restoreDeviceId(): string | null {
    const row = this._queryOne<{ device_id: string }>('SELECT device_id FROM device_id_backup WHERE id = 1');
    return row?.device_id ?? null;
  }

  backupKeyPair(aid: string, data: string): void {
    this._exec('INSERT OR REPLACE INTO key_pairs (aid, data, updated_at) VALUES (?, ?, ?)', aid, data, Date.now());
  }

  restoreKeyPair(aid: string): string | null {
    const row = this._queryOne<{ data: string }>('SELECT data FROM key_pairs WHERE aid = ?', aid);
    return row?.data ?? null;
  }

  backupCert(aid: string, certPem: string): void {
    this._exec('INSERT OR REPLACE INTO certs (aid, cert_pem, updated_at) VALUES (?, ?, ?)', aid, certPem, Date.now());
  }

  restoreCert(aid: string): string | null {
    const row = this._queryOne<{ cert_pem: string }>('SELECT cert_pem FROM certs WHERE aid = ?', aid);
    return row?.cert_pem ?? null;
  }

  backupMetadata(aid: string, data: string): void {
    this._exec('INSERT OR REPLACE INTO metadata (aid, data, updated_at) VALUES (?, ?, ?)', aid, data, Date.now());
  }

  restoreMetadata(aid: string): string | null {
    const row = this._queryOne<{ data: string }>('SELECT data FROM metadata WHERE aid = ?', aid);
    return row?.data ?? null;
  }

  loadPrekeys(aid: string): Record<string, JsonMap> {
    const rows = this._queryAll<{ prekey_id: string; data: string }>(
      `SELECT prekey_id, data
         FROM prekeys
        WHERE aid = ?
        ORDER BY created_at ASC, prekey_id ASC`,
      aid,
    );
    const result: Record<string, JsonMap> = {};
    for (const row of rows) {
      try {
        const data = JSON.parse(row.data) as JsonMap;
        if (data && typeof data === 'object') result[row.prekey_id] = data;
      } catch { /* ignore */ }
    }
    return result;
  }

  replacePrekeys(aid: string, prekeys: Record<string, JsonMap>): void {
    if (!this._db) return;
    this._runTransaction(() => {
      const stmt = this._db!.prepare(`
        INSERT OR REPLACE INTO prekeys
          (aid, prekey_id, data, created_at, updated_at, expires_at, deleted_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      for (const [prekeyId, data] of Object.entries(prekeys)) {
        stmt.run(
          aid,
          prekeyId,
          JSON.stringify(data),
          toNumber(data.created_at),
          defaultNumber(data.updated_at, data.created_at, Date.now()),
          toNumber(data.expires_at),
          toNumber(data.deleted_at),
        );
      }
    }, 'replace_prekeys');
  }

  cleanupPrekeysBefore(aid: string, cutoffMs: number, keepLatest = 7): string[] {
    const rows = this._queryAll<{ prekey_id: string; created_at: number | null; updated_at: number | null; expires_at: number | null }>(
      `SELECT prekey_id, created_at, updated_at, expires_at
         FROM prekeys
        WHERE aid = ?`,
      aid,
    );
    const retainedIds = new Set(
      rows
        .slice()
        .sort((left, right) => {
          const leftMarker = defaultNumber(left.created_at, left.updated_at, left.expires_at, 0);
          const rightMarker = defaultNumber(right.created_at, right.updated_at, right.expires_at, 0);
          if (rightMarker !== leftMarker) return rightMarker - leftMarker;
          return right.prekey_id.localeCompare(left.prekey_id);
        })
        .slice(0, keepLatest)
        .map(row => row.prekey_id),
    );
    const prekeyIds = rows
      .filter((row) => {
        const marker = defaultNumber(row.created_at, row.updated_at, row.expires_at, 0);
        return marker < cutoffMs && !retainedIds.has(row.prekey_id);
      })
      .map(row => row.prekey_id);
    if (prekeyIds.length === 0 || !this._db) return prekeyIds;

    this._runTransaction(() => {
      const stmt = this._db!.prepare('DELETE FROM prekeys WHERE aid = ? AND prekey_id = ?');
      for (const prekeyId of prekeyIds) stmt.run(aid, prekeyId);
    }, 'cleanup_prekeys');
    return prekeyIds;
  }

  loadGroupEntries(aid: string): Record<string, JsonMap> {
    const result: Record<string, JsonMap> = {};

    const currentRows = this._queryAll<{ group_id: string; data: string }>(
      `SELECT group_id, data
         FROM group_current
        WHERE aid = ?
        ORDER BY group_id ASC`,
      aid,
    );
    for (const row of currentRows) {
      try {
        const data = JSON.parse(row.data) as JsonMap;
        if (data && typeof data === 'object') result[row.group_id] = data;
      } catch { /* ignore */ }
    }

    const oldRows = this._queryAll<{ group_id: string; data: string }>(
      `SELECT group_id, data
         FROM group_old_epochs
        WHERE aid = ?
        ORDER BY group_id ASC, epoch ASC`,
      aid,
    );
    for (const row of oldRows) {
      try {
        const data = JSON.parse(row.data) as JsonMap;
        if (!data || typeof data !== 'object') continue;
        const entry = result[row.group_id] ?? {};
        const oldEpochs = Array.isArray(entry.old_epochs) ? entry.old_epochs as JsonObject[] : [];
        entry.old_epochs = [...oldEpochs, data];
        result[row.group_id] = entry;
      } catch { /* ignore */ }
    }

    return result;
  }

  replaceGroupEntries(aid: string, entries: Record<string, JsonMap>): void {
    if (!this._db) return;
    this._runTransaction(() => {
      const currentStmt = this._db!.prepare(`
        INSERT OR REPLACE INTO group_current
          (aid, group_id, epoch, data, updated_at)
        VALUES (?, ?, ?, ?, ?)
      `);
      const oldStmt = this._db!.prepare(`
        INSERT OR REPLACE INTO group_old_epochs
          (aid, group_id, epoch, data, updated_at, expires_at, deleted_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);

      for (const [groupId, entry] of Object.entries(entries)) {
        const current = { ...entry };
        const oldEpochs = Array.isArray(current.old_epochs) ? current.old_epochs as JsonMap[] : [];
        delete current.old_epochs;

        const epoch = toNumber(current.epoch);
        const updatedAt = defaultNumber(current.updated_at, Date.now());
        if (epoch !== null) {
          currentStmt.run(aid, groupId, epoch, JSON.stringify(current), updatedAt);
        }

        for (const old of oldEpochs) {
          const oldEpoch = toNumber(old.epoch);
          if (oldEpoch === null) continue;
          oldStmt.run(
            aid,
            groupId,
            oldEpoch,
            JSON.stringify(old),
            defaultNumber(old.updated_at, updatedAt, Date.now()),
            toNumber(old.expires_at),
            toNumber(old.deleted_at),
          );
        }
      }
    }, 'replace_group_entries');
  }

  cleanupGroupOldEpochs(aid: string, groupId: string, cutoffMs: number): number[] {
    const rows = this._queryAll<{ epoch: number }>(
      `SELECT epoch
         FROM group_old_epochs
        WHERE aid = ?
          AND group_id = ?
          AND COALESCE(expires_at, updated_at, 0) < ?`,
      aid,
      groupId,
      cutoffMs,
    );
    const epochs = rows.map(row => row.epoch);
    if (epochs.length === 0 || !this._db) return epochs;

    this._runTransaction(() => {
      const stmt = this._db!.prepare('DELETE FROM group_old_epochs WHERE aid = ? AND group_id = ? AND epoch = ?');
      for (const epoch of epochs) stmt.run(aid, groupId, epoch);
    }, 'cleanup_group_old_epochs');
    return epochs;
  }

  private _initTables(): void {
    this._db!.exec(`
      CREATE TABLE IF NOT EXISTS _schema_version (
        id INTEGER PRIMARY KEY,
        version INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS seed_backup (
        id INTEGER PRIMARY KEY,
        seed BLOB NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS device_id_backup (
        id INTEGER PRIMARY KEY,
        device_id TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS key_pairs (
        aid TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS certs (
        aid TEXT PRIMARY KEY,
        cert_pem TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS metadata (
        aid TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS prekeys (
        aid TEXT NOT NULL,
        prekey_id TEXT NOT NULL,
        data TEXT NOT NULL,
        created_at INTEGER,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER,
        deleted_at INTEGER,
        PRIMARY KEY (aid, prekey_id)
      );
      CREATE TABLE IF NOT EXISTS group_current (
        aid TEXT NOT NULL,
        group_id TEXT NOT NULL,
        epoch INTEGER NOT NULL,
        data TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (aid, group_id)
      );
      CREATE TABLE IF NOT EXISTS group_old_epochs (
        aid TEXT NOT NULL,
        group_id TEXT NOT NULL,
        epoch INTEGER NOT NULL,
        data TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER,
        deleted_at INTEGER,
        PRIMARY KEY (aid, group_id, epoch)
      );
      CREATE INDEX IF NOT EXISTS idx_prekeys_aid_expires
        ON prekeys (aid, expires_at, created_at, updated_at);
      CREATE INDEX IF NOT EXISTS idx_group_old_epochs_aid_group_expires
        ON group_old_epochs (aid, group_id, expires_at, updated_at);
    `);
    this._migrate();
  }

  private _migrate(): void {
    const row = this._queryOne<{ version: number }>('SELECT version FROM _schema_version WHERE id = 1');
    const current = row?.version ?? 0;
    if (current !== SCHEMA_VERSION && this._db) {
      this._db.prepare('INSERT OR REPLACE INTO _schema_version (id, version) VALUES (1, ?)').run(SCHEMA_VERSION);
    }
  }

  private _runTransaction(fn: () => void, label: string): void {
    if (!this._db) return;
    try {
      const txn = this._db.transaction(fn);
      txn();
    } catch (err) {
      console.warn(`SQLite ${label} 失败: ${err}`);
    }
  }

  private _exec(sql: string, ...params: SQLiteParam[]): void {
    if (!this._db) return;
    try {
      this._db.prepare(sql).run(...params);
    } catch (err) {
      console.warn(`SQLite 备份写入失败: ${err}`);
    }
  }

  private _queryOne<T>(sql: string, ...params: SQLiteParam[]): T | undefined {
    if (!this._db) return undefined;
    try {
      return this._db.prepare(sql).get(...params) as T | undefined;
    } catch (err) {
      console.warn(`SQLite 备份读取失败: ${err}`);
      return undefined;
    }
  }

  private _queryAll<T>(sql: string, ...params: SQLiteParam[]): T[] {
    if (!this._db) return [];
    try {
      return this._db.prepare(sql).all(...params) as T[];
    } catch (err) {
      console.warn(`SQLite 备份读取失败: ${err}`);
      return [];
    }
  }
}
