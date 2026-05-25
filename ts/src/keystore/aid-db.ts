/**
 * Per-AID SQLite 数据库。
 *
 * E2EE V2 ONLY：这里不再提供旧版 E2EE 密钥材料存储。
 * V2 设备密钥由 `v2/session/keystore.ts` 通过同一个 SQLite 句柄维护。
 */

import { mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';

const SCHEMA_VERSION = 1;

type NodeDatabaseSync = import('node:sqlite').DatabaseSync;
type NodeDatabaseSyncOptions = import('node:sqlite').DatabaseSyncOptions;

const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as {
  DatabaseSync: new (path: string, options?: NodeDatabaseSyncOptions) => NodeDatabaseSync;
};

const _dbPool = new Map<string, { db: NodeDatabaseSync; refCount: number }>();

function configureDatabase(db: NodeDatabaseSync, busyTimeoutMs: number): void {
  db.exec(`PRAGMA busy_timeout = ${busyTimeoutMs}`);
  const row = db.prepare('PRAGMA journal_mode = WAL').get() as { journal_mode?: string } | undefined;
  if (String(row?.journal_mode ?? '').toLowerCase() !== 'wal') {
    throw new Error(`SQLite WAL 模式启用失败: journal_mode=${String(row?.journal_mode ?? '')}`);
  }
  db.exec('PRAGMA synchronous = NORMAL');
}

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
  `CREATE TABLE IF NOT EXISTS agent_md_cache (
    aid TEXT PRIMARY KEY,
    content TEXT NOT NULL DEFAULT '',
    local_etag TEXT NOT NULL DEFAULT '',
    remote_etag TEXT NOT NULL DEFAULT '',
    last_modified TEXT NOT NULL DEFAULT '',
    fetched_at INTEGER NOT NULL DEFAULT 0,
    observed_at INTEGER NOT NULL DEFAULT 0,
    checked_at INTEGER NOT NULL DEFAULT 0,
    remote_status TEXT NOT NULL DEFAULT '',
    verify_status TEXT NOT NULL DEFAULT '',
    verify_error TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS group_state (
    group_id TEXT PRIMARY KEY,
    state_version INTEGER NOT NULL DEFAULT 0,
    state_hash TEXT NOT NULL DEFAULT '',
    key_epoch INTEGER NOT NULL DEFAULT 0,
    membership_json TEXT NOT NULL DEFAULT '',
    policy_json TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL DEFAULT 0
  )`,
];

function jsonParseObject(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

export class AIDDatabase {
  private _db: NodeDatabaseSync;
  private _dbPath: string;
  private _scope: string;
  private _log: { error: (m: string, e?: Error) => void; warn: (m: string) => void; info: (m: string) => void; debug: (m: string) => void };

  constructor(dbPath: string, _secretStore?: unknown, scope?: string, logger?: { error: (m: string, e?: Error) => void; warn: (m: string) => void; info: (m: string) => void; debug: (m: string) => void }) {
    mkdirSync(dirname(dbPath), { recursive: true });
    const absPath = resolve(dbPath);
    this._dbPath = absPath;
    this._scope = scope ?? dirname(absPath).split(/[\\/]/).pop() ?? '';
    this._log = logger ?? { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };
    const cached = _dbPool.get(absPath);
    if (cached) {
      cached.refCount++;
      this._db = cached.db;
    } else {
      this._db = new DatabaseSync(absPath, { timeout: 5000, readBigInts: false });
      configureDatabase(this._db, 5000);
      _dbPool.set(absPath, { db: this._db, refCount: 1 });
    }
    this._initSchema();
    this._log.debug(`AIDDatabase ready: path=${this._dbPath} scope=${this._scope}`);
  }

  /** 暴露底层 SQLite 句柄，供 V2KeyStore 共享同一 DB 连接。 */
  getSqliteHandle(): { exec(sql: string): unknown; prepare(sql: string): { run(...p: unknown[]): unknown; get(...p: unknown[]): unknown; all(...p: unknown[]): unknown } } {
    return this._db as unknown as { exec(sql: string): unknown; prepare(sql: string): { run(...p: unknown[]): unknown; get(...p: unknown[]): unknown; all(...p: unknown[]): unknown } };
  }

  close(): void {
    const cached = _dbPool.get(this._dbPath);
    if (cached) {
      cached.refCount--;
      if (cached.refCount <= 0) {
        _dbPool.delete(this._dbPath);
        if (this._db.isOpen) this._db.close();
        this._log.debug(`AIDDatabase closed: path=${this._dbPath}`);
      }
    } else {
      if (this._db.isOpen) this._db.close();
      this._log.debug(`AIDDatabase closed (uncached): path=${this._dbPath}`);
    }
  }

  private _initSchema(): void {
    for (const ddl of DDL_STATEMENTS) this._db.exec(ddl);
    const row = this._db.prepare('SELECT version FROM _schema_version WHERE id = 1').get() as { version: number } | undefined;
    if (!row) this._db.prepare('INSERT INTO _schema_version (id, version) VALUES (1, ?)').run(SCHEMA_VERSION);
  }

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
    for (const row of rows) result[row.key] = row.value;
    return result;
  }

  saveInstanceState(deviceId: string, slotId: string, state: Record<string, unknown>): void {
    const slot = slotId || '_singleton';
    this._db.prepare(
      'INSERT INTO instance_state (device_id, slot_id, data, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(device_id, slot_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at',
    ).run(deviceId, slot, JSON.stringify(state), Date.now());
  }

  loadInstanceState(deviceId: string, slotId = ''): Record<string, unknown> | null {
    const slot = slotId || '_singleton';
    const row = this._db.prepare('SELECT data FROM instance_state WHERE device_id = ? AND slot_id = ?').get(deviceId, slot) as { data: string } | undefined;
    return row ? jsonParseObject(row.data) : null;
  }

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
    for (const row of rows) result[row.namespace] = row.contiguous_seq;
    return result;
  }

  deleteSeq(deviceId: string, slotId: string, namespace: string): void {
    const slot = slotId || '_singleton';
    this._db.prepare(
      'DELETE FROM seq_tracker WHERE device_id = ? AND slot_id = ? AND namespace = ?',
    ).run(deviceId, slot, namespace);
  }

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
    for (const row of rows) result[row.key] = row.value;
    return result;
  }


  private _agentMdCacheColumns(): string[] {
    return [
      'aid',
      'content',
      'local_etag',
      'remote_etag',
      'last_modified',
      'fetched_at',
      'observed_at',
      'checked_at',
      'remote_status',
      'verify_status',
      'verify_error',
      'last_error',
      'updated_at',
    ];
  }

  private _normalizeAgentMdRecord(row: Record<string, unknown>): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const col of this._agentMdCacheColumns()) out[col] = row[col];
    for (const col of ['fetched_at', 'observed_at', 'checked_at', 'updated_at']) {
      out[col] = Number(out[col] ?? 0);
    }
    return out;
  }

  loadAgentMdCache(aid: string): Record<string, unknown> | null {
    const target = String(aid ?? '').trim();
    if (!target) return null;
    const columns = this._agentMdCacheColumns();
    const row = this._db.prepare(
      `SELECT ${columns.join(', ')} FROM agent_md_cache WHERE aid = ?`,
    ).get(target) as Record<string, unknown> | undefined;
    return row ? this._normalizeAgentMdRecord(row) : null;
  }

  upsertAgentMdCache(aid: string, fields: Record<string, unknown>): Record<string, unknown> {
    const target = String(aid ?? '').trim();
    if (!target) throw new Error('agent_md_cache aid is required');
    const current = this.loadAgentMdCache(target) ?? {
      aid: target,
      content: '',
      local_etag: '',
      remote_etag: '',
      last_modified: '',
      fetched_at: 0,
      observed_at: 0,
      checked_at: 0,
      remote_status: '',
      verify_status: '',
      verify_error: '',
      last_error: '',
      updated_at: 0,
    };
    for (const key of [
      'content',
      'local_etag',
      'remote_etag',
      'last_modified',
      'remote_status',
      'verify_status',
      'verify_error',
      'last_error',
    ]) {
      if (Object.prototype.hasOwnProperty.call(fields, key) && fields[key] !== undefined && fields[key] !== null) {
        current[key] = String(fields[key] ?? '');
      }
    }
    for (const key of ['fetched_at', 'observed_at', 'checked_at']) {
      if (Object.prototype.hasOwnProperty.call(fields, key) && fields[key] !== undefined && fields[key] !== null) {
        const value = Number(fields[key] ?? 0);
        current[key] = Number.isFinite(value) ? Math.trunc(value) : 0;
      }
    }
    current.updated_at = Date.now();
    const columns = this._agentMdCacheColumns();
    this._db.prepare(
      `INSERT INTO agent_md_cache (${columns.join(', ')}) VALUES (${columns.map(() => '?').join(', ')})
       ON CONFLICT(aid) DO UPDATE SET ${columns.filter(col => col !== 'aid').map(col => `${col}=excluded.${col}`).join(', ')}`,
    ).run(...columns.map(col => current[col] as string | number));
    return this.loadAgentMdCache(target) ?? current;
  }

  saveGroupState(groupId: string, stateVersion: number, stateHash: string, keyEpoch: number, membershipJson: string, policyJson: string): void {
    this._db.prepare(
      `INSERT INTO group_state (group_id, state_version, state_hash, key_epoch, membership_json, policy_json, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(group_id) DO UPDATE SET state_version=excluded.state_version, state_hash=excluded.state_hash, key_epoch=excluded.key_epoch, membership_json=excluded.membership_json, policy_json=excluded.policy_json, updated_at=excluded.updated_at`,
    ).run(groupId, stateVersion, stateHash, keyEpoch, membershipJson, policyJson, Date.now());
  }

  loadGroupState(groupId: string): { group_id: string; state_version: number; state_hash: string; key_epoch: number; membership_json: string; policy_json: string; updated_at: number } | null {
    const row = this._db.prepare(
      'SELECT state_version, state_hash, key_epoch, membership_json, policy_json, updated_at FROM group_state WHERE group_id = ?',
    ).get(groupId) as { state_version: number; state_hash: string; key_epoch: number; membership_json: string; policy_json: string; updated_at: number } | undefined;
    if (!row) return null;
    return { group_id: groupId, ...row };
  }
}
