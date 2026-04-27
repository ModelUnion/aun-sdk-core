/**
 * Per-AID SQLite 数据库。
 *
 * SQLite SDK 统一规则：
 * - schema 与 Python / Go 完全一致
 * - 敏感字段写入时一律字段级加密
 * - 读取时兼容密文 JSON 与历史明文
 */

import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import type { SecretStore } from '../secret-store/index.js';
import type { SecretRecord } from '../types.js';

const SCHEMA_VERSION = 1;

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

function jsonParseObject(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

export class AIDDatabase {
  private _db: Database.Database;
  private _dbPath: string;
  private _secretStore: SecretStore | null;
  private _scope: string;

  constructor(dbPath: string, secretStore?: SecretStore | null, scope?: string) {
    mkdirSync(dirname(dbPath), { recursive: true });
    const absPath = resolve(dbPath);
    this._dbPath = absPath;
    this._secretStore = secretStore ?? null;
    this._scope = scope ?? dirname(absPath).split(/[\\/]/).pop() ?? '';
    const cached = _dbPool.get(absPath);
    if (cached) {
      cached.refCount++;
      this._db = cached.db;
    } else {
      this._db = new Database(dbPath);
      try {
        this._db.pragma('journal_mode = WAL');
      } catch {
        this._db.pragma('locking_mode = EXCLUSIVE');
        this._db.pragma('journal_mode = DELETE');
      }
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
    for (const ddl of DDL_STATEMENTS) this._db.exec(ddl);
    this._migrateLegacyColumns();
    const row = this._db.prepare('SELECT version FROM _schema_version WHERE id = 1').get() as { version: number } | undefined;
    if (!row) this._db.prepare('INSERT INTO _schema_version (id, version) VALUES (1, ?)').run(SCHEMA_VERSION);
  }

  private _migrateLegacyColumns(): void {
    this._renameColumnIfExists('prekeys', 'private_key_pem', 'private_key_enc');
    this._renameColumnIfExists('group_current', 'secret', 'secret_enc');
    this._renameColumnIfExists('group_old_epochs', 'secret', 'secret_enc');
    this._renameColumnIfExists('e2ee_sessions', 'data', 'data_enc');
  }

  private _renameColumnIfExists(table: string, oldName: string, newName: string): void {
    const rows = this._db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
    const names = new Set(rows.map((row) => row.name));
    if (names.has(oldName) && !names.has(newName)) {
      this._db.exec(`ALTER TABLE ${table} RENAME COLUMN ${oldName} TO ${newName}`);
    }
  }

  private _protectText(name: string, plaintext: string): string {
    if (!this._secretStore || !plaintext) return plaintext;
    try {
      return JSON.stringify(this._secretStore.protect(this._scope, name, Buffer.from(plaintext, 'utf-8')));
    } catch {
      return plaintext;
    }
  }

  private _revealText(name: string, stored: string): string {
    if (!this._secretStore || !stored) return stored;
    try {
      const record = JSON.parse(stored) as SecretRecord;
      if (record?.scheme !== 'file_aes') return stored;
      const plain = this._secretStore.reveal(this._scope, name, record);
      return plain ? plain.toString('utf-8') : stored;
    } catch {
      return stored;
    }
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

  savePrekey(prekeyId: string, privateKeyPem: string, deviceId = '', createdAt?: number, expiresAt?: number, extraData?: Record<string, unknown>): void {
    const now = Date.now();
    this._db.prepare(
      `INSERT INTO prekeys (prekey_id, device_id, private_key_enc, data, created_at, updated_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(prekey_id, device_id) DO UPDATE SET
         private_key_enc=excluded.private_key_enc, data=excluded.data,
         updated_at=excluded.updated_at, expires_at=excluded.expires_at`,
    ).run(
      prekeyId,
      deviceId,
      this._protectText(`prekey/${prekeyId}`, privateKeyPem),
      JSON.stringify(extraData ?? {}),
      createdAt ?? now,
      now,
      expiresAt ?? null,
    );
  }

  loadPrekeys(deviceId = ''): Record<string, Record<string, unknown>> {
    const rows = this._db.prepare(
      'SELECT prekey_id, private_key_enc, data, created_at, updated_at, expires_at FROM prekeys WHERE device_id = ?',
    ).all(deviceId) as Array<{ prekey_id: string; private_key_enc: string; data: string; created_at: number | null; updated_at: number | null; expires_at: number | null }>;
    const result: Record<string, Record<string, unknown>> = {};
    for (const row of rows) {
      const entry: Record<string, unknown> = {
        private_key_pem: this._revealText(`prekey/${row.prekey_id}`, row.private_key_enc),
      };
      if (row.created_at != null) entry.created_at = row.created_at;
      if (row.updated_at != null) entry.updated_at = row.updated_at;
      if (row.expires_at != null) entry.expires_at = row.expires_at;
      Object.assign(entry, jsonParseObject(row.data));
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
    const latestIds = new Set(rows.slice(0, keepLatest).map((row) => row.prekey_id));
    const toDelete = rows
      .filter((row) => !latestIds.has(row.prekey_id) && row.created_at != null && row.created_at < cutoffMs)
      .map((row) => row.prekey_id);
    if (toDelete.length > 0) {
      const del = this._db.prepare('DELETE FROM prekeys WHERE device_id = ? AND prekey_id = ?');
      this._db.transaction(() => {
        for (const id of toDelete) del.run(deviceId, id);
      })();
    }
    return toDelete;
  }

  saveGroupCurrent(groupId: string, epoch: number, secret: string, data: Record<string, unknown>): void {
    this._db.prepare(
      `INSERT INTO group_current (group_id, epoch, secret_enc, data, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(group_id) DO UPDATE SET epoch=excluded.epoch, secret_enc=excluded.secret_enc, data=excluded.data, updated_at=excluded.updated_at`,
    ).run(groupId, epoch, this._protectText(`group/${groupId}/current`, secret), JSON.stringify(data), Date.now());
  }

  loadGroupCurrent(groupId: string): Record<string, unknown> | null {
    const row = this._db.prepare('SELECT epoch, secret_enc, data, updated_at FROM group_current WHERE group_id = ?').get(groupId) as
      { epoch: number; secret_enc: string; data: string; updated_at: number } | undefined;
    if (!row) return null;
    return {
      group_id: groupId,
      epoch: row.epoch,
      secret: this._revealText(`group/${groupId}/current`, row.secret_enc),
      ...jsonParseObject(row.data),
      updated_at: row.updated_at,
    };
  }

  loadGroupSecretEpoch(groupId: string, epoch?: number | null): Record<string, unknown> | null {
    const current = this.loadGroupCurrent(groupId);
    if (epoch === undefined || epoch === null) return current;
    if (current && Number(current.epoch ?? 0) === Number(epoch)) return current;
    const row = this._db.prepare(
      'SELECT epoch, secret_enc, data, updated_at, expires_at FROM group_old_epochs WHERE group_id = ? AND epoch = ?',
    ).get(groupId, epoch) as
      { epoch: number; secret_enc: string; data: string; updated_at: number; expires_at: number | null } | undefined;
    if (!row) return null;
    const entry: Record<string, unknown> = {
      epoch: row.epoch,
      secret: this._revealText(`group/${groupId}/epoch/${row.epoch}`, row.secret_enc),
      ...jsonParseObject(row.data),
      updated_at: row.updated_at,
    };
    if (row.expires_at != null) entry.expires_at = row.expires_at;
    return entry;
  }

  loadGroupSecretEpochs(groupId: string): Array<Record<string, unknown>> {
    const result: Array<Record<string, unknown>> = [];
    const current = this.loadGroupCurrent(groupId);
    if (current) result.push(current);
    const rows = this._db.prepare(
      'SELECT epoch, secret_enc, data, updated_at, expires_at FROM group_old_epochs WHERE group_id = ? ORDER BY epoch ASC',
    ).all(groupId) as Array<{ epoch: number; secret_enc: string; data: string; updated_at: number; expires_at: number | null }>;
    for (const row of rows) {
      const entry: Record<string, unknown> = {
        epoch: row.epoch,
        secret: this._revealText(`group/${groupId}/epoch/${row.epoch}`, row.secret_enc),
        ...jsonParseObject(row.data),
        updated_at: row.updated_at,
      };
      if (row.expires_at != null) entry.expires_at = row.expires_at;
      result.push(entry);
    }
    return result;
  }

  loadAllGroupCurrent(): Record<string, Record<string, unknown>> {
    const rows = this._db.prepare('SELECT group_id, epoch, secret_enc, data, updated_at FROM group_current').all() as
      Array<{ group_id: string; epoch: number; secret_enc: string; data: string; updated_at: number }>;
    const result: Record<string, Record<string, unknown>> = {};
    for (const row of rows) {
      result[row.group_id] = {
        group_id: row.group_id,
        epoch: row.epoch,
        secret: this._revealText(`group/${row.group_id}/current`, row.secret_enc),
        ...jsonParseObject(row.data),
        updated_at: row.updated_at,
      };
    }
    return result;
  }

  deleteGroupCurrent(groupId: string): void {
    this._db.prepare('DELETE FROM group_current WHERE group_id = ?').run(groupId);
  }

  saveGroupOldEpoch(groupId: string, epoch: number, secret: string, data: Record<string, unknown>, updatedAt?: number, expiresAt?: number): void {
    this._db.prepare(
      `INSERT INTO group_old_epochs (group_id, epoch, secret_enc, data, updated_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(group_id, epoch) DO UPDATE SET secret_enc=excluded.secret_enc, data=excluded.data, updated_at=excluded.updated_at, expires_at=excluded.expires_at`,
    ).run(groupId, epoch, this._protectText(`group/${groupId}/epoch/${epoch}`, secret), JSON.stringify(data), updatedAt ?? Date.now(), expiresAt ?? null);
  }

  loadGroupOldEpochs(groupId: string): Array<Record<string, unknown>> {
    const rows = this._db.prepare(
      'SELECT epoch, secret_enc, data, updated_at, expires_at FROM group_old_epochs WHERE group_id = ? ORDER BY epoch ASC',
    ).all(groupId) as Array<{ epoch: number; secret_enc: string; data: string; updated_at: number; expires_at: number | null }>;
    return rows.map((row) => {
      const entry: Record<string, unknown> = {
        epoch: row.epoch,
        secret: this._revealText(`group/${groupId}/epoch/${row.epoch}`, row.secret_enc),
        ...jsonParseObject(row.data),
        updated_at: row.updated_at,
      };
      if (row.expires_at != null) entry.expires_at = row.expires_at;
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
      'DELETE FROM group_old_epochs WHERE group_id = ? AND updated_at <= ?',
    ).run(groupId, cutoffMs);
    return result.changes;
  }

  storeGroupSecretTransition(groupId: string, opts: {
    epoch: number;
    secret: string;
    commitment: string;
    memberAids: string[];
    epochChain?: string;
    pendingRotationId?: string;
    epochChainUnverified?: boolean | null;
    epochChainUnverifiedReason?: string | null;
    oldEpochRetentionMs: number;
  }): boolean {
    const txn = this._db.transaction(() => {
      const now = Date.now();
      const epoch = Number(opts.epoch);
      const members = [...(opts.memberAids ?? [])].map((item) => String(item)).sort();
      const pendingRotationId = String(opts.pendingRotationId ?? '').trim();
      const current = this._db.prepare(
        'SELECT epoch, secret_enc, data, updated_at FROM group_current WHERE group_id = ?',
      ).get(groupId) as { epoch: number; secret_enc: string; data: string; updated_at: number } | undefined;

      if (current) {
        const localEpoch = Number(current.epoch);
        const currentSecret = this._revealText(`group/${groupId}/current`, current.secret_enc);
        const currentData = jsonParseObject(current.data);
        if (epoch < localEpoch) return false;
        if (epoch === localEpoch && currentSecret) {
          if (currentSecret !== opts.secret) {
            if (String(currentData.pending_rotation_id ?? '').trim()) {
              this._upsertGroupCurrent(groupId, epoch, opts.secret, this._buildGroupCurrentData(opts, members, now), now);
              return true;
            }
            return false;
          }
          const updated = { ...currentData };
          let changed = false;
          const oldMembers = Array.isArray(updated.member_aids) ? updated.member_aids.map(String).sort() : [];
          if (members.length > 0 && JSON.stringify(oldMembers) !== JSON.stringify(members)) {
            updated.member_aids = members;
            updated.commitment = opts.commitment;
            changed = true;
          }
          if (opts.epochChain !== undefined && updated.epoch_chain !== opts.epochChain) {
            updated.epoch_chain = opts.epochChain;
            changed = true;
          }
          if (opts.epochChainUnverified === true) {
            if (updated.epoch_chain_unverified !== true) {
              updated.epoch_chain_unverified = true;
              changed = true;
            }
            if (opts.epochChainUnverifiedReason && updated.epoch_chain_unverified_reason !== opts.epochChainUnverifiedReason) {
              updated.epoch_chain_unverified_reason = opts.epochChainUnverifiedReason;
              changed = true;
            }
          } else if (opts.epochChainUnverified === false) {
            if ('epoch_chain_unverified' in updated || 'epoch_chain_unverified_reason' in updated) {
              delete updated.epoch_chain_unverified;
              delete updated.epoch_chain_unverified_reason;
              changed = true;
            }
          }
          if (pendingRotationId && updated.pending_rotation_id !== pendingRotationId) {
            updated.pending_rotation_id = pendingRotationId;
            updated.pending_created_at = now;
            changed = true;
          }
          if (!pendingRotationId && updated.pending_rotation_id) {
            delete updated.pending_rotation_id;
            delete updated.pending_created_at;
            changed = true;
          }
          if (changed) this._upsertGroupCurrent(groupId, epoch, currentSecret, updated, now);
          return true;
        }
        if (localEpoch !== epoch) {
          const expiresAt = Number(current.updated_at || now) + opts.oldEpochRetentionMs;
          this._upsertGroupOldEpoch(groupId, localEpoch, currentSecret, currentData, Number(current.updated_at || now), expiresAt);
        }
      }

      this._upsertGroupCurrent(groupId, epoch, opts.secret, this._buildGroupCurrentData(opts, members, now), now);
      return true;
    });
    return Boolean(txn());
  }

  storeGroupSecretEpoch(groupId: string, opts: {
    epoch: number;
    secret: string;
    commitment: string;
    memberAids: string[];
    epochChain?: string;
    pendingRotationId?: string;
    epochChainUnverified?: boolean | null;
    epochChainUnverifiedReason?: string | null;
    oldEpochRetentionMs: number;
  }): boolean {
    const txn = this._db.transaction(() => {
      const now = Date.now();
      const epoch = Number(opts.epoch);
      const members = [...(opts.memberAids ?? [])].map((item) => String(item)).sort();
      const pendingRotationId = String(opts.pendingRotationId ?? '').trim();
      const data = this._buildGroupCurrentData(opts, members, now);
      const current = this._db.prepare(
        'SELECT epoch, secret_enc, data, updated_at FROM group_current WHERE group_id = ?',
      ).get(groupId) as { epoch: number; secret_enc: string; data: string; updated_at: number } | undefined;

      if (!current) {
        this._upsertGroupCurrent(groupId, epoch, opts.secret, data, now);
        return true;
      }

      const localEpoch = Number(current.epoch);
      if (epoch > localEpoch) return false;

      if (epoch === localEpoch) {
        const currentSecret = this._revealText(`group/${groupId}/current`, current.secret_enc);
        const currentData = jsonParseObject(current.data);
        if (currentSecret && currentSecret !== opts.secret) {
          if (!String(currentData.pending_rotation_id ?? '').trim()) return false;
          this._upsertGroupCurrent(groupId, epoch, opts.secret, data, now);
          return true;
        }
        const updated = { ...currentData };
        let changed = false;
        const oldMembers = Array.isArray(updated.member_aids) ? updated.member_aids.map(String).sort() : [];
        if (members.length > 0 && JSON.stringify(oldMembers) !== JSON.stringify(members)) {
          updated.member_aids = members;
          updated.commitment = opts.commitment;
          changed = true;
        }
        if (opts.epochChain !== undefined && updated.epoch_chain !== opts.epochChain) {
          updated.epoch_chain = opts.epochChain;
          changed = true;
        }
        if (opts.epochChainUnverified === true) {
          if (updated.epoch_chain_unverified !== true) {
            updated.epoch_chain_unverified = true;
            changed = true;
          }
          if (opts.epochChainUnverifiedReason && updated.epoch_chain_unverified_reason !== opts.epochChainUnverifiedReason) {
            updated.epoch_chain_unverified_reason = opts.epochChainUnverifiedReason;
            changed = true;
          }
        } else if (opts.epochChainUnverified === false) {
          if ('epoch_chain_unverified' in updated || 'epoch_chain_unverified_reason' in updated) {
            delete updated.epoch_chain_unverified;
            delete updated.epoch_chain_unverified_reason;
            changed = true;
          }
        }
        if (pendingRotationId && updated.pending_rotation_id !== pendingRotationId) {
          updated.pending_rotation_id = pendingRotationId;
          updated.pending_created_at = now;
          changed = true;
        }
        if (!pendingRotationId && updated.pending_rotation_id) {
          delete updated.pending_rotation_id;
          delete updated.pending_created_at;
          changed = true;
        }
        if (changed) this._upsertGroupCurrent(groupId, epoch, currentSecret, updated, now);
        return true;
      }

      const old = this._db.prepare(
        'SELECT secret_enc FROM group_old_epochs WHERE group_id = ? AND epoch = ?',
      ).get(groupId, epoch) as { secret_enc: string } | undefined;
      if (old) {
        const oldSecret = this._revealText(`group/${groupId}/epoch/${epoch}`, old.secret_enc);
        if (oldSecret && oldSecret !== opts.secret) return false;
      }
      this._upsertGroupOldEpoch(groupId, epoch, opts.secret, data, now, now + opts.oldEpochRetentionMs);
      return true;
    });
    return Boolean(txn());
  }

  discardPendingGroupSecretState(groupId: string, epoch: number, rotationId: string): boolean {
    const txn = this._db.transaction(() => {
      const rid = String(rotationId ?? '').trim();
      if (!rid) return false;
      const current = this._db.prepare(
        'SELECT epoch, data FROM group_current WHERE group_id = ?',
      ).get(groupId) as { epoch: number; data: string } | undefined;
      if (!current || Number(current.epoch) !== Number(epoch)) return false;
      const data = jsonParseObject(current.data);
      if (String(data.pending_rotation_id ?? '').trim() !== rid) return false;

      const old = this._db.prepare(
        'SELECT epoch, secret_enc, data, updated_at, expires_at FROM group_old_epochs WHERE group_id = ? AND epoch < ? ORDER BY epoch DESC LIMIT 1',
      ).get(groupId, epoch) as
        { epoch: number; secret_enc: string; data: string; updated_at: number; expires_at: number | null } | undefined;
      if (!old) {
        this._db.prepare('DELETE FROM group_current WHERE group_id = ?').run(groupId);
        this._db.prepare('DELETE FROM group_old_epochs WHERE group_id = ?').run(groupId);
        return true;
      }
      const secret = this._revealText(`group/${groupId}/epoch/${old.epoch}`, old.secret_enc);
      this._upsertGroupCurrent(groupId, Number(old.epoch), secret, jsonParseObject(old.data), Date.now());
      this._db.prepare('DELETE FROM group_old_epochs WHERE group_id = ? AND epoch = ?').run(groupId, old.epoch);
      return true;
    });
    return Boolean(txn());
  }

  private _buildGroupCurrentData(opts: {
    commitment: string;
    memberAids?: string[];
    epochChain?: string;
    pendingRotationId?: string;
    epochChainUnverified?: boolean | null;
    epochChainUnverifiedReason?: string | null;
  }, memberAids: string[], now: number): Record<string, unknown> {
    const data: Record<string, unknown> = {
      commitment: opts.commitment,
      member_aids: memberAids,
    };
    if (opts.epochChain !== undefined) data.epoch_chain = opts.epochChain;
    const pendingRotationId = String(opts.pendingRotationId ?? '').trim();
    if (pendingRotationId) {
      data.pending_rotation_id = pendingRotationId;
      data.pending_created_at = now;
    }
    if (opts.epochChainUnverified === true) {
      data.epoch_chain_unverified = true;
      if (opts.epochChainUnverifiedReason) data.epoch_chain_unverified_reason = opts.epochChainUnverifiedReason;
    }
    return data;
  }

  private _upsertGroupCurrent(groupId: string, epoch: number, secret: string, data: Record<string, unknown>, updatedAt: number): void {
    this._db.prepare(
      `INSERT INTO group_current (group_id, epoch, secret_enc, data, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(group_id) DO UPDATE SET epoch=excluded.epoch, secret_enc=excluded.secret_enc, data=excluded.data, updated_at=excluded.updated_at`,
    ).run(groupId, epoch, this._protectText(`group/${groupId}/current`, secret), JSON.stringify(data), updatedAt);
  }

  private _upsertGroupOldEpoch(
    groupId: string,
    epoch: number,
    secret: string,
    data: Record<string, unknown>,
    updatedAt: number,
    expiresAt?: number | null,
  ): void {
    this._db.prepare(
      `INSERT INTO group_old_epochs (group_id, epoch, secret_enc, data, updated_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(group_id, epoch) DO UPDATE SET secret_enc=excluded.secret_enc, data=excluded.data, updated_at=excluded.updated_at, expires_at=excluded.expires_at`,
    ).run(groupId, epoch, this._protectText(`group/${groupId}/epoch/${epoch}`, secret), JSON.stringify(data), updatedAt, expiresAt ?? null);
  }

  saveSession(sessionId: string, data: Record<string, unknown>): void {
    const dataJson = JSON.stringify(data);
    this._db.prepare(
      'INSERT INTO e2ee_sessions (session_id, data_enc, updated_at) VALUES (?, ?, ?) ON CONFLICT(session_id) DO UPDATE SET data_enc=excluded.data_enc, updated_at=excluded.updated_at',
    ).run(sessionId, this._protectText(`session/${sessionId}`, dataJson), Date.now());
  }

  loadAllSessions(): Array<Record<string, unknown>> {
    const rows = this._db.prepare('SELECT session_id, data_enc, updated_at FROM e2ee_sessions').all() as
      Array<{ session_id: string; data_enc: string; updated_at: number }>;
    return rows.map((row) => ({
      ...jsonParseObject(this._revealText(`session/${row.session_id}`, row.data_enc)),
      session_id: row.session_id,
      updated_at: row.updated_at,
    }));
  }

  deleteSession(sessionId: string): void {
    this._db.prepare('DELETE FROM e2ee_sessions WHERE session_id = ?').run(sessionId);
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
}
