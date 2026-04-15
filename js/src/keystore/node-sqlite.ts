// ── Node.js SQLite KeyStore 实现（对标 Python AIDDatabase）──────
//
// 每个 AID 一个独立的 aun.db，表结构与 Python sqlcipher_db.py 完全一致。
// 敏感字段（private_key_pem、secret、session data）通过 Node.js crypto
// 模块 AES-256-GCM 加密（对标 Python file_aes scheme）。

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import Database from 'better-sqlite3';
import { normalizeInstanceId } from '../config.js';
import type { KeyStore } from './index.js';
import type {
  GroupOldEpochRecord,
  GroupSecretMap,
  GroupSecretRecord,
  IdentityRecord,
  KeyPairRecord,
  MetadataRecord,
  PrekeyMap,
  PrekeyRecord,
  SessionRecord,
} from '../types.js';

function safeAid(aid: string): string {
  return aid.replace(/[/\\:]/g, '_');
}

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

// ── 字段级加密（兼容 Python file_aes scheme）──────────────────

function deriveMasterKey(seedBytes: Buffer): Buffer {
  return crypto.pbkdf2Sync(seedBytes, 'aun_file_secret_store_v1', 100_000, 32, 'sha256');
}

function deriveFieldKey(masterKey: Buffer, scope: string, name: string): Buffer {
  const msg = Buffer.from(`aun:${scope}:${name}\x01`, 'utf-8');
  return crypto.createHmac('sha256', masterKey).update(msg).digest();
}

function protectField(masterKey: Buffer, scope: string, name: string, plaintext: string): string {
  if (!plaintext) return plaintext;
  const fieldKey = deriveFieldKey(masterKey, scope, name);
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', fieldKey, nonce);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const record = {
    scheme: 'file_aes',
    name,
    persisted: true,
    nonce: nonce.toString('hex'),
    ciphertext: ct.toString('hex'),
    tag: tag.toString('hex'),
  };
  return JSON.stringify(record);
}

function revealField(masterKey: Buffer, scope: string, name: string, stored: string): string {
  if (!stored) return stored;
  let record: Record<string, string>;
  try {
    record = JSON.parse(stored);
  } catch {
    return stored; // 未加密的明文
  }
  if (record.scheme !== 'file_aes') return stored;
  const fieldKey = deriveFieldKey(masterKey, scope, name);
  const nonce = Buffer.from(record.nonce, 'hex');
  const ct = Buffer.from(record.ciphertext, 'hex');
  const tag = Buffer.from(record.tag, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', fieldKey, nonce);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf-8');
  } catch {
    return '';
  }
}

// ── seed 管理 ────────────────────────────────────────────────

function loadOrCreateSeed(root: string, encryptionSeed?: string): Buffer {
  if (encryptionSeed) return Buffer.from(encryptionSeed, 'utf-8');
  const seedPath = path.join(root, '.seed');
  if (fs.existsSync(seedPath)) return fs.readFileSync(seedPath);
  const seed = crypto.randomBytes(32);
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(seedPath, seed, { mode: 0o600 });
  return seed;
}

// ── DDL ──────────────────────────────────────────────────────

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
  `CREATE TABLE IF NOT EXISTS metadata_kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS seq_tracker (
    device_id TEXT NOT NULL,
    slot_id TEXT NOT NULL DEFAULT '_singleton',
    namespace TEXT NOT NULL,
    contiguous_seq INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, slot_id, namespace)
  )`,
];

// ── AIDDatabase ──────────────────────────────────────────────

class AIDDatabase {
  private db: Database.Database;

  constructor(dbPath: string) {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('busy_timeout = 5000');
    this.initSchema();
  }

  private initSchema(): void {
    for (const ddl of DDL_STATEMENTS) {
      this.db.exec(ddl);
    }
    const row = this.db.prepare('SELECT version FROM _schema_version WHERE id = 1').get() as { version: number } | undefined;
    if (!row) {
      this.db.prepare('INSERT INTO _schema_version (id, version) VALUES (1, 1)').run();
    }
  }

  close(): void {
    this.db.close();
  }

  // ── Tokens ───────────────────────────────────────────────

  getToken(key: string): string | null {
    const row = this.db.prepare('SELECT value FROM tokens WHERE key = ?').get(key) as { value: string } | undefined;
    return row?.value ?? null;
  }

  setToken(key: string, value: string): void {
    this.db.prepare(
      'INSERT INTO tokens (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at',
    ).run(key, value, Date.now());
  }

  deleteToken(key: string): void {
    this.db.prepare('DELETE FROM tokens WHERE key = ?').run(key);
  }

  getAllTokens(): Record<string, string> {
    const rows = this.db.prepare('SELECT key, value FROM tokens').all() as Array<{ key: string; value: string }>;
    const result: Record<string, string> = {};
    for (const row of rows) result[row.key] = row.value;
    return result;
  }

  // ── Prekeys ──────────────────────────────────────────────

  savePrekey(prekeyId: string, privateKeyPem: string, deviceId = '', createdAt?: number, expiresAt?: number, extraData?: Record<string, unknown>): void {
    const now = Date.now();
    
    const dataJson = JSON.stringify(extraData ?? {});
    this.db.prepare(
      `INSERT INTO prekeys (prekey_id, device_id, private_key_enc, data, created_at, updated_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(prekey_id, device_id) DO UPDATE SET
         private_key_enc=excluded.private_key_enc, data=excluded.data,
         updated_at=excluded.updated_at, expires_at=excluded.expires_at`,
    ).run(prekeyId, deviceId, privateKeyPem, dataJson, createdAt ?? now, now, expiresAt ?? null);
  }

  loadPrekeys(deviceId = ''): PrekeyMap {
    const rows = this.db.prepare(
      'SELECT prekey_id, private_key_enc, data, created_at, updated_at, expires_at FROM prekeys WHERE device_id = ?',
    ).all(deviceId) as Array<{ prekey_id: string; private_key_enc: string; data: string; created_at: number | null; updated_at: number | null; expires_at: number | null }>;
    const result: PrekeyMap = {};
    for (const row of rows) {
      const entry: PrekeyRecord = {
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
    this.db.prepare('DELETE FROM prekeys WHERE prekey_id = ? AND device_id = ?').run(prekeyId, deviceId);
  }

  cleanupPrekeys(deviceId: string, cutoffMs: number, keepLatest: number): string[] {
    const rows = this.db.prepare(
      'SELECT prekey_id, created_at FROM prekeys WHERE device_id = ? ORDER BY created_at DESC',
    ).all(deviceId) as Array<{ prekey_id: string; created_at: number | null }>;
    const latestIds = new Set(rows.slice(0, keepLatest).map((r) => r.prekey_id));
    const toDelete = rows
      .filter((r) => !latestIds.has(r.prekey_id) && r.created_at != null && r.created_at < cutoffMs)
      .map((r) => r.prekey_id);
    if (toDelete.length > 0) {
      const del = this.db.prepare('DELETE FROM prekeys WHERE device_id = ? AND prekey_id = ?');
      const tx = this.db.transaction(() => {
        for (const id of toDelete) del.run(deviceId, id);
      });
      tx();
    }
    return toDelete;
  }

  // ── Group Current ────────────────────────────────────────

  saveGroupCurrent(groupId: string, epoch: number, secret: string, data: Record<string, unknown>): void {
    
    this.db.prepare(
      `INSERT INTO group_current (group_id, epoch, secret_enc, data, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(group_id) DO UPDATE SET epoch=excluded.epoch, secret_enc=excluded.secret_enc, data=excluded.data, updated_at=excluded.updated_at`,
    ).run(groupId, epoch, secret, JSON.stringify(data), Date.now());
  }

  loadGroupCurrent(groupId: string): GroupSecretRecord | null {
    const row = this.db.prepare('SELECT epoch, secret_enc, data, updated_at FROM group_current WHERE group_id = ?').get(groupId) as
      { epoch: number; secret_enc: string; data: string; updated_at: number } | undefined;
    if (!row) return null;
    const result: GroupSecretRecord = {
      group_id: groupId,
      epoch: row.epoch,
      secret: row.secret_enc,
      updated_at: row.updated_at,
    };
    try {
      Object.assign(result, JSON.parse(row.data));
    } catch { /* ignore */ }
    return result;
  }

  loadAllGroupCurrent(): GroupSecretMap {
    const rows = this.db.prepare('SELECT group_id, epoch, secret_enc, data, updated_at FROM group_current').all() as
      Array<{ group_id: string; epoch: number; secret_enc: string; data: string; updated_at: number }>;
    const result: GroupSecretMap = {};
    for (const row of rows) {
      const entry: GroupSecretRecord = {
        group_id: row.group_id,
        epoch: row.epoch,
        secret: row.secret_enc,
        updated_at: row.updated_at,
      };
      try { Object.assign(entry, JSON.parse(row.data)); } catch { /* ignore */ }
      result[row.group_id] = entry;
    }
    return result;
  }

  deleteGroupCurrent(groupId: string): void {
    this.db.prepare('DELETE FROM group_current WHERE group_id = ?').run(groupId);
  }

  // ── Group Old Epochs ─────────────────────────────────────

  saveGroupOldEpoch(groupId: string, epoch: number, secret: string, data: Record<string, unknown>, updatedAt?: number, expiresAt?: number): void {
    
    this.db.prepare(
      `INSERT INTO group_old_epochs (group_id, epoch, secret_enc, data, updated_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(group_id, epoch) DO UPDATE SET secret_enc=excluded.secret_enc, data=excluded.data, updated_at=excluded.updated_at, expires_at=excluded.expires_at`,
    ).run(groupId, epoch, secret, JSON.stringify(data), updatedAt ?? Date.now(), expiresAt ?? null);
  }

  loadGroupOldEpochs(groupId: string): GroupOldEpochRecord[] {
    const rows = this.db.prepare(
      'SELECT epoch, secret_enc, data, updated_at, expires_at FROM group_old_epochs WHERE group_id = ? ORDER BY epoch ASC',
    ).all(groupId) as Array<{ epoch: number; secret_enc: string; data: string; updated_at: number; expires_at: number | null }>;
    return rows.map((row) => {
      const entry: GroupOldEpochRecord = {
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
    this.db.prepare('DELETE FROM group_old_epochs WHERE group_id = ?').run(groupId);
  }

  loadAllGroupIdsWithOldEpochs(): string[] {
    const rows = this.db.prepare('SELECT DISTINCT group_id FROM group_old_epochs').all() as Array<{ group_id: string }>;
    return rows.map((row) => row.group_id);
  }

  cleanupGroupOldEpochs(groupId: string, cutoffMs: number): number {
    const result = this.db.prepare(
      'DELETE FROM group_old_epochs WHERE group_id = ? AND (CASE WHEN expires_at IS NOT NULL THEN expires_at ELSE updated_at END) < ?',
    ).run(groupId, cutoffMs);
    return result.changes;
  }

  // ── E2EE Sessions ────────────────────────────────────────

  saveSession(sessionId: string, data: Record<string, unknown>): void {
    const dataJson = JSON.stringify(data);
    
    this.db.prepare(
      'INSERT INTO e2ee_sessions (session_id, data_enc, updated_at) VALUES (?, ?, ?) ON CONFLICT(session_id) DO UPDATE SET data_enc=excluded.data_enc, updated_at=excluded.updated_at',
    ).run(sessionId, dataJson, Date.now());
  }

  loadAllSessions(): SessionRecord[] {
    const rows = this.db.prepare('SELECT session_id, data_enc, updated_at FROM e2ee_sessions').all() as
      Array<{ session_id: string; data_enc: string; updated_at: number }>;
    return rows.map((row) => {
      const plain = row.data_enc;
      let entry: SessionRecord = {};
      try { entry = JSON.parse(plain); } catch { /* ignore */ }
      entry.session_id = row.session_id;
      entry.updated_at = row.updated_at;
      return entry;
    });
  }

  deleteSession(sessionId: string): void {
    this.db.prepare('DELETE FROM e2ee_sessions WHERE session_id = ?').run(sessionId);
  }

  // ── Instance State ───────────────────────────────────────

  saveInstanceState(deviceId: string, slotId: string, state: Record<string, unknown>): void {
    const slot = slotId || '_singleton';
    this.db.prepare(
      'INSERT INTO instance_state (device_id, slot_id, data, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(device_id, slot_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at',
    ).run(deviceId, slot, JSON.stringify(state), Date.now());
  }

  loadInstanceState(deviceId: string, slotId = ''): Record<string, unknown> | null {
    const slot = slotId || '_singleton';
    const row = this.db.prepare('SELECT data FROM instance_state WHERE device_id = ? AND slot_id = ?').get(deviceId, slot) as { data: string } | undefined;
    if (!row) return null;
    try { return JSON.parse(row.data); } catch { return null; }
  }

  // ── Metadata KV ──────────────────────────────────────────

  getMetadata(key: string): string | null {
    const row = this.db.prepare('SELECT value FROM metadata_kv WHERE key = ?').get(key) as { value: string } | undefined;
    return row?.value ?? null;
  }

  setMetadata(key: string, value: string): void {
    this.db.prepare(
      'INSERT INTO metadata_kv (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at',
    ).run(key, value, Date.now());
  }

  deleteMetadata(key: string): void {
    this.db.prepare('DELETE FROM metadata_kv WHERE key = ?').run(key);
  }

  getAllMetadata(): Record<string, string> {
    const rows = this.db.prepare('SELECT key, value FROM metadata_kv').all() as Array<{ key: string; value: string }>;
    const result: Record<string, string> = {};
    for (const row of rows) result[row.key] = row.value;
    return result;
  }

  // ── Seq Tracker ────────────────────────────────────────────

  saveSeq(deviceId: string, slotId: string, namespace: string, contiguousSeq: number): void {
    const slot = slotId || '_singleton';
    this.db.prepare(
      'INSERT INTO seq_tracker (device_id, slot_id, namespace, contiguous_seq, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(device_id, slot_id, namespace) DO UPDATE SET contiguous_seq=excluded.contiguous_seq, updated_at=excluded.updated_at',
    ).run(deviceId, slot, namespace, contiguousSeq, Date.now());
  }

  loadSeq(deviceId: string, slotId: string, namespace: string): number {
    const slot = slotId || '_singleton';
    const row = this.db.prepare(
      'SELECT contiguous_seq FROM seq_tracker WHERE device_id = ? AND slot_id = ? AND namespace = ?',
    ).get(deviceId, slot, namespace) as { contiguous_seq: number } | undefined;
    return row?.contiguous_seq ?? 0;
  }

  loadAllSeqs(deviceId: string, slotId: string): Record<string, number> {
    const slot = slotId || '_singleton';
    const rows = this.db.prepare(
      'SELECT namespace, contiguous_seq FROM seq_tracker WHERE device_id = ? AND slot_id = ?',
    ).all(deviceId, slot) as Array<{ namespace: string; contiguous_seq: number }>;
    const result: Record<string, number> = {};
    for (const r of rows) result[r.namespace] = r.contiguous_seq;
    return result;
  }
}

// ── NodeSQLiteKeyStore ───────────────────────────────────────

const TOKEN_FIELDS = new Set(['access_token', 'refresh_token', 'kite_token']);

export class NodeSQLiteKeyStore implements KeyStore {
  private root: string;
  private aidsRoot: string;
  private _masterKey: Buffer;
  private aidDBs = new Map<string, AIDDatabase>();

  constructor(root?: string, opts?: { encryptionSeed?: string }) {
    this.root = root || path.join(process.env.HOME || process.cwd(), '.aun');
    fs.mkdirSync(this.root, { recursive: true });
    this.aidsRoot = path.join(this.root, 'AIDs');
    fs.mkdirSync(this.aidsRoot, { recursive: true });
    const seedBytes = loadOrCreateSeed(this.root, opts?.encryptionSeed);
    // seed 仅用于 key.json 私钥加密
    this._masterKey = deriveMasterKey(seedBytes);
  }

  close(): void {
    for (const db of this.aidDBs.values()) db.close();
    this.aidDBs.clear();
  }

  private getDB(aid: string): AIDDatabase {
    const safe = safeAid(aid);
    let db = this.aidDBs.get(safe);
    if (!db) {
      const dbPath = path.join(this.aidsRoot, safe, 'aun.db');
      db = new AIDDatabase(dbPath);
      this.aidDBs.set(safe, db);
    }
    return db;
  }

  // ── KeyPair ──────────────────────────────────────────

  async loadKeyPair(aid: string): Promise<KeyPairRecord | null> {
    const kpPath = path.join(this.aidsRoot, safeAid(aid), 'private', 'key.json');
    if (!fs.existsSync(kpPath)) return null;
    const raw = JSON.parse(fs.readFileSync(kpPath, 'utf-8'));
    if (raw.private_key_protection) {
      const plain = revealField(this._masterKey, safeAid(aid), 'identity/private_key', JSON.stringify(raw.private_key_protection));
      if (plain) raw.private_key_pem = plain;
    }
    return raw;
  }

  async saveKeyPair(aid: string, keyPair: KeyPairRecord): Promise<void> {
    const kpPath = path.join(this.aidsRoot, safeAid(aid), 'private', 'key.json');
    fs.mkdirSync(path.dirname(kpPath), { recursive: true });
    const protected_ = deepClone(keyPair);
    if (typeof protected_.private_key_pem === 'string' && protected_.private_key_pem) {
      const enc = protectField(this._masterKey, safeAid(aid), 'identity/private_key', protected_.private_key_pem);
      delete protected_.private_key_pem;
      protected_.private_key_protection = JSON.parse(enc);
    }
    fs.writeFileSync(kpPath, JSON.stringify(protected_, null, 2), { mode: 0o600 });
  }

  // ── Cert ─────────────────────────────────────────────

  async loadCert(aid: string, certFingerprint?: string): Promise<string | null> {
    if (certFingerprint) {
      const versionPath = path.join(this.aidsRoot, safeAid(aid), 'public', 'certs', `${certFingerprint.replace(/:/g, '_')}.pem`);
      if (fs.existsSync(versionPath)) return fs.readFileSync(versionPath, 'utf-8');
      const certPath = path.join(this.aidsRoot, safeAid(aid), 'public', 'cert.pem');
      if (fs.existsSync(certPath)) {
        const certPem = fs.readFileSync(certPath, 'utf-8');
        const actualFingerprint = `sha256:${new crypto.X509Certificate(certPem).fingerprint256.replace(/:/g, '').toLowerCase()}`;
        if (actualFingerprint === String(certFingerprint).trim().toLowerCase()) {
          return certPem;
        }
      }
      return null;
    }
    const certPath = path.join(this.aidsRoot, safeAid(aid), 'public', 'cert.pem');
    if (!fs.existsSync(certPath)) return null;
    return fs.readFileSync(certPath, 'utf-8');
  }

  async saveCert(aid: string, certPem: string, certFingerprint?: string, opts?: { makeActive?: boolean }): Promise<void> {
    if (certFingerprint) {
      const versionPath = path.join(this.aidsRoot, safeAid(aid), 'public', 'certs', `${certFingerprint.replace(/:/g, '_')}.pem`);
      fs.mkdirSync(path.dirname(versionPath), { recursive: true });
      fs.writeFileSync(versionPath, certPem);
      if (!opts?.makeActive) return;
    }
    const certPath = path.join(this.aidsRoot, safeAid(aid), 'public', 'cert.pem');
    fs.mkdirSync(path.dirname(certPath), { recursive: true });
    fs.writeFileSync(certPath, certPem);
  }

  // ── Identity ─────────────────────────────────────────

  async loadIdentity(aid: string): Promise<IdentityRecord | null> {
    const [keyPair, cert] = await Promise.all([
      this.loadKeyPair(aid),
      this.loadCert(aid),
    ]);
    // 直接从 DB 读取 tokens + KV
    const db = this.getDB(aid);
    const tokens = db.getAllTokens();
    const kv = db.getAllMetadata();
    const hasMeta = Object.keys(tokens).length > 0 || Object.keys(kv).length > 0;
    if (!keyPair && !cert && !hasMeta) return null;
    const identity: IdentityRecord = {};
    for (const [k, v] of Object.entries(kv)) {
      try { identity[k] = JSON.parse(v); } catch { identity[k] = v; }
    }
    Object.assign(identity, tokens);
    if (keyPair) Object.assign(identity, keyPair);
    if (cert) identity.cert = cert;
    return identity;
  }

  async saveIdentity(aid: string, identity: IdentityRecord): Promise<void> {
    const keyPairFields: KeyPairRecord = {};
    for (const key of ['private_key_pem', 'public_key_der_b64', 'curve']) {
      if (key in identity) keyPairFields[key] = identity[key];
    }
    if (Object.keys(keyPairFields).length > 0) await this.saveKeyPair(aid, keyPairFields);
    if (typeof identity.cert === 'string' && identity.cert) await this.saveCert(aid, identity.cert);
    // 直接写入 tokens + KV
    const db = this.getDB(aid);
    const skip = new Set([...TOKEN_FIELDS, 'private_key_pem', 'public_key_der_b64', 'curve', 'cert', 'e2ee_prekeys', 'group_secrets', 'e2ee_sessions']);
    for (const field of TOKEN_FIELDS) {
      if (!(field in identity)) continue;
      const v = identity[field];
      if (typeof v === 'string' && v) db.setToken(field, v);
      else db.deleteToken(field);
    }
    for (const [k, v] of Object.entries(identity)) {
      if (skip.has(k)) continue;
      db.setMetadata(k, JSON.stringify(v));
    }
  }

  // ── Instance State ───────────────────────────────────

  async loadInstanceState(aid: string, deviceId: string, slotId = ''): Promise<MetadataRecord | null> {
    return this.getDB(aid).loadInstanceState(deviceId, slotId) as MetadataRecord | null;
  }

  async saveInstanceState(aid: string, deviceId: string, slotId: string, state: MetadataRecord): Promise<void> {
    this.getDB(aid).saveInstanceState(deviceId, slotId, state);
  }

  async updateInstanceState(aid: string, deviceId: string, slotId: string, updater: (state: MetadataRecord) => MetadataRecord | void): Promise<MetadataRecord> {
    const current = (this.getDB(aid).loadInstanceState(deviceId, slotId) ?? {}) as MetadataRecord;
    const working = deepClone(current);
    const updated = updater(working) ?? working;
    this.getDB(aid).saveInstanceState(deviceId, slotId, updated);
    return deepClone(updated);
  }

  // ── Prekeys ──────────────────────────────────────────

  async loadE2EEPrekeys(aid: string): Promise<PrekeyMap> {
    return this.getDB(aid).loadPrekeys('');
  }

  async loadE2EEPrekeysForDevice(aid: string, deviceId: string): Promise<PrekeyMap> {
    return this.getDB(aid).loadPrekeys(String(deviceId ?? '').trim());
  }

  async saveE2EEPrekey(aid: string, prekeyId: string, prekeyData: PrekeyRecord): Promise<void> {
    const pem = typeof prekeyData.private_key_pem === 'string' ? prekeyData.private_key_pem : '';
    const extra: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(prekeyData)) {
      if (!['private_key_pem', 'created_at', 'updated_at', 'expires_at'].includes(k)) extra[k] = v;
    }
    this.getDB(aid).savePrekey(prekeyId, pem, '', prekeyData.created_at, prekeyData.expires_at, extra);
  }

  async saveE2EEPrekeyForDevice(aid: string, deviceId: string, prekeyId: string, prekeyData: PrekeyRecord): Promise<void> {
    const pem = typeof prekeyData.private_key_pem === 'string' ? prekeyData.private_key_pem : '';
    const extra: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(prekeyData)) {
      if (!['private_key_pem', 'created_at', 'updated_at', 'expires_at'].includes(k)) extra[k] = v;
    }
    this.getDB(aid).savePrekey(prekeyId, pem, String(deviceId ?? '').trim(), prekeyData.created_at, prekeyData.expires_at, extra);
  }

  async cleanupE2EEPrekeys(aid: string, cutoffMs: number, keepLatest = 7): Promise<string[]> {
    return this.getDB(aid).cleanupPrekeys('', cutoffMs, keepLatest);
  }

  async cleanupE2EEPrekeysForDevice(aid: string, deviceId: string, cutoffMs: number, keepLatest = 7): Promise<string[]> {
    return this.getDB(aid).cleanupPrekeys(String(deviceId ?? '').trim(), cutoffMs, keepLatest);
  }

  // ── Group Secrets ────────────────────────────────────

  async loadGroupSecretState(aid: string, groupId: string): Promise<GroupSecretRecord | null> {
    const db = this.getDB(aid);
    const current = db.loadGroupCurrent(groupId);
    if (!current) return null;
    const old = db.loadGroupOldEpochs(groupId);
    if (old.length > 0) current.old_epochs = old;
    return current;
  }

  async loadAllGroupSecretStates(aid: string): Promise<GroupSecretMap> {
    const db = this.getDB(aid);
    const result = db.loadAllGroupCurrent();
    for (const [gid, entry] of Object.entries(result)) {
      const old = db.loadGroupOldEpochs(gid);
      if (old.length > 0) entry.old_epochs = old;
    }
    return result;
  }

  async saveGroupSecretState(aid: string, groupId: string, entry: GroupSecretRecord): Promise<void> {
    const db = this.getDB(aid);
    db.deleteAllGroupOldEpochs(groupId);
    if (typeof entry.epoch === 'number') {
      const secret = typeof entry.secret === 'string' ? entry.secret : '';
      const data: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(entry)) {
        if (!['group_id', 'epoch', 'secret', 'old_epochs', 'updated_at'].includes(k)) data[k] = v;
      }
      db.saveGroupCurrent(groupId, entry.epoch, secret, data);
    } else {
      db.deleteGroupCurrent(groupId);
    }
    if (Array.isArray(entry.old_epochs)) {
      for (const old of entry.old_epochs as GroupOldEpochRecord[]) {
        if (typeof old.epoch !== 'number') continue;
        const oldSecret = typeof old.secret === 'string' ? old.secret : '';
        const oldData: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(old)) {
          if (!['epoch', 'secret', 'updated_at', 'expires_at'].includes(k)) oldData[k] = v;
        }
        db.saveGroupOldEpoch(groupId, old.epoch, oldSecret, oldData, old.updated_at, old.expires_at);
      }
    }
  }

  async cleanupGroupOldEpochsState(aid: string, groupId: string, cutoffMs: number): Promise<number> {
    return this.getDB(aid).cleanupGroupOldEpochs(groupId, cutoffMs);
  }

  // ── E2EE Sessions ────────────────────────────────────

  async loadE2EESessions(aid: string): Promise<SessionRecord[]> {
    return this.getDB(aid).loadAllSessions();
  }

  async saveE2EESession(aid: string, sessionId: string, data: SessionRecord): Promise<void> {
    this.getDB(aid).saveSession(sessionId, data as Record<string, unknown>);
  }

  // ── Seq Tracker ────────────────────────────────────────

  async saveSeq(aid: string, deviceId: string, slotId: string, namespace: string, contiguousSeq: number): Promise<void> {
    this.getDB(aid).saveSeq(deviceId, slotId, namespace, contiguousSeq);
  }

  async loadSeq(aid: string, deviceId: string, slotId: string, namespace: string): Promise<number> {
    return this.getDB(aid).loadSeq(deviceId, slotId, namespace);
  }

  async loadAllSeqs(aid: string, deviceId: string, slotId: string): Promise<Record<string, number>> {
    return this.getDB(aid).loadAllSeqs(deviceId, slotId);
  }
}
