/**
 * 基于文件（key.json/cert.pem）+ AIDDatabase（SQLite）的 KeyStore 实现。
 *
 * 与 Python SDK FileKeyStore / Go FileKeyStore 对齐：
 * - key.json / cert.pem 仍用文件存储
 * - tokens / instance_state / metadata_kv / group_state 全部存 SQLite
 * - 废弃 meta.json
 */

import * as crypto from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  readdirSync,
  chmodSync,
  renameSync,
  unlinkSync,
  rmSync as fsRmSync,
  renameSync as fsRenameSync,
  statSync,
} from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';

import type { KeyStore } from './index.js';
import type { SecretStore } from '../secret-store/index.js';
import type { ModuleLogger } from '../logger.js';
import { AIDDatabase } from './aid-db.js';
import { V2KeyStore } from '../v2/session/keystore.js';
import { getDeviceId, normalizeInstanceId } from '../config.js';
import { certificateSha256Fingerprint } from '../crypto.js';
import { createDefaultSecretStore } from '../secret-store/index.js';
import { FileSecretStore, type SeedChangeResult } from '../secret-store/file-store.js';
import {
  isJsonObject,
  type IdentityRecord,
  type JsonObject,
  type KeyPairRecord,
  type MetadataRecord,
} from '../types.js';

const _noopLogger: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };

const TOKEN_FIELDS = new Set(['access_token', 'refresh_token', 'kite_token']);

function secureFilePermissions(path: string): void {
  if (process.platform !== 'win32') {
    try { chmodSync(path, 0o600); } catch { /* ignore */ }
  }
}

function replaceFileSync(tmpPath: string, targetPath: string): void {
  try {
    renameSync(tmpPath, targetPath);
    return;
  } catch (renameErr) {
    try {
      unlinkSync(targetPath);
    } catch (unlinkErr) {
      if ((unlinkErr as { code?: string }).code !== 'ENOENT') {
        throw new Error(`replace target cleanup failed: ${unlinkErr instanceof Error ? unlinkErr.message : String(unlinkErr)}; original rename error: ${renameErr instanceof Error ? renameErr.message : String(renameErr)}`);
      }
    }
    renameSync(tmpPath, targetPath);
  }
}

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function fingerprintFromCertPem(certPem: string): string {
  // 委托给 crypto.ts 的统一实现（ISSUE-SDK-TS-008: 消除两套指纹计算）
  return certificateSha256Fingerprint(certPem);
}

function normalizeCertFingerprint(fp?: string): string {
  const v = String(fp ?? '').trim().toLowerCase();
  if (!v.startsWith('sha256:') || v.length !== 71) return '';
  if (/[^0-9a-f]/.test(v.slice(7))) return '';
  return v;
}

function safeAid(aid: string): string {
  return aid.replace(/[/\\:]/g, '_');
}

export class FileKeyStore implements KeyStore {
  private _root: string;
  private _aidsRoot: string;
  private _secretStore: SecretStore;
  private _aidDBs = new Map<string, AIDDatabase>();
  private _deviceId: string;
  private _logger: ModuleLogger;

  constructor(
    root?: string,
    opts?: {
      secretStore?: SecretStore;
      encryptionSeed?: string;
      sqliteBackup?: unknown; // 保留参数签名，但不再使用
      logger?: ModuleLogger;
      secretStoreLogger?: ModuleLogger;
    },
  ) {
    this._logger = opts?.logger ?? _noopLogger;
    const preferred = root ?? join(homedir(), '.aun');
    const fallback = join(process.cwd(), '.aun');
    this._root = this._prepareRoot(preferred, fallback);
    this._secretStore = opts?.secretStore ?? createDefaultSecretStore(this._root, opts?.encryptionSeed, undefined, { logger: opts?.secretStoreLogger ?? this._logger });
    this._aidsRoot = join(this._root, 'AIDs');
    mkdirSync(this._aidsRoot, { recursive: true });
    this._deviceId = getDeviceId(this._root);
  }

  close(): void {
    this._logger.debug(`FileKeyStore close: closing ${this._aidDBs.size} AID databases`);
    for (const db of this._aidDBs.values()) db.close();
    this._aidDBs.clear();
  }

  static ChangeSeed(root: string, oldSeed: string, newSeed: string): SeedChangeResult {
    return FileSecretStore.changeSeed(root, oldSeed, newSeed);
  }

  changeSeed(oldSeed: string, newSeed: string): SeedChangeResult {
    this.close();
    const result = FileSecretStore.changeSeed(this._root, oldSeed, newSeed, { logger: this._logger });
    this._secretStore = createDefaultSecretStore(this._root, newSeed, undefined, { logger: this._logger });
    return result;
  }

  private _getDB(aid: string): AIDDatabase {
    const safe = safeAid(aid);
    let db = this._aidDBs.get(safe);
    if (!db) {
      const dbPath = join(this._aidsRoot, safe, 'aun.db');
      try {
        db = new AIDDatabase(dbPath, this._secretStore, safe, this._logger);
      } catch (exc) {
        // DB 损坏：备份后重建
        this._logger.warn(`database corrupted, backing up and rebuilding: aid=${aid} err=${exc instanceof Error ? exc.message : String(exc)}`);
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const bakPath = dbPath + `.corrupt_${ts}.bak`;
        try { renameSync(dbPath, bakPath); } catch (renameErr) {
          this._logger.warn(`backup rename failed: ${renameErr instanceof Error ? renameErr.message : String(renameErr)}`);
        }
        // 清理 WAL/SHM
        for (const suffix of ['-wal', '-shm', '-journal']) {
          try { unlinkSync(dbPath + suffix); } catch { /* 文件不存在/无权限均可忽略，下方重建会重新创建 */ }
        }
        db = new AIDDatabase(dbPath, this._secretStore, safe, this._logger);
      }
      this._aidDBs.set(safe, db);
    }
    return db;
  }

  private _prepareRoot(preferred: string, fallback: string): string {
    try {
      mkdirSync(preferred, { recursive: true });
      return preferred;
    } catch {
      // ISSUE-TS-003: 回退时警告用户数据存储位置变更
      this._logger.warn(`preferred path ${preferred} unavailable, falling back to ${fallback}`);
      mkdirSync(fallback, { recursive: true });
      return fallback;
    }
  }

  // ── KeyPair ──────────────────────────────────────────────

  loadKeyPair(aid: string): KeyPairRecord | null {
    const path = this._keyPairPath(aid);
    if (!existsSync(path)) return null;
    let raw: JsonObject;
    try {
      raw = JSON.parse(readFileSync(path, 'utf-8')) as JsonObject;
    } catch (exc) {
      this._logger.warn('key.json read or parse failed, treating as non-existent');
      return null;
    }
    return this._restoreKeyPair(aid, raw, path);
  }

  saveKeyPair(aid: string, keyPair: KeyPairRecord): void {
    const path = this._keyPairPath(aid);
    this._saveKeyPairAtPath(aid, path, keyPair);
  }

  private _saveKeyPairAtPath(aid: string, path: string, keyPair: KeyPairRecord): void {
    mkdirSync(dirname(path), { recursive: true });
    const protected_ = deepClone(keyPair);
    const pem = protected_.private_key_pem;
    if (typeof pem === 'string' && pem) {
      delete protected_.private_key_pem;
      const rec = this._secretStore.protect(safeAid(aid), 'identity/private_key', Buffer.from(pem, 'utf-8'));
      protected_.private_key_protection = rec;
    }
    const tmpPath = `${path}.tmp-${process.pid}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    writeFileSync(tmpPath, JSON.stringify(protected_, null, 2), { mode: 0o600 });
    secureFilePermissions(tmpPath);
    try {
      replaceFileSync(tmpPath, path);
    } catch (exc) {
      try { unlinkSync(tmpPath); } catch { /* ignore tmp cleanup failure */ }
      throw exc;
    }
    secureFilePermissions(path);
  }

  private _restoreKeyPair(aid: string, kp: JsonObject, persistPath?: string): KeyPairRecord {
    const out = deepClone(kp);
    const rec = out.private_key_protection;
    if (isJsonObject(rec)) {
      const plain = this._secretStore.reveal(safeAid(aid), 'identity/private_key', rec as any);
      if (!plain) {
        throw new Error(`private key decrypt failed for aid ${aid}: seed_password mismatch or key.json corrupted`);
      }
      out.private_key_pem = plain.toString('utf-8');
      return out;
    }
    if (persistPath && typeof out.private_key_pem === 'string' && out.private_key_pem) {
      // 兼容历史明文 key.json：首次加载成功后立即用当前 seed_password 加密回写。
      this._saveKeyPairAtPath(aid, persistPath, out as KeyPairRecord);
    }
    return out;
  }

  // ── Cert ─────────────────────────────────────────────────

  loadCert(aid: string, certFingerprint?: string): string | null {
    try {
      const norm = normalizeCertFingerprint(certFingerprint);
      if (norm) {
        const vp = this._certVersionPath(aid, norm);
        if (existsSync(vp)) return readFileSync(vp, 'utf-8');
        const active = this._certPath(aid);
        if (existsSync(active)) {
          const certPem = readFileSync(active, 'utf-8');
          if (fingerprintFromCertPem(certPem) === norm) return certPem;
        }
        return null;
      }
      const path = this._certPath(aid);
      return existsSync(path) ? readFileSync(path, 'utf-8') : null;
    } catch (exc) {
      // 文件被锁定、无权限、目录冲突等异常时降级返回 null
      this._logger.warn('cert.pem read failed, treating as non-existent');
      return null;
    }
  }

  saveCert(aid: string, certPem: string, certFingerprint?: string, opts?: { makeActive?: boolean }): void {
    const norm = normalizeCertFingerprint(certFingerprint);
    if (norm) {
      const vp = this._certVersionPath(aid, norm);
      mkdirSync(dirname(vp), { recursive: true });
      writeFileSync(vp, certPem);
      if (!opts?.makeActive) return;
    }
    const path = this._certPath(aid);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, certPem);
  }

  // ── Identity ─────────────────────────────────────────────

  loadIdentity(aid: string): IdentityRecord | null {
    // 只读语义保护：身份目录不存在时直接返回 null，绝不通过 _getDB 触发
    // `~/.aun/AIDs/{aid}/aun.db` 的副作用 mkdir。这避免了"用对端 AID
    // 误调 loadIdentity"导致本地落下空目录的安全事故。
    const identityDir = join(this._aidsRoot, safeAid(aid));
    if (!existsSync(identityDir)) return null;

    const kp = this.loadKeyPair(aid);
    const cert = this.loadCert(aid);
    // 直接从 DB 读取 tokens + KV
    const db = this._getDB(aid);
    const tokens = db.getAllTokens();
    const kv = db.getAllMetadata();
    const hasMeta = Object.keys(tokens).length > 0 || Object.keys(kv).length > 0;
    if (!kp && !cert && !hasMeta) return null;
    const identity: IdentityRecord = {};
    for (const [k, v] of Object.entries(kv)) {
      try { identity[k] = JSON.parse(v); } catch { identity[k] = v; }
    }
    Object.assign(identity, tokens);
    if (kp) Object.assign(identity, kp);
    if (cert) {
      // key/cert 公钥一致性校验：防止 cert.pem 被意外覆盖
      const localPubB64 = kp?.public_key_der_b64;
      if (typeof localPubB64 === 'string' && localPubB64) {
        try {
          const x = new crypto.X509Certificate(cert);
          const certPubDer = x.publicKey.export({ type: 'spki', format: 'der' });
          const localPubDer = Buffer.from(localPubB64, 'base64');
          if (!certPubDer.equals(localPubDer)) {
            this._logger.error('key.json public key does not match cert.pem public key, discarding cert');
          } else {
            identity.cert = cert;
          }
        } catch { identity.cert = cert; }
      } else {
        identity.cert = cert;
      }
    }
    return identity;
  }

  saveIdentity(aid: string, identity: IdentityRecord): void {
    const kp: KeyPairRecord = {};
    for (const k of ['private_key_pem', 'public_key_der_b64', 'curve'] as const) {
      if (k in identity) kp[k] = identity[k] as string;
    }
    if (Object.keys(kp).length > 0) this.saveKeyPair(aid, kp);
    if (typeof identity.cert === 'string' && identity.cert) this.saveCert(aid, identity.cert);
    // 直接写入 tokens + KV
    const db = this._getDB(aid);
    const skip = new Set([...TOKEN_FIELDS, 'private_key_pem', 'public_key_der_b64', 'curve', 'cert']);
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

  loadAnyIdentity(): IdentityRecord | null {
    if (!existsSync(this._aidsRoot)) return null;
    for (const entry of readdirSync(this._aidsRoot, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith('_')) continue;
      const identity = this.loadIdentity(entry.name);
      if (identity) return identity;
    }
    return null;
  }

  // ── Instance State ───────────────────────────────────────

  loadInstanceState(aid: string, deviceId: string, slotId = ''): MetadataRecord | null {
    return this._getDB(aid).loadInstanceState(deviceId, slotId) as MetadataRecord | null;
  }

  saveInstanceState(aid: string, deviceId: string, slotId: string, state: MetadataRecord): void {
    this._getDB(aid).saveInstanceState(deviceId, slotId, state);
  }

  updateInstanceState(aid: string, deviceId: string, slotId: string, updater: (state: MetadataRecord) => MetadataRecord | void): MetadataRecord {
    const db = this._getDB(aid);
    const current = (db.loadInstanceState(deviceId, slotId) ?? {}) as MetadataRecord;
    const working = deepClone(current);
    const updated: MetadataRecord = (updater(working) ?? working) as MetadataRecord;
    db.saveInstanceState(deviceId, slotId, updated);
    return deepClone(updated);
  }

  // ── Seq Tracker ───────────────────────────────────────────

  saveSeq(aid: string, deviceId: string, slotId: string, namespace: string, contiguousSeq: number): void {
    this._getDB(aid).saveSeq(deviceId, slotId, namespace, contiguousSeq);
  }

  loadSeq(aid: string, deviceId: string, slotId: string, namespace: string): number {
    return this._getDB(aid).loadSeq(deviceId, slotId, namespace);
  }

  loadAllSeqs(aid: string, deviceId: string, slotId: string): Record<string, number> {
    return this._getDB(aid).loadAllSeqs(deviceId, slotId);
  }

  deleteSeq(aid: string, deviceId: string, slotId: string, namespace: string): void {
    this._getDB(aid).deleteSeq(deviceId, slotId, namespace);
  }

  // ── 身份列表 ───────────────────────────────────────────

  /** 列出所有已存储的 AID（对齐 Python list_identities） */
  listIdentities(): string[] {
    if (!existsSync(this._aidsRoot)) return [];
    const aids: string[] = [];
    for (const entry of readdirSync(this._aidsRoot, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      // 跳过保留前缀的特殊目录（_pending 等）
      if (entry.name.startsWith('_')) continue;
      aids.push(entry.name);
    }
    return aids;
  }

  /** 加载指定 AID 的元数据（对齐 Python load_metadata） */
  loadMetadata(aid: string): Record<string, unknown> | null {
    try {
      const db = this._getDB(aid);
      const kv = db.getAllMetadata();
      if (Object.keys(kv).length === 0) return null;
      const result: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(kv)) {
        try { result[k] = JSON.parse(v); } catch { result[k] = v; }
      }
      return result;
    } catch {
      return null;
    }
  }

  /** 保存指定 AID 的元数据；只覆盖传入字段，不清理其它 metadata。 */
  saveMetadata(aid: string, metadata: Record<string, unknown>): void {
    const db = this._getDB(aid);
    for (const [k, v] of Object.entries(metadata)) {
      if (v === undefined) {
        db.deleteMetadata(k);
        continue;
      }
      db.setMetadata(k, JSON.stringify(v));
    }
  }

  // ── 旧 E2EE 存储互操作 ───────────────────────────────────

  async saveE2EEPrekey(aid: string, prekeyId: string, prekeyData: Record<string, unknown>, deviceId = ''): Promise<void> {
    const now = Date.now();
    const privateKey = String(prekeyData.private_key_pem ?? '');
    const extra: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(prekeyData)) {
      if (!['private_key_pem', 'created_at', 'updated_at', 'expires_at'].includes(key)) extra[key] = value;
    }
    this._getDB(aid).getSqliteHandle().prepare(
      `INSERT INTO prekeys (prekey_id, device_id, private_key_enc, data, created_at, updated_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(prekey_id, device_id) DO UPDATE SET
         private_key_enc=excluded.private_key_enc,
         data=excluded.data,
         updated_at=excluded.updated_at,
         expires_at=excluded.expires_at`,
    ).run(
      prekeyId,
      String(deviceId ?? ''),
      privateKey, // 阶段6：明文写入，IK 私钥除外
      JSON.stringify(extra),
      Number(prekeyData.created_at ?? now),
      now,
      prekeyData.expires_at == null ? null : Number(prekeyData.expires_at),
    );
  }

  async loadE2EEPrekeys(aid: string, deviceId = ''): Promise<Record<string, Record<string, unknown>>> {
    const rows = this._getDB(aid).getSqliteHandle().prepare(
      `SELECT prekey_id, private_key_enc, data, created_at, updated_at, expires_at
       FROM prekeys WHERE device_id = ?`,
    ).all(String(deviceId ?? '')) as Array<Record<string, unknown>>;
    const result: Record<string, Record<string, unknown>> = {};
    for (const row of rows) {
      const id = String(row.prekey_id ?? '');
      if (!id) continue;
      const entry: Record<string, unknown> = {
        private_key_pem: String(row.private_key_enc ?? ''),
        created_at: row.created_at,
        updated_at: row.updated_at,
        expires_at: row.expires_at,
      };
      try {
        const extra = JSON.parse(String(row.data ?? '{}'));
        if (extra && typeof extra === 'object' && !Array.isArray(extra)) Object.assign(entry, extra);
      } catch { /* ignore damaged extra payload */ }
      result[id] = entry;
    }
    return result;
  }

  async listGroupSecretIds(aid: string): Promise<string[]> {
    const db = this._getDB(aid).getSqliteHandle();
    const ids = new Set<string>();
    for (const row of db.prepare('SELECT group_id FROM group_current').all() as Array<Record<string, unknown>>) {
      ids.add(String(row.group_id ?? ''));
    }
    for (const row of db.prepare('SELECT DISTINCT group_id FROM group_old_epochs').all() as Array<Record<string, unknown>>) {
      ids.add(String(row.group_id ?? ''));
    }
    return Array.from(ids).filter(Boolean).sort();
  }

  async loadGroupSecretEpoch(aid: string, groupId: string, epoch?: number | null): Promise<Record<string, unknown> | null> {
    const db = this._getDB(aid).getSqliteHandle();
    const current = db.prepare(
      'SELECT epoch, secret_enc, data, updated_at FROM group_current WHERE group_id = ?',
    ).get(groupId) as Record<string, unknown> | undefined;
    if (current && (epoch == null || Number(current.epoch ?? 0) === Number(epoch))) {
      const entry: Record<string, unknown> = {
        group_id: groupId,
        epoch: current.epoch,
        secret: String(current.secret_enc ?? ''),
        updated_at: current.updated_at,
      };
      try {
        const extra = JSON.parse(String(current.data ?? '{}'));
        if (extra && typeof extra === 'object' && !Array.isArray(extra)) Object.assign(entry, extra);
      } catch { /* ignore damaged extra payload */ }
      return entry;
    }
    if (epoch == null) return null;
    const old = db.prepare(
      'SELECT epoch, secret_enc, data, updated_at, expires_at FROM group_old_epochs WHERE group_id = ? AND epoch = ?',
    ).get(groupId, Number(epoch)) as Record<string, unknown> | undefined;
    if (!old) return null;
    const entry: Record<string, unknown> = {
      epoch: old.epoch,
      secret: String(old.secret_enc ?? ''),
      updated_at: old.updated_at,
    };
    if (old.expires_at != null) entry.expires_at = old.expires_at;
    try {
      const extra = JSON.parse(String(old.data ?? '{}'));
      if (extra && typeof extra === 'object' && !Array.isArray(extra)) Object.assign(entry, extra);
    } catch { /* ignore damaged extra payload */ }
    return entry;
  }

  async storeGroupSecretTransition(
    aid: string,
    groupId: string,
    opts: {
      epoch: number;
      secret: string;
      commitment: string;
      memberAids?: string[];
      oldEpochRetentionMs?: number;
    },
  ): Promise<boolean> {
    const db = this._getDB(aid).getSqliteHandle();
    const now = Date.now();
    const epoch = Number(opts.epoch ?? 0);
    const current = db.prepare(
      'SELECT epoch, secret_enc, data, updated_at FROM group_current WHERE group_id = ?',
    ).get(groupId) as Record<string, unknown> | undefined;
    if (current && Number(current.epoch ?? 0) > epoch) return false;
    if (current && Number(current.epoch ?? 0) !== epoch) {
      const oldEpoch = Number(current.epoch ?? 0);
      const oldSecret = String(current.secret_enc ?? '');
      db.prepare(
        `INSERT INTO group_old_epochs (group_id, epoch, secret_enc, data, updated_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(group_id, epoch) DO UPDATE SET
           secret_enc=excluded.secret_enc,
           data=excluded.data,
           updated_at=excluded.updated_at,
           expires_at=excluded.expires_at`,
      ).run(
        groupId,
        oldEpoch,
        oldSecret,
        String(current.data ?? '{}'),
        Number(current.updated_at ?? now),
        Number(current.updated_at ?? now) + Number(opts.oldEpochRetentionMs ?? 0),
      );
    }
    const data = {
      commitment: String(opts.commitment ?? ''),
      member_aids: Array.isArray(opts.memberAids) ? [...opts.memberAids].map(String).sort() : [],
    };
    db.prepare(
      `INSERT INTO group_current (group_id, epoch, secret_enc, data, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(group_id) DO UPDATE SET
         epoch=excluded.epoch,
         secret_enc=excluded.secret_enc,
         data=excluded.data,
         updated_at=excluded.updated_at`,
    ).run(
      groupId,
      epoch,
      String(opts.secret ?? ''), // 阶段6：明文写入
      JSON.stringify(data),
      now,
    );
    return true;
  }

  async saveE2EESession(aid: string, sessionId: string, data: Record<string, unknown>): Promise<void> {
    const dataJson = JSON.stringify(data ?? {});
    this._getDB(aid).getSqliteHandle().prepare(
      `INSERT INTO e2ee_sessions (session_id, data_enc, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(session_id) DO UPDATE SET data_enc=excluded.data_enc, updated_at=excluded.updated_at`,
    ).run(sessionId, dataJson, Date.now()); // 阶段6：明文写入
  }

  async loadE2EESessions(aid: string): Promise<Array<Record<string, unknown>>> {
    const rows = this._getDB(aid).getSqliteHandle().prepare(
      'SELECT session_id, data_enc, updated_at FROM e2ee_sessions',
    ).all() as Array<Record<string, unknown>>;
    const result: Array<Record<string, unknown>> = [];
    for (const row of rows) {
      const sessionId = String(row.session_id ?? '');
      if (!sessionId) continue;
      try {
        const entry = JSON.parse(String(row.data_enc ?? '{}'));
        if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
          result.push({ ...entry, session_id: sessionId, updated_at: row.updated_at });
        }
      } catch { /* ignore damaged session payload */ }
    }
    return result;
  }


  // ── 信任根管理 ─────────────────────────────────────────────

  trustRootDir(): string {
    const dir = join(this._root, 'CA', 'root');
    mkdirSync(dir, { recursive: true });
    return dir;
  }

  trustRootBundlePath(): string {
    return join(this.trustRootDir(), 'trust-roots.pem');
  }

  saveTrustRoots(
    trustList: Record<string, unknown>,
    rootCerts: Array<{ id?: string; cert_pem: string; fingerprint_sha256?: string }>,
  ): string {
    const dir = this.trustRootDir();

    // 保存每个根证书
    for (let i = 0; i < rootCerts.length; i++) {
      const item = rootCerts[i];
      const certId = item.id || item.fingerprint_sha256 || `root-${i + 1}`;
      const safeName = certId.replace(/[^A-Za-z0-9_.-]+/g, '_').slice(0, 120);
      writeFileSync(join(dir, `${safeName}.crt`), item.cert_pem, 'utf-8');
    }

    // 生成合并 bundle
    const bundlePath = this.trustRootBundlePath();
    const bundle = rootCerts.map(i => i.cert_pem.trim()).join('\n') + '\n';
    writeFileSync(bundlePath, bundle, 'utf-8');

    // 保存元数据 JSON
    writeFileSync(join(dir, 'trust-roots.json'), JSON.stringify(trustList, null, 2), 'utf-8');

    return bundlePath;
  }

  saveIssuerRootCert(
    issuer: string,
    certPem: string,
    fingerprintSha256: string = '',
  ): [string, string] {
    const dir = this.trustRootDir();
    const issuersDir = join(dir, 'issuers');
    mkdirSync(issuersDir, { recursive: true });

    // 保存 issuer 根证书
    const safeIssuer = (issuer || 'issuer').replace(/[^A-Za-z0-9_.-]+/g, '_').slice(0, 120);
    const certPath = join(issuersDir, `${safeIssuer}.root.crt`);
    const normalizedPem = certPem.trim() + '\n';
    writeFileSync(certPath, normalizedPem, 'utf-8');

    // 读取已有 bundle 并合并（按指纹去重）
    const bundlePath = this.trustRootBundlePath();
    const existingPems = new Map<string, string>();
    try {
      const bundleText = readFileSync(bundlePath, 'utf-8');
      for (const pem of this._splitPemBundle(bundleText)) {
        const fp = this._pemFingerprint(pem);
        existingPems.set(fp, pem);
      }
    } catch { /* bundle 不存在时忽略 */ }

    // 新证书的指纹
    let newFp = this._pemFingerprint(normalizedPem);
    if (fingerprintSha256) {
      newFp = fingerprintSha256.toLowerCase().replace(/^sha256:/, '');
    }
    existingPems.set(newFp, normalizedPem);

    // 重写 bundle
    const merged = Array.from(existingPems.values()).map(p => p.trim()).join('\n') + '\n';
    writeFileSync(bundlePath, merged, 'utf-8');

    return [certPath, bundlePath];
  }

  private _splitPemBundle(bundleText: string): string[] {
    return bundleText
      .split(/(?<=-----END CERTIFICATE-----)\s*/)
      .map(s => s.trim())
      .filter(s => s.startsWith('-----BEGIN CERTIFICATE-----'));
  }

  private _pemFingerprint(pem: string): string {
    try {
      const der = pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s/g, '');
      const hash = crypto.createHash('sha256').update(Buffer.from(der, 'base64')).digest('hex');
      return hash;
    } catch {
      return crypto.createHash('sha256').update(pem, 'utf-8').digest('hex');
    }
  }

  // ── 路径辅助 ─────────────────────────────────────────────

  private _keyPairPath(aid: string): string {
    return join(this._aidsRoot, safeAid(aid), 'private', 'key.json');
  }

  private _certPath(aid: string): string {
    return join(this._aidsRoot, safeAid(aid), 'public', 'cert.pem');
  }

  private _certVersionPath(aid: string, fp: string): string {
    return join(this._aidsRoot, safeAid(aid), 'public', 'certs', `${fp.replace(/:/g, '_')}.pem`);
  }

  /** RegisterAID 临时目录根：AIDs/_pending/ */
  private _pendingRoot(): string {
    return join(this._aidsRoot, '_pending');
  }

  /**
   * 为 RegisterAID 分配一个临时目录 AIDs/_pending/{aid}-{nonce}-{ts}/。
   * 子目录 private/ public/ 一并创建。
   */
  pendingIdentityDir(aid: string): string {
    const nonce = crypto.randomBytes(4).toString('hex');
    const ts = Math.floor(Date.now() / 1000);
    const dir = join(this._pendingRoot(), `${safeAid(aid)}-${nonce}-${ts}`);
    mkdirSync(join(dir, 'private'), { recursive: true });
    mkdirSync(join(dir, 'public'), { recursive: true });
    return dir;
  }

  listPendingIdentityDirs(aid: string): string[] {
    const root = this._pendingRoot();
    if (!existsSync(root)) return [];
    const prefix = `${safeAid(aid)}-`;
    const items: Array<{ path: string; mtimeMs: number }> = [];
    for (const entry of readdirSync(root, { withFileTypes: true })) {
      if (!entry.isDirectory() || !entry.name.startsWith(prefix)) continue;
      const path = join(root, entry.name);
      try {
        items.push({ path, mtimeMs: statSync(path).mtimeMs });
      } catch { /* ignore unreadable pending entry */ }
    }
    return items.sort((a, b) => b.mtimeMs - a.mtimeMs).map((item) => item.path);
  }

  savePendingKeyPair(pendingDir: string, aid: string, keyPair: KeyPairRecord): void {
    this._saveKeyPairAtPath(aid, join(pendingDir, 'private', 'key.json'), keyPair);
  }

  loadPendingKeyPair(pendingDir: string, aid: string): KeyPairRecord | null {
    const keyPath = join(pendingDir, 'private', 'key.json');
    if (!existsSync(keyPath)) return null;
    let raw: JsonObject;
    try {
      raw = JSON.parse(readFileSync(keyPath, 'utf-8')) as JsonObject;
    } catch {
      return null;
    }
    return this._restoreKeyPair(aid, raw, keyPath);
  }

  savePendingCert(pendingDir: string, certPem: string): void {
    const certPath = join(pendingDir, 'public', 'cert.pem');
    mkdirSync(dirname(certPath), { recursive: true });
    writeFileSync(certPath, certPem, { encoding: 'utf-8', mode: 0o600 });
  }

  /**
   * 把临时目录原子 rename 到正式 AIDs/{aid}/。
   * 目标已存在 → 抛错（调用方应当返回 IdentityConflictError）。
   */
  promotePendingIdentity(pendingDir: string, aid: string): string {
    this._ensurePendingKeyPairProtected(pendingDir, aid);
    const target = join(this._aidsRoot, safeAid(aid));
    if (existsSync(target)) {
      throw new Error(`promotePendingIdentity: target exists: ${target}`);
    }
    // 关闭 lazy 打开的 db 句柄（如果有），避免句柄占用旧路径
    const safe = safeAid(aid);
    const db = this._aidDBs.get(safe);
    if (db) {
      try { db.close(); } catch { /* ignore */ }
      this._aidDBs.delete(safe);
    }
    mkdirSync(this._aidsRoot, { recursive: true });
    fsRenameSync(pendingDir, target);
    return target;
  }

  private _ensurePendingKeyPairProtected(pendingDir: string, aid: string): void {
    const keyPath = join(pendingDir, 'private', 'key.json');
    if (!existsSync(keyPath)) {
      throw new Error(`pending identity missing key pair for ${aid}`);
    }
    const raw = JSON.parse(readFileSync(keyPath, 'utf-8')) as JsonObject;
    if (typeof raw.private_key_pem === 'string' && raw.private_key_pem) {
      throw new Error(`pending identity private key is plaintext for ${aid}`);
    }
    if (!isJsonObject(raw.private_key_protection)) {
      throw new Error(`pending identity private key is not encrypted for ${aid}`);
    }
  }

  /**
   * 删除 AIDs/_pending/ 下 mtime 超过 maxAgeMs 的子目录。
   * 失败仅记 warn，不抛错。返回被清理的目录数量。
   */
  cleanupPendingDirs(maxAgeMs: number = 600_000): number {
    const root = this._pendingRoot();
    if (!existsSync(root)) return 0;
    let removed = 0;
    const now = Date.now();
    try {
      for (const entry of readdirSync(root, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        const path = join(root, entry.name);
        try {
          const st = statSync(path);
          if (now - st.mtimeMs < maxAgeMs) continue;
          fsRmSync(path, { recursive: true, force: true });
          removed++;
        } catch (e) {
          this._logger.warn(`cleanupPendingDirs entry failed: ${path} err=${e instanceof Error ? e.message : String(e)}`);
        }
      }
    } catch (e) {
      this._logger.warn(`cleanupPendingDirs read root failed: ${root} err=${e instanceof Error ? e.message : String(e)}`);
    }
    return removed;
  }

  discardPendingIdentity(pendingDir: string): void {
    fsRmSync(pendingDir, { recursive: true, force: true });
  }

  /** 获取指定 AID 的 V2KeyStore（共享同一 SQLite 连接）。 */
  getV2KeyStore(aid: string): V2KeyStore {
    const db = this._getDB(aid);
    return new V2KeyStore(db.getSqliteHandle());
  }
}
