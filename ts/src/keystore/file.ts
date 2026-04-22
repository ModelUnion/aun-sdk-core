/**
 * 基于文件（key.json/cert.pem）+ AIDDatabase（SQLite）的 KeyStore 实现。
 *
 * 与 Python SDK FileKeyStore / Go FileKeyStore 对齐：
 * - key.json / cert.pem 仍用文件存储
 * - tokens / prekeys / group_secrets / sessions / instance_state / metadata_kv 全部存 SQLite
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
} from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';

import type { KeyStore } from './index.js';
import type { SecretStore } from '../secret-store/index.js';
import { AIDDatabase } from './aid-db.js';
import { normalizeInstanceId } from '../config.js';
import { certificateSha256Fingerprint } from '../crypto.js';
import { createDefaultSecretStore } from '../secret-store/index.js';
import {
  isJsonObject,
  type GroupOldEpochRecord,
  type GroupSecretMap,
  type GroupSecretRecord,
  type IdentityRecord,
  type JsonObject,
  type KeyPairRecord,
  type MetadataRecord,
  type PrekeyMap,
  type PrekeyRecord,
} from '../types.js';

const TOKEN_FIELDS = new Set(['access_token', 'refresh_token', 'kite_token']);

function secureFilePermissions(path: string): void {
  if (process.platform !== 'win32') {
    try { chmodSync(path, 0o600); } catch { /* ignore */ }
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

  constructor(
    root?: string,
    opts?: {
      secretStore?: SecretStore;
      encryptionSeed?: string;
      sqliteBackup?: unknown; // 保留参数签名，但不再使用
    },
  ) {
    const preferred = root ?? join(homedir(), '.aun');
    const fallback = join(process.cwd(), '.aun');
    this._root = this._prepareRoot(preferred, fallback);
    this._secretStore = opts?.secretStore ?? createDefaultSecretStore(this._root, opts?.encryptionSeed);
    this._aidsRoot = join(this._root, 'AIDs');
    mkdirSync(this._aidsRoot, { recursive: true });
  }

  close(): void {
    for (const db of this._aidDBs.values()) db.close();
    this._aidDBs.clear();
  }

  private _getDB(aid: string): AIDDatabase {
    const safe = safeAid(aid);
    let db = this._aidDBs.get(safe);
    if (!db) {
      const dbPath = join(this._aidsRoot, safe, 'aun.db');
      try {
        db = new AIDDatabase(dbPath);
      } catch (exc) {
        // DB 损坏：备份后重建
        console.warn('[aun_core.keystore] 数据库损坏，备份后重建');
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const bakPath = dbPath + `.corrupt_${ts}.bak`;
        try { renameSync(dbPath, bakPath); } catch { /* 备份失败也继续重建 */ }
        // 清理 WAL/SHM
        for (const suffix of ['-wal', '-shm', '-journal']) {
          try { unlinkSync(dbPath + suffix); } catch { /* ignore */ }
        }
        db = new AIDDatabase(dbPath);
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
      console.warn(`[aun_core.keystore] 首选路径 ${preferred} 不可用，回退到 ${fallback}`);
      mkdirSync(fallback, { recursive: true });
      return fallback;
    }
  }

  // ── KeyPair ──────────────────────────────────────────────

  loadKeyPair(aid: string): KeyPairRecord | null {
    const path = this._keyPairPath(aid);
    if (!existsSync(path)) return null;
    try {
      const raw = JSON.parse(readFileSync(path, 'utf-8'));
      return this._restoreKeyPair(aid, raw);
    } catch (exc) {
      console.warn('[aun_core.keystore] key.json 读取或解析失败，视为不存在');
      return null;
    }
  }

  saveKeyPair(aid: string, keyPair: KeyPairRecord): void {
    const path = this._keyPairPath(aid);
    mkdirSync(dirname(path), { recursive: true });
    const protected_ = deepClone(keyPair);
    const pem = protected_.private_key_pem;
    if (typeof pem === 'string' && pem) {
      delete protected_.private_key_pem;
      const rec = this._secretStore.protect(safeAid(aid), 'identity/private_key', Buffer.from(pem, 'utf-8'));
      protected_.private_key_protection = rec;
    }
    writeFileSync(path, JSON.stringify(protected_, null, 2), { mode: 0o600 });
    secureFilePermissions(path);
  }

  private _restoreKeyPair(aid: string, kp: JsonObject): KeyPairRecord {
    const out = deepClone(kp);
    const rec = out.private_key_protection;
    if (isJsonObject(rec)) {
      const plain = this._secretStore.reveal(safeAid(aid), 'identity/private_key', rec as any);
      if (plain) out.private_key_pem = plain.toString('utf-8');
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
      console.warn('[aun_core.keystore] cert.pem 读取失败，视为不存在');
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
            console.error('[keystore] key.json 公钥与 cert.pem 公钥不匹配，丢弃 cert');
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

  loadAnyIdentity(): IdentityRecord | null {
    if (!existsSync(this._aidsRoot)) return null;
    for (const entry of readdirSync(this._aidsRoot, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const identity = this.loadIdentity(entry.name);
      if (identity) return identity;
    }
    return null;
  }

  // ── Prekeys ──────────────────────────────────────────────

  loadE2EEPrekeys(aid: string): PrekeyMap {
    return this._getDB(aid).loadPrekeys('') as PrekeyMap;
  }

  loadE2EEPrekeysForDevice(aid: string, deviceId: string): PrekeyMap {
    return this._getDB(aid).loadPrekeys(String(deviceId ?? '').trim()) as PrekeyMap;
  }

  saveE2EEPrekey(aid: string, prekeyId: string, prekeyData: PrekeyRecord): void {
    const pem = typeof prekeyData.private_key_pem === 'string' ? prekeyData.private_key_pem : '';
    const extra: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(prekeyData)) {
      if (!['private_key_pem', 'created_at', 'updated_at', 'expires_at'].includes(k)) extra[k] = v;
    }
    this._getDB(aid).savePrekey(prekeyId, pem, '', prekeyData.created_at, prekeyData.expires_at, extra);
  }

  saveE2EEPrekeyForDevice(aid: string, deviceId: string, prekeyId: string, prekeyData: PrekeyRecord): void {
    const pem = typeof prekeyData.private_key_pem === 'string' ? prekeyData.private_key_pem : '';
    const extra: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(prekeyData)) {
      if (!['private_key_pem', 'created_at', 'updated_at', 'expires_at'].includes(k)) extra[k] = v;
    }
    this._getDB(aid).savePrekey(prekeyId, pem, String(deviceId ?? '').trim(), prekeyData.created_at, prekeyData.expires_at, extra);
  }

  cleanupE2EEPrekeys(aid: string, cutoffMs: number, keepLatest = 7): string[] {
    return this._getDB(aid).cleanupPrekeys('', cutoffMs, keepLatest);
  }

  cleanupE2EEPrekeysForDevice(aid: string, deviceId: string, cutoffMs: number, keepLatest = 7): string[] {
    return this._getDB(aid).cleanupPrekeys(String(deviceId ?? '').trim(), cutoffMs, keepLatest);
  }

  // ── Group Secrets ────────────────────────────────────────

  loadGroupSecretState(aid: string, groupId: string): GroupSecretRecord | null {
    const db = this._getDB(aid);
    const current = db.loadGroupCurrent(groupId);
    if (!current) return null;
    const old = db.loadGroupOldEpochs(groupId);
    if (old.length > 0) (current as any).old_epochs = old;
    return current as GroupSecretRecord;
  }

  loadAllGroupSecretStates(aid: string): GroupSecretMap {
    const db = this._getDB(aid);
    const result = db.loadAllGroupCurrent();
    for (const [gid, entry] of Object.entries(result)) {
      const old = db.loadGroupOldEpochs(gid);
      if (old.length > 0) (entry as any).old_epochs = old;
    }
    return result as GroupSecretMap;
  }

  saveGroupSecretState(aid: string, groupId: string, entry: GroupSecretRecord): void {
    const db = this._getDB(aid);
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

  cleanupGroupOldEpochsState(aid: string, groupId: string, cutoffMs: number): number {
    return this._getDB(aid).cleanupGroupOldEpochs(groupId, cutoffMs);
  }

  deleteGroupSecretState(aid: string, groupId: string): void {
    const db = this._getDB(aid);
    db.deleteGroupCurrent(groupId);
    db.deleteAllGroupOldEpochs(groupId);
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
    const updated = updater(working) ?? working;
    db.saveInstanceState(deviceId, slotId, updated);
    return deepClone(updated);
  }

  // ── E2EE Sessions ────────────────────────────────────────

  loadE2EESessions(aid: string): Array<Record<string, unknown>> {
    return this._getDB(aid).loadAllSessions();
  }

  saveE2EESession(aid: string, sessionId: string, data: Record<string, unknown>): void {
    this._getDB(aid).saveSession(sessionId, data);
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

  // ── 身份列表 ───────────────────────────────────────────

  /** 列出所有已存储的 AID（对齐 Python list_identities） */
  listIdentities(): string[] {
    if (!existsSync(this._aidsRoot)) return [];
    const aids: string[] = [];
    for (const entry of readdirSync(this._aidsRoot, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
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
}
