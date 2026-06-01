/**
 * LocalTokenStore — 基于 SQLite 的 TokenStore 实现（不含私钥操作）。
 * AUNClient / AuthFlow 持有此类型。
 */

import * as crypto from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  renameSync,
  unlinkSync,
} from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';

import type { TokenStore } from './index.js';
import type { SecretStore } from '../secret-store/index.js';
import type { ModuleLogger } from '../logger.js';
import { AIDDatabase } from './aid-db.js';
import { V2KeyStore } from '../v2/session/keystore.js';
import { getDeviceId } from '../config.js';
import { certificateSha256Fingerprint } from '../crypto.js';
import { createDefaultSecretStore } from '../secret-store/index.js';
import { FileSecretStore, type SeedChangeResult } from '../secret-store/file-store.js';
import type { MetadataRecord } from '../types.js';

const _noopLogger: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };

function normalizeCertFingerprint(fp?: string): string {
  const v = String(fp ?? '').trim().toLowerCase();
  if (!v.startsWith('sha256:') || v.length !== 71) return '';
  if (/[^0-9a-f]/.test(v.slice(7))) return '';
  return v;
}

function safeAid(aid: string): string {
  return aid.replace(/[/\\:]/g, '_');
}

export class LocalTokenStore implements TokenStore {
  private _root: string;
  private _aidsRoot: string;
  private _secretStore: SecretStore;
  private _aidDBs = new Map<string, AIDDatabase>();
  readonly deviceId: string;
  private _logger: ModuleLogger;

  constructor(
    root?: string,
    opts?: {
      secretStore?: SecretStore;
      encryptionSeed?: string;
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
    this.deviceId = getDeviceId(this._root);
  }

  close(): void {
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

  private _prepareRoot(preferred: string, fallback: string): string {
    try {
      mkdirSync(preferred, { recursive: true });
      return preferred;
    } catch {
      this._logger.warn(`preferred path ${preferred} unavailable, falling back to ${fallback}`);
      mkdirSync(fallback, { recursive: true });
      return fallback;
    }
  }

  private _getDB(aid: string): AIDDatabase {
    const safe = safeAid(aid);
    let db = this._aidDBs.get(safe);
    if (!db) {
      const dbPath = join(this._aidsRoot, safe, 'aun.db');
      try {
        db = new AIDDatabase(dbPath, this._secretStore, safe, this._logger);
      } catch (exc) {
        this._logger.warn(`database corrupted, backing up and rebuilding: aid=${aid} err=${exc instanceof Error ? exc.message : String(exc)}`);
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const bakPath = dbPath + `.corrupt_${ts}.bak`;
        try { renameSync(dbPath, bakPath); } catch (renameErr) {
          this._logger.warn(`backup rename failed: ${renameErr instanceof Error ? renameErr.message : String(renameErr)}`);
        }
        for (const suffix of ['-wal', '-shm', '-journal']) {
          try { unlinkSync(dbPath + suffix); } catch { /* ignore */ }
        }
        db = new AIDDatabase(dbPath, this._secretStore, safe, this._logger);
      }
      this._aidDBs.set(safe, db);
    }
    return db;
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
          if (certificateSha256Fingerprint(certPem) === norm) return certPem;
        }
        return null;
      }
      const path = this._certPath(aid);
      return existsSync(path) ? readFileSync(path, 'utf-8') : null;
    } catch {
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
    const working = JSON.parse(JSON.stringify(current)) as MetadataRecord;
    const updated: MetadataRecord = (updater(working) ?? working) as MetadataRecord;
    db.saveInstanceState(deviceId, slotId, updated);
    return JSON.parse(JSON.stringify(updated)) as MetadataRecord;
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

  // ── Metadata ─────────────────────────────────────────────

  loadMetadata(aid: string): Record<string, unknown> | null {
    try {
      const dbPath = join(this._aidsRoot, safeAid(aid), 'aun.db');
      if (!existsSync(dbPath)) return null;
      const db = this._getDB(aid);
      const kv = db.getAllMetadata();
      if (Object.keys(kv).length === 0) return null;
      const result: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(kv)) {
        try { result[k] = JSON.parse(v); } catch { result[k] = v; }
      }
      return result;
    } catch { return null; }
  }

  saveMetadata(aid: string, metadata: Record<string, unknown>): void {
    const db = this._getDB(aid);
    for (const [k, v] of Object.entries(metadata)) {
      if (v === undefined) { db.deleteMetadata(k); continue; }
      db.setMetadata(k, JSON.stringify(v));
    }
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

  saveTrustRoots(trustList: Record<string, unknown>, rootCerts: Array<{ id?: string; cert_pem: string; fingerprint_sha256?: string }>): string {
    const dir = this.trustRootDir();
    for (let i = 0; i < rootCerts.length; i++) {
      const item = rootCerts[i];
      const certId = item.id || item.fingerprint_sha256 || `root-${i + 1}`;
      const safeName = certId.replace(/[^A-Za-z0-9_.-]+/g, '_').slice(0, 120);
      writeFileSync(join(dir, `${safeName}.crt`), item.cert_pem, 'utf-8');
    }
    const bundlePath = this.trustRootBundlePath();
    writeFileSync(bundlePath, rootCerts.map(i => i.cert_pem.trim()).join('\n') + '\n', 'utf-8');
    writeFileSync(join(dir, 'trust-roots.json'), JSON.stringify(trustList, null, 2), 'utf-8');
    return bundlePath;
  }

  saveIssuerRootCert(issuer: string, certPem: string, fingerprintSha256 = ''): [string, string] {
    const dir = this.trustRootDir();
    const issuersDir = join(dir, 'issuers');
    mkdirSync(issuersDir, { recursive: true });
    const safeIssuer = (issuer || 'issuer').replace(/[^A-Za-z0-9_.-]+/g, '_').slice(0, 120);
    const certPath = join(issuersDir, `${safeIssuer}.root.crt`);
    const normalizedPem = certPem.trim() + '\n';
    writeFileSync(certPath, normalizedPem, 'utf-8');
    const bundlePath = this.trustRootBundlePath();
    const existingPems = new Map<string, string>();
    try {
      for (const pem of readFileSync(bundlePath, 'utf-8').split(/(?<=-----END CERTIFICATE-----)\s*/).map(s => s.trim()).filter(s => s.startsWith('-----BEGIN CERTIFICATE-----'))) {
        existingPems.set(this._pemFingerprint(pem), pem);
      }
    } catch { /* bundle 不存在时忽略 */ }
    const newFp = fingerprintSha256 ? fingerprintSha256.toLowerCase().replace(/^sha256:/, '') : this._pemFingerprint(normalizedPem);
    existingPems.set(newFp, normalizedPem);
    writeFileSync(bundlePath, Array.from(existingPems.values()).map(p => p.trim()).join('\n') + '\n', 'utf-8');
    return [certPath, bundlePath];
  }

  private _pemFingerprint(pem: string): string {
    try {
      const der = pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s/g, '');
      return crypto.createHash('sha256').update(Buffer.from(der, 'base64')).digest('hex');
    } catch {
      return crypto.createHash('sha256').update(pem, 'utf-8').digest('hex');
    }
  }

  // ── E2EE 存储 ─────────────────────────────────────────────

  async saveE2EEPrekey(aid: string, prekeyId: string, prekeyData: Record<string, unknown>, deviceId = ''): Promise<void> {
    const now = Date.now();
    const extra: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(prekeyData)) {
      if (!['private_key_pem', 'created_at', 'updated_at', 'expires_at'].includes(key)) extra[key] = value;
    }
    this._getDB(aid).getSqliteHandle().prepare(
      `INSERT INTO prekeys (prekey_id, device_id, private_key_enc, data, created_at, updated_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(prekey_id, device_id) DO UPDATE SET
         private_key_enc=excluded.private_key_enc, data=excluded.data,
         updated_at=excluded.updated_at, expires_at=excluded.expires_at`,
    ).run(prekeyId, String(deviceId ?? ''), String(prekeyData.private_key_pem ?? ''), JSON.stringify(extra),
      Number(prekeyData.created_at ?? now), now, prekeyData.expires_at == null ? null : Number(prekeyData.expires_at));
  }

  async loadE2EEPrekeys(aid: string, deviceId = ''): Promise<Record<string, Record<string, unknown>>> {
    const rows = this._getDB(aid).getSqliteHandle().prepare(
      `SELECT prekey_id, private_key_enc, data, created_at, updated_at, expires_at FROM prekeys WHERE device_id = ?`,
    ).all(String(deviceId ?? '')) as Array<Record<string, unknown>>;
    const result: Record<string, Record<string, unknown>> = {};
    for (const row of rows) {
      const id = String(row.prekey_id ?? '');
      if (!id) continue;
      const entry: Record<string, unknown> = { private_key_pem: String(row.private_key_enc ?? ''), created_at: row.created_at, updated_at: row.updated_at, expires_at: row.expires_at };
      try { const extra = JSON.parse(String(row.data ?? '{}')); if (extra && typeof extra === 'object' && !Array.isArray(extra)) Object.assign(entry, extra); } catch { /* ignore */ }
      result[id] = entry;
    }
    return result;
  }

  async listGroupSecretIds(aid: string): Promise<string[]> {
    const db = this._getDB(aid).getSqliteHandle();
    const ids = new Set<string>();
    for (const row of db.prepare('SELECT group_id FROM group_current').all() as Array<Record<string, unknown>>) ids.add(String(row.group_id ?? ''));
    for (const row of db.prepare('SELECT DISTINCT group_id FROM group_old_epochs').all() as Array<Record<string, unknown>>) ids.add(String(row.group_id ?? ''));
    return Array.from(ids).filter(Boolean).sort();
  }

  async loadGroupSecretEpoch(aid: string, groupId: string, epoch?: number | null): Promise<Record<string, unknown> | null> {
    const db = this._getDB(aid).getSqliteHandle();
    const current = db.prepare('SELECT epoch, secret_enc, data, updated_at FROM group_current WHERE group_id = ?').get(groupId) as Record<string, unknown> | undefined;
    if (current && (epoch == null || Number(current.epoch ?? 0) === Number(epoch))) {
      const entry: Record<string, unknown> = { group_id: groupId, epoch: current.epoch, secret: String(current.secret_enc ?? ''), updated_at: current.updated_at };
      try { const extra = JSON.parse(String(current.data ?? '{}')); if (extra && typeof extra === 'object' && !Array.isArray(extra)) Object.assign(entry, extra); } catch { /* ignore */ }
      return entry;
    }
    if (epoch == null) return null;
    const old = db.prepare('SELECT epoch, secret_enc, data, updated_at, expires_at FROM group_old_epochs WHERE group_id = ? AND epoch = ?').get(groupId, Number(epoch)) as Record<string, unknown> | undefined;
    if (!old) return null;
    const entry: Record<string, unknown> = { epoch: old.epoch, secret: String(old.secret_enc ?? ''), updated_at: old.updated_at };
    if (old.expires_at != null) entry.expires_at = old.expires_at;
    try { const extra = JSON.parse(String(old.data ?? '{}')); if (extra && typeof extra === 'object' && !Array.isArray(extra)) Object.assign(entry, extra); } catch { /* ignore */ }
    return entry;
  }

  async storeGroupSecretTransition(aid: string, groupId: string, opts: { epoch: number; secret: string; commitment: string; memberAids?: string[]; oldEpochRetentionMs?: number }): Promise<boolean> {
    const db = this._getDB(aid).getSqliteHandle();
    const now = Date.now();
    const epoch = Number(opts.epoch ?? 0);
    const current = db.prepare('SELECT epoch, secret_enc, data, updated_at FROM group_current WHERE group_id = ?').get(groupId) as Record<string, unknown> | undefined;
    if (current && Number(current.epoch ?? 0) > epoch) return false;
    if (current && Number(current.epoch ?? 0) !== epoch) {
      db.prepare(`INSERT INTO group_old_epochs (group_id, epoch, secret_enc, data, updated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(group_id, epoch) DO UPDATE SET secret_enc=excluded.secret_enc, data=excluded.data, updated_at=excluded.updated_at, expires_at=excluded.expires_at`
      ).run(groupId, Number(current.epoch ?? 0), String(current.secret_enc ?? ''), String(current.data ?? '{}'), Number(current.updated_at ?? now), Number(current.updated_at ?? now) + Number(opts.oldEpochRetentionMs ?? 0));
    }
    db.prepare(`INSERT INTO group_current (group_id, epoch, secret_enc, data, updated_at) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(group_id) DO UPDATE SET epoch=excluded.epoch, secret_enc=excluded.secret_enc, data=excluded.data, updated_at=excluded.updated_at`
    ).run(groupId, epoch, String(opts.secret ?? ''), JSON.stringify({ commitment: String(opts.commitment ?? ''), member_aids: Array.isArray(opts.memberAids) ? [...opts.memberAids].map(String).sort() : [] }), now);
    return true;
  }

  async saveE2EESession(aid: string, sessionId: string, data: Record<string, unknown>): Promise<void> {
    this._getDB(aid).getSqliteHandle().prepare(
      `INSERT INTO e2ee_sessions (session_id, data_enc, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(session_id) DO UPDATE SET data_enc=excluded.data_enc, updated_at=excluded.updated_at`,
    ).run(sessionId, JSON.stringify(data ?? {}), Date.now());
  }

  async loadE2EESessions(aid: string): Promise<Array<Record<string, unknown>>> {
    const rows = this._getDB(aid).getSqliteHandle().prepare('SELECT session_id, data_enc, updated_at FROM e2ee_sessions').all() as Array<Record<string, unknown>>;
    const result: Array<Record<string, unknown>> = [];
    for (const row of rows) {
      const sessionId = String(row.session_id ?? '');
      if (!sessionId) continue;
      try {
        const entry = JSON.parse(String(row.data_enc ?? '{}'));
        if (entry && typeof entry === 'object' && !Array.isArray(entry)) result.push({ ...entry, session_id: sessionId, updated_at: row.updated_at });
      } catch { /* ignore */ }
    }
    return result;
  }

  /** 获取指定 AID 的 V2KeyStore（共享同一 SQLite 连接）。 */
  getV2KeyStore(aid: string): V2KeyStore {
    return new V2KeyStore(this._getDB(aid).getSqliteHandle());
  }

  // ── 路径辅助 ─────────────────────────────────────────────

  private _certPath(aid: string): string {
    return join(this._aidsRoot, safeAid(aid), 'public', 'cert.pem');
  }

  private _certVersionPath(aid: string, fp: string): string {
    return join(this._aidsRoot, safeAid(aid), 'public', 'certs', `${fp.replace(/:/g, '_')}.pem`);
  }
}
