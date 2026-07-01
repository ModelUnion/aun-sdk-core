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
