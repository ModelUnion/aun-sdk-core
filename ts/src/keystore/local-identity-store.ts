/**
 * LocalIdentityStore — 基于文件系统 + SQLite 的 KeyStore 实现（含私钥操作）。
 * AIDStore / RegisterFlow 持有此类型。
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
import { getDeviceId } from '../config.js';
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
    try { unlinkSync(targetPath); } catch (unlinkErr) {
      if ((unlinkErr as { code?: string }).code !== 'ENOENT') {
        throw new Error(`replace target cleanup failed: ${unlinkErr instanceof Error ? unlinkErr.message : String(unlinkErr)}`);
      }
    }
    renameSync(tmpPath, targetPath);
  }
}

function safeAid(aid: string): string {
  return aid.replace(/[/\\:]/g, '_');
}

export class LocalIdentityStore implements KeyStore {
  private static _aidLocks = new Map<string, { count: number; lockDir: string }>();
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

  private _withAidLock<T>(aid: string, fn: () => T): T {
    const key = safeAid(aid);
    const held = LocalIdentityStore._aidLocks.get(key);
    if (held) {
      held.count++;
      try {
        return fn();
      } finally {
        held.count--;
      }
    }
    const lockDir = this._acquireAidLock(key);
    LocalIdentityStore._aidLocks.set(key, { count: 1, lockDir });
    try {
      return fn();
    } finally {
      const current = LocalIdentityStore._aidLocks.get(key);
      if (current) {
        current.count--;
        if (current.count <= 0) {
          LocalIdentityStore._aidLocks.delete(key);
          this._releaseAidLock(current.lockDir);
        }
      }
    }
  }

  private _acquireAidLock(key: string): string {
    const root = join(this._root, 'locks', 'identity');
    mkdirSync(root, { recursive: true });
    const lockDir = join(root, `${key}.lock`);
    const deadline = Date.now() + 2000;
    while (true) {
      try {
        mkdirSync(lockDir);
        writeFileSync(join(lockDir, 'owner.json'), JSON.stringify({ pid: process.pid, ts: Date.now() }));
        return lockDir;
      } catch (exc) {
        const code = (exc as { code?: string }).code;
        if (code !== 'EEXIST') throw exc;
        try {
          if (Date.now() - statSync(lockDir).mtimeMs > 30_000) {
            fsRmSync(lockDir, { recursive: true, force: true });
            continue;
          }
        } catch {
          continue;
        }
        if (Date.now() >= deadline) {
          throw new Error(`identity store lock timeout: ${key}`);
        }
        LocalIdentityStore._sleepSync(10);
      }
    }
  }

  private _releaseAidLock(lockDir: string): void {
    try {
      fsRmSync(lockDir, { recursive: true, force: true });
    } catch (exc) {
      this._logger.warn(`identity lock release failed: ${exc instanceof Error ? exc.message : String(exc)}`);
    }
  }

  private static _sleepSync(ms: number): void {
    try {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
    } catch {
      const end = Date.now() + ms;
      while (Date.now() < end) { /* sync fallback */ }
    }
  }

  // ── KeyPair ──────────────────────────────────────────────

  loadKeyPair(aid: string): KeyPairRecord | null {
    return this._withAidLock(aid, () => this._loadKeyPairUnlocked(aid));
  }

  private _loadKeyPairUnlocked(aid: string): KeyPairRecord | null {
    const path = this._keyPairPath(aid);
    if (!existsSync(path)) return null;
    let raw: JsonObject;
    try {
      raw = JSON.parse(readFileSync(path, 'utf-8')) as JsonObject;
    } catch {
      this._logger.warn('key.json read or parse failed, treating as non-existent');
      return null;
    }
    return this._restoreKeyPair(aid, raw, path);
  }

  saveKeyPair(aid: string, keyPair: KeyPairRecord): void {
    this._withAidLock(aid, () => {
      this._saveKeyPairAtPath(aid, this._keyPairPath(aid), keyPair);
    });
  }

  private _saveKeyPairAtPath(aid: string, path: string, keyPair: KeyPairRecord): void {
    mkdirSync(dirname(path), { recursive: true });
    const protected_ = JSON.parse(JSON.stringify(keyPair)) as KeyPairRecord;
    const pem = protected_.private_key_pem;
    if (typeof pem === 'string' && pem) {
      delete protected_.private_key_pem;
      const rec = this._secretStore.protect(safeAid(aid), 'identity/private_key', Buffer.from(pem, 'utf-8'));
      protected_.private_key_protection = rec;
    }
    // 覆盖已有 key.json 前备份（.v1/.v2 递增）
    if (existsSync(path)) {
      let bakIdx = 1;
      while (existsSync(`${path}.v${bakIdx}`)) bakIdx++;
      try { writeFileSync(`${path}.v${bakIdx}`, readFileSync(path)); } catch { /* non-fatal */ }
    }
    const tmpPath = `${path}.tmp-${process.pid}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    writeFileSync(tmpPath, JSON.stringify(protected_, null, 2), { mode: 0o600 });
    secureFilePermissions(tmpPath);
    try {
      replaceFileSync(tmpPath, path);
    } catch (exc) {
      try { unlinkSync(tmpPath); } catch { /* ignore */ }
      throw exc;
    }
    secureFilePermissions(path);
  }

  private _restoreKeyPair(aid: string, kp: JsonObject, persistPath?: string): KeyPairRecord {
    const out = JSON.parse(JSON.stringify(kp)) as KeyPairRecord;
    const rec = (out as JsonObject).private_key_protection;
    if (isJsonObject(rec)) {
      const plain = this._secretStore.reveal(safeAid(aid), 'identity/private_key', rec as any);
      if (!plain) throw new Error(`private key decrypt failed for aid ${aid}: seed_password mismatch or key.json corrupted`);
      out.private_key_pem = plain.toString('utf-8');
      return out;
    }
    if (persistPath && typeof out.private_key_pem === 'string' && out.private_key_pem) {
      this._saveKeyPairAtPath(aid, persistPath, out);
    }
    return out;
  }

  // ── Cert ─────────────────────────────────────────────────

  loadCert(aid: string, certFingerprint?: string): string | null {
    try {
      const norm = this._normalizeCertFingerprint(certFingerprint);
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
    this._withAidLock(aid, () => this._saveCertUnlocked(aid, certPem, certFingerprint, opts));
  }

  private _saveCertUnlocked(aid: string, certPem: string, certFingerprint?: string, opts?: { makeActive?: boolean }): void {
    const norm = this._normalizeCertFingerprint(certFingerprint);
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

  private _normalizeCertFingerprint(fp?: string): string {
    const v = String(fp ?? '').trim().toLowerCase();
    if (!v.startsWith('sha256:') || v.length !== 71) return '';
    if (/[^0-9a-f]/.test(v.slice(7))) return '';
    return v;
  }

  // ── Identity ─────────────────────────────────────────────

  loadIdentity(aid: string): IdentityRecord | null {
    return this._withAidLock(aid, () => this._loadIdentityUnlocked(aid));
  }

  private _loadIdentityUnlocked(aid: string): IdentityRecord | null {
    const identityDir = join(this._aidsRoot, safeAid(aid));
    if (!existsSync(identityDir)) return null;

    const kp = this._loadKeyPairUnlocked(aid);
    const cert = this.loadCert(aid);
    const db = this._getDB(aid);
    const kv = db.getAllMetadata();
    const hasMeta = Object.keys(kv).length > 0;
    if (!kp && !cert && !hasMeta) return null;

    const identity: IdentityRecord = {};
    for (const [k, v] of Object.entries(kv)) {
      try { identity[k] = JSON.parse(v); } catch { identity[k] = v; }
    }
    if (kp) Object.assign(identity, kp);
    if (cert) {
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
    this._withAidLock(aid, () => {
      const kp: KeyPairRecord = {};
      for (const k of ['private_key_pem', 'public_key_der_b64', 'curve'] as const) {
        if (k in identity) kp[k] = identity[k] as string;
      }
      if (Object.keys(kp).length > 0) this._saveKeyPairAtPath(aid, this._keyPairPath(aid), kp);
      if (typeof identity.cert === 'string' && identity.cert) this._saveCertUnlocked(aid, identity.cert);
      const db = this._getDB(aid);
      const skip = new Set(['private_key_pem', 'public_key_der_b64', 'curve', 'cert']);
      for (const [k, v] of Object.entries(identity)) {
        if (skip.has(k)) continue;
        db.setMetadata(k, JSON.stringify(v));
      }
    });
  }

  loadAnyIdentity(): IdentityRecord | null {
    if (!existsSync(this._aidsRoot)) return null;
    for (const entry of readdirSync(this._aidsRoot, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name.startsWith('_')) continue;
      const identity = this.loadIdentity(entry.name);
      if (identity) return identity;
    }
    return null;
  }

  listIdentities(): string[] {
    if (!existsSync(this._aidsRoot)) return [];
    const aids: string[] = [];
    for (const entry of readdirSync(this._aidsRoot, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name.startsWith('_')) continue;
      aids.push(entry.name);
    }
    return aids;
  }

  loadMetadata(aid: string): Record<string, unknown> | null {
    try {
      const dbPath = join(this._aidsRoot, safeAid(aid), 'aun.db');
      if (!existsSync(dbPath)) return null;
      const kv = this._getDB(aid).getAllMetadata();
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

  // ── Instance State ───────────────────────────────────────

  loadInstanceState(aid: string, deviceId: string, slotId = ''): MetadataRecord | null {
    return this._getDB(aid).loadInstanceState(deviceId, slotId) as MetadataRecord | null;
  }

  saveInstanceState(aid: string, deviceId: string, slotId: string, state: MetadataRecord): void {
    this._getDB(aid).saveInstanceState(deviceId, slotId, state);
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
      writeFileSync(join(dir, `${certId.replace(/[^A-Za-z0-9_.-]+/g, '_').slice(0, 120)}.crt`), item.cert_pem, 'utf-8');
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
    const certPath = join(issuersDir, `${(issuer || 'issuer').replace(/[^A-Za-z0-9_.-]+/g, '_').slice(0, 120)}.root.crt`);
    const normalizedPem = certPem.trim() + '\n';
    writeFileSync(certPath, normalizedPem, 'utf-8');
    const bundlePath = this.trustRootBundlePath();
    const existingPems = new Map<string, string>();
    try {
      for (const pem of readFileSync(bundlePath, 'utf-8').split(/(?<=-----END CERTIFICATE-----)\s*/).map(s => s.trim()).filter(s => s.startsWith('-----BEGIN CERTIFICATE-----'))) {
        existingPems.set(this._pemFingerprint(pem), pem);
      }
    } catch { /* ignore */ }
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

  // ── Pending 身份管理 ─────────────────────────────────────

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
      try { items.push({ path, mtimeMs: statSync(path).mtimeMs }); } catch { /* ignore */ }
    }
    return items.sort((a, b) => b.mtimeMs - a.mtimeMs).map(item => item.path);
  }

  savePendingKeyPair(pendingDir: string, aid: string, keyPair: KeyPairRecord): void {
    this._saveKeyPairAtPath(aid, join(pendingDir, 'private', 'key.json'), keyPair);
  }

  loadPendingKeyPair(pendingDir: string, aid: string): KeyPairRecord | null {
    const keyPath = join(pendingDir, 'private', 'key.json');
    if (!existsSync(keyPath)) return null;
    let raw: JsonObject;
    try { raw = JSON.parse(readFileSync(keyPath, 'utf-8')) as JsonObject; } catch { return null; }
    return this._restoreKeyPair(aid, raw, keyPath);
  }

  savePendingCert(pendingDir: string, certPem: string): void {
    const certPath = join(pendingDir, 'public', 'cert.pem');
    mkdirSync(dirname(certPath), { recursive: true });
    writeFileSync(certPath, certPem, { encoding: 'utf-8', mode: 0o600 });
  }

  promotePendingIdentity(pendingDir: string, aid: string): string {
    this._ensurePendingKeyPairProtected(pendingDir, aid);
    const target = join(this._aidsRoot, safeAid(aid));
    if (existsSync(target)) throw new Error(`promotePendingIdentity: target exists: ${target}`);
    const safe = safeAid(aid);
    const db = this._aidDBs.get(safe);
    if (db) { try { db.close(); } catch { /* ignore */ } this._aidDBs.delete(safe); }
    mkdirSync(this._aidsRoot, { recursive: true });
    fsRenameSync(pendingDir, target);
    return target;
  }

  discardPendingIdentity(pendingDir: string): void {
    fsRmSync(pendingDir, { recursive: true, force: true });
  }

  cleanupPendingDirs(maxAgeMs = 600_000): number {
    const root = this._pendingRoot();
    if (!existsSync(root)) return 0;
    let removed = 0;
    const now = Date.now();
    try {
      for (const entry of readdirSync(root, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        const path = join(root, entry.name);
        try {
          if (now - statSync(path).mtimeMs < maxAgeMs) continue;
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

  private _ensurePendingKeyPairProtected(pendingDir: string, aid: string): void {
    const keyPath = join(pendingDir, 'private', 'key.json');
    if (!existsSync(keyPath)) throw new Error(`pending identity missing key pair for ${aid}`);
    const raw = JSON.parse(readFileSync(keyPath, 'utf-8')) as JsonObject;
    if (typeof raw.private_key_pem === 'string' && raw.private_key_pem) throw new Error(`pending identity private key is plaintext for ${aid}`);
    if (!isJsonObject(raw.private_key_protection)) throw new Error(`pending identity private key is not encrypted for ${aid}`);
  }

  private _pendingRoot(): string {
    return join(this._aidsRoot, '_pending');
  }

  // ── Pending Group Bind（幂等暂存槽位）────────────────────

  private _pendingBindsRoot(): string {
    return join(this._aidsRoot, '_pending_binds');
  }

  private _pendingBindPath(groupId: string): string {
    return join(this._pendingBindsRoot(), `${safeAid(groupId.trim())}.json`);
  }

  savePendingGroupBind(groupId: string, keyPair: KeyPairRecord): void {
    this._withAidLock(`group-bind:${groupId}`, () => this._savePendingGroupBindUnlocked(groupId, keyPair));
  }

  private _savePendingGroupBindUnlocked(groupId: string, keyPair: KeyPairRecord): void {
    const gid = groupId.trim();
    if (!gid) throw new Error('savePendingGroupBind requires non-empty group_id');

    const privateKeyPem = String(keyPair.private_key_pem || '').trim();
    const publicKeyDerB64 = String(keyPair.public_key_der_b64 || '').trim();
    if (!privateKeyPem || !publicKeyDerB64) {
      throw new Error('savePendingGroupBind requires private_key_pem and public_key_der_b64');
    }
    const curve = String(keyPair.curve || 'P-256').trim() || 'P-256';

    const protectedKey = this._secretStore.protect(
      safeAid(gid),
      'pending_bind/private_key',
      Buffer.from(privateKeyPem, 'utf-8'),
    );

    const record: JsonObject = {
      public_key_der_b64: publicKeyDerB64,
      curve,
      private_key_protection: protectedKey,
    };

    const path = this._pendingBindPath(gid);
    const dir = dirname(path);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });

    const tmpPath = `${path}.tmp.${process.pid}.${Date.now()}`;
    writeFileSync(tmpPath, JSON.stringify(record, null, 2), { encoding: 'utf-8', mode: 0o600 });
    replaceFileSync(tmpPath, path);
  }

  loadPendingGroupBind(groupId: string): KeyPairRecord | null {
    return this._withAidLock(`group-bind:${groupId}`, () => this._loadPendingGroupBindUnlocked(groupId));
  }

  private _loadPendingGroupBindUnlocked(groupId: string): KeyPairRecord | null {
    const gid = groupId.trim();
    if (!gid) return null;

    const path = this._pendingBindPath(gid);
    if (!existsSync(path)) return null;

    try {
      const data = JSON.parse(readFileSync(path, 'utf-8')) as JsonObject;
      const protection = data.private_key_protection;
      if (!isJsonObject(protection)) {
        this._logger.warn(`loadPendingGroupBind: invalid private_key_protection for ${gid}`);
        return null;
      }

      const privateKeyBytes = this._secretStore.reveal(
        safeAid(gid),
        'pending_bind/private_key',
        protection,
      );
      if (!privateKeyBytes) return null;

      return {
        public_key_der_b64: String(data.public_key_der_b64 || ''),
        private_key_pem: privateKeyBytes.toString('utf-8'),
        curve: String(data.curve || 'P-256'),
      };
    } catch (e) {
      this._logger.warn(`loadPendingGroupBind failed for ${gid}: ${e instanceof Error ? e.message : String(e)}`);
      return null;
    }
  }

  clearPendingGroupBind(groupId: string): void {
    this._withAidLock(`group-bind:${groupId}`, () => this._clearPendingGroupBindUnlocked(groupId));
  }

  private _clearPendingGroupBindUnlocked(groupId: string): void {
    const gid = groupId.trim();
    if (!gid) return;
    const path = this._pendingBindPath(gid);
    try {
      unlinkSync(path);
    } catch (e) {
      if ((e as { code?: string }).code !== 'ENOENT') {
        this._logger.warn(`clearPendingGroupBind failed for ${gid}: ${e instanceof Error ? e.message : String(e)}`);
      }
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
