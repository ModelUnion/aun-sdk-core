/**
 * 基于文件的 SecretStore（AES-256-GCM 加密）
 *
 * 密钥派生：
 *   - 传入 encryptionSeed → 从 seed 字符串派生
 *   - 未传 → 从空字符串派生；旧 .seed 仅作为严格迁移/失败回退来源
 *
 * 与 Python SDK 的 FileSecretStore 完全对齐。
 */

import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  pbkdf2Sync,
  randomBytes,
} from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  chmodSync,
  unlinkSync,
  renameSync,
  readdirSync,
  statSync,
} from 'node:fs';
import { join } from 'node:path';

import type { SecretStore } from './index.js';
import type { SecretRecord } from '../types.js';
import type { ModuleLogger } from '../logger.js';

const _noopLogger: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };

function decodeSecretPart(value: string): Buffer {
  if (/^[0-9a-fA-F]+$/.test(value) && value.length % 2 === 0) {
    return Buffer.from(value, 'hex');
  }
  return Buffer.from(value, 'base64');
}

export class SeedMigrationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SeedMigrationError';
  }
}

export interface SeedChangeResult {
  migrated: number;
  skipped: number;
  errors: number;
  seedFilesProcessed: number;
  seedFilesRenamed: number;
  privateKeysVerified: number;
  privateKeysMigrated: number;
  activeSeed?: Buffer;
}

type PrivateKeyMigration = {
  aid: string;
  path: string;
  plaintext: Buffer;
};

function deriveMasterKey(seedBytes: Buffer): Buffer {
  return pbkdf2Sync(seedBytes, 'aun_file_secret_store_v1', 100_000, 32, 'sha256');
}

function tryDecryptWithKey(masterKey: Buffer, scope: string, name: string, record: SecretRecord): Buffer | null {
  if (record.scheme !== 'file_aes') return null;
  if (String(record.name ?? name) !== name) return null;
  try {
    const key = createHmac('sha256', masterKey).update(`aun:${scope}:${name}\x01`).digest();
    const decipher = createDecipheriv('aes-256-gcm', key, decodeSecretPart(String(record.nonce)));
    decipher.setAuthTag(decodeSecretPart(String(record.tag)));
    return Buffer.concat([decipher.update(decodeSecretPart(String(record.ciphertext))), decipher.final()]);
  } catch {
    return null;
  }
}

function encryptWithKey(masterKey: Buffer, scope: string, name: string, plaintext: Buffer): SecretRecord {
  const key = createHmac('sha256', masterKey).update(`aun:${scope}:${name}\x01`).digest();
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    scheme: 'file_aes',
    name,
    persisted: true,
    nonce: nonce.toString('base64'),
    ciphertext: encrypted.toString('base64'),
    tag: tag.toString('base64'),
  };
}

function renameSeedFile(seedPath: string): boolean {
  const ts = Math.floor(Date.now() / 1000);
  let target = `${seedPath}.migrated.${ts}`;
  for (let index = 1; existsSync(target); index += 1) {
    target = `${seedPath}.migrated.${ts}.${index}`;
  }
  try {
    renameSync(seedPath, target);
    return true;
  } catch {
    return false;
  }
}

function nextVersionedBackupPath(path: string): string {
  for (let i = 1; ; i++) {
    const candidate = `${path}.v${i}`;
    if (!existsSync(candidate)) return candidate;
  }
}

function writeKeyJsonAtomic(path: string, data: object): void {
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}-${randomBytes(4).toString('hex')}`;
  try {
    writeFileSync(tmp, JSON.stringify(data, null, 2), { encoding: 'utf-8', mode: 0o600 });
    try { renameSync(tmp, path); } catch {
      try { unlinkSync(path); } catch { /* ignore */ }
      renameSync(tmp, path);
    }
  } catch (exc) {
    try { unlinkSync(tmp); } catch { /* ignore */ }
    throw exc;
  }
}

function verifyPrivateKeys(root: string, oldMasterKey: Buffer): PrivateKeyMigration[] {
  const aidsRoot = join(root, 'AIDs');
  if (!existsSync(aidsRoot)) throw new SeedMigrationError('seed migration refused: AIDs directory not found');

  const migrations: PrivateKeyMigration[] = [];
  for (const entry of readdirSync(aidsRoot, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name.startsWith('_')) continue;
    const aid = entry.name;
    const keyPath = join(aidsRoot, aid, 'private', 'key.json');
    if (!existsSync(keyPath)) continue;
    let data: any;
    try {
      data = JSON.parse(readFileSync(keyPath, 'utf-8'));
    } catch (exc) {
      throw new SeedMigrationError(`seed migration refused: invalid key.json for ${aid}: ${exc instanceof Error ? exc.message : String(exc)}`);
    }
    const protection = data?.private_key_protection;
    if (!protection) {
      if (typeof data?.private_key_pem === 'string' && data.private_key_pem) {
        migrations.push({ aid, path: keyPath, plaintext: Buffer.from(data.private_key_pem, 'utf-8') });
      }
      continue;
    }
    if (protection.scheme !== 'file_aes') continue;
    const name = 'identity/private_key';
    if (String(protection.name ?? name) !== name) {
      throw new SeedMigrationError(`seed migration refused: unexpected private key record name for ${aid}`);
    }
    const plain = tryDecryptWithKey(oldMasterKey, aid, name, protection);
    if (!plain) {
      throw new SeedMigrationError(`seed migration refused: private key is not encrypted by old seed: aid=${aid}`);
    }
    migrations.push({ aid, path: keyPath, plaintext: plain });
  }

  if (migrations.length === 0) {
    throw new SeedMigrationError('seed migration refused: no encrypted private key verified with old seed');
  }
  return migrations;
}

function changeSeedBytes(
  root: string,
  oldSeedBytes: Buffer,
  newSeedBytes: Buffer,
  renameSeedPath?: string,
  logger: ModuleLogger = _noopLogger,
): SeedChangeResult {
  const oldMasterKey = deriveMasterKey(oldSeedBytes);
  const newMasterKey = deriveMasterKey(newSeedBytes);
  const migrations = verifyPrivateKeys(root, oldMasterKey);
  const result: SeedChangeResult = {
    migrated: 0,
    skipped: 0,
    errors: 0,
    seedFilesProcessed: renameSeedPath ? 1 : 0,
    seedFilesRenamed: 0,
    privateKeysVerified: migrations.length,
    privateKeysMigrated: 0,
    activeSeed: newSeedBytes,
  };

  if (oldMasterKey.equals(newMasterKey)) {
    if (renameSeedPath && renameSeedFile(renameSeedPath)) result.seedFilesRenamed = 1;
    return result;
  }

  for (const item of migrations) {
    const record = encryptWithKey(newMasterKey, item.aid, 'identity/private_key', item.plaintext);
    const verified = tryDecryptWithKey(newMasterKey, item.aid, 'identity/private_key', record);
    if (!verified || !verified.equals(item.plaintext)) {
      throw new SeedMigrationError(`new seed verification failed for private key: aid=${item.aid}`);
    }
    const data = JSON.parse(readFileSync(item.path, 'utf-8'));
    data.private_key_protection = record;
    delete data.private_key_pem;
    // 覆盖前先备份（.v1/.v2 递增）
    const bakPath = nextVersionedBackupPath(item.path);
    writeFileSync(bakPath, readFileSync(item.path));
    writeKeyJsonAtomic(item.path, data);
    result.migrated += 1;
    result.privateKeysMigrated += 1;
  }

  if (renameSeedPath && renameSeedFile(renameSeedPath)) result.seedFilesRenamed = 1;
  logger.info(`seed migration complete: migrated=${result.migrated} skipped=${result.skipped} private_keys=${result.privateKeysMigrated} renamed=${result.seedFilesRenamed}`);
  return result;
}

export class FileSecretStore implements SecretStore {
  private _root: string;
  private _masterKey: Buffer;
  private _logger: ModuleLogger;

  constructor(
    root: string,
    encryptionSeed?: string,
    sqliteBackup?: { backupSeed(seed: Buffer): void; restoreSeed(): Buffer | null },
    opts?: { logger?: ModuleLogger },
  ) {
    this._root = root;
    this._logger = opts?.logger ?? _noopLogger;
    mkdirSync(this._root, { recursive: true });

    // seed_password 必传（空字符串有效），不再 fallback 到 .seed 文件
    const seedPassword = encryptionSeed ?? '';
    const newSeedBytes = Buffer.from(seedPassword, 'utf-8');

    // PBKDF2 派生主密钥，与 Python SDK 参数完全一致
    this._masterKey = deriveMasterKey(newSeedBytes);

    // 自动迁移：检测旧 .seed 文件，把旧 key 加密的材料迁移到新 key
    const activeSeed = this._autoMigrateFromSeedFile(newSeedBytes);
    if (activeSeed) this._masterKey = deriveMasterKey(activeSeed);
  }

  static changeSeed(root: string, oldSeed: string, newSeed: string, opts?: { logger?: ModuleLogger }): SeedChangeResult {
    const oldSeedBytes = oldSeed === '.seed' ? readFileSync(join(root, '.seed')) : Buffer.from(oldSeed, 'utf-8');
    if (oldSeed === '.seed' && oldSeedBytes.length === 0) {
      throw new SeedMigrationError('seed migration refused: .seed is empty');
    }
    return changeSeedBytes(
      root,
      oldSeedBytes,
      Buffer.from(newSeed, 'utf-8'),
      oldSeed === '.seed' ? join(root, '.seed') : undefined,
      opts?.logger ?? _noopLogger,
    );
  }

  changeSeed(oldSeed: string, newSeed: string): SeedChangeResult {
    const result = FileSecretStore.changeSeed(this._root, oldSeed, newSeed, { logger: this._logger });
    this._masterKey = deriveMasterKey(Buffer.from(newSeed, 'utf-8'));
    return result;
  }

  protect(scope: string, name: string, plaintext: Buffer): SecretRecord {
    const key = this._deriveKey(scope, name);
    const nonce = randomBytes(12);

    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      scheme: 'file_aes',
      name,
      persisted: true,
      nonce: nonce.toString('base64'),
      ciphertext: encrypted.toString('base64'),
      tag: tag.toString('base64'),
    };
  }

  reveal(scope: string, name: string, record: SecretRecord): Buffer | null {
    if (record.scheme !== 'file_aes') return null;
    if (String(record.name ?? '') !== name) return null;

    const nonceB64 = String(record.nonce ?? '');
    const ctB64 = String(record.ciphertext ?? '');
    const tagB64 = String(record.tag ?? '');
    if (!nonceB64 || !ctB64 || !tagB64) return null;

    const decrypted = tryDecryptWithKey(this._masterKey, scope, name, record);
    if (decrypted) return decrypted;

    const migratedSeeds = this._loadMigratedSeedFiles();
    for (const item of migratedSeeds) {
      const legacy = tryDecryptWithKey(deriveMasterKey(item.seed), scope, name, record);
      if (legacy) {
        this._logger.warn(`field decrypted with migrated .seed fallback (scope=${scope}, name=${name}, seed_file=${item.name})`);
        return legacy;
      }
    }

    this._logger.error(`field decryption failed (scope=${scope}, name=${name}); tried current seed and ${migratedSeeds.length} migrated seed file(s)`);
    return null;
  }

  /** 使用 HMAC-SHA256 从主密钥派生子密钥 */
  private _deriveKey(scope: string, name: string): Buffer {
    return createHmac('sha256', this._masterKey)
      .update(`aun:${scope}:${name}\x01`)
      .digest();
  }

  /** 自动迁移：检测旧 .seed 文件并迁移加密材料到 seed_password 派生的新 master_key */
  private _autoMigrateFromSeedFile(newSeedBytes: Buffer): Buffer | null {
    const seedPath = join(this._root, '.seed');
    if (!existsSync(seedPath)) return null;

    const oldSeedBytes = readFileSync(seedPath);
    try {
      const result = changeSeedBytes(this._root, oldSeedBytes, newSeedBytes, seedPath, this._logger);
      return result.activeSeed ?? newSeedBytes;
    } catch (exc) {
      this._logger.warn(`seed migration failed; continuing with legacy .seed: ${exc instanceof Error ? exc.message : String(exc)}`);
      return oldSeedBytes;
    }
  }

  /**
   * 兼容半迁移状态：.seed 已被重命名为 .seed.migrated.*，但 key.json
   * 仍是旧 seed 加密。只作为解密兜底，不会主动创建新 .seed。
   */
  private _loadMigratedSeedFiles(): Array<{ name: string; seed: Buffer }> {
    try {
      return readdirSync(this._root, { withFileTypes: true })
        .filter((entry) => entry.isFile() && entry.name.startsWith('.seed.migrated.'))
        .map((entry) => {
          const path = join(this._root, entry.name);
          return { name: entry.name, path, mtimeMs: statSync(path).mtimeMs };
        })
        .sort((a, b) => b.mtimeMs - a.mtimeMs)
        .map((entry) => ({ name: entry.name, seed: readFileSync(entry.path) }))
        .filter((entry) => entry.seed.length > 0);
    } catch {
      return [];
    }
  }

  /** [已废弃] 仅保留供参考，不再被调用。 */
  private _loadOrCreateSeed(backup?: { backupSeed(seed: Buffer): void; restoreSeed(): Buffer | null }): Buffer {
    const seedPath = join(this._root, '.seed');
    let source = '';

    // 1. 先读文件
    if (existsSync(seedPath)) {
      const seed = readFileSync(seedPath);
      source = 'file';
      // 双写：确保 SQLite 也有
      if (backup) backup.backupSeed(seed);
      return seed;
    }

    // 2. 文件不存在 → 读 SQLite
    if (backup) {
      const restored = backup.restoreSeed();
      if (restored && restored.length > 0) {
        source = 'sqlite';
        this._logger.info('restoring .seed file from SQLite');
        writeFileSync(seedPath, restored);
        if (process.platform !== 'win32') {
          try { chmodSync(seedPath, 0o600); } catch { /* ignore */ }
        }
        return restored;
      }
    }

    // 3. 都没有 → 生成新 seed
    const seed = randomBytes(32);
    writeFileSync(seedPath, seed);
    if (process.platform !== 'win32') {
      try { chmodSync(seedPath, 0o600); } catch { /* ignore */ }
    }
    // 双写：备份到 SQLite
    if (backup) backup.backupSeed(seed);
    return seed;
  }
}
