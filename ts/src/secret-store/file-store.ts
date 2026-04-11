/**
 * 基于文件的 SecretStore（AES-256-GCM 加密）
 *
 * 密钥派生：
 *   - 传入 encryptionSeed → 从 seed 字符串派生
 *   - 未传 → 从 {root}/.seed 文件派生（首次自动生成）
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
} from 'node:fs';
import { join } from 'node:path';

import type { SecretStore } from './index.js';
import type { SecretRecord } from '../types.js';

export class FileSecretStore implements SecretStore {
  private _root: string;
  private _masterKey: Buffer;

  constructor(root: string, encryptionSeed?: string, sqliteBackup?: { backupSeed(seed: Buffer): void; restoreSeed(): Buffer | null }) {
    this._root = root;
    mkdirSync(this._root, { recursive: true });

    let seedBytes: Buffer;
    if (encryptionSeed) {
      seedBytes = Buffer.from(encryptionSeed, 'utf-8');
    } else {
      seedBytes = this._loadOrCreateSeed(sqliteBackup);
    }

    // PBKDF2 派生主密钥，与 Python SDK 参数完全一致
    this._masterKey = pbkdf2Sync(
      seedBytes,
      'aun_file_secret_store_v1',
      100_000,
      32,
      'sha256',
    );
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

    const key = this._deriveKey(scope, name);

    try {
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(nonceB64, 'base64'));
      decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(ctB64, 'base64')),
        decipher.final(),
      ]);
      return decrypted;
    } catch {
      return null;
    }
  }

  /** 使用 HMAC-SHA256 从主密钥派生子密钥 */
  private _deriveKey(scope: string, name: string): Buffer {
    return createHmac('sha256', this._masterKey)
      .update(`aun:${scope}:${name}\x01`)
      .digest();
  }

  /** 三级恢复：文件 → SQLite → 新建，双写确保一致 */
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
        console.log('从 SQLite 恢复 .seed 文件');
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
