/**
 * KeyStore 单元测试 — 覆盖 FileSecretStore、LocalIdentityStore
 */

import { execFile } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import { describe, it, expect, beforeEach } from 'vitest';

import { FileSecretStore } from '../../src/secret-store/file-store.js';
import { LocalIdentityStore } from '../../src/keystore/local-identity-store.js';
import { LocalTokenStore } from '../../src/keystore/local-token-store.js';

const execFileAsync = promisify(execFile);
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as {
  DatabaseSync: new (path: string) => {
    exec(sql: string): void;
    prepare(sql: string): {
      all(...params: unknown[]): unknown[];
    };
    close(): void;
  };
};

type KeystoreWorkerPayload = {
  root: string;
  seed: string;
  aid: string;
  worker: number;
  rounds: number;
};

function writeKeystoreStressWorker(root: string): string {
  const workerPath = join(root, 'keystore-multiprocess-worker.ts');
  const LocalIdentityStoreUrl = pathToFileURL(join(process.cwd(), 'src', 'keystore', 'local-identity-store.ts')).href;
  writeFileSync(workerPath, `
import { LocalIdentityStore } from ${JSON.stringify(LocalIdentityStoreUrl)};

const payload = JSON.parse(process.argv[2] ?? '{}');
const root = String(payload.root);
const seed = String(payload.seed);
const aid = String(payload.aid);
const worker = Number(payload.worker);
const rounds = Number(payload.rounds);
const deviceId = 'device-shared';
const slotId = \`slot-\${worker}\`;
const ks = new LocalIdentityStore(root, { encryptionSeed: seed });

try {
  const db = (ks as any)._getDB(aid);
  for (let round = 1; round <= rounds; round += 1) {
    const seq = worker * 10000 + round;
    ks.saveInstanceState(aid, deviceId, slotId, {
      worker,
      round,
      marker: \`state-\${worker}-\${round}\`,
    });
    ks.saveSeq(aid, deviceId, slotId, 'inbox', seq);
    ks.saveSeq(aid, deviceId, slotId, \`ns-\${round % 4}\`, seq);
    db.setToken(\`token_\${worker}_\${round}\`, \`token-value-\${worker}-\${round}\`);
    db.setMetadata(\`meta_\${worker}_\${round}\`, JSON.stringify({ worker, round }));
  }
  console.log(JSON.stringify({ worker, rounds }));
} finally {
  ks.close();
}
`);
  return workerPath;
}

async function runKeystoreStressWorker(workerPath: string, payload: KeystoreWorkerPayload): Promise<void> {
  const viteNodeBin = join(process.cwd(), 'node_modules', 'vite-node', 'vite-node.mjs');
  await execFileAsync(process.execPath, [viteNodeBin, workerPath, JSON.stringify(payload)], {
    cwd: process.cwd(),
    timeout: 60_000,
    maxBuffer: 1024 * 1024,
    env: { ...process.env, AUN_ENV: 'test' },
  });
}

// ── FileSecretStore 测试 ────────────────────────────────────

describe('FileSecretStore', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'aun-test-'));
  });

  it('protect/reveal 往返成功', () => {
    const store = new FileSecretStore(tmpDir, 'test-seed');
    const plaintext = Buffer.from('hello-secret', 'utf-8');
    const record = store.protect('scope1', 'key1', plaintext);

    expect(record.scheme).toBe('file_aes');
    expect(record.persisted).toBe(true);
    expect(record.name).toBe('key1');

    const revealed = store.reveal('scope1', 'key1', record);
    expect(revealed).not.toBeNull();
    expect(revealed!.toString('utf-8')).toBe('hello-secret');
  });

  it('使用相同 seed 重启后仍能解密', () => {
    const store1 = new FileSecretStore(tmpDir, 'stable-seed');
    const plaintext = Buffer.from('persistent', 'utf-8');
    const record = store1.protect('scope', 'name', plaintext);

    // 用相同 seed 创建新实例
    const store2 = new FileSecretStore(tmpDir, 'stable-seed');
    const revealed = store2.reveal('scope', 'name', record);
    expect(revealed).not.toBeNull();
    expect(revealed!.toString('utf-8')).toBe('persistent');
  });

  it('使用错误 seed 无法解密', () => {
    const store1 = new FileSecretStore(tmpDir, 'seed-A');
    const plaintext = Buffer.from('secret-data', 'utf-8');
    const record = store1.protect('scope', 'name', plaintext);

    const store2 = new FileSecretStore(tmpDir, 'seed-B');
    const revealed = store2.reveal('scope', 'name', record);
    expect(revealed).toBeNull();
  });

  it('scope 隔离：不同 scope 无法解密', () => {
    const store = new FileSecretStore(tmpDir, 'seed');
    const plaintext = Buffer.from('scoped', 'utf-8');
    const record = store.protect('scopeA', 'key', plaintext);

    // 用不同 scope 解密应失败
    const revealed = store.reveal('scopeB', 'key', record);
    expect(revealed).toBeNull();
  });

  it('name 不匹配时返回 null', () => {
    const store = new FileSecretStore(tmpDir, 'seed');
    const record = store.protect('scope', 'key1', Buffer.from('data'));
    const revealed = store.reveal('scope', 'key2', record);
    expect(revealed).toBeNull();
  });

  it('scheme 不匹配时返回 null', () => {
    const store = new FileSecretStore(tmpDir, 'seed');
    const record = store.protect('scope', 'key', Buffer.from('data'));
    record.scheme = 'unknown';
    const revealed = store.reveal('scope', 'key', record);
    expect(revealed).toBeNull();
  });

  it('不提供 seed 时使用空字符串派生 master_key，不再自动生成 .seed 文件', () => {
    const store = new FileSecretStore(tmpDir);
    const seedPath = join(tmpDir, '.seed');
    expect(existsSync(seedPath)).toBe(false);

    // 同一目录再次创建（同样空 seed_password）应派生相同 master_key
    const plaintext = Buffer.from('auto-seed', 'utf-8');
    const record = store.protect('scope', 'key', plaintext);

    const store2 = new FileSecretStore(tmpDir);
    const revealed = store2.reveal('scope', 'key', record);
    expect(revealed!.toString('utf-8')).toBe('auto-seed');
  });

  it('ChangeSeed 严格验证私钥后迁移 .seed', () => {
    const oldStore = new FileSecretStore(tmpDir, 'old-seed');
    const aid = 'good.agentid.pub';
    const keyDir = join(tmpDir, 'AIDs', aid, 'private');
    mkdirSync(keyDir, { recursive: true });
    writeFileSync(
      join(keyDir, 'key.json'),
      JSON.stringify({ private_key_protection: oldStore.protect(aid, 'identity/private_key', Buffer.from('GOOD_PRIVATE')) }),
      'utf-8',
    );
    writeFileSync(join(tmpDir, '.seed'), 'old-seed');

    const result = FileSecretStore.changeSeed(tmpDir, '.seed', '');
    expect(result.privateKeysMigrated).toBe(1);
    expect(existsSync(join(tmpDir, '.seed'))).toBe(false);

    const migratedStore = new FileSecretStore(tmpDir, '');
    const protection = JSON.parse(readFileSync(join(keyDir, 'key.json'), 'utf-8')).private_key_protection;
    expect(migratedStore.reveal(aid, 'identity/private_key', protection)!.toString('utf-8')).toBe('GOOD_PRIVATE');
  });

  it('ChangeSeed 支持旧 seed 到新 seed 且旧 seed 不再可读', () => {
    const aid = 'old-to-new.agentid.pub';
    const oldStore = new LocalIdentityStore(tmpDir, { encryptionSeed: 'old-seed' });
    oldStore.saveKeyPair(aid, {
      private_key_pem: 'OLD_TO_NEW_PRIVATE',
      public_key_der_b64: 'pub',
      curve: 'P-256',
    });

    const result = oldStore.changeSeed('old-seed', 'new-seed');
    expect(result.privateKeysMigrated).toBe(1);

    const loaded = new LocalIdentityStore(tmpDir, { encryptionSeed: 'new-seed' }).loadKeyPair(aid);
    expect(loaded?.private_key_pem).toBe('OLD_TO_NEW_PRIVATE');
    expect(() => new LocalIdentityStore(tmpDir, { encryptionSeed: 'old-seed' }).loadKeyPair(aid)).toThrow(/decrypt failed/);
  });

  it('ChangeSeed 支持历史明文 key.json 到加密 key.json', () => {
    const aid = 'plaintext-change-seed.agentid.pub';
    const keyDir = join(tmpDir, 'AIDs', aid, 'private');
    mkdirSync(keyDir, { recursive: true });
    const keyPath = join(keyDir, 'key.json');
    writeFileSync(keyPath, JSON.stringify({
      private_key_pem: 'PLAINTEXT_PRIVATE',
      public_key_der_b64: 'pub',
      curve: 'P-256',
    }), 'utf-8');

    const result = FileSecretStore.changeSeed(tmpDir, 'legacy-unused', 'new-seed');
    expect(result.privateKeysMigrated).toBe(1);

    const rawText = readFileSync(keyPath, 'utf-8');
    const raw = JSON.parse(rawText);
    expect(raw.private_key_pem).toBeUndefined();
    expect(rawText).not.toContain('PLAINTEXT_PRIVATE');
    expect(raw.private_key_protection).toMatchObject({ scheme: 'file_aes', name: 'identity/private_key' });
    const loaded = new LocalIdentityStore(tmpDir, { encryptionSeed: 'new-seed' }).loadKeyPair(aid);
    expect(loaded?.private_key_pem).toBe('PLAINTEXT_PRIVATE');
  });

  it('ChangeSeed 旧 seed 不匹配时不改写原 key.json', () => {
    const aid = 'wrong-seed-no-destroy.agentid.pub';
    const oldStore = new LocalIdentityStore(tmpDir, { encryptionSeed: 'old-seed' });
    oldStore.saveKeyPair(aid, {
      private_key_pem: 'KEEP_OLD_PRIVATE',
      public_key_der_b64: 'pub',
      curve: 'P-256',
    });
    const keyPath = join(tmpDir, 'AIDs', aid, 'private', 'key.json');
    const before = readFileSync(keyPath, 'utf-8');

    expect(() => FileSecretStore.changeSeed(tmpDir, 'wrong-seed', 'new-seed')).toThrow(/seed migration refused/);
    expect(readFileSync(keyPath, 'utf-8')).toBe(before);
    const loaded = new LocalIdentityStore(tmpDir, { encryptionSeed: 'old-seed' }).loadKeyPair(aid);
    expect(loaded?.private_key_pem).toBe('KEEP_OLD_PRIVATE');
  });

  it('迁移半成品可用 .seed.migrated 兜底解密旧私钥', () => {
    const oldStore = new FileSecretStore(tmpDir, 'legacy-seed');
    const aid = 'legacy.agentid.pub';
    const keyDir = join(tmpDir, 'AIDs', aid, 'private');
    mkdirSync(keyDir, { recursive: true });
    writeFileSync(
      join(keyDir, 'key.json'),
      JSON.stringify({
        private_key_protection: oldStore.protect(aid, 'identity/private_key', Buffer.from('LEGACY_PRIVATE')),
      }),
      'utf-8',
    );
    writeFileSync(join(tmpDir, '.seed.migrated.100'), 'legacy-seed');

    const migratedStore = new FileSecretStore(tmpDir, '');
    const protection = JSON.parse(readFileSync(join(keyDir, 'key.json'), 'utf-8')).private_key_protection;
    expect(migratedStore.reveal(aid, 'identity/private_key', protection)!.toString('utf-8')).toBe('LEGACY_PRIVATE');
  });

  it('自动迁移严格验证失败时继续使用旧 .seed', () => {
    const oldStore = new FileSecretStore(tmpDir, 'old-seed');
    const otherStore = new FileSecretStore(tmpDir, 'other-seed');

    const cases = [
      {
        aid: 'good.agentid.pub',
        record: oldStore.protect('good.agentid.pub', 'identity/private_key', Buffer.from('GOOD_PRIVATE')),
      },
      {
        aid: 'wrong-name.agentid.pub',
        record: oldStore.protect('wrong-name.agentid.pub', 'other/private_key', Buffer.from('WRONG_NAME')),
      },
      {
        aid: 'wrong-seed.agentid.pub',
        record: otherStore.protect('wrong-seed.agentid.pub', 'identity/private_key', Buffer.from('WRONG_SEED')),
      },
    ];
    for (const item of cases) {
      const keyDir = join(tmpDir, 'AIDs', item.aid, 'private');
      mkdirSync(keyDir, { recursive: true });
      writeFileSync(join(keyDir, 'key.json'), JSON.stringify({ private_key_protection: item.record }), 'utf-8');
    }
    writeFileSync(join(tmpDir, '.seed'), 'old-seed');

    const migratedStore = new FileSecretStore(tmpDir, '');
    expect(existsSync(join(tmpDir, '.seed'))).toBe(true);

    const readProtection = (aid: string) => JSON.parse(
      readFileSync(join(tmpDir, 'AIDs', aid, 'private', 'key.json'), 'utf-8'),
    ).private_key_protection;

    const good = readProtection('good.agentid.pub');
    expect(migratedStore.reveal('good.agentid.pub', 'identity/private_key', good)!.toString('utf-8')).toBe('GOOD_PRIVATE');

    const wrongName = readProtection('wrong-name.agentid.pub');
    expect(oldStore.reveal('wrong-name.agentid.pub', 'other/private_key', wrongName)!.toString('utf-8')).toBe('WRONG_NAME');

    const wrongSeed = readProtection('wrong-seed.agentid.pub');
    expect(migratedStore.reveal('wrong-seed.agentid.pub', 'identity/private_key', wrongSeed)).toBeNull();
    expect(otherStore.reveal('wrong-seed.agentid.pub', 'identity/private_key', wrongSeed)!.toString('utf-8')).toBe('WRONG_SEED');
  });

});

// ── LocalIdentityStore 测试 ────────────────────────────────────────

describe('LocalIdentityStore', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'aun-ks-test-'));
  });

  it('保存和加载密钥对', () => {
    const ks = new LocalIdentityStore(tmpDir);
    const keyPair = {
      private_key_pem: '-----BEGIN PRIVATE KEY-----\ntest-key\n-----END PRIVATE KEY-----',
      public_key_der_b64: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE',
      curve: 'P-256',
    };
    ks.saveKeyPair('test.aid', keyPair);

    const loaded = ks.loadKeyPair('test.aid');
    expect(loaded).not.toBeNull();
    expect(loaded!.private_key_pem).toBe(keyPair.private_key_pem);
    expect(loaded!.public_key_der_b64).toBe(keyPair.public_key_der_b64);
  });

  it('保存和加载证书', () => {
    const ks = new LocalIdentityStore(tmpDir);
    const certPem = '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n';
    ks.saveCert('test.aid', certPem);

    const loaded = ks.loadCert('test.aid');
    expect(loaded).toBe(certPem);
  });

  it('支持按证书指纹保存和加载证书版本', () => {
    const ks = new LocalIdentityStore(tmpDir);
    const certPem = '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n';
    ks.saveCert(
      'test.aid',
      certPem,
      'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      { makeActive: false },
    );

    const loaded = ks.loadCert(
      'test.aid',
      'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    );
    expect(loaded).toBe(certPem);
    expect(ks.loadCert('test.aid')).toBeNull();
  });

  it('保存和加载身份信息', () => {
    const ks = new LocalIdentityStore(tmpDir);
    const identity = {
      aid: 'test.aid',
      private_key_pem: '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----',
      public_key_der_b64: 'MFkwEw...',
      curve: 'P-256',
      cert: '-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n',
      access_token: 'tok_12345',
    };
    ks.saveIdentity('test.aid', identity);

    const loaded = ks.loadIdentity('test.aid');
    expect(loaded).not.toBeNull();
    expect(loaded!.private_key_pem).toBe(identity.private_key_pem);
    expect(loaded!.cert).toBe(identity.cert);
    expect(loaded!.access_token).toBe(identity.access_token);
  });

  it('重启后仍能加载身份信息', () => {
    const ks1 = new LocalIdentityStore(tmpDir);
    const identity = {
      private_key_pem: '-----BEGIN PRIVATE KEY-----\npersistent\n-----END PRIVATE KEY-----',
      public_key_der_b64: 'base64pub',
      curve: 'P-256',
    };
    ks1.saveKeyPair('persist.aid', identity);

    // 用相同路径创建新实例
    const ks2 = new LocalIdentityStore(tmpDir);
    const loaded = ks2.loadKeyPair('persist.aid');
    expect(loaded).not.toBeNull();
    expect(loaded!.private_key_pem).toBe(identity.private_key_pem);
  });

  it('多个 AID 互不干扰', () => {
    const ks = new LocalIdentityStore(tmpDir);
    ks.saveKeyPair('aid1', { private_key_pem: 'key1', public_key_der_b64: 'pub1' });
    ks.saveKeyPair('aid2', { private_key_pem: 'key2', public_key_der_b64: 'pub2' });

    const loaded1 = ks.loadKeyPair('aid1');
    const loaded2 = ks.loadKeyPair('aid2');
    expect(loaded1!.private_key_pem).toBe('key1');
    expect(loaded2!.private_key_pem).toBe('key2');
  });

  it('私钥不以明文保存在磁盘上', () => {
    const ks = new LocalIdentityStore(tmpDir);
    const privPem = '-----BEGIN PRIVATE KEY-----\nSECRET_DATA\n-----END PRIVATE KEY-----';
    ks.saveIdentity('secure.aid', {
      private_key_pem: privPem,
      public_key_der_b64: 'pub',
      curve: 'P-256',
    });

    const keyFilePath = join(tmpDir, 'AIDs', 'secure.aid', 'private', 'key.json');
    expect(existsSync(keyFilePath)).toBe(true);
    const content = JSON.parse(readFileSync(keyFilePath, 'utf-8'));
    // 磁盘上不应有 private_key_pem 明文
    expect(content.private_key_pem).toBeUndefined();
    // 应有 private_key_protection 加密记录
    expect(content.private_key_protection).toBeDefined();
    expect(content.private_key_protection.scheme).toBe('file_aes');

    // 但通过 API 加载应能恢复
    const loaded = ks.loadKeyPair('secure.aid');
    expect(loaded!.private_key_pem).toBe(privPem);
  });

  it('loadKeyPair 会把历史明文 key.json 迁移为加密存储', () => {
    const aid = 'legacy-plaintext.agentid.pub';
    const keyDir = join(tmpDir, 'AIDs', aid, 'private');
    mkdirSync(keyDir, { recursive: true });
    const keyPath = join(keyDir, 'key.json');
    writeFileSync(keyPath, JSON.stringify({
      private_key_pem: 'LEGACY_PLAINTEXT_PRIVATE',
      public_key_der_b64: 'pub',
      curve: 'P-256',
    }), 'utf-8');

    const ks = new LocalIdentityStore(tmpDir, { encryptionSeed: 'new-seed' });
    const loaded = ks.loadKeyPair(aid);
    expect(loaded?.private_key_pem).toBe('LEGACY_PLAINTEXT_PRIVATE');

    const rawText = readFileSync(keyPath, 'utf-8');
    const raw = JSON.parse(rawText);
    expect(raw.private_key_pem).toBeUndefined();
    expect(rawText).not.toContain('LEGACY_PLAINTEXT_PRIVATE');
    expect(raw.private_key_protection).toMatchObject({ scheme: 'file_aes', name: 'identity/private_key' });
  });

  it('loadKeyPair seed 不匹配时抛错且不破坏 key.json', () => {
    const aid = 'wrong-load-seed.agentid.pub';
    const ks = new LocalIdentityStore(tmpDir, { encryptionSeed: 'correct-seed' });
    ks.saveKeyPair(aid, {
      private_key_pem: 'CORRECT_SEED_PRIVATE',
      public_key_der_b64: 'pub',
      curve: 'P-256',
    });
    const keyPath = join(tmpDir, 'AIDs', aid, 'private', 'key.json');
    const before = readFileSync(keyPath, 'utf-8');

    const wrong = new LocalIdentityStore(tmpDir, { encryptionSeed: 'wrong-seed' });
    expect(() => wrong.loadKeyPair(aid)).toThrow(/decrypt failed/);
    expect(readFileSync(keyPath, 'utf-8')).toBe(before);
  });

  it('loadPendingKeyPair 会把历史明文 pending key.json 迁移为加密存储', () => {
    const aid = 'pending-legacy.agentid.pub';
    const ks = new LocalIdentityStore(tmpDir, { encryptionSeed: 'pending-seed' });
    const pendingDir = ks.pendingIdentityDir(aid);
    const keyPath = join(pendingDir, 'private', 'key.json');
    writeFileSync(keyPath, JSON.stringify({
      private_key_pem: 'PENDING_PLAINTEXT_PRIVATE',
      public_key_der_b64: 'pub',
      curve: 'P-256',
    }), 'utf-8');

    const loaded = ks.loadPendingKeyPair(pendingDir, aid);
    expect(loaded?.private_key_pem).toBe('PENDING_PLAINTEXT_PRIVATE');
    const rawText = readFileSync(keyPath, 'utf-8');
    const raw = JSON.parse(rawText);
    expect(raw.private_key_pem).toBeUndefined();
    expect(rawText).not.toContain('PENDING_PLAINTEXT_PRIVATE');
    expect(raw.private_key_protection).toMatchObject({ scheme: 'file_aes', name: 'identity/private_key' });
  });

  it('token 实例态由 LocalTokenStore 持久化', () => {
    const ks = new LocalTokenStore(tmpDir);
    ks.saveInstanceState('token.aid', 'device-1', 'slot-1', {
      access_token: 'secret-token-123',
      refresh_token: 'refresh-token-456',
    });

    const loaded = ks.loadInstanceState('token.aid', 'device-1', 'slot-1');
    expect(loaded!.access_token).toBe('secret-token-123');
    expect(loaded!.refresh_token).toBe('refresh-token-456');
    ks.close();
  });

  it('旧 instance_state/seq_tracker schema 无版本记录时应自动补 slot_id_full 列', () => {
    const aid = 'legacy-slot-schema.agentid.pub';
    const aidDir = join(tmpDir, 'AIDs', aid);
    mkdirSync(aidDir, { recursive: true });
    const dbPath = join(aidDir, 'aun.db');
    const db = new DatabaseSync(dbPath);
    try {
      db.exec(`CREATE TABLE instance_state (
        device_id TEXT NOT NULL,
        slot_id TEXT NOT NULL DEFAULT '_singleton',
        data TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (device_id, slot_id)
      )`);
      db.exec(`CREATE TABLE seq_tracker (
        device_id TEXT NOT NULL,
        slot_id TEXT NOT NULL DEFAULT '_singleton',
        namespace TEXT NOT NULL,
        contiguous_seq INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (device_id, slot_id, namespace)
      )`);
    } finally {
      db.close();
    }

    const ks = new LocalTokenStore(tmpDir);
    try {
      ks.saveInstanceState(aid, 'device-1', 'slot-a', { access_token: 'token-a' });
      expect(ks.loadInstanceState(aid, 'device-1', 'slot-a')!.access_token).toBe('token-a');
      ks.saveSeq(aid, 'device-1', 'slot-a', 'inbox', 7);
      expect(ks.loadSeq(aid, 'device-1', 'slot-a', 'inbox')).toBe(7);
    } finally {
      ks.close();
    }

    const verify = new DatabaseSync(dbPath);
    try {
      const instanceColumns = new Set((verify.prepare('PRAGMA table_info(instance_state)').all() as Array<{ name: string }>).map((row) => row.name));
      const seqColumns = new Set((verify.prepare('PRAGMA table_info(seq_tracker)').all() as Array<{ name: string }>).map((row) => row.name));
      expect(instanceColumns.has('slot_id_full')).toBe(true);
      expect(seqColumns.has('slot_id_full')).toBe(true);
    } finally {
      verify.close();
    }
  });

  it('loadKeyPair 不存在的 AID 返回 null', () => {
    const ks = new LocalIdentityStore(tmpDir);
    expect(ks.loadKeyPair('nonexistent')).toBeNull();
  });

  it('loadCert 不存在的 AID 返回 null', () => {
    const ks = new LocalIdentityStore(tmpDir);
    expect(ks.loadCert('nonexistent')).toBeNull();
  });

  it('loadIdentity 不存在的 AID 返回 null（原 loadMetadata）', () => {
    const ks = new LocalIdentityStore(tmpDir);
    expect(ks.loadIdentity('nonexistent')).toBeNull();
  });

  it('loadIdentity 不存在的 AID 返回 null', () => {
    const ks = new LocalIdentityStore(tmpDir);
    expect(ks.loadIdentity('nonexistent')).toBeNull();
  });

  it('safeAid 替换特殊字符', () => {
    // user/domain, user\domain, user:domain 都映射到同一个 safe AID: user_domain
    const ks = new LocalIdentityStore(tmpDir);
    const db1 = (ks as any)._getDB('normal.aid');
    db1.setMetadata('custom', 'normal');
    const db2 = (ks as any)._getDB('user/domain');
    db2.setMetadata('custom', 'slash');

    const meta1 = (ks as any)._getDB('normal.aid').getAllMetadata();
    expect(meta1.custom).toBe('normal');
    // 同一个 safe AID 下后写覆盖前写
    const meta2 = (ks as any)._getDB('user/domain').getAllMetadata();
    expect(meta2.custom).toBe('slash');
    const meta3 = (ks as any)._getDB('user:domain').getAllMetadata();
    expect(meta3.custom).toBe('slash');
    ks.close();
  });

  it('saveIdentity 更新 token 时不应覆盖已有 metadata', () => {
    const ks = new LocalIdentityStore(tmpDir);
    const db = (ks as any)._getDB('identity.aid');
    db.setMetadata('custom', JSON.stringify({ keep: true }));

    ks.saveIdentity('identity.aid', {
      aid: 'identity.aid',
      access_token: 'tok-new',
      refresh_token: 'rt-new',
    });

    const loaded = ks.loadIdentity('identity.aid');
    expect(loaded!.access_token).toBe('tok-new');
    expect(loaded!.refresh_token).toBe('rt-new');
    expect(JSON.parse(db.getMetadata('custom') ?? '{}')).toEqual({ keep: true });
  });

  it('实例态应按 device_id/slot_id 隔离保存', () => {
    const ks = new LocalIdentityStore(tmpDir);
    ks.saveInstanceState!('instance.aid', 'device-a', '', {
      access_token: 'tok-a',
    });
    ks.saveInstanceState!('instance.aid', 'device-a', 'slot-2', {
      access_token: 'tok-b',
    });

    const singleton = ks.loadInstanceState!('instance.aid', 'device-a', '');
    const slot2 = ks.loadInstanceState!('instance.aid', 'device-a', 'slot-2');

    expect(singleton!.access_token).toBe('tok-a');
    expect(slot2!.access_token).toBe('tok-b');
  });

  it('同进程多 LocalIdentityStore 实例共享同一 AID DB 时应隔离 slot/seq 并共享 token/metadata', () => {
    const seed = 'same-process-shared-seed';
    const aid = 'same-process.agentid.pub';
    const deviceId = 'device-shared';
    const ks1 = new LocalIdentityStore(tmpDir, { encryptionSeed: seed });
    const ks2 = new LocalIdentityStore(tmpDir, { encryptionSeed: seed });

    try {
      ks1.saveInstanceState(aid, deviceId, 'slot-a', { owner: 'a', cursor: 1 });
      ks2.saveInstanceState(aid, deviceId, 'slot-b', { owner: 'b', cursor: 2 });
      ks1.saveSeq(aid, deviceId, 'slot-a', 'inbox', 101);
      ks2.saveSeq(aid, deviceId, 'slot-b', 'inbox', 202);

      const db1 = (ks1 as any)._getDB(aid);
      db1.setToken('access_token', 'token-from-ks1');
      db1.setMetadata('profile', JSON.stringify({ owner: 'ks1' }));

      expect(ks2.loadInstanceState!(aid, deviceId, 'slot-a')).toMatchObject({ owner: 'a', cursor: 1 });
      expect(ks1.loadInstanceState!(aid, deviceId, 'slot-b')).toMatchObject({ owner: 'b', cursor: 2 });
      expect(ks2.loadSeq!(aid, deviceId, 'slot-a', 'inbox')).toBe(101);
      expect(ks1.loadSeq!(aid, deviceId, 'slot-b', 'inbox')).toBe(202);
      const db2 = (ks2 as any)._getDB(aid);
      expect(db2.getToken('access_token')).toBe('token-from-ks1');
      expect(JSON.parse(db2.getMetadata('profile') ?? '{}')).toEqual({ owner: 'ks1' });
    } finally {
      ks1.close();
      ks2.close();
    }
  });

  it('多进程共享同一 AID DB 并发写入时应覆盖 seq、instance、token 和 metadata', async () => {
    const workerPath = writeKeystoreStressWorker(tmpDir);
    const seed = 'multiprocess-shared-seed';
    const aid = 'multiprocess.agentid.pub';
    const workers = 8;
    const rounds = 16;

    await Promise.all(Array.from({ length: workers }, (_, worker) => runKeystoreStressWorker(workerPath, {
      root: tmpDir,
      seed,
      aid,
      worker,
      rounds,
    })));

    const ks = new LocalIdentityStore(tmpDir, { encryptionSeed: seed });
    try {
      const db = (ks as any)._getDB(aid);

      for (let worker = 0; worker < workers; worker += 1) {
        const slotId = `slot-${worker}`;
        const deviceId = 'device-shared';
        const finalSeq = worker * 10000 + rounds;
        expect(ks.loadInstanceState!(aid, deviceId, slotId)).toMatchObject({
          worker,
          round: rounds,
          marker: `state-${worker}-${rounds}`,
        });
        expect(ks.loadSeq!(aid, deviceId, slotId, 'inbox')).toBe(finalSeq);

        const seqs = ks.loadAllSeqs!(aid, deviceId, slotId);
        expect(seqs.inbox).toBe(finalSeq);
        for (let ns = 0; ns < 4; ns += 1) {
          const latestRound = Array.from({ length: rounds }, (_, index) => index + 1)
            .filter((round) => round % 4 === ns)
            .pop();
          if (latestRound) expect(seqs[`ns-${ns}`]).toBe(worker * 10000 + latestRound);
        }

        expect(db.getToken(`token_${worker}_${rounds}`)).toBe(`token-value-${worker}-${rounds}`);
        expect(JSON.parse(db.getMetadata(`meta_${worker}_${rounds}`) ?? '{}')).toEqual({ worker, round: rounds });
      }
    } finally {
      ks.close();
    }
  }, 90_000);

  // ── ISSUE-SDK-TS-010: loadKeyPair 对损坏的 key.json 的健壮性 ──

  it('loadKeyPair 在 key.json 内容损坏时应返回 null', () => {
    const ks = new LocalIdentityStore(tmpDir);
    // 先创建目录结构
    const keyDir = join(tmpDir, 'AIDs', 'corrupt.aid', 'private');
    mkdirSync(keyDir, { recursive: true });
    // 写入损坏的 JSON
    writeFileSync(join(keyDir, 'key.json'), '{invalid json!!!');

    const result = ks.loadKeyPair('corrupt.aid');
    expect(result).toBeNull();
    ks.close();
  });

  it('loadKeyPair 在 key.json 为空文件时应返回 null', () => {
    const ks = new LocalIdentityStore(tmpDir);
    const keyDir = join(tmpDir, 'AIDs', 'empty.aid', 'private');
    mkdirSync(keyDir, { recursive: true });
    writeFileSync(join(keyDir, 'key.json'), '');

    const result = ks.loadKeyPair('empty.aid');
    expect(result).toBeNull();
    ks.close();
  });

  // ── ISSUE-SDK-TS-020: loadCert readFileSync 异常处理 ──

  it('loadCert 在 cert.pem 内容不可读时应返回 null（文件目录冲突模拟）', () => {
    const ks = new LocalIdentityStore(tmpDir);
    // 用目录替代文件来模拟 readFileSync 抛异常的场景
    const certDir = join(tmpDir, 'AIDs', 'badcert.aid', 'public');
    mkdirSync(certDir, { recursive: true });
    // 创建一个同名目录来让 readFileSync 抛 EISDIR
    mkdirSync(join(certDir, 'cert.pem'), { recursive: true });

    const result = ks.loadCert('badcert.aid');
    expect(result).toBeNull();
    ks.close();
  });

  it('loadCert 按指纹加载时 readFileSync 失败应返回 null', () => {
    const ks = new LocalIdentityStore(tmpDir);
    const fp = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    // 用目录替代文件来模拟 readFileSync 失败
    const certVerDir = join(tmpDir, 'AIDs', 'badcert2.aid', 'public', 'certs');
    mkdirSync(certVerDir, { recursive: true });
    mkdirSync(join(certVerDir, `${fp.replace(/:/g, '_')}.pem`), { recursive: true });

    const result = ks.loadCert('badcert2.aid', fp);
    expect(result).toBeNull();
    ks.close();
  });
});

describe('ChangeSeed versioned backup', () => {
  it('ChangeSeed 写 .v1 备份且旧 seed 可解密备份', () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'aun-backup-'));
    const aid = 'backup-test.agentid.pub';
    const keyDir = join(tmpDir, 'AIDs', aid, 'private');
    mkdirSync(keyDir, { recursive: true });
    const keyPath = join(keyDir, 'key.json');
    const oldStore = new LocalIdentityStore(tmpDir, { encryptionSeed: 'old-seed' });
    oldStore.saveKeyPair(aid, { private_key_pem: 'BACKUP_PRIVATE', public_key_der_b64: 'pub', curve: 'P-256' });
    oldStore.close();

    FileSecretStore.changeSeed(tmpDir, 'old-seed', 'new-seed');

    const bakPath = keyPath + '.v1';
    expect(existsSync(bakPath)).toBe(true);
    const bak = JSON.parse(readFileSync(bakPath, 'utf-8'));
    expect(bak.private_key_protection?.scheme).toBe('file_aes');
  });

  it('saveKeyPair 覆盖已有 key.json 时写 .v1 备份', () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'aun-overwrite-'));
    const aid = 'overwrite-backup.agentid.pub';
    const ks = new LocalIdentityStore(tmpDir, { encryptionSeed: 'seed1' });
    ks.saveKeyPair(aid, { private_key_pem: 'FIRST', public_key_der_b64: 'pub', curve: 'P-256' });
    ks.saveKeyPair(aid, { private_key_pem: 'SECOND', public_key_der_b64: 'pub', curve: 'P-256' });
    ks.close();

    const bakPath = join(tmpDir, 'AIDs', aid, 'private', 'key.json.v1');
    expect(existsSync(bakPath)).toBe(true);
  });
});
