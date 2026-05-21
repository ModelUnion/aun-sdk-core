/**
 * KeyStore 单元测试 — 覆盖 FileSecretStore、FileKeyStore
 */

import { execFile } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import { describe, it, expect, beforeEach } from 'vitest';

import { FileSecretStore } from '../../src/secret-store/file-store.js';
import { FileKeyStore } from '../../src/keystore/file.js';

const execFileAsync = promisify(execFile);

type KeystoreWorkerPayload = {
  root: string;
  seed: string;
  aid: string;
  worker: number;
  rounds: number;
};

function writeKeystoreStressWorker(root: string): string {
  const workerPath = join(root, 'keystore-multiprocess-worker.ts');
  const fileKeyStoreUrl = pathToFileURL(join(process.cwd(), 'src', 'keystore', 'file.ts')).href;
  writeFileSync(workerPath, `
import { FileKeyStore } from ${JSON.stringify(fileKeyStoreUrl)};

const payload = JSON.parse(process.argv[2] ?? '{}');
const root = String(payload.root);
const seed = String(payload.seed);
const aid = String(payload.aid);
const worker = Number(payload.worker);
const rounds = Number(payload.rounds);
const deviceId = 'device-shared';
const slotId = \`slot-\${worker}\`;
const ks = new FileKeyStore(root, { encryptionSeed: seed });

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

  it('不提供 seed 时自动生成 .seed 文件', () => {
    const store = new FileSecretStore(tmpDir);
    const seedPath = join(tmpDir, '.seed');
    expect(existsSync(seedPath)).toBe(true);

    // 同一目录再次创建应复用同一个 seed
    const plaintext = Buffer.from('auto-seed', 'utf-8');
    const record = store.protect('scope', 'key', plaintext);

    const store2 = new FileSecretStore(tmpDir);
    const revealed = store2.reveal('scope', 'key', record);
    expect(revealed!.toString('utf-8')).toBe('auto-seed');
  });

});

// ── FileKeyStore 测试 ────────────────────────────────────────

describe('FileKeyStore', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'aun-ks-test-'));
  });

  it('保存和加载密钥对', () => {
    const ks = new FileKeyStore(tmpDir);
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
    const ks = new FileKeyStore(tmpDir);
    const certPem = '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n';
    ks.saveCert('test.aid', certPem);

    const loaded = ks.loadCert('test.aid');
    expect(loaded).toBe(certPem);
  });

  it('支持按证书指纹保存和加载证书版本', () => {
    const ks = new FileKeyStore(tmpDir);
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
    const ks = new FileKeyStore(tmpDir);
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
    const ks1 = new FileKeyStore(tmpDir);
    const identity = {
      private_key_pem: '-----BEGIN PRIVATE KEY-----\npersistent\n-----END PRIVATE KEY-----',
      public_key_der_b64: 'base64pub',
      curve: 'P-256',
    };
    ks1.saveKeyPair('persist.aid', identity);

    // 用相同路径创建新实例
    const ks2 = new FileKeyStore(tmpDir);
    const loaded = ks2.loadKeyPair('persist.aid');
    expect(loaded).not.toBeNull();
    expect(loaded!.private_key_pem).toBe(identity.private_key_pem);
  });

  it('多个 AID 互不干扰', () => {
    const ks = new FileKeyStore(tmpDir);
    ks.saveKeyPair('aid1', { private_key_pem: 'key1', public_key_der_b64: 'pub1' });
    ks.saveKeyPair('aid2', { private_key_pem: 'key2', public_key_der_b64: 'pub2' });

    const loaded1 = ks.loadKeyPair('aid1');
    const loaded2 = ks.loadKeyPair('aid2');
    expect(loaded1!.private_key_pem).toBe('key1');
    expect(loaded2!.private_key_pem).toBe('key2');
  });

  it('私钥不以明文保存在磁盘上', () => {
    const ks = new FileKeyStore(tmpDir);
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

  it('token 存取往返正确（存 SQLite）', () => {
    const ks = new FileKeyStore(tmpDir);
    const db = (ks as any)._getDB('token.aid');
    db.setToken('access_token', 'secret-token-123');
    db.setToken('refresh_token', 'refresh-token-456');

    const loaded = ks.loadIdentity('token.aid');
    expect(loaded!.access_token).toBe('secret-token-123');
    expect(loaded!.refresh_token).toBe('refresh-token-456');
    ks.close();
  });

  it('loadKeyPair 不存在的 AID 返回 null', () => {
    const ks = new FileKeyStore(tmpDir);
    expect(ks.loadKeyPair('nonexistent')).toBeNull();
  });

  it('loadCert 不存在的 AID 返回 null', () => {
    const ks = new FileKeyStore(tmpDir);
    expect(ks.loadCert('nonexistent')).toBeNull();
  });

  it('loadIdentity 不存在的 AID 返回 null（原 loadMetadata）', () => {
    const ks = new FileKeyStore(tmpDir);
    expect(ks.loadIdentity('nonexistent')).toBeNull();
  });

  it('loadIdentity 不存在的 AID 返回 null', () => {
    const ks = new FileKeyStore(tmpDir);
    expect(ks.loadIdentity('nonexistent')).toBeNull();
  });

  it('safeAid 替换特殊字符', () => {
    // user/domain, user\domain, user:domain 都映射到同一个 safe AID: user_domain
    const ks = new FileKeyStore(tmpDir);
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
    const ks = new FileKeyStore(tmpDir);
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
    const ks = new FileKeyStore(tmpDir);
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

  it('同进程多 FileKeyStore 实例共享同一 AID DB 时应隔离 slot/seq 并共享 token/metadata', () => {
    const seed = 'same-process-shared-seed';
    const aid = 'same-process.agentid.pub';
    const deviceId = 'device-shared';
    const ks1 = new FileKeyStore(tmpDir, { encryptionSeed: seed });
    const ks2 = new FileKeyStore(tmpDir, { encryptionSeed: seed });

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

    const ks = new FileKeyStore(tmpDir, { encryptionSeed: seed });
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
    const ks = new FileKeyStore(tmpDir);
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
    const ks = new FileKeyStore(tmpDir);
    const keyDir = join(tmpDir, 'AIDs', 'empty.aid', 'private');
    mkdirSync(keyDir, { recursive: true });
    writeFileSync(join(keyDir, 'key.json'), '');

    const result = ks.loadKeyPair('empty.aid');
    expect(result).toBeNull();
    ks.close();
  });

  // ── ISSUE-SDK-TS-020: loadCert readFileSync 异常处理 ──

  it('loadCert 在 cert.pem 内容不可读时应返回 null（文件目录冲突模拟）', () => {
    const ks = new FileKeyStore(tmpDir);
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
    const ks = new FileKeyStore(tmpDir);
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
