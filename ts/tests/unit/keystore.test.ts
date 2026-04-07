/**
 * KeyStore 单元测试 — 覆盖 FileSecretStore、FileKeyStore
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { FileSecretStore } from '../../src/secret-store/file-store.js';
import { FileKeyStore } from '../../src/keystore/file.js';

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

  it('clear 不报错', () => {
    const store = new FileSecretStore(tmpDir, 'seed');
    // file_aes 方案的 clear 是 no-op
    expect(() => store.clear('scope', 'name')).not.toThrow();
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

  it('删除身份信息', () => {
    const ks = new FileKeyStore(tmpDir);
    ks.saveIdentity('del.aid', {
      private_key_pem: '-----BEGIN PRIVATE KEY-----\ndelete-me\n-----END PRIVATE KEY-----',
      public_key_der_b64: 'pub',
      curve: 'P-256',
    });
    expect(ks.loadIdentity('del.aid')).not.toBeNull();

    ks.deleteIdentity('del.aid');
    expect(ks.loadIdentity('del.aid')).toBeNull();
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

  it('token 不以明文保存在磁盘上', () => {
    const ks = new FileKeyStore(tmpDir);
    ks.saveMetadata('token.aid', {
      access_token: 'secret-token-123',
      refresh_token: 'refresh-token-456',
    });

    const metaFilePath = join(tmpDir, 'AIDs', 'token.aid', 'tokens', 'meta.json');
    expect(existsSync(metaFilePath)).toBe(true);
    const content = JSON.parse(readFileSync(metaFilePath, 'utf-8'));
    expect(content.access_token).toBeUndefined();
    expect(content.refresh_token).toBeUndefined();
    expect(content.access_token_protection).toBeDefined();
    expect(content.refresh_token_protection).toBeDefined();

    const loaded = ks.loadMetadata('token.aid');
    expect(loaded!.access_token).toBe('secret-token-123');
    expect(loaded!.refresh_token).toBe('refresh-token-456');
  });

  it('prekey 私钥不以明文保存在磁盘上', () => {
    const ks = new FileKeyStore(tmpDir);
    const privPem = '-----BEGIN PRIVATE KEY-----\nprekey-secret\n-----END PRIVATE KEY-----';
    ks.saveMetadata('prekey.aid', {
      e2ee_prekeys: {
        'prekey-123': {
          private_key_pem: privPem,
          public_key: 'MFkw...',
          created_at: Date.now(),
        },
      },
    });

    const metaFilePath = join(tmpDir, 'AIDs', 'prekey.aid', 'tokens', 'meta.json');
    const content = JSON.parse(readFileSync(metaFilePath, 'utf-8'));
    const prekeyData = content.e2ee_prekeys['prekey-123'];
    expect(prekeyData.private_key_pem).toBeUndefined();
    expect(prekeyData.private_key_protection).toBeDefined();

    const loaded = ks.loadMetadata('prekey.aid');
    expect((loaded!.e2ee_prekeys as Record<string, Record<string, unknown>>)['prekey-123'].private_key_pem).toBe(privPem);
  });

  it('group_secret 不以明文保存在磁盘上', () => {
    const ks = new FileKeyStore(tmpDir);
    ks.saveMetadata('group.aid', {
      group_secrets: {
        'group-1': {
          epoch: 1,
          secret: Buffer.from('group-secret-bytes').toString('base64'),
          commitment: 'abc',
          member_aids: ['a', 'b'],
          updated_at: Date.now(),
          old_epochs: [],
        },
      },
    });

    const metaFilePath = join(tmpDir, 'AIDs', 'group.aid', 'tokens', 'meta.json');
    const content = JSON.parse(readFileSync(metaFilePath, 'utf-8'));
    const groupData = content.group_secrets['group-1'];
    expect(groupData.secret).toBeUndefined();
    expect(groupData.secret_protection).toBeDefined();

    const loaded = ks.loadMetadata('group.aid');
    const gs = (loaded!.group_secrets as Record<string, Record<string, unknown>>)['group-1'];
    expect(gs.secret).toBe(Buffer.from('group-secret-bytes').toString('base64'));
  });

  it('loadKeyPair 不存在的 AID 返回 null', () => {
    const ks = new FileKeyStore(tmpDir);
    expect(ks.loadKeyPair('nonexistent')).toBeNull();
  });

  it('loadCert 不存在的 AID 返回 null', () => {
    const ks = new FileKeyStore(tmpDir);
    expect(ks.loadCert('nonexistent')).toBeNull();
  });

  it('loadMetadata 不存在的 AID 返回 null', () => {
    const ks = new FileKeyStore(tmpDir);
    expect(ks.loadMetadata('nonexistent')).toBeNull();
  });

  it('loadIdentity 不存在的 AID 返回 null', () => {
    const ks = new FileKeyStore(tmpDir);
    expect(ks.loadIdentity('nonexistent')).toBeNull();
  });

  it('safeAid 替换特殊字符', () => {
    expect(FileKeyStore._safeAid('user/domain')).toBe('user_domain');
    expect(FileKeyStore._safeAid('user\\domain')).toBe('user_domain');
    expect(FileKeyStore._safeAid('user:domain')).toBe('user_domain');
    expect(FileKeyStore._safeAid('normal.aid')).toBe('normal.aid');
  });

  it('metadata 防御性合并：不丢失关键数据', () => {
    const ks = new FileKeyStore(tmpDir);

    // 先保存带有 e2ee_prekeys 的 metadata
    ks.saveMetadata('merge.aid', {
      e2ee_prekeys: { 'pk-1': { public_key: 'pub1' } },
      some_field: 'value',
    });

    // 再保存不包含 e2ee_prekeys 的 metadata
    ks.saveMetadata('merge.aid', {
      some_field: 'updated',
    });

    // e2ee_prekeys 应被自动合并保留
    const loaded = ks.loadMetadata('merge.aid');
    expect(loaded!.some_field).toBe('updated');
    expect(loaded!.e2ee_prekeys).toBeDefined();
  });

  it('e2ee_sessions 的 key 被保护', () => {
    const ks = new FileKeyStore(tmpDir);
    ks.saveMetadata('session.aid', {
      e2ee_sessions: [
        { session_id: 'sess-1', key: 'session-secret-key', peer_aid: 'peer.aid' },
      ],
    });

    const metaFilePath = join(tmpDir, 'AIDs', 'session.aid', 'tokens', 'meta.json');
    const content = JSON.parse(readFileSync(metaFilePath, 'utf-8'));
    const sess = content.e2ee_sessions[0];
    expect(sess.key).toBeUndefined();
    expect(sess.key_protection).toBeDefined();

    const loaded = ks.loadMetadata('session.aid');
    const sessions = loaded!.e2ee_sessions as Record<string, unknown>[];
    expect(sessions[0].key).toBe('session-secret-key');
  });

  it('deleteKeyPair 删除密钥文件', () => {
    const ks = new FileKeyStore(tmpDir);
    ks.saveKeyPair('del.aid', {
      private_key_pem: '-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----',
      public_key_der_b64: 'pub',
    });
    expect(ks.loadKeyPair('del.aid')).not.toBeNull();

    ks.deleteKeyPair('del.aid');
    expect(ks.loadKeyPair('del.aid')).toBeNull();
  });

  it('old_epochs 中的 secret 也被保护', () => {
    const ks = new FileKeyStore(tmpDir);
    ks.saveMetadata('epoch.aid', {
      group_secrets: {
        'group-1': {
          epoch: 2,
          secret: Buffer.from('new-secret').toString('base64'),
          commitment: 'xyz',
          member_aids: ['a', 'b'],
          updated_at: Date.now(),
          old_epochs: [
            {
              epoch: 1,
              secret: Buffer.from('old-secret').toString('base64'),
              commitment: 'old-xyz',
              member_aids: ['a'],
              updated_at: Date.now() - 10000,
            },
          ],
        },
      },
    });

    const metaFilePath = join(tmpDir, 'AIDs', 'epoch.aid', 'tokens', 'meta.json');
    const content = JSON.parse(readFileSync(metaFilePath, 'utf-8'));
    const oldEpoch = content.group_secrets['group-1'].old_epochs[0];
    expect(oldEpoch.secret).toBeUndefined();
    expect(oldEpoch.secret_protection).toBeDefined();

    const loaded = ks.loadMetadata('epoch.aid');
    const gs = (loaded!.group_secrets as Record<string, Record<string, unknown>>)['group-1'];
    const oldEpochs = gs.old_epochs as Record<string, unknown>[];
    expect(oldEpochs[0].secret).toBe(Buffer.from('old-secret').toString('base64'));
  });
});
