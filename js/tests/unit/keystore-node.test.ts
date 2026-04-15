// @vitest-environment node
// ── NodeSQLiteKeyStore 单元测试 ──────────────────────────────
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { NodeSQLiteKeyStore } from '../../src/keystore/node-sqlite.js';
import type { PrekeyRecord, GroupSecretRecord } from '../../src/types.js';

let tmpDir: string;
let ks: NodeSQLiteKeyStore;

function makeTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'aun-node-sqlite-test-'));
}

describe('NodeSQLiteKeyStore', () => {
  beforeEach(() => {
    tmpDir = makeTmpDir();
    ks = new NodeSQLiteKeyStore(tmpDir, { encryptionSeed: 'test-seed' });
  });

  afterEach(() => {
    ks.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // ── 密钥对 CRUD ──────────────────────────────────────

  it('保存和加载密钥对', async () => {
    const kp = {
      private_key_pem: '-----BEGIN PRIVATE KEY-----\ntest-key\n-----END PRIVATE KEY-----',
      public_key_der_b64: 'base64pubkey',
      curve: 'P-256',
    };
    await ks.saveKeyPair('alice.test', kp);

    const loaded = await ks.loadKeyPair('alice.test');
    expect(loaded).not.toBeNull();
    expect(loaded!.private_key_pem).toBe(kp.private_key_pem);
    expect(loaded!.public_key_der_b64).toBe(kp.public_key_der_b64);
    expect(loaded!.curve).toBe('P-256');
  });

  it('加载不存在的密钥对应返回 null', async () => {
    expect(await ks.loadKeyPair('nonexistent')).toBeNull();
  });

  it('私钥不以明文存储在 key.json 文件中', async () => {
    const privPem = '-----BEGIN PRIVATE KEY-----\nsecret-data\n-----END PRIVATE KEY-----';
    await ks.saveKeyPair('alice.test', { private_key_pem: privPem, curve: 'P-256' });

    const filePath = path.join(tmpDir, 'AIDs', 'alice.test', 'private', 'key.json');
    const raw = fs.readFileSync(filePath, 'utf-8');
    expect(raw).not.toContain('secret-data');
    expect(raw).toContain('private_key_protection');
  });

  it('相同 seed 重建后能还原私钥', async () => {
    const privPem = '-----BEGIN PRIVATE KEY-----\npersistent\n-----END PRIVATE KEY-----';
    await ks.saveKeyPair('alice.test', { private_key_pem: privPem, curve: 'P-256' });
    ks.close();

    const ks2 = new NodeSQLiteKeyStore(tmpDir, { encryptionSeed: 'test-seed' });
    const loaded = await ks2.loadKeyPair('alice.test');
    expect(loaded!.private_key_pem).toBe(privPem);
    ks2.close();
  });

  // ── 证书 CRUD ────────────────────────────────────────

  it('保存和加载证书 PEM', async () => {
    const certPem = '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----';
    await ks.saveCert('bob.test', certPem);

    expect(await ks.loadCert('bob.test')).toBe(certPem);
  });

  it('支持按证书指纹保存和加载证书版本', async () => {
    const certPem = '-----BEGIN CERTIFICATE-----\nversioned\n-----END CERTIFICATE-----';
    const fp = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    await ks.saveCert('versioned.test', certPem, fp, { makeActive: false });

    expect(await ks.loadCert('versioned.test', fp)).toBe(certPem);
    expect(await ks.loadCert('versioned.test')).toBeNull();
  });

  it('makeActive=true 时同时更新 active cert', async () => {
    const certPem = '-----BEGIN CERTIFICATE-----\nactive\n-----END CERTIFICATE-----';
    const fp = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    await ks.saveCert('active.test', certPem, fp, { makeActive: true });

    expect(await ks.loadCert('active.test')).toBe(certPem);
    expect(await ks.loadCert('active.test', fp)).toBe(certPem);
  });

  it('加载不存在的证书应返回 null', async () => {
    expect(await ks.loadCert('nonexistent')).toBeNull();
  });

  // ── Identity CRUD ────────────────────────────────────

  it('saveIdentity 应拆分保存到各仓库', async () => {
    await ks.saveIdentity('alice.test', {
      private_key_pem: '-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----',
      public_key_der_b64: 'pub64',
      curve: 'P-256',
      cert: '-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----',
      access_token: 'tok-1',
    });

    expect(await ks.loadKeyPair('alice.test')).not.toBeNull();
    expect(await ks.loadCert('alice.test')).toContain('cert');
    const identity = await ks.loadIdentity('alice.test');
    expect(identity!.access_token).toBe('tok-1');
  });

  it('loadIdentity 应合并所有仓库数据', async () => {
    await ks.saveKeyPair('alice.test', { private_key_pem: 'pk', curve: 'P-256' });
    await ks.saveCert('alice.test', 'cert-pem');
    await ks.saveIdentity('alice.test', { access_token: 'tok' });

    const identity = await ks.loadIdentity('alice.test');
    expect(identity).not.toBeNull();
    expect(identity!.private_key_pem).toBe('pk');
    expect(identity!.cert).toBe('cert-pem');
    expect(identity!.access_token).toBe('tok');
  });

  it('加载不存在的身份应返回 null', async () => {
    expect(await ks.loadIdentity('nonexistent')).toBeNull();
  });

  it('saveIdentity 更新 token 时不应覆盖已有 prekey', async () => {
    await ks.saveE2EEPrekey!('alice', 'pk1', {
      private_key_pem: 'KEEP',
      created_at: Date.now(),
    });
    await ks.saveIdentity('alice', { access_token: 'new-tok' });

    const prekeys = await ks.loadE2EEPrekeys!('alice');
    expect(prekeys.pk1.private_key_pem).toBe('KEEP');
    const identity = await ks.loadIdentity('alice');
    expect(identity!.access_token).toBe('new-tok');
  });

  // ── Prekeys ──────────────────────────────────────────

  it('保存和加载 prekeys', async () => {
    await ks.saveE2EEPrekey!('alice', 'pk-1', {
      private_key_pem: 'prekey-pem-1',
      created_at: 1000,
      expires_at: 9999999999999,
    });
    await ks.saveE2EEPrekey!('alice', 'pk-2', {
      private_key_pem: 'prekey-pem-2',
      created_at: 2000,
    });

    const prekeys = await ks.loadE2EEPrekeys!('alice');
    expect(Object.keys(prekeys)).toHaveLength(2);
    expect(prekeys['pk-1'].private_key_pem).toBe('prekey-pem-1');
    expect(prekeys['pk-1'].created_at).toBe(1000);
    expect(prekeys['pk-2'].private_key_pem).toBe('prekey-pem-2');
  });

  it('cleanupE2EEPrekeys 应仅清理过期且不在最新 N 个里的 prekey', async () => {
    const now = Date.now();
    // 创建 3 个 prekeys
    await ks.saveE2EEPrekey!('alice', 'pk-old', {
      private_key_pem: 'old-key',
      created_at: now - 8 * 24 * 3600 * 1000, // 8 天前
    });
    await ks.saveE2EEPrekey!('alice', 'pk-recent', {
      private_key_pem: 'recent-key',
      created_at: now - 1000,
    });
    await ks.saveE2EEPrekey!('alice', 'pk-new', {
      private_key_pem: 'new-key',
      created_at: now,
    });

    // cutoff = 7天前，keepLatest = 2
    const cutoff = now - 7 * 24 * 3600 * 1000;
    const removed = await ks.cleanupE2EEPrekeys!('alice', cutoff, 2);
    expect(removed).toEqual(['pk-old']);

    const remaining = await ks.loadE2EEPrekeys!('alice');
    expect(Object.keys(remaining)).toHaveLength(2);
    expect(remaining['pk-old']).toBeUndefined();
  });

  it('device-scoped prekey 应允许同一 prekey_id 并存且 cleanup 只影响目标 device', async () => {
    const now = Date.now();
    const cutoff = now - 7 * 24 * 3600 * 1000;

    await ks.saveE2EEPrekeyForDevice!('alice', 'phone', 'pk-same', {
      private_key_pem: 'phone-key',
      created_at: cutoff - 1000,
    });
    await ks.saveE2EEPrekeyForDevice!('alice', 'laptop', 'pk-same', {
      private_key_pem: 'laptop-key',
      created_at: cutoff - 1000,
    });

    expect(await ks.loadE2EEPrekeysForDevice!('alice', 'phone')).toMatchObject({
      'pk-same': { private_key_pem: 'phone-key', created_at: cutoff - 1000 },
    });
    expect(await ks.loadE2EEPrekeysForDevice!('alice', 'laptop')).toMatchObject({
      'pk-same': { private_key_pem: 'laptop-key', created_at: cutoff - 1000 },
    });
    expect(await ks.loadE2EEPrekeys!('alice')).toEqual({});

    const removed = await ks.cleanupE2EEPrekeysForDevice!('alice', 'phone', cutoff, 0);
    expect(removed).toEqual(['pk-same']);
    expect(await ks.loadE2EEPrekeysForDevice!('alice', 'phone')).toEqual({});
    expect(await ks.loadE2EEPrekeysForDevice!('alice', 'laptop')).toMatchObject({
      'pk-same': { private_key_pem: 'laptop-key', created_at: cutoff - 1000 },
    });
  });

  // ── Group Secrets ────────────────────────────────────

  it('保存和加载群组密钥状态', async () => {
    await ks.saveGroupSecretState!('alice', 'grp-1', {
      epoch: 1,
      secret: 'group-secret-1',
      member_aids: ['alice', 'bob'] as unknown as string[],
    });

    const loaded = await ks.loadGroupSecretState!('alice', 'grp-1');
    expect(loaded).not.toBeNull();
    expect(loaded!.epoch).toBe(1);
    expect(loaded!.secret).toBe('group-secret-1');
  });

  it('保存和加载含 old_epochs 的群组状态', async () => {
    await ks.saveGroupSecretState!('alice', 'grp-1', {
      epoch: 3,
      secret: 'current-secret',
      old_epochs: [
        { epoch: 1, secret: 'old-1', updated_at: Date.now() },
        { epoch: 2, secret: 'old-2', updated_at: Date.now() },
      ],
    });

    const loaded = await ks.loadGroupSecretState!('alice', 'grp-1');
    expect(loaded!.epoch).toBe(3);
    expect(loaded!.old_epochs).toHaveLength(2);
    expect((loaded!.old_epochs![0] as GroupSecretRecord).epoch).toBe(1);
    expect((loaded!.old_epochs![1] as GroupSecretRecord).epoch).toBe(2);
  });

  it('loadAllGroupSecretStates 加载全部群组', async () => {
    await ks.saveGroupSecretState!('alice', 'grp-1', { epoch: 1, secret: 's1' });
    await ks.saveGroupSecretState!('alice', 'grp-2', { epoch: 2, secret: 's2' });

    const all = await ks.loadAllGroupSecretStates!('alice');
    expect(Object.keys(all)).toHaveLength(2);
    expect(all['grp-1'].epoch).toBe(1);
    expect(all['grp-2'].epoch).toBe(2);
  });

  it('cleanupGroupOldEpochsState 清理过期 old epochs', async () => {
    const now = Date.now();
    await ks.saveGroupSecretState!('alice', 'grp-1', {
      epoch: 3,
      secret: 'current',
      old_epochs: [
        { epoch: 1, secret: 'old-1', updated_at: now - 10000, expires_at: now - 5000 },
        { epoch: 2, secret: 'old-2', updated_at: now, expires_at: now + 60000 },
      ],
    });

    const removed = await ks.cleanupGroupOldEpochsState!('alice', 'grp-1', now);
    expect(removed).toBe(1);

    const loaded = await ks.loadGroupSecretState!('alice', 'grp-1');
    expect(loaded!.old_epochs).toHaveLength(1);
    expect((loaded!.old_epochs![0] as GroupSecretRecord).epoch).toBe(2);
  });

  it('加载不存在的群组状态应返回 null', async () => {
    expect(await ks.loadGroupSecretState!('alice', 'nonexistent')).toBeNull();
  });

  // ── E2EE Sessions ────────────────────────────────────

  it('保存和加载 sessions', async () => {
    await ks.saveE2EESession!('alice', 'sess-1', {
      session_id: 'sess-1',
      key: 'session-key-data',
      peer_aid: 'bob',
    });
    await ks.saveE2EESession!('alice', 'sess-2', {
      session_id: 'sess-2',
      key: 'session-key-2',
      peer_aid: 'charlie',
    });

    const sessions = await ks.loadE2EESessions!('alice');
    expect(sessions).toHaveLength(2);

    const sess1 = sessions.find((s) => s.session_id === 'sess-1');
    expect(sess1).toBeDefined();
    expect(sess1!.key).toBe('session-key-data');
    expect(sess1!.peer_aid).toBe('bob');
  });

  it('sessions 通过 saveE2EESession 保存也能独立加载', async () => {
    await ks.saveE2EESession!('alice', 'meta-sess', {
      session_id: 'meta-sess',
      key: 'meta-key',
      peer_aid: 'bob',
    });

    const sessions = await ks.loadE2EESessions!('alice');
    expect(sessions).toHaveLength(1);
    expect(sessions[0].session_id).toBe('meta-sess');
  });

  it('sessions 加密存储在 DB 中', async () => {
    await ks.saveE2EESession!('alice', 'enc-sess', {
      session_id: 'enc-sess',
      key: 'ultra-secret-session-key',
    });

    const dbPath = path.join(tmpDir, 'AIDs', 'alice', 'aun.db');
    const raw = fs.readFileSync(dbPath);
    expect(raw.toString()).not.toContain('ultra-secret-session-key');
  });

  // ── Instance State ───────────────────────────────────

  it('实例态应按 device_id/slot_id 隔离保存', async () => {
    await ks.saveInstanceState!('alice', 'device-a', '', {
      access_token: 'tok-singleton',
    });
    await ks.saveInstanceState!('alice', 'device-a', 'slot-2', {
      access_token: 'tok-slot-2',
    });

    const singleton = await ks.loadInstanceState!('alice', 'device-a', '');
    const slot2 = await ks.loadInstanceState!('alice', 'device-a', 'slot-2');

    expect(singleton!.access_token).toBe('tok-singleton');
    expect(slot2!.access_token).toBe('tok-slot-2');
  });

  it('updateInstanceState 应原子更新', async () => {
    await ks.saveInstanceState!('alice', 'dev-1', 'slot-1', { count: 1 });

    const result = await ks.updateInstanceState!('alice', 'dev-1', 'slot-1', (state) => {
      state.count = (state.count as number) + 1;
      state.extra = 'added';
      return state;
    });

    expect(result.count).toBe(2);
    expect(result.extra).toBe('added');

    const loaded = await ks.loadInstanceState!('alice', 'dev-1', 'slot-1');
    expect(loaded!.count).toBe(2);
  });

  it('加载不存在的实例态应返回 null', async () => {
    expect(await ks.loadInstanceState!('alice', 'nonexistent', '')).toBeNull();
  });

  // ── AID 隔离 ─────────────────────────────────────────

  it('不同 AID 的数据互相隔离', async () => {
    await ks.saveIdentity('alice', { access_token: 'alice-tok' });
    await ks.saveIdentity('bob', { access_token: 'bob-tok' });

    const alice = await ks.loadIdentity('alice');
    const bob = await ks.loadIdentity('bob');
    expect(alice!.access_token).toBe('alice-tok');
    expect(bob!.access_token).toBe('bob-tok');
  });

  it('AID 中的特殊字符应被安全处理', async () => {
    const weirdAid = 'alice/bob\\charlie:test';
    await ks.saveIdentity(weirdAid, { custom: 'ok' });

    const loaded = await ks.loadIdentity(weirdAid);
    expect(loaded!.custom).toBe('ok');
  });

  // ── DB 持久化 ────────────────────────────────────────

  it('关闭并重新打开后数据应持久化', async () => {
    await ks.saveIdentity('alice', { access_token: 'persist-tok' });
    await ks.saveE2EEPrekey!('alice', 'pk-persist', {
      private_key_pem: 'persist-pem',
      created_at: Date.now(),
    });
    ks.close();

    const ks2 = new NodeSQLiteKeyStore(tmpDir, { encryptionSeed: 'test-seed' });
    const identity = await ks2.loadIdentity('alice');
    expect(identity!.access_token).toBe('persist-tok');

    const prekeys = await ks2.loadE2EEPrekeys!('alice');
    expect(prekeys['pk-persist'].private_key_pem).toBe('persist-pem');
    ks2.close();
  });
});
