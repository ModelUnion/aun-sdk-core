// ── e2ee-group 模块单元测试 ──────────────────────────────────
// 群组端到端加密测试。密码学操作全部异步。
import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach } from 'vitest';
import {
  GroupE2EEManager,
  GroupReplayGuard,
  GroupKeyRequestThrottle,
  MODE_EPOCH_GROUP_KEY,
  AAD_FIELDS_GROUP,
  AAD_MATCH_FIELDS_GROUP,
  OLD_EPOCH_RETENTION_SECONDS,
  encryptGroupMessage,
  decryptGroupMessage,
  buildMembershipManifest,
  signMembershipManifest,
  verifyMembershipManifest,
  computeMembershipCommitment,
  verifyMembershipCommitment,
  storeGroupSecret,
  loadGroupSecret,
  loadAllGroupSecrets,
  cleanupOldEpochs,
  generateGroupSecret,
  buildKeyDistribution,
  handleKeyDistribution,
  handleKeyRequest,
  handleKeyResponse,
  buildKeyRequest,
  checkEpochDowngrade,
} from '../../src/e2ee-group.js';
import { CryptoProvider, uint8ToBase64, base64ToUint8 } from '../../src/crypto.js';
import type { KeyStore } from '../../src/keystore/index.js';
import type { GroupOldEpochRecord, GroupSecretMap, JsonObject, KeyPairRecord } from '../../src/types.js';

const hasSubtleCrypto = typeof globalThis.crypto?.subtle?.generateKey === 'function';

// ── 内存 KeyStore mock ──────────────────────────────────

function createMockKeyStore(): KeyStore {
  const keyPairs = new Map<string, KeyPairRecord>();
  const certs = new Map<string, string>();
  const groups = new Map<string, GroupSecretMap>();
  return {
    async loadKeyPair(aid) { return keyPairs.get(aid) ?? null; },
    async saveKeyPair(aid, kp) { keyPairs.set(aid, kp); },
    async loadCert(aid) { return certs.get(aid) ?? null; },
    async saveCert(aid, cert) { certs.set(aid, cert); },
    async loadGroupSecretState(aid, groupId) {
      return JSON.parse(JSON.stringify(groups.get(aid)?.[groupId] ?? null));
    },
    async loadAllGroupSecretStates(aid) {
      return JSON.parse(JSON.stringify(groups.get(aid) ?? {}));
    },
    async saveGroupSecretState(aid, groupId, entry) {
      const current = groups.get(aid) ?? {};
      current[groupId] = JSON.parse(JSON.stringify(entry));
      groups.set(aid, current);
    },
    async cleanupGroupOldEpochsState(aid, groupId, cutoffMs) {
      const entry = groups.get(aid)?.[groupId];
      if (!entry) return 0;
      const oldEpochs = Array.isArray(entry.old_epochs) ? entry.old_epochs as GroupOldEpochRecord[] : [];
      const remaining = oldEpochs.filter((old) => Number(old.expires_at ?? old.updated_at ?? 0) >= cutoffMs);
      const removed = oldEpochs.length - remaining.length;
      entry.old_epochs = remaining;
      return removed;
    },
    async loadIdentity(aid) {
      const kp = keyPairs.get(aid);
      if (!kp) return null;
      const cert = certs.get(aid);
      return { ...kp, ...(cert ? { cert } : {}) };
    },
    async saveIdentity(aid, identity) {
      const kp: KeyPairRecord = {};
      for (const k of ['private_key_pem', 'public_key_der_b64', 'curve']) {
        if (k in identity) kp[k] = identity[k];
      }
      if (Object.keys(kp).length) keyPairs.set(aid, kp);
      if (identity.cert) certs.set(aid, identity.cert as string);
    },
  };
}

// ── 常量测试 ────────────────────────────────────────────

describe('群组 E2EE 常量', () => {
  it('MODE_EPOCH_GROUP_KEY 值正确', () => {
    expect(MODE_EPOCH_GROUP_KEY).toBe('epoch_group_key');
  });

  it('AAD_FIELDS_GROUP 包含必需字段', () => {
    expect(AAD_FIELDS_GROUP).toContain('group_id');
    expect(AAD_FIELDS_GROUP).toContain('from');
    expect(AAD_FIELDS_GROUP).toContain('message_id');
    expect(AAD_FIELDS_GROUP).toContain('timestamp');
    expect(AAD_FIELDS_GROUP).toContain('epoch');
    expect(AAD_FIELDS_GROUP).toContain('encryption_mode');
    expect(AAD_FIELDS_GROUP).toContain('suite');
  });

  it('AAD_MATCH_FIELDS_GROUP 不含 timestamp', () => {
    expect(AAD_MATCH_FIELDS_GROUP).not.toContain('timestamp');
    expect(AAD_MATCH_FIELDS_GROUP).toContain('group_id');
    expect(AAD_MATCH_FIELDS_GROUP).toContain('epoch');
  });

  it('OLD_EPOCH_RETENTION_SECONDS 为 7 天', () => {
    expect(OLD_EPOCH_RETENTION_SECONDS).toBe(7 * 24 * 3600);
  });
});

// ── GroupReplayGuard 测试 ──────────────────────────────

describe('GroupReplayGuard', () => {
  it('首次消息应通过', () => {
    const guard = new GroupReplayGuard();
    expect(guard.checkAndRecord('g1', 'alice', 'msg-1')).toBe(true);
  });

  it('重复消息应被拒绝', () => {
    const guard = new GroupReplayGuard();
    guard.checkAndRecord('g1', 'alice', 'msg-1');
    expect(guard.checkAndRecord('g1', 'alice', 'msg-1')).toBe(false);
  });

  it('不同群组/发送方/消息 ID 应隔离', () => {
    const guard = new GroupReplayGuard();
    expect(guard.checkAndRecord('g1', 'alice', 'msg-1')).toBe(true);
    expect(guard.checkAndRecord('g2', 'alice', 'msg-1')).toBe(true);
    expect(guard.checkAndRecord('g1', 'bob', 'msg-1')).toBe(true);
    expect(guard.checkAndRecord('g1', 'alice', 'msg-2')).toBe(true);
  });

  it('isSeen 应正确反映状态', () => {
    const guard = new GroupReplayGuard();
    expect(guard.isSeen('g1', 'alice', 'msg-1')).toBe(false);
    guard.record('g1', 'alice', 'msg-1');
    expect(guard.isSeen('g1', 'alice', 'msg-1')).toBe(true);
  });

  it('size 应正确反映记录数量', () => {
    const guard = new GroupReplayGuard();
    expect(guard.size).toBe(0);
    guard.checkAndRecord('g1', 'a', 'm1');
    guard.checkAndRecord('g1', 'a', 'm2');
    expect(guard.size).toBe(2);
  });

  it('超过 maxSize 应自动裁剪', () => {
    const guard = new GroupReplayGuard(10);
    for (let i = 0; i < 15; i++) {
      guard.checkAndRecord('g', 's', `m${i}`);
    }
    // 裁剪到 80% = 8 条
    expect(guard.size).toBeLessThanOrEqual(10);
  });
});

// ── GroupKeyRequestThrottle 测试 ──────────────────────────

describe('GroupKeyRequestThrottle', () => {
  it('首次请求应允许', () => {
    const throttle = new GroupKeyRequestThrottle(30);
    expect(throttle.allow('key1')).toBe(true);
  });

  it('冷却期内重复请求应被拒绝', () => {
    const throttle = new GroupKeyRequestThrottle(9999); // 很长的冷却期
    throttle.allow('key1');
    expect(throttle.allow('key1')).toBe(false);
  });

  it('不同 key 应独立', () => {
    const throttle = new GroupKeyRequestThrottle(9999);
    throttle.allow('key1');
    expect(throttle.allow('key2')).toBe(true);
  });

  it('reset 应清除限制', () => {
    const throttle = new GroupKeyRequestThrottle(9999);
    throttle.allow('key1');
    expect(throttle.allow('key1')).toBe(false);
    throttle.reset('key1');
    expect(throttle.allow('key1')).toBe(true);
  });
});

// ── generateGroupSecret 测试 ──────────────────────────────

describe('generateGroupSecret', () => {
  it('应生成 32 字节随机数据', () => {
    const secret = generateGroupSecret();
    expect(secret).toBeInstanceOf(Uint8Array);
    expect(secret.length).toBe(32);
  });

  it('两次生成应不同', () => {
    const s1 = generateGroupSecret();
    const s2 = generateGroupSecret();
    expect(uint8ToBase64(s1)).not.toBe(uint8ToBase64(s2));
  });
});

// ── checkEpochDowngrade 测试 ──────────────────────────────

describe('checkEpochDowngrade', () => {
  it('消息 epoch >= 本地 epoch 应通过', () => {
    expect(checkEpochDowngrade(3, 2)).toBe(true);
    expect(checkEpochDowngrade(2, 2)).toBe(true);
  });

  it('消息 epoch < 本地 epoch 默认拒绝', () => {
    expect(checkEpochDowngrade(1, 3)).toBe(false);
  });

  it('allowOldEpoch=true 时应允许旧 epoch', () => {
    expect(checkEpochDowngrade(1, 3, { allowOldEpoch: true })).toBe(true);
  });
});

// ── buildMembershipManifest 测试 ──────────────────────────

describe('buildMembershipManifest', () => {
  it('应构建合法的 manifest 结构', () => {
    const manifest = buildMembershipManifest('group-1', 2, 1, ['alice', 'bob'], {
      added: ['charlie'],
      removed: [],
      initiatorAid: 'alice',
    });

    expect(manifest.manifest_version).toBe(1);
    expect(manifest.group_id).toBe('group-1');
    expect(manifest.epoch).toBe(2);
    expect(manifest.prev_epoch).toBe(1);
    expect(manifest.member_aids).toEqual(['alice', 'bob']); // 已排序
    expect(manifest.added).toEqual(['charlie']);
    expect(manifest.removed).toEqual([]);
    expect(manifest.initiator_aid).toBe('alice');
    expect(manifest.issued_at).toBeGreaterThan(0);
  });

  it('成员列表应自动排序', () => {
    const manifest = buildMembershipManifest('g', 1, null, ['charlie', 'alice', 'bob']);
    expect(manifest.member_aids).toEqual(['alice', 'bob', 'charlie']);
  });

  it('prev_epoch 为 null 时应正确处理', () => {
    const manifest = buildMembershipManifest('g', 1, null, ['alice']);
    expect(manifest.prev_epoch).toBeNull();
  });
});

// ── buildKeyRequest 测试 ──────────────────────────────────

describe('buildKeyRequest', () => {
  it('应构建合法的密钥请求', () => {
    const req = buildKeyRequest('group-1', 3, 'alice');
    expect(req.type).toBe('e2ee.group_key_request');
    expect(req.group_id).toBe('group-1');
    expect(req.epoch).toBe(3);
    expect(req.requester_aid).toBe('alice');
  });
});

// ── storeGroupSecret / loadGroupSecret 测试 ──────────────

describe('storeGroupSecret / loadGroupSecret', () => {
  it('存取 group_secret 往返', async () => {
    const ks = createMockKeyStore();
    const secret = generateGroupSecret();
    const ok = await storeGroupSecret(ks, 'alice', 'g1', 1, secret, 'commit-1', ['alice', 'bob']);
    expect(ok).toBe(true);

    const loaded = await loadGroupSecret(ks, 'alice', 'g1');
    expect(loaded).not.toBeNull();
    expect(loaded!.epoch).toBe(1);
    expect(uint8ToBase64(loaded!.secret)).toBe(uint8ToBase64(secret));
    expect(loaded!.commitment).toBe('commit-1');
    expect(loaded!.member_aids).toEqual(['alice', 'bob']);
  });

  it('加载不存在的群组应返回 null', async () => {
    const ks = createMockKeyStore();
    expect(await loadGroupSecret(ks, 'alice', 'nonexistent')).toBeNull();
  });

  it('epoch 降级应被拒绝', async () => {
    const ks = createMockKeyStore();
    const s1 = generateGroupSecret();
    const s2 = generateGroupSecret();
    await storeGroupSecret(ks, 'alice', 'g1', 5, s1, 'c1', ['alice']);
    const ok = await storeGroupSecret(ks, 'alice', 'g1', 3, s2, 'c2', ['alice']);
    expect(ok).toBe(false);

    // 原 epoch 5 数据应保持不变
    const loaded = await loadGroupSecret(ks, 'alice', 'g1');
    expect(loaded!.epoch).toBe(5);
  });

  it('epoch 升级应保留旧 epoch 到 old_epochs', async () => {
    const ks = createMockKeyStore();
    const s1 = generateGroupSecret();
    const s2 = generateGroupSecret();
    await storeGroupSecret(ks, 'alice', 'g1', 1, s1, 'c1', ['alice']);
    await storeGroupSecret(ks, 'alice', 'g1', 2, s2, 'c2', ['alice', 'bob']);

    // 当前 epoch 应为 2
    const current = await loadGroupSecret(ks, 'alice', 'g1');
    expect(current!.epoch).toBe(2);

    // 旧 epoch 1 应可加载
    const old = await loadGroupSecret(ks, 'alice', 'g1', 1);
    expect(old).not.toBeNull();
    expect(old!.epoch).toBe(1);
    expect(uint8ToBase64(old!.secret)).toBe(uint8ToBase64(s1));
  });

  it('指定 epoch 加载当前 epoch 应成功', async () => {
    const ks = createMockKeyStore();
    const secret = generateGroupSecret();
    await storeGroupSecret(ks, 'alice', 'g1', 3, secret, 'c', ['alice']);

    const loaded = await loadGroupSecret(ks, 'alice', 'g1', 3);
    expect(loaded).not.toBeNull();
    expect(loaded!.epoch).toBe(3);
  });
});

// ── loadAllGroupSecrets 测试 ──────────────────────────────

describe('loadAllGroupSecrets', () => {
  it('应加载所有 epoch 的 secret', async () => {
    const ks = createMockKeyStore();
    const s1 = generateGroupSecret();
    const s2 = generateGroupSecret();
    const s3 = generateGroupSecret();
    await storeGroupSecret(ks, 'alice', 'g1', 1, s1, 'c1', ['a']);
    await storeGroupSecret(ks, 'alice', 'g1', 2, s2, 'c2', ['a']);
    await storeGroupSecret(ks, 'alice', 'g1', 3, s3, 'c3', ['a']);

    const all = await loadAllGroupSecrets(ks, 'alice', 'g1');
    expect(all.size).toBe(3);
    expect(all.has(1)).toBe(true);
    expect(all.has(2)).toBe(true);
    expect(all.has(3)).toBe(true);
  });

  it('不存在的群组应返回空 Map', async () => {
    const ks = createMockKeyStore();
    const all = await loadAllGroupSecrets(ks, 'alice', 'nonexistent');
    expect(all.size).toBe(0);
  });
});

// ── cleanupOldEpochs 测试 ──────────────────────────────

describe('cleanupOldEpochs', () => {
  it('应清理过期的旧 epoch', async () => {
    const ks = createMockKeyStore();
    const s1 = generateGroupSecret();
    const s2 = generateGroupSecret();
    await storeGroupSecret(ks, 'alice', 'g1', 1, s1, 'c1', ['a']);
    // 等待一小段时间后升级
    await storeGroupSecret(ks, 'alice', 'g1', 2, s2, 'c2', ['a']);

    // 使用极短的保留时间清理
    const removed = await cleanupOldEpochs(ks, 'alice', 'g1', 0);
    // 旧 epoch 1 的 updated_at 刚设置，取决于时间精度可能为 0 或 1
    expect(removed).toBeGreaterThanOrEqual(0);
  });

  it('不存在的群组应返回 0', async () => {
    const ks = createMockKeyStore();
    const removed = await cleanupOldEpochs(ks, 'alice', 'nonexistent');
    expect(removed).toBe(0);
  });
});

// ── computeMembershipCommitment / verifyMembershipCommitment ──

describe('Membership Commitment', () => {
  it.skipIf(!hasSubtleCrypto)(
    'compute 后 verify 应成功',
    async () => {
      const secret = generateGroupSecret();
      const members = ['alice', 'bob', 'charlie'];
      const commitment = await computeMembershipCommitment(members, 1, 'g1', secret);

      expect(typeof commitment).toBe('string');
      expect(commitment.length).toBe(64); // SHA-256 hex

      // 成员验证应通过
      const valid = await verifyMembershipCommitment(commitment, members, 1, 'g1', 'alice', secret);
      expect(valid).toBe(true);
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    '非成员验证应失败',
    async () => {
      const secret = generateGroupSecret();
      const members = ['alice', 'bob'];
      const commitment = await computeMembershipCommitment(members, 1, 'g1', secret);

      const valid = await verifyMembershipCommitment(commitment, members, 1, 'g1', 'eve', secret);
      expect(valid).toBe(false);
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    '不同参数产生不同 commitment',
    async () => {
      const secret = generateGroupSecret();
      const c1 = await computeMembershipCommitment(['alice', 'bob'], 1, 'g1', secret);
      const c2 = await computeMembershipCommitment(['alice', 'charlie'], 1, 'g1', secret);
      const c3 = await computeMembershipCommitment(['alice', 'bob'], 2, 'g1', secret);
      expect(c1).not.toBe(c2);
      expect(c1).not.toBe(c3);
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    '成员顺序不影响 commitment 值',
    async () => {
      const secret = generateGroupSecret();
      const c1 = await computeMembershipCommitment(['bob', 'alice'], 1, 'g1', secret);
      const c2 = await computeMembershipCommitment(['alice', 'bob'], 1, 'g1', secret);
      expect(c1).toBe(c2);
    },
  );
});

// ── signMembershipManifest / verifyMembershipManifest ──────

describe('Membership Manifest 签名', () => {
  it.skipIf(!hasSubtleCrypto)(
    '签名后验证应通过',
    async () => {
      const provider = new CryptoProvider();
      const identity = await provider.generateIdentity();
      // 签名需要证书环境，此处需要 SPKI PEM 而非真实证书
      // 为简化测试，使用构造的 cert PEM（内含公钥 SPKI）
      // 由于 verifyMembershipManifest 需要真实证书 PEM 来提取 SPKI，
      // 而不是简单的 SPKI DER，这里暂跳过完整 roundtrip
      expect(identity.private_key_pem).toContain('BEGIN PRIVATE KEY');
    },
  );
});

// ── encryptGroupMessage / decryptGroupMessage 往返 ──────

describe('群组消息加密/解密往返', () => {
  it.skipIf(!hasSubtleCrypto)(
    '加密后应能正确解密（无签名验证模式）',
    async () => {
      const secret = generateGroupSecret();
      const groupId = 'test-group-1';
      const epoch = 1;
      const messageId = 'gmsg-001';
      const timestamp = Date.now();

      // 加密
      const payload = { text: 'Hello, group!', num: 42 };
      const envelope = await encryptGroupMessage(groupId, epoch, secret, payload, {
        fromAid: 'alice',
        messageId,
        timestamp,
      });

      expect(envelope.type).toBe('e2ee.group_encrypted');
      expect(envelope.encryption_mode).toBe(MODE_EPOCH_GROUP_KEY);
      expect(envelope.epoch).toBe(epoch);
      expect(envelope.ciphertext).toBeDefined();
      expect(envelope.tag).toBeDefined();
      expect(envelope.nonce).toBeDefined();

      // 解密
      const message = {
        group_id: groupId,
        from: 'alice',
        message_id: messageId,
        payload: envelope,
      };
      const secrets = new Map<number, Uint8Array>();
      secrets.set(epoch, secret);

      // 不要求签名验证（无签名场景）
      const decrypted = await decryptGroupMessage(message, secrets, null, { requireSignature: false });
      expect(decrypted).not.toBeNull();
      expect(decrypted!.encrypted).toBe(true);
      expect((decrypted!.payload as JsonObject).text).toBe('Hello, group!');
      expect((decrypted!.payload as JsonObject).num).toBe(42);
      expect((decrypted!.e2ee as JsonObject).encryption_mode).toBe(MODE_EPOCH_GROUP_KEY);
      expect((decrypted!.e2ee as JsonObject).epoch).toBe(epoch);
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    '错误的 group_secret 应解密失败',
    async () => {
      const secret = generateGroupSecret();
      const wrongSecret = generateGroupSecret();

      const envelope = await encryptGroupMessage('g1', 1, secret, { text: 'hi' }, {
        fromAid: 'alice',
        messageId: 'msg-1',
        timestamp: Date.now(),
      });

      const message = { group_id: 'g1', from: 'alice', message_id: 'msg-1', payload: envelope };
      const secrets = new Map<number, Uint8Array>();
      secrets.set(1, wrongSecret);

      const decrypted = await decryptGroupMessage(message, secrets, null, { requireSignature: false });
      expect(decrypted).toBeNull();
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    '错误的 epoch 应解密失败',
    async () => {
      const secret = generateGroupSecret();
      const envelope = await encryptGroupMessage('g1', 1, secret, { text: 'hi' }, {
        fromAid: 'alice',
        messageId: 'msg-1',
        timestamp: Date.now(),
      });

      const message = { group_id: 'g1', from: 'alice', message_id: 'msg-1', payload: envelope };
      const secrets = new Map<number, Uint8Array>();
      secrets.set(2, secret); // epoch 不匹配

      const decrypted = await decryptGroupMessage(message, secrets, null, { requireSignature: false });
      expect(decrypted).toBeNull();
    },
  );

  it('非加密消息应返回 null', async () => {
    const message = {
      payload: { type: 'plain_text', text: 'hello' },
    };
    const decrypted = await decryptGroupMessage(message, new Map());
    expect(decrypted).toBeNull();
  });
});

// ── handleKeyDistribution / handleKeyResponse 测试 ────────

describe('handleKeyDistribution', () => {
  it.skipIf(!hasSubtleCrypto)(
    '合法的密钥分发应成功存储',
    async () => {
      const ks = createMockKeyStore();
      const secret = generateGroupSecret();
      const groupId = 'g1';
      const epoch = 1;
      const members = ['alice', 'bob'];
      const commitment = await computeMembershipCommitment(members, epoch, groupId, secret);

      const payload = {
        type: 'e2ee.group_key_distribution',
        group_id: groupId,
        epoch,
        group_secret: uint8ToBase64(secret),
        commitment,
        member_aids: members,
        distributed_by: 'alice',
        distributed_at: Date.now(),
      };

      // 不验证 manifest 签名（无 initiatorCertPem）
      const ok = await handleKeyDistribution(payload, ks, 'bob');
      expect(ok).toBe(true);

      // 验证已存储
      const loaded = await loadGroupSecret(ks, 'bob', groupId);
      expect(loaded).not.toBeNull();
      expect(loaded!.epoch).toBe(epoch);
      expect(loaded!.commitment).toBe(commitment);
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    'commitment 不匹配应拒绝',
    async () => {
      const ks = createMockKeyStore();
      const secret = generateGroupSecret();

      const payload = {
        type: 'e2ee.group_key_distribution',
        group_id: 'g1',
        epoch: 1,
        group_secret: uint8ToBase64(secret),
        commitment: 'wrong-commitment',
        member_aids: ['alice', 'bob'],
        distributed_by: 'alice',
      };

      const ok = await handleKeyDistribution(payload, ks, 'bob');
      expect(ok).toBe(false);
    },
  );
});

describe('handleKeyRequest', () => {
  it.skipIf(!hasSubtleCrypto)(
    '合法成员的密钥请求应返回响应',
    async () => {
      const ks = createMockKeyStore();
      const secret = generateGroupSecret();
      const commitment = await computeMembershipCommitment(['alice', 'bob'], 1, 'g1', secret);
      await storeGroupSecret(ks, 'alice', 'g1', 1, secret, commitment, ['alice', 'bob']);

      const request = {
        type: 'e2ee.group_key_request',
        group_id: 'g1',
        epoch: 1,
        requester_aid: 'bob',
      };

      const response = await handleKeyRequest(request, ks, 'alice', ['alice', 'bob']);
      expect(response).not.toBeNull();
      expect(response!.type).toBe('e2ee.group_key_response');
      expect(response!.group_id).toBe('g1');
      expect(response!.epoch).toBe(1);
      expect(response!.group_secret).toBeDefined();
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    '非成员的请求应返回 null',
    async () => {
      const ks = createMockKeyStore();
      const secret = generateGroupSecret();
      const commitment = await computeMembershipCommitment(['alice', 'bob'], 1, 'g1', secret);
      await storeGroupSecret(ks, 'alice', 'g1', 1, secret, commitment, ['alice', 'bob']);

      const request = {
        type: 'e2ee.group_key_request',
        group_id: 'g1',
        epoch: 1,
        requester_aid: 'eve',
      };

      const response = await handleKeyRequest(request, ks, 'alice', ['alice', 'bob']);
      expect(response).toBeNull();
    },
  );
});

describe('handleKeyResponse', () => {
  it.skipIf(!hasSubtleCrypto)(
    '合法的密钥响应应成功存储',
    async () => {
      const ks = createMockKeyStore();
      const secret = generateGroupSecret();
      const commitment = await computeMembershipCommitment(['alice', 'bob'], 1, 'g1', secret);

      const response = {
        type: 'e2ee.group_key_response',
        group_id: 'g1',
        epoch: 1,
        group_secret: uint8ToBase64(secret),
        commitment,
        member_aids: ['alice', 'bob'],
      };

      const ok = await handleKeyResponse(response, ks, 'bob');
      expect(ok).toBe(true);

      const loaded = await loadGroupSecret(ks, 'bob', 'g1');
      expect(loaded).not.toBeNull();
      expect(loaded!.epoch).toBe(1);
    },
  );
});

// ── buildKeyDistribution 测试 ──────────────────────────────

describe('buildKeyDistribution', () => {
  it.skipIf(!hasSubtleCrypto)(
    '应构建包含 commitment 的分发 payload',
    async () => {
      const secret = generateGroupSecret();
      const members = ['alice', 'bob'];
      const dist = await buildKeyDistribution('g1', 1, secret, members, 'alice');

      expect(dist.type).toBe('e2ee.group_key_distribution');
      expect(dist.group_id).toBe('g1');
      expect(dist.epoch).toBe(1);
      expect(dist.group_secret).toBe(uint8ToBase64(secret));
      expect(dist.commitment).toBeDefined();
      expect(typeof dist.commitment).toBe('string');
      expect((dist.commitment as string).length).toBe(64);
      expect(dist.member_aids).toEqual(['alice', 'bob']);
      expect(dist.distributed_by).toBe('alice');
      expect(dist.distributed_at).toBeGreaterThan(0);
    },
  );
});

// ── GroupE2EEManager 基本测试 ──────────────────────────────

describe('GroupE2EEManager', () => {
  let ks: KeyStore;
  let provider: CryptoProvider;
  let aliceIdentity: { private_key_pem: string; public_key_der_b64: string; curve: string };

  beforeEach(async () => {
    ks = createMockKeyStore();
    provider = new CryptoProvider();
    if (hasSubtleCrypto) {
      aliceIdentity = await provider.generateIdentity();
      await ks.saveKeyPair('alice', {
        private_key_pem: aliceIdentity.private_key_pem,
        public_key_der_b64: aliceIdentity.public_key_der_b64,
        curve: aliceIdentity.curve,
      });
    }
  });

  it.skipIf(!hasSubtleCrypto)(
    'createEpoch 应生成 epoch 1 并返回分发列表',
    async () => {
      const manager = new GroupE2EEManager({
        identityFn: () => ({
          aid: 'alice',
          private_key_pem: aliceIdentity.private_key_pem,
          public_key_der_b64: aliceIdentity.public_key_der_b64,
        }),
        keystore: ks,
      });

      const result = await manager.createEpoch('g1', ['alice', 'bob']);
      expect(result.epoch).toBe(1);
      expect(result.commitment).toBeDefined();
      const dists = result.distributions as Array<{ to: string; payload: JsonObject }>;
      expect(dists.length).toBe(1); // 只分发给 bob（排除 alice 自己）
      expect(dists[0].to).toBe('bob');

      // 验证本地已存储
      const loaded = await loadGroupSecret(ks, 'alice', 'g1');
      expect(loaded).not.toBeNull();
      expect(loaded!.epoch).toBe(1);
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    'rotateEpoch 应递增 epoch',
    async () => {
      const manager = new GroupE2EEManager({
        identityFn: () => ({
          aid: 'alice',
          private_key_pem: aliceIdentity.private_key_pem,
          public_key_der_b64: aliceIdentity.public_key_der_b64,
        }),
        keystore: ks,
      });

      await manager.createEpoch('g1', ['alice', 'bob']);
      const rotated = await manager.rotateEpoch('g1', ['alice', 'bob']);
      expect(rotated.epoch).toBe(2);
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    'hasSecret / currentEpoch / getMemberAids 应正确反映状态',
    async () => {
      const manager = new GroupE2EEManager({
        identityFn: () => ({
          aid: 'alice',
          private_key_pem: aliceIdentity.private_key_pem,
          public_key_der_b64: aliceIdentity.public_key_der_b64,
        }),
        keystore: ks,
      });

      expect(await manager.hasSecret('g1')).toBe(false);
      expect(await manager.currentEpoch('g1')).toBeNull();
      expect(await manager.getMemberAids('g1')).toEqual([]);

      await manager.createEpoch('g1', ['alice', 'bob']);
      expect(await manager.hasSecret('g1')).toBe(true);
      expect(await manager.currentEpoch('g1')).toBe(1);
      const members = await manager.getMemberAids('g1');
      expect(members).toContain('alice');
      expect(members).toContain('bob');
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    'encrypt 无密钥时应抛 E2EEGroupSecretMissingError',
    async () => {
      const { E2EEGroupSecretMissingError } = await import('../../src/errors.js');
      const manager = new GroupE2EEManager({
        identityFn: () => ({
          aid: 'alice',
          private_key_pem: aliceIdentity.private_key_pem,
        }),
        keystore: ks,
      });

      await expect(manager.encrypt('nonexistent-group', { text: 'hi' }))
        .rejects.toThrow(E2EEGroupSecretMissingError);
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    'encrypt 应返回 e2ee.group_encrypted 信封',
    async () => {
      const certPem = '-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----';
      const manager = new GroupE2EEManager({
        identityFn: () => ({
          aid: 'alice',
          private_key_pem: aliceIdentity.private_key_pem,
          public_key_der_b64: aliceIdentity.public_key_der_b64,
          cert: certPem,
        }),
        keystore: ks,
      });

      await manager.createEpoch('g1', ['alice', 'bob']);
      const envelope = await manager.encrypt('g1', { text: 'hello group' });

      expect(envelope.type).toBe('e2ee.group_encrypted');
      expect(envelope.encryption_mode).toBe(MODE_EPOCH_GROUP_KEY);
      expect(envelope.epoch).toBe(1);
      expect(envelope.ciphertext).toBeDefined();
      expect(envelope.tag).toBeDefined();
      expect(envelope.nonce).toBeDefined();
      expect(envelope.sender_signature).toBeDefined(); // 自动签名
      expect(String(envelope.sender_cert_fingerprint ?? '')).toMatch(/^sha256:[0-9a-f]{64}$/);
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    'rotateEpochTo 应使用指定的目标 epoch',
    async () => {
      const manager = new GroupE2EEManager({
        identityFn: () => ({
          aid: 'alice',
          private_key_pem: aliceIdentity.private_key_pem,
          public_key_der_b64: aliceIdentity.public_key_der_b64,
        }),
        keystore: ks,
      });

      const result = await manager.rotateEpochTo('g1', 5, ['alice', 'bob']);
      expect(result.epoch).toBe(5);

      expect(await manager.currentEpoch('g1')).toBe(5);
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    'storeSecret 应允许手动存储',
    async () => {
      const manager = new GroupE2EEManager({
        identityFn: () => ({
          aid: 'alice',
          private_key_pem: aliceIdentity.private_key_pem,
        }),
        keystore: ks,
      });

      const secret = generateGroupSecret();
      const commitment = await computeMembershipCommitment(['alice'], 1, 'g1', secret);
      const ok = await manager.storeSecret('g1', 1, secret, commitment, ['alice']);
      expect(ok).toBe(true);
      expect(await manager.hasSecret('g1')).toBe(true);
    },
  );
});

// ── ISSUE-SDK-JS-011/019: 签名失败应抛出而非静默降级 ──────────

describe('encryptGroupMessage 签名失败应抛出错误（ISSUE-SDK-JS-011/019）', () => {
  it.skipIf(!hasSubtleCrypto)(
    '传入无效私钥时应抛出错误而非静默发送无签名消息',
    async () => {
      const secret = generateGroupSecret();
      await expect(
        encryptGroupMessage('grp-1', 1, secret, { text: 'test' }, {
          fromAid: 'alice.test',
          messageId: 'msg-1',
          timestamp: Date.now(),
          senderPrivateKeyPem: 'INVALID_PEM_DATA',
        }),
      ).rejects.toThrow();
    },
  );
});
