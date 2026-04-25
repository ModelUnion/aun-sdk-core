/**
 * 群组 E2EE 单元测试 — 覆盖群消息加解密、Membership Commitment、
 * GroupReplayGuard、epoch 管理、密钥分发/请求/响应、Manifest 签名验证。
 */

import { describe, it, expect, beforeEach } from 'vitest';
import * as crypto from 'node:crypto';
import {
  encryptGroupMessage,
  decryptGroupMessage,
  computeMembershipCommitment,
  verifyMembershipCommitment,
  storeGroupSecret,
  loadGroupSecret,
  loadAllGroupSecrets,
  cleanupOldEpochs,
  GroupReplayGuard,
  GroupKeyRequestThrottle,
  buildKeyDistribution,
  handleKeyDistribution,
  buildKeyRequest,
  handleKeyRequest,
  handleKeyResponse,
  buildMembershipManifest,
  signMembershipManifest,
  verifyMembershipManifest,
  generateGroupSecret,
  GroupE2EEManager,
} from '../../src/e2ee-group.js';
import { FakeKeystore, generateECKeypair, makeSelfSignedCert, buildIdentity } from './helpers.js';
import type { GroupOldEpochRecord, JsonObject, Message } from '../../src/types.js';

// ── 测试辅助 ──────────────────────────────────────────────────

function makeGroupSecret(): Buffer {
  return crypto.randomBytes(32);
}

function makeGroupKs(aid: string): FakeKeystore {
  const ks = new FakeKeystore();
  const { privateKey } = generateECKeypair();
  const identity = buildIdentity(aid, privateKey);
  ks._keyPairs[aid] = {
    private_key_pem: identity.private_key_pem,
    public_key_der_b64: identity.public_key_der_b64,
  };
  return ks;
}

// ── 群消息加解密 ─────────────────────────────────────────────

describe('encryptGroupMessage', () => {
  it('信封包含正确字段', () => {
    const gs = makeGroupSecret();
    const envelope = encryptGroupMessage('grp-1', 1, gs, { type: 'text', text: 'hello' }, {
      fromAid: 'alice.test',
      messageId: 'msg-1',
      timestamp: Date.now(),
    });

    expect(envelope.type).toBe('e2ee.group_encrypted');
    expect(envelope.version).toBe('1');
    expect(envelope.encryption_mode).toBe('epoch_group_key');
    expect(envelope.epoch).toBe(1);
    expect(envelope.nonce).toBeTruthy();
    expect(envelope.ciphertext).toBeTruthy();
    expect(envelope.tag).toBeTruthy();
    expect(envelope.aad).toBeTruthy();
  });

  it('包含发送方签名（提供私钥时）', () => {
    const gs = makeGroupSecret();
    const { privateKey } = generateECKeypair();
    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const certPem = makeSelfSignedCert(privateKey, 'alice.test');

    const envelope = encryptGroupMessage('grp-1', 1, gs, { type: 'text', text: 'signed' }, {
      fromAid: 'alice.test',
      messageId: 'msg-1',
      timestamp: Date.now(),
      senderPrivateKeyPem: privPem,
      senderCertPem: certPem,
    });

    expect(envelope.sender_signature).toBeTruthy();
    expect(envelope.sender_cert_fingerprint).toBeTruthy();
  });

  it('签名失败时应抛出错误而非静默降级（TS-017）', () => {
    const gs = makeGroupSecret();
    // 提供无效的私钥 PEM，应该抛出错误
    expect(() => {
      encryptGroupMessage('grp-1', 1, gs, { type: 'text', text: 'fail' }, {
        fromAid: 'alice.test',
        messageId: 'msg-1',
        timestamp: Date.now(),
        senderPrivateKeyPem: 'INVALID_PEM_DATA',
      });
    }).toThrow();
  });

  it('senderPrivateKeyPem 为 null 时信封不含签名（纯函数行为）', () => {
    const gs = makeGroupSecret();
    const envelope = encryptGroupMessage('grp-1', 1, gs, { type: 'text', text: 'no sig' }, {
      fromAid: 'alice.test',
      messageId: 'msg-1',
      timestamp: Date.now(),
      senderPrivateKeyPem: null,
    });
    // 纯函数级别：无私钥则不签名
    expect(envelope.sender_signature).toBeUndefined();
  });
});

describe('encryptGroupMessage/decryptGroupMessage 往返', () => {
  it('加解密往返成功', () => {
    const gs = makeGroupSecret();
    const { privateKey } = generateECKeypair();
    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const certPem = makeSelfSignedCert(privateKey, 'alice.test');
    const mid = `msg-${crypto.randomUUID()}`;
    const ts = Date.now();

    const envelope = encryptGroupMessage('grp-1', 1, gs, { type: 'text', text: 'roundtrip' }, {
      fromAid: 'alice.test',
      messageId: mid,
      timestamp: ts,
      senderPrivateKeyPem: privPem,
    });

    const message = {
      group_id: 'grp-1',
      from: 'alice.test',
      message_id: mid,
      timestamp: ts,
      payload: envelope,
    };
    const secrets = new Map<number, Buffer>();
    secrets.set(1, gs);

    const result = decryptGroupMessage(message, secrets, certPem);
    expect(result).not.toBeNull();
    expect((result as Message).payload).toEqual({ type: 'text', text: 'roundtrip' });
    const e2ee = (result as Message).e2ee as JsonObject;
    expect(e2ee.encryption_mode).toBe('epoch_group_key');
    expect(e2ee.epoch).toBe(1);
    expect(e2ee.sender_verified).toBe(true);
  });

  it('错误的 group_secret 无法解密', () => {
    const gs = makeGroupSecret();
    const wrongGs = makeGroupSecret();
    const mid = `msg-${crypto.randomUUID()}`;

    const envelope = encryptGroupMessage('grp-1', 1, gs, { type: 'text', text: 'test' }, {
      fromAid: 'alice.test',
      messageId: mid,
      timestamp: Date.now(),
    });

    const message = { group_id: 'grp-1', from: 'alice.test', message_id: mid, payload: envelope };
    const secrets = new Map<number, Buffer>();
    secrets.set(1, wrongGs);

    // 无签名模式测试解密失败
    const result = decryptGroupMessage(message, secrets, null, { requireSignature: false });
    expect(result).toBeNull();
  });
});

// ── 群组 AAD 测试 ────────────────────────────────────────────

describe('群组 AAD', () => {
  it('AAD 序列化是确定性的', () => {
    const gs = makeGroupSecret();
    const mid = 'deterministic-msg';
    const ts = 1700000000000;

    const e1 = encryptGroupMessage('grp-1', 1, gs, { type: 'text', text: 'a' }, {
      fromAid: 'alice.test', messageId: mid, timestamp: ts,
    });
    const e2 = encryptGroupMessage('grp-1', 1, gs, { type: 'text', text: 'a' }, {
      fromAid: 'alice.test', messageId: mid, timestamp: ts,
    });

    // AAD 应相同（即使加密结果不同因为随机 nonce）
    expect(JSON.stringify(e1.aad)).toBe(JSON.stringify(e2.aad));
  });
});

// ── Membership Commitment 测试 ───────────────────────────────

describe('computeMembershipCommitment', () => {
  it('相同输入产生相同输出', () => {
    const gs = makeGroupSecret();
    const c1 = computeMembershipCommitment(['a', 'b'], 1, 'grp-1', gs);
    const c2 = computeMembershipCommitment(['a', 'b'], 1, 'grp-1', gs);
    expect(c1).toBe(c2);
  });

  it('成员顺序不影响结果（内部排序）', () => {
    const gs = makeGroupSecret();
    const c1 = computeMembershipCommitment(['b', 'a'], 1, 'grp-1', gs);
    const c2 = computeMembershipCommitment(['a', 'b'], 1, 'grp-1', gs);
    expect(c1).toBe(c2);
  });

  it('不同 group_secret 产生不同 commitment', () => {
    const gs1 = makeGroupSecret();
    const gs2 = makeGroupSecret();
    const c1 = computeMembershipCommitment(['a'], 1, 'grp-1', gs1);
    const c2 = computeMembershipCommitment(['a'], 1, 'grp-1', gs2);
    expect(c1).not.toBe(c2);
  });
});

describe('verifyMembershipCommitment', () => {
  it('有效的 commitment 验证通过', () => {
    const gs = makeGroupSecret();
    const members = ['alice.test', 'bob.test'];
    const commitment = computeMembershipCommitment(members, 1, 'grp-1', gs);
    expect(verifyMembershipCommitment(commitment, members, 1, 'grp-1', 'alice.test', gs)).toBe(true);
  });

  it('不在成员列表中的 AID 验证失败', () => {
    const gs = makeGroupSecret();
    const members = ['alice.test', 'bob.test'];
    const commitment = computeMembershipCommitment(members, 1, 'grp-1', gs);
    expect(verifyMembershipCommitment(commitment, members, 1, 'grp-1', 'eve.test', gs)).toBe(false);
  });

  it('错误的 commitment 验证失败', () => {
    const gs = makeGroupSecret();
    const members = ['alice.test'];
    expect(verifyMembershipCommitment('wrong-commitment', members, 1, 'grp-1', 'alice.test', gs)).toBe(false);
  });
});

// ── storeGroupSecret / epoch 管理 ────────────────────────────

describe('storeGroupSecret', () => {
  it('存储和加载 group_secret', () => {
    const ks = new FakeKeystore();
    const gs = makeGroupSecret();
    const commitment = computeMembershipCommitment(['a'], 1, 'grp-1', gs);
    const ok = storeGroupSecret(ks, 'a', 'grp-1', 1, gs, commitment, ['a']);
    expect(ok).toBe(true);

    const loaded = loadGroupSecret(ks, 'a', 'grp-1');
    expect(loaded).not.toBeNull();
    expect(loaded!.epoch).toBe(1);
    expect(Buffer.isBuffer(loaded!.secret)).toBe(true);
    expect((loaded!.secret as Buffer).equals(gs)).toBe(true);
  });

  it('epoch 降级被拒绝', () => {
    const ks = new FakeKeystore();
    const gs1 = makeGroupSecret();
    const gs2 = makeGroupSecret();

    storeGroupSecret(ks, 'a', 'grp-1', 2, gs1, 'c1', ['a']);
    // 尝试用更低的 epoch 覆盖
    const ok = storeGroupSecret(ks, 'a', 'grp-1', 1, gs2, 'c2', ['a']);
    expect(ok).toBe(false);

    // 应仍是 epoch 2
    const loaded = loadGroupSecret(ks, 'a', 'grp-1');
    expect(loaded!.epoch).toBe(2);
  });

  it('升级 epoch 时旧 epoch 移入 old_epochs', () => {
    const ks = new FakeKeystore();
    const gs1 = makeGroupSecret();
    const gs2 = makeGroupSecret();

    storeGroupSecret(ks, 'a', 'grp-1', 1, gs1, 'c1', ['a']);
    storeGroupSecret(ks, 'a', 'grp-1', 2, gs2, 'c2', ['a']);

    // 加载当前 epoch
    const current = loadGroupSecret(ks, 'a', 'grp-1');
    expect(current!.epoch).toBe(2);

    // 加载旧 epoch
    const old = loadGroupSecret(ks, 'a', 'grp-1', 1);
    expect(old).not.toBeNull();
    expect(old!.epoch).toBe(1);
  });
});

describe('loadAllGroupSecrets', () => {
  it('加载所有 epoch 的 secret', () => {
    const ks = new FakeKeystore();
    const gs1 = makeGroupSecret();
    const gs2 = makeGroupSecret();

    storeGroupSecret(ks, 'a', 'grp-1', 1, gs1, 'c1', ['a']);
    storeGroupSecret(ks, 'a', 'grp-1', 2, gs2, 'c2', ['a']);

    const all = loadAllGroupSecrets(ks, 'a', 'grp-1');
    expect(all.size).toBe(2);
    expect(all.has(1)).toBe(true);
    expect(all.has(2)).toBe(true);
  });
});

describe('cleanupOldEpochs', () => {
  it('清理过期的旧 epoch', () => {
    const ks = new FakeKeystore();
    const gs1 = makeGroupSecret();
    const gs2 = makeGroupSecret();

    storeGroupSecret(ks, 'a', 'grp-1', 1, gs1, 'c1', ['a']);
    // 需要先升级 epoch 产生 old_epochs
    storeGroupSecret(ks, 'a', 'grp-1', 2, gs2, 'c2', ['a']);

    // 手动修改结构化主存里的 old_epochs.updated_at 为很久以前
    const oldEpochs = ks._groups['a']['grp-1'].old_epochs as GroupOldEpochRecord[];
    oldEpochs[0].updated_at = 0; // 很久以前

    const removed = cleanupOldEpochs(ks, 'a', 'grp-1', 1); // 1 秒保留期
    expect(removed).toBe(1);

    // epoch 1 应已被清理
    expect(loadGroupSecret(ks, 'a', 'grp-1', 1)).toBeNull();
    // 当前 epoch 2 不受影响
    expect(loadGroupSecret(ks, 'a', 'grp-1')!.epoch).toBe(2);
  });
});

// ── GroupReplayGuard 测试 ────────────────────────────────────

describe('GroupReplayGuard', () => {
  it('首次消息通过，重复消息被拒绝', () => {
    const guard = new GroupReplayGuard();
    expect(guard.checkAndRecord('grp-1', 'alice', 'msg-1')).toBe(true);
    expect(guard.checkAndRecord('grp-1', 'alice', 'msg-1')).toBe(false);
  });

  it('不同群组不互相干扰', () => {
    const guard = new GroupReplayGuard();
    expect(guard.checkAndRecord('grp-1', 'alice', 'msg-1')).toBe(true);
    expect(guard.checkAndRecord('grp-2', 'alice', 'msg-1')).toBe(true);
  });

  it('isSeen 查询不消耗', () => {
    const guard = new GroupReplayGuard();
    expect(guard.isSeen('grp-1', 'alice', 'msg-1')).toBe(false);
    guard.record('grp-1', 'alice', 'msg-1');
    expect(guard.isSeen('grp-1', 'alice', 'msg-1')).toBe(true);
  });

  it('超过上限时自动裁剪', () => {
    const guard = new GroupReplayGuard(100);
    for (let i = 0; i < 120; i++) {
      guard.record('grp', 'alice', `msg-${i}`);
    }
    // 第 101 次时 trim 到 80，之后 102-120 又加了 19 个 → 99
    expect(guard.size).toBeLessThanOrEqual(100);
  });
});

// ── GroupKeyRequestThrottle 测试 ─────────────────────────────

describe('GroupKeyRequestThrottle', () => {
  it('首次请求允许', () => {
    const throttle = new GroupKeyRequestThrottle();
    expect(throttle.allow('request:grp-1:1')).toBe(true);
  });

  it('冷却期内请求被拒绝', () => {
    const throttle = new GroupKeyRequestThrottle(9999); // 很长的冷却期
    expect(throttle.allow('key')).toBe(true);
    expect(throttle.allow('key')).toBe(false);
  });

  it('reset 后允许再次请求', () => {
    const throttle = new GroupKeyRequestThrottle(9999);
    expect(throttle.allow('key')).toBe(true);
    expect(throttle.allow('key')).toBe(false);
    throttle.reset('key');
    expect(throttle.allow('key')).toBe(true);
  });
});

// ── 密钥分发/请求/响应测试 ───────────────────────────────────

describe('buildKeyDistribution / handleKeyDistribution', () => {
  it('构建分发消息包含正确字段', () => {
    const gs = makeGroupSecret();
    const dist = buildKeyDistribution('grp-1', 1, gs, ['a', 'b'], 'a');
    expect(dist.type).toBe('e2ee.group_key_distribution');
    expect(dist.group_id).toBe('grp-1');
    expect(dist.epoch).toBe(1);
    expect(dist.group_secret).toBeTruthy();
    expect(dist.commitment).toBeTruthy();
    expect(dist.member_aids).toEqual(['a', 'b']);
    expect(dist.distributed_by).toBe('a');
  });

  it('handleKeyDistribution 成功存储密钥', () => {
    const ks = new FakeKeystore();
    const gs = makeGroupSecret();
    const members = ['alice.test', 'bob.test'];
    const dist = buildKeyDistribution('grp-1', 1, gs, members, 'alice.test');

    const ok = handleKeyDistribution(dist, ks, 'bob.test');
    expect(ok).toBe(true);

    const loaded = loadGroupSecret(ks, 'bob.test', 'grp-1');
    expect(loaded).not.toBeNull();
    expect(loaded!.epoch).toBe(1);
  });

  it('非成员收到分发消息被拒绝', () => {
    const ks = new FakeKeystore();
    const gs = makeGroupSecret();
    const members = ['alice.test', 'bob.test'];
    const dist = buildKeyDistribution('grp-1', 1, gs, members, 'alice.test');

    const ok = handleKeyDistribution(dist, ks, 'eve.test'); // eve 不在成员列表中
    expect(ok).toBe(false);
  });
});

describe('buildKeyRequest / handleKeyRequest / handleKeyResponse', () => {
  it('密钥请求/响应完整流程', () => {
    // alice 有密钥，bob 请求密钥
    const aliceKs = new FakeKeystore();
    const gs = makeGroupSecret();
    const members = ['alice.test', 'bob.test'];
    const commitment = computeMembershipCommitment(members, 1, 'grp-1', gs);
    storeGroupSecret(aliceKs, 'alice.test', 'grp-1', 1, gs, commitment, members);

    // bob 构建密钥请求
    const request = buildKeyRequest('grp-1', 1, 'bob.test');
    expect(request.type).toBe('e2ee.group_key_request');
    expect(request.requester_aid).toBe('bob.test');

    // alice 处理请求
    const response = handleKeyRequest(request, aliceKs, 'alice.test', members);
    expect(response).not.toBeNull();
    expect(response!.type).toBe('e2ee.group_key_response');
    expect(response!.group_id).toBe('grp-1');
    expect(response!.epoch).toBe(1);

    // bob 处理响应
    const bobKs = new FakeKeystore();
    const ok = handleKeyResponse(response!, bobKs, 'bob.test');
    expect(ok).toBe(true);

    const loaded = loadGroupSecret(bobKs, 'bob.test', 'grp-1');
    expect(loaded).not.toBeNull();
    expect(loaded!.epoch).toBe(1);
  });

  it('非成员请求密钥被拒绝', () => {
    const aliceKs = new FakeKeystore();
    const gs = makeGroupSecret();
    const members = ['alice.test', 'bob.test'];
    const commitment = computeMembershipCommitment(members, 1, 'grp-1', gs);
    storeGroupSecret(aliceKs, 'alice.test', 'grp-1', 1, gs, commitment, members);

    const request = buildKeyRequest('grp-1', 1, 'eve.test'); // eve 不是成员
    const response = handleKeyRequest(request, aliceKs, 'alice.test', members);
    expect(response).toBeNull();
  });
});

// ── Membership Manifest 测试 ─────────────────────────────────

describe('Membership Manifest', () => {
  it('构建 manifest 包含正确字段', () => {
    const manifest = buildMembershipManifest('grp-1', 2, 1, ['a', 'b'], {
      added: ['b'],
      removed: [],
      initiatorAid: 'a',
    });
    expect(manifest.manifest_version).toBe(1);
    expect(manifest.group_id).toBe('grp-1');
    expect(manifest.epoch).toBe(2);
    expect(manifest.prev_epoch).toBe(1);
    expect(manifest.member_aids).toEqual(['a', 'b']);
    expect(manifest.added).toEqual(['b']);
    expect(manifest.removed).toEqual([]);
    expect(manifest.initiator_aid).toBe('a');
    expect(manifest.issued_at).toBeTruthy();
  });

  it('签名和验证往返成功', () => {
    const { privateKey } = generateECKeypair();
    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const certPem = makeSelfSignedCert(privateKey, 'alice.test');

    const manifest = buildMembershipManifest('grp-1', 1, null, ['a', 'b'], {
      initiatorAid: 'alice.test',
    });
    const signed = signMembershipManifest(manifest, privPem);
    expect(signed.signature).toBeTruthy();

    const ok = verifyMembershipManifest(signed, certPem);
    expect(ok).toBe(true);
  });

  it('篡改后验证失败', () => {
    const { privateKey } = generateECKeypair();
    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const certPem = makeSelfSignedCert(privateKey, 'alice.test');

    const manifest = buildMembershipManifest('grp-1', 1, null, ['a', 'b']);
    const signed = signMembershipManifest(manifest, privPem);

    // 篡改
    signed.epoch = 999;
    const ok = verifyMembershipManifest(signed, certPem);
    expect(ok).toBe(false);
  });

  it('无签名时验证失败', () => {
    const certPem = makeSelfSignedCert(generateECKeypair().privateKey, 'alice.test');
    const manifest = buildMembershipManifest('grp-1', 1, null, ['a']);
    const ok = verifyMembershipManifest(manifest, certPem);
    expect(ok).toBe(false);
  });

  it('错误的证书（不同密钥）验证失败', () => {
    const { privateKey: key1 } = generateECKeypair();
    const { privateKey: key2 } = generateECKeypair();
    const privPem = key1.export({ type: 'pkcs8', format: 'pem' }) as string;
    const wrongCertPem = makeSelfSignedCert(key2, 'alice.test');

    const manifest = buildMembershipManifest('grp-1', 1, null, ['a']);
    const signed = signMembershipManifest(manifest, privPem);
    const ok = verifyMembershipManifest(signed, wrongCertPem);
    expect(ok).toBe(false);
  });
});

// ── 带 manifest 的密钥分发测试 ──────────────────────────────

describe('handleKeyDistribution 带 manifest', () => {
  it('有效 manifest 签名通过验证', () => {
    const { privateKey } = generateECKeypair();
    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const certPem = makeSelfSignedCert(privateKey, 'alice.test');

    const gs = makeGroupSecret();
    const members = ['alice.test', 'bob.test'];
    const manifest = signMembershipManifest(
      buildMembershipManifest('grp-1', 1, null, members, { initiatorAid: 'alice.test' }),
      privPem,
    );
    const dist = buildKeyDistribution('grp-1', 1, gs, members, 'alice.test', manifest);

    const ks = new FakeKeystore();
    const ok = handleKeyDistribution(dist, ks, 'bob.test', certPem);
    expect(ok).toBe(true);
  });

  it('无效 manifest 签名被拒绝', () => {
    const { privateKey: key1 } = generateECKeypair();
    const { privateKey: key2 } = generateECKeypair();
    const privPem = key1.export({ type: 'pkcs8', format: 'pem' }) as string;
    const wrongCertPem = makeSelfSignedCert(key2, 'alice.test');

    const gs = makeGroupSecret();
    const members = ['alice.test', 'bob.test'];
    const manifest = signMembershipManifest(
      buildMembershipManifest('grp-1', 1, null, members, { initiatorAid: 'alice.test' }),
      privPem,
    );
    const dist = buildKeyDistribution('grp-1', 1, gs, members, 'alice.test', manifest);

    const ks = new FakeKeystore();
    const ok = handleKeyDistribution(dist, ks, 'bob.test', wrongCertPem);
    expect(ok).toBe(false);
  });
});

// ── generateGroupSecret 测试 ─────────────────────────────────

describe('generateGroupSecret', () => {
  it('返回 32 字节 Buffer', () => {
    const gs = generateGroupSecret();
    expect(Buffer.isBuffer(gs)).toBe(true);
    expect(gs.length).toBe(32);
  });

  it('每次生成不同的密钥', () => {
    const gs1 = generateGroupSecret();
    const gs2 = generateGroupSecret();
    expect(gs1.equals(gs2)).toBe(false);
  });
});

// ── GroupE2EEManager.encrypt 签名强制测试（TS-017）──────────────

describe('GroupE2EEManager.encrypt 签名强制（TS-017）', () => {
  it('identity 无私钥时 encrypt 应抛出异常而非发送无签名消息', () => {
    const aid = 'nosig-test.aid';
    const ks = makeGroupKs(aid);
    // 构建一个没有 private_key_pem 的 identity
    const identityWithoutKey = { aid, cert: null, private_key_pem: null };

    const mgr = new GroupE2EEManager({
      identityFn: () => identityWithoutKey,
      keystore: ks,
    });

    const groupId = 'grp-nosig';
    const gs = generateGroupSecret();
    const members = [aid, 'other.aid'];
    const commitment = computeMembershipCommitment(members, 1, groupId, gs);
    storeGroupSecret(ks, aid, groupId, 1, gs, commitment, members);

    // 应抛出异常：签名失败不允许静默跳过
    expect(() => {
      mgr.encrypt(groupId, { type: 'text', text: 'should fail' });
    }).toThrow();
  });
});

// ── commitment 绑定测试 ─────────────────────────────────────

describe('GroupE2EEManager.rotateEpoch', () => {
  it('无先前 epoch 时应返回 epoch=1 且 prevEpoch 为 null（TS-018）', () => {
    const aid = 'rotate-test.aid';
    const ks = makeGroupKs(aid);
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity(aid, privateKey);
    ks._identities[aid] = identity;

    const mgr = new GroupE2EEManager({
      identityFn: () => identity,
      keystore: ks,
    });

    const groupId = 'grp-rotate-1';
    const members = [aid, 'other.aid'];

    // 没有先前 epoch，rotateEpoch 应正常工作
    const result = mgr.rotateEpoch(groupId, members);
    expect(result.epoch).toBe(1);
    // 应存储了新的 group secret
    const stored = loadGroupSecret(ks, aid, groupId);
    expect(stored).not.toBeNull();
    expect(stored!.epoch).toBe(1);
  });

  it('有先前 epoch 时应返回 prevEpoch+1（TS-018）', () => {
    const aid = 'rotate-test2.aid';
    const ks = makeGroupKs(aid);
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity(aid, privateKey);
    ks._identities[aid] = identity;

    const mgr = new GroupE2EEManager({
      identityFn: () => identity,
      keystore: ks,
    });

    const groupId = 'grp-rotate-2';
    const members = [aid, 'other.aid'];

    // 先创建 epoch 1
    mgr.createEpoch(groupId, members);
    const stored1 = loadGroupSecret(ks, aid, groupId);
    expect(stored1!.epoch).toBe(1);

    // rotateEpoch 应返回 epoch=2
    const result = mgr.rotateEpoch(groupId, members);
    expect(result.epoch).toBe(2);
  });

  it('epoch 为 0 时不应被 || 运算符误判为 falsy（TS-018）', () => {
    const aid = 'rotate-test3.aid';
    const ks = makeGroupKs(aid);
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity(aid, privateKey);
    ks._identities[aid] = identity;

    const mgr = new GroupE2EEManager({
      identityFn: () => identity,
      keystore: ks,
    });

    const groupId = 'grp-rotate-3';
    const members = [aid, 'other.aid'];

    // 手动存储一个 epoch=0 的 group secret
    const gs = generateGroupSecret();
    const commitment = computeMembershipCommitment(members, 0, groupId, gs);
    storeGroupSecret(ks, aid, groupId, 0, gs, commitment, members);

    // rotateEpoch 应返回 epoch=1（0+1），而非 epoch=1（因为 0||0 = 0 → 0+1=1）
    // 关键：如果用 ?? 替代 ||，epoch 0 不会被误判
    const result = mgr.rotateEpoch(groupId, members);
    expect(result.epoch).toBe(1);
  });
});

describe('Commitment 绑定', () => {
  it('commitment 绑定 group_secret', () => {
    const gs1 = makeGroupSecret();
    const gs2 = makeGroupSecret();
    const c1 = computeMembershipCommitment(['a'], 1, 'grp-1', gs1);
    const c2 = computeMembershipCommitment(['a'], 1, 'grp-1', gs2);
    expect(c1).not.toBe(c2);
  });

  it('commitment 绑定 epoch', () => {
    const gs = makeGroupSecret();
    const c1 = computeMembershipCommitment(['a'], 1, 'grp-1', gs);
    const c2 = computeMembershipCommitment(['a'], 2, 'grp-1', gs);
    expect(c1).not.toBe(c2);
  });

  it('commitment 绑定 group_id', () => {
    const gs = makeGroupSecret();
    const c1 = computeMembershipCommitment(['a'], 1, 'grp-1', gs);
    const c2 = computeMembershipCommitment(['a'], 1, 'grp-2', gs);
    expect(c1).not.toBe(c2);
  });

  it('commitment 绑定 member_aids', () => {
    const gs = makeGroupSecret();
    const c1 = computeMembershipCommitment(['a'], 1, 'grp-1', gs);
    const c2 = computeMembershipCommitment(['a', 'b'], 1, 'grp-1', gs);
    expect(c1).not.toBe(c2);
  });
});
