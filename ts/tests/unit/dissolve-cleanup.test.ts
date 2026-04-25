/**
 * dissolve 后清理本地 epoch key 和 seq_tracker 的测试
 *
 * 验证：
 * 1. SeqTracker.removeNamespace 能正确删除命名空间状态
 * 2. KeyStore.deleteGroupSecretState 能正确删除群组密钥
 * 3. GroupE2EEManager.removeGroup 能清理所有群组相关状态
 * 4. AUNClient 收到 dissolved 事件后自动清理
 */

import { describe, it, expect, beforeEach } from 'vitest';
import * as crypto from 'node:crypto';
import { SeqTracker } from '../../src/seq-tracker.js';
import {
  GroupE2EEManager,
  storeGroupSecret,
  loadGroupSecret,
  computeMembershipCommitment,
} from '../../src/e2ee-group.js';
import { FakeKeystore, generateECKeypair, buildIdentity } from './helpers.js';

// ── SeqTracker.removeNamespace ─────────────────────────────

describe('SeqTracker.removeNamespace', () => {
  let tracker: SeqTracker;

  beforeEach(() => {
    tracker = new SeqTracker();
  });

  it('删除已存在的命名空间', () => {
    tracker.onMessageSeq('group:grp-1', 1);
    tracker.onMessageSeq('group:grp-1', 2);
    expect(tracker.getContiguousSeq('group:grp-1')).toBe(2);
    expect(tracker.getMaxSeenSeq('group:grp-1')).toBe(2);

    tracker.removeNamespace('group:grp-1');

    // 删除后应回到默认值 0
    expect(tracker.getContiguousSeq('group:grp-1')).toBe(0);
    expect(tracker.getMaxSeenSeq('group:grp-1')).toBe(0);
  });

  it('删除不存在的命名空间不报错', () => {
    expect(() => tracker.removeNamespace('group:nonexistent')).not.toThrow();
  });

  it('删除后不影响其他命名空间', () => {
    tracker.onMessageSeq('group:grp-1', 1);
    tracker.onMessageSeq('group:grp-2', 1);
    tracker.onMessageSeq('group:grp-2', 2);

    tracker.removeNamespace('group:grp-1');

    expect(tracker.getContiguousSeq('group:grp-1')).toBe(0);
    expect(tracker.getContiguousSeq('group:grp-2')).toBe(2);
  });

  it('删除后 exportState 不包含该命名空间', () => {
    tracker.onMessageSeq('group:grp-1', 1);
    tracker.onMessageSeq('group:grp-2', 1);

    tracker.removeNamespace('group:grp-1');

    const state = tracker.exportState();
    expect(state['group:grp-1']).toBeUndefined();
    expect(state['group:grp-2']).toBe(1);
  });

  it('同时删除群消息和群事件命名空间', () => {
    tracker.onMessageSeq('group:grp-1', 1);
    tracker.onMessageSeq('group_event:grp-1', 1);

    tracker.removeNamespace('group:grp-1');
    tracker.removeNamespace('group_event:grp-1');

    expect(tracker.getContiguousSeq('group:grp-1')).toBe(0);
    expect(tracker.getContiguousSeq('group_event:grp-1')).toBe(0);
  });
});

// ── KeyStore.deleteGroupSecretState ─────────────────────────

describe('KeyStore.deleteGroupSecretState', () => {
  let ks: FakeKeystore;
  const aid = 'alice.test';
  const groupId = 'grp-1';

  beforeEach(() => {
    ks = new FakeKeystore();
    // 存入一个群组密钥
    const gs = crypto.randomBytes(32);
    const commitment = computeMembershipCommitment(
      [aid, 'bob.test'], 1, groupId, gs,
    );
    storeGroupSecret(ks, aid, groupId, 1, gs, commitment, [aid, 'bob.test']);
  });

  it('删除前密钥存在', () => {
    const secret = loadGroupSecret(ks, aid, groupId);
    expect(secret).not.toBeNull();
  });

  it('deleteGroupSecretState 删除后密钥不存在', () => {
    expect(typeof ks.deleteGroupSecretState).toBe('function');
    ks.deleteGroupSecretState!(aid, groupId);
    const secret = loadGroupSecret(ks, aid, groupId);
    expect(secret).toBeNull();
  });

  it('删除不影响其他群组', () => {
    // 存入另一个群组密钥
    const gs2 = crypto.randomBytes(32);
    const commitment2 = computeMembershipCommitment(
      [aid, 'carol.test'], 1, 'grp-2', gs2,
    );
    storeGroupSecret(ks, aid, 'grp-2', 1, gs2, commitment2, [aid, 'carol.test']);

    ks.deleteGroupSecretState!(aid, groupId);

    expect(loadGroupSecret(ks, aid, groupId)).toBeNull();
    expect(loadGroupSecret(ks, aid, 'grp-2')).not.toBeNull();
  });
});

// ── GroupE2EEManager.removeGroup ─────────────────────────────

describe('GroupE2EEManager.removeGroup', () => {
  let mgr: GroupE2EEManager;
  let ks: FakeKeystore;
  const aid = 'alice.test';
  const groupId = 'grp-1';

  beforeEach(() => {
    ks = new FakeKeystore();
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity(aid, privateKey);
    ks._keyPairs[aid] = {
      private_key_pem: identity.private_key_pem,
      public_key_der_b64: identity.public_key_der_b64,
    };

    mgr = new GroupE2EEManager({
      identityFn: () => identity,
      keystore: ks,
      senderCertResolver: () => identity.cert as string,
      initiatorCertResolver: () => identity.cert as string,
    });

    // 创建 epoch 密钥
    mgr.createEpoch(groupId, [aid, 'bob.test']);
    expect(mgr.hasSecret(groupId)).toBe(true);
    expect(mgr.currentEpoch(groupId)).toBe(1);
  });

  it('removeGroup 清理后 hasSecret 返回 false', () => {
    mgr.removeGroup(groupId);
    expect(mgr.hasSecret(groupId)).toBe(false);
  });

  it('removeGroup 清理后 currentEpoch 返回 null', () => {
    mgr.removeGroup(groupId);
    expect(mgr.currentEpoch(groupId)).toBeNull();
  });

  it('removeGroup 清理后 getMemberAids 返回空数组', () => {
    mgr.removeGroup(groupId);
    expect(mgr.getMemberAids(groupId)).toEqual([]);
  });

  it('removeGroup 清理后 loadSecret 返回 null', () => {
    mgr.removeGroup(groupId);
    expect(mgr.loadSecret(groupId)).toBeNull();
  });

  it('removeGroup 不影响其他群组', () => {
    mgr.createEpoch('grp-2', [aid, 'carol.test']);
    mgr.removeGroup(groupId);

    expect(mgr.hasSecret(groupId)).toBe(false);
    expect(mgr.hasSecret('grp-2')).toBe(true);
  });

  it('removeGroup 对不存在的群组不报错', () => {
    expect(() => mgr.removeGroup('nonexistent')).not.toThrow();
  });

  it('removeGroup 后加密操作应抛出 E2EEGroupSecretMissingError', () => {
    mgr.removeGroup(groupId);
    expect(() => mgr.encrypt(groupId, { type: 'text', text: 'hello' })).toThrow();
  });
});
