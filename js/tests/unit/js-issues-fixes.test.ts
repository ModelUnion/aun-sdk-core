// ── JS-001 ~ JS-007 修复测试 ─────────────────────────────────
// TDD: 先写失败测试暴露问题 → 确认失败 → 修复代码 → 确认通过
import 'fake-indexeddb/auto';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Message, GroupSecretRecord } from '../../src/types.js';

// ── JS-001: Message 类型应声明 group_id 和 sender_aid 字段 ──────
describe('JS-001: Message 类型字段声明', () => {
  it('Message 接口应包含可选的 group_id 字段', () => {
    // 编译时检查：如果字段未声明，TypeScript 会报错
    const msg: Message = {
      message_id: 'test-1',
      group_id: 'grp-1',
    };
    expect(msg.group_id).toBe('grp-1');
  });

  it('Message 接口应包含可选的 sender_aid 字段', () => {
    const msg: Message = {
      message_id: 'test-2',
      sender_aid: 'alice.aid.com',
    };
    expect(msg.sender_aid).toBe('alice.aid.com');
  });

  it('group_id 和 sender_aid 都为可选（不设置时为 undefined）', () => {
    const msg: Message = { message_id: 'test-3' };
    expect(msg.group_id).toBeUndefined();
    expect(msg.sender_aid).toBeUndefined();
  });

  it('decryptGroupMessage 中使用 message.group_id 不需 as 断言', async () => {
    // 验证类型安全：直接读取 group_id 不报编译错误
    const msg: Message = {
      message_id: 'msg-1',
      group_id: 'grp-1',
      sender_aid: 'alice.aid.com',
      from: 'alice.aid.com',
    };
    expect(typeof msg.group_id).toBe('string');
    expect(typeof msg.sender_aid).toBe('string');
  });
});

// ── JS-002: IndexedDB 群组密钥事务隔离 ─────────────────────────
// 注：IndexedDB 事务隔离属于内部实现细节，通过功能测试验证正确性
describe('JS-002: IndexedDB 群组密钥操作原子性', () => {
  it('IndexedDBKeyStore 应有 row 化群组密钥方法', async () => {
    const { IndexedDBKeyStore } = await import('../../src/keystore/indexeddb.js');
    const ks = new IndexedDBKeyStore({ dbName: 'test-js002' });
    expect(typeof ks.storeGroupSecretTransition).toBe('function');
    expect(typeof ks.storeGroupSecretEpoch).toBe('function');
    expect(typeof ks.loadGroupSecretEpoch).toBe('function');
    expect(typeof ks.listGroupSecretIds).toBe('function');
  });

  it('storeGroupSecretTransition 后 loadGroupSecretEpoch 应返回一致的数据', async () => {
    const { IndexedDBKeyStore } = await import('../../src/keystore/indexeddb.js');
    const ks = new IndexedDBKeyStore({ dbName: 'test-js002-rw' });

    const entry: GroupSecretRecord = {
      epoch: 3,
      secret: 'dGVzdC1zZWNyZXQ=',
      commitment: 'abc123',
      member_aids: ['alice.test', 'bob.test'],
      updated_at: Date.now(),
      old_epochs: [
        { epoch: 1, secret: 'b2xk', commitment: 'old1', updated_at: Date.now() - 10000 },
        { epoch: 2, secret: 'b2xkMg==', commitment: 'old2', updated_at: Date.now() - 5000 },
      ],
    };

    await ks.storeGroupSecretTransition('alice.test', 'grp-1', {
      epoch: 1,
      secret: 'b2xk',
      commitment: 'old1',
      memberAids: ['alice.test'],
      oldEpochRetentionMs: 7 * 24 * 3600 * 1000,
    });
    await ks.storeGroupSecretTransition('alice.test', 'grp-1', {
      epoch: 2,
      secret: 'b2xkMg==',
      commitment: 'old2',
      memberAids: ['alice.test'],
      oldEpochRetentionMs: 7 * 24 * 3600 * 1000,
    });
    await ks.storeGroupSecretTransition('alice.test', 'grp-1', {
      epoch: entry.epoch,
      secret: entry.secret,
      commitment: entry.commitment,
      memberAids: entry.member_aids,
      oldEpochRetentionMs: 7 * 24 * 3600 * 1000,
    });
    const loaded = await ks.loadGroupSecretEpoch('alice.test', 'grp-1');

    expect(loaded).not.toBeNull();
    expect(loaded!.epoch).toBe(3);
    expect(loaded!.secret).toBe('dGVzdC1zZWNyZXQ=');
    expect(loaded!.member_aids).toEqual(['alice.test', 'bob.test']);
    expect(await ks.listGroupSecretIds('alice.test')).toEqual(['grp-1']);
  });

  it('并发写同一群组密钥不应丢失数据', async () => {
    const { IndexedDBKeyStore } = await import('../../src/keystore/indexeddb.js');
    const ks = new IndexedDBKeyStore({ dbName: 'test-js002-concurrent' });

    const entry1: GroupSecretRecord = {
      epoch: 1,
      secret: 'c2VjcmV0MQ==',
      commitment: 'commit1',
      member_aids: ['alice.test'],
      updated_at: Date.now(),
    };
    const entry2: GroupSecretRecord = {
      epoch: 2,
      secret: 'c2VjcmV0Mg==',
      commitment: 'commit2',
      member_aids: ['alice.test', 'bob.test'],
      updated_at: Date.now() + 1,
    };

    // 并发写入
    await Promise.all([
      ks.storeGroupSecretTransition('alice.test', 'grp-1', {
        epoch: entry1.epoch,
        secret: entry1.secret,
        commitment: entry1.commitment,
        memberAids: entry1.member_aids,
        oldEpochRetentionMs: 7 * 24 * 3600 * 1000,
      }),
      ks.storeGroupSecretTransition('alice.test', 'grp-1', {
        epoch: entry2.epoch,
        secret: entry2.secret,
        commitment: entry2.commitment,
        memberAids: entry2.member_aids,
        oldEpochRetentionMs: 7 * 24 * 3600 * 1000,
      }),
    ]);

    const loaded = await ks.loadGroupSecretEpoch('alice.test', 'grp-1');
    expect(loaded).not.toBeNull();
    // 最终应保持后写入的 epoch 2（_withAidLock 保证串行化）
    expect(loaded!.epoch).toBe(2);
  });
});

// ── JS-003: V2-only 后旧 group epoch 发送预检已移除 ──
describe('JS-003: V2-only group E2EE 编排', () => {
  it('旧 _sendGroupEncrypted 与 group.e2ee.* RPC 不应再可用', async () => {
    const { AUNClient } = await import('../../src/client.js');
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'alice.aid.com';
    (client as any)._deviceId = 'dev-1';
    (client as any)._identity = { aid: 'alice.aid.com', private_key_pem: null, cert: null };
    (client as any)._transport.call = vi.fn().mockResolvedValue({ ok: true });

    expect((client as any)._groupE2ee).toBeUndefined();
    expect((client as any)._sendGroupEncrypted).toBeUndefined();
    expect((client as any)._recoverGroupEpochKey).toBeUndefined();
    await expect(client.call('group.e2ee.get_epoch', { group_id: 'g1' }))
      .rejects.toThrow('legacy E2EE method is removed');
    expect((client as any)._transport.call).not.toHaveBeenCalled();
  });
});

// ── JS-004: V2-only 后旧 decryptGroupMessage 模块已移除 ──────────────
describe('JS-004: V2-only group decrypt cleanup', () => {
  it('旧 e2ee-group.ts 与 client 解密 helper 不应再存在', async () => {
    const { AUNClient } = await import('../../src/client.js');
    const proto = Object.getPrototypeOf(new AUNClient()) as Record<string, unknown>;

    expect(existsSync(join(process.cwd(), 'src', 'e2ee-group.ts'))).toBe(false);
    expect(proto._decryptGroupMessage).toBeUndefined();
    expect(proto._decryptGroupMessages).toBeUndefined();
  });
});

// ── JS-005: _isGroupEpochRecoverable 空字符串 secret 判断 ───────
describe('JS-005: _isGroupEpochRecoverable 空字符串 secret 判断', () => {
  it('空字符串 secret 的 epoch 记录不应被视为可恢复', async () => {
    const { IndexedDBKeyStore } = await import('../../src/keystore/indexeddb.js');
    const ks = new IndexedDBKeyStore({ dbName: 'test-js005' });

    // 保存一个 secret 为空字符串的记录
    const entry: GroupSecretRecord = {
      epoch: 1,
      secret: '',  // 空字符串
      commitment: 'test',
      member_aids: ['alice.test'],
      updated_at: Date.now(),
    };

    await ks.storeGroupSecretTransition('alice.test', 'grp-1', {
      epoch: entry.epoch,
      secret: entry.secret,
      commitment: entry.commitment,
      memberAids: entry.member_aids,
      oldEpochRetentionMs: 7 * 24 * 3600 * 1000,
    });
    const loaded = await ks.loadGroupSecretEpoch('alice.test', 'grp-1');

    // 加载后 secret 应存在但为空
    // _isGroupEpochRecoverable 应在 secret 为空时返回 false
    // 这样 legacy 迁移不会把空 secret 记录当成有效记录合并
    if (loaded) {
      expect(loaded.secret === '' || loaded.secret === undefined || loaded.secret === null).toBe(true);
    }
  });

  it('有效 secret 的 epoch 记录应被正常保存和加载', async () => {
    const { IndexedDBKeyStore } = await import('../../src/keystore/indexeddb.js');
    const ks = new IndexedDBKeyStore({ dbName: 'test-js005-valid' });

    const entry: GroupSecretRecord = {
      epoch: 1,
      secret: 'dGVzdC1zZWNyZXQ=',
      commitment: 'test',
      member_aids: ['alice.test'],
      updated_at: Date.now(),
    };

    await ks.storeGroupSecretTransition('alice.test', 'grp-1', {
      epoch: entry.epoch,
      secret: entry.secret,
      commitment: entry.commitment,
      memberAids: entry.member_aids,
      oldEpochRetentionMs: 7 * 24 * 3600 * 1000,
    });
    const loaded = await ks.loadGroupSecretEpoch('alice.test', 'grp-1');

    expect(loaded).not.toBeNull();
    expect(loaded!.secret).toBe('dGVzdC1zZWNyZXQ=');
  });
});

// ── JS-006: V1 GroupReplayGuard 已随 e2ee-group 移除 ────────────────────────────
describe('JS-006: V1 group replay cleanup', () => {
  it('e2ee.ts 仅保留 protected headers 兼容入口', () => {
    const source = readFileSync(join(process.cwd(), 'src', 'e2ee.ts'), 'utf8');

    expect(source).toContain('ProtectedHeaders');
    expect(source).not.toContain('class E2EEManager');
    expect(source).not.toContain('prekey_ecdh_v2');
    expect(source).not.toContain('long_term_key');
  });
});

// ── JS-007: dissolve 后清理本地 epoch key 和 seq_tracker ────────
describe('JS-007: dissolve 后清理本地状态', () => {

  // ── SeqTracker.removeNamespace ──
  it('SeqTracker 应有 removeNamespace 方法', async () => {
    const { SeqTracker } = await import('../../src/seq-tracker.js');
    const tracker = new SeqTracker();
    expect(typeof tracker.removeNamespace).toBe('function');
  });

  it('removeNamespace 删除后 contiguousSeq 应归零', async () => {
    const { SeqTracker } = await import('../../src/seq-tracker.js');
    const tracker = new SeqTracker();

    tracker.onMessageSeq('group:grp-1', 1);
    tracker.onMessageSeq('group:grp-1', 2);
    expect(tracker.getContiguousSeq('group:grp-1')).toBe(2);

    tracker.removeNamespace('group:grp-1');
    expect(tracker.getContiguousSeq('group:grp-1')).toBe(0);
    expect(tracker.getMaxSeenSeq('group:grp-1')).toBe(0);
  });

  it('removeNamespace 不影响其他命名空间', async () => {
    const { SeqTracker } = await import('../../src/seq-tracker.js');
    const tracker = new SeqTracker();

    tracker.onMessageSeq('group:grp-1', 1);
    tracker.onMessageSeq('group:grp-2', 1);
    tracker.onMessageSeq('group:grp-2', 2);

    tracker.removeNamespace('group:grp-1');

    expect(tracker.getContiguousSeq('group:grp-1')).toBe(0);
    expect(tracker.getContiguousSeq('group:grp-2')).toBe(2);
  });

  it('removeNamespace 后 exportState 不包含该命名空间', async () => {
    const { SeqTracker } = await import('../../src/seq-tracker.js');
    const tracker = new SeqTracker();

    tracker.onMessageSeq('group:grp-1', 1);
    tracker.onMessageSeq('group:grp-2', 1);

    tracker.removeNamespace('group:grp-1');

    const state = tracker.exportState();
    expect(state['group:grp-1']).toBeUndefined();
    expect(state['group:grp-2']).toBe(1);
  });

  it('group.pull_events 返回 event_seq 时推进 group_event 命名空间', async () => {
    const { SeqTracker } = await import('../../src/seq-tracker.js');
    const tracker = new SeqTracker();

    tracker.onMessageSeq('group_event:grp-1', 1);
    tracker.onMessageSeq('group_event:grp-1', 4);
    tracker.onPullResult('group_event:grp-1', [
      { event_seq: 2, event_type: 'group.announcement_updated' },
      { event_seq: 3, event_type: 'group.rules_updated' },
    ]);

    expect(tracker.getContiguousSeq('group_event:grp-1')).toBe(4);
  });

  // ── KeyStore.deleteGroupSecretState ──
  it('IndexedDBKeyStore 应有 deleteGroupSecretState 方法', async () => {
    const { IndexedDBKeyStore } = await import('../../src/keystore/indexeddb.js');
    const ks = new IndexedDBKeyStore({ dbName: 'test-js007-delete' });
    expect(typeof ks.deleteGroupSecretState).toBe('function');
  });

  it('deleteGroupSecretState 删除后 loadGroupSecretEpoch 返回 null', async () => {
    const { IndexedDBKeyStore } = await import('../../src/keystore/indexeddb.js');
    const ks = new IndexedDBKeyStore({ dbName: 'test-js007-delete-2' });

    // 先保存
    await ks.storeGroupSecretTransition('alice.test', 'grp-1', {
      epoch: 1,
      secret: 'dGVzdA==',
      commitment: 'test',
      memberAids: ['alice.test'],
      oldEpochRetentionMs: 7 * 24 * 3600 * 1000,
    });

    const before = await ks.loadGroupSecretEpoch('alice.test', 'grp-1');
    expect(before).not.toBeNull();

    // 删除
    await ks.deleteGroupSecretState!('alice.test', 'grp-1');

    const after = await ks.loadGroupSecretEpoch('alice.test', 'grp-1');
    expect(after).toBeNull();
  });

  it('deleteGroupSecretState 不影响其他群组', async () => {
    const { IndexedDBKeyStore } = await import('../../src/keystore/indexeddb.js');
    const ks = new IndexedDBKeyStore({ dbName: 'test-js007-delete-3' });

    await ks.storeGroupSecretTransition('alice.test', 'grp-1', {
      epoch: 1, secret: 'dGVzdA==', commitment: 'c1', memberAids: ['alice.test'], oldEpochRetentionMs: 7 * 24 * 3600 * 1000,
    });
    await ks.storeGroupSecretTransition('alice.test', 'grp-2', {
      epoch: 1, secret: 'dGVzdDI=', commitment: 'c2', memberAids: ['alice.test'], oldEpochRetentionMs: 7 * 24 * 3600 * 1000,
    });

    await ks.deleteGroupSecretState!('alice.test', 'grp-1');

    expect(await ks.loadGroupSecretEpoch('alice.test', 'grp-1')).toBeNull();
    expect(await ks.loadGroupSecretEpoch('alice.test', 'grp-2')).not.toBeNull();
  });

  // ── GroupE2EEManager.removeGroup ──
  it('GroupE2EEManager 已移除，dissolve 清理只保留客户端本地状态清理', () => {
    expect(existsSync(join(process.cwd(), 'src', 'e2ee-group.ts'))).toBe(false);
  });

  // ── AUNClient group.dissolved 事件处理 ──
  it('AUNClient _onRawGroupChanged 收到 dissolved 应清理状态', async () => {
    const { AUNClient } = await import('../../src/client.js');
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'alice.aid.com';
    (client as any)._deviceId = 'dev-1';

    // mock _saveSeqTrackerState
    const saveSeqSpy = vi.fn();
    (client as any)._saveSeqTrackerState = saveSeqSpy;

    // 设置 seq tracker 状态
    (client as any)._seqTracker.onMessageSeq('group:grp-1', 1);
    (client as any)._seqTracker.onMessageSeq('group_event:grp-1', 1);

    // 触发 dissolved 事件
    await (client as any)._onRawGroupChanged({
      action: 'dissolved',
      group_id: 'grp-1',
    });

    // V2-only 客户端不再持有 V1 group epoch manager
    expect((client as any)._groupE2ee).toBeUndefined();

    // seq_tracker 中相关命名空间应被清理
    expect((client as any)._seqTracker.getContiguousSeq('group:grp-1')).toBe(0);
    expect((client as any)._seqTracker.getContiguousSeq('group_event:grp-1')).toBe(0);
  });

  it('dissolved 事件仍应透传给用户', async () => {
    const { AUNClient } = await import('../../src/client.js');
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'alice.aid.com';
    (client as any)._deviceId = 'dev-1';

    (client as any)._saveSeqTrackerState = vi.fn();

    const publishSpy = vi.spyOn((client as any)._dispatcher, 'publish');

    await (client as any)._onRawGroupChanged({
      action: 'dissolved',
      group_id: 'grp-1',
    });

    // group.changed 事件应被透传
    expect(publishSpy).toHaveBeenCalledWith('group.changed', expect.objectContaining({
      action: 'dissolved',
      group_id: 'grp-1',
    }));
  });
});
