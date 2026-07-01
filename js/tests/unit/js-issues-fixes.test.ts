// ── JS-001 ~ JS-007 修复测试 ─────────────────────────────────
// TDD: 先写失败测试暴露问题 → 确认失败 → 修复代码 → 确认通过
import 'fake-indexeddb/auto';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Message } from '../../src/types.js';

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

// ── JS-007: dissolve 后清理本地 seq_tracker ────────
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
