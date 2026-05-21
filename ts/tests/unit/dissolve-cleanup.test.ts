/**
 * dissolve 后清理本地 seq_tracker 的测试
 *
 * 验证：
 * 1. SeqTracker.removeNamespace 能正确删除命名空间状态
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { SeqTracker } from '../../src/seq-tracker.js';

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

  it('group.pull_events 返回 event_seq 时推进 group_event 命名空间', () => {
    tracker.onMessageSeq('group_event:grp-1', 1);
    tracker.onMessageSeq('group_event:grp-1', 4);

    tracker.onPullResult('group_event:grp-1', [
      { event_seq: 2, event_type: 'group.announcement_updated' },
      { event_seq: 3, event_type: 'group.rules_updated' },
    ]);

    expect(tracker.getContiguousSeq('group_event:grp-1')).toBe(4);
  });
});

