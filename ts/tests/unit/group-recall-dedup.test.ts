import { describe, expect, it } from 'vitest';

import { MessageDeliveryEngine } from '../../src/client/delivery.js';
import { ClientRuntime } from '../../src/client/runtime.js';
import { normalizeGroupId } from '../../src/group-id.js';

// groupRecallDedupKey 是 MessageDeliveryEngine 的实例方法，但其实现只用到
// normalizeGroupId + payload.message_ids，完全不触碰 runtime/client。
// 因此用一个空 client 构造最小 ClientRuntime 即可静态地验证去重键。
function createEngine(): MessageDeliveryEngine {
  return new MessageDeliveryEngine(new ClientRuntime({}));
}

describe('groupRecallDedupKey 群撤回去重键（#1 修复）', () => {
  it('去重键不含 recalled_at：recalled_at 不同但键相同', () => {
    const engine = createEngine();

    // 在线 push（事务后重取时间）与 pull tombstone（事务内时间）recalled_at 不同源，
    // 但同一次撤回必须命中同一去重键，否则应用层回调两次。
    const keyEarly = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-aaa'], recalled_at: 1000 });
    const keyLate = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-aaa'], recalled_at: 1007 });

    expect(keyEarly).toBe(keyLate);
    // normalizeGroupId('grp-1') === 'grp-1'（不含点、不以 g- 开头，原样返回），实测值见下方断言。
    expect(normalizeGroupId('grp-1')).toBe('grp-1');
    expect(keyEarly).toBe('grp-1|m-aaa');
  });

  it('message_ids 顺序不同时键相同（排序保证）', () => {
    const engine = createEngine();

    const keyAsc = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-aaa', 'm-bbb'] });
    const keyDesc = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-bbb', 'm-aaa'] });

    expect(keyAsc).toBe(keyDesc);
    expect(keyAsc).toBe('grp-1|m-aaa,m-bbb');
  });

  it('不同 message_ids 的键不同', () => {
    const engine = createEngine();

    const keyA = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-aaa'] });
    const keyB = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-bbb'] });

    expect(keyA).not.toBe(keyB);
  });
});
