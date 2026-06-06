import { describe, expect, it } from 'vitest';

import { MessageDeliveryEngine } from '../../src/client/delivery.js';
import { ClientRuntime } from '../../src/client/runtime.js';

/**
 * 群撤回去重键单元测试（锁定修复 #1）。
 *
 * groupRecallDedupKey(groupId, payload) 只用 `group_id|sorted(message_ids)` 组键，
 * 不再含 recalled_at。原因：在线 push 与 pull tombstone 三条通道对同一次撤回会携带
 * 不同来源的 recalled_at（push 在事务后重取时间戳），纳入去重键会使去重失效、
 * 应用层回调多次。本测试锁死该行为，防回归。
 *
 * 注意：JS 版去重键直接返回 `${groupId}|${idPart}`，不对 group_id 做 normalize
 * （与 TS 版不同），断言按 JS 实际行为写。
 *
 * groupRecallDedupKey 是 MessageDeliveryEngine 的实例方法，且不访问 client，
 * 故用空 client 构造最小引擎实例即可调用。
 */
function createEngine(): MessageDeliveryEngine {
  return new MessageDeliveryEngine(new ClientRuntime({}));
}

describe('groupRecallDedupKey 群撤回去重键', () => {
  it('recalled_at 不同但 group_id + message_ids 相同时，去重键相同（修复 #1 核心）', () => {
    const engine = createEngine();

    const keyA = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-aaa'], recalled_at: 1000 });
    const keyB = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-aaa'], recalled_at: 1007 });

    expect(keyA).toBe(keyB);
    // JS 版不 normalize group_id，键就是原始 group_id 加排序后的 message_ids。
    expect(keyA).toBe('grp-1|m-aaa');
  });

  it('message_ids 顺序无关（内部排序）', () => {
    const engine = createEngine();

    const keyAsc = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-a', 'm-b', 'm-c'] });
    const keyDesc = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-c', 'm-b', 'm-a'] });

    expect(keyAsc).toBe(keyDesc);
    expect(keyAsc).toBe('grp-1|m-a,m-b,m-c');
  });

  it('不同 message_ids 产生不同去重键', () => {
    const engine = createEngine();

    const keyOne = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-aaa'] });
    const keyTwo = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-bbb'] });

    expect(keyOne).not.toBe(keyTwo);
  });

  it('不同 group_id 产生不同去重键', () => {
    const engine = createEngine();

    const keyG1 = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-aaa'] });
    const keyG2 = engine.groupRecallDedupKey('grp-2', { message_ids: ['m-aaa'] });

    expect(keyG1).not.toBe(keyG2);
  });

  it('message_ids 中的空串/空白项被过滤，且去重键不含 recalled_at', () => {
    const engine = createEngine();

    const key = engine.groupRecallDedupKey('grp-1', {
      message_ids: ['m-aaa', '', '  ', 'm-bbb'],
      recalled_at: 9999,
    });

    expect(key).toBe('grp-1|m-aaa,m-bbb');
    expect(key).not.toContain('9999');
  });
});
