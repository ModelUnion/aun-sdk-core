import { describe, expect, it } from 'vitest';

import { MessageDeliveryEngine } from '../../src/client/delivery.js';
import { ClientRuntime } from '../../src/client/runtime.js';
import { normalizeGroupId } from '../../src/group-id.js';

// groupRecallDedupKey/messageRecallDedupKey 是 MessageDeliveryEngine 的实例方法，
// 但 key 计算不触碰 runtime/client。
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
    expect(keyEarly).toBe('grp-1|id:m-aaa');
  });

  it('message_ids 顺序不同时键相同（排序保证）', () => {
    const engine = createEngine();

    const keyAsc = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-aaa', 'm-bbb'] });
    const keyDesc = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-bbb', 'm-aaa'] });

    expect(keyAsc).toBe(keyDesc);
    expect(keyAsc).toBe('grp-1|id:m-aaa,m-bbb');
  });

  it('不同 message_ids 的键不同', () => {
    const engine = createEngine();

    const keyA = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-aaa'] });
    const keyB = engine.groupRecallDedupKey('grp-1', { message_ids: ['m-bbb'] });

    expect(keyA).not.toBe(keyB);
  });

  it('缺 message_ids 时按 target_message_seqs 兜底', () => {
    const engine = createEngine();

    const keyPlaceholder = engine.groupRecallDedupKey('grp-1', { message_id: 'ph-1', target_message_seqs: [3] });
    const keyNotice = engine.groupRecallDedupKey('grp-1', { message_id: 'notice-1', target_message_seqs: [3] });

    expect(keyPlaceholder).toBe(keyNotice);
    expect(keyPlaceholder).toBe('grp-1|seq:3');
  });
});

describe('messageRecallDedupKey P2P 撤回去重键', () => {
  it('recalled_at 不同但 message_ids 相同时键相同', () => {
    const engine = createEngine();

    const keyPush = engine.messageRecallDedupKey({ message_ids: ['m-aaa'], recalled_at: 1007 });
    const keyPull = engine.messageRecallDedupKey({ message_ids: ['m-aaa'], recalled_at: 1000 });

    expect(keyPush).toBe(keyPull);
    expect(keyPush).toBe('p2p|id:m-aaa');
  });
});
