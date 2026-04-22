/**
 * 群事件推送路径 ack 测试 — ISSUE-TS-002
 * 验证 _onRawGroupChanged 在处理 event_seq 后发送 ack 并持久化状态
 *
 * 由于 _onRawGroupChanged 是私有方法，通过源码分析验证关键调用存在。
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

function getOnRawGroupChangedSource(): string {
  const src = readFileSync(
    resolve(__dirname, '../../src/client.ts'),
    'utf-8',
  );
  // 提取 _onRawGroupChanged 方法体
  const start = src.indexOf('private async _onRawGroupChanged');
  if (start === -1) throw new Error('未找到 _onRawGroupChanged 方法');
  // 找到方法结束（下一个同级 private/public 方法或类结束）
  let braceCount = 0;
  let methodStart = -1;
  for (let i = start; i < src.length; i++) {
    if (src[i] === '{') {
      if (methodStart === -1) methodStart = i;
      braceCount++;
    } else if (src[i] === '}') {
      braceCount--;
      if (braceCount === 0) {
        return src.substring(start, i + 1);
      }
    }
  }
  throw new Error('无法解析 _onRawGroupChanged 方法体');
}

describe('群事件推送路径 ack（ISSUE-TS-002）', () => {
  const methodBody = getOnRawGroupChangedSource();

  it('event_seq 处理后应调用 _saveSeqTrackerState 持久化', () => {
    expect(methodBody).toContain('_saveSeqTrackerState');
  });

  it('event_seq 处理后应发送 group.ack_events', () => {
    expect(methodBody).toContain('group.ack_events');
  });
});
