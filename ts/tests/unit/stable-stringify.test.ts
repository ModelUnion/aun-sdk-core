/**
 * stableStringify 单元测试 — ISSUE-TS-001
 * 验证 undefined 值处理与 JSON.stringify 一致
 */
import { describe, it, expect } from 'vitest';
import { stableStringify } from '../../src/client.js';

describe('stableStringify undefined 值处理（ISSUE-TS-001）', () => {
  it('对象中 undefined 值的 key 应被跳过，与 JSON.stringify 一致', () => {
    const obj = { a: 1, b: undefined, c: 'hello' };
    const result = stableStringify(obj);
    const expected = JSON.stringify({ a: 1, c: 'hello' }); // JSON.stringify 跳过 undefined
    expect(result).toBe(expected);
  });

  it('嵌套对象中 undefined 值的 key 也应被跳过', () => {
    const obj = { outer: { keep: true, drop: undefined } };
    const result = stableStringify(obj);
    expect(result).not.toContain('drop');
    expect(result).toContain('keep');
  });

  it('数组中的 undefined 应序列化为 null（与 JSON.stringify 一致）', () => {
    const arr = [1, undefined, 3];
    const result = stableStringify(arr);
    expect(result).toBe('[1,null,3]');
  });

  it('顶层 undefined 应序列化为 "null"', () => {
    expect(stableStringify(undefined)).toBe('null');
  });

  it('正常对象排序序列化不受影响', () => {
    const obj = { b: 2, a: 1 };
    expect(stableStringify(obj)).toBe('{"a":1,"b":2}');
  });
});
