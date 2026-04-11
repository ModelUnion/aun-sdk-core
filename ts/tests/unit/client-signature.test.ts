// ── 客户端签名覆盖面测试 ──────────────────────────────────────
// SIGNED_METHODS 是模块私有常量，无法直接 import。
// 通过读取源文件提取方法列表，验证签名覆盖了所有关键操作。
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/** 从 client.ts 源文件中提取 SIGNED_METHODS 集合的方法名 */
function extractSignedMethods(): string[] {
  const src = readFileSync(
    resolve(__dirname, '../../src/client.ts'),
    'utf-8',
  );
  // 匹配 const SIGNED_METHODS = new Set([ ... ]);
  const match = src.match(
    /const\s+SIGNED_METHODS\s*=\s*new\s+Set\(\[\s*([\s\S]*?)\]\)/,
  );
  if (!match) throw new Error('未找到 SIGNED_METHODS 定义');
  // 提取所有单引号字符串
  const methods: string[] = [];
  for (const m of match[1].matchAll(/'([^']+)'/g)) {
    methods.push(m[1]);
  }
  return methods;
}

/** 预期需要签名的 20 个方法 */
const EXPECTED_SIGNED_METHODS = [
  'group.send',
  'group.kick',
  'group.add_member',
  'group.leave',
  'group.remove_member',
  'group.update_rules',
  'group.update',
  'group.update_announcement',
  'group.update_join_requirements',
  'group.set_role',
  'group.transfer_owner',
  'group.review_join_request',
  'group.batch_review_join_request',
  'group.resources.put',
  'group.resources.update',
  'group.resources.delete',
  'group.resources.request_add',
  'group.resources.direct_add',
  'group.resources.approve_request',
  'group.resources.reject_request',
] as const;

describe('SIGNED_METHODS 签名覆盖面', () => {
  const actual = extractSignedMethods();

  it('应包含全部 20 个预期方法', () => {
    expect(actual).toHaveLength(20);
  });

  it('每个预期方法都应在 SIGNED_METHODS 中', () => {
    for (const method of EXPECTED_SIGNED_METHODS) {
      expect(actual, `缺少方法: ${method}`).toContain(method);
    }
  });

  it('不应包含预期之外的方法', () => {
    const expectedSet = new Set<string>(EXPECTED_SIGNED_METHODS);
    const unexpected = actual.filter((m) => !expectedSet.has(m));
    expect(unexpected, `意外的签名方法: ${unexpected.join(', ')}`).toHaveLength(0);
  });
});
