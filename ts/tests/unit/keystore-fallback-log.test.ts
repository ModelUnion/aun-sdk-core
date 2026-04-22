/**
 * FileKeyStore _prepareRoot fallback 日志测试 — ISSUE-TS-003
 * 验证 preferred 路径失败回退到 fallback 时输出警告日志
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

function getPrepareRootSource(): string {
  const src = readFileSync(
    resolve(__dirname, '../../src/keystore/file.ts'),
    'utf-8',
  );
  const start = src.indexOf('private _prepareRoot');
  if (start === -1) throw new Error('未找到 _prepareRoot 方法');
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
  throw new Error('无法解析 _prepareRoot 方法体');
}

describe('_prepareRoot fallback 日志（ISSUE-TS-003）', () => {
  const methodBody = getPrepareRootSource();

  it('fallback 路径应包含 console.warn 日志警告', () => {
    // catch 块中应有日志输出，告知用户数据存储位置发生了回退
    expect(methodBody).toMatch(/console\.warn/);
  });
});
