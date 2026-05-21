import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import { canonicalJson } from '../../src/v2/crypto/canonical';

/**
 * base64 解码（浏览器兼容方式）
 * 测试环境中 atob 由 jsdom 提供
 */
function b64ToUint8Array(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

const GOLDEN_DIR = join(__dirname, 'golden', 'canonical');

describe('canonicalJson - golden vectors', () => {
  const files = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith('.json'));

  expect(files.length).toBeGreaterThanOrEqual(19);

  for (const file of files) {
    it(`golden: ${file.replace('.json', '')}`, () => {
      let raw = readFileSync(join(GOLDEN_DIR, file), 'utf-8');
      // 将 JSON 字符串中的裸控制字符（0x00-0x1F，排除已有转义的）替换为 \uXXXX 转义
      // 这样 JSON.parse 才能正确解析含控制字符的 golden 文件
      raw = raw.replace(/[\x00-\x1f]/g, (ch) => {
        if (ch === '\n' || ch === '\r' || ch === '\t') return ch;
        return '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0');
      });
      const vector = JSON.parse(raw) as {
        description: string;
        input: unknown;
        expected_output_b64: string;
      };

      const actual = canonicalJson(vector.input);
      const expected = b64ToUint8Array(vector.expected_output_b64);

      // 逐字节比较
      expect(actual.length).toBe(expected.length);
      for (let i = 0; i < expected.length; i++) {
        if (actual[i] !== expected[i]) {
          // 提供有用的错误信息
          const actualStr = new TextDecoder().decode(actual);
          const expectedStr = new TextDecoder().decode(expected);
          expect.fail(
            `Byte mismatch at index ${i}: ` +
            `actual=0x${actual[i].toString(16)} expected=0x${expected[i].toString(16)}\n` +
            `actual:   ${actualStr}\n` +
            `expected: ${expectedStr}`
          );
        }
      }
    });
  }
});
