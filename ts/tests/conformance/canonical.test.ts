import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalJson } from '../../src/v2/crypto/canonical.js';

/**
 * Golden vector 一致性测试 — 验证 TS canonical JSON 输出与 Python SDK 字节级一致。
 *
 * Golden 向量源自 Python SDK conformance 测试，每个 JSON 文件包含：
 *   { description, input, expected_output_b64 }
 */

// 使用 Python 源目录的 golden 文件（确保控制字符等特殊文件完整）
const GOLDEN_DIR = join(
  __dirname,
  '..', '..', '..', 'python', 'tests', 'conformance', 'golden', 'canonical',
);

function base64ToUint8Array(b64: string): Uint8Array {
  return Buffer.from(b64, 'base64');
}

describe('canonical_json golden vectors', () => {
  const files = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith('.json'));

  expect(files.length).toBeGreaterThanOrEqual(19);

  for (const file of files) {
    it(file.replace('.json', ''), () => {
      const raw = readFileSync(join(GOLDEN_DIR, file), 'utf-8');
      const vector = JSON.parse(raw) as {
        description: string;
        input: unknown;
        expected_output_b64: string;
      };

      const actual = canonicalJson(vector.input);
      const expected = base64ToUint8Array(vector.expected_output_b64);

      // 逐字节比较
      expect(Buffer.from(actual).toString('hex')).toBe(
        Buffer.from(expected).toString('hex'),
      );
    });
  }
});
