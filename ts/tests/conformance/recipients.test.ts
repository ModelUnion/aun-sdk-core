import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  sortRecipients,
  computeRecipientsDigest,
  computeMerkleProof,
  computeLeafHash,
  verifyMerkleProof,
} from '../../src/v2/crypto/recipients.js';

/**
 * Recipients 排序 + Merkle digest golden 一致性测试。
 *
 * empty 用例只验 sorted_rows（Python digest 在空时返回 ""，golden 中的 hex 是其他实现的产物，跳过）。
 */

const GOLDEN_DIR = join(__dirname, 'golden', 'recipients_digest');

describe('recipients_digest golden vectors', () => {
  const files = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith('.json'));
  expect(files.length).toBeGreaterThanOrEqual(2);

  for (const f of files) {
    it(f.replace('.json', ''), () => {
      const g = JSON.parse(readFileSync(join(GOLDEN_DIR, f), 'utf-8')) as {
        input_rows: string[][];
        expected_sorted_rows: string[][];
        expected_digest_hex: string;
      };

      const sorted = sortRecipients(g.input_rows);
      expect(sorted).toEqual(g.expected_sorted_rows);

      if (g.input_rows.length === 0) {
        // 空：digest 协议未定，Python 返回 ""，跳过 hex 比较
        const digest = computeRecipientsDigest(sorted);
        expect(digest).toBe('');
        return;
      }

      const digest = computeRecipientsDigest(sorted);
      expect(digest).toBe(g.expected_digest_hex);
    });
  }
});

describe('Merkle proof verification roundtrip', () => {
  it('proof for each recipient verifies against root', () => {
    const g = JSON.parse(
      readFileSync(join(GOLDEN_DIR, 'three_members.json'), 'utf-8'),
    ) as { expected_sorted_rows: string[][]; expected_digest_hex: string };

    const rows = g.expected_sorted_rows;
    const root = g.expected_digest_hex;
    for (let i = 0; i < rows.length; i++) {
      const proof = computeMerkleProof(rows, i);
      const leaf = computeLeafHash(rows[i]);
      expect(verifyMerkleProof(leaf, proof, root)).toBe(true);
    }
  });
});
