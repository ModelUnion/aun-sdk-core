import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import {
  computeLeafHash,
  computeMerkleProof,
  computeMerkleRoot,
  computeRecipientsDigest,
  sortRecipients,
  verifyMerkleProof,
} from '../../src/v2/crypto/recipients';

const GOLDEN_DIR = join(__dirname, 'golden', 'recipients_digest');

describe('recipients - sort & merkle root golden', () => {
  const files = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith('.json'));
  expect(files.length).toBeGreaterThanOrEqual(2);

  for (const f of files) {
    it(`golden: ${f}`, async () => {
      const golden = JSON.parse(
        readFileSync(join(GOLDEN_DIR, f), 'utf-8'),
      ) as Record<string, unknown>;

      const inputRows = golden.input_rows as string[][];
      const expectedSorted = golden.expected_sorted_rows as string[][];

      const sorted = sortRecipients(inputRows);
      // 排序结果与 expected_sorted_rows 等价
      expect(sorted.length).toBe(expectedSorted.length);
      for (let i = 0; i < sorted.length; i++) {
        expect(sorted[i]).toEqual(expectedSorted[i]);
      }

      // empty 用例：Python 实现 digest 为空串，golden 中 expected_digest_hex = ""，
      // 直接对比即可。
      const expectedDigestHex = golden.expected_digest_hex as string;
      const digest = await computeRecipientsDigest(sorted);
      expect(digest).toBe(expectedDigestHex);
    });
  }
});

describe('recipients - sort rules', () => {
  it('sort by aid then device_id then role', () => {
    const rows: string[][] = [
      ['carol.aid', 'dev-3', 'member', 'group_device_prekey', 'fp', 'spk', 'n', 'w'],
      ['alice.aid', 'dev-1', 'member', 'group_device_prekey', 'fp', 'spk', 'n', 'w'],
      ['bob.aid', 'dev-2', 'member', 'group_device', 'fp', '', 'n', 'w'],
      ['bob.aid', 'dev-1', 'audit', 'aid_master', 'fp', '', 'n', 'w'],
      ['bob.aid', 'dev-1', 'member', 'group_device', 'fp', '', 'n', 'w'],
    ];
    const out = sortRecipients(rows);
    expect(out[0][0]).toBe('alice.aid');
    expect(out[1][0]).toBe('bob.aid');
    expect(out[1][1]).toBe('dev-1');
    expect(out[1][2]).toBe('audit'); // audit < member（同 device_id）
    expect(out[2][0]).toBe('bob.aid');
    expect(out[2][1]).toBe('dev-1');
    expect(out[2][2]).toBe('member');
    expect(out[3][0]).toBe('bob.aid');
    expect(out[3][1]).toBe('dev-2');
    expect(out[4][0]).toBe('carol.aid');
  });
});

describe('recipients - empty', () => {
  it('empty rows → empty digest string', async () => {
    const digest = await computeRecipientsDigest([]);
    expect(digest).toBe('');
  });
});

describe('recipients - merkle proof verification', () => {
  it('proof verifies for each row', async () => {
    const rows: string[][] = [
      ['alice.aid', 'dev-1', 'member', 'gd', 'fp1', 'spk1', 'n1', 'w1'],
      ['bob.aid', 'dev-2', 'member', 'gd', 'fp2', '', 'n2', 'w2'],
      ['carol.aid', 'dev-3', 'member', 'gd', 'fp3', 'spk3', 'n3', 'w3'],
      ['dave.aid', 'dev-4', 'member', 'gd', 'fp4', '', 'n4', 'w4'],
      ['eve.aid', 'dev-5', 'member', 'gd', 'fp5', 'spk5', 'n5', 'w5'],
    ];
    const sorted = sortRecipients(rows);
    const root = await computeMerkleRoot(sorted);

    for (let i = 0; i < sorted.length; i++) {
      const leaf = await computeLeafHash(sorted[i]);
      const proof = await computeMerkleProof(sorted, i);
      const ok = await verifyMerkleProof(leaf, proof, root);
      expect(ok).toBe(true);
    }
  });

  it('tampered leaf fails verification', async () => {
    const rows: string[][] = [
      ['alice.aid', 'dev-1', 'member', 'gd', 'fp1', 'spk1', 'n1', 'w1'],
      ['bob.aid', 'dev-2', 'member', 'gd', 'fp2', '', 'n2', 'w2'],
    ];
    const root = await computeMerkleRoot(rows);
    const leaf0 = await computeLeafHash(rows[0]);
    const proof0 = await computeMerkleProof(rows, 0);
    expect(await verifyMerkleProof(leaf0, proof0, root)).toBe(true);

    const tamperedLeaf = new Uint8Array(leaf0);
    tamperedLeaf[0] ^= 0xff;
    expect(await verifyMerkleProof(tamperedLeaf, proof0, root)).toBe(false);
  });
});
