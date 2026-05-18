import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { computeStateCommitment } from '../../src/v2/state/commitment.js';

const GOLDEN_DIR = join(__dirname, 'golden', 'state_commitment');

describe('state_commitment golden vectors', () => {
  const files = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith('.json'));
  expect(files.length).toBeGreaterThanOrEqual(1);

  for (const f of files) {
    it(f.replace('.json', ''), () => {
      const g = JSON.parse(readFileSync(join(GOLDEN_DIR, f), 'utf-8')) as {
        group_id: string;
        epoch: number;
        state_payload: Record<string, unknown>;
        expected_commitment_hex: string;
      };
      const out = computeStateCommitment(g.group_id, g.epoch, g.state_payload);
      expect(out).toBe(g.expected_commitment_hex);
    });
  }
});

describe('state_commitment internal sorting', () => {
  it('reordering members/devices/audit_aids produces same commitment', () => {
    const baseline = {
      members: [
        { aid: 'a.aid', devices: [{ device_id: 'd1', fp: 'f1' }] },
        { aid: 'b.aid', devices: [{ device_id: 'd2', fp: 'f2' }] },
      ],
      audit_aids: ['z.aid', 'a.aid'],
      admin_set: { admin_aids: ['b.aid', 'a.aid'], threshold: 1 },
      recovery_quorum: { trigger: 't', quorum_aids: ['c', 'a', 'b'], threshold: 2 },
      history_policy: 'none',
      wrap_protocol: '3DH',
    };
    const shuffled = {
      members: [
        {
          aid: 'b.aid',
          devices: [{ device_id: 'd2', fp: 'f2' }],
        },
        {
          aid: 'a.aid',
          devices: [{ device_id: 'd1', fp: 'f1' }],
        },
      ],
      audit_aids: ['a.aid', 'z.aid'],
      admin_set: { admin_aids: ['a.aid', 'b.aid'], threshold: 1 },
      recovery_quorum: { trigger: 't', quorum_aids: ['a', 'b', 'c'], threshold: 2 },
      history_policy: 'none',
      wrap_protocol: '3DH',
    };
    const a = computeStateCommitment('g', 1, baseline);
    const b = computeStateCommitment('g', 1, shuffled);
    expect(a).toBe(b);
  });
});
