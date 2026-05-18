import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { computeStateCommitment } from '../../src/v2/state/commitment';

describe('state_commitment - golden', () => {
  it('basic.json', async () => {
    const golden = JSON.parse(
      readFileSync(join(__dirname, 'golden', 'state_commitment', 'basic.json'), 'utf-8'),
    ) as Record<string, unknown>;

    const groupId = golden.group_id as string;
    const epoch = golden.epoch as number;
    const statePayload = golden.state_payload as Record<string, unknown>;
    const expected = golden.expected_commitment_hex as string;

    const commitment = await computeStateCommitment(groupId, epoch, statePayload);

    expect(commitment).toBe(expected);
  });

  it('order independence: shuffled members → same digest', async () => {
    const groupId = 'g-test.agentid.pub';
    const epoch = 1;
    const a = {
      members: [
        { aid: 'alice.aid', devices: [{ device_id: 'd1', fp: 'sha256:fp1' }] },
        { aid: 'bob.aid', devices: [{ device_id: 'd2', fp: 'sha256:fp2' }] },
      ],
      audit_aids: ['x.aid', 'y.aid'],
      admin_set: { admin_aids: ['alice.aid'], threshold: 1 },
      recovery_quorum: null,
      history_policy: 'none',
      wrap_protocol: '3DH',
    };
    const b = {
      members: [
        { aid: 'bob.aid', devices: [{ device_id: 'd2', fp: 'sha256:fp2' }] },
        { aid: 'alice.aid', devices: [{ device_id: 'd1', fp: 'sha256:fp1' }] },
      ],
      audit_aids: ['y.aid', 'x.aid'],
      admin_set: { admin_aids: ['alice.aid'], threshold: 1 },
      recovery_quorum: null,
      history_policy: 'none',
      wrap_protocol: '3DH',
    };

    const c1 = await computeStateCommitment(groupId, epoch, a);
    const c2 = await computeStateCommitment(groupId, epoch, b);
    expect(c1).toBe(c2);
  });

  it('different epoch → different commitment', async () => {
    const groupId = 'g-test.agentid.pub';
    const payload = {
      members: [{ aid: 'alice.aid', devices: [{ device_id: 'd1', fp: 'fp' }] }],
      audit_aids: [],
      admin_set: { admin_aids: ['alice.aid'], threshold: 1 },
      history_policy: 'none',
      wrap_protocol: '1DH',
    };
    const c1 = await computeStateCommitment(groupId, 1, payload);
    const c2 = await computeStateCommitment(groupId, 2, payload);
    expect(c1).not.toBe(c2);
  });
});
