import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';
import {
  GROUP_INDEX_KEY,
  parseGroupIndex,
  prepareGroupSettingsWithIndex,
  verifyGroupIndex,
} from '../../src/group-index.js';
import { createTestClient, registerAndLoadIdentity } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-gi-'));
  return createTestClient({ aunPath: tmpDir, debug: true, requireForwardSecrecy: false });
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect();
}

function settingsMap(result: Record<string, any>): Record<string, any> {
  const out: Record<string, any> = {};
  for (const item of result.settings ?? []) out[item.key] = item.value;
  return out;
}

describe('Group Index integration', () => {
  it('writes signed group.index, rejects bare indexed writes, and retries after CAS conflict', async () => {
    const rid = runId();
    const aliceAid = `gi-a-${rid}.${ISSUER}`;
    const bobAid = `gi-b-${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();
    let groupId = '';

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      const created = await alice.group.create({ name: `group-index-${rid}`, visibility: 'public' });
      groupId = String((created as any).group?.group_id ?? '');
      expect(groupId).toBeTruthy();

      await alice.group.addMember({ group_id: groupId, aid: bobAid });
      await alice.group.setRole({ group_id: groupId, aid: bobAid, role: 'admin' });

      const first = await alice.group.updateGroupIndex({
        group_id: groupId,
        settings: { 'rules.content': `群规 v1 ${rid}` },
      });
      expect((first as any).updated_keys).toContain(GROUP_INDEX_KEY);
      expect((first as any).updated_keys).toContain('rules.content');

      const bobRead = await bob.group.getSettings({ group_id: groupId, keys: [GROUP_INDEX_KEY] });
      const groupAid = String((bobRead as any).group_aid ?? groupId);
      const firstIndex = settingsMap(bobRead as any)[GROUP_INDEX_KEY];
      const firstParsed = parseGroupIndex(firstIndex);
      const firstVerified = verifyGroupIndex(firstIndex, alice.currentAid as any);
      expect(firstVerified.ok && firstVerified.data.valid).toBe(true);
      expect(firstParsed.entries.map((item) => item.key)).toContain('rules.content');
      expect(bob.isGroupIndexStale(groupAid)).toBe(true);
      bob.markGroupIndexFresh(groupAid, { etag: String(firstParsed.meta.etag) });
      expect(bob.isGroupIndexStale(groupAid)).toBe(false);

      await expect(
        alice.group.setSettings({ group_id: groupId, settings: { 'rules.content': '裸写应失败' } }),
      ).rejects.toThrow(/group\.index|indexed/i);

      const baseIndex = firstIndex;
      const baseEtag = String(firstParsed.meta.etag ?? '');
      const aliceUpdate = prepareGroupSettingsWithIndex({
        groupAid,
        settings: { 'rules.content': `群规 v2 ${rid}` },
        signer: alice.currentAid as any,
        lastModified: Date.now(),
        baseIndex,
      });
      await alice.group.setSettings({
        group_id: groupId,
        settings: aliceUpdate,
        expected_index_etag: baseEtag,
      });

      const staleBobUpdate = prepareGroupSettingsWithIndex({
        groupAid,
        settings: { 'announcement.content': `公告 stale ${rid}` },
        signer: bob.currentAid as any,
        lastModified: Date.now(),
        baseIndex,
      });
      await expect(
        bob.group.setSettings({
          group_id: groupId,
          settings: staleBobUpdate,
          expected_index_etag: baseEtag,
        }),
      ).rejects.toThrow(/etag conflict/i);

      const retried = await bob.group.updateGroupIndex({
        group_id: groupId,
        settings: { 'announcement.content': `公告 v2 ${rid}` },
      });
      expect((retried as any).updated_keys).toContain('announcement.content');

      const finalRead = await alice.group.getSettings({
        group_id: groupId,
        keys: [GROUP_INDEX_KEY, 'rules.content', 'announcement.content'],
      });
      const finalSettings = settingsMap(finalRead as any);
      const finalParsed = parseGroupIndex(finalSettings[GROUP_INDEX_KEY]);
      expect(finalParsed.meta.signed_by).toBe(bobAid);
      expect(finalParsed.entries.map((item) => item.key).sort()).toEqual(['announcement.content', 'rules.content']);
      expect(finalSettings['rules.content']).toBe(`群规 v2 ${rid}`);
      expect(finalSettings['announcement.content']).toBe(`公告 v2 ${rid}`);
    } finally {
      if (groupId) {
        try { await alice.group.dissolve({ group_id: groupId }); } catch { /* ignore cleanup */ }
      }
      await alice.close();
      await bob.close();
    }
  }, 60_000);
});
