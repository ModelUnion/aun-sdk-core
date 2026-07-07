import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as http from 'http';
import * as fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JS_ROOT = path.resolve(__dirname, '..', '..');
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

let server: http.Server;
let baseUrl: string;

test.beforeAll(async () => {
  server = http.createServer((req, res) => {
    const safePath = (req.url ?? '/').split('?')[0];
    const filePath = path.join(JS_ROOT, safePath);
    if (!filePath.startsWith(JS_ROOT)) {
      res.writeHead(403);
      res.end('Forbidden');
      return;
    }
    const ext = path.extname(filePath);
    const mimeTypes: Record<string, string> = {
      '.html': 'text/html',
      '.js': 'application/javascript',
      '.mjs': 'application/javascript',
      '.css': 'text/css',
      '.json': 'application/json',
    };
    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(404);
        res.end('Not Found');
        return;
      }
      res.writeHead(200, { 'Content-Type': mimeTypes[ext] ?? 'application/octet-stream' });
      res.end(data);
    });
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

test.afterAll(async () => {
  if (server) await new Promise<void>((resolve) => server.close(() => resolve()));
});

test('browser SDK writes signed group.index and retries after CAS conflict', async ({ page }) => {
  test.setTimeout(60_000);
  await page.goto(`${baseUrl}/tests/e2e-browser/test-page.html`);
  await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });

  const result = await page.evaluate(async (issuer: string) => {
    const w = window as any;
    const AUN = w.AUN;
    const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
    const runId = () => crypto.randomUUID().replace(/-/g, '').slice(0, 8);
    const settingsMap = (rpc: any) => {
      const out: Record<string, any> = {};
      for (const item of rpc?.settings ?? []) out[item.key] = item.value;
      return out;
    };

    const rid = runId();
    const aliceAid = `jsgi-a-${rid}.${issuer}`;
    const bobAid = `jsgi-b-${rid}.${issuer}`;
    const alice = w.AUN_TEST_HELPERS.createClient({ aunPath: `js-gi-a-${rid}`, deviceId: `js-gi-a-${rid}`, requireForwardSecrecy: false });
    const bob = w.AUN_TEST_HELPERS.createClient({ aunPath: `js-gi-b-${rid}`, deviceId: `js-gi-b-${rid}`, requireForwardSecrecy: false });
    let groupId = '';

    try {
      await w.AUN_TEST_HELPERS.connectIdentity(alice, aliceAid);
      await w.AUN_TEST_HELPERS.connectIdentity(bob, bobAid);

      const created = await alice.group.create({ name: `js-group-index-${rid}`, visibility: 'public' });
      groupId = created?.group?.group_id ?? created?.group_id ?? '';
      if (!groupId) return { error: 'group.create 未返回 group_id' };

      await alice.group.addMember({ group_id: groupId, aid: bobAid });
      await alice.group.setRole({ group_id: groupId, aid: bobAid, role: 'admin' });
      await sleep(300);

      const first = await alice.group.updateGroupIndex({
        group_id: groupId,
        settings: { 'rules.content': `群规 v1 ${rid}` },
      });
      const bobRead = await bob.group.getSettings({ group_id: groupId, keys: [AUN.GROUP_INDEX_KEY] });
      const groupAid = bobRead.group_aid ?? groupId;
      const firstIndex = settingsMap(bobRead)[AUN.GROUP_INDEX_KEY];
      const firstParsed = AUN.parseGroupIndex(firstIndex);
      const firstVerified = await AUN.verifyGroupIndex(firstIndex, alice.currentAid);
      const staleBefore = bob.isGroupIndexStale(groupAid);
      const bobRemoteMetaBefore = bob.getGroupIndexRemoteMeta(groupAid);
      const bobLocalEtagBefore = bob.getGroupIndexLocalEtag(groupAid);
      bob.markGroupIndexFresh(groupAid, { etag: String(firstParsed.meta.etag) });
      const staleAfter = bob.isGroupIndexStale(groupAid);

      let bareRejected = false;
      try {
        await alice.group.setSettings({ group_id: groupId, settings: { 'rules.content': '裸写应失败' } });
      } catch (e: any) {
        bareRejected = /group\.index|indexed/i.test(e?.message ?? String(e));
      }

      const baseEtag = String(firstParsed.meta.etag ?? '');
      const aliceUpdate = await AUN.prepareGroupSettingsWithIndex({
        groupAid,
        settings: { 'rules.content': `群规 v2 ${rid}` },
        signer: alice.currentAid,
        lastModified: Date.now(),
        baseIndex: firstIndex,
      });
      await alice.group.setSettings({
        group_id: groupId,
        settings: aliceUpdate,
        expected_index_etag: baseEtag,
      });

      const staleBobUpdate = await AUN.prepareGroupSettingsWithIndex({
        groupAid,
        settings: { 'announcement.content': `公告 stale ${rid}` },
        signer: bob.currentAid,
        lastModified: Date.now(),
        baseIndex: firstIndex,
      });
      let casConflict = false;
      try {
        await bob.group.setSettings({
          group_id: groupId,
          settings: staleBobUpdate,
          expected_index_etag: baseEtag,
        });
      } catch (e: any) {
        casConflict = /etag conflict/i.test(e?.message ?? String(e));
      }

      const retried = await bob.group.updateGroupIndex({
        group_id: groupId,
        settings: { 'announcement.content': `公告 v2 ${rid}` },
      });
      const finalRead = await alice.group.getSettings({
        group_id: groupId,
        keys: [AUN.GROUP_INDEX_KEY, 'rules.content', 'announcement.content'],
      });
      const finalSettings = settingsMap(finalRead);
      const finalParsed = AUN.parseGroupIndex(finalSettings[AUN.GROUP_INDEX_KEY]);
      return {
        firstUpdatedKeys: first.updated_keys ?? [],
        firstVerified: firstVerified.ok && firstVerified.data.valid,
        staleBefore,
        staleDebug: {
          groupAid,
          bobReadKeys: Object.keys(bobRead ?? {}),
          bobReadMeta: bobRead?._meta ?? null,
          bobRemoteMetaBefore,
          bobLocalEtagBefore,
          firstEtag: String(firstParsed.meta.etag ?? ''),
        },
        staleAfter,
        bareRejected,
        casConflict,
        retriedKeys: retried.updated_keys ?? [],
        finalSignedBy: finalParsed.meta.signed_by,
        finalKeys: finalParsed.entries.map((item: any) => item.key).sort(),
        finalRules: finalSettings['rules.content'],
        finalAnnouncement: finalSettings['announcement.content'],
        expectedRules: `群规 v2 ${rid}`,
        expectedAnnouncement: `公告 v2 ${rid}`,
        bobAid,
      };
    } finally {
      if (groupId) {
        try { await alice.group.dissolve({ group_id: groupId }); } catch {}
      }
      await alice.close();
      await bob.close();
    }
  }, ISSUER);

  const r = result as any;
  if (r.error) throw new Error(r.error);
  expect(r.firstUpdatedKeys).toContain('group.index');
  expect(r.firstUpdatedKeys).toContain('rules.content');
  expect(r.firstVerified).toBe(true);
  expect(r.staleBefore, JSON.stringify(r.staleDebug)).toBe(true);
  expect(r.staleAfter).toBe(false);
  expect(r.bareRejected).toBe(true);
  expect(r.casConflict).toBe(true);
  expect(r.retriedKeys).toContain('announcement.content');
  expect(r.finalSignedBy).toBe(r.bobAid);
  expect(r.finalKeys).toEqual(['announcement.content', 'rules.content']);
  expect(r.finalRules).toBe(r.expectedRules);
  expect(r.finalAnnouncement).toBe(r.expectedAnnouncement);
});
