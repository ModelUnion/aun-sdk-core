// ── Playwright E2E 浏览器测试：Collab 协作层 smoke ──────────────
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/collab.spec.ts --grep collab --reporter=line
//
// 前置条件：
//   - Docker 单域环境运行中（不要由测试脚本启动 Kite）
//   - 浏览器通过 --host-resolver-rules 解析 gateway.agentid.pub → 127.0.0.1

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
      if (addr && typeof addr === 'object') {
        baseUrl = `http://127.0.0.1:${addr.port}`;
      }
      resolve();
    });
  });
});

test.afterAll(async () => {
  if (server) {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

function testPageUrl(): string {
  return `${baseUrl}/tests/e2e-browser/test-page.html`;
}

async function installCollabHelpers(page: any): Promise<void> {
  await page.evaluate((issuer: string) => {
    const w = window as any;
    if (w.__collabSmoke) return;

    const makeAndConnect = async (instanceId: string, aid: string): Promise<any> => {
      const client = w.AUN_TEST_HELPERS.createClient({
        aunPath: `js-collab-${instanceId}`,
        deviceId: instanceId,
        requireForwardSecrecy: false,
      });
      await w.AUN_TEST_HELPERS.connectIdentity(client, aid);
      return client;
    };
    const runId = () => crypto.randomUUID().replace(/-/g, '').slice(0, 10);
    const b64 = (text: string) => btoa(unescape(encodeURIComponent(text)));
    const text = (content: string) => decodeURIComponent(escape(atob(content)));
    const isCollabUnavailable = (err: any) => {
      const message = String(err?.message ?? err ?? '').toLowerCase();
      return message.includes('method not found')
        || message.includes('not implement')
        || message.includes('collab disabled')
        || message.includes('collab not initialized');
    };

    w.__collabSmoke = { makeAndConnect, runId, b64, text, isCollabUnavailable, ISSUER: issuer };
  }, ISSUER);
}

test.describe('collab 浏览器 SDK smoke', () => {
  test.setTimeout(120_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installCollabHelpers(page);
  });

  test('collab create/show/commit/log 使用裸 collab.* RPC', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { makeAndConnect, runId, b64, text, isCollabUnavailable, ISSUER } = (window as any).__collabSmoke;
      const rid = runId();
      const aliceAid = `jscol${rid}.${ISSUER}`;
      const collabRoot = `${aliceAid}:/collab-smoke/${rid}/proj`;
      const doc = 'spec.md';
      const alice = await makeAndConnect(`alice-${rid}`, aliceAid);

      try {
        let created: any;
        try {
          created = await alice.collab.create(collabRoot, doc, b64(`v1-${rid}\n`));
        } catch (err: any) {
          if (isCollabUnavailable(err)) {
            return { skip: true, reason: `collab.* 不可用: ${err?.message ?? String(err)}` };
          }
          throw err;
        }

        const shown = await alice.collab.show(collabRoot, doc);
        const committed = await alice.collab.commit(collabRoot, doc, b64(`v1-${rid}\nv2-${rid}\n`), 1);
        const log = await alice.collab.log(collabRoot, doc);
        const diff = await alice.collab.diff(collabRoot, doc, 1, 2);
        const shownRev1 = await alice.collab.show(collabRoot, doc, 1);

        try {
          await alice.storage.remove(`/collab-smoke/${rid}`, { owner: aliceAid, recursive: true });
        } catch {
          // 清理失败不影响 smoke 结论。
        }

        return {
          skip: false,
          createdVersion: Number(created?.version ?? 0),
          showVersion: Number(shown?.version ?? 0),
          showText: text(String(shown?.content ?? '')),
          commitVersion: Number(committed?.version ?? 0),
          logVersions: Array.isArray(log) ? log.map((item: any) => Number(item?.version ?? 0)) : [],
          targetIsAidPath: String(committed?.current_target ?? '').startsWith(`${aliceAid}:/`),
          diffText: String(diff?.diff ?? ''),
          showRev1Text: text(String(shownRev1?.content ?? '')),
        };
      } finally {
        await alice.close();
      }
    });

    if ((result as any).skip) {
      console.log((result as any).reason);
      test.skip();
      return;
    }

    expect((result as any).createdVersion).toBe(1);
    expect((result as any).showVersion).toBe(1);
    expect((result as any).showText).toContain('v1-');
    expect((result as any).commitVersion).toBe(2);
    expect((result as any).logVersions).toEqual([1, 2]);
    expect((result as any).targetIsAidPath).toBe(true);
    expect((result as any).diffText).toContain('+v2-');
    expect((result as any).showRev1Text).toContain('v1-');
  });

  test('collab merge/tag/clone/reflog/prune 使用裸 collab.* RPC', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { makeAndConnect, runId, b64, text, isCollabUnavailable, ISSUER } = (window as any).__collabSmoke;
      const rid = runId();
      const aliceAid = `jscoladv${rid}.${ISSUER}`;
      const rootPath = `/collab-smoke/${rid}/advanced`;
      const conflictPath = `/collab-smoke/${rid}/conflict`;
      const clonePath = `/collab-smoke/${rid}/clone`;
      const adoptPath = `/collab-smoke/${rid}/adopt`;
      const collabRoot = `${aliceAid}:${rootPath}`;
      const conflictRoot = `${aliceAid}:${conflictPath}`;
      const cloneRoot = `${aliceAid}:${clonePath}`;
      const adoptRoot = `${aliceAid}:${adoptPath}`;
      const doc = 'guide.md';
      const alice = await makeAndConnect(`alice-adv-${rid}`, aliceAid);

      try {
        try {
          await alice.collab.create(collabRoot, doc, b64('line1\nline2\nline3\n'));
        } catch (err: any) {
          if (isCollabUnavailable(err)) {
            return { skip: true, reason: `collab.* 不可用: ${err?.message ?? String(err)}` };
          }
          throw err;
        }
        await alice.collab.commit(collabRoot, doc, b64('line1\nLINE2\nline3\n'), 1, 'theirs');

        const merged = await alice.collab.merge(collabRoot, doc, b64('line1\nline2\nLINE3\n'), 1);
        let staleDenied = false;
        try {
          await alice.collab.commit(collabRoot, doc, b64('stale\n'), 1, 'stale');
        } catch {
          staleDenied = true;
        }

        await alice.collab.create(conflictRoot, doc, b64('X\n'));
        await alice.collab.commit(conflictRoot, doc, b64('THEIRS\n'), 1, 'theirs');
        const conflict = await alice.collab.merge(conflictRoot, doc, b64('OURS\n'), 1);

        const tag1 = await alice.collab.tag.create(collabRoot, { message: 'init' });
        await alice.collab.commit(collabRoot, doc, b64('line1\nLINE2\nLINE3\nv4\n'), 2, 'patch');
        const tag2 = await alice.collab.tag.create(collabRoot, { message: 'patch' });
        const tags = await alice.collab.tag.list(collabRoot);
        const shownTag = await alice.collab.tag.show(collabRoot, '1.0.0');
        const tagDiff = await alice.collab.tag.diff(collabRoot, '1.0.0', '1.0.1');
        const restored = await alice.collab.tag.restore(collabRoot, '1.0.0', { message: 'restore' });
        const afterRestore = await alice.collab.show(collabRoot, doc);
        const cloned = await alice.collab.clone(collabRoot, cloneRoot, false);
        const clonedLog = await alice.collab.log(cloneRoot, doc);
        const adopted = await alice.collab.clone(collabRoot, adoptRoot, true);
        const reflog = await alice.collab.reflog(collabRoot, doc, 20);
        const pruned = await alice.collab.prune(conflictRoot, doc);

        for (const p of [rootPath, conflictPath, clonePath, adoptPath]) {
          try {
            await alice.storage.remove(p, { owner: aliceAid, recursive: true });
          } catch {
            // 清理失败不影响测试结论。
          }
        }

        return {
          skip: false,
          mergedConflicts: merged?.conflicts,
          mergedText: text(String(merged?.content ?? '')),
          staleDenied,
          conflictConflicts: conflict?.conflicts,
          conflictText: text(String(conflict?.content ?? '')),
          tagVersions: [tag1?.version, tag2?.version],
          listedVersions: Array.isArray(tags) ? tags.map((item: any) => item?.version) : [],
          tagHasDoc: Array.isArray(shownTag?.entries) && shownTag.entries.some((entry: any) => entry?.doc === doc),
          tagChanged: (tagDiff?.changed?.length ?? 0) + (tagDiff?.modified?.length ?? 0),
          restoredFrom: restored?.restored_from,
          afterRestoreText: text(String(afterRestore?.content ?? '')),
          cloneOk: cloned?.ok === true && cloned?.dest === cloneRoot,
          clonedLogCount: Array.isArray(clonedLog) ? clonedLog.length : 0,
          adoptedRoot: adopted?.new_root,
          adoptedAuthority: adopted?.new_authority_aid,
          reflogCount: Array.isArray(reflog) ? reflog.length : 0,
          prunedCount: Number(pruned?.pruned ?? 0),
        };
      } finally {
        await alice.close();
      }
    });

    if ((result as any).skip) {
      console.log((result as any).reason);
      test.skip();
      return;
    }

    const r = result as any;
    expect(r.mergedConflicts).toBe(false);
    expect(r.mergedText).toBe('line1\nLINE2\nLINE3\n');
    expect(r.staleDenied).toBe(true);
    expect(r.conflictConflicts).toBe(true);
    expect(r.conflictText).toContain('<<<<<<< ours');
    expect(r.tagVersions).toEqual(['1.0.0', '1.0.1']);
    expect(r.listedVersions).toEqual(['1.0.0', '1.0.1']);
    expect(r.tagHasDoc).toBe(true);
    expect(r.tagChanged).toBeGreaterThan(0);
    expect(r.restoredFrom).toBe('1.0.0');
    expect(r.afterRestoreText).toBe('line1\nLINE2\nline3\n');
    expect(r.cloneOk).toBe(true);
    expect(r.clonedLogCount).toBeGreaterThanOrEqual(3);
    expect(r.adoptedRoot).toContain('/adopt');
    expect(r.adoptedAuthority).toContain('jscoladv');
    expect(r.reflogCount).toBeGreaterThan(0);
    expect(r.prunedCount).toBeGreaterThanOrEqual(0);
  });
});
