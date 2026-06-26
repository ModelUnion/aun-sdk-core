import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { AUNClient } from '../../src/client.js';
import { createTestClient, registerAndLoadIdentity } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const TEST_TIMEOUT = 90_000;

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function b64(value: string): string {
  return Buffer.from(value, 'utf-8').toString('base64');
}

function decodeText(result: { content?: unknown; source?: unknown }): string {
  return Buffer.from(String(result.content ?? result.source ?? ''), 'base64').toString('utf-8');
}

function asArray<T = unknown>(value: unknown): T[] {
  return Array.isArray(value) ? value as T[] : [];
}

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-collab-ts-'));
  return createTestClient({ aunPath: tmpDir, debug: true, requireForwardSecrecy: false });
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect({ auto_reconnect: false });
}

describe('Collab TypeScript Docker 集成', () => {
  it('create/show/commit/log 使用真实 collab.* RPC', async () => {
    const rid = runId();
    const aliceAid = `collabtsa${rid}.${ISSUER}`;
    const rootPath = `/collab-ts/${rid}/proj`;
    const collabRoot = `${aliceAid}:${rootPath}`;
    const doc = 'spec.md';
    const alice = makeClient();

    try {
      await ensureConnected(alice, aliceAid);

      const created = await alice.collab.create(collabRoot, doc, b64('a\n'));
      expect(created.version).toBe(1);
      expect(String(created.current_target ?? '')).toContain(`${aliceAid}:/`);

      const show1 = await alice.collab.show(collabRoot, doc);
      expect(show1.version).toBe(1);
      expect(decodeText(show1)).toBe('a\n');

      const committed = await alice.collab.commit(collabRoot, doc, b64('a\nb\n'), 1);
      expect(committed.version).toBe(2);
      expect(String(committed.current_target ?? '')).toContain(`${aliceAid}:/`);

      const show2 = await alice.collab.show(collabRoot, doc);
      expect(show2.version).toBe(2);
      expect(decodeText(show2)).toBe('a\nb\n');

      const log = await alice.collab.log(collabRoot, doc);
      expect(log.map((item) => item.version)).toEqual([1, 2]);
      expect(log.every((item) => String(item.target ?? '').startsWith(`${aliceAid}:/`))).toBe(true);

      const diff = await alice.collab.diff(collabRoot, doc, 1, 2);
      expect(diff.diff).toContain('+b');

      const showRev1 = await alice.collab.show(collabRoot, doc, 1);
      expect(decodeText(showRev1)).toBe('a\n');
    } finally {
      await alice.storage.remove(rootPath, { owner: aliceAid, recursive: true }).catch(() => undefined);
      await alice.close();
    }
  }, TEST_TIMEOUT);

  it('merge/tag/clone/reflog/prune 使用真实 collab.* RPC', async () => {
    const rid = runId();
    const aliceAid = `collabtsadv${rid}.${ISSUER}`;
    const rootPath = `/collab-ts/${rid}/advanced`;
    const conflictPath = `/collab-ts/${rid}/conflict`;
    const clonePath = `/collab-ts/${rid}/clone`;
    const adoptPath = `/collab-ts/${rid}/adopt`;
    const collabRoot = `${aliceAid}:${rootPath}`;
    const conflictRoot = `${aliceAid}:${conflictPath}`;
    const cloneRoot = `${aliceAid}:${clonePath}`;
    const adoptRoot = `${aliceAid}:${adoptPath}`;
    const doc = 'guide.md';
    const alice = makeClient();

    try {
      await ensureConnected(alice, aliceAid);

      await alice.collab.create(collabRoot, doc, b64('line1\nline2\nline3\n'));
      await alice.collab.commit(collabRoot, doc, b64('line1\nLINE2\nline3\n'), 1, 'theirs');

      const merged = await alice.collab.merge(collabRoot, doc, b64('line1\nline2\nLINE3\n'), 1);
      expect(merged.conflicts).toBe(false);
      expect(decodeText(merged)).toBe('line1\nLINE2\nLINE3\n');

      await expect(alice.collab.commit(collabRoot, doc, b64('stale\n'), 1, 'stale')).rejects.toThrow();

      await alice.collab.create(conflictRoot, doc, b64('X\n'));
      await alice.collab.commit(conflictRoot, doc, b64('THEIRS\n'), 1, 'theirs');
      const conflict = await alice.collab.merge(conflictRoot, doc, b64('OURS\n'), 1);
      expect(conflict.conflicts).toBe(true);
      expect(decodeText(conflict)).toContain('<<<<<<< ours');

      const tag1 = await alice.collab.tag.create(collabRoot, { message: 'init' });
      expect(tag1.version).toBe('1.0.0');
      await alice.collab.commit(collabRoot, doc, b64('line1\nLINE2\nLINE3\nv4\n'), 2, 'patch');
      const tag2 = await alice.collab.tag.create(collabRoot, { message: 'patch' });
      expect(tag2.version).toBe('1.0.1');

      const tags = await alice.collab.tag.list(collabRoot);
      expect(tags.map((item) => item.version)).toEqual(['1.0.0', '1.0.1']);
      const shownTag = await alice.collab.tag.show(collabRoot, '1.0.0');
      expect(asArray<{ doc?: unknown }>(shownTag.entries).some((entry) => entry.doc === doc)).toBe(true);
      const tagDiff = await alice.collab.tag.diff(collabRoot, '1.0.0', '1.0.1');
      expect(asArray(tagDiff.changed).length + asArray(tagDiff.modified).length).toBeGreaterThan(0);

      const restored = await alice.collab.tag.restore(collabRoot, '1.0.0', { message: 'restore' });
      expect(restored.restored_from).toBe('1.0.0');
      expect(decodeText(await alice.collab.show(collabRoot, doc))).toBe('line1\nLINE2\nline3\n');

      const cloned = await alice.collab.clone(collabRoot, cloneRoot, false);
      expect(cloned.ok).toBe(true);
      expect(cloned.dest).toBe(cloneRoot);
      expect((await alice.collab.log(cloneRoot, doc)).length).toBeGreaterThanOrEqual(3);

      const adopted = await alice.collab.clone(collabRoot, adoptRoot, true);
      expect(adopted.new_root).toBe(adoptRoot);
      expect(adopted.new_authority_aid).toBe(aliceAid);

      const reflog = await alice.collab.reflog(collabRoot, doc, 20);
      expect(reflog.length).toBeGreaterThan(0);
      const pruned = await alice.collab.prune(conflictRoot, doc);
      expect(Number(pruned.pruned ?? 0)).toBeGreaterThanOrEqual(0);
    } finally {
      await alice.storage.remove(rootPath, { owner: aliceAid, recursive: true }).catch(() => undefined);
      await alice.storage.remove(conflictPath, { owner: aliceAid, recursive: true }).catch(() => undefined);
      await alice.storage.remove(clonePath, { owner: aliceAid, recursive: true }).catch(() => undefined);
      await alice.storage.remove(adoptPath, { owner: aliceAid, recursive: true }).catch(() => undefined);
      await alice.close();
    }
  }, TEST_TIMEOUT);
});
