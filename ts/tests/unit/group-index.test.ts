import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import { AUNClient } from '../../src/client.js';
import { resultOk } from '../../src/result.js';
import {
  GROUP_INDEX_KEY,
  GROUP_INDEX_SCHEMA,
  GroupIndexMetaCache,
  buildSignedGroupIndex,
  computeGroupIndexBodyHash,
  groupIndexEtag,
  parseGroupIndex,
  prepareGroupSettingsWithIndex,
  verifyGroupIndex,
} from '../../src/group-index.js';

function payloadBytes(payload: Buffer | Uint8Array | string): Buffer {
  return typeof payload === 'string' ? Buffer.from(payload, 'utf-8') : Buffer.from(payload);
}

function fakeSigner(aid = 'owner.example.test') {
  return {
    aid,
    sign: vi.fn((payload: Buffer | Uint8Array | string) =>
      resultOk({ signature: payloadBytes(payload).toString('base64') }),
    ),
    verify: vi.fn((payload: Buffer | Uint8Array | string, signature: string) =>
      resultOk({ valid: signature === payloadBytes(payload).toString('base64') }),
    ),
  };
}

describe('group index JSONL', () => {
  it('computes body hash and etag from sorted canonical entries', () => {
    const entries = [
      { key: 'rules.content', source: 'db', etag: '"sha256:rules"', last_modified: 2 },
      { key: 'announcement.content', source: 'db', etag: '"sha256:ann"', last_modified: 1 },
    ];

    expect(computeGroupIndexBodyHash(entries)).toBe(
      'sha256:88a4efec147e1d95d95a0868aca6f26447fd5f1f1d22b7c5a2ea5fd03ddbd30e',
    );
    expect(groupIndexEtag(entries)).toBe(
      '"sha256:88a4efec147e1d95d95a0868aca6f26447fd5f1f1d22b7c5a2ea5fd03ddbd30e"',
    );
  });

  it('builds a signed index and verifies signature payload without signature field', () => {
    const signer = fakeSigner();

    const signed = buildSignedGroupIndex({
      groupAid: 'g-team.example.test',
      entries: [{ key: 'rules.content', source: 'db', etag: '"sha256:rules"', last_modified: 2 }],
      signer,
      lastModified: 1000,
    });

    const parsed = parseGroupIndex(signed.body);
    expect(parsed.meta).toMatchObject({
      type: 'index_meta',
      group_aid: 'g-team.example.test',
      schema: GROUP_INDEX_SCHEMA,
      signed_by: signer.aid,
      sig_alg: 'ECDSA-P256-SHA256',
    });
    expect(parsed.entries.map((item) => item.key)).toEqual(['rules.content']);
    expect(signer.sign).toHaveBeenCalledTimes(1);

    const verified = verifyGroupIndex(signed.body, signer);
    expect(verified.ok && verified.data.valid).toBe(true);
    expect(signer.verify).toHaveBeenCalledTimes(1);
  });

  it('prepares settings by merging the current index and replacing changed keys', () => {
    const signer = fakeSigner();
    const base = buildSignedGroupIndex({
      groupAid: 'g-team.example.test',
      entries: [
        { key: 'rules.content', source: 'db', etag: '"sha256:old"', last_modified: 1 },
        { key: 'announcement.content', source: 'db', etag: '"sha256:ann"', last_modified: 1 },
      ],
      signer,
      lastModified: 1,
    });

    const settings = prepareGroupSettingsWithIndex({
      groupAid: 'g-team.example.test',
      settings: { 'rules.content': '新群规' },
      signer,
      lastModified: 2000,
      baseIndex: base,
    });

    expect(settings['rules.content']).toBe('新群规');
    const index = parseGroupIndex(settings[GROUP_INDEX_KEY]);
    expect(index.entries).toEqual([
      { key: 'announcement.content', source: 'db', etag: '"sha256:ann"', last_modified: 1 },
      {
        key: 'rules.content',
        source: 'db',
        etag: '"sha256:c43beb3d1be3d5fb41b8bf8cd11248d49382f5138a033c8f1679c116be6fa97a"',
        last_modified: 2000,
      },
    ]);
  });
});

describe('group index meta cache', () => {
  it('marks a local index stale when gateway meta advertises a newer etag', () => {
    const cache = new GroupIndexMetaCache();

    cache.observeRpcMeta(
      { group_indexes: { 'g-team.example.test': { etag: '"one"', last_modified: 1, schema: GROUP_INDEX_SCHEMA } } },
      { localAid: 'alice.example.test' },
    );

    expect(cache.isStale('alice.example.test', 'g-team.example.test')).toBe(true);
    expect(cache.remoteMeta('alice.example.test', 'g-team.example.test')).toEqual({
      etag: '"one"',
      last_modified: 1,
      schema: GROUP_INDEX_SCHEMA,
    });

    cache.markFresh('alice.example.test', 'g-team.example.test', { etag: '"one"' });
    expect(cache.isStale('alice.example.test', 'g-team.example.test')).toBe(false);
  });

  it('persists pulled index JSONL and cache envelope under local aid and group aid', () => {
    const root = mkdtempSync(join(tmpdir(), 'aun-group-index-'));
    const signer = fakeSigner();
    const signed = buildSignedGroupIndex({
      groupAid: 'g-team.example.test',
      entries: [{ key: 'rules.content', source: 'db', etag: '"entry-v1"', last_modified: 1 }],
      signer,
      lastModified: 1,
    });
    const entries = [{ key: 'rules.content', etag: '"entry-v1"' }];
    const cache = new GroupIndexMetaCache(root);

    cache.observeRpcMeta(
      { group_indexes: { 'g-team.example.test': { etag: '"v1"', last_modified: 1, schema: GROUP_INDEX_SCHEMA } } },
      { localAid: 'alice.example.test' },
    );
    cache.markFresh('alice.example.test', 'g-team.example.test', { etag: '"v1"' });
    cache.cacheSettings(
      'alice.example.test',
      'g-team.example.test',
      { 'rules.content': '缓存群规' },
      { entries, etag: '"v1"', groupIndex: signed },
    );

    const cacheDir = join(root, 'AIDs', 'alice.example.test', 'groups', 'g-team.example.test');
    expect(readFileSync(join(cacheDir, 'index.jsonl'), 'utf-8')).toBe(signed.body);
    expect(JSON.parse(readFileSync(join(cacheDir, 'group-index-cache.json'), 'utf-8')).settings['rules.content']).toBe('缓存群规');

    const restored = new GroupIndexMetaCache(root);
    expect(restored.localEtag('alice.example.test', 'g-team.example.test')).toBe('"v1"');
    expect(restored.remoteMeta('alice.example.test', 'g-team.example.test')).toEqual({
      etag: '"v1"',
      last_modified: 1,
      schema: GROUP_INDEX_SCHEMA,
    });
    expect(restored.cachedSettings('alice.example.test', 'g-team.example.test', ['rules.content'])).toEqual({
      'rules.content': '缓存群规',
    });
    expect(restored.cachedSettingsByEntries('alice.example.test', 'g-team.example.test', ['rules.content'], entries as any)).toEqual({
      cached: { 'rules.content': '缓存群规' },
      missing: [],
    });
  });

  it('AUNClient observes group_indexes meta and exposes stale/fresh helpers', () => {
    const client = new AUNClient();
    (client as any)._groupIndexMetaCache = new GroupIndexMetaCache(mkdtempSync(join(tmpdir(), 'aun-group-index-client-')));
    (client as any)._aid = 'alice.example.test';

    (client as any)._observeRpcMeta({
      group_indexes: { 'g-team.example.test': { etag: '"one"', last_modified: 1, schema: GROUP_INDEX_SCHEMA } },
    });

    expect(client.isGroupIndexStale('g-team.example.test')).toBe(true);
    client.markGroupIndexFresh('g-team.example.test', { etag: '"one"' });
    expect(client.isGroupIndexStale('g-team.example.test')).toBe(false);
  });
});
