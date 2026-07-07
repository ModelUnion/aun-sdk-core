import { describe, expect, it, vi } from 'vitest';

import { AUNClient } from '../../src/client.js';
import { IndexedDBTokenStore } from '../../src/keystore/indexeddb-token-store.js';
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

const encoder = new TextEncoder();

function payloadBytes(payload: Uint8Array | string): Uint8Array {
  return typeof payload === 'string' ? encoder.encode(payload) : payload;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function fakeSigner(aid = 'owner.example.test') {
  return {
    aid,
    sign: vi.fn(async (payload: Uint8Array | string) =>
      resultOk({ signature: bytesToBase64(payloadBytes(payload)) }),
    ),
    verify: vi.fn(async (payload: Uint8Array | string, signature: string) =>
      resultOk({ valid: signature === bytesToBase64(payloadBytes(payload)) }),
    ),
  };
}

describe('browser group index JSONL', () => {
  it('computes body hash and etag from sorted canonical entries', async () => {
    const entries = [
      { key: 'rules.content', source: 'db', etag: '"sha256:rules"', last_modified: 2 },
      { key: 'announcement.content', source: 'db', etag: '"sha256:ann"', last_modified: 1 },
    ];

    expect(await computeGroupIndexBodyHash(entries)).toBe(
      'sha256:88a4efec147e1d95d95a0868aca6f26447fd5f1f1d22b7c5a2ea5fd03ddbd30e',
    );
    expect(await groupIndexEtag(entries)).toBe(
      '"sha256:88a4efec147e1d95d95a0868aca6f26447fd5f1f1d22b7c5a2ea5fd03ddbd30e"',
    );
  });

  it('builds a signed index and verifies signature payload without signature field', async () => {
    const signer = fakeSigner();

    const signed = await buildSignedGroupIndex({
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

    const verified = await verifyGroupIndex(signed.body, signer);
    expect(verified.ok && verified.data.valid).toBe(true);
    expect(signer.verify).toHaveBeenCalledTimes(1);
  });

  it('prepares settings by merging the current index and replacing changed keys', async () => {
    const signer = fakeSigner();
    const base = await buildSignedGroupIndex({
      groupAid: 'g-team.example.test',
      entries: [
        { key: 'rules.content', source: 'db', etag: '"sha256:old"', last_modified: 1 },
        { key: 'announcement.content', source: 'db', etag: '"sha256:ann"', last_modified: 1 },
      ],
      signer,
      lastModified: 1,
    });

    const settings = await prepareGroupSettingsWithIndex({
      groupAid: 'g-team.example.test',
      settings: { 'rules.content': '新群规' },
      signer,
      lastModified: 2000,
      baseIndex: base,
    });

    expect(settings['rules.content']).toBe('新群规');
    const index = parseGroupIndex(settings[GROUP_INDEX_KEY] as any);
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

describe('browser group index meta cache', () => {
  it('marks a local index stale when gateway meta advertises a newer etag', () => {
    const cache = new GroupIndexMetaCache();

    cache.observeRpcMeta(
      { group_indexes: { 'g-team.example.test': { etag: '"one"', last_modified: 1, schema: GROUP_INDEX_SCHEMA } } },
      { localAid: 'alice.example.test' },
    );

    expect(cache.isStale('alice.example.test', 'g-team.example.test')).toBe(true);
    cache.markFresh('alice.example.test', 'g-team.example.test', { etag: '"one"' });
    expect(cache.isStale('alice.example.test', 'g-team.example.test')).toBe(false);
  });

  it('AUNClient observes group_indexes meta and exposes stale/fresh helpers', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'alice.example.test';
    (client as any)._agentMdManager = { observeRpcMeta: vi.fn(async () => undefined) };
    const observeSpy = vi.spyOn((client as any)._groupIndexMetaCache, 'observeRpcMeta');

    await (client as any)._observeRpcMeta({
      group_indexes: { 'g-team.example.test': { etag: '"one"', last_modified: 1, schema: GROUP_INDEX_SCHEMA } },
    });

    expect(observeSpy).toHaveBeenCalledTimes(1);
    expect(client.isGroupIndexStale('g-team.example.test')).toBe(true);
    client.markGroupIndexFresh('g-team.example.test', { etag: '"one"' });
    expect(client.isGroupIndexStale('g-team.example.test')).toBe(false);
  });

  it('waits for async RPC meta observation before transport observer resolves', async () => {
    const client = new AUNClient();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let observed = false;
    (client as any)._observeRpcMeta = vi.fn(async () => {
      await gate;
      observed = true;
    });

    const observer = (client as any)._transport._metaObserver as ((meta: Record<string, unknown>) => unknown) | null;
    expect(observer).toBeTypeOf('function');
    const returned = observer!({
      group_indexes: { 'g-team.example.test': { etag: '"one"', last_modified: 1, schema: GROUP_INDEX_SCHEMA } },
    });
    release();

    expect(returned && typeof (returned as Promise<void>).then).toBe('function');
    await (returned as Promise<void>);
    expect(observed).toBe(true);
  });
});

describe('browser group index IndexedDB persistence', () => {
  it('persists pulled index JSONL and cache envelope by local aid and group aid', async () => {
    const store = new IndexedDBTokenStore();
    const signer = fakeSigner();
    const signed = await buildSignedGroupIndex({
      groupAid: 'g-team.example.test',
      entries: [{ key: 'rules.content', source: 'db', etag: '"entry-v1"', last_modified: 1 }],
      signer,
      lastModified: 1,
    });

    await store.upsertGroupIndexCache('alice.example.test', 'g-team.example.test', {
      index_jsonl: signed.body,
      remote_meta: { etag: '"v1"', last_modified: 1, schema: GROUP_INDEX_SCHEMA },
      local_etag: '"v1"',
      settings: { 'rules.content': '缓存群规' },
      entry_etags: { 'rules.content': '"entry-v1"' },
    });

    const restored = await store.loadGroupIndexCache('alice.example.test', 'g-team.example.test');

    expect(restored).toMatchObject({
      local_aid: 'alice.example.test',
      group_aid: 'g-team.example.test',
      index_jsonl: signed.body,
      local_etag: '"v1"',
      remote_meta: { etag: '"v1"', last_modified: 1, schema: GROUP_INDEX_SCHEMA },
      settings: { 'rules.content': '缓存群规' },
      entry_etags: { 'rules.content': '"entry-v1"' },
    });
  });

  it('hydrates AUNClient group index settings cache from IndexedDB', async () => {
    const signer = fakeSigner();
    const signed = await buildSignedGroupIndex({
      groupAid: 'g-team.example.test',
      entries: [{ key: 'rules.content', source: 'db', etag: '"entry-v1"', last_modified: 1 }],
      signer,
      lastModified: 1,
    });
    const entries = parseGroupIndex(signed.body).entries;

    const client1 = new AUNClient();
    (client1 as any)._aid = 'alice.example.test';
    await (client1 as any).cacheGroupIndexSettings(
      'g-team.example.test',
      { 'rules.content': '缓存群规' },
      { entries, etag: '"v1"', groupIndex: signed },
    );

    const record = await new IndexedDBTokenStore().loadGroupIndexCache('alice.example.test', 'g-team.example.test');
    expect(record?.index_jsonl).toBe(signed.body);

    const client2 = new AUNClient();
    (client2 as any)._aid = 'alice.example.test';
    const cached = await (client2 as any).getGroupIndexCachedSettings('g-team.example.test', ['rules.content']);

    expect(cached).toEqual({ 'rules.content': '缓存群规' });
  });
});
