import { describe, expect, it, vi } from 'vitest';

import { GroupFacade } from '../../src/facades.js';
import { resultOk } from '../../src/result.js';
import { GROUP_INDEX_SCHEMA, buildSignedGroupIndex, parseGroupIndex, verifyGroupIndex } from '../../src/group-index.js';

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

function baseIndex(signer: ReturnType<typeof fakeSigner>, seed: string) {
  return buildSignedGroupIndex({
    groupAid: 'g-team.example.test',
    entries: [{ key: 'rules.content', source: 'db', etag: `"sha256:${seed}"`, last_modified: 1 }],
    signer,
    lastModified: 1,
  });
}

function indexWithEntries(signer: ReturnType<typeof fakeSigner>, entries: Array<Record<string, any>>) {
  return buildSignedGroupIndex({
    groupAid: 'g-team.example.test',
    entries,
    signer,
    lastModified: 1,
  });
}

function tamperIndex(index: { body: string }) {
  const lines = index.body.split(/\r?\n/).filter((line) => line.trim());
  const entry = parseGroupIndex(index.body).entries[0];
  entry.etag = '"sha256:tampered"';
  lines[1] = JSON.stringify(entry, Object.keys(entry).sort());
  return { ...index, body: `${lines.join('\n')}\n` };
}

class FakeClient {
  currentAid = fakeSigner();
  calls: Array<{ method: string; params: Record<string, any> }> = [];
  getResults: any[];
  failFirstSet: boolean;
  remoteMeta: Record<string, any> | null = null;
  localEtag = '';
  stale = false;
  freshMarks: Array<{ groupAid: string; etag: string }> = [];
  remoteSettings: Record<string, any> = {};
  cachedSettings: Record<string, any> = {};
  cachedEntryEtags: Record<string, string> = {};
  cachedGroupEtag = '';
  cacheCalls: string[] = [];

  constructor(getResults: any[], failFirstSet = false) {
    this.getResults = [...getResults];
    this.failFirstSet = failFirstSet;
  }

  async call(method: string, params?: Record<string, any>) {
    this.calls.push({ method, params: params ?? {} });
    if (method === 'group.get_settings') {
      const keys = [...(params?.keys ?? [])];
      if (keys.length !== 1 || keys[0] !== 'group.index') {
        return {
          group_id: params?.group_id,
          group_aid: 'g-team.example.test',
          settings: keys.filter((key) => key in this.remoteSettings).map((key) => ({ key, value: this.remoteSettings[key] })),
        };
      }
      const value = this.getResults.shift();
      return {
        group_id: params?.group_id,
        group_aid: 'g-team.example.test',
        settings: value ? [{ key: 'group.index', value }] : [],
      };
    }
    if (method === 'group.set_settings') {
      if (this.failFirstSet) {
        this.failFirstSet = false;
        throw new Error('group.index etag conflict');
      }
      return { group_id: params?.group_id, updated_keys: Object.keys(params?.settings ?? {}) };
    }
    throw new Error(`unexpected method ${method}`);
  }

  isGroupIndexStale(_groupAid: string): boolean {
    return this.stale;
  }

  getGroupIndexRemoteMeta(_groupAid: string): Record<string, any> | null {
    return this.remoteMeta;
  }

  getGroupIndexLocalEtag(_groupAid: string): string {
    return this.localEtag;
  }

  markGroupIndexFresh(groupAid: string, options: { etag: string }): void {
    this.freshMarks.push({ groupAid, etag: options.etag });
    this.stale = false;
    this.localEtag = options.etag;
  }

  getGroupIndexCachedSettings(_groupAid: string, keys: string[]): Record<string, any> | null {
    if (!keys.every((key) => key in this.cachedSettings)) return null;
    return Object.fromEntries(keys.map((key) => [key, this.cachedSettings[key]]));
  }

  getGroupIndexCachedSettingsByEntries(_groupAid: string, keys: string[], entries: Array<Record<string, any>>) {
    const entryEtags = Object.fromEntries(entries.map((item) => [String(item.key ?? ''), String(item.etag ?? '')]));
    const cached: Record<string, any> = {};
    const missing: string[] = [];
    for (const key of keys) {
      if (key in this.cachedSettings && this.cachedEntryEtags[key] === entryEtags[key]) {
        cached[key] = this.cachedSettings[key];
      } else {
        missing.push(key);
      }
    }
    return { cached, missing };
  }

  cacheGroupIndexSettings(_groupAid: string, settings: Record<string, any>, options?: { entries?: Array<Record<string, any>>; etag?: string; groupIndex?: unknown }): void {
    this.cacheCalls.push(_groupAid);
    Object.assign(this.cachedSettings, settings);
    for (const item of options?.entries ?? []) {
      const key = String(item.key ?? '');
      if (key) this.cachedEntryEtags[key] = String(item.etag ?? '');
    }
    if (options?.etag) this.cachedGroupEtag = options.etag;
  }
}

describe('GroupFacade.updateGroupIndex', () => {
  it('does not expose setSettingsWithIndex alias', () => {
    const facade = new GroupFacade(new FakeClient([]));

    expect('setSettingsWithIndex' in facade).toBe(false);
  });

  it('sends expected_index_etag and a signed group.index in the same settings update', async () => {
    const signer = fakeSigner();
    const oldIndex = baseIndex(signer, 'old');
    const client = new FakeClient([oldIndex]);
    client.currentAid = signer;
    const facade = new GroupFacade(client);

    const result = await facade.updateGroupIndex({
      group_id: 'g-team.example.test',
      settings: { 'rules.content': '新群规' },
      last_modified: 2000,
    });

    expect(result.updated_keys).toEqual(['rules.content', 'group.index']);
    const setCall = client.calls.find((item) => item.method === 'group.set_settings')?.params;
    expect(setCall?.expected_index_etag).toBe(parseGroupIndex(oldIndex.body).meta.etag);
    expect(setCall?.settings['rules.content']).toBe('新群规');
    expect(setCall?.settings['group.index']).toBeTruthy();
    const verified = verifyGroupIndex(setCall?.settings['group.index'].body, client.currentAid);
    expect(verified.ok && verified.data.valid).toBe(true);
  });

  it('checkGroupIndex reports observed remote meta without RPC', async () => {
    const signer = fakeSigner();
    const client = new FakeClient([]);
    client.currentAid = signer;
    client.stale = true;
    client.localEtag = '"sha256:local"';
    client.remoteMeta = { etag: '"sha256:remote"', last_modified: 1234, schema: GROUP_INDEX_SCHEMA };
    const facade = new GroupFacade(client);

    const result = await (facade as any).checkGroupIndex({ group_aid: 'g-team.example.test' });

    expect(result).toEqual({
      group_aid: 'g-team.example.test',
      local_found: true,
      remote_found: true,
      local_etag: '"sha256:local"',
      remote_etag: '"sha256:remote"',
      in_sync: false,
      needs_update: true,
      last_modified: 1234,
      status: 200,
      cached: true,
    });
    expect(client.calls).toEqual([]);
  });

  it('getGroupIndex fetches remote index and marks it fresh', async () => {
    const signer = fakeSigner();
    const remoteIndex = baseIndex(signer, 'remote');
    const client = new FakeClient([remoteIndex]);
    client.currentAid = signer;
    client.stale = true;
    client.remoteSettings = { 'rules.content': '远端群规' };
    const facade = new GroupFacade(client);

    const result = await (facade as any).getGroupIndex({ group_id: 'g-team.example.test' });

    const parsed = parseGroupIndex(remoteIndex.body);
    expect(result.group_id).toBe('g-team.example.test');
    expect(result.group_aid).toBe('g-team.example.test');
    expect(result.group_index).toEqual(remoteIndex);
    expect(result.meta).toEqual(parsed.meta);
    expect(result.entries).toEqual(parsed.entries);
    expect(client.freshMarks).toEqual([{ groupAid: 'g-team.example.test', etag: parsed.meta.etag }]);
    expect(client.cachedSettings['rules.content']).toBe('远端群规');
    expect(client.calls).toEqual([
      { method: 'group.get_settings', params: { group_id: 'g-team.example.test', keys: ['group.index'] } },
      { method: 'group.get_settings', params: { group_id: 'g-team.example.test', keys: ['rules.content'] } },
    ]);
  });

  it('getGroupIndex rejects a tampered remote index before updating cache', async () => {
    const signer = fakeSigner();
    const remoteIndex = tamperIndex(baseIndex(signer, 'remote'));
    const client = new FakeClient([remoteIndex]);
    client.currentAid = signer;
    client.remoteSettings = { 'rules.content': '不应读取' };
    const facade = new GroupFacade(client);

    await expect((facade as any).getGroupIndex({ group_id: 'g-team.example.test' })).rejects.toThrow(/group\.index/);

    expect(client.freshMarks).toEqual([]);
    expect(client.cachedSettings).toEqual({});
    expect(client.calls).toEqual([
      { method: 'group.get_settings', params: { group_id: 'g-team.example.test', keys: ['group.index'] } },
    ]);
  });

  it('getRules returns cached rules even when group index is stale', async () => {
    const client = new FakeClient([]);
    client.stale = true;
    client.cachedSettings = {
      'rules.content': '缓存群规',
      'rules.attachments': [{ uri: 'groupfs://rules.pdf' }],
    };
    const facade = new GroupFacade(client);

    const result = await facade.getRules({ group_id: 'g-team.example.test' });

    expect(result).toEqual({
      group_id: 'g-team.example.test',
      rules: {
        group_id: 'g-team.example.test',
        content: '缓存群规',
        attachments: [{ uri: 'groupfs://rules.pdf' }],
        updated_by: '',
        updated_at: 0,
      },
    });
    expect(client.calls).toEqual([]);
  });

  it('getRules fetches settings only when local cache is missing', async () => {
    const client = new FakeClient([]);
    client.stale = true;
    client.remoteSettings = {
      'rules.content': '远端群规',
      'rules.attachments': [{ uri: 'groupfs://rules.pdf' }],
    };
    const facade = new GroupFacade(client);

    const result = await facade.getRules({ group_id: 'g-team.example.test' });

    expect(result.rules.content).toBe('远端群规');
    expect(result.rules.attachments).toEqual([{ uri: 'groupfs://rules.pdf' }]);
    expect(client.calls).toEqual([
      { method: 'group.get_settings', params: { group_id: 'g-team.example.test', keys: ['rules.content', 'rules.attachments'] } },
    ]);
    expect(client.freshMarks).toEqual([]);
    expect(client.cachedSettings['rules.content']).toBe('远端群规');
  });

  it('getRules caches settings under canonical and requested group ids', async () => {
    const client = new FakeClient([]);
    client.remoteSettings = {
      'rules.content': '远端群规',
      'rules.attachments': [],
    };
    const facade = new GroupFacade(client);

    await facade.getRules({ group_id: 'legacy.remote.example' });

    expect(client.cacheCalls).toEqual(['g-team.example.test', 'legacy.remote.example']);
  });

  it('updateRules refreshes indexed settings cache after push', async () => {
    const signer = fakeSigner();
    const oldIndex = baseIndex(signer, 'old');
    const client = new FakeClient([oldIndex]);
    client.currentAid = signer;
    const facade = new GroupFacade(client);

    await facade.updateRules({ group_id: 'g-team.example.test', content: '新群规', last_modified: 2000 });

    expect(client.cachedSettings['rules.content']).toBe('新群规');
    expect(client.cachedGroupEtag).toBeTruthy();
  });

  it('updateGroupIndex pulls, merges, and pushes with CAS', async () => {
    const signer = fakeSigner();
    const oldIndex = baseIndex(signer, 'old');
    const client = new FakeClient([oldIndex]);
    client.currentAid = signer;
    const facade = new GroupFacade(client);

    const result = await (facade as any).updateGroupIndex({
      group_id: 'g-team.example.test',
      settings: { 'rules.content': '新群规' },
      last_modified: 2000,
    });

    expect(result.updated_keys).toEqual(['rules.content', 'group.index']);
    const setCall = client.calls.find((item) => item.method === 'group.set_settings')?.params;
    expect(setCall?.expected_index_etag).toBe(parseGroupIndex(oldIndex.body).meta.etag);
    expect(setCall?.settings['rules.content']).toBe('新群规');
    const verified = verifyGroupIndex(setCall?.settings['group.index'].body, client.currentAid);
    expect(verified.ok && verified.data.valid).toBe(true);
  });

  it('marks the pushed index fresh after updateGroupIndex succeeds', async () => {
    const signer = fakeSigner();
    const oldIndex = baseIndex(signer, 'old');
    const client = new FakeClient([oldIndex]);
    client.currentAid = signer;
    client.stale = true;
    const facade = new GroupFacade(client);

    await facade.updateGroupIndex({
      group_id: 'g-team.example.test',
      settings: { 'rules.content': '新群规' },
      last_modified: 2000,
    });

    const setCall = client.calls.find((item) => item.method === 'group.set_settings')?.params;
    const pushedEtag = parseGroupIndex(setCall?.settings['group.index'].body).meta.etag;
    expect(client.freshMarks).toEqual([{ groupAid: 'g-team.example.test', etag: pushedEtag }]);
    expect(client.stale).toBe(false);
  });

  it('reloads index and retries once when CAS reports etag conflict', async () => {
    const signer = fakeSigner();
    const oldIndex = baseIndex(signer, 'old');
    const newerIndex = baseIndex(signer, 'newer');
    const client = new FakeClient([oldIndex, newerIndex], true);
    client.currentAid = signer;
    const facade = new GroupFacade(client);

    await facade.updateGroupIndex({
      group_id: 'g-team.example.test',
      settings: { 'rules.content': '我的版本' },
      last_modified: 2000,
    });

    const setCalls = client.calls.filter((item) => item.method === 'group.set_settings').map((item) => item.params);
    expect(setCalls).toHaveLength(2);
    expect(setCalls[0].expected_index_etag).toBe(parseGroupIndex(oldIndex.body).meta.etag);
    expect(setCalls[1].expected_index_etag).toBe(parseGroupIndex(newerIndex.body).meta.etag);
    expect(setCalls[1].settings['rules.content']).toBe('我的版本');
  });

  it.each([
    ['updateRules', { content: '新群规' }, 'rules.content'],
    ['updateAnnouncement', { content: '新公告' }, 'announcement.content'],
    ['updateJoinRequirements', { mode: 'approval' }, 'join.mode'],
  ])('%s writes indexed settings through updateGroupIndex', async (methodName, params, expectedKey) => {
    const signer = fakeSigner();
    const oldIndex = baseIndex(signer, 'old');
    const client = new FakeClient([oldIndex]);
    client.currentAid = signer;
    const facade = new GroupFacade(client);

    await (facade as any)[methodName]({
      group_id: 'g-team.example.test',
      last_modified: 2000,
      ...params,
    });

    expect(client.calls.map((item) => item.method)).toEqual(['group.get_settings', 'group.set_settings']);
    const setCall = client.calls[1].params;
    expect(setCall.settings[expectedKey]).toBeDefined();
    expect(setCall.settings['group.index']).toBeDefined();
    expect(setCall.expected_index_etag).toBe(parseGroupIndex(oldIndex.body).meta.etag);
  });
});
