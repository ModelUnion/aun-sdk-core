import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';

import * as PublicApi from '../../src/index.js';
import { AUNClient } from '../../src/client.js';

describe('MetaNamespace 公开 API 移除守卫', () => {
  it('包入口不再导出 MetaNamespace', () => {
    expect('MetaNamespace' in PublicApi).toBe(false);
  });

  it('AUNClient 不再暴露 meta namespace 与 meta convenience 方法', () => {
    const client = new AUNClient();
    expect((client as any).meta).toBeUndefined();
    expect((client as any).ping).toBeUndefined();
    expect((client as any).status).toBeUndefined();
    expect((client as any).trustRoots).toBeUndefined();
  });

  it('meta RPC 走统一 call 通道', async () => {
    const client = new AUNClient();
    const calls: Array<[string, unknown]> = [];
    (client as any).call = async (method: string, params?: unknown) => {
      calls.push([method, params ?? {}]);
      return { ok: true };
    };

    await (client as any).call('meta.ping', {});
    await (client as any).call('meta.status', {});
    await (client as any).call('meta.trust_roots', {});

    expect(calls).toEqual([
      ['meta.ping', {}],
      ['meta.status', {}],
      ['meta.trust_roots', {}],
    ]);
  });
});
