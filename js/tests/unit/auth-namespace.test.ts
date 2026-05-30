import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';

import * as PublicApi from '../../src/index.js';
import { AUNClient } from '../../src/client.js';

describe('AuthNamespace 公开 API 移除守卫', () => {
  it('包入口不再导出 AuthNamespace / CustodyNamespace / MetaNamespace', () => {
    expect('AuthNamespace' in PublicApi).toBe(false);
    expect('CustodyNamespace' in PublicApi).toBe(false);
    expect('MetaNamespace' in PublicApi).toBe(false);
  });

  it('AUNClient 不再暴露 auth/custody/meta namespace', () => {
    const client = new AUNClient();
    expect((client as any).auth).toBeUndefined();
    expect((client as any).custody).toBeUndefined();
    expect((client as any).meta).toBeUndefined();
    expect((client as any)._authNamespace).toBeUndefined();
  });

  it('认证入口迁移为 loadIdentity(AID) + authenticate/connect', () => {
    const client = new AUNClient();
    expect(typeof client.loadIdentity).toBe('function');
    expect(typeof client.authenticate).toBe('function');
    expect(typeof client.connect).toBe('function');
  });
});
