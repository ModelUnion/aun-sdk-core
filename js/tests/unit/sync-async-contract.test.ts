import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';

import { AIDStore, CryptoProvider, IndexedDBIdentityStore, RegisterFlow } from '../../src/index.js';

function isPromiseLike(value: unknown): value is Promise<unknown> {
  return !!value && typeof (value as { then?: unknown }).then === 'function';
}

describe('TB1/TB6 JS 浏览器异步契约', () => {
  it('CryptoProvider 公开方法保持 Promise 返回', async () => {
    const crypto = new CryptoProvider();

    const identityPromise = crypto.generateIdentity();
    expect(isPromiseLike(identityPromise)).toBe(true);
    const identity = await identityPromise;
    expect(identity.curve).toBe('P-256');
    const identityAsync = crypto.generateIdentityAsync();
    expect(isPromiseLike(identityAsync)).toBe(true);
    await expect(identityAsync).resolves.toMatchObject({ curve: 'P-256' });

    const signaturePromise = crypto.signLoginNonce(identity.private_key_pem, 'contract-nonce', '1234567890');
    expect(isPromiseLike(signaturePromise)).toBe(true);
    await expect(signaturePromise).resolves.toMatchObject([expect.any(String), '1234567890']);
    const signatureAsync = crypto.signLoginNonceAsync(identity.private_key_pem, 'contract-nonce', '1234567890');
    expect(isPromiseLike(signatureAsync)).toBe(true);
    await expect(signatureAsync).resolves.toMatchObject([expect.any(String), '1234567890']);
  });

  it('AIDStore 本地身份方法和联网方法都保持 Promise 返回', async () => {
    const store = new AIDStore({ aunPath: 'browser-contract-aun', encryptionSeed: 'contract-seed' });

    const loaded = store.load('missing.agentid.pub');
    expect(isPromiseLike(loaded)).toBe(true);
    await expect(loaded).resolves.toMatchObject({ ok: false });
    const loadedAsync = store.loadAsync('missing.agentid.pub');
    expect(isPromiseLike(loadedAsync)).toBe(true);
    await expect(loadedAsync).resolves.toMatchObject({ ok: false });

    const listed = store.list();
    expect(isPromiseLike(listed)).toBe(true);
    await expect(listed).resolves.toMatchObject({ ok: true, data: { identities: [] } });
    const listedAsync = store.listAsync();
    expect(isPromiseLike(listedAsync)).toBe(true);
    await expect(listedAsync).resolves.toMatchObject({ ok: true, data: { identities: [] } });

    const seedChange = store.changeSeed('', 'next-seed');
    expect(isPromiseLike(seedChange)).toBe(true);
    await expect(seedChange).resolves.toMatchObject({ ok: false });
    const seedChangeAsync = store.changeSeedAsync('', 'next-seed');
    expect(isPromiseLike(seedChangeAsync)).toBe(true);
    await expect(seedChangeAsync).resolves.toMatchObject({ ok: false });

    const imported = store.importGroupIdentity('contract-group-js.agentid.pub', {});
    expect(isPromiseLike(imported)).toBe(true);
    await expect(imported).resolves.toMatchObject({ ok: false });
    const importedAsync = store.importGroupIdentityAsync('contract-group-js.agentid.pub', {});
    expect(isPromiseLike(importedAsync)).toBe(true);
    await expect(importedAsync).resolves.toMatchObject({ ok: false });

    const registerResult = store.register('');
    expect(isPromiseLike(registerResult)).toBe(true);
    await expect(registerResult).resolves.toMatchObject({ ok: false });
  });

  it('底层 IndexedDB 身份存储保持异步 seed 迁移入口', async () => {
    const migration = IndexedDBIdentityStore.changeSeed('', 'next-seed');
    expect(isPromiseLike(migration)).toBe(true);
    await expect(migration).rejects.toThrow(/seed migration refused/);
  });

  it('RegisterFlow 本地身份生成保持 Promise，nonce 生成两端均保持同步', async () => {
    const flow = new RegisterFlow({
      keystore: {
        savePendingKey: async () => undefined,
        loadPendingKey: async () => null,
        deletePendingKey: async () => undefined,
      },
      crypto: new CryptoProvider(),
    });

    const identityPromise = flow.generateIdentity();
    expect(isPromiseLike(identityPromise)).toBe(true);
    const identity = await identityPromise;
    expect(identity.curve).toBe('P-256');
    const identityAsync = flow.generateIdentityAsync();
    expect(isPromiseLike(identityAsync)).toBe(true);
    await expect(identityAsync).resolves.toMatchObject({ curve: 'P-256' });

    const nonce = flow.newClientNonce();
    expect(isPromiseLike(nonce)).toBe(false);
    expect(typeof nonce).toBe('string');
    expect(nonce.length).toBeGreaterThan(0);
  });
});
