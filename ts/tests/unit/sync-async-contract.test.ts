import { describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AIDStore, CryptoProvider, LocalIdentityStore, RegisterFlow } from '../../src/index.js';
import { buildIdentity, generateECKeypair } from './helpers.js';

function isPromiseLike(value: unknown): value is Promise<unknown> {
  return !!value && typeof (value as { then?: unknown }).then === 'function';
}

function makeStoreWithIdentity(aid = 'contract-ts.agentid.pub'): { store: AIDStore; identity: ReturnType<typeof buildIdentity> } {
  const aunPath = mkdtempSync(join(tmpdir(), 'aun-ts-contract-'));
  const { privateKey } = generateECKeypair();
  const identity = buildIdentity(aid, privateKey);
  const keyStore = new LocalIdentityStore(aunPath, { encryptionSeed: 'contract-seed' });
  keyStore.saveIdentity(aid, identity);
  const store = new AIDStore({ aunPath, encryptionSeed: 'contract-seed' });
  return { store, identity };
}

describe('TB1/TB6 TS Node 同步契约', () => {
  it('CryptoProvider 公开方法保持同步返回，同时提供 Promise alias', async () => {
    const crypto = new CryptoProvider();

    const identity = crypto.generateIdentity();
    expect(isPromiseLike(identity)).toBe(false);
    expect(identity.curve).toBe('P-256');
    const identityAsync = crypto.generateIdentityAsync();
    expect(isPromiseLike(identityAsync)).toBe(true);
    await expect(identityAsync).resolves.toMatchObject({ curve: 'P-256' });

    const signature = crypto.signLoginNonce(identity.private_key_pem, 'contract-nonce', '1234567890');
    expect(isPromiseLike(signature)).toBe(false);
    expect(signature[1]).toBe('1234567890');
    const signatureAsync = crypto.signLoginNonceAsync(identity.private_key_pem, 'contract-nonce', '1234567890');
    expect(isPromiseLike(signatureAsync)).toBe(true);
    await expect(signatureAsync).resolves.toMatchObject([expect.any(String), '1234567890']);
  });

  it('AIDStore 本地身份方法保持同步 Result 返回，联网方法保持 Promise 返回', async () => {
    const { store, identity } = makeStoreWithIdentity();
    try {
      const loaded = store.load(identity.aid as string);
      expect(isPromiseLike(loaded)).toBe(false);
      expect(loaded.ok).toBe(true);
      const loadedAsync = store.loadAsync(identity.aid as string);
      expect(isPromiseLike(loadedAsync)).toBe(true);
      await expect(loadedAsync).resolves.toMatchObject({ ok: true });

      const listed = store.list();
      expect(isPromiseLike(listed)).toBe(false);
      expect(listed.ok).toBe(true);
      const listedAsync = store.listAsync();
      expect(isPromiseLike(listedAsync)).toBe(true);
      await expect(listedAsync).resolves.toMatchObject({ ok: true });

      const seedChange = store.changeSeed('', 'next-seed');
      expect(isPromiseLike(seedChange)).toBe(false);
      expect(seedChange.ok).toBe(false);
      const seedChangeAsync = store.changeSeedAsync('', 'next-seed');
      expect(isPromiseLike(seedChangeAsync)).toBe(true);
      await expect(seedChangeAsync).resolves.toMatchObject({ ok: false });

      const imported = store.importGroupIdentity('contract-group-ts.agentid.pub', {
        private_key_pem: identity.private_key_pem,
        public_key_der_b64: identity.public_key_der_b64,
        cert_pem: identity.cert,
      });
      expect(isPromiseLike(imported)).toBe(false);
      expect(imported.ok).toBe(false);
      const importedAsync = store.importGroupIdentityAsync('contract-group-ts.agentid.pub', {
        private_key_pem: identity.private_key_pem,
        public_key_der_b64: identity.public_key_der_b64,
        cert_pem: identity.cert,
      });
      expect(isPromiseLike(importedAsync)).toBe(true);
      await expect(importedAsync).resolves.toMatchObject({ ok: false });

      const registerResult = store.register('');
      expect(isPromiseLike(registerResult)).toBe(true);
      await expect(registerResult).resolves.toMatchObject({ ok: false });
    } finally {
      store.close();
    }
  });

  it('RegisterFlow 本地身份生成保持同步并提供 Promise alias，nonce 生成两端均保持同步', async () => {
    const flow = new RegisterFlow({
      keystore: {
        savePendingKey: () => undefined,
        loadPendingKey: () => null,
        deletePendingKey: () => undefined,
      },
      crypto: new CryptoProvider(),
    });

    const identity = flow.generateIdentity();
    expect(isPromiseLike(identity)).toBe(false);
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
