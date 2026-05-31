import { describe, expect, it, vi } from 'vitest';
import * as nodeCrypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { AIDStore, AUNClient, AuthFlow, CryptoProvider, FileKeyStore, RegisterFlow } from '../../src/index.js';
import { makeSelfSignedCert } from './helpers.js';
import type { IdentityRecord, KeyPairRecord } from '../../src/types.js';

const SEED_CASES: Array<{ label: string; seed?: string }> = [
  { label: '不带 seed_password' },
  { label: '带 seed_password', seed: 'matrix-seed' },
];

function makeKeyStore(root: string, seed?: string): FileKeyStore {
  return seed === undefined
    ? new FileKeyStore(root)
    : new FileKeyStore(root, { encryptionSeed: seed });
}

function keyJsonPath(root: string, aid: string): string {
  return path.join(root, 'AIDs', aid, 'private', 'key.json');
}

function readJson(file: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(file, 'utf-8')) as Record<string, unknown>;
}

function assertEncryptedKeyJson(file: string): void {
  const rawText = fs.readFileSync(file, 'utf-8');
  const data = JSON.parse(rawText) as Record<string, unknown>;
  expect(data.private_key_pem).toBeUndefined();
  expect(rawText).not.toContain('BEGIN PRIVATE KEY');
  expect(data.private_key_protection).toMatchObject({
    scheme: 'file_aes',
    name: 'identity/private_key',
  });
}

function findPendingKeyJson(root: string, aid: string): string {
  const pendingRoot = path.join(root, 'AIDs', '_pending');
  const entries = fs.readdirSync(pendingRoot, { withFileTypes: true });
  const match = entries.find((entry) => entry.isDirectory() && entry.name.startsWith(`${aid}-`));
  if (!match) throw new Error(`pending identity not found for ${aid}`);
  return path.join(pendingRoot, match.name, 'private', 'key.json');
}

function certForIdentity(aid: string, identity: IdentityRecord | KeyPairRecord): string {
  const privateKey = nodeCrypto.createPrivateKey(String(identity.private_key_pem));
  return makeSelfSignedCert(privateKey, aid);
}

describe('注册/认证 seed_password 矩阵', () => {
  it.each(SEED_CASES)('$label：RegisterFlow pending 与正式 key.json 均加密，loadIdentity 后可复用 cached token', async ({ seed }) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-ts-seed-matrix-'));
    const aid = seed ? 'matrix-seed.agentid.pub' : 'matrix-noseed.agentid.pub';
    const keystore = makeKeyStore(root, seed);
    const registerFlow = new RegisterFlow({
      keystore,
      crypto: new CryptoProvider(),
      verifySsl: false,
    });

    (registerFlow as any)._downloadRegisteredCert = vi.fn().mockResolvedValue(null);
    (registerFlow as any)._createAid = vi.fn(async (_gateway: string, identity: IdentityRecord) => {
      const pendingKey = findPendingKeyJson(root, aid);
      assertEncryptedKeyJson(pendingKey);
      return { cert: certForIdentity(aid, identity) };
    });

    const registered = await registerFlow.registerAid('ws://gateway.example/aun', aid);
    expect(registered.aid).toBe(aid);
    expect(registered.private_key_pem).toContain('BEGIN PRIVATE KEY');
    assertEncryptedKeyJson(keyJsonPath(root, aid));

    const loadedIdentity = keystore.loadIdentity(aid);
    expect(loadedIdentity?.private_key_pem).toBe(registered.private_key_pem);
    expect(loadedIdentity?.cert).toBe(registered.cert);

    const aidStore = new AIDStore({ aunPath: root, encryptionSeed: seed ?? '', verifySsl: false });
    const loaded = aidStore.load(aid);
    expect(loaded.ok).toBe(true);
    const loadedAid = loaded.ok ? loaded.data.aid : null;
    expect(loadedAid?.isPrivateKeyValid()).toBe(true);

    const client = new AUNClient();
    client.loadIdentity(loadedAid!);
    expect(client.currentAid?.aid).toBe(aid);
    expect((client as any)._identity.private_key_pem).toBe(registered.private_key_pem);

    const expiresAt = Math.floor(Date.now() / 1000) + 3600;
    keystore.saveInstanceState(aid, loadedAid!.deviceId, loadedAid!.slotId, {
      access_token: 'cached-access',
      refresh_token: 'cached-refresh',
      access_token_expires_at: expiresAt,
    });

    const authFlow: AuthFlow = (client as any)._auth;
    const loginSpy = vi.fn();
    (authFlow as any)._login = loginSpy;
    const authIdentity = authFlow.loadIdentity(aid);
    expect(authIdentity.private_key_pem).toBe(registered.private_key_pem);

    const authResult = await authFlow.authenticate('ws://gateway.example/aun', { aid });
    expect(loginSpy).not.toHaveBeenCalled();
    expect(authResult).toMatchObject({
      aid,
      access_token: 'cached-access',
      refresh_token: 'cached-refresh',
      gateway: 'ws://gateway.example/aun',
    });
  });

  it.each(SEED_CASES)('$label：注册 RPC 失败时 pending key.json 仍为加密私钥', async ({ seed }) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-ts-pending-seed-matrix-'));
    const aid = seed ? 'pending-seed.agentid.pub' : 'pending-noseed.agentid.pub';
    const registerFlow = new RegisterFlow({
      keystore: makeKeyStore(root, seed),
      crypto: new CryptoProvider(),
      verifySsl: false,
    });

    (registerFlow as any)._downloadRegisteredCert = vi.fn().mockResolvedValue(null);
    (registerFlow as any)._createAid = vi.fn().mockRejectedValue(new Error('gateway down'));

    await expect(registerFlow.registerAid('ws://gateway.example/aun', aid)).rejects.toThrow('gateway down');
    assertEncryptedKeyJson(findPendingKeyJson(root, aid));
    expect(fs.existsSync(path.join(root, 'AIDs', aid))).toBe(false);
  });
});
