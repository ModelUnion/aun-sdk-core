import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { AID, AIDStore, AUNClient, GatewayDiscovery } from '../src/index.js';

export type TestAIDStoreOptions = {
  aunPath: string;
  encryptionSeed?: string;
  verifySsl?: boolean;
  rootCaPath?: string | null;
  debug?: boolean;
  slotId?: string;
};

export type TestIdentityOptions = TestAIDStoreOptions & {
  deviceId?: string;
};

export type TestClientOptions = TestIdentityOptions & {
  requireForwardSecrecy?: boolean;
};

export function writeTestDeviceId(aunPath: string, deviceId?: string): void {
  const value = String(deviceId ?? '').trim();
  if (!value) return;
  mkdirSync(aunPath, { recursive: true });
  writeFileSync(join(aunPath, '.device_id'), value, 'utf-8');
}

export function createAIDStore(opts: TestAIDStoreOptions): AIDStore {
  return new AIDStore({
    aunPath: opts.aunPath,
    encryptionSeed: opts.encryptionSeed ?? '',
    verifySsl: opts.verifySsl ?? false,
    rootCaPath: opts.rootCaPath ?? null,
    debug: opts.debug ?? false,
    ...(opts.slotId ? { slotId: opts.slotId } : {}),
  });
}

export async function prepareIdentity(opts: TestIdentityOptions & { aid: string }): Promise<AID> {
  writeTestDeviceId(opts.aunPath, opts.deviceId);
  const store = createAIDStore(opts);
  const registered = await store.register(opts.aid);
  if (!registered.ok) {
    const existing = store.load(opts.aid);
    if (existing.ok && existing.data?.aid.isPrivateKeyValid()) {
      return existing.data.aid;
    }
    throw new Error(`${registered.error.code}: ${registered.error.message}`);
  }
  const loaded = store.load(opts.aid);
  if (!loaded.ok || !loaded.data) {
    throw new Error(`load identity failed for ${opts.aid}: ${loaded.ok ? 'empty result' : loaded.error.message}`);
  }
  return loaded.data.aid;
}

export function loadPreparedIdentity(opts: TestIdentityOptions & { aid: string }): AID {
  writeTestDeviceId(opts.aunPath, opts.deviceId);
  const store = createAIDStore(opts);
  const loaded = store.load(opts.aid);
  if (!loaded.ok || !loaded.data) {
    throw new Error(`load identity failed for ${opts.aid}: ${loaded.ok ? 'empty result' : loaded.error.message}`);
  }
  return loaded.data.aid;
}

export async function createClientWithIdentity(opts: TestIdentityOptions & { aid: string }): Promise<AUNClient> {
  return new AUNClient(await prepareIdentity(opts));
}

export function createClientFromStore(opts: TestIdentityOptions & { aid: string }): AUNClient {
  return new AUNClient(loadPreparedIdentity(opts));
}

function clientAunPath(client: AUNClient): string {
  const config = (client as unknown as {
    __testAunPath?: string;
    config: Record<string, unknown>;
    _configModel?: { aunPath?: string };
  });
  return String(
    config.__testAunPath
      ?? config._configModel?.aunPath
      ?? config.config.aun_path
      ?? config.config.aunPath
      ?? 'aun',
  );
}

function clientEncryptionSeed(client: AUNClient): string {
  const config = (client as unknown as {
    __testEncryptionSeed?: string;
    config: Record<string, unknown>;
    _configModel?: { seedPassword?: string; encryptionSeed?: string };
  });
  return String(
    config.__testEncryptionSeed
      ?? config._configModel?.encryptionSeed
      ?? config._configModel?.seedPassword
      ?? config.config.encryption_seed
      ?? config.config.encryptionSeed
      ?? config.config.seed_password
      ?? config.config.seedPassword
      ?? '',
  );
}

function clientVerifySsl(client: AUNClient): boolean {
  const raw = client as unknown as {
    __testVerifySsl?: boolean;
    _configModel?: { verifySsl?: boolean };
  };
  return Boolean(raw.__testVerifySsl ?? raw._configModel?.verifySsl ?? false);
}

function clientDiscoveryPort(client: AUNClient): string {
  const raw = client as unknown as {
    _configModel?: { discoveryPort?: number | null };
  };
  const port = raw._configModel?.discoveryPort;
  return port ? `:${port}` : '';
}

export function createAIDStoreForClient(client: AUNClient, slotId?: string): AIDStore {
  const raw = client as any;
  const model = raw._configModel ?? {};
  const aunPath = clientAunPath(client);
  writeTestDeviceId(aunPath, raw.__testDeviceId);
  return new AIDStore({
    aunPath,
    encryptionSeed: clientEncryptionSeed(client),
    verifySsl: Boolean(raw.__testVerifySsl ?? model.verifySsl ?? false),
    rootCaPath: raw.__testRootCaPath ?? model.rootCaPath ?? null,
    debug: Boolean(raw.__testDebug ?? model.debug ?? false),
    ...(slotId ? { slotId } : {}),
  });
}

export function configureTestClient(client: AUNClient, opts: TestClientOptions): AUNClient {
  const raw = client as any;
  raw.__testAunPath = opts.aunPath;
  if (opts.encryptionSeed !== undefined) raw.__testEncryptionSeed = opts.encryptionSeed;
  if (opts.verifySsl !== undefined) raw.__testVerifySsl = opts.verifySsl;
  if (opts.rootCaPath !== undefined) raw.__testRootCaPath = opts.rootCaPath;
  if (opts.debug !== undefined) raw.__testDebug = opts.debug;
  if (opts.deviceId) {
    raw.__testDeviceId = opts.deviceId;
    writeTestDeviceId(opts.aunPath, opts.deviceId);
  }
  if (raw._configModel && opts.requireForwardSecrecy !== undefined) {
    raw._configModel.requireForwardSecrecy = opts.requireForwardSecrecy;
  }
  return client;
}

export function createTestClient(opts: TestClientOptions): AUNClient {
  return configureTestClient(new AUNClient(), opts);
}

export async function registerIdentity(client: AUNClient, aid: string): Promise<void> {
  const store = createAIDStoreForClient(client);
  const registered = await store.register(aid);
  if (!registered.ok) {
    throw new Error(`${registered.error.code}: ${registered.error.message}`);
  }
}

export async function registerAndLoadIdentity(client: AUNClient, aid: string, slotId?: string): Promise<AID> {
  const store = createAIDStoreForClient(client, slotId);
  const registered = await store.register(aid);
  if (!registered.ok) {
    const existing = store.load(aid);
    if (existing.ok && existing.data?.aid.isPrivateKeyValid()) {
      client.loadIdentity(existing.data.aid);
      return existing.data.aid;
    }
    throw new Error(`${registered.error.code}: ${registered.error.message}`);
  }
  return loadIdentityFromStore(client, aid, slotId);
}

export function loadIdentityFromStore(client: AUNClient, aid: string, slotId?: string): AID {
  const store = createAIDStoreForClient(client, slotId);
  const loaded = store.load(aid);
  if (!loaded.ok || !loaded.data) {
    throw new Error(`load identity failed for ${aid}`);
  }
  client.loadIdentity(loaded.data.aid);
  return loaded.data.aid;
}

export function moveAccessTokenExpiryIntoRefreshWindow(client: AUNClient, secondsFromNow = 60): number {
  const raw = client as any;
  const aid = String(raw._currentAid?.aid ?? client.currentAid?.aid ?? raw._aid ?? '').trim();
  if (!aid) throw new Error('moveAccessTokenExpiryIntoRefreshWindow requires loaded AID');
  const deviceId = String(raw._deviceId ?? raw._currentAid?.deviceId ?? client.currentAid?.deviceId ?? '');
  const slotId = String(raw._slotId ?? raw._currentAid?.slotId ?? client.currentAid?.slotId ?? 'default');
  const expiresAt = Math.floor(Date.now() / 1000) + secondsFromNow;
  const tokenStore = raw._tokenStore;
  if (typeof tokenStore?.updateInstanceState !== 'function') {
    throw new Error('test tokenStore does not support updateInstanceState');
  }
  tokenStore.updateInstanceState(aid, deviceId, slotId, (state: Record<string, unknown>) => {
    state.access_token_expires_at = expiresAt;
    return state;
  });
  if (raw._identity && String(raw._identity.aid ?? '') === aid) {
    raw._identity.access_token_expires_at = expiresAt;
  }
  return expiresAt;
}

export async function resolveGateway(client: AUNClient, aid?: string): Promise<string> {
  const target = String(aid ?? client.currentAid?.aid ?? '').trim();
  const dotIdx = target.indexOf('.');
  const issuerDomain = dotIdx >= 0 ? target.slice(dotIdx + 1) : target;
  const discoveryPort = clientDiscoveryPort(client);
  const candidates = [
    `https://${target}${discoveryPort}/.well-known/aun-gateway`,
    `https://gateway.${issuerDomain}${discoveryPort}/.well-known/aun-gateway`,
  ];
  const discovery = new GatewayDiscovery({ verifySsl: clientVerifySsl(client) });
  let lastError: unknown = null;
  for (const url of candidates) {
    try {
      return await discovery.discover(url);
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError instanceof Error ? lastError : new Error(`gateway discovery failed for ${target}`);
}

export async function setGatewayForClient(client: AUNClient, aid?: string): Promise<string> {
  return await resolveGateway(client, aid);
}

export async function checkGatewayHealth(client: AUNClient, gateway: string, timeoutMs = 5_000): Promise<boolean> {
  const discovery = new GatewayDiscovery({ verifySsl: clientVerifySsl(client) });
  return await discovery.checkHealth(gateway, timeoutMs);
}
