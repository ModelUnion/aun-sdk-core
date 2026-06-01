import { AID, AIDStore, AUNClient } from '../src/index.js';

export type TestAIDStoreOptions = {
  aunPath: string;
  encryptionSeed?: string;
  verifySsl?: boolean;
  rootCaPem?: string | null;
  debug?: boolean;
  deviceId?: string;
  slotId?: string;
};

export function createAIDStore(opts: TestAIDStoreOptions): AIDStore {
  return new AIDStore({
    aunPath: opts.aunPath,
    encryptionSeed: opts.encryptionSeed ?? '',
    rootCaPem: opts.rootCaPem ?? null,
    verifySsl: opts.verifySsl ?? true,
    ...(opts.deviceId ? { deviceId: opts.deviceId } : {}),
    ...(opts.slotId ? { slotId: opts.slotId } : {}),
  });
}

export async function prepareIdentity(opts: TestAIDStoreOptions & { aid: string }): Promise<AID> {
  const store = createAIDStore(opts);
  const registered = await store.register(opts.aid);
  if (!registered.ok) {
    const existing = await store.load(opts.aid);
    if (existing.ok && existing.data?.aid.isPrivateKeyValid()) {
      return existing.data.aid;
    }
    throw new Error(`${registered.error.code}: ${registered.error.message}`);
  }
  const loaded = await store.load(opts.aid);
  if (!loaded.ok || !loaded.data) {
    throw new Error(`load identity failed for ${opts.aid}: ${loaded.ok ? 'empty result' : loaded.error.message}`);
  }
  return loaded.data.aid;
}

export async function loadPreparedIdentity(opts: TestAIDStoreOptions & { aid: string }): Promise<AID> {
  const store = createAIDStore(opts);
  const loaded = await store.load(opts.aid);
  if (!loaded.ok || !loaded.data) {
    throw new Error(`load identity failed for ${opts.aid}: ${loaded.ok ? 'empty result' : loaded.error.message}`);
  }
  return loaded.data.aid;
}

export async function createClientWithIdentity(opts: TestAIDStoreOptions & { aid: string }): Promise<AUNClient> {
  return new AUNClient(await prepareIdentity(opts));
}

export async function createClientFromStore(opts: TestAIDStoreOptions & { aid: string }): Promise<AUNClient> {
  return new AUNClient(await loadPreparedIdentity(opts));
}

function clientAunPath(client: AUNClient): string {
  const raw = client as unknown as {
    __testAunPath?: string;
    config?: Record<string, unknown>;
    configModel?: { aunPath?: string };
  };
  return String(
    raw.__testAunPath
      ?? raw.configModel?.aunPath
      ?? raw.config?.aun_path
      ?? raw.config?.aunPath
      ?? 'aun',
  );
}

function clientEncryptionSeed(client: AUNClient): string {
  const raw = client as unknown as {
    __testEncryptionSeed?: string;
    config?: Record<string, unknown>;
    configModel?: { seedPassword?: string | null; encryptionSeed?: string | null };
  };
  return String(
    raw.__testEncryptionSeed
      ?? raw.configModel?.encryptionSeed
      ?? raw.configModel?.seedPassword
      ?? raw.config?.encryption_seed
      ?? raw.config?.encryptionSeed
      ?? raw.config?.seed_password
      ?? raw.config?.seedPassword
      ?? '',
  );
}

export function createAIDStoreForClient(client: AUNClient, slotId?: string): AIDStore {
  const raw = client as unknown as {
    __testVerifySsl?: boolean;
    __testRootCaPem?: string | null;
    __testDeviceId?: string;
    configModel?: {
      rootCaPem?: string | null;
      verifySsl?: boolean;
      discoveryPort?: number | null;
    };
  };
  const model = raw.configModel ?? {};
  return new AIDStore({
    aunPath: clientAunPath(client),
    encryptionSeed: clientEncryptionSeed(client),
    rootCaPem: raw.__testRootCaPem ?? model.rootCaPem ?? null,
    verifySsl: Boolean(raw.__testVerifySsl ?? model.verifySsl ?? true),
    ...(raw.__testDeviceId ?? (raw as any)._deviceId ? { deviceId: raw.__testDeviceId ?? (raw as any)._deviceId } : {}),
    ...(slotId ? { slotId } : {}),
  });
}

export async function registerIdentity(client: AUNClient, aid: string): Promise<void> {
  const store = createAIDStoreForClient(client);
  const registered = await store.register(aid);
  if (!registered.ok) {
    throw new Error(`${registered.error.code}: ${registered.error.message}`);
  }
}

export async function loadIdentityFromStore(client: AUNClient, aid: string, slotId?: string): Promise<AID> {
  const store = createAIDStoreForClient(client, slotId);
  const loaded = await store.load(aid);
  if (!loaded.ok || !loaded.data) {
    throw new Error(`load identity failed for ${aid}: ${loaded.ok ? 'empty result' : loaded.error.message}`);
  }
  client.loadIdentity(loaded.data.aid);
  return loaded.data.aid;
}

export async function registerAndLoadIdentity(client: AUNClient, aid: string, slotId?: string): Promise<AID> {
  const store = createAIDStoreForClient(client, slotId);
  const registered = await store.register(aid);
  if (!registered.ok) {
    const existing = await store.load(aid);
    if (existing.ok && existing.data?.aid.isPrivateKeyValid()) {
      client.loadIdentity(existing.data.aid);
      return existing.data.aid;
    }
    throw new Error(`${registered.error.code}: ${registered.error.message}`);
  }
  return await loadIdentityFromStore(client, aid, slotId);
}

export async function moveAccessTokenExpiryIntoRefreshWindow(client: AUNClient, secondsFromNow = 60): Promise<number> {
  const raw = client as any;
  const aid = String(raw._currentAid?.aid ?? client.currentAid?.aid ?? raw._aid ?? '').trim();
  if (!aid) throw new Error('moveAccessTokenExpiryIntoRefreshWindow requires loaded AID');
  const deviceId = String(raw._deviceId ?? raw._currentAid?.deviceId ?? client.currentAid?.deviceId ?? '');
  const slotId = String(raw._slotId ?? raw._currentAid?.slotId ?? client.currentAid?.slotId ?? 'default');
  const expiresAt = Math.floor(Date.now() / 1000) + secondsFromNow;
  const tokenStore = raw._tokenStore;
  if (typeof tokenStore?.updateInstanceState !== 'function') {
    throw new Error('test token store does not support updateInstanceState');
  }
  await tokenStore.updateInstanceState(aid, deviceId, slotId, (state: Record<string, unknown>) => {
    state.access_token_expires_at = expiresAt;
    return state;
  });
  if (raw._identity && String(raw._identity.aid ?? '') === aid) {
    raw._identity.access_token_expires_at = expiresAt;
  }
  return expiresAt;
}

function issuerFromAid(aid: string): string {
  const target = String(aid ?? '').trim();
  const dot = target.indexOf('.');
  return dot >= 0 ? target.slice(dot + 1) : target;
}

export async function resolveGateway(client: AUNClient, aid?: string): Promise<string> {
  const target = String(aid ?? '').trim();
  const issuer = issuerFromAid(target);
  const port = client.configModel.discoveryPort ? `:${client.configModel.discoveryPort}` : '';
  let lastError: unknown = null;
  for (const scheme of ['https', 'http']) {
    const url = `${scheme}://${issuer}${port}/.well-known/aun-gateway`;
    try {
      return await client.discovery.discover(url);
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError instanceof Error ? lastError : new Error(`gateway discovery failed for ${target}`);
}

export async function setGatewayForClient(client: AUNClient, aid?: string): Promise<string> {
  const gateway = await resolveGateway(client, aid);
  return gateway;
}

export async function connectLoadedClient(
  client: AUNClient,
  options: Record<string, unknown> = {},
): Promise<void> {
  await client.connect(options);
}
