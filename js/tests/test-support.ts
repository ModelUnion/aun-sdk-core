import { AID, AIDStore, AUNClient } from '../src/index.js';

function clientAunPath(client: AUNClient): string {
  const raw = client as unknown as {
    config?: Record<string, unknown>;
    configModel?: { aunPath?: string };
  };
  return String(
    raw.configModel?.aunPath
      ?? raw.config?.aun_path
      ?? raw.config?.aunPath
      ?? 'aun',
  );
}

function clientEncryptionSeed(client: AUNClient): string {
  const raw = client as unknown as {
    config?: Record<string, unknown>;
    configModel?: { seedPassword?: string | null; encryptionSeed?: string | null };
  };
  return String(
    raw.configModel?.encryptionSeed
      ?? raw.configModel?.seedPassword
      ?? raw.config?.encryption_seed
      ?? raw.config?.encryptionSeed
      ?? raw.config?.seed_password
      ?? raw.config?.seedPassword
      ?? '',
  );
}

export function createAIDStoreForClient(client: AUNClient, slotId?: string): AIDStore {
  const model = (client as unknown as {
    configModel?: {
      rootCaPem?: string | null;
      verifySsl?: boolean;
      discoveryPort?: number | null;
    };
  }).configModel ?? {};
  return new AIDStore({
    aunPath: clientAunPath(client),
    encryptionSeed: clientEncryptionSeed(client),
    rootCaPem: model.rootCaPem ?? null,
    verifySsl: Boolean(model.verifySsl ?? true),
    discoveryPort: model.discoveryPort ?? null,
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
  (client as unknown as { gatewayUrl?: string | null; _gatewayUrl?: string | null }).gatewayUrl = gateway;
  (client as unknown as { _gatewayUrl?: string | null })._gatewayUrl = gateway;
  return gateway;
}

export async function connectLoadedClient(
  client: AUNClient,
  options: Record<string, unknown> = {},
): Promise<void> {
  await client.connect(options);
}
