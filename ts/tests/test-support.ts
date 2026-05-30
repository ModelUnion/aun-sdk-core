import { AID, AIDStore, AUNClient } from '../src/index.js';

function clientAunPath(client: AUNClient): string {
  const config = (client as unknown as {
    config: Record<string, unknown>;
    _configModel?: { aunPath?: string };
  });
  return String(
    config._configModel?.aunPath
      ?? config.config.aun_path
      ?? config.config.aunPath
      ?? '',
  );
}

function clientEncryptionSeed(client: AUNClient): string {
  const config = (client as unknown as {
    config: Record<string, unknown>;
    _configModel?: { seedPassword?: string; encryptionSeed?: string };
  });
  return String(
    config._configModel?.encryptionSeed
      ?? config._configModel?.seedPassword
      ?? config.config.encryption_seed
      ?? config.config.encryptionSeed
      ?? config.config.seed_password
      ?? config.config.seedPassword
      ?? '',
  );
}

export function createAIDStoreForClient(client: AUNClient, slotId?: string): AIDStore {
  const model = (client as any)._configModel ?? {};
  return new AIDStore({
    aunPath: clientAunPath(client),
    encryptionSeed: clientEncryptionSeed(client),
    verifySsl: Boolean(model.verifySsl ?? false),
    discoveryPort: model.discoveryPort ?? null,
    rootCaPath: model.rootCaPath ?? null,
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

export async function resolveGateway(client: AUNClient, aid?: string): Promise<string> {
  return await (client as any)._resolveGatewayForAid(aid ?? client.currentAid?.aid ?? '');
}

export async function setGatewayForClient(client: AUNClient, aid?: string): Promise<string> {
  const gateway = await resolveGateway(client, aid);
  (client as any)._gatewayUrl = gateway;
  return gateway;
}
