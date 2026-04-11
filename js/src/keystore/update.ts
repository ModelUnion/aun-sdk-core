import type { KeyStore } from './index.js';
import type { MetadataRecord } from '../types.js';

type MetadataUpdater = (metadata: MetadataRecord) => MetadataRecord | void;

type AtomicMetadataKeyStore = KeyStore & {
  updateMetadata?: (aid: string, updater: MetadataUpdater) => Promise<MetadataRecord>;
};

export async function updateKeyStoreMetadata(
  keystore: KeyStore,
  aid: string,
  updater: MetadataUpdater,
): Promise<MetadataRecord> {
  const atomic = keystore as AtomicMetadataKeyStore;
  if (typeof atomic.updateMetadata === 'function') {
    return await atomic.updateMetadata(aid, updater);
  }

  const metadata = (await keystore.loadMetadata(aid)) ?? {};
  const updated = updater(metadata) ?? metadata;
  await keystore.saveMetadata(aid, updated);
  return updated;
}
