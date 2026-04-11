import type { KeyStore } from './index.js';
import type { MetadataRecord } from '../types.js';

type MetadataUpdater = (metadata: MetadataRecord) => MetadataRecord | void;

type AtomicMetadataKeyStore = KeyStore & {
  updateMetadata?: (aid: string, updater: MetadataUpdater) => MetadataRecord;
};

export function updateKeyStoreMetadata(
  keystore: KeyStore,
  aid: string,
  updater: MetadataUpdater,
): MetadataRecord {
  const atomic = keystore as AtomicMetadataKeyStore;
  if (typeof atomic.updateMetadata === 'function') {
    return atomic.updateMetadata(aid, updater);
  }

  const metadata = keystore.loadMetadata(aid) ?? {};
  const updated = updater(metadata) ?? metadata;
  keystore.saveMetadata(aid, updated);
  return updated;
}
