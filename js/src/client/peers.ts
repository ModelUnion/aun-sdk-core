import { AID } from '../aid.js';
import { NotFoundError, StateError, ValidationError } from '../errors.js';
import { ClientRuntime } from './runtime.js';

export class PeerDirectory {
  constructor(private readonly runtime: ClientRuntime) {}

  cachePeer(aid: AID): AID {
    const client = this.runtime.client;
    if (!client.hasIdentity) throw new StateError('cachePeer requires a loaded identity');
    if (!aid.isCertValid()) throw new ValidationError('cachePeer requires an AID with a valid certificate');
    client._peerCache.set(aid.aid, aid);
    return aid;
  }

  getPeer(aid: string): AID | null {
    const client = this.runtime.client;
    if (!client.hasIdentity) throw new StateError('getPeer requires a loaded identity');
    return client._peerCache.get(String(aid ?? '').trim()) ?? null;
  }

  async lookupPeer(aid: string): Promise<AID> {
    const client = this.runtime.client;
    if (!client.hasIdentity) throw new StateError('lookupPeer requires a loaded identity');
    const target = String(aid ?? '').trim();
    if (!target) throw new ValidationError('lookupPeer requires non-empty aid');
    const cached = client._peerCache.get(target);
    if (cached) return cached;
    throw new NotFoundError(`peer not found in cache: ${target}`);
  }

  peers(): AID[] {
    const client = this.runtime.client;
    if (!client.hasIdentity) throw new StateError('peers requires a loaded identity');
    const entries = Array.from((client._peerCache as Map<string, AID>).entries());
    return entries.sort(([a], [b]) => a.localeCompare(b)).map(([, value]) => value);
  }
}
