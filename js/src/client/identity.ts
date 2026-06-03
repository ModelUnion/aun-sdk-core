import { AID } from '../aid.js';
import { StateError } from '../errors.js';
import { ConnectionState } from '../types.js';
import { ClientRuntime } from './runtime.js';

export class IdentityRuntimeManager {
  constructor(private readonly runtime: ClientRuntime) {}

  loadIdentity(aid: AID): void {
    const client = this.runtime.client;
    if (!aid?.isPrivateKeyValid()) throw new StateError('loadIdentity requires an AID with a valid private key');
    const publicState = client.state as ConnectionState;
    if (publicState !== ConnectionState.NO_IDENTITY && publicState !== ConnectionState.CLOSED) {
      throw new StateError(`loadIdentity not allowed in state ${publicState}`);
    }
    client._applyAidRuntimeContext(aid);
    this.runtime.identity.setLoadedIdentity(aid, {
      aid: aid.aid,
      private_key_pem: aid.privateKeyPem,
      public_key_der_b64: aid.publicKey,
      cert: aid.certPem,
    });
    this.runtime.lifecycle.setState('standby');
    this.runtime.lifecycle.setClosing(false);
    this.runtime.lifecycle.clearRetryState();
  }
}
