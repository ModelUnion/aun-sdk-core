import { describe, expect, it, vi } from 'vitest';

import { IdentityRuntimeManager } from '../../src/client/identity.js';
import { PeerDirectory } from '../../src/client/peers.js';
import { ClientRuntime } from '../../src/client/runtime.js';
import { NotFoundError, StateError, ValidationError } from '../../src/errors.js';
import { ConnectionState } from '../../src/types.js';

function fakeAid(aid: string, options: { privateKeyValid?: boolean; certValid?: boolean } = {}): Record<string, any> {
  return {
    aid,
    privateKeyPem: `priv:${aid}`,
    publicKey: `pub:${aid}`,
    certPem: `cert:${aid}`,
    isPrivateKeyValid: vi.fn(() => options.privateKeyValid ?? true),
    isCertValid: vi.fn(() => options.certValid ?? true),
  };
}

function createIdentityClient(state: ConnectionState = ConnectionState.NO_IDENTITY): Record<string, any> {
  return {
    state,
    _applyAidRuntimeContext: vi.fn(),
    _auth: { setIdentity: vi.fn() },
    _state: 'retry_backoff',
    _closing: true,
    _lastError: new Error('old'),
    _lastErrorCode: 'OLD',
    _retryAttempt: 3,
    _nextRetryAt: Date.now() + 1000,
  };
}

function createPeerClient(hasIdentity = true): Record<string, any> {
  return {
    hasIdentity,
    _peerCache: new Map<string, any>(),
  };
}

describe('IdentityRuntimeManager 组件边界', () => {
  it('loadIdentity 只接受有效私钥 AID，并重置身份运行态', () => {
    const client = createIdentityClient();
    const manager = new IdentityRuntimeManager(new ClientRuntime(client));
    const aid = fakeAid('alice.aid.com');

    manager.loadIdentity(aid as any);

    expect(client._applyAidRuntimeContext).toHaveBeenCalledWith(aid);
    expect(client._currentAid).toBe(aid);
    expect(client._aid).toBe('alice.aid.com');
    expect(client._identity).toEqual({
      aid: 'alice.aid.com',
      private_key_pem: 'priv:alice.aid.com',
      public_key_der_b64: 'pub:alice.aid.com',
      cert: 'cert:alice.aid.com',
    });
    expect(client._auth.setIdentity).toHaveBeenCalledWith(client._identity);
    expect(client._state).toBe('standby');
    expect(client._closing).toBe(false);
    expect(client._lastError).toBeNull();
    expect(client._lastErrorCode).toBeNull();
    expect(client._retryAttempt).toBe(0);
    expect(client._nextRetryAt).toBeNull();
  });

  it('loadIdentity 拒绝无私钥 AID 和非 no_identity/closed 状态', () => {
    expect(() => new IdentityRuntimeManager(new ClientRuntime(createIdentityClient()))
      .loadIdentity(fakeAid('alice.aid.com', { privateKeyValid: false }) as any))
      .toThrow(StateError);

    const readyClient = createIdentityClient(ConnectionState.READY);
    expect(() => new IdentityRuntimeManager(new ClientRuntime(readyClient))
      .loadIdentity(fakeAid('alice.aid.com') as any))
      .toThrow(StateError);
  });
});

describe('PeerDirectory 组件边界', () => {
  it('cachePeer/getPeer/lookupPeer 使用本地缓存并按 aid 排序返回 peers', async () => {
    const client = createPeerClient();
    const directory = new PeerDirectory(new ClientRuntime(client));
    const bob = fakeAid('bob1.aid.com');
    const alice = fakeAid('alice.aid.com');

    expect(directory.cachePeer(bob as any)).toBe(bob);
    directory.cachePeer(alice as any);

    expect(directory.getPeer(' bob1.aid.com ')).toBe(bob);
    await expect(directory.lookupPeer('bob1.aid.com')).resolves.toBe(bob);
    expect(directory.peers()).toEqual([alice, bob]);
  });

  it('PeerDirectory 对身份状态、证书有效性和 lookup 空值/未命中做边界校验', async () => {
    expect(() => new PeerDirectory(new ClientRuntime(createPeerClient(false)))
      .cachePeer(fakeAid('bob1.aid.com') as any))
      .toThrow(StateError);

    const directory = new PeerDirectory(new ClientRuntime(createPeerClient()));
    expect(() => directory.cachePeer(fakeAid('bob1.aid.com', { certValid: false }) as any))
      .toThrow(ValidationError);
    await expect(directory.lookupPeer('   ')).rejects.toThrow(ValidationError);
    await expect(directory.lookupPeer('missing.aid.com')).rejects.toThrow(NotFoundError);
  });
});
