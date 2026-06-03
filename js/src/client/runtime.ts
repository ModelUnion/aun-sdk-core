export type ClientHost = Record<string, any>;

class RuntimeSection {
  protected readonly runtime: ClientRuntime;

  constructor(runtime: ClientRuntime) {
    this.runtime = runtime;
  }

  protected get client(): ClientHost {
    return this.runtime.client;
  }
}

export class RuntimeIdentityState extends RuntimeSection {
  get aid(): string | null {
    return this.client._aid ?? null;
  }

  get currentAid(): unknown {
    return this.client._currentAid ?? null;
  }

  get identity(): Record<string, unknown> | null {
    return this.client._identity ?? null;
  }

  get deviceId(): string {
    return String(this.client._deviceId ?? '');
  }

  get slotId(): string {
    return String(this.client._slotId ?? '');
  }

  setLoadedIdentity(aid: any, identity: Record<string, unknown>): void {
    this.client._currentAid = aid;
    this.client._aid = aid.aid;
    this.client._identity = identity;
    this.client._auth?.setIdentity?.(identity);
  }

  setIdentity(identity: Record<string, unknown> | null): void {
    this.client._identity = identity;
  }

  setAid(aid: string | null): void {
    this.client._aid = aid;
  }

  setInstanceContext(deviceId: string, slotId: string): void {
    this.client._deviceId = deviceId;
    this.client._slotId = slotId;
    this.client._auth?.setInstanceContext?.(deviceId, slotId);
  }

  clear(): void {
    this.client._currentAid = null;
    this.client._aid = null;
    this.client._identity = null;
  }
}

export class RuntimeLifecycleState extends RuntimeSection {
  get state(): string {
    return String(this.client._state ?? '');
  }

  setState(state: string): void {
    this.client._state = state;
  }

  setClosing(closing: boolean): void {
    this.client._closing = closing;
  }

  setGatewayUrl(gatewayUrl: string | null): void {
    this.client._gatewayUrl = gatewayUrl;
  }

  setSession(params: Record<string, unknown> | null, options?: Record<string, unknown>): void {
    this.client._sessionParams = params;
    if (options !== undefined) this.client._sessionOptions = options;
  }

  clearRetryState(): void {
    this.client._nextRetryAt = null;
    this.client._retryAttempt = 0;
    this.client._lastError = null;
    this.client._lastErrorCode = null;
  }

  setNextRetryAt(nextRetryAt: number | null): void {
    this.client._nextRetryAt = nextRetryAt;
  }

  setRetryAttempt(attempt: number): void {
    this.client._retryAttempt = attempt;
  }

  setError(error: Error | null, code: string | null): void {
    this.client._lastError = error;
    this.client._lastErrorCode = code;
  }

  clearReconnectState(): void {
    this.client._reconnectAbort = null;
    this.client._reconnectActive = false;
  }

  resetForDisconnect(nextState: string): void {
    this.client._state = nextState;
    this.client._nextRetryAt = null;
    this.client._retryAttempt = 0;
    this.client._lastError = null;
    this.client._lastErrorCode = null;
  }

  resetForClose(): void {
    this.client._state = 'closed';
    this.client._currentAid = null;
    this.client._aid = null;
    this.client._identity = null;
    this.client._gatewayUrl = null;
    this.client._sessionParams = null;
    this.clearRetryState();
  }
}

export class RuntimeRpcState extends RuntimeSection {
  get protectedHeaders(): Record<string, string> | null {
    return this.client._instanceProtectedHeaders ?? null;
  }

  set protectedHeaders(value: Record<string, string> | null) {
    this.client._instanceProtectedHeaders = value;
  }

  get pullGates(): Map<string, { inflight: boolean; startedAt: number; token: number }> {
    if (!this.client._pullGates) {
      this.client._pullGates = new Map();
    }
    return this.client._pullGates;
  }
}

export class RuntimeDeliveryState extends RuntimeSection {
  get seqTracker(): unknown {
    return this.client._seqTracker;
  }

  set seqTracker(value: unknown) {
    this.client._seqTracker = value;
  }

  setGapFillActive(active: boolean): void {
    this.client._gapFillActive = active;
  }

  setOnlineUnreadHintTimer(timer: unknown): void {
    this.client._onlineUnreadHintTimer = timer;
  }

  setOnlineUnreadHintDrainActive(active: boolean): void {
    this.client._onlineUnreadHintDrainActive = active;
  }

  setV2PullPending(pending: boolean): void {
    this.client._v2PullPending = pending;
  }

  setV2PullInflight(inflight: boolean): void {
    this.client._v2PullInflight = inflight;
  }
}

export class RuntimeV2State extends RuntimeSection {
  get session(): unknown {
    return this.client._v2Session;
  }

  set session(value: unknown) {
    this.client._v2Session = value;
  }

  get bootstrapCache(): Map<string, unknown> {
    if (!this.client._v2BootstrapCache) {
      this.client._v2BootstrapCache = new Map();
    }
    return this.client._v2BootstrapCache;
  }

  setBootstrapCache(cache: Map<string, unknown>): void {
    this.client._v2BootstrapCache = cache;
  }

  setSessionState(keyStore: unknown, session: unknown): void {
    this.client._v2KeyStore = keyStore;
    this.client._v2Session = session;
  }

  resetForIdentity(): void {
    this.client._v2Session = undefined;
    this.client._v2KeyStore = undefined;
    this.client._v2SessionInitInFlight = null;
    this.client._v2BootstrapCache = new Map();
    this.client._v2SigCache = new Map();
    this.client._v2SenderIKPending = new Map();
    this.client._v2SenderIKFetching = new Set();
  }

  get groupSpkRegistrationInflight(): Set<string> {
    if (!this.client._groupSpkRegistrationInflight) {
      this.client._groupSpkRegistrationInflight = new Set<string>();
    }
    return this.client._groupSpkRegistrationInflight;
  }

  get groupSpkRotationInflight(): Set<string> {
    if (!this.client._groupSpkRotationInflight) {
      this.client._groupSpkRotationInflight = new Set<string>();
    }
    return this.client._groupSpkRotationInflight;
  }

  get groupSpkPeerFallbackRegistered(): Set<string> {
    if (!this.client._groupSpkPeerFallbackRegistered) {
      this.client._groupSpkPeerFallbackRegistered = new Set<string>();
    }
    return this.client._groupSpkPeerFallbackRegistered;
  }
}

export class RuntimeGroupState extends RuntimeSection {
  get chains(): Map<string, [number, string]> {
    if (!this.client._v2StateChains) this.client._v2StateChains = new Map();
    return this.client._v2StateChains;
  }

  get securityLevels(): Map<string, string> {
    if (!this.client._v2GroupSecurityLevels) this.client._v2GroupSecurityLevels = new Map();
    return this.client._v2GroupSecurityLevels;
  }

  get sigCache(): Map<string, number> {
    if (!this.client._v2SigCache) this.client._v2SigCache = new Map();
    return this.client._v2SigCache;
  }

  get lazyProposeTriggered(): Map<string, number> {
    if (!this.client._v2LazyProposeTriggered) this.client._v2LazyProposeTriggered = new Map();
    return this.client._v2LazyProposeTriggered;
  }
}

export class RuntimeServices extends RuntimeSection {
  get logger(): unknown { return this.client._logger; }
  get clientLog(): unknown { return this.client._clientLog; }
  get dispatcher(): unknown { return this.client._dispatcher; }
  get tokenStore(): unknown { return this.client._tokenStore; }
  get auth(): unknown { return this.client._auth; }
  get transport(): unknown { return this.client._transport; }
  get discovery(): unknown { return this.client._discovery; }
  get agentMdManager(): unknown { return this.client._agentMdManager; }
}

export class ClientRuntime {
  readonly client: ClientHost;
  readonly identity: RuntimeIdentityState;
  readonly lifecycle: RuntimeLifecycleState;
  readonly rpc: RuntimeRpcState;
  readonly delivery: RuntimeDeliveryState;
  readonly v2: RuntimeV2State;
  readonly groupState: RuntimeGroupState;
  readonly services: RuntimeServices;

  constructor(client: unknown) {
    this.client = client as ClientHost;
    this.identity = new RuntimeIdentityState(this);
    this.lifecycle = new RuntimeLifecycleState(this);
    this.rpc = new RuntimeRpcState(this);
    this.delivery = new RuntimeDeliveryState(this);
    this.v2 = new RuntimeV2State(this);
    this.groupState = new RuntimeGroupState(this);
    this.services = new RuntimeServices(this);
  }
}
