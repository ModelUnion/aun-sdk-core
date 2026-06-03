import { StateError, ValidationError } from '../errors.js';
import { ConnectionState, type RpcParams } from '../types.js';
import type { ConnectionOptions } from '../client.js';
import { ClientRuntime, type ClientHost } from './runtime.js';

const PUBLIC_CONNECTION_OPTION_KEYS = new Set([
  'auto_reconnect',
  'connect_timeout',
  'retry_initial_delay',
  'retry_max_delay',
  'retry_max_attempts',
  'heartbeat_interval',
  'call_timeout',
  'connection_kind',
  'short_ttl_ms',
  'delivery_mode',
  'extra_info',
  'background_sync',
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function gatewayFromAuthResult(result: unknown, fallback: string): string {
  if (!isRecord(result)) return fallback;
  return String(result.gateway ?? result.gateway_url ?? fallback).trim();
}

function accessTokenFromAuthResult(result: unknown): string {
  if (!isRecord(result)) return '';
  return String(result.access_token ?? result.token ?? result.kite_token ?? '').trim();
}

function identityFromAuthResult(client: ClientHost, result: unknown, target: string): Record<string, unknown> | null {
  const base = isRecord(client._identity) ? { ...client._identity } : {};
  const aid = String(base.aid ?? target ?? '').trim();
  if (!aid) return null;
  const identity: Record<string, unknown> = { ...base, aid };
  if (isRecord(result)) {
    const accessToken = accessTokenFromAuthResult(result);
    const refreshToken = String(result.refresh_token ?? '').trim();
    if (accessToken) identity.access_token = accessToken;
    if (typeof result.token === 'string' && result.token.trim()) identity.token = result.token.trim();
    if (typeof result.kite_token === 'string' && result.kite_token.trim()) identity.kite_token = result.kite_token.trim();
    if (refreshToken) identity.refresh_token = refreshToken;
    if (typeof result.access_token_expires_at === 'number') {
      identity.access_token_expires_at = result.access_token_expires_at;
    } else if (typeof result.expires_at === 'number') {
      identity.access_token_expires_at = result.expires_at;
    }
  }
  return identity;
}

function cachedAccessToken(client: Record<string, any>): string {
  if (isRecord(client._identity)) {
    const token = String(client._identity.access_token ?? '').trim();
    if (token) return token;
  }
  if (isRecord(client._sessionParams)) {
    return String(client._sessionParams.access_token ?? '').trim();
  }
  return '';
}

export class LifecycleController {
  constructor(private readonly runtime: ClientRuntime) {}

  async authenticate(options: RpcParams = {}): Promise<Record<string, unknown>> {
    const client = this.runtime.client;
    const tStart = Date.now();
    const target = client._currentAid?.aid ?? client._aid ?? '';
    if (!target || !client._currentAid?.isPrivateKeyValid()) {
      throw new StateError('authenticate requires a loaded AID with a valid private key');
    }
    const publicState = client.state as ConnectionState;
    if (publicState !== ConnectionState.STANDBY) {
      throw new StateError(`authenticate not allowed in state ${publicState}`);
    }
    if ('gateway' in options || 'gateways' in options) {
      throw new ValidationError('gateway must be resolved by discovery and cannot be supplied externally');
    }
    if ('aid' in options || 'access_token' in options || 'token' in options || 'kite_token' in options) {
      throw new ValidationError('authenticate options must not include aid or token fields; load an AID object first');
    }
    client._state = 'connecting';
    try {
      const gateway = String(client._gatewayUrl ?? await client._resolveGatewayForAid(target)).trim();
      const result = await client._auth.authenticate(gateway, target);
      client._gatewayUrl = gatewayFromAuthResult(result, gateway);
      let loadedIdentity: Record<string, unknown> | null = null;
      try {
        loadedIdentity = await client._auth.loadIdentityOrNone(target);
      } catch (exc) {
        client._clientLog.debug(`authenticate identity reload skipped: ${exc instanceof Error ? exc.message : String(exc)}`);
      }
      client._identity = loadedIdentity ?? identityFromAuthResult(client, result, target);
      client._state = 'authenticated';
      client._lastError = null;
      client._lastErrorCode = null;
      client._clientLog.debug(`authenticate exit: elapsed=${Date.now() - tStart}ms aid=${target}`);
      return result as Record<string, unknown>;
    } catch (err) {
      client._state = 'standby';
      client._lastError = err instanceof Error ? err : new Error(String(err));
      client._lastErrorCode = 'AUTHENTICATE_FAILED';
      client._clientLog.debug(`authenticate exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  async connect(opts?: ConnectionOptions): Promise<void> {
    const client = this.runtime.client;
    const tStart = Date.now();
    if (opts !== undefined && opts !== null && typeof opts === 'object') {
      const raw = opts as Record<string, unknown>;
      const invalid = Object.keys(raw).filter((key) => !PUBLIC_CONNECTION_OPTION_KEYS.has(key)).sort();
      if (invalid.length > 0) {
        throw new ValidationError(`connect options contain unsupported field(s): ${invalid.join(', ')}`);
      }
    }
    const target = client._currentAid?.aid ?? client._aid ?? '';
    if (!target || !client._currentAid?.isPrivateKeyValid()) {
      throw new StateError('connect requires a loaded AID with a valid private key');
    }
    const options: RpcParams = {};
    if (opts?.auto_reconnect !== undefined) options.auto_reconnect = opts.auto_reconnect;
    if (opts?.heartbeat_interval !== undefined) options.heartbeat_interval = opts.heartbeat_interval;
    if (opts?.connect_timeout !== undefined || opts?.call_timeout !== undefined) {
      options.timeouts = {
        ...(opts.connect_timeout !== undefined ? { connect: opts.connect_timeout } : {}),
        ...(opts.call_timeout !== undefined ? { call: opts.call_timeout } : {}),
      };
    }
    if (opts?.retry_initial_delay !== undefined || opts?.retry_max_delay !== undefined || opts?.retry_max_attempts !== undefined) {
      options.retry = {
        initial_delay: opts.retry_initial_delay ?? 1,
        max_delay: opts.retry_max_delay ?? 64,
        max_attempts: opts.retry_max_attempts ?? 0,
      };
    }
    if (opts?.connection_kind !== undefined) options.connection_kind = opts.connection_kind;
    if (opts?.short_ttl_ms !== undefined) options.short_ttl_ms = opts.short_ttl_ms;
    if (opts?.delivery_mode !== undefined) options.delivery_mode = opts.delivery_mode;
    if (opts?.extra_info !== undefined) options.extra_info = opts.extra_info;
    if (opts?.background_sync !== undefined) options.background_sync = opts.background_sync;
    client._clientLog.debug(`connect enter: state=${client._state} aid=${client._aid ?? '-'}`);
    const publicState = client.state as ConnectionState;
    const allowed = new Set<ConnectionState>([
      ConnectionState.STANDBY,
      ConnectionState.AUTHENTICATED,
      ConnectionState.RETRY_BACKOFF,
      ConnectionState.CONNECTION_FAILED,
    ]);
    if (!allowed.has(publicState)) {
      client._clientLog.debug(`connect exit (error): elapsed=${Date.now() - tStart}ms err=invalid_state state=${client._state}`);
      throw new StateError(`connect not allowed in state ${publicState}`);
    }
    if (publicState === ConnectionState.RETRY_BACKOFF && client._reconnectAbort) {
      client._reconnectAbort.abort();
      client._reconnectAbort = null;
      client._reconnectActive = false;
    }
    if (publicState === ConnectionState.CONNECTION_FAILED) {
      client._retryAttempt = 0;
      client._lastError = null;
      client._lastErrorCode = null;
    }
    client._nextRetryAt = null;
    let authResult: Record<string, unknown> | null = null;
    if (!client._gatewayUrl) {
      authResult = await client.authenticate();
    }
    client._state = 'connecting';

    const gateway = String(client._gatewayUrl ?? '').trim();
    const accessToken = accessTokenFromAuthResult(authResult) || cachedAccessToken(client);
    const params = { ...options, gateway, ...(accessToken ? { access_token: accessToken } : {}) };
    const normalized = client._normalizeConnectParams(params);
    client._sessionParams = normalized;
    client._sessionOptions = client._buildSessionOptions(normalized);
    client._transport.setTimeout(client._sessionOptions.timeouts.call);
    client._closing = false;

    const gateways = client._resolveGateways(normalized);
    let lastErr: unknown = null;
    for (const gw of gateways) {
      try {
        const gwParams = { ...normalized, gateway: gw };
        await client._connectOnce(gwParams, true);
        client._clientLog.debug(`connect exit: elapsed=${Date.now() - tStart}ms state=${client._state}`);
        return;
      } catch (err) {
        lastErr = err;
        if (gateways.length > 1) {
          client._clientLog.warn(`connect: gateway ${gw} failed, trying next: ${err instanceof Error ? err.message : String(err)}`);
        }
        if (client._state === 'connecting' || client._state === 'authenticating') {
          client._state = 'connecting';
        }
      }
    }
    if (client._state === 'connecting' || client._state === 'authenticating') {
      client._state = client._currentAid || client._aid ? 'standby' : 'idle';
    }
    client._lastError = lastErr instanceof Error ? lastErr : new Error(String(lastErr));
    client._lastErrorCode = 'CONNECT_FAILED';
    client._clientLog.debug(`connect exit (error): elapsed=${Date.now() - tStart}ms err=${lastErr instanceof Error ? lastErr.message : String(lastErr)}`);
    throw lastErr;
  }
}
