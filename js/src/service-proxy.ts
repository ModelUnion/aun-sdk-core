import { AuthError, ConnectionError, ValidationError } from './errors.js';
import type { ModuleLogger } from './logger.js';

type Dict = Record<string, unknown>;

const PROXY_DISCOVERY_CACHE_KEY = 'service_proxy_discovery';
const PROXY_DISCOVERY_CACHE_TTL_MS = 3600_000;
const TOKEN_EXPIRY_SKEW_SECONDS = 30;

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'upgrade',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
]);
const AUTO_RESPONSE_HEADERS = new Set(['content-length', 'date', 'server']);
const ALLOWED_SCHEMES = new Set(['http:', 'https:', 'ws:', 'wss:']);
const RESERVED_SERVICE_NAMES = new Set([
  'api',
  'health',
  'metrics',
  'status',
  'proxy',
  'admin',
  'ws',
  'wss',
  'static',
  'favicon.ico',
]);
const SENSITIVE_METADATA_KEYS = new Set([
  'endpoint',
  'url',
  'uri',
  'token',
  'access_token',
  'authorization',
  'cookie',
  'secret',
  'password',
  'private_key',
  'key',
  'cert',
  'certificate',
]);
const SERVICE_NAME_RE = /^[a-z0-9_-]+$/;
const STREAMING_SERVICE_TYPES = new Set(['mcp', 'mcp-sse', 'mcp-streamable-http', 'sse', 'stream', 'file', 'ws', 'websocket']);
const VALID_STREAM_MODES = new Set(['auto', 'stream', 'always', 'no_stream']);
const FILE_CONTENT_TYPES = new Set([
  'application/octet-stream',
  'application/pdf',
  'application/zip',
  'application/x-zip-compressed',
  'application/gzip',
  'application/x-tar',
]);

export interface ServiceSummary {
  service_name: string;
  service_type: string;
  visibility: string;
  metadata: Dict;
}

export interface WebSocketFactoryOptions {
  headers?: Record<string, string>;
  maxPayloadBytes?: number;
  verifySsl?: boolean;
}

export interface WebSocketLike {
  readonly readyState: number;
  readonly protocol?: string;
  binaryType?: BinaryType;
  send(data: string | ArrayBuffer | Blob | ArrayBufferView): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: 'open', listener: (event: Event) => void): void;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  addEventListener(type: 'close', listener: (event: CloseEvent) => void): void;
  addEventListener(type: 'error', listener: (event: Event) => void): void;
  removeEventListener(type: 'open', listener: (event: Event) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  removeEventListener(type: 'close', listener: (event: CloseEvent) => void): void;
  removeEventListener(type: 'error', listener: (event: Event) => void): void;
}

export type WebSocketFactory = (
  url: string,
  protocols?: string | string[],
  options?: WebSocketFactoryOptions,
) => WebSocketLike;

export class ServiceRecord {
  readonly service_name: string;
  readonly endpoint: string;
  readonly service_type: string;
  readonly visibility: string;
  readonly metadata: Dict;

  constructor(params: {
    service_name: string;
    endpoint: string;
    service_type?: string;
    visibility?: string;
    metadata?: Dict | null;
  }) {
    this.service_name = params.service_name;
    this.endpoint = params.endpoint;
    this.service_type = String(params.service_type ?? 'http').trim() || 'http';
    this.visibility = String(params.visibility ?? 'private').trim() || 'private';
    this.metadata = sanitizeMetadata(params.metadata ?? {});
  }

  summary(): ServiceSummary {
    return {
      service_name: this.service_name,
      service_type: this.service_type,
      visibility: this.visibility,
      metadata: sanitizeMetadata(this.metadata),
    };
  }
}

export class EndpointPolicy {
  readonly allowedHosts: Set<string>;

  constructor(opts: { allowedHosts?: Iterable<string> } = {}) {
    this.allowedHosts = new Set(Array.from(opts.allowedHosts ?? []).map(normalizeHost).filter(Boolean));
  }

  isAllowed(endpoint: string): boolean {
    let parsed: URL;
    try {
      parsed = new URL(String(endpoint ?? '').trim());
    } catch {
      return false;
    }
    if (!ALLOWED_SCHEMES.has(parsed.protocol)) return false;
    const host = normalizeHost(parsed.hostname);
    if (!host) return false;
    if (this.allowedHosts.has(host)) return true;
    if (host === 'localhost') return true;
    return isIPv4LoopbackHost(host);
  }
}

export class EmbeddedServiceRegistry {
  private readonly _endpointPolicy: EndpointPolicy;
  private readonly _replaceExisting: boolean;
  private readonly _records = new Map<string, ServiceRecord>();

  constructor(opts: { endpointPolicy?: EndpointPolicy; replaceExisting?: boolean } = {}) {
    this._endpointPolicy = opts.endpointPolicy ?? new EndpointPolicy();
    this._replaceExisting = opts.replaceExisting ?? true;
  }

  register(
    serviceName: string,
    endpoint: string,
    opts: { serviceType?: string; visibility?: string; metadata?: Dict | null } = {},
  ): ServiceRecord {
    const normalizedName = normalizeServiceName(serviceName);
    const endpointText = String(endpoint ?? '').trim();
    if (!this._endpointPolicy.isAllowed(endpointText)) {
      throw new ValidationError('endpoint is not allowed');
    }
    if (this._records.has(normalizedName) && !this._replaceExisting) {
      throw new ValidationError(`service already registered: ${normalizedName}`);
    }
    const record = new ServiceRecord({
      service_name: normalizedName,
      endpoint: endpointText,
      service_type: opts.serviceType,
      visibility: opts.visibility,
      metadata: opts.metadata,
    });
    this._records.set(normalizedName, record);
    return record;
  }

  unregister(serviceName: string): boolean {
    return this._records.delete(normalizeServiceName(serviceName));
  }

  get(serviceName: string): ServiceRecord | null {
    return this._records.get(normalizeServiceName(serviceName)) ?? null;
  }

  listRecords(): ServiceRecord[] {
    return Array.from(this._records.values()).sort((a, b) => a.service_name.localeCompare(b.service_name));
  }

  listSummaries(): ServiceSummary[] {
    return this.listRecords().map((record) => record.summary());
  }
}

export interface ServiceProxyClientOptions {
  providerAid: string;
  registry?: EmbeddedServiceRegistry;
  endpointPolicy?: EndpointPolicy;
  logger?: ModuleLogger | null;
  aunClient?: unknown;
  maxResponseBodyBytes?: number;
  maxTunnelMessageBytes?: number;
  webSocketFactory?: WebSocketFactory;
}

interface ProtocolDetection {
  serviceType: string;
  streamMode: string;
  isStream: boolean;
}

class AsyncQueue<T> {
  private readonly _items: T[] = [];
  private readonly _waiters: Array<(value: T | null) => void> = [];
  private _closed = false;

  push(value: T): void {
    if (this._closed) return;
    const waiter = this._waiters.shift();
    if (waiter) waiter(value);
    else this._items.push(value);
  }

  close(): void {
    this._closed = true;
    for (const waiter of this._waiters.splice(0)) waiter(null);
  }

  shift(timeoutMs?: number): Promise<T | null> {
    if (this._items.length > 0) return Promise.resolve(this._items.shift()!);
    if (this._closed) return Promise.resolve(null);
    return new Promise((resolve) => {
      let timer: ReturnType<typeof setTimeout> | null = null;
      const done = (value: T | null): void => {
        if (timer !== null) clearTimeout(timer);
        resolve(value);
      };
      this._waiters.push(done);
      if (timeoutMs !== undefined) {
        timer = setTimeout(() => {
          const idx = this._waiters.indexOf(done);
          if (idx >= 0) this._waiters.splice(idx, 1);
          resolve(null);
        }, Math.max(0, timeoutMs));
      }
    });
  }
}

class TunnelSocket {
  private readonly _ws: WebSocketLike;
  private readonly _queue = new AsyncQueue<string>();

  constructor(ws: WebSocketLike) {
    this._ws = ws;
    try { this._ws.binaryType = 'arraybuffer'; } catch { /* noop */ }
    ws.addEventListener('message', (event) => {
      const data = event.data;
      if (typeof data === 'string') {
        this._queue.push(data);
      } else if (data instanceof ArrayBuffer) {
        this._queue.push(new TextDecoder().decode(new Uint8Array(data)));
      } else if (ArrayBuffer.isView(data)) {
        this._queue.push(new TextDecoder().decode(new Uint8Array(data.buffer, data.byteOffset, data.byteLength)));
      } else {
        this._queue.push(String(data ?? ''));
      }
    });
    ws.addEventListener('close', () => this._queue.close());
    ws.addEventListener('error', () => this._queue.close());
  }

  async send(message: Dict): Promise<void> {
    this._ws.send(JSON.stringify(message));
  }

  recv(timeoutMs?: number): Promise<string | null> {
    return this._queue.shift(timeoutMs);
  }

  close(): void {
    try { this._ws.close(); } catch { /* noop */ }
    this._queue.close();
  }
}

export class ServiceProxyClient {
  readonly providerAid: string;
  readonly registry: EmbeddedServiceRegistry;
  readonly maxResponseBodyBytes: number;
  readonly maxTunnelMessageBytes: number;
  private readonly _logger: ModuleLogger | null;
  private readonly _aunClient: unknown;
  private readonly _webSocketFactory: WebSocketFactory | null;
  private _running = false;
  private _activeTunnel: TunnelSocket | null = null;

  constructor(opts: ServiceProxyClientOptions) {
    this.providerAid = String(opts.providerAid ?? '').trim();
    this.registry = opts.registry ?? new EmbeddedServiceRegistry({ endpointPolicy: opts.endpointPolicy });
    this._logger = opts.logger ?? null;
    this._aunClient = opts.aunClient ?? null;
    this._webSocketFactory = opts.webSocketFactory ?? null;
    this.maxResponseBodyBytes = Math.max(1, Math.floor(opts.maxResponseBodyBytes ?? 16 * 1024 * 1024));
    this.maxTunnelMessageBytes = Math.max(1, Math.floor(opts.maxTunnelMessageBytes ?? 64 * 1024 * 1024));
  }

  get isRunning(): boolean {
    return this._running;
  }

  get is_running(): boolean {
    return this.isRunning;
  }

  stop(): void {
    this._running = false;
    this._activeTunnel?.close();
  }

  registerService(
    serviceName: string,
    endpoint: string,
    opts: { serviceType?: string; service_type?: string; visibility?: string; metadata?: Dict | null } = {},
  ): ServiceRecord {
    return this.registry.register(serviceName, endpoint, {
      serviceType: opts.serviceType ?? opts.service_type,
      visibility: opts.visibility,
      metadata: opts.metadata,
    });
  }

  register_service(serviceName: string, endpoint: string, opts: { service_type?: string; visibility?: string; metadata?: Dict | null } = {}): ServiceRecord {
    return this.registerService(serviceName, endpoint, opts);
  }

  unregisterService(serviceName: string): boolean {
    return this.registry.unregister(serviceName);
  }

  unregister_service(serviceName: string): boolean {
    return this.unregisterService(serviceName);
  }

  listServiceSummaries(): ServiceSummary[] {
    return this.registry.listSummaries();
  }

  list_service_summaries(): ServiceSummary[] {
    return this.listServiceSummaries();
  }

  async registerServicesWithGateway(services?: ServiceSummary[]): Promise<Dict> {
    const call = this._gatewayCallMethod(true);
    const result = await call('proxy.register_services', {
      provider_aid: this.providerAid,
      services: services ?? this.listServiceSummaries(),
    });
    if (!isRecord(result)) return {};
    if (result.ok === false) throw new ValidationError(String(result.error ?? 'Gateway service registration failed'));
    return result;
  }

  register_services_with_gateway(services?: ServiceSummary[]): Promise<Dict> {
    return this.registerServicesWithGateway(services);
  }

  async unregisterServicesFromGateway(serviceNames?: string[] | string | null): Promise<Dict> {
    const call = this._gatewayCallMethod(true);
    const params: Dict = { provider_aid: this.providerAid };
    if (typeof serviceNames === 'string') params.service_names = [serviceNames];
    else if (Array.isArray(serviceNames)) params.service_names = serviceNames.map(String);
    const result = await call('proxy.unregister_services', params);
    return isRecord(result) ? result : {};
  }

  unregister_services_from_gateway(serviceNames?: string[] | string | null): Promise<Dict> {
    return this.unregisterServicesFromGateway(serviceNames);
  }

  async listGatewayServices(): Promise<Dict> {
    const call = this._gatewayCallMethod(true);
    const result = await call('proxy.list_services', { provider_aid: this.providerAid });
    return isRecord(result) ? result : {};
  }

  list_gateway_services(): Promise<Dict> {
    return this.listGatewayServices();
  }

  async discoverProxyServer(opts: { forceRefresh?: boolean; force_refresh?: boolean; timeout?: number } = {}): Promise<Dict> {
    const forceRefresh = Boolean(opts.forceRefresh ?? opts.force_refresh ?? false);
    if (!forceRefresh) {
      const cached = await this._loadCachedProxyDiscovery();
      if (cached) return cached;
    }
    const errors: string[] = [];
    for (const url of this._proxyWellKnownUrls()) {
      try {
        const discovery = await this._fetchProxyWellKnown(url, opts.timeout ?? 5);
        await this._persistProxyDiscovery(discovery);
        return discovery;
      } catch (exc) {
        errors.push(`${url}: ${formatError(exc)}`);
        this._logWarn(`Service Proxy discovery failed: url=${url} err=${formatError(exc)}`);
      }
    }
    throw new ConnectionError(`Service Proxy discovery failed: ${errors.join('; ')}`, { retryable: true });
  }

  discover_proxy_server(opts: { force_refresh?: boolean; timeout?: number } = {}): Promise<Dict> {
    return this.discoverProxyServer(opts);
  }

  async discoverProxyWsUrl(opts: { forceRefresh?: boolean; force_refresh?: boolean; timeout?: number } = {}): Promise<string> {
    const discovery = await this.discoverProxyServer(opts);
    return String(discovery.ws_url ?? '').trim();
  }

  discover_proxy_ws_url(opts: { force_refresh?: boolean; timeout?: number } = {}): Promise<string> {
    return this.discoverProxyWsUrl(opts);
  }

  async connectOnce(opts: { authRequestId?: string; registerRequestId?: string; heartbeatRequestId?: string | null } = {}): Promise<Dict> {
    this._running = true;
    try {
      await this._autoRegisterServicesWithGateway();
      const tunnel = await this._connectProxyWs();
      this._activeTunnel = tunnel;
      await tunnel.send({
        type: 'service_proxy_auth',
        request_id: opts.authRequestId ?? 'auth',
        provider_aid: this.providerAid,
        client_version: 'js',
      });
      const authResponse = parseTunnelMessage(await tunnel.recv());
      if (!authResponse.ok) {
        const err = isRecord(authResponse.error) ? authResponse.error : {};
        throw new AuthError(String(err.message ?? 'Service Proxy auth failed'));
      }
      const registered = await this.registerServicesWithProxyServer(tunnel, {
        registerRequestId: opts.registerRequestId ?? 'register-services',
      });
      let heartbeat = false;
      if (opts.heartbeatRequestId) {
        await tunnel.send({ type: 'heartbeat', request_id: opts.heartbeatRequestId });
        heartbeat = Boolean(parseTunnelMessage(await tunnel.recv()).ok);
      }
      return { registered, heartbeat };
    } finally {
      this._running = false;
      this._activeTunnel?.close();
      this._activeTunnel = null;
    }
  }

  connect_once(opts: { auth_request_id?: string; register_request_id?: string; heartbeat_request_id?: string | null } = {}): Promise<Dict> {
    return this.connectOnce({
      authRequestId: opts.auth_request_id,
      registerRequestId: opts.register_request_id,
      heartbeatRequestId: opts.heartbeat_request_id,
    });
  }

  async serveOnce(opts: { authRequestId?: string; registerRequestId?: string; maxRequests?: number } = {}): Promise<Dict> {
    this._running = true;
    try {
      await this._autoRegisterServicesWithGateway();
      const tunnel = await this._connectProxyWs();
      this._activeTunnel = tunnel;
      return await this._serveTunnel(tunnel, {
        authRequestId: opts.authRequestId ?? 'auth',
        registerRequestId: opts.registerRequestId ?? 'register-services',
        maxRequests: opts.maxRequests ?? 1,
      });
    } finally {
      this._running = false;
      this._activeTunnel?.close();
      this._activeTunnel = null;
    }
  }

  serve_once(opts: { auth_request_id?: string; register_request_id?: string; max_requests?: number } = {}): Promise<Dict> {
    return this.serveOnce({
      authRequestId: opts.auth_request_id,
      registerRequestId: opts.register_request_id,
      maxRequests: opts.max_requests,
    });
  }

  async serveForever(opts: {
    connectionMode?: 'persistent' | 'on_demand';
    authRequestId?: string;
    registerRequestId?: string;
    idleTimeoutSeconds?: number;
    reconnectDelaySeconds?: number;
  } = {}): Promise<Dict> {
    const mode = opts.connectionMode ?? 'persistent';
    if (mode !== 'persistent' && mode !== 'on_demand') {
      throw new ValidationError('connectionMode must be persistent or on_demand');
    }
    this._running = true;
    const stats: Dict = { connection_mode: mode, connections: 0, registered: 0, handled_requests: 0, wakeup_count: 0 };
    try {
      if (mode === 'persistent') {
        while (this._running) {
          try {
            await this._autoRegisterServicesWithGateway();
            const tunnel = await this._connectProxyWs();
            this._activeTunnel = tunnel;
            const result = await this._serveTunnel(tunnel, {
              authRequestId: opts.authRequestId ?? 'auth',
              registerRequestId: opts.registerRequestId ?? 'register-services',
            });
            stats.connections = Number(stats.connections) + 1;
            stats.registered = Number(result.registered ?? stats.registered);
            stats.handled_requests = Number(stats.handled_requests) + Number(result.handled_requests ?? 0);
          } catch (exc) {
            if (!this._running) break;
            this._logWarn(`persistent tunnel reconnect scheduled after error: ${formatError(exc)}`);
            await sleep(Math.max(0, opts.reconnectDelaySeconds ?? 1) * 1000);
          } finally {
            this._activeTunnel?.close();
            this._activeTunnel = null;
          }
        }
        return stats;
      }
      return await this._serveOnDemand(stats, opts);
    } finally {
      this._running = false;
      this._activeTunnel?.close();
      this._activeTunnel = null;
    }
  }

  serve_forever(opts: {
    connection_mode?: 'persistent' | 'on_demand';
    auth_request_id?: string;
    register_request_id?: string;
    idle_timeout_seconds?: number;
    reconnect_delay_seconds?: number;
  } = {}): Promise<Dict> {
    return this.serveForever({
      connectionMode: opts.connection_mode,
      authRequestId: opts.auth_request_id,
      registerRequestId: opts.register_request_id,
      idleTimeoutSeconds: opts.idle_timeout_seconds,
      reconnectDelaySeconds: opts.reconnect_delay_seconds,
    });
  }

  async registerServicesWithProxyServer(
    tunnel: TunnelSocket,
    opts: { registerRequestId?: string; services?: ServiceSummary[] } = {},
  ): Promise<number> {
    const services = opts.services ?? this.listServiceSummaries();
    await tunnel.send({ type: 'register_services', request_id: opts.registerRequestId ?? 'register-services', services });
    const response = parseTunnelMessage(await tunnel.recv());
    if (!response.ok) throw new ValidationError('Service Proxy service registration failed');
    return Number(response.count ?? services.length);
  }

  register_services_with_proxy_server(tunnel: TunnelSocket, opts: { register_request_id?: string; services?: ServiceSummary[] } = {}): Promise<number> {
    return this.registerServicesWithProxyServer(tunnel, { registerRequestId: opts.register_request_id, services: opts.services });
  }

  async *iterRequestMessages(
    message: Dict,
    opts: { chunkSize?: number; bodyIter?: AsyncIterable<Uint8Array> } = {},
  ): AsyncGenerator<Dict> {
    const requestId = String(message.request_id ?? '');
    const serviceName = String(message.service_name ?? '');
    let record: ServiceRecord | null = null;
    try { record = this.registry.get(serviceName); } catch { record = null; }
    if (!record) {
      yield errorMessage(requestId, 'service_not_registered', 'service is not registered');
      return;
    }

    const method = String(message.method ?? 'GET').toUpperCase();
    const path = normalizePath(String(message.path ?? '/'));
    const targetUrl = buildTargetUrl(record.endpoint, path, String(message.query_string ?? ''));
    const bodyStream = message.body_stream === true;
    let body: BodyInit | ReadableStream<Uint8Array> | undefined;
    if (bodyStream) {
      if (!opts.bodyIter) {
        yield errorMessage(requestId, 'missing_body_stream', 'request body stream is missing');
        return;
      }
      body = readableStreamFromAsyncIterable(opts.bodyIter);
    } else if (message.body_base64) {
      try { body = toExactArrayBuffer(decodeBase64Strict(String(message.body_base64))); } catch {
        yield errorMessage(requestId, 'invalid_body', 'body_base64 is invalid');
        return;
      }
    }
    const headers = backendHeaders(isRecord(message.headers) ? message.headers : {});
    let response: Response;
    try {
      const init: RequestInit = { method, headers };
      if (method !== 'GET' && method !== 'HEAD') {
        init.body = body as BodyInit;
        if (bodyStream) (init as Dict).duplex = 'half';
      }
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 30_000);
      try {
        response = await fetch(targetUrl, { ...init, signal: controller.signal });
      } finally {
        clearTimeout(timer);
      }
    } catch (exc) {
      this._logWarn(`backend request failed: request_id=${requestId} service_name=${serviceName} err=${formatError(exc)}`);
      yield errorMessage(requestId, 'backend_unreachable', 'backend request failed');
      return;
    }

    const responseHeaders = responseHeadersMap(response.headers);
    const detection = detectRequestProtocol(message, record);
    const shouldStream = detection.isStream || (detection.streamMode !== 'no_stream' && isStreamResponseHeaders(responseHeaders));
    if (!shouldStream) {
      try {
        const bytes = new Uint8Array(await response.arrayBuffer());
        if (bytes.length > this.maxResponseBodyBytes) throw new Error('too large');
        yield {
          type: 'service_proxy_response',
          request_id: requestId,
          status: response.status,
          headers: responseHeaders,
          body_base64: encodeBase64(bytes),
        };
      } catch {
        yield errorMessage(requestId, 'response_body_too_large', 'backend response body is too large');
      }
      return;
    }

    const streamType = streamTypeFromResponse(responseHeaders, detection.serviceType);
    if (!responseHeaders['x-stream-type']) responseHeaders['x-stream-type'] = streamType;
    const chunkSize = Math.max(1, Math.floor(opts.chunkSize ?? 65536));
    let index = 0;
    let pending: Uint8Array | null = null;
    for await (const chunk of responseChunks(response, chunkSize)) {
      if (pending) {
        yield streamMessage(requestId, index, response.status, responseHeaders, pending, false);
        index += 1;
      }
      pending = chunk;
    }
    if (pending) {
      yield streamMessage(requestId, index, response.status, responseHeaders, pending, true);
    } else if (index === 0) {
      yield { type: 'service_proxy_stream', request_id: requestId, index: 0, status: response.status, headers: responseHeaders, data_base64: '', done: true };
    }
  }

  async handleWsConnectMessage(message: Dict, tunnel: TunnelSocket, inboundQueue: AsyncQueue<Dict>): Promise<void> {
    const connectionId = String(message.connection_id ?? '');
    const serviceName = String(message.service_name ?? '');
    let record: ServiceRecord | null = null;
    try { record = this.registry.get(serviceName); } catch { record = null; }
    if (!record) {
      await tunnel.send(wsErrorMessage(connectionId, 'service_not_registered', 'service is not registered'));
      return;
    }
    const protocols = Array.isArray(message.subprotocols)
      ? message.subprotocols.map(String).map((item) => item.trim()).filter(Boolean)
      : [];
    let backend: WebSocketLike;
    try {
      backend = this._createWebSocket(
        buildTargetUrl(record.endpoint, normalizePath(String(message.path ?? '/')), String(message.query_string ?? '')),
        protocols,
        { headers: backendHeaders(isRecord(message.headers) ? message.headers : {}), verifySsl: this._shouldVerifySsl() },
        false,
      );
      await waitForWsOpen(backend);
      await tunnel.send({ type: 'ws_connected', connection_id: connectionId, subprotocol: backend.protocol || '' });
    } catch (exc) {
      this._logWarn(`backend websocket bridge failed: connection_id=${connectionId} err=${formatError(exc)}`);
      await tunnel.send(wsErrorMessage(connectionId, 'backend_ws_unreachable', 'backend websocket request failed'));
      return;
    }

    backend.binaryType = 'arraybuffer';
    const backendClosed = new Promise<void>((resolve) => {
      backend.addEventListener('message', (event) => {
        const data = event.data;
        if (typeof data === 'string') {
          tunnel.send({ type: 'ws_message', connection_id: connectionId, text: data }).catch(() => {});
        } else {
          bytesFromWsData(data).then((bytes) => {
            tunnel.send({ type: 'ws_message', connection_id: connectionId, data_base64: encodeBase64(bytes) }).catch(() => {});
          }).catch(() => {});
        }
      });
      backend.addEventListener('close', (event) => {
        tunnel.send({ type: 'ws_close', connection_id: connectionId, code: event.code || 1000, reason: '' }).catch(() => {});
        resolve();
      });
      backend.addEventListener('error', () => resolve());
    });

    const tunnelToBackend = (async (): Promise<void> => {
      while (this._running) {
        const item = await inboundQueue.shift();
        if (!item) return;
        const msgType = String(item.type ?? '');
        if (msgType === 'ws_message') {
          if (item.text !== undefined && item.text !== null) {
            backend.send(String(item.text));
          } else if (item.data_base64 !== undefined) {
            try { backend.send(decodeBase64Strict(String(item.data_base64 ?? ''))); } catch {
              await tunnel.send(wsErrorMessage(connectionId, 'invalid_ws_frame', 'data_base64 is invalid'));
              backend.close();
              return;
            }
          }
        } else if (msgType === 'ws_close' || msgType === 'ws_error') {
          backend.close(Number(item.code ?? 1000), String(item.reason ?? ''));
          return;
        }
      }
    })();
    await Promise.race([backendClosed, tunnelToBackend]);
    try { backend.close(); } catch { /* noop */ }
  }

  private async _serveOnDemand(stats: Dict, opts: { authRequestId?: string; registerRequestId?: string; idleTimeoutSeconds?: number; reconnectDelaySeconds?: number }): Promise<Dict> {
    const client = this._aunClient as { on?: (event: string, handler: (payload: unknown) => void) => { unsubscribe?: () => void } };
    if (!client || typeof client.on !== 'function') throw new ValidationError('on_demand mode requires aunClient with on()');
    await this._autoRegisterServicesWithGateway();
    const queue = new AsyncQueue<Dict>();
    const subscription = client.on('app.service_proxy.wakeup', (payload: unknown) => {
      if (!isRecord(payload)) return;
      if (String(payload.type ?? '') !== 'aun.service_proxy.wakeup') return;
      const providerAid = String(payload.provider_aid ?? '').trim();
      if (providerAid && providerAid !== this.providerAid) return;
      queue.push({ ...payload });
    });
    try {
      while (this._running) {
        const wakeup = await queue.shift(100);
        if (!this._running) break;
        if (!wakeup) continue;
        stats.wakeup_count = Number(stats.wakeup_count) + 1;
        try {
          await this._autoRegisterServicesWithGateway();
          const tunnel = await this._connectProxyWs();
          this._activeTunnel = tunnel;
          const result = await this._serveTunnel(tunnel, {
            authRequestId: opts.authRequestId ?? 'auth',
            registerRequestId: opts.registerRequestId ?? 'register-services',
            idleTimeoutSeconds: opts.idleTimeoutSeconds ?? 60,
          });
          stats.connections = Number(stats.connections) + 1;
          stats.registered = Number(result.registered ?? stats.registered);
          stats.handled_requests = Number(stats.handled_requests) + Number(result.handled_requests ?? 0);
        } catch (exc) {
          if (!this._running) break;
          this._logWarn(`on-demand tunnel connection failed after wakeup: ${formatError(exc)}`);
          await sleep(Math.max(0, opts.reconnectDelaySeconds ?? 1) * 1000);
        } finally {
          this._activeTunnel?.close();
          this._activeTunnel = null;
        }
      }
      return stats;
    } finally {
      subscription?.unsubscribe?.();
      queue.close();
    }
  }

  private async _serveTunnel(tunnel: TunnelSocket, opts: { authRequestId: string; registerRequestId: string; maxRequests?: number; idleTimeoutSeconds?: number }): Promise<Dict> {
    let handledRequests = 0;
    const activeWsQueues = new Map<string, AsyncQueue<Dict>>();
    const registered = await this._authAndRegister(tunnel, opts.authRequestId, opts.registerRequestId);
    try {
      while (this._running) {
        if (opts.maxRequests !== undefined && handledRequests >= opts.maxRequests && activeWsQueues.size === 0) break;
        const waitForWsTasks = opts.maxRequests !== undefined && handledRequests >= opts.maxRequests && activeWsQueues.size > 0;
        const timeoutMs = waitForWsTasks
          ? 50
          : opts.idleTimeoutSeconds === undefined
            ? undefined
            : opts.idleTimeoutSeconds * 1000;
        const raw = await tunnel.recv(timeoutMs);
        if (raw === null) {
          if (timeoutMs !== undefined && activeWsQueues.size > 0) continue;
          break;
        }
        let message: Dict;
        try {
          const parsed = JSON.parse(raw) as unknown;
          if (!isRecord(parsed)) continue;
          message = parsed;
        } catch { continue; }
        const msgType = String(message.type ?? '');
        if (msgType === 'service_proxy_request') {
          const requestId = String(message.request_id ?? '');
          const bodyIter = message.body_stream === true ? this._iterRequestBodyChunks(tunnel, requestId, activeWsQueues) : undefined;
          for await (const response of this.iterRequestMessages(message, { bodyIter })) await tunnel.send(response);
          handledRequests += 1;
        } else if (msgType === 'ws_connect') {
          const connectionId = String(message.connection_id ?? '');
          if (!connectionId) {
            await tunnel.send(wsErrorMessage('', 'missing_connection_id', 'connection_id is required'));
            continue;
          }
          const queue = new AsyncQueue<Dict>();
          activeWsQueues.set(connectionId, queue);
          this.handleWsConnectMessage(message, tunnel, queue).finally(() => {
            queue.close();
            activeWsQueues.delete(connectionId);
          });
          handledRequests += 1;
        } else if (msgType === 'ws_message' || msgType === 'ws_close' || msgType === 'ws_error') {
          const connectionId = String(message.connection_id ?? '');
          const queue = activeWsQueues.get(connectionId);
          if (queue) queue.push(message);
          else if (connectionId) await tunnel.send(wsErrorMessage(connectionId, 'unknown_ws_connection', 'WebSocket connection is not active'));
        } else if (msgType !== 'heartbeat_ack') {
          await tunnel.send(errorMessage(String(message.request_id ?? ''), 'unsupported_message', 'unsupported Service Proxy tunnel message'));
        }
      }
      return { registered, handled_requests: handledRequests };
    } finally {
      for (const queue of activeWsQueues.values()) queue.close();
    }
  }

  private async _authAndRegister(tunnel: TunnelSocket, authRequestId: string, registerRequestId: string): Promise<number> {
    await tunnel.send({ type: 'service_proxy_auth', request_id: authRequestId, provider_aid: this.providerAid, client_version: 'js' });
    const authResponse = parseTunnelMessage(await tunnel.recv());
    if (!authResponse.ok) {
      const err = isRecord(authResponse.error) ? authResponse.error : {};
      throw new AuthError(String(err.message ?? 'Service Proxy auth failed'));
    }
    return this.registerServicesWithProxyServer(tunnel, { registerRequestId });
  }

  private async *_iterRequestBodyChunks(tunnel: TunnelSocket, requestId: string, activeWsQueues: Map<string, AsyncQueue<Dict>>): AsyncGenerator<Uint8Array> {
    while (true) {
      const message = parseTunnelMessage(await tunnel.recv());
      const msgType = String(message.type ?? '');
      if (msgType === 'ws_message' || msgType === 'ws_close' || msgType === 'ws_error') {
        const queue = activeWsQueues.get(String(message.connection_id ?? ''));
        if (queue) {
          queue.push(message);
          continue;
        }
      }
      if (msgType !== 'service_proxy_request_body') throw new Error('invalid_body_stream');
      if (String(message.request_id ?? '') !== requestId) throw new Error('request body stream request_id mismatch');
      if (isRecord(message.error)) throw new Error(String(message.error.message ?? 'request body stream failed'));
      const dataText = String(message.data_base64 ?? '');
      if (dataText) yield decodeBase64Strict(dataText);
      if (message.done === true) return;
    }
  }

  private _createWebSocket(url: string, protocols: string | string[] | undefined, options: WebSocketFactoryOptions, requireHeaders: boolean): WebSocketLike {
    if (this._webSocketFactory) return this._webSocketFactory(url, protocols, options);
    if (requireHeaders && options.headers && Object.keys(options.headers).length > 0) {
      throw new AuthError('Browser WebSocket cannot set Authorization header; pass webSocketFactory to ServiceProxyClient');
    }
    return new WebSocket(url, protocols) as WebSocketLike;
  }

  private async _connectProxyWs(): Promise<TunnelSocket> {
    const proxyUrl = await this.discoverProxyWsUrl();
    const token = await this._ensureAccessToken();
    if (!token) throw new AuthError('AUN access_token is required for Service Proxy tunnel');
    const ws = this._createWebSocket(
      proxyUrl,
      undefined,
      {
        headers: { Authorization: `Bearer ${token}` },
        maxPayloadBytes: this.maxTunnelMessageBytes,
        verifySsl: this._shouldVerifySsl(),
      },
      true,
    );
    await waitForWsOpen(ws);
    return new TunnelSocket(ws);
  }

  private _gatewayCallMethod(required: boolean): (method: string, params?: Dict) => Promise<unknown> {
    const call = (this._aunClient as { call?: unknown } | null)?.call;
    if (typeof call === 'function') return (method, params) => Promise.resolve(call.call(this._aunClient, method, params ?? {}));
    if (required) throw new ValidationError('Gateway service registration requires aunClient with call()');
    return async () => ({ skipped: true });
  }

  private async _autoRegisterServicesWithGateway(): Promise<Dict> {
    const call = (this._aunClient as { call?: unknown } | null)?.call;
    if (typeof call !== 'function') return { skipped: true };
    return this.registerServicesWithGateway();
  }

  private _issuerDomainForAid(aid: string): string {
    const target = String(aid ?? '').trim().toLowerCase();
    if (!target.includes('.')) return '';
    return target.split('.').slice(1).join('.').replace(/^\.+|\.+$/g, '');
  }

  private _proxyWellKnownUrls(): string[] {
    const issuer = this._issuerDomainForAid(this.providerAid);
    if (!this.providerAid || !issuer) throw new ValidationError('providerAid must be a full AID for Service Proxy discovery');
    return [`https://${this.providerAid}/.well-known/aun-proxy`, `https://proxy.${issuer}/.well-known/aun-proxy`];
  }

  private _normalizeProxyWsUrl(rawUrl: string): string {
    const value = String(rawUrl ?? '').trim();
    if (!value) return '';
    let parsed: URL;
    try { parsed = new URL(value); } catch { return ''; }
    if (parsed.protocol === 'ws:' && this._shouldVerifySsl()) return '';
    if (parsed.protocol !== 'wss:' && parsed.protocol !== 'ws:') return '';
    if (parsed.username || parsed.password || !parsed.hostname || parsed.pathname === '/') return '';
    parsed.hash = '';
    return parsed.toString();
  }

  private _selectProxyWsUrl(payload: Dict): string {
    const direct = this._normalizeProxyWsUrl(String(payload.ws_url ?? ''));
    if (direct) return direct;
    const servers = Array.isArray(payload.proxy_servers) ? payload.proxy_servers.filter(isRecord) : [];
    servers.sort((a, b) => Number(a.priority ?? 999) - Number(b.priority ?? 999));
    for (const item of servers) {
      const url = this._normalizeProxyWsUrl(String(item.ws_url ?? ''));
      if (url) return url;
    }
    return '';
  }

  private async _fetchProxyWellKnown(wellKnownUrl: string, timeoutSeconds: number): Promise<Dict> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(100, timeoutSeconds * 1000));
    try {
      const response = await fetch(wellKnownUrl, { signal: controller.signal });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = await response.json() as unknown;
      if (!isRecord(payload)) throw new ValidationError('Service Proxy well-known returned invalid payload');
      const wsUrl = this._selectProxyWsUrl(payload);
      if (!wsUrl) throw new ValidationError('Service Proxy well-known missing valid ws_url');
      return { ...payload, ws_url: wsUrl, source_url: wellKnownUrl, discovered_at: Date.now() / 1000 };
    } finally {
      clearTimeout(timer);
    }
  }

  private async _loadCachedProxyDiscovery(): Promise<Dict | null> {
    const tokenStore = (this._aunClient as { _tokenStore?: unknown } | null)?._tokenStore as
      | { getMetadata?: (aid: string, key: string) => Promise<string>; loadMetadata?: (aid: string) => Promise<Dict | null> }
      | undefined;
    if (!tokenStore) return null;
    try {
      let raw: unknown = '';
      if (typeof tokenStore.getMetadata === 'function') raw = await tokenStore.getMetadata(this.providerAid, PROXY_DISCOVERY_CACHE_KEY);
      else if (typeof tokenStore.loadMetadata === 'function') raw = (await tokenStore.loadMetadata(this.providerAid))?.[PROXY_DISCOVERY_CACHE_KEY];
      const cached = typeof raw === 'string' ? JSON.parse(raw) as unknown : raw;
      if (!isRecord(cached)) return null;
      const wsUrl = this._normalizeProxyWsUrl(String(cached.ws_url ?? ''));
      if (!wsUrl) return null;
      const discoveredAt = Number(cached.discovered_at ?? 0);
      if (!Number.isFinite(discoveredAt) || Date.now() - discoveredAt * 1000 >= PROXY_DISCOVERY_CACHE_TTL_MS) return null;
      return { ...cached, ws_url: wsUrl, cached: true };
    } catch { return null; }
  }

  private async _persistProxyDiscovery(discovery: Dict): Promise<void> {
    const tokenStore = (this._aunClient as { _tokenStore?: unknown } | null)?._tokenStore as
      | { setMetadata?: (aid: string, key: string, value: string) => Promise<void> }
      | undefined;
    if (!tokenStore || typeof tokenStore.setMetadata !== 'function' || !this.providerAid) return;
    try {
      await tokenStore.setMetadata(this.providerAid, PROXY_DISCOVERY_CACHE_KEY, JSON.stringify(discovery));
    } catch (exc) {
      this._logWarn(`Service Proxy discovery cache write failed: ${formatError(exc)}`);
    }
  }

  private _shouldVerifySsl(): boolean {
    const client = this._aunClient as { configModel?: Dict; _configModel?: Dict; currentAid?: Dict; _currentAid?: Dict } | null;
    const cfg = client?.configModel ?? client?._configModel;
    if (cfg && (typeof cfg.verifySsl === 'boolean' || typeof cfg.verify_ssl === 'boolean')) return Boolean(cfg.verifySsl ?? cfg.verify_ssl);
    const aid = client?.currentAid ?? client?._currentAid;
    if (aid && (typeof aid.verifySsl === 'boolean' || typeof aid.verify_ssl === 'boolean')) return Boolean(aid.verifySsl ?? aid.verify_ssl);
    return true;
  }

  private _mappingAccessToken(mapping: Dict | null | undefined): string {
    if (!mapping) return '';
    const token = String(mapping.access_token ?? mapping.token ?? mapping.kite_token ?? '').trim();
    if (!token) return '';
    const expiresAt = Number(mapping.access_token_expires_at ?? mapping.expires_at ?? 0);
    if (Number.isFinite(expiresAt) && expiresAt > 0 && expiresAt <= Date.now() / 1000 + TOKEN_EXPIRY_SKEW_SECONDS) return '';
    return token;
  }

  private async _resolveCachedAccessToken(): Promise<string> {
    const client = this._aunClient as Dict | null;
    if (!client) return '';
    const direct = this._mappingAccessToken(client);
    if (direct) return direct;
    if (isRecord(client._identity)) {
      const token = this._mappingAccessToken(client._identity);
      if (token) return token;
    }
    const auth = client._auth as { loadIdentityOrNone?: (aid?: string) => Promise<Dict | null> } | undefined;
    if (auth && typeof auth.loadIdentityOrNone === 'function') {
      try {
        const token = this._mappingAccessToken(await auth.loadIdentityOrNone(this.providerAid));
        if (token) return token;
      } catch { /* noop */ }
    }
    const tokenStore = client._tokenStore as { loadInstanceState?: (aid: string, deviceId: string, slotId?: string) => Promise<Dict | null> } | undefined;
    if (tokenStore && typeof tokenStore.loadInstanceState === 'function') {
      try {
        const deviceId = String(client.deviceId ?? client.device_id ?? client._deviceId ?? client._device_id ?? '');
        const slotId = String(client.slotId ?? client.slot_id ?? client._slotId ?? client._slot_id ?? '');
        const token = this._mappingAccessToken(await tokenStore.loadInstanceState(this.providerAid, deviceId, slotId));
        if (token) return token;
      } catch { /* noop */ }
    }
    return '';
  }

  private async _authenticateForAccessToken(): Promise<string> {
    const authenticate = (this._aunClient as { authenticate?: unknown } | null)?.authenticate;
    if (typeof authenticate !== 'function') throw new AuthError('Service Proxy tunnel requires aunClient.authenticate() for AUN token authentication');
    let result: unknown;
    try { result = await authenticate.call(this._aunClient); } catch (exc) {
      throw new AuthError(`AUNClient authenticate failed for Service Proxy tunnel: ${formatError(exc)}`);
    }
    const token = this._mappingAccessToken(isRecord(result) ? result : null);
    if (token) return token;
    throw new AuthError('AUNClient authenticate did not return a valid access_token');
  }

  private async _ensureAccessToken(): Promise<string> {
    return await this._resolveCachedAccessToken() || await this._authenticateForAccessToken();
  }

  private _logWarn(message: string): void {
    try { this._logger?.warn(message); } catch { /* noop */ }
  }
}

function normalizeServiceName(serviceName: string): string {
  const value = String(serviceName ?? '').trim();
  if (!value) throw new ValidationError('service_name is required');
  if (RESERVED_SERVICE_NAMES.has(value)) throw new ValidationError('service_name is reserved');
  if (!SERVICE_NAME_RE.test(value)) throw new ValidationError('service_name must match [a-z0-9_-]+');
  return value;
}

function normalizeHost(host: string): string {
  return String(host ?? '').trim().toLowerCase().replace(/\.+$/g, '');
}

function isIPv4LoopbackHost(host: string): boolean {
  const parts = host.split('.');
  if (parts.length !== 4 || parts[0] !== '127') return false;
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function isRecord(value: unknown): value is Dict {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isSensitiveMetadataKey(key: string): boolean {
  const normalized = key.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  return SENSITIVE_METADATA_KEYS.has(normalized) || /(_token|_secret|_password|_private_key)$/.test(normalized);
}

function sanitizeMetadata(metadata: Dict): Dict {
  const out: Dict = {};
  for (const [key, value] of Object.entries(metadata ?? {})) {
    if (isSensitiveMetadataKey(key)) continue;
    if (isRecord(value)) out[key] = sanitizeMetadata(value);
    else if (Array.isArray(value)) out[key] = value.map((item) => isRecord(item) ? sanitizeMetadata(item) : item);
    else out[key] = value;
  }
  return out;
}

function headersMap(headers: unknown): Record<string, string> {
  const result: Record<string, string> = {};
  if (!isRecord(headers)) return result;
  for (const [key, value] of Object.entries(headers)) result[key.toLowerCase()] = String(value);
  return result;
}

function streamModeFrom(headers: Record<string, string>, record: ServiceRecord, message: Dict): string {
  let value = String(message.stream_mode ?? '').trim().toLowerCase();
  if (!value) value = String(headers['x-stream-mode'] ?? '').trim().toLowerCase();
  if (!value) value = String(record.metadata.stream_mode ?? '').trim().toLowerCase();
  if (value === 'always') return 'stream';
  return VALID_STREAM_MODES.has(value) ? value : 'auto';
}

function detectRequestProtocol(message: Dict, record: ServiceRecord): ProtocolDetection {
  const headers = headersMap(isRecord(message.headers) ? message.headers : {});
  const streamMode = streamModeFrom(headers, record, message);
  let serviceType = String(message.service_type ?? '').trim().toLowerCase() || record.service_type.toLowerCase() || 'http';
  if (streamMode === 'no_stream') {
    serviceType = 'http';
  } else if (!message.service_type) {
    const explicitType = String(headers['x-service-type'] ?? '').trim().toLowerCase();
    const method = String(message.method ?? '').toUpperCase();
    const path = String(message.path ?? '').toLowerCase();
    const accept = String(headers.accept ?? '').toLowerCase();
    const contentType = String(headers['content-type'] ?? '').toLowerCase();
    if (explicitType) serviceType = explicitType;
    else if (accept.includes('text/event-stream')) serviceType = 'sse';
    else if ('mcp-session-id' in headers) serviceType = 'mcp';
    else if (method === 'POST' && bodyHasJsonRpc(message)) serviceType = 'mcp';
    else if (contentType.startsWith('application/grpc')) serviceType = 'ws';
    else if (path.includes('/mcp')) serviceType = 'mcp';
    else if (path.includes('/sse') || path.includes('/events')) serviceType = 'sse';
    else if (path.includes('/download') || path.includes('/files/')) serviceType = 'file';
  }
  let isStream: boolean;
  if (streamMode === 'stream') isStream = true;
  else if (streamMode === 'no_stream') isStream = false;
  else if ('is_stream' in message) isStream = Boolean(message.is_stream);
  else if ('stream' in message) isStream = Boolean(message.stream);
  else isStream = STREAMING_SERVICE_TYPES.has(serviceType);
  return { serviceType, streamMode, isStream };
}

function bodyHasJsonRpc(message: Dict): boolean {
  const raw = String(message.body_base64 ?? '');
  if (!raw) return false;
  let text = '';
  try { text = new TextDecoder().decode(decodeBase64Strict(raw)); } catch { return false; }
  if (text.includes('"jsonrpc"') || text.includes("'jsonrpc'")) return true;
  try {
    const parsed = JSON.parse(text) as unknown;
    if (isRecord(parsed)) return String(parsed.jsonrpc ?? '') === '2.0';
    if (Array.isArray(parsed)) return parsed.some((item) => isRecord(item) && String(item.jsonrpc ?? '') === '2.0');
  } catch { /* noop */ }
  return false;
}

function backendHeaders(headers: Dict): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    const name = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(name) || name === 'host') continue;
    result[name] = String(value);
  }
  return result;
}

function responseHeadersMap(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    const name = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(name) || AUTO_RESPONSE_HEADERS.has(name)) return;
    result[name] = value;
  });
  return result;
}

function isStreamResponseHeaders(headers: Record<string, string>): boolean {
  const contentType = String(headers['content-type'] ?? '').split(';', 1)[0].trim().toLowerCase();
  const contentDisposition = String(headers['content-disposition'] ?? '').toLowerCase();
  if (String(headers['content-type'] ?? '').toLowerCase().includes('text/event-stream')) return true;
  if (FILE_CONTENT_TYPES.has(contentType)) return true;
  if (contentType.startsWith('image/') || contentType.startsWith('video/')) return true;
  return contentDisposition.includes('attachment');
}

function streamTypeFromResponse(headers: Record<string, string>, fallback: string): string {
  const contentType = String(headers['content-type'] ?? '').toLowerCase();
  if (contentType.includes('text/event-stream')) return 'sse';
  if (isStreamResponseHeaders(headers)) return 'file';
  return String(fallback || 'stream').trim().toLowerCase() || 'stream';
}

function normalizePath(path: string): string {
  const text = String(path || '/');
  return text.startsWith('/') ? text : `/${text}`;
}

function buildTargetUrl(endpoint: string, path: string, queryString: string): string {
  const base = endpoint.replace(/\/+$/g, '') + '/';
  const url = new URL(path.replace(/^\/+/g, ''), base);
  if (queryString) url.search = queryString.startsWith('?') ? queryString : `?${queryString}`;
  return url.toString();
}

function errorMessage(requestId: string, code: string, message: string): Dict {
  return { type: 'service_proxy_error', request_id: requestId, error: { code, message } };
}

function wsErrorMessage(connectionId: string, code: string, message: string): Dict {
  return { type: 'ws_error', connection_id: connectionId, error: { code, message } };
}

function streamMessage(requestId: string, index: number, status: number, headers: Record<string, string>, data: Uint8Array, done: boolean): Dict {
  return { type: 'service_proxy_stream', request_id: requestId, index, status: index === 0 ? status : null, headers: index === 0 ? headers : {}, data_base64: encodeBase64(data), done };
}

function parseTunnelMessage(raw: string | null): Dict {
  if (raw === null) throw new ConnectionError('Service Proxy tunnel closed');
  const parsed = JSON.parse(raw) as unknown;
  return isRecord(parsed) ? parsed : {};
}

function waitForWsOpen(ws: WebSocketLike): Promise<void> {
  return new Promise((resolve, reject) => {
    const cleanup = (): void => {
      ws.removeEventListener('open', onOpen);
      ws.removeEventListener('error', onError);
    };
    const onOpen = (_event: Event): void => { cleanup(); resolve(); };
    const onError = (_event: Event): void => { cleanup(); reject(new ConnectionError('websocket connect failed')); };
    ws.addEventListener('open', onOpen);
    ws.addEventListener('error', onError);
  });
}

async function* responseChunks(response: Response, chunkSize: number): AsyncGenerator<Uint8Array> {
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    for (let offset = 0; offset < bytes.length; offset += chunkSize) yield bytes.slice(offset, offset + chunkSize);
    return;
  }
  const reader = response.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) return;
      if (!value) continue;
      for (let offset = 0; offset < value.length; offset += chunkSize) yield value.slice(offset, offset + chunkSize);
    }
  } finally {
    reader.releaseLock();
  }
}

function readableStreamFromAsyncIterable(iterable: AsyncIterable<Uint8Array>): ReadableStream<Uint8Array> {
  const iterator = iterable[Symbol.asyncIterator]();
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      const { done, value } = await iterator.next();
      if (done) controller.close();
      else controller.enqueue(value);
    },
    async cancel() {
      await iterator.return?.();
    },
  });
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function encodeBase64(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  if (i < bytes.length) {
    const a = bytes[i]!;
    const b = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const n = (a << 16) | (b << 8);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + (i + 1 < bytes.length ? B64[(n >> 6) & 63] : '=') + '=';
  }
  return out;
}

function decodeBase64Strict(value: string): Uint8Array {
  const text = String(value ?? '').trim();
  if (!text) return new Uint8Array();
  if (text.length % 4 === 1 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) throw new Error('invalid base64');
  const clean = text.replace(/=+$/g, '');
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of clean) {
    const v = B64.indexOf(ch);
    if (v < 0) throw new Error('invalid base64');
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

function toExactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function bytesFromWsData(data: unknown): Promise<Uint8Array> {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (data instanceof Blob) return new Uint8Array(await data.arrayBuffer());
  return new TextEncoder().encode(String(data ?? ''));
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
