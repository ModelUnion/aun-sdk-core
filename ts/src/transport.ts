/**
 * RPC 传输层
 *
 * 基于 WebSocket（ws 包）的 JSON-RPC 2.0 传输层。
 * 与 Python SDK 的 RPCTransport 完全对齐：
 * - connect → 接收初始 challenge
 * - call → 请求/响应匹配
 * - 事件路由 → EventDispatcher
 */

import WebSocket from 'ws';
import * as crypto from 'node:crypto';

import { ConnectionError, SerializationError, TimeoutError, ValidationError, mapRemoteError } from './errors.js';
import type { EventDispatcher } from './events.js';
import type { ModuleLogger } from './logger.js';
import { isJsonObject, type JsonObject, type JsonValue, type RpcMessage, type RpcParams, type RpcResult } from './types.js';

const MAX_WS_PAYLOAD_SIZE = 1_000_000;
const MAX_RPC_INFLIGHT = 16;
const MAX_BACKGROUND_RPC_INFLIGHT = 8;

type PendingRpc = {
  resolve: (value: RpcMessage) => void;
  reject: (reason: Error) => void;
  timer: ReturnType<typeof setTimeout>;
};

type QueuedRpc = {
  rpcId: string;
  method: string;
  payload: string;
  pending: PendingRpc;
  tStart: number;
  timeoutMs: number;
  background: boolean;
};

type PendingRpcMeta = {
  method: string;
  queuedAt: number;
  pendingSince: number;
  deadlineAt: number;
  background: boolean;
};

const _noopLogger: ModuleLogger = {
  error: () => {},
  warn:  () => {},
  info:  () => {},
  debug: () => {},
};

// ── Trace 树状展示 ─────────────────────────────────────────────

const TRACE_SPAN_DETAIL_FIELDS = [
  'method', 'route', 'namespace', 'instance_id', 'aid', 'caller_aid',
  'peer_aid', 'to_aid', 'from_aid', 'group_id', 'message_id', 'event',
  'status', 'error_code', 'error_msg', 'found', 'delivered_count',
  'success', 'created', 'connection_id', 'device_id', 'slot_id',
  'key_source', 'spk_id', 'curve', 'lifecycle_state', 'auth_method',
] as const;

/** 按因果顺序排序 trace spans（不依赖绝对 ts，避免跨进程时钟偏差） */
function sortTraceSpansForDisplay(spans: Record<string, unknown>[]): Record<string, unknown>[] {
  const indexed = spans
    .map((span, idx) => ({ idx, span }))
    .filter(({ span }) => span !== null && typeof span === 'object');

  indexed.sort((a, b) => {
    const stageA = _spanStage(a.span);
    const stageB = _spanStage(b.span);
    if (stageA !== stageB) return stageA - stageB;
    return a.idx - b.idx;
  });

  return indexed.map(({ span }) => span);
}

function _spanStage(span: Record<string, unknown>): number {
  const node = String(span.node ?? '');
  const action = String(span.action ?? 'process');
  if (node === 'sdk' && action === 'send') return 0;
  if (node === 'gateway' && (action === 'relay_in' || action === 'enter')) return 10;
  if (node === 'gateway' && (action === 'relay_out' || action === 'exit')) return 90;
  if (node === 'sdk' && action === 'recv') return 100;
  return 50;
}

/** 生成单调逻辑时间偏移（以 sdk.send 为 0 点，sdk.recv 为总耗时） */
function traceLogicalOffsets(spans: Record<string, unknown>[]): number[] {
  let totalMs: number | null = null;
  for (const span of spans) {
    if (span.node === 'sdk' && span.action === 'recv') {
      const ms = span.ms;
      if (typeof ms === 'number' && ms >= 0) {
        totalMs = Math.round(ms);
        break;
      }
    }
  }

  const serverTs: number[] = [];
  for (const span of spans) {
    if (span.node !== 'sdk' && typeof span.ts === 'number' && span.ts > 0) {
      serverTs.push(Math.round(span.ts as number));
    }
  }
  const serverMin = serverTs.length > 0 ? Math.min(...serverTs) : null;
  const serverMax = serverTs.length > 0 ? Math.max(...serverTs) : null;
  const serverDur = (serverMin !== null && serverMax !== null) ? serverMax - serverMin : 0;

  let serverBase: number;
  let serverScale: number;
  if (totalMs !== null && serverMin !== null) {
    if (serverDur > totalMs && serverDur > 0) {
      serverBase = 0;
      serverScale = totalMs / serverDur;
    } else {
      serverBase = Math.max(0, totalMs - serverDur);
      serverScale = 1.0;
    }
  } else {
    serverBase = 0;
    serverScale = 1.0;
  }

  const offsets: number[] = [];
  let lastOffset = 0;
  for (let idx = 0; idx < spans.length; idx++) {
    const span = spans[idx];
    const node = span.node;
    const action = span.action;
    const ts = span.ts;
    let offset: number;

    if (node === 'sdk' && action === 'send') {
      offset = 0;
    } else if (node === 'sdk' && action === 'recv' && totalMs !== null) {
      offset = totalMs;
    } else if (node !== 'sdk' && serverMin !== null && typeof ts === 'number' && ts > 0) {
      offset = Math.round(serverBase + (Math.round(ts) - serverMin) * serverScale);
    } else {
      offset = idx === 0 ? 0 : lastOffset;
    }

    if (offset < lastOffset) offset = lastOffset;
    offsets.push(offset);
    lastOffset = offset;
  }
  return offsets;
}

/** 格式化 span 的业务字段为 key=value 字符串 */
function formatTraceFields(span: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const key of TRACE_SPAN_DETAIL_FIELDS) {
    const value = span[key];
    if (value === undefined || value === null || value === '') continue;
    let s = String(value);
    if (s.length > 48) s = s.slice(0, 45) + '...';
    parts.push(`${key}=${s}`);
  }
  return parts.join(' ');
}

/** 将 span 列表格式化为树状结构字符串 */
function formatTraceTree(spans: Record<string, unknown>[]): string {
  if (!spans || spans.length === 0) return '';

  const sortedSpans = sortTraceSpansForDisplay(spans);
  const offsets = traceLogicalOffsets(sortedSpans);

  const lines: string[] = [];
  const stack: Array<{ node: string; span: Record<string, unknown> }> = [];

  for (let idx = 0; idx < sortedSpans.length; idx++) {
    const span = sortedSpans[idx];
    const node = String(span.node ?? '?');
    const action = String(span.action ?? 'process');
    const timePart = ` +${offsets[idx]}ms`;

    if (action === 'enter') {
      const indent = '  '.repeat(stack.length);
      const fieldsStr = formatTraceFields(span);
      const detail = fieldsStr ? ` ${fieldsStr}` : '';
      lines.push(`${indent}├─ ${node}.enter${detail}${timePart}`);
      stack.push({ node, span });
    } else if (action === 'exit') {
      if (stack.length > 0 && stack[stack.length - 1].node === node) {
        stack.pop();
      }
      const indent = '  '.repeat(stack.length);
      const dur = span.ms ?? 0;
      const fieldsStr = formatTraceFields(span);
      const detail = fieldsStr ? ` ${fieldsStr}` : '';
      lines.push(`${indent}└─ ${node}.exit${detail} dur=${dur}ms${timePart}`);
    } else {
      const indent = '  '.repeat(stack.length);
      const fieldsStr = formatTraceFields(span);
      const dur = span.ms;
      const durPart = dur !== undefined && dur !== null ? ` dur=${dur}ms` : '';
      const detail = fieldsStr ? ` ${fieldsStr}` : '';
      lines.push(`${indent}├─ ${node}.${action}${detail}${durPart}${timePart}`);
    }
  }
  return lines.join('\n');
}

/** 格式化完整 trace 展示（header + tree） */
function traceDisplay(method: string, status: string, durationMs: number, trace: Record<string, unknown>, spans: Record<string, unknown>[]): string {
  const tree = formatTraceTree(spans);
  const header = `[TRACE][${method}][${status}] total=${durationMs}ms trace_id=${String(trace.trace_id ?? '')}`;
  return tree ? `${header}\n${tree}` : header;
}

// 提取诊断字段时使用的字段白名单（仅元数据/路由字段，绝不打印 payload 明文/token/私钥/密钥/密文）
const DIAG_PARAM_FIELDS = [
  'to', 'to_aid', 'from', 'from_aid', 'group_id', 'message_id', 'mid',
  'method', 'device_id', 'slot_id', 'epoch', 'epoch_id', 'rotation_id',
  'after_seq', 'after_event_seq', 'seq', 'event_seq', 'limit', 'cursor',
  'aid', 'session_id', 'type', 'encrypt', 'encryption_mode', 'suite',
  'prekey_id', 'trust_root_version', 'version', 'ok', 'request_id',
  'owner_aid', 'rotated_by', 'action', 'force',
] as const;

const DIAG_RESULT_FIELDS = [
  ...DIAG_PARAM_FIELDS,
  'members', 'messages', 'events', 'count', 'imported', 'skipped',
  'next_cursor', 'current_seq', 'committed_epoch',
] as const;

function summarizeDict(payload: unknown, fields: readonly string[]): string {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    if (Array.isArray(payload)) return `[list len=${payload.length}]`;
    if (payload === null || payload === undefined) return '<empty>';
    return `<${typeof payload}>`;
  }
  const obj = payload as Record<string, unknown>;
  const parts: string[] = [];
  for (const key of fields) {
    const v = obj[key];
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) {
      parts.push(`${key}=[len=${v.length}]`);
    } else if (typeof v === 'object') {
      parts.push(`${key}={keys=${Object.keys(v as object).length}}`);
    } else if (typeof v === 'boolean' || typeof v === 'number') {
      parts.push(`${key}=${v}`);
    } else {
      let s = String(v);
      if (s.length > 64) s = s.slice(0, 61) + '...';
      parts.push(`${key}=${s}`);
    }
  }
  return parts.length === 0 ? '<no diag fields>' : parts.join(' ');
}

/** 协议事件名映射 */
const EVENT_NAME_MAP: Record<string, string> = {
  'message.received': 'message.received',
  'message.recalled': 'message.recalled',
  'message.ack': 'message.ack',
  'group.changed': 'group.changed',
  'group.message_created': 'group.message_created',
  'group.message_recalled': 'group.message_recalled',
  'storage.object_changed': 'storage.object_changed',
};

/** 断线回调，closeCode 为 WebSocket close code（1006 = 网络异常断开，其他 = 服务端主动关闭） */
export type DisconnectCallback = (error: Error | null, closeCode?: number) => void | Promise<void>;

/** RPC envelope 的 _meta 字段观察者；observer 抛错被吞掉，不影响业务。 */
export type MetaObserver = (meta: Record<string, unknown>) => void;

/** Trace observer；observer(traceInfo) 在每次 RPC/事件携带 _trace 时调用。 */
export type TraceObserver = (traceInfo: Record<string, unknown>) => void;

/**
 * WebSocket JSON-RPC 2.0 传输层
 */
export class RPCTransport {
  private _logger: ModuleLogger;
  private _dispatcher: EventDispatcher;
  private _timeout: number;
  private _onDisconnect: DisconnectCallback | null;
  private _verifySsl: boolean;
  private _dnsNet: import('./net.js').DnsResilientNet | null = null;
  private _ws: WebSocket | null = null;
  private _closed = true;
  private _lastCloseCode: number | null = null;
  private _challenge: RpcMessage | null = null;
  private _pending: Map<string, PendingRpc> = new Map();
  private _pendingMeta: Map<string, PendingRpcMeta> = new Map();
  private _pendingBackground: Set<string> = new Set();
  private _rpcQueue: QueuedRpc[] = [];
  private _backgroundRpcQueue: QueuedRpc[] = [];
  private _drainingRpcQueue = false;
  private _idCounter = 0;
  // Gateway 在 RPC envelope 注入 _meta 字段（与 result 同级），由 client 层 observer 接收。
  // observer 抛异常会被吞掉，不影响 RPC result 返回。
  private _metaObserver: MetaObserver | null = null;
  // Trace 模式：off / log / diag
  private _traceMode: string = 'off';
  // Trace observer：observer(traceInfo) 在每次 RPC/事件携带 _trace 时调用
  private _traceObserver: TraceObserver | null = null;

  constructor(opts: {
    eventDispatcher: EventDispatcher;
    timeout?: number;
    onDisconnect?: DisconnectCallback | null;
    verifySsl?: boolean;
    logger?: ModuleLogger;
    dnsNet?: import('./net.js').DnsResilientNet | null;
  }) {
    this._logger = opts.logger ?? _noopLogger;
    this._dispatcher = opts.eventDispatcher;
    this._timeout = opts.timeout ?? 10_000;
    this._onDisconnect = opts.onDisconnect ?? null;
    this._verifySsl = opts.verifySsl ?? true;
    this._dnsNet = opts.dnsNet ?? null;
  }

  /** 设置默认 RPC 超时（毫秒） */
  setTimeout(timeout: number): void {
    this._timeout = timeout;
  }

  /**
   * 注册 RPC envelope _meta 字段观察者；observer(meta) 在每次成功 RPC 时调用。
   *
   * Gateway 注入的 _meta 与业务无关（如 agent_md_etag），observer 抛异常会被吞掉，
   * 不影响 RPC 结果返回。
   */
  setMetaObserver(observer: MetaObserver | null): void {
    this._metaObserver = observer;
  }

  /** 设置 trace 模式：off / log / diag */
  setTraceMode(mode: string): void {
    if (mode !== 'off' && mode !== 'log' && mode !== 'diag') {
      throw new ValidationError(`invalid trace mode: ${mode}, must be off/log/diag`);
    }
    this._traceMode = mode;
  }

  /** 注册 trace observer；observer(traceInfo) 在每次 RPC/事件携带 _trace 时调用。 */
  setTraceObserver(observer: TraceObserver | null): void {
    this._traceObserver = observer;
  }

  /** 获取上次连接的 challenge 消息 */
  get challenge(): RpcMessage | null {
    return this._challenge;
  }

  /**
   * 连接到 Gateway WebSocket 端点。
   * 返回初始 challenge 消息（如果有）。
   */
  async connect(url: string): Promise<RpcMessage | null> {
    const tStart = Date.now();
    this._logger.debug(`connect enter: url=${url}`);
    // ws 8.x+ 中 rejectUnauthorized 需通过 https.Agent 传递
    let wsOpts: any = undefined;
    if (!this._verifySsl) {
      const https = await import('https');
      wsOpts = { agent: new https.Agent({ rejectUnauthorized: false }) };
    }
    const ws = new WebSocket(url, wsOpts);
    try {
      const result = await this._connectWithWs(ws);
      this._logger.debug(`connect exit: elapsed=${Date.now() - tStart}ms, has_challenge=${result !== null}`);
      return result;
    } catch (err) {
      // DNS fallback
      if (this._dnsNet && err instanceof Error) {
        const { isDnsError, parseHostPort, replaceHostWithIP } = await import('./net.js');
        if (isDnsError(err)) {
          const { hostname, port } = parseHostPort(url);
          this._logger.debug(`WS DNS failed for ${hostname}, trying cached IP`);
          const cached = this._dnsNet.loadDnsCache(hostname);
          if (cached) {
            const ipUrl = replaceHostWithIP(url, cached.ip);
            const https = await import('https');
            const ipOpts: any = this._verifySsl
              ? { agent: new https.Agent({ servername: hostname }), headers: { Host: hostname } }
              : { agent: new https.Agent({ rejectUnauthorized: false }), headers: { Host: hostname } };
            const ipWs = new WebSocket(ipUrl, ipOpts);
            try {
              const result = await this._connectWithWs(ipWs);
              this._logger.debug(`connect exit (IP fallback): elapsed=${Date.now() - tStart}ms`);
              return result;
            } catch (ipErr) {
              this._logger.debug(`connect IP fallback also failed: ${ipErr instanceof Error ? ipErr.message : String(ipErr)}`);
            }
          }
        }
      }
      this._logger.debug(`connect exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 内部：使用已创建的 WebSocket 实例完成握手。
   * 握手阶段（open 后到首条消息处理完毕）如果发生 error 或解析失败，
   * 会回滚 _ws / _closed，确保不留下半连接状态。
   */
  private _connectWithWs(ws: WebSocket): Promise<RpcMessage | null> {
    return new Promise<RpcMessage | null>((resolve, reject) => {
      let initialResolved = false;

      /** 握手失败时回滚内部状态，避免半连接 */
      const rollback = (): void => {
        this._ws = null;
        this._closed = true;
        try { ws.close(); } catch { /* noop */ }
      };

      /** 清理握手阶段的临时监听器 */
      const cleanupHandshakeListeners = (): void => {
        try { ws.removeListener('message', onFirstMessage); } catch { /* noop */ }
        try { ws.removeListener('error', onHandshakeError); } catch { /* noop */ }
        try { ws.removeListener('open', onOpen); } catch { /* noop */ }
      };

      let connectTimeout: ReturnType<typeof setTimeout> | null = null;

      const onHandshakeError = (err: Error): void => {
        if (!initialResolved) {
          initialResolved = true;
          if (connectTimeout) clearTimeout(connectTimeout);
          cleanupHandshakeListeners();
          rollback();
          this._logger.error(`connection failed: ${err.message}`);
          reject(new ConnectionError(`websocket connect failed: ${err.message}`));
        }
      };

      const onOpen = (): void => {
        // 防止超时/错误已 rollback 后，迟到的 open 事件重新赋值 _ws 导致 zombie 连接
        if (initialResolved) return;
        this._ws = ws;
        this._closed = false;
        this._lastCloseCode = null;
        this._logger.debug('WebSocket open, waiting for challenge');
        // 等待第一条消息作为 challenge
      };

      const onFirstMessage = (data: unknown): void => {
        if (!initialResolved) {
          // 第一条消息：尝试解析为 challenge
          initialResolved = true;
          if (connectTimeout) clearTimeout(connectTimeout);
          cleanupHandshakeListeners();
          try {
            const message = this._decodeMessage(data as string | Buffer | Buffer[] | ArrayBuffer | JsonObject);
            if (message.method === 'challenge') {
              this._challenge = message;
              this._setupListeners(ws);
              resolve(message);
            } else {
              this._challenge = null;
              this._setupListeners(ws);
              // 非 challenge 消息，路由处理后返回 null
              this._routeMessage(message);
              resolve(null);
            }
          } catch (err) {
            // 握手消息解析失败：回滚状态，不留半连接
            rollback();
            reject(err instanceof Error ? err : new SerializationError(String(err)));
          }
          return;
        }
        // 后续消息由 _setupListeners 处理
      };

      ws.on('error', onHandshakeError);
      ws.on('open', onOpen);
      ws.on('message', onFirstMessage);

      // 连接超时覆盖整个握手流程（open + 等待 challenge）。
      // 不在 open 时清除，防止服务端沉默导致 Promise 永远不 resolve。
      connectTimeout = setTimeout(() => {
        if (!initialResolved) {
          initialResolved = true;
          cleanupHandshakeListeners();
          rollback();
          this._logger.error('connect timeout');
          reject(new ConnectionError('websocket connect timeout'));
        }
      }, this._timeout);
    });
  }

  /** 关闭连接 */
  async close(): Promise<void> {
    const tStart = Date.now();
    const pendingCount = this._pending.size;
    const queuedCount = this._rpcQueue.length + this._backgroundRpcQueue.length;
    this._logger.debug(`close enter: pending_rpc=${pendingCount}, queued_rpc=${queuedCount}, background_pending=${this._pendingBackground.size}`);
    this._closed = true;
    // 取消所有待处理的 RPC
    for (const [, pending] of this._pending) {
      clearTimeout(pending.timer);
      pending.reject(new ConnectionError('transport closed'));
    }
    this._pending.clear();
    this._pendingMeta.clear();
    this._pendingBackground.clear();
    for (const queued of this._rpcQueue) {
      clearTimeout(queued.pending.timer);
      queued.pending.reject(new ConnectionError('transport closed'));
    }
    this._rpcQueue = [];
    for (const queued of this._backgroundRpcQueue) {
      clearTimeout(queued.pending.timer);
      queued.pending.reject(new ConnectionError('transport closed'));
    }
    this._backgroundRpcQueue = [];
    this._logger.debug(`close: cancelled ${pendingCount} pending rpc(s), ${queuedCount} queued rpc(s)`);

    if (this._ws) {
      const ws = this._ws;
      this._ws = null;
      // M25: close() 返回前先移除路由相关的监听器，避免
      // 超时强制 resolve 后，stale ws 仍把消息注入 _routeMessage 或
      // 向 EventDispatcher 广播 connection.error。
      try { ws.removeAllListeners('message'); } catch { /* noop */ }
      try { ws.removeAllListeners('error'); } catch { /* noop */ }
      return new Promise<void>((resolve) => {
        let settled = false;
        let timer: ReturnType<typeof setTimeout> | null = null;
        const finish = (): void => {
          if (settled) return;
          settled = true;
          if (timer !== null) clearTimeout(timer);
          try { ws.removeAllListeners(); } catch { /* noop */ }
          try { ws.terminate?.(); } catch { /* noop */ }
          this._logger.debug(`close exit: elapsed=${Date.now() - tStart}ms`);
          resolve();
        };
        ws.on('close', finish);
        // 超时强制解析，并在定时器触发时通过 terminate() 彻底清理残留 socket。
        timer = setTimeout(finish, 3_000);
        try {
          ws.close();
        } catch {
          finish();
          return;
        }
      });
    }
    this._logger.debug(`close exit: elapsed=${Date.now() - tStart}ms (no ws)`);
  }

  /**
   * 发送 JSON-RPC 2.0 请求并等待响应。
   */
  async call(
    method: string,
    params?: RpcParams,
    timeout?: number,
    trace?: string,
    background = false,
  ): Promise<RpcResult> {
    if (this._closed || !this._ws) {
      const suffix = this._lastCloseCode !== null ? `: close code ${this._lastCloseCode}` : '';
      throw new ConnectionError(`transport not connected${suffix}`, {
        ...(this._lastCloseCode !== null ? { code: this._lastCloseCode } : {}),
      });
    }

    const rpcId = `rpc-${crypto.randomBytes(8).toString('hex')}`;
    const effectiveTimeout = timeout ?? this._timeout;
    const tStart = Date.now();

    // 注入 _trace（会话级或调用级 mode 非 off 时）
    const effectiveTraceMode = (trace === 'off' || trace === 'log' || trace === 'diag') ? trace : this._traceMode;
    let traceId = '';
    const sendParams = { ...(params ?? {}) } as RpcParams;
    const localParams = sendParams as Record<string, unknown>;
    const backgroundRpc = background || localParams._rpc_background === true;
    delete localParams._rpc_background;
    if (effectiveTraceMode !== 'off') {
      traceId = crypto.randomBytes(16).toString('hex');
      const tracePayload: Record<string, unknown> = { trace_id: traceId, mode: effectiveTraceMode };
      if (effectiveTraceMode === 'diag') {
        tracePayload.spans = [{ node: 'sdk', ts: tStart, action: 'send' }];
      }
      localParams._trace = tracePayload;
      this._logger.info(`[trace=${traceId}] rpc_send method=${method} rpc_id=${rpcId}`);
    }

    const payload = JSON.stringify({
      jsonrpc: '2.0',
      id: rpcId,
      method,
      params: sendParams,
    });

    const payloadSize = new TextEncoder().encode(payload).length;
    if (payloadSize > MAX_WS_PAYLOAD_SIZE) {
      throw new ValidationError('payload is too large');
    }

    return new Promise<RpcResult>((resolve, reject) => {
      const timer = setTimeout(() => {
        this._removeRpc(rpcId, pending);
        this._logger.warn(`RPC timeout: method=${method}, id=${rpcId}, elapsed=${Date.now() - tStart}ms, timeout=${effectiveTimeout}ms`);
        reject(new TimeoutError(`rpc timeout: ${method}`, { retryable: true }));
        this._drainRpcQueue();
      }, effectiveTimeout);

      const pending: PendingRpc = {
        resolve: (response) => {
          clearTimeout(timer);
          const elapsed = Date.now() - tStart;
          if (response.error !== undefined) {
            this._logger.debug(`RPC error response: method=${method}, id=${rpcId}, elapsed=${elapsed}ms, error=${JSON.stringify(response.error)}`);
            if (traceId) {
              this._logger.info(`[trace=${traceId}] rpc_recv method=${method} rpc_id=${rpcId} duration_ms=${elapsed} status=error`);
            }
            // 处理 error 路径的 _trace
            const respTrace = (response as Record<string, unknown>)._trace;
            if (respTrace && typeof respTrace === 'object' && !Array.isArray(respTrace)) {
              this._handleResponseTrace(method, 'error', elapsed, respTrace as Record<string, unknown>);
            }
            reject(mapRemoteError(response.error));
          } else if (response.result !== undefined) {
            this._logger.debug(`RPC response ok: method=${method}, id=${rpcId}, elapsed=${elapsed}ms ${summarizeDict(response.result, DIAG_RESULT_FIELDS)}`);
            if (traceId) {
              this._logger.info(`[trace=${traceId}] rpc_recv method=${method} rpc_id=${rpcId} duration_ms=${elapsed} status=ok`);
            }
            // 透传 envelope._meta 给 observer
            if (this._metaObserver !== null) {
              const meta = (response as Record<string, unknown>)._meta;
              if (meta !== null && typeof meta === 'object' && !Array.isArray(meta)) {
                try {
                  this._metaObserver(meta as Record<string, unknown>);
                } catch (err) {
                  this._logger.debug(`meta_observer raised: ${err instanceof Error ? err.message : String(err)}`);
                }
              }
            }
            // 处理 success 路径的 _trace
            const respTrace = (response as Record<string, unknown>)._trace;
            if (respTrace && typeof respTrace === 'object' && !Array.isArray(respTrace)) {
              this._handleResponseTrace(method, 'ok', elapsed, respTrace as Record<string, unknown>);
            }
            resolve(response.result);
          } else {
            this._logger.warn(`RPC response missing result or error: method=${method}, id=${rpcId}, elapsed=${elapsed}ms`);
            reject(new SerializationError(`rpc response missing result and error: ${method}`));
          }
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
        timer,
      };

      this._rpcQueue.push({
        rpcId,
        method,
        payload,
        pending,
        tStart,
        timeoutMs: effectiveTimeout,
        background: backgroundRpc,
      });
      if (backgroundRpc) {
        this._rpcQueue.pop();
        this._backgroundRpcQueue.push({
          rpcId,
          method,
          payload,
          pending,
          tStart,
          timeoutMs: effectiveTimeout,
          background: true,
        });
      }
      this._drainRpcQueue();
    });
  }

  /** 发送 JSON-RPC 2.0 Notification，不分配 id，也不等待响应。 */
  async notify(method: string, params?: RpcParams | null): Promise<void> {
    if (this._closed || !this._ws) {
      const suffix = this._lastCloseCode !== null ? `: close code ${this._lastCloseCode}` : '';
      throw new ConnectionError(`transport not connected${suffix}`, {
        ...(this._lastCloseCode !== null ? { code: this._lastCloseCode } : {}),
      });
    }
    const normalizedMethod = String(method ?? '').trim();
    if (!normalizedMethod.startsWith('notification/') && !normalizedMethod.startsWith('event/')) {
      throw new ValidationError('notify method must start with notification/ or event/');
    }
    if (params !== undefined && params !== null && !isJsonObject(params)) {
      throw new ValidationError('notify params must be an object');
    }
    const payload = JSON.stringify({
      jsonrpc: '2.0',
      method: normalizedMethod,
      params: params ?? {},
    });
    const payloadSize = new TextEncoder().encode(payload).length;
    if (payloadSize > MAX_WS_PAYLOAD_SIZE) {
      throw new ValidationError('payload is too large');
    }

    await new Promise<void>((resolve, reject) => {
      try {
        this._ws!.send(payload, (err) => {
          if (err) {
            reject(new ConnectionError(`failed to send notification ${normalizedMethod}: ${err.message}`));
            return;
          }
          this._logger.debug(`notification sent: method=${normalizedMethod}, size=${payloadSize}`);
          resolve();
        });
      } catch (err) {
        reject(new ConnectionError(`failed to send notification ${normalizedMethod}: ${err instanceof Error ? err.message : String(err)}`));
      }
    });
  }

  private _removeRpc(rpcId: string, pending?: PendingRpc): void {
    const current = this._pending.get(rpcId);
    if (current && (!pending || current === pending)) {
      this._pending.delete(rpcId);
      this._pendingMeta.delete(rpcId);
      this._pendingBackground.delete(rpcId);
    }
    if (this._rpcQueue.length > 0) {
      this._rpcQueue = this._rpcQueue.filter((entry) => entry.rpcId !== rpcId || (pending !== undefined && entry.pending !== pending));
    }
    if (this._backgroundRpcQueue.length > 0) {
      this._backgroundRpcQueue = this._backgroundRpcQueue.filter((entry) => entry.rpcId !== rpcId || (pending !== undefined && entry.pending !== pending));
    }
  }

  private _drainRpcQueue(): void {
    if (this._drainingRpcQueue) return;
    this._drainingRpcQueue = true;
    try {
      while (!this._closed && this._ws && this._pending.size < MAX_RPC_INFLIGHT) {
        let entry: QueuedRpc | undefined;
        if (this._rpcQueue.length > 0) {
          entry = this._rpcQueue.shift()!;
        } else if (this._backgroundRpcQueue.length > 0 && this._pendingBackground.size < MAX_BACKGROUND_RPC_INFLIGHT) {
          entry = this._backgroundRpcQueue.shift()!;
        } else {
          break;
        }
        const elapsed = Date.now() - entry.tStart;
        if (elapsed >= entry.timeoutMs) {
          clearTimeout(entry.pending.timer);
          this._logger.warn(`RPC queue timeout: method=${entry.method}, id=${entry.rpcId}, elapsed=${elapsed}ms, timeout=${entry.timeoutMs}ms`);
          entry.pending.reject(new TimeoutError(`rpc timeout before send: ${entry.method}`, { retryable: true }));
          continue;
        }

        this._pending.set(entry.rpcId, entry.pending);
        this._pendingMeta.set(entry.rpcId, {
          method: entry.method,
          queuedAt: entry.tStart,
          pendingSince: Date.now(),
          deadlineAt: entry.tStart + entry.timeoutMs,
          background: entry.background,
        });
        if (entry.background) {
          this._pendingBackground.add(entry.rpcId);
        }
        try {
          this._ws.send(entry.payload);
          this._logger.debug(`RPC request sent: method=${entry.method}, id=${entry.rpcId}, background=${entry.background}`);
        } catch (err) {
          this._removeRpc(entry.rpcId, entry.pending);
          this._logger.error(`RPC send failed: method=${entry.method}, id=${entry.rpcId}, error=${err instanceof Error ? err.message : String(err)}`);
          entry.pending.reject(
            new ConnectionError(
              `failed to send rpc ${entry.method}: ${err instanceof Error ? err.message : String(err)}`,
            ),
          );
        }
      }
    } finally {
      this._drainingRpcQueue = false;
    }
  }

  /** 处理 RPC 响应中的 _trace 字段：追加 sdk.recv span，格式化输出，通知 observer */
  private _handleResponseTrace(method: string, status: string, elapsedMs: number, respTrace: Record<string, unknown>): void {
    try {
      const sdkRecvSpan: Record<string, unknown> = {
        node: 'sdk',
        ts: Date.now(),
        action: 'recv',
        ms: elapsedMs,
      };
      const existingSpans = Array.isArray(respTrace.spans) ? respTrace.spans : [];
      const spans = [...existingSpans, sdkRecvSpan] as Record<string, unknown>[];
      const enriched = { ...respTrace, spans };

      this._logger.info(traceDisplay(method, status, elapsedMs, respTrace, spans));

      if (this._traceObserver !== null) {
        this._traceObserver({ type: 'rpc', method, trace: enriched, status, duration_ms: elapsedMs });
      }
    } catch (err) {
      this._logger.debug(`trace handling raised: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // ── 内部方法 ────────────────────────────────────────────

  /** 设置 WebSocket 监听器（首条消息已处理后调用） */
  private _setupListeners(ws: WebSocket): void {
    ws.on('message', (data) => {
      try {
        const message = this._decodeMessage(data);
        this._routeMessage(message);
      } catch (err) {
        // 解析异常，发布错误事件
        this._dispatcher.publish('connection.error', {
          error: err instanceof Error ? err : String(err),
        });
      }
    });

    ws.on('close', (code: number) => {
      const wasClosed = this._closed;
      this._closed = true;
      this._lastCloseCode = Number.isFinite(code) ? code : null;
      this._logger.debug(`WebSocket closed: code=${code}, intentional close=${wasClosed}`);
      const err = new ConnectionError(`websocket closed: code=${code}`);
      for (const [, pending] of this._pending) {
        clearTimeout(pending.timer);
        pending.reject(err);
      }
      this._pending.clear();
      this._pendingMeta.clear();
      this._pendingBackground.clear();
      for (const queued of this._rpcQueue) {
        clearTimeout(queued.pending.timer);
        queued.pending.reject(err);
      }
      this._rpcQueue = [];
      for (const queued of this._backgroundRpcQueue) {
        clearTimeout(queued.pending.timer);
        queued.pending.reject(err);
      }
      this._backgroundRpcQueue = [];
      if (!wasClosed && this._onDisconnect) {
        const cb = this._onDisconnect;
        Promise.resolve(cb(null, code)).catch(() => this._logger.warn('disconnect callback error'));
      }
    });

    ws.on('error', (err) => {
      if (!this._closed) {
        this._logger.error(`WebSocket error: ${err.message}`);
        this._dispatcher.publish('connection.error', { error: err });
      }
    });
  }

  /** 路由消息：RPC 响应 / challenge / 事件 / 通知 */
  private _routeMessage(message: RpcMessage): void {
    // 入口 debug: 识别消息类型
    const hasId = 'id' in message;
    const methodStr = String(message.method ?? '');
    this._logger.debug(`_routeMessage enter: has_id=${hasId}, method=${methodStr || '<none>'}`);
    // RPC 响应（有 id 字段）
    if ('id' in message) {
      const rpcId = String(message.id);
      const pending = this._pending.get(rpcId);
      if (pending) {
        this._pending.delete(rpcId);
        this._pendingMeta.delete(rpcId);
        this._pendingBackground.delete(rpcId);
        pending.resolve(message);
        this._drainRpcQueue();
      }
      return;
    }

    const method = String(message.method ?? '');

    // Challenge 消息
    if (method === 'challenge') {
      this._challenge = message;
      this._logger.debug('challenge received');
      this._dispatcher.publish('connection.challenge', message.params ?? {});
      return;
    }

    // 事件消息（event/ 前缀）
    if (method.startsWith('event/')) {
      const protocolEvent = method.slice('event/'.length);
      const sdkEvent = EVENT_NAME_MAP[protocolEvent] ?? protocolEvent;
      this._logger.debug(`event recv: event=${sdkEvent} ${summarizeDict(message.params, DIAG_RESULT_FIELDS)}`);
      const meta = (message as Record<string, unknown>)._meta;
      if (this._metaObserver !== null && meta !== null && typeof meta === 'object' && !Array.isArray(meta)) {
        try {
          this._metaObserver(meta as Record<string, unknown>);
        } catch (err) {
          this._logger.debug(`event meta_observer raised: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
      // 提取事件中的 _trace 并回调 observer，然后从 params 中剥离
      const params = (message.params ?? {}) as Record<string, unknown>;
      if ('_trace' in params) {
        const eventTrace = params._trace;
        delete params._trace;
        if (eventTrace && typeof eventTrace === 'object' && !Array.isArray(eventTrace)) {
          if (this._traceObserver !== null) {
            try {
              this._traceObserver({ type: 'event', event: sdkEvent, trace: eventTrace as Record<string, unknown> });
            } catch { /* observer 抛错被吞 */ }
          }
          const traceObj = eventTrace as Record<string, unknown>;
          this._logger.info(`[trace=${String(traceObj.trace_id ?? '')}] event_recv event=${sdkEvent}`);
        }
      }
      // 发布为 _raw.{event}，由 AUNClient 处理后再发布用户可见的事件
      if (sdkEvent.startsWith('app.')) {
        this._dispatcher.publish(sdkEvent, params as unknown as import('./types.js').JsonValue);
        return;
      }
      this._dispatcher.publish(`_raw.${sdkEvent}`, params as unknown as import('./types.js').JsonValue);
      return;
    }

    // 其他通知
    const meta = (message as Record<string, unknown>)._meta;
    if (this._metaObserver !== null && meta !== null && typeof meta === 'object' && !Array.isArray(meta)) {
      try {
        this._metaObserver(meta as Record<string, unknown>);
      } catch (err) {
        this._logger.debug(`notification meta_observer raised: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    this._dispatcher.publish('notification', message);
  }

  /** 解码 WebSocket 消息为 JSON 对象 */
  private _decodeMessage(raw: string | Buffer | Buffer[] | ArrayBuffer | JsonObject): RpcMessage {
    if (isJsonObject(raw)) {
      return raw as RpcMessage;
    }
    let str: string;
    if (Buffer.isBuffer(raw)) {
      str = raw.toString('utf-8');
    } else if (Array.isArray(raw)) {
      str = Buffer.concat(raw).toString('utf-8');
    } else if (raw instanceof ArrayBuffer) {
      str = Buffer.from(raw).toString('utf-8');
    } else if (typeof raw === 'string') {
      str = raw;
    } else {
      throw new SerializationError(`unsupported websocket payload type: ${typeof raw}`);
    }
    try {
      const parsed = JSON.parse(str) as JsonValue;
      if (!isJsonObject(parsed)) {
        throw new SerializationError('invalid json payload');
      }
      return parsed as RpcMessage;
    } catch {
      throw new SerializationError('invalid json payload');
    }
  }
}
