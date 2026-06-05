// ── RPC Transport（浏览器原生 WebSocket）──────────────────

import { EventDispatcher } from './events.js';
import type { ModuleLogger } from './logger.js';
import {
  ConnectionError,
  SerializationError,
  TimeoutError,
  ValidationError,
  mapRemoteError,
} from './errors.js';
import { isJsonObject, type JsonObject, type JsonValue, type RpcMessage, type RpcParams, type RpcResult } from './types.js';


const MAX_WS_PAYLOAD_SIZE = 1_000_000;
const MAX_RPC_INFLIGHT = 16;
const MAX_BACKGROUND_RPC_INFLIGHT = 8;

type PendingRpc = {
  resolve: (value: RpcMessage) => void;
  reject: (reason: Error) => void;
  timer: ReturnType<typeof globalThis.setTimeout>;
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

const _noopLog: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };

/** RPC 请求递增计数器，避免 Date.now() 高并发碰撞 */
let _rpcIdCounter = 0;

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

/** 协议事件名映射 */
const EVENT_NAME_MAP: Record<string, string> = {
  'message.received': 'message.received',
  'message.recalled': 'message.recalled',
  'message.ack': 'message.ack',
  'group.changed': 'group.changed',
  'group.message_created': 'group.message_created',
  'group.state_committed': 'group.state_committed',
  'storage.object_changed': 'storage.object_changed',
};

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

/**
 * JSON-RPC 2.0 传输层 — 基于浏览器原生 WebSocket。
 *
 * 职责：
 * - 连接管理（connect / close）
 * - RPC 调用（call — 请求/响应匹配）
 * - 事件路由（服务端推送 → EventDispatcher）
 */
export class RPCTransport {
  private _log: ModuleLogger = _noopLog;
  setLogger(log: ModuleLogger): void { this._log = log; }

  private _dispatcher: EventDispatcher;
  private _timeout: number;
  private _onDisconnect: ((error: Error | null, closeCode?: number) => Promise<void>) | null;
  private _ws: WebSocket | null = null;
  private _closed = true;
  private _lastCloseCode: number | null = null;
  private _lastCloseReason = '';
  private _challenge: RpcMessage | null = null;
  private _pending: Map<string, PendingRpc> = new Map();
  private _pendingBackground: Set<string> = new Set();
  private _rpcQueue: QueuedRpc[] = [];
  private _backgroundRpcQueue: QueuedRpc[] = [];
  private _drainingRpcQueue = false;
  // Gateway 在 RPC envelope 注入 _meta 字段（与 result 同级），由 client 层 observer 接收。
  // 注入失败 / 字段缺失时 observer 不会被调用，不影响业务路径。
  private _metaObserver: ((meta: JsonObject) => void) | null = null;
  // Trace 模式：off / log / diag
  private _traceMode: string = 'off';
  // Trace observer：observer(traceInfo) 在每次 RPC/事件携带 _trace 时调用
  private _traceObserver: ((traceInfo: Record<string, unknown>) => void) | null = null;

  constructor(opts: {
    eventDispatcher: EventDispatcher;
    timeout?: number;
    onDisconnect?: ((error: Error | null, closeCode?: number) => Promise<void>) | null;
  }) {
    this._dispatcher = opts.eventDispatcher;
    this._timeout = opts.timeout ?? 10;
    this._onDisconnect = opts.onDisconnect ?? null;
  }

  /** 设置默认超时（秒） */
  setTimeout(timeout: number): void {
    this._timeout = timeout;
  }

  /**
   * 注册 RPC envelope `_meta` 字段观察者；observer(meta) 在每次成功 RPC 时调用。
   *
   * Gateway 注入的 `_meta` 与业务无关（如 `agent_md_etag`），observer 抛异常会被吞掉，
   * 不影响 RPC result 返回。
   */
  setMetaObserver(observer: ((meta: JsonObject) => void) | null): void {
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
  setTraceObserver(observer: ((traceInfo: Record<string, unknown>) => void) | null): void {
    this._traceObserver = observer;
  }

  /** 获取连接时收到的 challenge */
  get challenge(): RpcMessage | null {
    return this._challenge;
  }

  /**
   * 连接到 WebSocket URL。
   * 等待首条消息，若为 challenge 则返回，否则进入消息路由。
   */
  async connect(url: string): Promise<RpcMessage | null> {
    const tStart = Date.now();
    this._log.debug(`connect enter: url=${url}`);
    this._lastCloseCode = null;
    this._lastCloseReason = '';
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      this._ws = ws;
      this._closed = false;
      let initialResolved = false;

      ws.onopen = () => {
        // 连接已建立，等待首条消息
      };

      ws.onerror = (event) => {
        if (!initialResolved) {
          initialResolved = true;
          this._log.debug(`connect exit (error): elapsed=${Date.now() - tStart}ms err=websocket_error`);
          reject(new ConnectionError(`websocket connection failed to ${url}`));
        }
      };

      ws.onmessage = (event) => {
        if (!initialResolved) {
          // 首条消息：可能是 challenge
          initialResolved = true;
          try {
            const message = this._decodeMessage(event.data);
            if (message.method === 'challenge') {
              this._challenge = message;
              // 切换到正常消息路由
              ws.onmessage = (evt) => this._handleMessage(evt.data);
              ws.onclose = (evt) => this._handleClose(evt);
              ws.onerror = null;
              this._log.debug(`connect exit: elapsed=${Date.now() - tStart}ms has_challenge=true`);
              resolve(message);
            } else {
              // 非 challenge 消息，路由处理后返回 null
              ws.onmessage = (evt) => this._handleMessage(evt.data);
              ws.onclose = (evt) => this._handleClose(evt);
              ws.onerror = null;
              this._routeMessage(message);
              this._log.debug(`connect exit: elapsed=${Date.now() - tStart}ms has_challenge=false`);
              resolve(null);
            }
          } catch (err) {
            this._log.debug(`connect exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
            reject(err instanceof Error ? err : new ConnectionError(String(err)));
          }
          return;
        }
      };

      ws.onclose = (event) => {
        this._lastCloseCode = event.code;
        this._lastCloseReason = event.reason ?? '';
        if (!initialResolved) {
          initialResolved = true;
          this._log.debug(`connect exit (error): elapsed=${Date.now() - tStart}ms err=closed_before_initial code=${event.code}`);
          reject(new ConnectionError(`websocket closed before initial message: code=${event.code}`));
        }
      };
    });
  }

  /** 关闭连接 */
  async close(): Promise<void> {
    const tStart = Date.now();
    const pendingCount = this._pending.size;
    const queuedCount = this._rpcQueue.length + this._backgroundRpcQueue.length;
    this._log.debug(`close enter: pending_rpc=${pendingCount}, queued_rpc=${queuedCount}, background_pending=${this._pendingBackground.size}`);
    this._closed = true;
    if (this._ws) {
      try {
        this._ws.onclose = null;
        this._ws.onerror = null;
        this._ws.onmessage = null;
        this._ws.close();
      } catch (exc) {
        this._log.warn('[aun_core.transport] WebSocket closeexception:', String(exc));
      }
      this._ws = null;
    }

    // 拒绝所有待处理的 RPC 调用
    for (const [, pending] of this._pending) {
      clearTimeout(pending.timer);
      pending.reject(new ConnectionError('transport closed'));
    }
    this._pending.clear();
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
    this._log.debug(`close exit: elapsed=${Date.now() - tStart}ms, cancelled ${pendingCount} pending, ${queuedCount} queued`);
  }

  /**
   * 发起 JSON-RPC 2.0 调用。
   * 返回 result 字段的值；若有 error 字段则抛出映射后的错误。
   */
  async call(
    method: string,
    params?: RpcParams | null,
    timeout?: number,
    trace?: string,
    background = false,
  ): Promise<RpcResult> {
    if (this._closed || !this._ws) {
      throw this._notConnectedError();
    }

    // 生成唯一 RPC ID（递增计数器，避免高并发碰撞）
    const rpcId = `rpc-${String(++_rpcIdCounter).padStart(6, '0')}`;
    const effectiveTimeout = (timeout ?? this._timeout) * 1000;
    const tStart = Date.now();

    // 注入 _trace（会话级或调用级 mode 非 off 时）
    const effectiveTraceMode = (trace === 'off' || trace === 'log' || trace === 'diag') ? trace : this._traceMode;
    let traceId = '';
    const sendParams = { ...(params ?? {}) } as RpcParams;
    const localParams = sendParams as Record<string, unknown>;
    const backgroundRpc = background || localParams._rpc_background === true;
    delete localParams._rpc_background;
    if (effectiveTraceMode !== 'off') {
      // 浏览器环境使用 crypto.randomUUID 或 Math.random 生成 trace_id
      traceId = typeof crypto !== 'undefined' && crypto.randomUUID
        ? crypto.randomUUID().replace(/-/g, '')
        : Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
      const tracePayload: Record<string, unknown> = { trace_id: traceId, mode: effectiveTraceMode };
      if (effectiveTraceMode === 'diag') {
        tracePayload.spans = [{ node: 'sdk', ts: tStart, action: 'send' }];
      }
      localParams._trace = tracePayload;
      this._log.info(`[trace=${traceId}] rpc_send method=${method} rpc_id=${rpcId}`);
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
      const timer = globalThis.setTimeout(() => {
        this._removeRpc(rpcId, pending);
        this._log.warn(`RPC timeout: method=${method}, id=${rpcId}, elapsed=${Date.now() - tStart}ms, timeout=${effectiveTimeout}ms`);
        reject(new TimeoutError(`rpc timeout: ${method}`, { retryable: true }));
        this._drainRpcQueue();
      }, effectiveTimeout);

      const pending: PendingRpc = {
        resolve: (response) => {
          clearTimeout(timer);
          const elapsed = Date.now() - tStart;
          if (response.error !== undefined) {
            this._log.debug(`RPC error response: method=${method}, id=${rpcId}, elapsed=${elapsed}ms, error=${JSON.stringify(response.error)}`);
            if (traceId) {
              this._log.info(`[trace=${traceId}] rpc_recv method=${method} rpc_id=${rpcId} duration_ms=${elapsed} status=error`);
            }
            const respTrace = (response as Record<string, unknown>)._trace;
            if (respTrace && typeof respTrace === 'object' && !Array.isArray(respTrace)) {
              this._handleResponseTrace(method, 'error', elapsed, respTrace as Record<string, unknown>);
            }
            reject(mapRemoteError(response.error));
          } else if (response.result !== undefined) {
            this._log.debug(`RPC response ok: method=${method}, id=${rpcId}, elapsed=${elapsed}ms ${summarizeDict(response.result, DIAG_RESULT_FIELDS)}`);
            if (traceId) {
              this._log.info(`[trace=${traceId}] rpc_recv method=${method} rpc_id=${rpcId} duration_ms=${elapsed} status=ok`);
            }
            // 透传 envelope._meta 给 observer
            if (this._metaObserver !== null) {
              const meta = (response as Record<string, unknown>)._meta;
              if (isJsonObject(meta)) {
                try {
                  this._metaObserver(meta as JsonObject);
                } catch (exc) {
                  this._log.debug(`meta_observer raised: ${String(exc)}`);
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
            this._log.warn(`RPC response missing result or error: method=${method}, id=${rpcId}, elapsed=${elapsed}ms`);
            reject(new SerializationError(`rpc response missing result and error: ${method}`));
          }
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
        timer,
      };

      // 入队并触发 drain
      if (backgroundRpc) {
        this._backgroundRpcQueue.push({
          rpcId, method, payload, pending, tStart, timeoutMs: effectiveTimeout, background: true,
        });
      } else {
        this._rpcQueue.push({
          rpcId, method, payload, pending, tStart, timeoutMs: effectiveTimeout, background: false,
        });
      }
      this._drainRpcQueue();
    });
  }

  /** 发送 JSON-RPC 2.0 Notification，不分配 id，也不等待响应。 */
  async notify(method: string, params?: RpcParams | null): Promise<void> {
    if (this._closed || !this._ws) {
      throw this._notConnectedError();
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
    try {
      this._ws.send(payload);
      this._log.debug(`notification sent: method=${normalizedMethod}, size=${payloadSize}`);
    } catch (err) {
      throw new ConnectionError(`failed to send notification ${normalizedMethod}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /** 从 pending / queue 中移除指定 RPC */
  private _removeRpc(rpcId: string, pending?: PendingRpc): void {
    const current = this._pending.get(rpcId);
    if (current && (!pending || current === pending)) {
      this._pending.delete(rpcId);
      this._pendingBackground.delete(rpcId);
    }
    if (this._rpcQueue.length > 0) {
      this._rpcQueue = this._rpcQueue.filter((entry) => entry.rpcId !== rpcId || (pending !== undefined && entry.pending !== pending));
    }
    if (this._backgroundRpcQueue.length > 0) {
      this._backgroundRpcQueue = this._backgroundRpcQueue.filter((entry) => entry.rpcId !== rpcId || (pending !== undefined && entry.pending !== pending));
    }
  }

  /** 从队列中取出 RPC 并发送，直到 inflight 达到上限 */
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
          this._log.warn(`RPC queue timeout: method=${entry.method}, id=${entry.rpcId}, elapsed=${elapsed}ms, timeout=${entry.timeoutMs}ms`);
          entry.pending.reject(new TimeoutError(`rpc timeout before send: ${entry.method}`, { retryable: true }));
          continue;
        }

        this._pending.set(entry.rpcId, entry.pending);
        if (entry.background) {
          this._pendingBackground.add(entry.rpcId);
        }
        try {
          this._ws.send(entry.payload);
          this._log.debug(`RPC request sent: method=${entry.method}, id=${entry.rpcId}, background=${entry.background}`);
        } catch (err) {
          this._removeRpc(entry.rpcId, entry.pending);
          this._log.error(`RPC send failed: method=${entry.method}, id=${entry.rpcId}, error=${String(err)}`, err instanceof Error ? err : undefined);
          entry.pending.reject(
            new ConnectionError(`failed to send rpc ${entry.method}: ${err instanceof Error ? err.message : String(err)}`),
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

      this._log.info(traceDisplay(method, status, elapsedMs, respTrace, spans));

      if (this._traceObserver !== null) {
        this._traceObserver({ type: 'rpc', method, trace: enriched, status, duration_ms: elapsedMs });
      }
    } catch (err) {
      this._log.debug(`trace handling raised: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // ── 内部消息处理 ──────────────────────────────────

  private _handleMessage(data: string | JsonObject): void {
    try {
      const message = this._decodeMessage(data);
      this._routeMessage(message);
    } catch (exc) {
      this._log.warn('message decode exception:', exc);
    }
  }

  private _handleClose(event: CloseEvent): void {
    const wasClosed = this._closed;
    this._closed = true;
    this._lastCloseCode = event.code;
    this._lastCloseReason = event.reason ?? '';

    // 拒绝所有待处理调用
    const err = new ConnectionError(`websocket closed: code=${event.code}`);
    for (const [, pending] of this._pending) {
      clearTimeout(pending.timer);
      pending.reject(err);
    }
    this._pending.clear();
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

    // 非主动关闭时触发断线回调
    if (!wasClosed) {
      const error = new ConnectionError(`websocket closed: code=${event.code} reason=${event.reason}`);
      this._dispatcher.publish('connection.error', { error });
      if (this._onDisconnect) {
        this._onDisconnect(error, event.code).catch(exc => this._log.warn('[aun_core.transport] disconnect callback exception:', exc));
      }
    }
  }

  private _notConnectedError(): ConnectionError {
    if (this._lastCloseCode !== null) {
      const reason = this._lastCloseReason ? ` reason=${this._lastCloseReason}` : '';
      return new ConnectionError(`transport not connected: last websocket close code=${this._lastCloseCode}${reason}`);
    }
    return new ConnectionError('transport not connected');
  }

  private _routeMessage(message: RpcMessage): void {
    // RPC 响应（有 id 字段）
    if ('id' in message) {
      const rpcId = String(message.id);
      const pending = this._pending.get(rpcId);
      if (pending) {
        this._pending.delete(rpcId);
        this._pendingBackground.delete(rpcId);
        pending.resolve(message);
        this._drainRpcQueue();
      } else {
        // H23: 未知 id 多数是超时后到达的慢响应；打 warn 便于排查，避免被完全吞掉
        this._log.warn('[aun_core.transport] recv unknown rpc response (maybe arrived after timeout): id=' + rpcId);
      }
      return;
    }

    const method = String(message.method ?? '');

    // challenge 消息
    if (method === 'challenge') {
      this._challenge = message;
      this._log.debug('challenge received');
      this._dispatcher.publish('connection.challenge', message.params ?? {});
      return;
    }

    // 事件推送
    if (method.startsWith('event/')) {
      const protocolEvent = method.slice(6);
      const sdkEvent = EVENT_NAME_MAP[protocolEvent] ?? protocolEvent;
      this._log.debug(`event recv: event=${sdkEvent} ${summarizeDict(message.params, DIAG_RESULT_FIELDS)}`);
      const meta = (message as Record<string, unknown>)._meta;
      if (this._metaObserver !== null && isJsonObject(meta)) {
        try {
          this._metaObserver(meta as JsonObject);
        } catch (exc) {
          this._log.debug(`event meta_observer raised: ${String(exc)}`);
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
          this._log.info(`[trace=${String(traceObj.trace_id ?? '')}] event_recv event=${sdkEvent}`);
        }
      }
      // 发布为 _raw.{event}，由 AUNClient 处理后再发布用户可见的事件
      if (sdkEvent.startsWith('app.')) {
        this._dispatcher.publish(sdkEvent, params as unknown as JsonValue);
        return;
      }
      this._dispatcher.publish(`_raw.${sdkEvent}`, params as unknown as import('./types.js').JsonValue);
      return;
    }

    // 其他通知
    const meta = (message as Record<string, unknown>)._meta;
    if (this._metaObserver !== null && isJsonObject(meta)) {
      try {
        this._metaObserver(meta as JsonObject);
      } catch (exc) {
        this._log.debug(`notification meta_observer raised: ${String(exc)}`);
      }
    }
    this._log.debug(`notification recv: method=${method || '<no-method>'}`);
    this._dispatcher.publish('notification', message);
  }

  private _decodeMessage(raw: string | JsonObject): RpcMessage {
    if (isJsonObject(raw)) {
      return raw as RpcMessage;
    }
    if (typeof raw !== 'string') {
      throw new SerializationError(`unsupported websocket payload type: ${typeof raw}`);
    }
    try {
      const parsed = JSON.parse(raw) as JsonValue;
      if (!isJsonObject(parsed)) {
        throw new SerializationError('invalid json payload');
      }
      return parsed as RpcMessage;
    } catch {
      throw new SerializationError('invalid json payload');
    }
  }
}
