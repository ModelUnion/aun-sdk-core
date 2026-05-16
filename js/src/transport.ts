// ── RPC Transport（浏览器原生 WebSocket）──────────────────

import { EventDispatcher } from './events.js';
import type { ModuleLogger } from './logger.js';
import {
  ConnectionError,
  SerializationError,
  TimeoutError,
  mapRemoteError,
} from './errors.js';
import { isJsonObject, type JsonObject, type JsonValue, type RpcMessage, type RpcParams, type RpcResult } from './types.js';


const _noopLog: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };

/** RPC 请求递增计数器，避免 Date.now() 高并发碰撞 */
let _rpcIdCounter = 0;

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
  'owner_aid', 'rotated_by', 'action',
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
  private _challenge: RpcMessage | null = null;
  private _pending: Map<string, {
    resolve: (value: RpcMessage) => void;
    reject: (error: Error) => void;
  }> = new Map();

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
    this._log.debug(`close enter: pending_rpc=${pendingCount}`);
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
      pending.reject(new ConnectionError('transport closed'));
    }
    this._pending.clear();
    this._log.debug(`close exit: elapsed=${Date.now() - tStart}ms`);
  }

  /**
   * 发起 JSON-RPC 2.0 调用。
   * 返回 result 字段的值；若有 error 字段则抛出映射后的错误。
   */
  async call(
    method: string,
    params?: RpcParams | null,
    timeout?: number,
  ): Promise<RpcResult> {
    if (this._closed || !this._ws) {
      throw new ConnectionError('transport not connected');
    }

    // 生成唯一 RPC ID（递增计数器，避免高并发碰撞）
    const rpcId = `rpc-${String(++_rpcIdCounter).padStart(6, '0')}`;
    const effectiveTimeout = (timeout ?? this._timeout) * 1000;
    const tStart = Date.now();

    const promise = new Promise<RpcMessage>((resolve, reject) => {
      this._pending.set(rpcId, { resolve, reject });
    });

    // 发送请求
    try {
      this._ws.send(JSON.stringify({
        jsonrpc: '2.0',
        id: rpcId,
        method,
        params: params ?? {},
      }));
      this._log.debug(`RPC request sent: method=${method}, id=${rpcId} ${summarizeDict(params, DIAG_PARAM_FIELDS)}`);
    } catch (exc) {
      this._pending.delete(rpcId);
      this._log.error(`RPC send failed: method=${method}, id=${rpcId}, error=${String(exc)}`, exc instanceof Error ? exc : undefined);
      throw new ConnectionError(`failed to send rpc ${method}: ${exc}`);
    }

    // 超时控制（H23 修复：成功路径必须 clearTimeout，避免定时器泄漏 + 慢响应被静默丢弃）
    let timeoutHandle: ReturnType<typeof globalThis.setTimeout> | null = null;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutHandle = globalThis.setTimeout(() => {
        this._pending.delete(rpcId);
        this._log.warn(`RPC timeout: method=${method}, id=${rpcId}, elapsed=${Date.now() - tStart}ms, timeout=${effectiveTimeout}ms`);
        reject(new TimeoutError(`rpc timeout: ${method}`, { retryable: true }));
      }, effectiveTimeout);
    });

    try {
      const response = await Promise.race([promise, timeoutPromise]);

      const elapsed = Date.now() - tStart;
      if (response.error !== undefined) {
        this._log.debug(`RPC error response: method=${method}, id=${rpcId}, elapsed=${elapsed}ms, error=${JSON.stringify(response.error)}`);
        throw mapRemoteError(response.error);
      }
      if (response.result === undefined) {
        throw new SerializationError(`rpc response missing result and error: ${method}`);
      }
      this._log.debug(`RPC response ok: method=${method}, id=${rpcId}, elapsed=${elapsed}ms ${summarizeDict(response.result, DIAG_RESULT_FIELDS)}`);
      return response.result;
    } finally {
      if (timeoutHandle !== null) {
        globalThis.clearTimeout(timeoutHandle);
      }
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

    // 拒绝所有待处理调用
    for (const [, pending] of this._pending) {
      pending.reject(new ConnectionError(`websocket closed: code=${event.code}`));
    }
    this._pending.clear();

    // 非主动关闭时触发断线回调
    if (!wasClosed) {
      const error = new ConnectionError(`websocket closed: code=${event.code} reason=${event.reason}`);
      this._dispatcher.publish('connection.error', { error });
      if (this._onDisconnect) {
        this._onDisconnect(error, event.code).catch(exc => this._log.warn('[aun_core.transport] disconnect callback exception:', exc));
      }
    }
  }

  private _routeMessage(message: RpcMessage): void {
    // RPC 响应（有 id 字段）
    if ('id' in message) {
      const rpcId = String(message.id);
      const pending = this._pending.get(rpcId);
      if (pending) {
        this._pending.delete(rpcId);
        pending.resolve(message);
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
      // 发布为 _raw.{event}，由 AUNClient 处理后再发布用户可见的事件
      this._dispatcher.publish(`_raw.${sdkEvent}`, message.params ?? {});
      return;
    }

    // 其他通知
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
