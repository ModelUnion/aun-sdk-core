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

import { ConnectionError, SerializationError, TimeoutError, mapRemoteError } from './errors.js';
import type { EventDispatcher } from './events.js';
import type { ModuleLogger } from './logger.js';
import { isJsonObject, type JsonObject, type JsonValue, type RpcMessage, type RpcParams, type RpcResult } from './types.js';

const _noopLogger: ModuleLogger = {
  error: () => {},
  warn:  () => {},
  info:  () => {},
  debug: () => {},
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

/** 协议事件名映射 */
const EVENT_NAME_MAP: Record<string, string> = {
  'message.received': 'message.received',
  'message.recalled': 'message.recalled',
  'message.ack': 'message.ack',
  'group.changed': 'group.changed',
  'group.message_created': 'group.message_created',
  'storage.object_changed': 'storage.object_changed',
};

/** 断线回调，closeCode 为 WebSocket close code（1006 = 网络异常断开，其他 = 服务端主动关闭） */
export type DisconnectCallback = (error: Error | null, closeCode?: number) => void | Promise<void>;

/**
 * WebSocket JSON-RPC 2.0 传输层
 */
export class RPCTransport {
  private _logger: ModuleLogger;
  private _dispatcher: EventDispatcher;
  private _timeout: number;
  private _onDisconnect: DisconnectCallback | null;
  private _verifySsl: boolean;
  private _ws: WebSocket | null = null;
  private _closed = true;
  private _challenge: RpcMessage | null = null;
  private _pending: Map<string, {
    resolve: (value: RpcMessage) => void;
    reject: (reason: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = new Map();
  private _idCounter = 0;

  constructor(opts: {
    eventDispatcher: EventDispatcher;
    timeout?: number;
    onDisconnect?: DisconnectCallback | null;
    verifySsl?: boolean;
    logger?: ModuleLogger;
  }) {
    this._logger = opts.logger ?? _noopLogger;
    this._dispatcher = opts.eventDispatcher;
    this._timeout = opts.timeout ?? 10_000;
    this._onDisconnect = opts.onDisconnect ?? null;
    this._verifySsl = opts.verifySsl ?? true;
  }

  /** 设置默认 RPC 超时（毫秒） */
  setTimeout(timeout: number): void {
    this._timeout = timeout;
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
    this._logger.debug(`close enter: pending_rpc=${pendingCount}`);
    this._closed = true;
    // 取消所有待处理的 RPC
    for (const [id, pending] of this._pending) {
      clearTimeout(pending.timer);
      pending.reject(new ConnectionError('transport closed'));
    }
    this._pending.clear();
    this._logger.debug(`close: cancelled ${pendingCount} pending rpc(s)`);

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
        const finish = (): void => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          try { ws.removeAllListeners(); } catch { /* noop */ }
          try { ws.terminate?.(); } catch { /* noop */ }
          this._logger.debug(`close exit: elapsed=${Date.now() - tStart}ms`);
          resolve();
        };
        ws.on('close', finish);
        try {
          ws.close();
        } catch {
          finish();
          return;
        }
        // 超时强制解析，并在定时器触发时通过 terminate() 彻底清理残留 socket
        const timer = setTimeout(finish, 3_000);
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
  ): Promise<RpcResult> {
    if (this._closed || !this._ws) {
      throw new ConnectionError('transport not connected');
    }

    const rpcId = `rpc-${crypto.randomBytes(8).toString('hex')}`;
    const effectiveTimeout = timeout ?? this._timeout;
    const tStart = Date.now();

    return new Promise<RpcResult>((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pending.delete(rpcId);
        this._logger.warn(`RPC timeout: method=${method}, id=${rpcId}, elapsed=${Date.now() - tStart}ms, timeout=${effectiveTimeout}ms`);
        reject(new TimeoutError(`rpc timeout: ${method}`, { retryable: true }));
      }, effectiveTimeout);

      this._pending.set(rpcId, {
        resolve: (response) => {
          clearTimeout(timer);
          const elapsed = Date.now() - tStart;
          if (response.error !== undefined) {
            this._logger.debug(`RPC error response: method=${method}, id=${rpcId}, elapsed=${elapsed}ms, error=${JSON.stringify(response.error)}`);
            reject(mapRemoteError(response.error));
          } else if (response.result !== undefined) {
            this._logger.debug(`RPC response ok: method=${method}, id=${rpcId}, elapsed=${elapsed}ms ${summarizeDict(response.result, DIAG_RESULT_FIELDS)}`);
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
      });

      const payload = JSON.stringify({
        jsonrpc: '2.0',
        id: rpcId,
        method,
        params: params ?? {},
      });

      try {
        this._ws!.send(payload);
        this._logger.debug(`RPC request sent: method=${method}, id=${rpcId} ${summarizeDict(params, DIAG_PARAM_FIELDS)}`);
      } catch (err) {
        this._pending.delete(rpcId);
        clearTimeout(timer);
        this._logger.error(`RPC send failed: method=${method}, id=${rpcId}, error=${err instanceof Error ? err.message : String(err)}`);
        reject(
          new ConnectionError(
            `failed to send rpc ${method}: ${err instanceof Error ? err.message : String(err)}`,
          ),
        );
      }
    });
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
      this._logger.debug(`WebSocket closed: code=${code}, intentional close=${wasClosed}`);
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
        pending.resolve(message);
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
      // 发布为 _raw.{event}，由 AUNClient 处理后再发布用户可见的事件
      this._dispatcher.publish(`_raw.${sdkEvent}`, message.params ?? {});
      return;
    }

    // 其他通知
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
