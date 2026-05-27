/**
 * AUN SDK 事件调度器
 *
 * 与 Python SDK 的 EventDispatcher 完全对齐：订阅、取消订阅、发布。
 */

import type { JsonValue } from './types.js';
import type { ModuleLogger } from './logger.js';

const _noopLogger: ModuleLogger = {
  error: () => {},
  warn:  () => {},
  info:  () => {},
  debug: () => {},
};

export type EventPayload =
  | JsonValue
  | Error
  | { [key: string]: JsonValue | Error };

export type EventHandler = (payload: EventPayload) => void | Promise<void>;

function isPromiseLike<T = void>(value: unknown): value is PromiseLike<T> {
  return Boolean(value && typeof (value as { then?: unknown }).then === 'function');
}

/**
 * 订阅句柄，调用 unsubscribe() 取消订阅。
 */
export class Subscription {
  private _dispatcher: EventDispatcher;
  private _event: string;
  private _handler: EventHandler;
  private _active = true;

  /** @internal */
  constructor(dispatcher: EventDispatcher, event: string, handler: EventHandler) {
    this._dispatcher = dispatcher;
    this._event = event;
    this._handler = handler;
  }

  /** 取消该订阅 */
  unsubscribe(): void {
    if (!this._active) return;
    this._dispatcher.unsubscribe(this._event, this._handler);
    this._active = false;
  }
}

/**
 * 事件调度器：管理事件处理器的注册与派发。
 *
 * 线程安全说明：本实现依赖 Node.js 单线程事件循环模型，
 * _handlers 的读写在同一微任务中完成，无需额外的并发保护。
 * 若未来需要在 Worker 线程中共享同一实例，须引入锁或消息传递机制。
 */
export class EventDispatcher {
  private _logger: ModuleLogger;
  private _handlers: Map<string, EventHandler[]> = new Map();

  constructor(logger?: ModuleLogger) {
    this._logger = logger ?? _noopLogger;
  }

  /** 订阅指定事件，返回 Subscription 句柄 */
  subscribe(event: string, handler: EventHandler): Subscription {
    let handlers = this._handlers.get(event);
    if (!handlers) {
      handlers = [];
      this._handlers.set(event, handlers);
    }
    handlers.push(handler);
    return new Subscription(this, event, handler);
  }

  /** 移除指定事件的指定处理器 */
  unsubscribe(event: string, handler: EventHandler): void {
    const handlers = this._handlers.get(event);
    if (!handlers) return;
    const filtered = handlers.filter((h) => h !== handler);
    if (filtered.length === 0) {
      this._handlers.delete(event);
    } else {
      this._handlers.set(event, filtered);
    }
  }

  private _invokeHandler(event: string, handler: EventHandler, payload: EventPayload): void | Promise<void> {
    try {
      const result = handler(payload);
      if (isPromiseLike(result)) {
        return Promise.resolve(result).catch((exc) => {
          this._logger.warn(`event ${event} handler ${handler.name || '<anonymous>'} threw: ${exc instanceof Error ? exc.message : String(exc)}`);
        });
      }
    } catch (exc) {
      // 与 Python SDK 一致：处理器异常不阻断其他处理器
      this._logger.warn(`event ${event} handler ${handler.name || '<anonymous>'} threw: ${exc instanceof Error ? exc.message : String(exc)}`);
    }
  }

  /**
   * 同步优先发布事件。
   *
   * 消息交付路径会在应用 handler 返回后立即推进已交付游标；同步 handler
   * 不能被 async publish 人为延后一轮微任务，否则应用侧刚收到事件就可能读到旧游标。
   * 若 handler 返回 Promise，仍按原语义等待它完成后再继续。
   */
  publishSyncAware(event: string, payload: EventPayload): void | Promise<void> {
    const handlers = this._handlers.get(event);
    if (!handlers) return;
    const snapshot = [...handlers];
    let chain: Promise<void> | undefined;
    for (const handler of snapshot) {
      if (chain) {
        chain = chain.then(() => {
          const result = this._invokeHandler(event, handler, payload);
          return isPromiseLike(result) ? result : undefined;
        });
        continue;
      }
      const result = this._invokeHandler(event, handler, payload);
      if (isPromiseLike(result)) {
        chain = Promise.resolve(result);
      }
    }
    return chain;
  }

  /** 发布事件，按注册顺序调用所有处理器（支持异步） */
  async publish(event: string, payload: EventPayload): Promise<void> {
    const result = this.publishSyncAware(event, payload);
    if (isPromiseLike(result)) await result;
  }
}
