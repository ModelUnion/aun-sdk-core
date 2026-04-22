// ── 事件调度器 ──────────────────────────────────────────

import type { JsonValue } from './types.js';

/** 事件处理函数类型 */
export type EventPayload =
  | JsonValue
  | Error
  | { [key: string]: JsonValue | Error };

export type EventHandler = (payload: EventPayload) => void | Promise<void>;

/** 订阅句柄，调用 unsubscribe() 取消监听 */
export class Subscription {
  private _dispatcher: EventDispatcher;
  private _event: string;
  private _handler: EventHandler;
  private _active = true;

  constructor(dispatcher: EventDispatcher, event: string, handler: EventHandler) {
    this._dispatcher = dispatcher;
    this._event = event;
    this._handler = handler;
  }

  /** 取消订阅 */
  unsubscribe(): void {
    if (!this._active) return;
    this._dispatcher.unsubscribe(this._event, this._handler);
    this._active = false;
  }
}

/** 事件调度器：支持订阅、取消订阅、发布（同步/异步处理函数） */
export class EventDispatcher {
  private _handlers: Map<string, EventHandler[]> = new Map();

  /**
   * 订阅事件，返回订阅句柄。
   *
   * 注意：unsubscribe() 使用引用相等（===）匹配 handler。若传入匿名函数，
   * 将无法通过 off(event, handler) 取消订阅——应使用返回的 Subscription
   * 对象调用 unsubscribe() 来取消。
   */
  subscribe(event: string, handler: EventHandler): Subscription {
    const list = this._handlers.get(event) ?? [];
    list.push(handler);
    this._handlers.set(event, list);
    return new Subscription(this, event, handler);
  }

  /** 取消订阅 */
  unsubscribe(event: string, handler: EventHandler): void {
    const list = this._handlers.get(event);
    if (!list) return;
    const filtered = list.filter((h) => h !== handler);
    if (filtered.length > 0) {
      this._handlers.set(event, filtered);
    } else {
      this._handlers.delete(event);
    }
  }

  /** 发布事件（依次调用所有处理函数，支持异步） */
  async publish(event: string, payload: EventPayload): Promise<void> {
    // 浅拷贝 handler 列表：防止迭代过程中 subscribe/unsubscribe 修改原数组导致跳过或重复执行。
    // 浏览器单线程事件循环模型下，浅拷贝即可保证并发安全（无需锁机制）。
    const handlers = [...(this._handlers.get(event) ?? [])];
    for (const handler of handlers) {
      try {
        const result = handler(payload);
        if (result instanceof Promise) {
          await result;
        }
      } catch (exc) {
        console.warn(`事件 ${event} 处理器执行异常:`, exc);
      }
    }
  }
}
