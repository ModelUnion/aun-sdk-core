/**
 * 事件调度器单元测试
 */

import { describe, it, expect, vi } from 'vitest';
import { EventDispatcher } from '../../src/events.js';
import type { JsonValue } from '../../src/types.js';

describe('EventDispatcher', () => {
  it('订阅后收到发布的事件', async () => {
    const dispatcher = new EventDispatcher();
    const received: JsonValue[] = [];
    dispatcher.subscribe('test', (data) => {
      received.push(data);
    });

    await dispatcher.publish('test', { msg: 'hello' });
    expect(received).toEqual([{ msg: 'hello' }]);
  });

  it('取消订阅后不再收到事件', async () => {
    const dispatcher = new EventDispatcher();
    const received: JsonValue[] = [];
    const sub = dispatcher.subscribe('test', (data) => {
      received.push(data);
    });

    await dispatcher.publish('test', 'first');
    sub.unsubscribe();
    await dispatcher.publish('test', 'second');

    expect(received).toEqual(['first']);
  });

  it('多个处理器都能收到事件', async () => {
    const dispatcher = new EventDispatcher();
    const r1: JsonValue[] = [];
    const r2: JsonValue[] = [];
    dispatcher.subscribe('test', (data) => r1.push(data));
    dispatcher.subscribe('test', (data) => r2.push(data));

    await dispatcher.publish('test', 42);
    expect(r1).toEqual([42]);
    expect(r2).toEqual([42]);
  });

  it('不同事件互不干扰', async () => {
    const dispatcher = new EventDispatcher();
    const r1: JsonValue[] = [];
    const r2: JsonValue[] = [];
    dispatcher.subscribe('evt1', (data) => r1.push(data));
    dispatcher.subscribe('evt2', (data) => r2.push(data));

    await dispatcher.publish('evt1', 'a');
    await dispatcher.publish('evt2', 'b');

    expect(r1).toEqual(['a']);
    expect(r2).toEqual(['b']);
  });

  it('支持异步处理器', async () => {
    const dispatcher = new EventDispatcher();
    const received: JsonValue[] = [];
    dispatcher.subscribe('async', async (data) => {
      await new Promise((r) => setTimeout(r, 5));
      received.push(data);
    });

    await dispatcher.publish('async', 'delayed');
    expect(received).toEqual(['delayed']);
  });

  it('处理器异常不阻断其他处理器', async () => {
    const dispatcher = new EventDispatcher();
    const received: JsonValue[] = [];
    // 第一个处理器抛出异常
    dispatcher.subscribe('test', () => {
      throw new Error('boom');
    });
    // 第二个处理器正常执行
    dispatcher.subscribe('test', (data) => {
      received.push(data);
    });

    // 应该不抛异常，第二个处理器正常收到事件
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await dispatcher.publish('test', 'ok');
    warnSpy.mockRestore();

    expect(received).toEqual(['ok']);
  });

  it('发布无订阅者的事件不报错', async () => {
    const dispatcher = new EventDispatcher();
    // 应该不抛异常
    await dispatcher.publish('nonexistent', 'data');
  });

  it('重复取消订阅是安全的', () => {
    const dispatcher = new EventDispatcher();
    const sub = dispatcher.subscribe('test', () => {});
    sub.unsubscribe();
    sub.unsubscribe(); // 第二次调用不应报错
  });
});
