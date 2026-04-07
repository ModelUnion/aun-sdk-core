// ── events 模块单元测试 ──────────────────────────────────────
import { describe, it, expect, vi } from 'vitest';
import { EventDispatcher, Subscription } from '../../src/events.js';

describe('EventDispatcher', () => {
  it('subscribe 应返回 Subscription 实例', () => {
    const dispatcher = new EventDispatcher();
    const sub = dispatcher.subscribe('test', () => {});
    expect(sub).toBeInstanceOf(Subscription);
  });

  it('publish 应按顺序调用所有处理器', async () => {
    const dispatcher = new EventDispatcher();
    const calls: number[] = [];
    dispatcher.subscribe('evt', () => { calls.push(1); });
    dispatcher.subscribe('evt', () => { calls.push(2); });

    await dispatcher.publish('evt', { data: 'hello' });
    expect(calls).toEqual([1, 2]);
  });

  it('publish 应传递 payload', async () => {
    const dispatcher = new EventDispatcher();
    const handler = vi.fn();
    dispatcher.subscribe('evt', handler);

    const payload = { key: 'value', num: 42 };
    await dispatcher.publish('evt', payload);
    expect(handler).toHaveBeenCalledWith(payload);
  });

  it('unsubscribe 后不应再收到事件', async () => {
    const dispatcher = new EventDispatcher();
    const handler = vi.fn();
    const sub = dispatcher.subscribe('evt', handler);

    await dispatcher.publish('evt', 1);
    expect(handler).toHaveBeenCalledTimes(1);

    sub.unsubscribe();
    await dispatcher.publish('evt', 2);
    expect(handler).toHaveBeenCalledTimes(1); // 不再调用
  });

  it('重复 unsubscribe 应安全幂等', () => {
    const dispatcher = new EventDispatcher();
    const sub = dispatcher.subscribe('evt', () => {});
    sub.unsubscribe();
    sub.unsubscribe(); // 不应抛异常
  });

  it('publish 不存在的事件应安全返回', async () => {
    const dispatcher = new EventDispatcher();
    await dispatcher.publish('nonexistent', {}); // 不应抛异常
  });

  it('处理器异常不应影响后续处理器执行', async () => {
    const dispatcher = new EventDispatcher();
    const calls: number[] = [];
    dispatcher.subscribe('evt', () => { throw new Error('boom'); });
    dispatcher.subscribe('evt', () => { calls.push(2); });

    // 应不抛异常，且第二个处理器正常执行
    await dispatcher.publish('evt', null);
    expect(calls).toEqual([2]);
  });

  it('应支持异步处理器', async () => {
    const dispatcher = new EventDispatcher();
    const calls: number[] = [];
    dispatcher.subscribe('evt', async () => {
      await new Promise(r => setTimeout(r, 10));
      calls.push(1);
    });
    dispatcher.subscribe('evt', () => { calls.push(2); });

    await dispatcher.publish('evt', null);
    // 异步处理器先完成，同步处理器后执行
    expect(calls).toEqual([1, 2]);
  });

  it('不同事件名应隔离', async () => {
    const dispatcher = new EventDispatcher();
    const handlerA = vi.fn();
    const handlerB = vi.fn();
    dispatcher.subscribe('a', handlerA);
    dispatcher.subscribe('b', handlerB);

    await dispatcher.publish('a', 'dataA');
    expect(handlerA).toHaveBeenCalledTimes(1);
    expect(handlerB).not.toHaveBeenCalled();
  });
});
