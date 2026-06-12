import { describe, it, expect, vi } from 'vitest';
import { EventDispatcher } from '../../src/events.js';
import { RPCTransport } from '../../src/transport.js';

describe('RPCTransport WebSocket 写保护', () => {
  it('同一 transport 的底层 send 应串行执行', async () => {
    let releaseFirst: (() => void) | null = null;
    const writes: string[] = [];
    const ws = {
      send: vi.fn((payload: string, cb: (err?: Error) => void) => {
        writes.push(payload);
        if (payload === 'first') {
          releaseFirst = () => cb();
          return;
        }
        cb();
      }),
    };
    const transport = new RPCTransport({ eventDispatcher: new EventDispatcher() });
    (transport as any)._closed = false;
    (transport as any)._ws = ws;

    const first = (transport as any)._sendText('first', 'first');
    const second = (transport as any)._sendText('second', 'second');
    await Promise.resolve();

    expect(writes).toEqual(['first']);
    expect(releaseFirst).toBeTypeOf('function');
    releaseFirst!();
    await Promise.all([first, second]);

    expect(writes).toEqual(['first', 'second']);
  });
});
