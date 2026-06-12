import { describe, it, expect, vi } from 'vitest';
import { EventDispatcher } from '../../src/events.js';
import { RPCTransport } from '../../src/transport.js';

describe('RPCTransport WebSocket 写保护', () => {
  it('同一 transport 的底层 send 应通过 send chain 顺序执行', async () => {
    const writes: string[] = [];
    const ws = {
      send: vi.fn((payload: string) => {
        writes.push(payload);
      }),
    };
    const transport = new RPCTransport({ eventDispatcher: new EventDispatcher() });
    (transport as any)._closed = false;
    (transport as any)._ws = ws;

    const first = (transport as any)._sendText('first', 'first');
    const second = (transport as any)._sendText('second', 'second');

    expect(writes).toEqual([]);
    await first;
    expect(writes).toEqual(['first']);
    await second;
    expect(writes).toEqual(['first', 'second']);
  });
});
