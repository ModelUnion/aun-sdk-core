import { afterEach, describe, expect, it, vi } from 'vitest';
import { GatewayDiscovery } from '../../src/discovery.js';

const okPayload = {
  gateways: [
    { url: 'ws://gw2', priority: 5 },
    { url: 'ws://gw1', priority: 1 },
  ],
};
const wellKnownUrl = 'https://agentid.pub/.well-known/aun-gateway';

function wellKnownFetchCount(fetchMock: ReturnType<typeof vi.spyOn>): number {
  return fetchMock.mock.calls.filter(([url]) => String(url) === wellKnownUrl).length;
}

describe('GatewayDiscovery', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('按 priority 选择最优 gateway', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => okPayload,
    } as Response);

    const discovery = new GatewayDiscovery();
    await expect(discovery.discover(wellKnownUrl))
      .resolves.toBe('ws://gw1');
    expect(wellKnownFetchCount(fetchMock)).toBe(1);
  });

  it('发现端点瞬时断连时应短重试后成功', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(new TypeError('socket hang up'))
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          gateways: [{ url: 'ws://gw-flaky', priority: 1 }],
        }),
      } as Response);

    const discovery = new GatewayDiscovery();
    await expect(discovery.discover(wellKnownUrl))
      .resolves.toBe('ws://gw-flaky');
    expect(wellKnownFetchCount(fetchMock)).toBe(2);
  });

  it('HTTP 非 2xx 不应重试', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      status: 503,
      json: async () => ({}),
    } as Response);

    const discovery = new GatewayDiscovery();
    await expect(discovery.discover(wellKnownUrl))
      .rejects.toThrow('HTTP 503');
    expect(wellKnownFetchCount(fetchMock)).toBe(1);
  });
});
