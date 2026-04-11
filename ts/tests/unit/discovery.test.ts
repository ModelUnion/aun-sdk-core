import * as http from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { GatewayDiscovery } from '../../src/discovery.js';

describe('GatewayDiscovery', () => {
  let server: http.Server | null = null;
  let baseUrl = '';

  beforeEach(async () => {
    server = http.createServer((req, res) => {
      if (req.url === '/ok') {
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({
          gateways: [
            { url: 'ws://gw2', priority: 5 },
            { url: 'ws://gw1', priority: 1 },
          ],
        }));
        return;
      }
      if (req.url === '/invalid') {
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ gateways: [] }));
        return;
      }
      res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('unavailable');
    });

    await new Promise<void>((resolve) => {
      server!.listen(0, '127.0.0.1', () => resolve());
    });

    const address = server.address();
    if (!address || typeof address === 'string') {
      throw new Error('failed to bind test http server');
    }
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterEach(async () => {
    if (!server) {
      return;
    }
    await new Promise<void>((resolve, reject) => {
      server!.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });
    server = null;
    baseUrl = '';
  });

  it('按 priority 选择最优 gateway', async () => {
    const discovery = new GatewayDiscovery({ verifySsl: true });
    await expect(discovery.discover(`${baseUrl}/ok`, 1234))
      .resolves.toBe('ws://gw1');
  });

  it('HTTP 非 2xx 时应抛出 ConnectionError', async () => {
    const discovery = new GatewayDiscovery({ verifySsl: true });
    await expect(discovery.discover(`${baseUrl}/unavailable`))
      .rejects.toThrow(`gateway discovery failed for ${baseUrl}/unavailable: HTTP 503`);
  });

  it('空 gateways 应抛出 ValidationError', async () => {
    const discovery = new GatewayDiscovery({ verifySsl: true });
    await expect(discovery.discover(`${baseUrl}/invalid`))
      .rejects.toThrow('well-known returned empty gateways');
  });
});
