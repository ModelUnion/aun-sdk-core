/**
 * Service Proxy 单域 Docker E2E。
 *
 * 运行：
 *   cd /workspace/ts && npx vitest run tests/e2e/service-proxy.test.ts --reporter=verbose
 */

import { afterEach, describe, expect, it } from 'vitest';

import { ServiceProxyClient } from '../../src/service-proxy.js';
import {
  SERVICE_PROXY_EXPECTED_REQUESTS,
  connectServiceProxyProvider,
  makeServiceProxyProviderClient,
  preflightServiceProxy,
  registerServiceProxyTestServices,
  runServiceProxyVisitorChecks,
  serviceProxyRunId,
  startServiceProxyBackend,
  waitForResult,
  waitServiceProxyRegistered,
} from '../service-proxy-e2e-helper.js';
import type { AUNClient } from '../../src/client.js';

process.env.AUN_ENV ??= 'development';

const TEST_TIMEOUT = 120_000;
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

describe('Service Proxy 单域 Docker E2E', () => {
  const clients: AUNClient[] = [];

  afterEach(async () => {
    await Promise.allSettled(clients.map(client => client.close()));
    clients.length = 0;
  });

  it('TS provider 通过真实 service_proxy 暴露 HTTP/SSE/File/WebSocket 服务', async () => {
    await preflightServiceProxy(ISSUER);
    const rid = serviceProxyRunId();
    const providerAid = `ts-sp-${rid}.${ISSUER}`;
    const aunClient = makeServiceProxyProviderClient(rid);
    clients.push(aunClient);
    const backend = await startServiceProxyBackend(providerAid);
    const proxyClient = new ServiceProxyClient({ providerAid, aunClient });
    let serveTask: Promise<Record<string, unknown>> | undefined;
    try {
      await connectServiceProxyProvider(aunClient, providerAid);
      registerServiceProxyTestServices(proxyClient, backend.baseHttp, backend.baseWs);
      serveTask = proxyClient.serveOnce({ maxRequests: SERVICE_PROXY_EXPECTED_REQUESTS });
      await waitServiceProxyRegistered(ISSUER, 4, serveTask);
      await runServiceProxyVisitorChecks(providerAid, ISSUER);
      const result = await waitForResult(serveTask, 10_000);
      expect(result.registered).toBe(4);
      expect(result.handled_requests).toBe(SERVICE_PROXY_EXPECTED_REQUESTS);
    } finally {
      proxyClient.stop();
      await backend.close();
      if (serveTask) await Promise.allSettled([serveTask]);
    }
  }, TEST_TIMEOUT);
});
