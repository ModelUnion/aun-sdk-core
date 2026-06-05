/**
 * Service Proxy 双域 Federation E2E。
 *
 * 运行：
 *   cd /workspace/ts && npx vitest run tests/integration/federation-service-proxy.test.ts --reporter=verbose
 */

import { afterEach, describe, expect, it } from 'vitest';

import { ServiceProxyClient } from '../../src/service-proxy.js';
import {
  SERVICE_PROXY_EXPECTED_REQUESTS,
  connectServiceProxyProvider,
  makeServiceProxyProviderClient,
  preflightServiceProxy,
  registerServiceProxyTestServices,
  runRemoteServiceProxyBoundaryCheck,
  runServiceProxyVisitorChecks,
  serviceProxyRunId,
  startServiceProxyBackend,
  waitForResult,
  waitServiceProxyRegistered,
} from '../service-proxy-e2e-helper.js';
import type { AUNClient } from '../../src/client.js';

process.env.AUN_ENV ??= 'development';

const TEST_TIMEOUT = 120_000;
const LOCAL_ISSUER = process.env.LOCAL_ISSUER ?? process.env.AUN_TEST_ISSUER_A ?? 'aid.com';
const REMOTE_ISSUER = process.env.REMOTE_ISSUER ?? process.env.AUN_TEST_ISSUER_B ?? 'aid.net';

describe('Service Proxy 双域 Federation E2E', () => {
  const clients: AUNClient[] = [];

  afterEach(async () => {
    await Promise.allSettled(clients.map(client => client.close()));
    clients.length = 0;
  });

  it('TS provider 只注册到本域 proxy，远端 proxy 不跨 issuer 串线', async () => {
    await preflightServiceProxy(LOCAL_ISSUER);
    await preflightServiceProxy(REMOTE_ISSUER);
    const rid = serviceProxyRunId();
    const providerAid = `ts-sp-fed-${rid}.${LOCAL_ISSUER}`;
    const aunClient = makeServiceProxyProviderClient(`fed-${rid}`);
    clients.push(aunClient);
    const backend = await startServiceProxyBackend(providerAid);
    const proxyClient = new ServiceProxyClient({ providerAid, aunClient });
    let serveTask: Promise<Record<string, unknown>> | undefined;
    try {
      await connectServiceProxyProvider(aunClient, providerAid);
      registerServiceProxyTestServices(proxyClient, backend.baseHttp, backend.baseWs);
      serveTask = proxyClient.serveOnce({ maxRequests: SERVICE_PROXY_EXPECTED_REQUESTS });
      await waitServiceProxyRegistered(LOCAL_ISSUER, 4, serveTask);
      await runServiceProxyVisitorChecks(providerAid, LOCAL_ISSUER);
      await runRemoteServiceProxyBoundaryCheck(providerAid, REMOTE_ISSUER);
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
