import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as os from 'node:os';
import * as path from 'node:path';
import type { AddressInfo } from 'node:net';
import { URL } from 'node:url';
import WebSocket, { WebSocketServer } from 'ws';

import { AUNClient } from '../src/client.js';
import { ServiceProxyClient } from '../src/service-proxy.js';
import { createTestClient, registerAndLoadIdentity } from './test-support.js';

type Dict = Record<string, unknown>;

export const SERVICE_PROXY_EXPECTED_REQUESTS = 7;

export function serviceProxyRunId(): string {
  return randomUUID().replace(/-/g, '').slice(0, 10);
}

export function serviceProxyUser(providerAid: string): string {
  return providerAid.split('.', 1)[0] ?? providerAid;
}

export function serviceProxyBase(issuer: string): string {
  const port = Number(process.env.AUN_SERVICE_PROXY_PORT ?? '19890');
  return `https://proxy.${issuer}:${port}`;
}

export function serviceProxyWsBase(issuer: string): string {
  const port = Number(process.env.AUN_SERVICE_PROXY_PORT ?? '19890');
  return `wss://proxy.${issuer}:${port}`;
}

export async function preflightServiceProxy(issuer: string): Promise<void> {
  console.log(`[service-proxy-e2e] preflight ${issuer}`);
  const response = await httpRequest('GET', `${serviceProxyBase(issuer)}/health`);
  if (response.status !== 200) {
    throw new Error(`${issuer} service_proxy health HTTP ${response.status}: ${response.body.toString('utf8')}`);
  }
  const payload = JSON.parse(response.body.toString('utf8')) as Dict;
  if (payload.module !== 'service_proxy') {
    throw new Error(`${issuer} service_proxy health 响应异常: ${JSON.stringify(payload)}`);
  }
}

export function makeServiceProxyProviderClient(tag: string): AUNClient {
  return createTestClient({
    aunPath: fs.mkdtempSync(path.join(os.tmpdir(), `aun-ts-sp-${tag}-`)),
    requireForwardSecrecy: false,
  });
}

export async function connectServiceProxyProvider(client: AUNClient, providerAid: string): Promise<void> {
  console.log(`[service-proxy-e2e] register/load provider ${providerAid}`);
  await withTimeout(registerAndLoadIdentity(client, providerAid), 45_000, `register/load ${providerAid}`);
  console.log(`[service-proxy-e2e] connect provider ${providerAid}`);
  await withTimeout(client.connect({ auto_reconnect: false }), 45_000, `connect ${providerAid}`);
  await sleep(300);
}

export async function startServiceProxyBackend(providerAid: string): Promise<{
  baseHttp: string;
  baseWs: string;
  close: () => Promise<void>;
}> {
  console.log(`[service-proxy-e2e] start backend ${providerAid}`);
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const chunks: Buffer[] = [];
    req.on('data', chunk => chunks.push(Buffer.from(chunk)));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      if (url.pathname === '/http/headers') {
        res.writeHead(200, { 'content-type': 'application/json', 'x-header-check': 'ok' });
        res.end(JSON.stringify({
          provider_aid: providerAid,
          method: req.method,
          path_qs: `${url.pathname}${url.search}`,
          x_trace_id: req.headers['x-trace-id'] ?? '',
          x_aun_spoof: req.headers['x-aun-spoof'] ?? '',
          x_aun_provider_aid: req.headers['x-aun-provider-aid'] ?? '',
          x_aun_service_name: req.headers['x-aun-service-name'] ?? '',
          x_forwarded_prefix: req.headers['x-forwarded-prefix'] ?? '',
          x_forwarded_host: req.headers['x-forwarded-host'] ?? '',
        }));
        return;
      }
      if (url.pathname === '/sse/live') {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.end(`data: ${providerAid}:one\n\ndata: ${providerAid}:two\n\n`);
        return;
      }
      if (url.pathname === '/files/download/report.bin') {
        res.writeHead(200, {
          'content-type': 'application/octet-stream',
          'content-disposition': 'attachment; filename=report.bin',
        });
        res.end('report-bytes');
        return;
      }
      if (url.pathname === '/http/status/404') {
        res.writeHead(404, { 'x-backend-status': 'missing' });
        res.end('missing');
        return;
      }
      res.writeHead(200, { 'content-type': 'text/plain', 'x-provider-aid': providerAid });
      res.end(`${providerAid}:${req.method}:${url.pathname}${url.search}:${body.toString('utf8')}`);
    });
  });

  const wsServer = new WebSocketServer({ noServer: true });
  const openWebSockets = new Set<WebSocket>();
  wsServer.on('connection', ws => {
    openWebSockets.add(ws);
    ws.on('close', () => openWebSockets.delete(ws));
    ws.on('message', (data, isBinary) => {
      if (isBinary) ws.send(Buffer.concat([Buffer.from(`${providerAid}:`), Buffer.from(data as Buffer)]), { binary: true });
      else ws.send(`${providerAid}:echo:${data.toString()}`);
    });
  });
  server.on('upgrade', (request, socket, head) => {
    wsServer.handleUpgrade(request, socket, head, ws => wsServer.emit('connection', ws, request));
  });

  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as AddressInfo;
  return {
    baseHttp: `http://127.0.0.1:${address.port}`,
    baseWs: `ws://127.0.0.1:${address.port}`,
    close: async () => {
      for (const ws of openWebSockets) {
        try { ws.terminate(); } catch { /* noop */ }
      }
      await withTimeout(new Promise<void>(resolve => wsServer.close(() => resolve())), 3_000, 'close backend ws server');
      await withTimeout(new Promise<void>(resolve => server.close(() => resolve())), 3_000, 'close backend http server');
    },
  };
}

export function registerServiceProxyTestServices(client: ServiceProxyClient, baseHttp: string, baseWs: string): void {
  console.log(`[service-proxy-e2e] register local services backend=${baseHttp}`);
  client.registerService('fileshare', `${baseHttp}/http`, { visibility: 'public' });
  client.registerService('events', `${baseHttp}/sse`, { serviceType: 'sse', visibility: 'public' });
  client.registerService('files', `${baseHttp}/files`, { serviceType: 'file', visibility: 'public' });
  client.registerService('chat', `${baseWs}/ws`, { serviceType: 'websocket', visibility: 'public' });
}

export async function waitServiceProxyRegistered(issuer: string, expectedServices: number, serveTask: Promise<unknown>): Promise<void> {
  console.log(`[service-proxy-e2e] wait proxy registered issuer=${issuer} expected=${expectedServices}`);
  const deadline = Date.now() + 8_000;
  let lastHealth = '';
  while (Date.now() < deadline) {
    if (await promiseSettled(serveTask)) throw new Error('service-proxy-client 隧道任务提前结束');
    try {
      const response = await httpRequest('GET', `${serviceProxyBase(issuer)}/health`);
      lastHealth = response.body.toString('utf8');
      const payload = JSON.parse(lastHealth) as Dict;
      const connections = payload.connections as Dict | undefined;
      if (Number(connections?.services ?? 0) >= expectedServices) {
        console.log(`[service-proxy-e2e] proxy registered services=${String(connections?.services ?? '')}`);
        return;
      }
    } catch (exc) {
      lastHealth = String(exc);
    }
    await sleep(200);
  }
  throw new Error(`service-proxy-client 未完成服务注册，最后 health=${lastHealth}`);
}

export async function runServiceProxyVisitorChecks(providerAid: string, issuer: string): Promise<void> {
  console.log(`[service-proxy-e2e] visitor checks provider=${providerAid} issuer=${issuer}`);
  const user = serviceProxyUser(providerAid);
  const proxyHost = `proxy.${issuer}`;
  const proxyBase = serviceProxyBase(issuer);

  let response = await httpRequest('GET', `${proxyBase}/${user}/fileshare/health?x=1`, { Host: proxyHost });
  expectStatus(response.status, 200, 'canonical GET');
  expectBody(response.body, `${providerAid}:GET:/http/health?x=1:`, 'canonical GET body');

  response = await httpRequest('POST', `${proxyBase}/${user}/fileshare/upload?token=abc`, { Host: proxyHost }, Buffer.from('payload'));
  expectStatus(response.status, 200, 'canonical POST');
  expectBody(response.body, `${providerAid}:POST:/http/upload?token=abc:payload`, 'canonical POST body');

  response = await httpRequest('GET', `${proxyBase}/${user}/fileshare/headers`, {
    Host: proxyHost,
    'x-trace-id': 'trace-ts-e2e',
    'x-aun-spoof': 'must-not-forward',
  });
  expectStatus(response.status, 200, 'header check');
  const headerPayload = JSON.parse(response.body.toString('utf8')) as Dict;
  if (
    headerPayload.x_trace_id !== 'trace-ts-e2e' ||
    headerPayload.x_aun_spoof !== '' ||
    headerPayload.x_aun_provider_aid !== providerAid ||
    headerPayload.x_aun_service_name !== 'fileshare' ||
    headerPayload.x_forwarded_prefix !== `/${user}/fileshare`
  ) {
    throw new Error(`header check 响应异常: ${JSON.stringify(headerPayload)}`);
  }

  response = await httpRequest('GET', `${proxyBase}/${user}/events/live`, { Host: proxyHost });
  expectStatus(response.status, 200, 'SSE');
  expectBody(response.body, `data: ${providerAid}:one\n\ndata: ${providerAid}:two\n\n`, 'SSE body');
  if (response.headers['x-stream-type'] !== 'sse') throw new Error(`SSE x-stream-type 异常: ${response.headers['x-stream-type']}`);

  response = await httpRequest('GET', `${proxyBase}/${user}/files/download/report.bin`, { Host: proxyHost });
  expectStatus(response.status, 200, 'file');
  expectBody(response.body, 'report-bytes', 'file body');
  if (response.headers['x-stream-type'] !== 'file') throw new Error(`file x-stream-type 异常: ${response.headers['x-stream-type']}`);

  await runServiceProxyWebSocketCheck(`${serviceProxyWsBase(issuer)}/${user}/chat/socket`, providerAid);

  const redirect = await httpRequest('GET', `https://${issuer}/proxy/fileshare/from-ns?y=2`, { Host: providerAid });
  expectStatus(redirect.status, 302, 'NameService redirect');
  const location = String(redirect.headers.location ?? '');
  const redirectedURL = proxyURLFromLocation(location, proxyBase);
  response = await httpRequest('GET', redirectedURL, { Host: proxyHost });
  expectStatus(response.status, 200, 'NameService redirected GET');
  expectBody(response.body, `${providerAid}:GET:/http/from-ns?y=2:`, 'NameService redirected body');
}

export async function runRemoteServiceProxyBoundaryCheck(providerAid: string, remoteIssuer: string): Promise<void> {
  console.log(`[service-proxy-e2e] remote boundary provider=${providerAid} remote=${remoteIssuer}`);
  const user = serviceProxyUser(providerAid);
  const response = await httpRequest('GET', `${serviceProxyBase(remoteIssuer)}/${user}/fileshare/direct?x=remote`, {
    Host: `proxy.${remoteIssuer}`,
  });
  let payload: Dict = {};
  try { payload = JSON.parse(response.body.toString('utf8')) as Dict; } catch { payload = { raw: response.body.toString('utf8') }; }
  const error = String(payload.error ?? '');
  const allowed = (response.status === 503 && ['provider_offline', 'provider_wakeup_failed', 'provider_wakeup_timeout'].includes(error)) ||
    (response.status === 404 && ['provider_aid_not_found', 'provider_not_found'].includes(error));
  if (!allowed) {
    throw new Error(`REMOTE issuer 不应命中本域 provider: status=${response.status} body=${JSON.stringify(payload)}`);
  }
}

export async function waitForResult<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_resolve, reject) => { timer = setTimeout(() => reject(new Error('等待 service-proxy-client 结束超时')), timeoutMs); }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function httpRequest(method: string, urlText: string, headers: Record<string, string> = {}, body?: Buffer): Promise<{
  status: number;
  headers: Record<string, string>;
  body: Buffer;
}> {
  const parsed = new URL(urlText);
  const mod = parsed.protocol === 'https:' ? https : http;
  const options: http.RequestOptions | https.RequestOptions = {
    method,
    headers,
    timeout: 15_000,
    ...(parsed.protocol === 'https:' ? { rejectUnauthorized: false } : {}),
  };
  return await new Promise((resolve, reject) => {
    const req = mod.request(parsed, options, res => {
      const chunks: Buffer[] = [];
      res.on('data', chunk => chunks.push(Buffer.from(chunk)));
      res.on('end', () => {
        const responseHeaders: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (Array.isArray(value)) responseHeaders[key.toLowerCase()] = value.join(', ');
          else if (value !== undefined) responseHeaders[key.toLowerCase()] = String(value);
        }
        resolve({ status: res.statusCode ?? 0, headers: responseHeaders, body: Buffer.concat(chunks) });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error(`HTTP timeout: ${method} ${urlText}`)));
    if (body && body.length > 0) req.write(body);
    req.end();
  });
}

async function runServiceProxyWebSocketCheck(url: string, providerAid: string): Promise<void> {
  const ws = new WebSocket(url, ['chat.v1'], { rejectUnauthorized: false });
  await onceWs(ws, 'open');
  if (ws.protocol !== 'chat.v1') throw new Error(`WS subprotocol 异常: ${ws.protocol}`);
  ws.send('hello');
  const text = await nextWsMessage(ws);
  if (text.toString('utf8') !== `${providerAid}:echo:hello`) throw new Error(`WS text echo 异常: ${text.toString('utf8')}`);
  ws.send(Buffer.from('bin'));
  const binary = await nextWsMessage(ws);
  if (!binary.equals(Buffer.from(`${providerAid}:bin`))) throw new Error(`WS binary echo 异常: ${binary.toString('hex')}`);
  ws.close();
}

function nextWsMessage(ws: WebSocket): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      ws.off('message', onMessage);
      ws.off('error', onError);
    };
    const onMessage = (data: WebSocket.RawData) => { cleanup(); resolve(Buffer.from(data as Buffer)); };
    const onError = (err: Error) => { cleanup(); reject(err); };
    ws.once('message', onMessage);
    ws.once('error', onError);
  });
}

function onceWs(ws: WebSocket, event: 'open'): Promise<void> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      ws.off(event, onOpen);
      ws.off('error', onError);
    };
    const onOpen = () => { cleanup(); resolve(); };
    const onError = (err: Error) => { cleanup(); reject(err); };
    ws.once(event, onOpen);
    ws.once('error', onError);
  });
}

function proxyURLFromLocation(location: string, proxyBase: string): string {
  const parsed = new URL(location);
  return `${proxyBase}${parsed.pathname}${parsed.search}`;
}

function expectStatus(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(`${label} status=${actual}, want=${expected}`);
}

function expectBody(actual: Buffer, expected: string, label: string): void {
  const got = actual.toString('utf8');
  if (got !== expected) throw new Error(`${label} body=${JSON.stringify(got)}, want=${JSON.stringify(expected)}`);
}

async function promiseSettled(promise: Promise<unknown>): Promise<boolean> {
  const sentinel = Symbol('pending');
  return await Promise.race([promise.then(() => true, () => true), Promise.resolve(sentinel)]) !== sentinel;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return Promise.race([
    promise,
    new Promise<T>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} 超时 (${timeoutMs}ms)`)), timeoutMs);
    }),
  ]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}
