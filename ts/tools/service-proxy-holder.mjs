#!/usr/bin/env node
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { WebSocketServer } from 'ws';

import { AIDStore, AUNClient, ServiceProxyClient } from '../dist/index.js';

const args = parseArgs(process.argv.slice(2));
const providerAid = value('provider-aid', 'AUN_PROXY_PROVIDER_AID', 'AUN_SERVICE_PROXY_PROVIDER_AID');
if (!providerAid) fail('必须通过 --provider-aid 或 AUN_PROXY_PROVIDER_AID 指定 provider AID');
const aunPath = value('aun-path', 'AUN_PROXY_PROVIDER_AUN_PATH', 'AUN_SERVICE_PROXY_PROVIDER_AUN_PATH') ||
  path.join(os.homedir(), '.aun', 'service-proxy-holder-ts', safeName(providerAid));
const seed = value('seed', 'AUN_SEED_PASSWORD', 'AUN_PROXY_SEED') || '';
const verifySsl = boolValue('verify-ssl', 'AUN_VERIFY_SSL', false);
const connectionMode = value('connection-mode', 'AUN_SERVICE_PROXY_CONNECTION_MODE') || 'persistent';

const { server, baseHttp, baseWs } = await startBackend(providerAid);
const store = new AIDStore({ aunPath, encryptionSeed: seed, verifySsl });
let loaded = store.load(providerAid);
if (!loaded.ok) {
  const registered = await store.register(providerAid);
  if (!registered.ok) fail(`注册 AID 失败: ${registered.error.code}: ${registered.error.message}`);
  loaded = store.load(providerAid);
}
if (!loaded.ok || !loaded.data?.aid) fail(`加载 AID 失败: ${loaded.ok ? 'empty result' : loaded.error.message}`);

const aunClient = new AUNClient(loaded.data.aid);
if (aunClient.configModel) aunClient.configModel.requireForwardSecrecy = false;
await aunClient.connect({ auto_reconnect: false });

const proxyClient = new ServiceProxyClient({ providerAid, aunClient });
proxyClient.registerService('rest', `${baseHttp}/http`, { visibility: 'public' });
proxyClient.registerService('events', `${baseHttp}/sse`, { serviceType: 'sse', visibility: 'public' });
proxyClient.registerService('files', `${baseHttp}/files`, { serviceType: 'file', visibility: 'public' });
proxyClient.registerService('chat', `${baseWs}/ws`, { serviceType: 'websocket', visibility: 'public' });

printURLs(providerAid);
const stop = async () => {
  proxyClient.stop();
  await Promise.allSettled([aunClient.close(), closeServer(server)]);
};
process.once('SIGINT', () => { stop().finally(() => process.exit(130)); });
process.once('SIGTERM', () => { stop().finally(() => process.exit(143)); });

try {
  await proxyClient.serveForever({ connectionMode, reconnectDelaySeconds: 1 });
} finally {
  await stop();
}

function parseArgs(items) {
  const out = new Map();
  for (let i = 0; i < items.length; i += 1) {
    const item = items[i];
    if (!item.startsWith('--')) continue;
    const key = item.slice(2);
    const next = items[i + 1];
    if (!next || next.startsWith('--')) out.set(key, '1');
    else {
      out.set(key, next);
      i += 1;
    }
  }
  return out;
}

function value(argName, ...envNames) {
  return String(args.get(argName) ?? envNames.map(name => process.env[name]).find(Boolean) ?? '').trim();
}

function boolValue(argName, envName, fallback) {
  const raw = String(args.get(argName) ?? process.env[envName] ?? '').trim().toLowerCase();
  if (!raw) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(raw);
}

function safeName(text) {
  return String(text).replace(/[^a-zA-Z0-9._-]+/g, '_');
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

async function startBackend(provider) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    const chunks = [];
    req.on('data', chunk => chunks.push(Buffer.from(chunk)));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      if (url.pathname === '/http/headers') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
          provider_aid: provider,
          method: req.method,
          path_qs: `${url.pathname}${url.search}`,
          x_trace_id: req.headers['x-trace-id'] || '',
          x_aun_provider_aid: req.headers['x-aun-provider-aid'] || '',
          x_aun_service_name: req.headers['x-aun-service-name'] || '',
          x_forwarded_prefix: req.headers['x-forwarded-prefix'] || '',
        }));
        return;
      }
      if (url.pathname === '/sse/live') {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.end(`data: ${provider}:one\n\ndata: ${provider}:two\n\n`);
        return;
      }
      if (url.pathname === '/files/download/report.txt') {
        res.writeHead(200, { 'content-type': 'text/plain', 'content-disposition': 'attachment; filename=report.txt' });
        res.end(`Service Proxy report from ${provider}\n`);
        return;
      }
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(`${provider}:${req.method}:${url.pathname}${url.search}:${body.toString('utf8')}`);
    });
  });
  const wsServer = new WebSocketServer({ noServer: true });
  wsServer.on('connection', ws => {
    ws.on('message', (data, isBinary) => {
      if (isBinary) ws.send(Buffer.concat([Buffer.from(`${provider}:`), Buffer.from(data)]), { binary: true });
      else ws.send(`${provider}:echo:${data.toString()}`);
    });
  });
  server.on('upgrade', (request, socket, head) => {
    wsServer.handleUpgrade(request, socket, head, ws => wsServer.emit('connection', ws, request));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  server.__wsServer = wsServer;
  return { server, baseHttp: `http://127.0.0.1:${port}`, baseWs: `ws://127.0.0.1:${port}` };
}

async function closeServer(server) {
  await new Promise(resolve => server.__wsServer.close(() => resolve()));
  await new Promise(resolve => server.close(() => resolve()));
}

function printURLs(aid) {
  const user = aid.split('.', 1)[0];
  const issuer = aid.split('.').slice(1).join('.');
  const base = `https://proxy.${issuer}:19890/${user}`;
  console.log(`TS Service Proxy holder 已启动: ${aid}`);
  console.log(`REST: ${base}/rest/headers`);
  console.log(`SSE : ${base}/events/live`);
  console.log(`File: ${base}/files/download/report.txt`);
  console.log(`WS  : wss://proxy.${issuer}:19890/${user}/chat/socket`);
}
