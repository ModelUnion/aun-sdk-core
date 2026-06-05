#!/usr/bin/env node
import * as http from 'node:http';
import * as https from 'node:https';
import WebSocket from 'ws';

const args = parseArgs(process.argv.slice(2));
const providerAid = value('provider-aid', 'AUN_PROXY_PROVIDER_AID', 'AUN_SERVICE_PROXY_PROVIDER_AID');
if (!providerAid) fail('必须通过 --provider-aid 或 AUN_PROXY_PROVIDER_AID 指定 provider AID');
const user = providerAid.split('.', 1)[0];
const issuer = providerAid.split('.').slice(1).join('.');
const proxyBase = value('proxy-base', 'AUN_PROXY_BASE', 'AUN_SERVICE_PROXY_PUBLIC_BASE') || `https://proxy.${issuer}:19890`;
const proxyHost = new URL(proxyBase).host;

await checkHTTP('GET', `${proxyBase}/${user}/rest/headers`, { Host: proxyHost, 'x-trace-id': 'ts-visitor' });
await checkHTTP('GET', `${proxyBase}/${user}/events/live`, { Host: proxyHost, accept: 'text/event-stream' });
await checkHTTP('GET', `${proxyBase}/${user}/files/download/report.txt`, { Host: proxyHost });
await checkWS(`${proxyBase.replace(/^http/, 'ws')}/${user}/chat/socket`);
console.log('TS Service Proxy visitor 检查完成: PASS');

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

function fail(message) {
  console.error(message);
  process.exit(1);
}

async function checkHTTP(method, targetURL, headers) {
  const parsed = new URL(targetURL);
  const mod = parsed.protocol === 'https:' ? https : http;
  const body = await new Promise((resolve, reject) => {
    const req = mod.request(parsed, {
      method,
      headers,
      rejectUnauthorized: false,
      timeout: 15000,
    }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(Buffer.from(chunk)));
      res.on('end', () => {
        const data = Buffer.concat(chunks);
        if ((res.statusCode || 0) < 200 || (res.statusCode || 0) >= 300) {
          reject(new Error(`${method} ${targetURL} HTTP ${res.statusCode}: ${data.toString('utf8')}`));
          return;
        }
        resolve(data);
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error(`timeout: ${targetURL}`)));
    req.end();
  });
  console.log(`${method} ${targetURL} -> ${body.toString('utf8').slice(0, 160)}`);
}

async function checkWS(targetURL) {
  const ws = new WebSocket(targetURL, ['chat.v1'], { rejectUnauthorized: false });
  await new Promise((resolve, reject) => {
    ws.once('open', resolve);
    ws.once('error', reject);
  });
  ws.send('hello');
  const message = await new Promise((resolve, reject) => {
    ws.once('message', data => resolve(Buffer.from(data).toString('utf8')));
    ws.once('error', reject);
  });
  ws.close();
  if (!message.includes('echo:hello')) throw new Error(`WS echo 异常: ${message}`);
  console.log(`WS ${targetURL} -> ${message}`);
}
