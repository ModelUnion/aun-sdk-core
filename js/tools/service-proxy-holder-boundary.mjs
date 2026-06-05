#!/usr/bin/env node
import { ServiceProxyClient } from '../dist/index.js';

const client = new ServiceProxyClient({
  providerAid: process.env.AUN_PROXY_PROVIDER_AID || 'alice.agentid.pub',
  aunClient: {
    authenticate: async () => ({ access_token: 'demo-token', expires_at: Date.now() / 1000 + 3600 }),
  },
});
client.discoverProxyWsUrl = async () => process.env.AUN_PROXY_WS_URL || 'wss://proxy.agentid.pub:19890/ws/client';

try {
  await client.connectOnce();
  console.error('异常：浏览器 SDK 原生 WebSocket 不应直接完成 provider tunnel 认证');
  process.exit(1);
} catch (err) {
  const message = String(err?.message || err);
  if (!/webSocketFactory|Authorization/i.test(message)) {
    console.error(`异常错误: ${message}`);
    process.exit(1);
  }
  console.log('PASS: 浏览器 SDK holder 需要注入可携带 Authorization header 的 webSocketFactory');
}
