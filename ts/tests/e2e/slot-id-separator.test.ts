/**
 * slot_id 分隔符语义 E2E 测试
 *
 * 对齐 Python e2e_test_slot_id_separator.py 的 4 个场景：
 *   1. P2P 明文 — 同前缀 c2 踢掉 c1 后收到消息
 *   2. P2P 加密 — 同前缀 c2 踢掉 c1 后收到并解密
 *   3. Group 明文 — 同前缀 c2 踢掉 c1 后收到群消息
 *   4. Group 加密 — 同前缀 c2 踢掉 c1 后收到并解密群消息
 *
 * 运行（容器内）：
 *   MSYS_NO_PATHCONV=1 docker exec kite-ts-tester bash -lc \
 *     "cd /workspace/ts && npx vitest run tests/e2e/slot-id-separator.test.ts --reporter=verbose"
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';
import { registerAndLoadIdentity, loadIdentityFromStore, setGatewayForClient } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const GATEWAY_AID = process.env.AUN_TEST_GATEWAY_AID ?? `gateway.${ISSUER}`;

function rid(): string { return crypto.randomUUID().replace(/-/g, '').slice(0, 8); }
function sleep(ms: number): Promise<void> { return new Promise(r => setTimeout(r, ms)); }

function makeClient(tag: string): AUNClient {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `aun-sep-${tag}-`));
  const c = new AUNClient({ aun_path: dir, debug: false });
  (c as any)._configModel.requireForwardSecrecy = false;
  return c;
}

async function connect(client: AUNClient, aid: string, slotId: string, register = false): Promise<void> {
  let lastErr: unknown;
  for (let i = 0; i < 3; i++) {
    try {
      await setGatewayForClient(client, GATEWAY_AID);
      if (register) {
        await registerAndLoadIdentity(client, aid, slotId);
      } else {
        loadIdentityFromStore(client, aid, slotId);
      }
      await client.connect({ auto_reconnect: false, heartbeat_interval: 30 });
      return;
    } catch (e) {
      lastErr = e;
      await sleep(1000 * (i + 1));
    }
  }
  throw lastErr;
}

async function safeClose(c: AUNClient): Promise<void> {
  try { await c.close(); } catch { /* ignore */ }
}

// ── Test 1: P2P 明文 ──────────────────────────────────────────

describe('slot_id E2E — P2P 明文', { timeout: 60_000 }, () => {
  it('同前缀 c2 踢掉 c1 后收到 bob 发的明文消息', async () => {
    const r = rid();
    const aliceAid = `sep-ts-ea-${r}.${ISSUER}`;
    const bobAid = `sep-ts-eb-${r}.${ISSUER}`;

    const c1 = makeClient('c1');
    const c2 = makeClient('c2');
    const bob = makeClient('bob');

    try {
      await connect(c1, aliceAid, `evolclaw cli-${r}`, true);
      expect(c1.state).toBe('ready');

      await connect(c2, aliceAid, `evolclaw daemon-${r}`);
      expect(c2.state).toBe('ready');

      // 等待 c1 被踢
      const deadline = Date.now() + 8_000;
      while (c1.state === 'ready' && Date.now() < deadline) await sleep(200);
      expect(c1.state).not.toBe('ready');

      await connect(bob, bobAid, 'main', true);

      const text = `sep-plain-${r}`;
      let received = false;
      const p = new Promise<void>(resolve => {
        c2.on('message.received', (d: any) => {
          if (d?.payload?.text === text) { received = true; resolve(); }
        });
      });

      await bob.call('message.send', { to: aliceAid, payload: { type: 'text', text }, encrypt: false });
      await Promise.race([p, sleep(15_000)]);
      expect(received).toBe(true);
    } finally {
      await safeClose(c1); await safeClose(c2); await safeClose(bob);
    }
  });
});

// ── Test 2: P2P 加密 ──────────────────────────────────────────

describe('slot_id E2E — P2P 加密', { timeout: 60_000 }, () => {
  it('同前缀 c2 踢掉 c1 后收到并解密 bob 发的加密消息', async () => {
    const r = rid();
    const aliceAid = `sep-ts-fa-${r}.${ISSUER}`;
    const bobAid = `sep-ts-fb-${r}.${ISSUER}`;

    const c1 = makeClient('c1');
    const c2 = makeClient('c2');
    const bob = makeClient('bob');

    try {
      await connect(c1, aliceAid, `evolclaw cli-${r}`, true);
      await connect(c2, aliceAid, `evolclaw daemon-${r}`);

      const deadline = Date.now() + 8_000;
      while (c1.state === 'ready' && Date.now() < deadline) await sleep(200);
      expect(c1.state).not.toBe('ready');

      await connect(bob, bobAid, 'main', true);

      const text = `sep-enc-${r}`;
      let received = false;
      let encrypted = false;
      const p = new Promise<void>(resolve => {
        c2.on('message.received', (d: any) => {
          if (d?.payload?.text === text) { received = true; encrypted = d?.encrypted === true; resolve(); }
        });
      });

      await bob.call('message.send', { to: aliceAid, payload: { type: 'text', text }, encrypt: true });
      await Promise.race([p, sleep(20_000)]);
      expect(received).toBe(true);
      expect(encrypted).toBe(true);
    } finally {
      await safeClose(c1); await safeClose(c2); await safeClose(bob);
    }
  });
});

// ── Test 3: Group 明文 ────────────────────────────────────────

describe('slot_id E2E — Group 明文', { timeout: 60_000 }, () => {
  it('同前缀 c2 踢掉 c1 后收到群明文消息', async () => {
    const r = rid();
    const aliceAid = `sep-ts-ga-${r}.${ISSUER}`;
    const bobAid = `sep-ts-gb-${r}.${ISSUER}`;

    const c1 = makeClient('c1');
    const c2 = makeClient('c2');
    const bob = makeClient('bob');

    try {
      await connect(c1, aliceAid, `evolclaw cli-${r}`, true);
      await connect(c2, aliceAid, `evolclaw daemon-${r}`);

      const deadline = Date.now() + 8_000;
      while (c1.state === 'ready' && Date.now() < deadline) await sleep(200);
      expect(c1.state).not.toBe('ready');

      await connect(bob, bobAid, 'main', true);

      const grpResult = await bob.call('group.create', { name: `sep-grp-${r}`, visibility: 'private' }) as any;
      const grp = (grpResult?.group ?? grpResult) as any;
      const groupId = grp?.group_id;
      expect(groupId).toBeTruthy();

      await bob.call('group.add_member', { group_id: groupId, aid: aliceAid });

      // 等待 alice 收到加群事件
      await new Promise<void>(resolve => {
        const t = setTimeout(resolve, 5000);
        c2.on('group.member_joined', (d: any) => { if (d?.group_id === groupId) { clearTimeout(t); resolve(); } });
      });

      const text = `sep-grp-${r}`;
      let received = false;
      const p = new Promise<void>(resolve => {
        c2.on('group.message_created', (d: any) => {
          if (d?.payload?.text === text) { received = true; resolve(); }
        });
      });

      await bob.call('group.send', { group_id: groupId, payload: { type: 'text', text }, encrypt: false });
      await Promise.race([p, sleep(15_000)]);
      expect(received).toBe(true);
    } finally {
      await safeClose(c1); await safeClose(c2); await safeClose(bob);
    }
  });
});

// ── Test 4: Group 加密 ────────────────────────────────────────

describe('slot_id E2E — Group 加密', { timeout: 90_000 }, () => {
  it('同前缀 c2 踢掉 c1 后收到并解密群加密消息', async () => {
    const r = rid();
    const aliceAid = `sep-ts-gea-${r}.${ISSUER}`;
    const bobAid = `sep-ts-geb-${r}.${ISSUER}`;

    const c1 = makeClient('c1');
    const c2 = makeClient('c2');
    const bob = makeClient('bob');

    try {
      await connect(c1, aliceAid, `evolclaw cli-${r}`, true);
      await connect(c2, aliceAid, `evolclaw daemon-${r}`);

      const deadline = Date.now() + 8_000;
      while (c1.state === 'ready' && Date.now() < deadline) await sleep(200);
      expect(c1.state).not.toBe('ready');

      await connect(bob, bobAid, 'main', true);

      const grpResult = await bob.call('group.create', { name: `sep-egrp-${r}`, visibility: 'private' }) as any;
      const grp = (grpResult?.group ?? grpResult) as any;
      const groupId = grp?.group_id;
      expect(groupId).toBeTruthy();

      await bob.call('group.add_member', { group_id: groupId, aid: aliceAid });

      // 等待 V2 群密钥就绪
      await new Promise<void>(resolve => {
        const t = setTimeout(resolve, 10000);
        c2.on('group.v2.epoch_committed', (d: any) => { if (d?.group_id === groupId) { clearTimeout(t); resolve(); } });
      });

      const text = `sep-egrp-${r}`;
      let received = false;
      let encrypted = false;
      const p = new Promise<void>(resolve => {
        c2.on('group.message_created', (d: any) => {
          if (d?.payload?.text === text) { received = true; encrypted = d?.encrypted === true; resolve(); }
        });
      });

      await bob.call('group.send', { group_id: groupId, payload: { type: 'text', text }, encrypt: true });
      await Promise.race([p, sleep(20_000)]);
      expect(received).toBe(true);
      expect(encrypted).toBe(true);
    } finally {
      await safeClose(c1); await safeClose(c2); await safeClose(bob);
    }
  });
});
