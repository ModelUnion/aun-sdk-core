import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { AUNClient } from '../../src/index.js';
import {
  createTestClient,
  moveAccessTokenExpiryIntoRefreshWindow,
  registerAndLoadIdentity,
} from '../test-support.js';

process.env.AUN_ENV ??= 'development';

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(): AUNClient {
  return createTestClient({
    aunPath: fs.mkdtempSync(path.join(os.tmpdir(), 'aun-refresh-ts-')),
    requireForwardSecrecy: false,
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

describe('Token refresh 集成测试', () => {
  it('真实 Gateway 上会刷新并换发 access_token', async () => {
    const issuer = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
    const aid = `ts-refresh-${runId()}.${issuer}`;
    const client = makeClient();
    const refreshEvents: unknown[] = [];
    client.on('token.refreshed', (payload: unknown) => refreshEvents.push(payload));

    try {
      await registerAndLoadIdentity(client, aid);
      const auth = await client.authenticate();
      const initialToken = String(auth.access_token ?? '');
      expect(initialToken).not.toBe('');
      const forcedExpiresAt = moveAccessTokenExpiryIntoRefreshWindow(client, 60);
      console.log(`token-refresh ts aid=${aid} forced_expires_at=${forcedExpiresAt}`);

      await client.connect({
        auto_reconnect: false,
        heartbeat_interval: 0,
      });

      const deadline = Date.now() + 45_000;
      let refreshedToken = '';
      let lastLogAt = 0;
      while (Date.now() < deadline) {
        refreshedToken = String(((client as any)._identity?.access_token) ?? '');
        if (refreshedToken && refreshedToken !== initialToken) break;
        if (Date.now() - lastLogAt >= 5_000) {
          lastLogAt = Date.now();
          console.log(`token-refresh ts waiting aid=${aid} events=${refreshEvents.length}`);
        }
        await sleep(1000);
      }

      expect(refreshedToken).not.toBe('');
      expect(refreshedToken).not.toBe(initialToken);
      await expect(client.call('meta.ping', {})).resolves.toBeTruthy();
      const expiresAt = Number((client as any)._identity?.access_token_expires_at ?? 0);
      expect(expiresAt - Math.floor(Date.now() / 1000)).toBeGreaterThan(3000);
      expect(refreshEvents.length).toBeGreaterThanOrEqual(1);
    } finally {
      await client.close();
    }
  }, 60_000);
});
