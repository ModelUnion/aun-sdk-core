import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { AUNClient } from '../../src/index.js';
import { registerAndLoadIdentity } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(): AUNClient {
  const client = new AUNClient({
    aun_path: fs.mkdtempSync(path.join(os.tmpdir(), 'aun-refresh-ts-')),
  });
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  return client;
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

      await client.connect({
        auto_reconnect: false,
        heartbeat_interval: 0,
        token_refresh_before: 3590,
      });

      const deadline = Date.now() + 45_000;
      let refreshedToken = '';
      while (Date.now() < deadline) {
        refreshedToken = String(((client as any)._identity?.access_token) ?? '');
        if (refreshedToken && refreshedToken !== initialToken) break;
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
