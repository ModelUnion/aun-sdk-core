import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e-browser',
  timeout: 120_000,
  retries: 0,
  use: {
    channel: 'chrome',
    headless: true,
    ignoreHTTPSErrors: true,
    launchOptions: {
      args: [
        '--disable-web-security',
        '--disable-features=IsolateOrigins,site-per-process',
        '--ignore-certificate-errors',
        '--no-proxy-server',
        '--proxy-server=direct://',
        '--proxy-bypass-list=*',
        '--host-resolver-rules=MAP *.agentid.pub 127.0.0.1,MAP agentid.pub 127.0.0.1,EXCLUDE localhost',
      ],
    },
  },
  workers: 1,
});
