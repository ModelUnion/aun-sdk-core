import { defineConfig } from '@playwright/test';
import { buildChromeHostResolverRules, collectLocalDockerIssuers } from './tests/local-docker.js';

const localDockerIssuers = collectLocalDockerIssuers();
const hostResolverRules = buildChromeHostResolverRules(localDockerIssuers);

export default defineConfig({
  testDir: './tests/e2e-browser',
  timeout: 120_000,
  retries: 0,
  use: {
    channel: 'chrome',
    headless: true,
    ignoreHTTPSErrors: true,
    launchOptions: {
      env: {
        HTTP_PROXY: '',
        HTTPS_PROXY: '',
        ALL_PROXY: '',
        http_proxy: '',
        https_proxy: '',
        all_proxy: '',
        NO_PROXY: '*',
        no_proxy: '*',
      },
      args: [
        '--disable-web-security',
        '--disable-features=IsolateOrigins,site-per-process',
        '--ignore-certificate-errors',
        '--no-proxy-server',
        '--proxy-server=direct://',
        '--proxy-bypass-list=*',
        `--host-resolver-rules=${hostResolverRules}`,
      ],
    },
  },
  workers: 1,
});
