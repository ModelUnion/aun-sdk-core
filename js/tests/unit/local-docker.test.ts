import { describe, expect, it } from 'vitest';

import { buildChromeHostResolverRules } from '../local-docker.js';

describe('local Docker Playwright host resolver', () => {
  it('为 federation 域生成端口级映射，避免落到单域默认 443/20001', () => {
    const rules = buildChromeHostResolverRules(['agentid.pub', 'aid.com', 'aid.net']);
    const parts = rules.split(',');

    expect(parts).toContain('MAP *.aid.com:443 127.0.0.1:21443');
    expect(parts).toContain('MAP aid.com:443 127.0.0.1:21443');
    expect(parts).toContain('MAP *.aid.net:443 127.0.0.1:22443');
    expect(parts).toContain('MAP aid.net:443 127.0.0.1:22443');
    expect(parts).toContain('MAP *.aid.com:20001 127.0.0.1:21001');
    expect(parts).toContain('MAP *.aid.net:20001 127.0.0.1:22001');
    expect(parts).toContain('MAP *.agentid.pub 127.0.0.1');
  });
});
