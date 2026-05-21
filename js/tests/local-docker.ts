import { isIP } from 'node:net';

const DEFAULT_LOCAL_ISSUERS = ['agentid.pub', 'aid.com', 'aid.net'];

function normalizeHostLike(value: string | null | undefined): string {
  let text = String(value ?? '').trim().toLowerCase();
  if (!text) return '';

  if (text.includes('://')) {
    try {
      text = new URL(text).hostname.toLowerCase();
    } catch {
      return '';
    }
  } else if (text.startsWith('[')) {
    const end = text.indexOf(']');
    if (end > 0) {
      text = text.slice(1, end);
    }
  } else {
    const colon = text.lastIndexOf(':');
    if (colon > 0 && text.indexOf(':') === colon) {
      text = text.slice(0, colon);
    }
  }

  return text;
}

function addIssuer(target: Set<string>, value: string | null | undefined): void {
  const host = normalizeHostLike(value);
  if (!host || host === 'localhost' || isIP(host)) return;
  target.add(host);
}

function issuerFromAidHost(value: string | null | undefined): string {
  const host = normalizeHostLike(value);
  if (!host || host === 'localhost' || isIP(host)) return '';
  const dot = host.indexOf('.');
  if (dot < 0) return '';
  return host.slice(dot + 1);
}

export function collectLocalDockerIssuers(): string[] {
  const issuers = new Set<string>(DEFAULT_LOCAL_ISSUERS);
  addIssuer(issuers, process.env.AUN_TEST_ISSUER);
  addIssuer(issuers, process.env.AUN_TEST_ISSUER_A);
  addIssuer(issuers, process.env.AUN_TEST_ISSUER_B);

  for (const [key, value] of Object.entries(process.env)) {
    if (!key.startsWith('AUN_TEST_') || !key.endsWith('_AID')) continue;
    const issuer = issuerFromAidHost(value);
    if (issuer && issuer !== 'localhost' && !isIP(issuer)) {
      issuers.add(issuer);
    }
  }

  return [...issuers];
}

export function isLocalDockerHost(hostname: string, issuers = collectLocalDockerIssuers()): boolean {
  const host = normalizeHostLike(hostname);
  if (!host || host === 'localhost' || isIP(host)) return false;
  return issuers.some((issuer) => host === issuer || host.endsWith(`.${issuer}`));
}

export function buildChromeHostResolverRules(issuers = collectLocalDockerIssuers()): string {
  const rules = issuers.flatMap((issuer) => [
    `MAP *.${issuer} 127.0.0.1`,
    `MAP ${issuer} 127.0.0.1`,
  ]);
  rules.push('EXCLUDE localhost');
  return rules.join(',');
}
