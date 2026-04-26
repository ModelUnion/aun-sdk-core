import type { AUNClient } from '../client.js';
import { AUNError, ValidationError } from '../errors.js';
import { isJsonObject, type JsonObject, type JsonValue } from '../types.js';

const CUSTODY_HTTP_TIMEOUT_MS = 30_000;

interface ClientBridge {
  _identity: JsonObject | null;
  _configModel: { discoveryPort?: number | null; verifySsl?: boolean };
}

function issuerDomainFromAid(aid: string): string {
  const parts = String(aid || '').trim().split('.', 2);
  return parts.length > 1 ? parts[1] : parts[0] || '';
}

function custodyWellKnownUrls(aid: string, discoveryPort: number | null | undefined, verifySsl: boolean): string[] {
  const portSuffix = discoveryPort ? `:${discoveryPort}` : '';
  const issuerDomain = issuerDomainFromAid(aid);
  const aidUrl = `https://${aid}${portSuffix}/.well-known/aun-custody`;
  const fallbackUrl = `https://aid_custody.${issuerDomain}${portSuffix}/.well-known/aun-custody`;
  const urls = verifySsl ? [aidUrl, fallbackUrl] : [fallbackUrl, aidUrl];
  return [...new Set(urls)];
}

function extractCustodyUrl(payload: JsonObject): string {
  for (const key of ['custody_url', 'custodyUrl', 'url'] as const) {
    const value = String(payload[key] ?? '').trim();
    if (value) return value;
  }
  if (isJsonObject(payload.custody)) {
    const value = String(payload.custody.url ?? '').trim();
    if (value) return value;
  }
  for (const key of ['custody_services', 'custodyServices', 'services'] as const) {
    const items = payload[key];
    if (Array.isArray(items)) {
      const candidates = items
        .filter(isJsonObject)
        .sort((a, b) => Number(a.priority ?? 999) - Number(b.priority ?? 999));
      for (const item of candidates) {
        const value = String(item.url ?? '').trim();
        if (value) return value;
      }
    }
  }
  throw new ValidationError('custody well-known missing custody url');
}

function normalizeCustodyUrl(url: string): string | null {
  const value = String(url ?? '').trim().replace(/\/+$/, '');
  if (!value) return null;
  try {
    const parsed = new URL(value);
    if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') || !parsed.hostname) {
      return null;
    }
    return value;
  } catch {
    return null;
  }
}

async function fetchJsonWithTimeout(
  input: string,
  init: RequestInit,
  timeoutMs: number = CUSTODY_HTTP_TIMEOUT_MS,
): Promise<JsonValue> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(input, { ...init, signal: controller.signal });
    const payload = await response.json() as JsonValue;
    if (response.ok) {
      return payload;
    }
    const error = isJsonObject(payload) && isJsonObject(payload.error) ? payload.error : null;
    const code = String(error?.code ?? '');
    const message = String(error?.message ?? '');
    throw new AUNError(
      message ? `custody ${code || response.status}: ${message}` : `custody HTTP ${response.status}`,
    );
  } catch (error) {
    if (controller.signal.aborted) {
      throw new AUNError(`custody request timed out after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export class CustodyNamespace {
  private _client: AUNClient;
  private _custodyUrl = '';

  constructor(client: AUNClient) {
    this._client = client;
  }

  private get _internal(): ClientBridge {
    return this._client as unknown as ClientBridge;
  }

  setUrl(url: string): void {
    this._custodyUrl = String(url ?? '').trim().replace(/\/+$/, '');
  }

  configureUrl(url: string): void {
    this.setUrl(url);
  }

  async discoverUrl(params: { aid?: string | null; timeout?: number } = {}): Promise<string> {
    const aid = String(params.aid ?? this._client.aid ?? '').trim();
    if (!aid) {
      throw new ValidationError('custody.discoverUrl requires aid or authenticated client');
    }
    let lastError: unknown = null;
    const config = this._internal._configModel;
    const urls = custodyWellKnownUrls(aid, config.discoveryPort, config.verifySsl ?? true);
    for (const wellKnownUrl of urls) {
      try {
        const payload = await fetchJsonWithTimeout(wellKnownUrl, { method: 'GET' }, params.timeout ?? 5_000);
        if (!isJsonObject(payload)) {
          throw new ValidationError('custody well-known returned invalid payload');
        }
        const custodyUrl = normalizeCustodyUrl(extractCustodyUrl(payload));
        if (!custodyUrl) {
          throw new ValidationError('custody well-known returned invalid custody url');
        }
        this._custodyUrl = custodyUrl;
        return custodyUrl;
      } catch (error) {
        lastError = error;
      }
    }
    throw new AUNError(`custody discovery failed for ${aid}: ${lastError instanceof Error ? lastError.message : String(lastError)}`);
  }

  private async _resolveCustodyUrl(aid?: string | null): Promise<string> {
    const custodyUrl = normalizeCustodyUrl(this._custodyUrl);
    if (custodyUrl) {
      if (custodyUrl !== this._custodyUrl) {
        this._custodyUrl = custodyUrl;
      }
      return custodyUrl;
    }
    return this.discoverUrl({ aid });
  }

  private _getAccessToken(): string {
    const identity = this._internal._identity;
    if (identity) {
      const token = String(identity.access_token ?? '').trim();
      if (token) return token;
    }
    throw new ValidationError('no access_token available: call auth.authenticate() first');
  }

  private async _post(
    path: string,
    body: JsonObject,
    opts: { token?: string | null } = {},
  ): Promise<JsonObject> {
    const headers: Record<string, string> = {'Content-Type': 'application/json'};
    const token = String(opts.token ?? '').trim();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    const payload = await fetchJsonWithTimeout(
      `${await this._resolveCustodyUrl(String(body.aid ?? '') || this._client.aid)}${path}`,
      {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
      },
    );
    if (!isJsonObject(payload)) {
      throw new AUNError('custody returned invalid JSON payload');
    }
    return payload;
  }

  async sendCode(params: { phone: string; aid?: string | null }): Promise<JsonObject> {
    const phone = String(params.phone ?? '').trim();
    const aid = String(params.aid ?? '').trim();
    if (!phone) {
      throw new ValidationError('custody.sendCode requires non-empty phone');
    }
    const body: JsonObject = {phone};
    let token: string | null = null;
    if (aid) {
      body.aid = aid;
    } else {
      token = this._getAccessToken();
    }
    return this._post('/custody/accounts/send-code', body, {token});
  }

  async bindPhone(params: {
    phone: string;
    code: string;
    cert: string;
    key: string;
    metadata?: JsonObject | null;
  }): Promise<JsonObject> {
    const phone = String(params.phone ?? '').trim();
    const code = String(params.code ?? '').trim();
    const cert = String(params.cert ?? '').trim();
    const key = String(params.key ?? '').trim();
    if (!phone || !code || !cert || !key) {
      throw new ValidationError('custody.bindPhone requires phone, code, cert and key');
    }
    const body: JsonObject = {phone, code, cert, key};
    if (params.metadata && isJsonObject(params.metadata)) {
      body.metadata = params.metadata;
    }
    return this._post('/custody/accounts/bind-phone', body, {
      token: this._getAccessToken(),
    });
  }

  async restorePhone(params: {
    phone: string;
    code: string;
    aid: string;
  }): Promise<JsonObject> {
    const phone = String(params.phone ?? '').trim();
    const code = String(params.code ?? '').trim();
    const aid = String(params.aid ?? '').trim();
    if (!phone || !code || !aid) {
      throw new ValidationError('custody.restorePhone requires phone, code and aid');
    }
    return this._post('/custody/accounts/restore-phone', {phone, code, aid});
  }

  async createDeviceCopy(params: { aid?: string | null } = {}): Promise<JsonObject> {
    const aid = String(params.aid ?? this._client.aid ?? '').trim();
    if (!aid) {
      throw new ValidationError('custody.createDeviceCopy requires aid or authenticated client');
    }
    return this._post('/custody/transfers', {aid}, {token: this._getAccessToken()});
  }

  async uploadDeviceCopyMaterials(params: {
    transferCode: string;
    cert: string;
    key: string;
    aid?: string | null;
    metadata?: JsonObject | null;
  }): Promise<JsonObject> {
    const transferCode = String(params.transferCode ?? '').trim();
    const aid = String(params.aid ?? this._client.aid ?? '').trim();
    const cert = String(params.cert ?? '').trim();
    const key = String(params.key ?? '').trim();
    if (!transferCode || !aid || !cert || !key) {
      throw new ValidationError('custody.uploadDeviceCopyMaterials requires transferCode, aid, cert and key');
    }
    const body: JsonObject = {aid, cert, key};
    if (params.metadata && isJsonObject(params.metadata)) {
      body.metadata = params.metadata;
    }
    return this._post(`/custody/transfers/${encodeURIComponent(transferCode)}/materials`, body, {
      token: this._getAccessToken(),
    });
  }

  async claimDeviceCopy(params: {
    aid: string;
    transferCode: string;
  }): Promise<JsonObject> {
    const aid = String(params.aid ?? '').trim();
    const transferCode = String(params.transferCode ?? '').trim();
    if (!aid || !transferCode) {
      throw new ValidationError('custody.claimDeviceCopy requires aid and transferCode');
    }
    return this._post('/custody/transfers/claim', {aid, transfer_code: transferCode});
  }
}
