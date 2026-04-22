import type { AUNClient } from '../client.js';
import { AUNError, ValidationError } from '../errors.js';
import { isJsonObject, type JsonObject, type JsonValue } from '../types.js';

const CUSTODY_HTTP_TIMEOUT_MS = 30_000;

interface ClientBridge {
  _identity: JsonObject | null;
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

  private _getCustodyUrl(): string {
    if (this._custodyUrl) {
      return this._custodyUrl;
    }
    const configured = String(this._client.configModel.custodyUrl ?? '').trim().replace(/\/+$/, '');
    if (configured) {
      this._custodyUrl = configured;
      return configured;
    }
    throw new ValidationError(
      "custody_url not configured: set client config 'custodyUrl' or call client.custody.setUrl()",
    );
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
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    const token = String(opts.token ?? '').trim();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    const payload = await fetchJsonWithTimeout(
      `${this._getCustodyUrl()}${path}`,
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
    const body: JsonObject = { phone };
    let token: string | null = null;
    if (aid) {
      body.aid = aid;
    } else {
      token = this._getAccessToken();
    }
    return this._post('/custody/accounts/send-code', body, { token });
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
    const body: JsonObject = { phone, code, cert, key };
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
    return this._post('/custody/accounts/restore-phone', { phone, code, aid });
  }
}
