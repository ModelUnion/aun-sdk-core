/**
 * Auth 命名空间
 *
 * 提供 auth.createAid / auth.authenticate 等高层方法，
 * 内部通过 AUNClient 的 transport、auth、discovery 完成实际流程。
 *
 * 与 Python SDK 的 AuthNamespace 完全对齐。
 */

import { AUNError, NotFoundError, StateError, ValidationError } from '../errors.js';
import type { AUNConfig } from '../config.js';
import type { AUNClient } from '../client.js';
import { isJsonObject, type IdentityRecord, type JsonObject, type JsonValue, type RpcParams, type RpcResult } from '../types.js';

const AGENT_MD_HTTP_TIMEOUT_MS = 30_000;

interface AuthNamespaceResult extends IdentityRecord {
  gateway?: string;
  cert_pem?: string;
}

interface AuthFlowBridge {
  createAid: (url: string, aid: string) => Promise<IdentityRecord>;
  authenticate: (url: string, opts?: { aid?: string }) => Promise<AuthNamespaceResult>;
  loadIdentityOrNone: (aid?: string) => IdentityRecord | null;
  getAccessTokenExpiry?: (identity: IdentityRecord) => number | null;
  refreshCachedTokens?: (gatewayUrl: string, identity: IdentityRecord) => Promise<IdentityRecord>;
}

interface ClientBridge {
  _aid: string | null;
  _gatewayUrl: string | null;
  _identity: IdentityRecord | null;
  _configModel: AUNConfig;
  _discovery: {
    discover: (url: string) => Promise<string>;
  };
  _auth: AuthFlowBridge;
}

function agentMdHttpScheme(gatewayUrl: string): string {
  const raw = String(gatewayUrl ?? '').trim().toLowerCase();
  return raw.startsWith('ws://') ? 'http' : 'https';
}

function agentMdAuthority(aid: string, discoveryPort: number | null | undefined): string {
  const host = String(aid ?? '').trim();
  if (!host) return '';
  if (discoveryPort && !host.includes(':')) {
    return `${host}:${discoveryPort}`;
  }
  return host;
}

async function fetchWithTimeout(
  input: string,
  init: RequestInit,
  timeoutMs: number = AGENT_MD_HTTP_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } catch (error) {
    if (controller.signal.aborted) {
      throw new AUNError(`agent.md request timed out after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export class AuthNamespace {
  private _client: AUNClient;

  constructor(client: AUNClient) {
    this._client = client;
  }

  private get _internal(): ClientBridge {
    return this._client as any as ClientBridge;
  }

  /**
   * 解析 Gateway URL。
   * 优先使用已预置的 _gatewayUrl，否则基于 AID 自动发现。
   *
   * 发现流程：
   * 1. 若 _gatewayUrl 已预置，直接返回
   * 2. https://{aid}/.well-known/aun-gateway（泛域名 nameservice）
   * 3. https://gateway.{issuer}/.well-known/aun-gateway（Gateway 直连）
   */
  async _resolveGateway(aid?: string): Promise<string> {
    // 访问内部属性
    const client = this._internal;
    const gatewayUrl = client._gatewayUrl;
    if (gatewayUrl) return gatewayUrl;

    const resolvedAid = aid ?? client._aid;
    if (resolvedAid) {
      const parts = resolvedAid.split('.');
      const issuerDomain = parts.length > 1 ? parts.slice(1).join('.') : resolvedAid;

      const configModel = client._configModel;
      const port = configModel.discoveryPort;
      const portSuffix = port ? `:${port}` : '';

      const primaryUrl = `https://${resolvedAid}${portSuffix}/.well-known/aun-gateway`;
      const discovery = client._discovery;

      try {
        return await discovery.discover(primaryUrl);
      } catch {
        // 主路径失败，尝试 fallback
      }

      const fallbackUrl = `https://gateway.${issuerDomain}${portSuffix}/.well-known/aun-gateway`;
      return await discovery.discover(fallbackUrl);
    }

    throw new ValidationError(
      "unable to resolve gateway: set client._gatewayUrl or provide 'aid' for auto-discovery",
    );
  }

  /** 创建新 AID */
  async createAid(params: RpcParams): Promise<AuthNamespaceResult> {
    const aid = String(params?.aid ?? '');
    if (!aid) throw new Error("auth.create_aid requires 'aid'");

    const client = this._internal;
    const gatewayUrl = await this._resolveGateway(aid);
    client._gatewayUrl = gatewayUrl;

    const auth = client._auth;
    const result = await auth.createAid(gatewayUrl, aid);
    client._aid = result.aid ?? null;
    client._identity = auth.loadIdentityOrNone(String(result.aid));

    return {
      aid: result.aid,
      cert_pem: result.cert,
      gateway: gatewayUrl,
    };
  }

  /** 认证（登录） */
  async authenticate(params?: RpcParams): Promise<AuthNamespaceResult> {
    const request = { ...(params ?? {}) };
    const aid = request.aid as string | undefined;

    const client = this._internal;
    const gatewayUrl = await this._resolveGateway(aid);
    client._gatewayUrl = gatewayUrl;

    const auth = client._auth;
    const result = await auth.authenticate(gatewayUrl, { aid });
    client._aid = result.aid ?? null;
    client._identity = auth.loadIdentityOrNone(String(result.aid));

    return result;
  }

  private async _resolveAgentMdUrl(aid: string): Promise<string> {
    const resolvedAid = String(aid ?? '').trim();
    if (!resolvedAid) {
      throw new ValidationError('agent.md requires non-empty aid');
    }
    const client = this._internal;
    let gatewayUrl = client._gatewayUrl ?? '';
    if (!gatewayUrl) {
      try {
        gatewayUrl = await this._resolveGateway(resolvedAid);
      } catch {
        gatewayUrl = '';
      }
    }
    const configModel = client._configModel;
    const discoveryPort = configModel.discoveryPort;
    const authority = agentMdAuthority(resolvedAid, discoveryPort);
    return `${agentMdHttpScheme(gatewayUrl)}://${authority}/agent.md`;
  }

  private async _ensureAgentMdUploadToken(aid: string, gatewayUrl: string): Promise<string> {
    const auth = this._internal._auth;

    let identity = auth.loadIdentityOrNone(aid);
    if (!identity) {
      throw new StateError('no local identity found, call auth.createAid() first');
    }

    const cachedToken = String(identity.access_token ?? '');
    const expiresAt = auth.getAccessTokenExpiry ? auth.getAccessTokenExpiry(identity) : null;
    if (cachedToken && (expiresAt === null || expiresAt > Date.now() / 1000 + 30)) {
      return cachedToken;
    }

    if (typeof auth.refreshCachedTokens === 'function' && identity.refresh_token) {
      try {
        identity = await auth.refreshCachedTokens(gatewayUrl, identity);
        const refreshedToken = String(identity.access_token ?? '');
        const refreshedExpiry = auth.getAccessTokenExpiry ? auth.getAccessTokenExpiry(identity) : null;
        if (refreshedToken && (refreshedExpiry === null || refreshedExpiry > Date.now() / 1000 + 30)) {
          return refreshedToken;
        }
      } catch {
        // refresh 失败时回退到完整 authenticate
      }
    }

    const result = await this.authenticate({ aid });
    const token = String(result.access_token ?? '');
    if (!token) {
      throw new StateError('authenticate did not return access_token');
    }
    return token;
  }

  async uploadAgentMd(content: string): Promise<JsonObject> {
    const client = this._internal;
    const auth = client._auth;
    const identity = auth.loadIdentityOrNone(client._aid ?? undefined);
    if (!identity) {
      throw new StateError('no local identity found, call auth.createAid() first');
    }
    const aid = String(identity.aid ?? client._aid ?? '').trim();
    if (!aid) {
      throw new StateError('no local identity found, call auth.createAid() first');
    }

    const gatewayUrl = await this._resolveGateway(aid);
    client._gatewayUrl = gatewayUrl;
    const token = await this._ensureAgentMdUploadToken(aid, gatewayUrl);
    const response = await fetchWithTimeout(await this._resolveAgentMdUrl(aid), {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'text/markdown; charset=utf-8',
      },
      body: content,
    });

    if (response.status === 404) {
      throw new NotFoundError(`agent.md endpoint not found for aid: ${aid}`);
    }
    if (!response.ok) {
      const message = (await response.text()).trim();
      throw new AUNError(
        `upload agent.md failed: HTTP ${response.status}${message ? ` - ${message}` : ''}`,
      );
    }
    const payload = await response.json() as JsonValue;
    if (!isJsonObject(payload)) {
      throw new AUNError('upload agent.md returned invalid JSON payload');
    }
    return payload;
  }

  async downloadAgentMd(aid: string): Promise<string> {
    const targetAid = String(aid ?? '').trim();
    if (!targetAid) {
      throw new ValidationError('downloadAgentMd requires non-empty aid');
    }
    const response = await fetchWithTimeout(await this._resolveAgentMdUrl(targetAid), {
      method: 'GET',
      headers: {
        Accept: 'text/markdown',
      },
    });

    if (response.status === 404) {
      throw new NotFoundError(`agent.md not found for aid: ${targetAid}`);
    }
    if (!response.ok) {
      const message = (await response.text()).trim();
      throw new AUNError(
        `download agent.md failed: HTTP ${response.status}${message ? ` - ${message}` : ''}`,
      );
    }
    return await response.text();
  }

  /** 下载证书 */
  async downloadCert(params?: RpcParams): Promise<RpcResult> {
    return await this._client.call('auth.download_cert', params ?? {});
  }

  /** 请求签发证书 */
  async requestCert(params: RpcParams): Promise<RpcResult> {
    return await this._client.call('auth.request_cert', params);
  }

  /** 续期证书 */
  async renewCert(params?: RpcParams): Promise<RpcResult> {
    return await this._client.call('auth.renew_cert', params ?? {});
  }

  /** 密钥轮换 */
  async rekey(params?: RpcParams): Promise<RpcResult> {
    return await this._client.call('auth.rekey', params ?? {});
  }

  /** 获取信任根证书列表 */
  async trustRoots(params?: RpcParams): Promise<RpcResult> {
    return await this._client.call('meta.trust_roots', params ?? {});
  }
}
