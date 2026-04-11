// ── AuthNamespace（认证命名空间 — 完整实现）──────────────────

import type { AUNClient } from '../client.js';
import { AUNError, NotFoundError, StateError, ValidationError } from '../errors.js';
import { isJsonObject, type IdentityRecord, type JsonObject, type JsonValue, type RpcParams, type RpcResult } from '../types.js';

const AGENT_MD_HTTP_TIMEOUT_MS = 30_000;

interface AuthNamespaceResult extends IdentityRecord {
  gateway?: string;
  cert_pem?: string;
}

interface AuthFlowBridge {
  createAid: (url: string, aid: string) => Promise<IdentityRecord>;
  authenticate: (url: string, aid?: string) => Promise<AuthNamespaceResult>;
  loadIdentityOrNone: (aid?: string) => Promise<IdentityRecord | null>;
  getAccessTokenExpiry: (identity: IdentityRecord) => number | null;
  refreshCachedTokens?: (gatewayUrl: string, identity: IdentityRecord) => Promise<IdentityRecord>;
}

interface ClientBridge {
  _aid: string | null;
  _identity: IdentityRecord | null;
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

/**
 * 认证命名空间 — 提供 AID 注册、登录认证等高级操作。
 * 通过 AUNClient 内部的 AuthFlow 完成完整的 PKI 注册和两阶段认证。
 */
export class AuthNamespace {
  private _client: AUNClient;

  constructor(client: AUNClient) {
    this._client = client;
  }

  private get _internal(): ClientBridge {
    return this._client as any as ClientBridge;
  }

  /**
   * 解析 gateway URL。
   * 优先使用已预置的 gatewayUrl，否则基于 AID 自动发现。
   *
   * 发现流程：
   * 1. 若 gatewayUrl 已预置，直接返回
   * 2. https://{aid}/.well-known/aun-gateway（泛域名 nameservice）
   * 3. https://gateway.{issuer}/.well-known/aun-gateway（Gateway 直连）
   */
  private async _resolveGateway(aid?: string): Promise<string> {
    if (this._client.gatewayUrl) {
      return this._client.gatewayUrl;
    }

    const resolvedAid = aid ?? this._client.aid;
    if (resolvedAid) {
      const parts = resolvedAid.split('.');
      const issuerDomain = parts.length > 1 ? parts.slice(1).join('.') : resolvedAid;
      const port = this._client.configModel.discoveryPort;
      const portSuffix = port ? `:${port}` : '';

      // 尝试 nameservice 发现
      const primaryUrl = `https://${resolvedAid}${portSuffix}/.well-known/aun-gateway`;
      try {
        return await this._client.discovery.discover(primaryUrl);
      } catch {
        // 降级到 Gateway 直连
      }

      const fallbackUrl = `https://gateway.${issuerDomain}${portSuffix}/.well-known/aun-gateway`;
      return await this._client.discovery.discover(fallbackUrl);
    }

    throw new ValidationError(
      "unable to resolve gateway: set client.gatewayUrl or provide 'aid' for auto-discovery",
    );
  }

  /** 内部访问 client 私有属性 */
  /**
   * 注册新 AID。
   * 通过 well-known 发现 gateway → 调用 AuthFlow.createAid 注册。
   */
  async createAid(params: RpcParams): Promise<AuthNamespaceResult> {
    const aid = String(params?.aid ?? '');
    if (!aid) throw new ValidationError("auth.createAid requires 'aid'");

    const gatewayUrl = await this._resolveGateway(aid);
    this._client.gatewayUrl = gatewayUrl;

    const auth = this._internal._auth;
    const result = await auth.createAid(gatewayUrl, aid);
    this._internal._aid = result.aid ?? null;
    this._internal._identity = await auth.loadIdentityOrNone(String(result.aid));

    return {
      aid: result.aid,
      cert_pem: result.cert,
      gateway: gatewayUrl,
    };
  }

  /**
   * 认证已有 AID（login1 + login2 两阶段认证）。
   * 通过 well-known 发现 gateway → 调用 AuthFlow.authenticate。
   */
  async authenticate(params?: RpcParams): Promise<AuthNamespaceResult> {
    const request = { ...(params ?? {}) };
    const aid = request.aid as string | undefined;

    const gatewayUrl = await this._resolveGateway(aid);
    this._client.gatewayUrl = gatewayUrl;

    const auth = this._internal._auth;
    const result = await auth.authenticate(gatewayUrl, aid);
    this._internal._aid = result.aid ?? null;
    this._internal._identity = await auth.loadIdentityOrNone(String(result.aid));

    return result; // 包含 aid, access_token, refresh_token, expires_at, gateway
  }

  private async _resolveAgentMdUrl(aid: string): Promise<string> {
    const resolvedAid = String(aid ?? '').trim();
    if (!resolvedAid) {
      throw new ValidationError('agent.md requires non-empty aid');
    }
    let gatewayUrl = this._client.gatewayUrl ?? '';
    if (!gatewayUrl) {
      try {
        gatewayUrl = await this._resolveGateway(resolvedAid);
      } catch {
        gatewayUrl = '';
      }
    }
    const authority = agentMdAuthority(resolvedAid, this._client.configModel.discoveryPort);
    return `${agentMdHttpScheme(gatewayUrl)}://${authority}/agent.md`;
  }

  private async _ensureAgentMdUploadToken(aid: string, gatewayUrl: string): Promise<string> {
    const auth = this._internal._auth;

    let identity = await auth.loadIdentityOrNone(aid);
    if (!identity) {
      throw new StateError('no local identity found, call auth.createAid() first');
    }

    const cachedToken = String(identity.access_token ?? '');
    const expiresAt = auth.getAccessTokenExpiry(identity);
    if (cachedToken && (expiresAt === null || expiresAt > Date.now() / 1000 + 30)) {
      return cachedToken;
    }

    if (typeof auth.refreshCachedTokens === 'function' && identity.refresh_token) {
      try {
        identity = await auth.refreshCachedTokens(gatewayUrl, identity);
        const refreshedToken = String(identity.access_token ?? '');
        const refreshedExpiry = auth.getAccessTokenExpiry(identity);
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
    const auth = this._internal._auth;
    const identity = await auth.loadIdentityOrNone(this._client.aid ?? undefined);
    if (!identity) {
      throw new StateError('no local identity found, call auth.createAid() first');
    }
    const aid = String(identity.aid ?? this._client.aid ?? '').trim();
    if (!aid) {
      throw new StateError('no local identity found, call auth.createAid() first');
    }

    const gatewayUrl = await this._resolveGateway(aid);
    this._client.gatewayUrl = gatewayUrl;
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

  /** 下载证书（透传 RPC） */
  async downloadCert(params?: RpcParams): Promise<RpcResult> {
    return this._client.call('auth.download_cert', params ?? {});
  }

  /** 请求签发证书（透传 RPC） */
  async requestCert(params: RpcParams): Promise<RpcResult> {
    return this._client.call('auth.request_cert', params);
  }

  /** 续期证书（透传 RPC） */
  async renewCert(params?: RpcParams): Promise<RpcResult> {
    return this._client.call('auth.renew_cert', params ?? {});
  }

  /** 密钥轮换（透传 RPC） */
  async rekey(params?: RpcParams): Promise<RpcResult> {
    return this._client.call('auth.rekey', params ?? {});
  }

  /** 获取信任根（透传 RPC） */
  async trustRoots(params?: RpcParams): Promise<RpcResult> {
    return this._client.call('meta.trust_roots', params ?? {});
  }
}
