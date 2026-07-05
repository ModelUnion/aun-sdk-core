import { AID } from './aid.js';
import { certMatchesFingerprint, parseAgentMdTailSignature } from './cert-utils.js';
import { AUNError, ClientSignatureError, NotFoundError, StateError, ValidationError } from './errors.js';
import type { TokenStore } from './keystore/index.js';
import type { ModuleLogger } from './logger.js';
import { isJsonObject, type JsonObject } from './types.js';

const DEFAULT_HTTP_TIMEOUT_MS = 30_000;
const HEAD_HTTP_TIMEOUT_MS = 15_000;

const noopLogger: ModuleLogger = {
  error: () => {},
  warn: () => {},
  info: () => {},
  debug: () => {},
};

export type AgentMdVerification = { status: string; reason?: string };

export type AgentMdDownloadResult = {
  aid: string;
  content: string;
  verification: AgentMdVerification;
  signature: Record<string, unknown>;
  cert_pem: string;
  etag: string;
  last_modified: string;
  status: number;
  in_sync: boolean | null;
  saved_to: string | null;
  save_error: string | null;
};

export type AgentMdCheckResult = {
  aid: string;
  local_found: boolean;
  remote_found: boolean;
  local_etag: string;
  remote_etag: string;
  in_sync: boolean;
  needs_update: boolean;
  last_modified: string;
  status: number;
  cached: boolean;
  verify_status: string;
  verify_error: string;
  ttl_days: number;
};

type AgentMdHeadResult = {
  aid: string;
  found: boolean;
  etag: string;
  last_modified: string;
  content_length: number;
  status: number;
};

type AgentMdHttpResult = {
  content: string;
  etag: string;
  last_modified: string;
  status: number;
};

export interface AgentMdManagerOptions {
  aunPath: string;
  tokenStore?: TokenStore;
  logger?: ModuleLogger | null;
  ownerAidGetter?: () => string | null | undefined;
  currentAidGetter?: () => AID | null | undefined;
  gatewayResolver?: (aid: string) => Promise<string> | string;
  peerResolver?: (aid: string, certFingerprint?: string | null) => Promise<AID> | AID;
  accessTokenResolver?: (aid: string, gatewayUrl: string) => Promise<string> | string;
  aidValidator?: (aid: string) => void;
}

async function fetchWithTimeout(input: string, init: RequestInit, timeoutMs = DEFAULT_HTTP_TIMEOUT_MS): Promise<Response> {
  const controller = new AbortController();
  const timer = globalThis.setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } catch (error) {
    if (controller.signal.aborted) {
      throw new AUNError(`agent.md request timed out after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    globalThis.clearTimeout(timer);
  }
}

function headerValue(headers: Headers | undefined, name: string): string {
  return String(headers?.get(name) ?? headers?.get(name.toLowerCase()) ?? '').trim();
}

function agentMdHttpScheme(gatewayUrl: string): string {
  return String(gatewayUrl ?? '').trim().toLowerCase().startsWith('ws://') ? 'http' : 'https';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export class AgentMdManager {
  private _aunPath: string;
  private _agentMdPath: string;
  private _tokenStore?: TokenStore;
  private _log: ModuleLogger;
  private _ownerAidGetter?: () => string | null | undefined;
  private _currentAidGetter?: () => AID | null | undefined;
  private _gatewayResolver?: (aid: string) => Promise<string> | string;
  private _peerResolver?: (aid: string, certFingerprint?: string | null) => Promise<AID> | AID;
  private _accessTokenResolver?: (aid: string, gatewayUrl: string) => Promise<string> | string;
  private _aidValidator?: (aid: string) => void;
  private _cache: Map<string, Record<string, unknown>> = new Map();
  private _memoryStorage: Map<string, string> = new Map();
  private _fetchInflight: Set<string> = new Set();
  private _lock: Promise<unknown> = Promise.resolve();
  private _localAgentMdEtag = '';
  private _remoteAgentMdEtag = '';

  constructor(opts: AgentMdManagerOptions) {
    this._aunPath = String(opts.aunPath ?? '');
    this._agentMdPath = this._defaultRoot();
    this._tokenStore = opts.tokenStore;
    this._log = opts.logger ?? noopLogger;
    this._ownerAidGetter = opts.ownerAidGetter;
    this._currentAidGetter = opts.currentAidGetter;
    this._gatewayResolver = opts.gatewayResolver;
    this._peerResolver = opts.peerResolver;
    this._accessTokenResolver = opts.accessTokenResolver;
    this._aidValidator = opts.aidValidator;
  }

  get root(): string {
    return this._agentMdPath || this._defaultRoot();
  }

  setAunPath(aunPath: string): void {
    this._aunPath = String(aunPath ?? '');
    this.setRoot(null);
  }

  setRoot(root?: string | null): string {
    this._agentMdPath = String(root ?? '').trim() || this._defaultRoot();
    this._cache.clear();
    this._memoryStorage.clear();
    this._fetchInflight.clear();
    this._localAgentMdEtag = '';
    this._remoteAgentMdEtag = '';
    return this._agentMdPath;
  }

  async upload(content?: string | null): Promise<Record<string, unknown>> {
    const target = this._ownerAid();
    const current = this._currentAid();
    if (!target || !current) {
      throw new ValidationError('uploadAgentMd requires local AID');
    }
    if (!current.isPrivateKeyValid()) {
      throw new StateError('uploadAgentMd requires loaded AID with a valid private key');
    }

    if (content !== undefined && content !== null) {
      const text = String(content ?? '');
      if (text.length === 0) throw new ValidationError('uploadAgentMd requires non-empty content');
      await this.saveRecord(target, {
        content: text,
        local_etag: await AgentMdManager.contentEtag(text),
        fetched_at: Date.now(),
      });
    }

    const localContent = await this.readContent(target);
    if (localContent === null || localContent.length === 0) {
      throw new ValidationError('uploadAgentMd requires local agent.md content');
    }
    const signedResult = await current.signAgentMd(localContent);
    if (!signedResult.ok) {
      throw new ClientSignatureError(signedResult.error.message || 'agent.md signing failed');
    }

    const signed = signedResult.data.signed;
    const result = await this._uploadHttp(target, signed);
    const localEtag = await AgentMdManager.contentEtag(signed);
    const remoteEtag = String(result.etag ?? '').trim();
    await this.saveRecord(target, {
      content: signed,
      local_etag: localEtag,
      remote_etag: remoteEtag || undefined,
      last_modified: String(result.last_modified ?? result.lastModified ?? '').trim(),
      fetched_at: Date.now(),
      checked_at: Date.now(),
      remote_status: remoteEtag ? 'found' : 'unknown',
      last_error: '',
    });
    return result;
  }

  async download(aid?: string | null, timeoutMs = DEFAULT_HTTP_TIMEOUT_MS): Promise<AgentMdDownloadResult> {
    const target = this._safeAid(String(aid ?? this._ownerAid() ?? '').trim());
    const contentResult = await this._downloadHttp(target, timeoutMs);
    const parsed = parseAgentMdTailSignature(contentResult.content);
    const expectedFp = parsed.fields?.cert_fingerprint || parsed.fields?.public_key_fingerprint || null;
    const peer = await this._resolvePeer(target, expectedFp);
    const verified = await peer.verifyAgentMd(contentResult.content);
    if (!verified.ok) throw new AUNError(verified.error.message);

    const signature = { ...verified.data } as Record<string, unknown>;
    const statusText = String(signature.status ?? 'invalid');
    const reason = String(signature.reason ?? '').trim();
    const verification: AgentMdVerification = { status: statusText };
    if (reason) verification.reason = reason;

    const localEtag = await AgentMdManager.contentEtag(contentResult.content);
    const saved = await this.saveRecord(target, {
      content: contentResult.content,
      local_etag: localEtag,
      remote_etag: contentResult.etag || undefined,
      last_modified: contentResult.last_modified || undefined,
      fetched_at: Date.now(),
      checked_at: Date.now(),
      remote_status: 'found',
      verify_status: statusText,
      verify_error: reason,
      last_error: '',
    });

    let inSync: boolean | null = null;
    if (target === this._ownerAid()) {
      const remote = contentResult.etag || String(saved.remote_etag ?? '');
      inSync = localEtag && remote ? localEtag === remote : false;
    }
    return {
      aid: target,
      content: contentResult.content,
      verification,
      signature,
      cert_pem: peer.certPem,
      etag: contentResult.etag,
      last_modified: contentResult.last_modified,
      status: contentResult.status,
      in_sync: inSync,
      saved_to: this._logicalPath(this._contentKey(target)),
      save_error: null,
    };
  }

  async check(aid?: string | null, ttlDays = 1): Promise<AgentMdCheckResult> {
    const target = this._safeAid(String(aid ?? this._ownerAid() ?? '').trim());
    const before = await this.loadRecord(target) ?? {};
    const localEtag = String(before.local_etag ?? '').trim();
    const localFound = !!(Object.keys(before).length > 0 && (String(before.content ?? '') || localEtag));
    const remoteEtagCached = String(before.remote_etag ?? before.etag ?? '').trim();
    const lastModifiedCached = String(before.last_modified ?? '').trim();
    const checkedAtCached = Number(before.checked_at ?? 0) || 0;
    const cacheFresh = AgentMdManager.checkedAtFresh(checkedAtCached, ttlDays) || AgentMdManager.lastModifiedFresh(lastModifiedCached, ttlDays);
    if (localFound && localEtag && remoteEtagCached && localEtag === remoteEtagCached && cacheFresh) {
      return {
        aid: target,
        local_found: true,
        remote_found: true,
        local_etag: localEtag,
        remote_etag: remoteEtagCached,
        in_sync: true,
        needs_update: false,
        last_modified: lastModifiedCached,
        status: 200,
        cached: true,
        verify_status: String(before.verify_status ?? ''),
        verify_error: String(before.verify_error ?? ''),
        ttl_days: Number(ttlDays) || 0,
      };
    }

    const now = Date.now();
    let remote: AgentMdHeadResult;
    try {
      remote = await this._head(target);
    } catch (err) {
      await this.saveRecord(target, { checked_at: now, remote_status: 'error', last_error: err instanceof Error ? err.message : String(err) });
      throw err;
    }
    const remoteFound = !!remote.found;
    const remoteEtag = String(remote.etag ?? '').trim();
    const lastModified = String(remote.last_modified ?? '').trim();
    const saved = await this.saveRecord(target, {
      remote_etag: remoteFound ? remoteEtag : '',
      last_modified: lastModified,
      checked_at: now,
      remote_status: remoteFound ? 'found' : 'missing',
      last_error: '',
    });
    const inSync = !!(localFound && remoteFound && localEtag && remoteEtag && localEtag === remoteEtag);
    return {
      aid: target,
      local_found: localFound,
      remote_found: remoteFound,
      local_etag: localEtag,
      remote_etag: remoteEtag,
      in_sync: inSync,
      needs_update: !!(remoteFound && !inSync),
      last_modified: lastModified,
      status: Number(remote.status ?? (remoteFound ? 200 : 404)),
      cached: false,
      verify_status: String(saved.verify_status ?? before.verify_status ?? ''),
      verify_error: String(saved.verify_error ?? before.verify_error ?? ''),
      ttl_days: Number(ttlDays) || 0,
    };
  }

  async observeMeta(aid: string, etag = '', lastModified = '', source = ''): Promise<void> {
    const target = String(aid ?? '').trim();
    const remoteEtag = String(etag ?? '').trim();
    const remoteLastModified = String(lastModified ?? '').trim();
    if (!target || (!remoteEtag && !remoteLastModified)) return;
    let before = this._cache.get(target);
    if (!before || typeof before !== 'object') before = await this.loadRecord(target) ?? {};
    const same =
      (!remoteEtag || String(before.remote_etag ?? '').trim() === remoteEtag) &&
      (!remoteLastModified || String(before.last_modified ?? '').trim() === remoteLastModified);
    let record: Record<string, unknown> = { ...before };
    if (!same || Object.keys(before).length === 0) {
      const fields: Record<string, unknown> = {
        observed_at: Date.now(),
        remote_status: 'found',
      };
      if (remoteEtag) fields.remote_etag = remoteEtag;
      if (remoteLastModified) fields.last_modified = remoteLastModified;
      record = await this.saveRecord(target, fields) || record;
    }
    if (target === this._ownerAid() && remoteEtag) this._remoteAgentMdEtag = remoteEtag;
    await this._scheduleFetchIfMissing(target, record, source);
    this._log.debug(`agent.md meta observed: aid=${target} etag=${remoteEtag || '-'} last_modified=${remoteLastModified || '-'} source=${source || '-'}`);
  }

  async observeRpcMeta(meta: JsonObject, ownerAid?: string | null): Promise<void> {
    if (!isJsonObject(meta)) return;
    const owner = String(ownerAid ?? this._ownerAid() ?? '').trim();
    const etag = String(meta.agent_md_etag ?? '').trim();
    if (etag && owner) {
      this._remoteAgentMdEtag = etag;
      await this.observeMeta(owner, etag, '', 'rpc.self');
    }
    const etags = meta.agent_md_etags;
    if (!isJsonObject(etags)) return;
    for (const key of ['requester', 'peer', 'group', 'receiver', 'target', 'to', 'sender', 'from']) {
      const item = etags[key];
      if (!isJsonObject(item)) continue;
      await this.observeMeta(
        String(item.aid ?? ''),
        String(item.etag ?? ''),
        String(item.last_modified ?? item.lastModified ?? ''),
        `rpc.${key}`,
      );
    }
  }

  async observeEnvelope(envelope: unknown): Promise<void> {
    if (!isJsonObject(envelope)) return;
    if (!isJsonObject(envelope.agent_md)) return;
    const agentMd = envelope.agent_md;
    if (isJsonObject(agentMd.sender)) {
      const sender = agentMd.sender;
      let senderAid = String(sender.aid ?? '').trim();
      if (!senderAid) {
        const aad = isJsonObject(envelope.aad) ? envelope.aad : {};
        senderAid = String(aad.from ?? envelope.from ?? '').trim();
      }
      await this.observeMeta(
        senderAid,
        String(sender.etag ?? '').trim(),
        String(sender.last_modified ?? sender.lastModified ?? '').trim(),
        'envelope.sender',
      );
    }
    if (isJsonObject(agentMd.group)) {
      const group = agentMd.group;
      let groupAid = String(group.aid ?? '').trim();
      if (!groupAid) {
        const aad = isJsonObject(envelope.aad) ? envelope.aad : {};
        groupAid = String(envelope.group_aid ?? envelope.group_id ?? aad.group_aid ?? aad.group_id ?? '').trim();
      }
      await this.observeMeta(
        groupAid,
        String(group.etag ?? '').trim(),
        String(group.last_modified ?? group.lastModified ?? '').trim(),
        'envelope.group',
      );
    }
  }

  eventSnapshot(): { local_etag: string; remote_etag: string } | null {
    if (!this._localAgentMdEtag && !this._remoteAgentMdEtag) return null;
    return { local_etag: this._localAgentMdEtag, remote_etag: this._remoteAgentMdEtag };
  }

  async readContent(aid: string): Promise<string | null> {
    return await this._readStorage(this._contentKey(aid));
  }

  async writeContent(aid: string, content: string): Promise<void> {
    await this._writeStorage(this._contentKey(aid), String(content ?? ''));
  }

  async loadRecord(aid: string): Promise<Record<string, unknown> | null> {
    const target = String(aid ?? '').trim();
    if (!target) return null;
    try {
      const loaded = await this._withLock(async () => {
        const record = await this._readRecordUnlocked(target);
        const next: Record<string, unknown> = Object.keys(record).length > 0 ? { ...record, aid: target } : { aid: target };
        try {
          const content = await this.readContent(target);
          if (content !== null) {
            next.content = content;
            next.local_etag = await AgentMdManager.contentEtag(content);
          } else {
            const metaRaw = await this._readStorage(this._metaKey(target));
            if (metaRaw !== null) this._log.warn(`agent.md content read failed: aid=${target}`);
          }
        } catch (err) {
          this._log.warn(`agent.md content read failed: aid=${target} err=${err instanceof Error ? err.message : String(err)}`);
        }
        return next;
      });
      if (Object.keys(loaded).length <= 1) return null;
      this._cache.set(target, { ...loaded });
      this._refreshOwnerEtags(target, loaded);
      return { ...loaded };
    } catch (err) {
      this._log.debug(`agent.md cache load skipped: aid=${target} err=${err instanceof Error ? err.message : String(err)}`);
      return null;
    }
  }

  async saveRecord(aid: string, fields: Record<string, unknown>): Promise<Record<string, unknown>> {
    const target = String(aid ?? '').trim();
    if (!target) return {};
    try {
      const inputFields: Record<string, unknown> = { ...fields };
      const hasContent = Object.prototype.hasOwnProperty.call(inputFields, 'content') && inputFields.content !== undefined && inputFields.content !== null;
      if (hasContent) {
        const text = String(inputFields.content ?? '');
        await this.writeContent(target, text);
        if (!inputFields.local_etag) inputFields.local_etag = await AgentMdManager.contentEtag(text);
        if (!inputFields.fetched_at) inputFields.fetched_at = Date.now();
      }
      delete inputFields.content;
      const record = await this._withLock(async () => {
        const next: Record<string, unknown> = { ...(await this._readRecordUnlocked(target)), aid: target };
        for (const [key, value] of Object.entries(inputFields)) {
          if (value !== undefined && value !== null) next[key] = value;
        }
        next.updated_at = Date.now();
        await this._writeRecordUnlocked(target, next);
        return next;
      });
      const loaded: Record<string, unknown> = { ...record };
      if (hasContent) loaded.content = String(fields.content ?? '');
      this._cache.set(target, { ...loaded });
      this._refreshOwnerEtags(target, loaded);
      return { ...loaded };
    } catch (err) {
      this._log.debug(`agent.md cache save skipped: aid=${target} err=${err instanceof Error ? err.message : String(err)}`);
      return {};
    }
  }

  static async contentEtag(content: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(content ?? '')));
    const hex = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
    return `"${hex}"`;
  }

  private static checkedAtFresh(checkedAtMs: number, ttlDays: number): boolean {
    const days = Number(ttlDays || 0);
    if (!Number.isFinite(days) || days <= 0) return false;
    if (!Number.isFinite(checkedAtMs) || checkedAtMs <= 0) return false;
    return Date.now() - checkedAtMs <= days * 86400000;
  }

  private static lastModifiedFresh(lastModified: string, ttlDays: number): boolean {
    const days = Number(ttlDays || 0);
    if (!Number.isFinite(days) || days <= 0) return false;
    const ts = Date.parse(String(lastModified ?? '').trim());
    if (!Number.isFinite(ts)) return false;
    return Date.now() <= ts + days * 86400000;
  }

  private _defaultRoot(): string {
    return this._joinPath(this._aunPath || '.', 'AIDs');
  }

  private _joinPath(base: string, name: string): string {
    const left = String(base ?? '').trim().replace(/[\\/]+$/g, '');
    return left ? `${left}/${name}` : name;
  }

  private _logicalPath(key: string): string {
    return this._joinPath(this.root, key);
  }

  private _safeAid(aid: string): string {
    const target = String(aid ?? '').trim();
    if (!target || target.includes('/') || target.includes('\\') || target.includes('\0')) {
      throw new ValidationError('agent.md aid is empty or contains path separators');
    }
    this._aidValidator?.(target);
    return target;
  }

  private _metaKey(aid: string): string {
    return `${this._safeAid(aid)}/agentmd.json`;
  }

  private _contentKey(aid: string): string {
    return `${this._safeAid(aid)}/agent.md`;
  }

  private _ownerAid(): string {
    return String(this._ownerAidGetter?.() ?? '').trim();
  }

  private _currentAid(): AID | null {
    return this._currentAidGetter?.() ?? null;
  }

  private async _resolveGateway(aid: string): Promise<string> {
    return String(await this._gatewayResolver?.(aid) ?? '');
  }

  private async _resolvePeer(aid: string, certFingerprint?: string | null): Promise<AID> {
    const expectedFp = String(certFingerprint ?? '').trim().toLowerCase();
    const current = this._currentAid();
    if (current?.aid === aid) {
      if (!expectedFp || await certMatchesFingerprint(current.certPem, expectedFp)) return current;
      throw new StateError(`current AID certificate fingerprint mismatch for ${aid}`);
    }
    const peer = await this._peerResolver?.(aid, expectedFp || null);
    if (!(peer instanceof AID)) {
      throw new StateError(`agent.md peer resolver did not return AID for ${aid}`);
    }
    return peer;
  }

  private async _accessToken(aid: string, gatewayUrl: string): Promise<string> {
    const token = String(await this._accessTokenResolver?.(aid, gatewayUrl) ?? '').trim();
    if (!token) throw new StateError('authenticate did not return access_token');
    return token;
  }

  private _url(aid: string, gatewayUrl: string): string {
    return `${agentMdHttpScheme(gatewayUrl)}://${this._safeAid(aid)}/agent.md`;
  }

  private async _uploadHttp(aid: string, content: string): Promise<Record<string, unknown>> {
    const gatewayUrl = await this._resolveGateway(aid);
    const token = await this._accessToken(aid, gatewayUrl);
    const response = await fetchWithTimeout(this._url(aid, gatewayUrl), {
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
      throw new AUNError(`upload agent.md failed: HTTP ${response.status}${message ? ` - ${message}` : ''}`);
    }
    const payload = await response.json() as unknown;
    if (!isJsonObject(payload)) throw new AUNError('upload agent.md returned invalid JSON payload');
    return payload as Record<string, unknown>;
  }

  private async _downloadHttp(aid: string, timeoutMs: number): Promise<AgentMdHttpResult> {
    const target = this._safeAid(aid);
    const cached = await this.loadRecord(target) ?? {};
    const gatewayUrl = await this._resolveGateway(target);
    const url = this._url(target, gatewayUrl);
    const headers: Record<string, string> = { Accept: 'text/markdown' };
    const cachedEtag = String(cached.remote_etag ?? cached.etag ?? cached.local_etag ?? '').trim();
    const cachedLastModified = String(cached.last_modified ?? '').trim();

    let response = await fetchWithTimeout(url, {
      method: 'GET',
      headers,
      redirect: 'follow',
    }, timeoutMs);

    if (response.status === 304 && cached.content !== undefined && cached.content !== null) {
      return {
        content: String(cached.content),
        etag: headerValue(response.headers, 'ETag') || cachedEtag,
        last_modified: headerValue(response.headers, 'Last-Modified') || cachedLastModified,
        status: response.status,
      };
    }
    if (response.status === 304) {
      response = await fetchWithTimeout(url, {
        method: 'GET',
        headers: { Accept: 'text/markdown' },
        redirect: 'follow',
      }, timeoutMs);
    }
    if (response.status === 404) {
      await this.saveRecord(target, { remote_status: 'missing', checked_at: Date.now(), last_error: '' });
      throw new NotFoundError(`agent.md not found for aid: ${target}`);
    }
    if (!response.ok) {
      const message = (await response.text()).trim();
      throw new AUNError(`download agent.md failed: HTTP ${response.status}${message ? ` - ${message}` : ''}`);
    }
    const content = await response.text();
    return {
      content,
      etag: headerValue(response.headers, 'ETag') || cachedEtag,
      last_modified: headerValue(response.headers, 'Last-Modified') || cachedLastModified,
      status: response.status,
    };
  }

  private async _head(aid: string): Promise<AgentMdHeadResult> {
    const target = this._safeAid(aid);
    const gatewayUrl = await this._resolveGateway(target);
    const response = await fetchWithTimeout(this._url(target, gatewayUrl), {
      method: 'HEAD',
      headers: { Accept: 'text/markdown' },
    }, HEAD_HTTP_TIMEOUT_MS);
    const etag = headerValue(response.headers, 'ETag');
    const lastModified = headerValue(response.headers, 'Last-Modified');
    if (response.status === 404) {
      await this.saveRecord(target, {
        remote_etag: '',
        last_modified: '',
        checked_at: Date.now(),
        remote_status: 'missing',
        last_error: '',
      });
      return { aid: target, found: false, etag: '', last_modified: '', content_length: 0, status: 404 };
    }
    if (!response.ok) {
      throw new AUNError(`head agent.md failed: HTTP ${response.status}`);
    }
    const contentLength = Number.parseInt(headerValue(response.headers, 'Content-Length') || '0', 10) || 0;
    const data = { aid: target, found: true, etag, last_modified: lastModified, content_length: contentLength, status: response.status };
    await this.saveRecord(target, {
      remote_etag: etag,
      last_modified: lastModified,
      checked_at: Date.now(),
      remote_status: 'found',
      last_error: '',
    });
    return data;
  }

  private async _readStorage(logicalKey: string): Promise<string | null> {
    const key = String(logicalKey ?? '').trim();
    if (!key) return null;
    const load = this._tokenStore?.loadAgentMdCache;
    if (typeof load === 'function') {
      const record = await load.call(this._tokenStore, this.root, key);
      if (record && Object.prototype.hasOwnProperty.call(record, 'content')) {
        return String(record.content ?? '');
      }
      return null;
    }
    return this._memoryStorage.has(key) ? String(this._memoryStorage.get(key) ?? '') : null;
  }

  private async _writeStorage(logicalKey: string, content: string): Promise<void> {
    const key = String(logicalKey ?? '').trim();
    if (!key) return;
    const save = this._tokenStore?.upsertAgentMdCache;
    const text = String(content ?? '');
    if (typeof save === 'function') {
      await save.call(this._tokenStore, this.root, key, {
        content: text,
        local_etag: await AgentMdManager.contentEtag(text),
        fetched_at: Date.now(),
      });
      return;
    }
    this._memoryStorage.set(key, text);
  }

  private async _withLock<T>(fn: () => Promise<T>): Promise<T> {
    const previous = this._lock.catch(() => undefined);
    let release!: () => void;
    const current = new Promise<void>((resolve) => { release = resolve; });
    this._lock = previous.then(() => current);
    await previous;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  private _normalizeRecord(aid: string, data: unknown): Record<string, unknown> {
    if (!isRecord(data)) return {};
    const record: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data)) {
      if (key !== 'content') record[key] = value;
    }
    record.aid = this._safeAid(String(record.aid ?? aid));
    for (const key of ['fetched_at', 'observed_at', 'checked_at', 'updated_at']) {
      record[key] = Number(record[key] ?? 0) || 0;
    }
    return record;
  }

  private async _writeRecordUnlocked(aid: string, record: Record<string, unknown>): Promise<void> {
    const payload: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(record)) {
      if (key !== 'content' && value !== undefined && value !== null) payload[key] = value;
    }
    payload.aid = this._safeAid(aid);
    await this._writeStorage(this._metaKey(aid), `${JSON.stringify(payload, null, 2)}\n`);
  }

  private async _readRecordUnlocked(aid: string): Promise<Record<string, unknown>> {
    const raw = await this._readStorage(this._metaKey(aid));
    if (raw === null) return {};
    try {
      return this._normalizeRecord(aid, JSON.parse(raw));
    } catch (err) {
      this._log.warn(`agent.md metadata damaged, ignoring: aid=${aid} err=${err instanceof Error ? err.message : String(err)}`);
      return {};
    }
  }

  private async _hasLocalContent(aid: string, record?: Record<string, unknown> | null): Promise<boolean> {
    if (record && typeof record.content === 'string' && record.content.length > 0) return true;
    try {
      return (await this.readContent(aid)) !== null;
    } catch {
      return false;
    }
  }

  private async _scheduleFetchIfMissing(aid: string, record?: Record<string, unknown> | null, source = ''): Promise<void> {
    const target = String(aid ?? '').trim();
    if (!target || await this._hasLocalContent(target, record)) return;
    if (this._fetchInflight.has(target)) return;
    this._fetchInflight.add(target);
    try {
      await this.download(target);
    } catch (err) {
      await this.saveRecord(target, {
        last_error: err instanceof Error ? err.message : String(err),
        remote_status: 'found',
      });
      this._log.debug(`agent.md auto fetch failed: aid=${target} source=${source || '-'} err=${err instanceof Error ? err.message : String(err)}`);
    } finally {
      this._fetchInflight.delete(target);
    }
  }

  private _refreshOwnerEtags(aid: string, record: Record<string, unknown>): void {
    if (aid !== this._ownerAid()) return;
    const localEtag = String(record.local_etag ?? '').trim();
    const remoteEtag = String(record.remote_etag ?? '').trim();
    if (localEtag) this._localAgentMdEtag = localEtag;
    if (remoteEtag) this._remoteAgentMdEtag = remoteEtag;
  }
}
