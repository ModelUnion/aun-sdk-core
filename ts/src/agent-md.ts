import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as path from 'node:path';

import { AID } from './aid.js';
import {
  AUNError,
  ClientSignatureError,
  NotFoundError,
  StateError,
  ValidationError,
} from './errors.js';
import type { ModuleLogger } from './logger.js';
import { isJsonObject, type JsonObject, type JsonValue } from './types.js';

const DEFAULT_HTTP_TIMEOUT_MS = 30_000;
const HEAD_HTTP_TIMEOUT_MS = 15_000;
const DOWNLOAD_CONCURRENCY = 8;

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

export interface AgentMdManagerOptions {
  aunPath: string;
  verifySsl?: boolean;
  logger?: ModuleLogger | null;
  discoveryPort?: number | null;
  ownerAidGetter?: () => string | null | undefined;
  currentAidGetter?: () => AID | null | undefined;
  gatewayResolver?: (aid: string) => Promise<string> | string;
  peerResolver?: (aid: string) => Promise<AID> | AID;
  accessTokenResolver?: (aid: string, gatewayUrl: string) => Promise<string> | string;
  aidValidator?: (aid: string) => void;
}

type HttpResult = {
  status: number;
  headers: Record<string, string>;
  text: string;
};

function headerValue(headers: Record<string, string>, name: string): string {
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target) return String(value ?? '').trim();
  }
  return '';
}

function toHeaders(headers: http.IncomingHttpHeaders): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (typeof value === 'string') out[key] = value;
    else if (Array.isArray(value)) out[key] = value[0] ?? '';
  }
  return out;
}

function agentMdSchemeFromGateway(gatewayUrl: string): string {
  return String(gatewayUrl ?? '').trim().toLowerCase().startsWith('ws://') ? 'http' : 'https';
}

function requestText(
  url: string,
  opts: {
    method: string;
    verifySsl: boolean;
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
    redirectsLeft?: number;
  },
): Promise<HttpResult> {
  const redirectsLeft = opts.redirectsLeft ?? 3;
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const requestOptions: https.RequestOptions = {
      method: opts.method,
      headers: opts.headers,
      timeout: opts.timeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS,
    };
    if (!opts.verifySsl) requestOptions.rejectUnauthorized = false;
    const req = mod.request(url, requestOptions, (res) => {
      const status = res.statusCode ?? 0;
      const location = typeof res.headers.location === 'string' ? res.headers.location : '';
      if ([301, 302, 303, 307, 308].includes(status) && location && redirectsLeft > 0) {
        res.resume();
        const nextUrl = new URL(location, url).toString();
        requestText(nextUrl, { ...opts, redirectsLeft: redirectsLeft - 1 }).then(resolve, reject);
        return;
      }

      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        resolve({
          status,
          headers: toHeaders(res.headers),
          text: Buffer.concat(chunks).toString('utf-8'),
        });
      });
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new AUNError(`agent.md request timed out after ${opts.timeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS}ms`));
    });
    if (opts.body !== undefined) req.write(opts.body, 'utf-8');
    req.end();
  });
}

export class AgentMdManager {
  private _aunPath: string;
  private _verifySsl: boolean;
  private _log: ModuleLogger;
  private _discoveryPort: number | null;
  private _ownerAidGetter?: () => string | null | undefined;
  private _currentAidGetter?: () => AID | null | undefined;
  private _gatewayResolver?: (aid: string) => Promise<string> | string;
  private _peerResolver?: (aid: string) => Promise<AID> | AID;
  private _accessTokenResolver?: (aid: string, gatewayUrl: string) => Promise<string> | string;
  private _aidValidator?: (aid: string) => void;
  private _cache: Map<string, Record<string, unknown>> = new Map();
  private _downloadInflight: Map<string, Promise<AgentMdDownloadResult>> = new Map();
  private _downloadActive = 0;
  private _downloadWaiters: Array<() => void> = [];

  constructor(opts: AgentMdManagerOptions) {
    this._aunPath = String(opts.aunPath ?? '');
    this._verifySsl = opts.verifySsl ?? true;
    this._log = opts.logger ?? noopLogger;
    this._discoveryPort = opts.discoveryPort ?? null;
    this._ownerAidGetter = opts.ownerAidGetter;
    this._currentAidGetter = opts.currentAidGetter;
    this._gatewayResolver = opts.gatewayResolver;
    this._peerResolver = opts.peerResolver;
    this._accessTokenResolver = opts.accessTokenResolver;
    this._aidValidator = opts.aidValidator;
  }

  static contentEtag(content: string): string {
    return `"${crypto.createHash('sha256').update(String(content ?? ''), 'utf-8').digest('hex')}"`;
  }

  get root(): string {
    const root = path.join(this._aunPath, 'AIDs');
    fs.mkdirSync(root, { recursive: true });
    return root;
  }

  setAunPath(aunPath: string): void {
    this._aunPath = String(aunPath ?? '');
    this._cache.clear();
    this._downloadInflight.clear();
  }

  safeAid(aid: string): string {
    const target = String(aid ?? '').trim();
    if (!target || target.includes('/') || target.includes('\\') || target.includes('\0')) {
      throw new ValidationError('agent.md aid is empty or contains path separators');
    }
    this._aidValidator?.(target);
    return target;
  }

  filePath(aid: string): string {
    return path.join(this.root, this.safeAid(aid), 'agent.md');
  }

  metaPath(aid: string): string {
    return path.join(this.root, this.safeAid(aid), 'agentmd.json');
  }

  readContent(aid: string): string {
    return fs.readFileSync(this.filePath(aid), 'utf-8');
  }

  writeContent(aid: string, content: string): string {
    const filePath = this.filePath(aid);
    this._atomicWriteText(filePath, String(content ?? ''));
    return filePath;
  }

  loadRecord(aid: string): Record<string, unknown> | null {
    const target = String(aid ?? '').trim();
    if (!target) return null;
    try {
      const record = this._withRecordLock(target, () => this._readRecordUnlocked(target));
      const loaded: Record<string, unknown> = Object.keys(record).length > 0 ? { ...record, aid: target } : { aid: target };
      try {
        const content = this.readContent(target);
        loaded.content = content;
        loaded.local_etag = AgentMdManager.contentEtag(content);
      } catch (err) {
        if (fs.existsSync(this.metaPath(target))) {
          this._log.warn(`agent.md content read failed: aid=${target} err=${err instanceof Error ? err.message : String(err)}`);
        }
      }
      if (Object.keys(loaded).length <= 1) return null;
      if (Object.keys(record).length === 0 && typeof loaded.content === 'string') {
        this._withRecordLock(target, () => this._writeRecordUnlocked(target, {
          aid: target,
          local_etag: loaded.local_etag,
          updated_at: Date.now(),
        }));
      }
      this._cache.set(target, { ...loaded });
      return { ...loaded };
    } catch (err) {
      this._log.debug(`agent.md cache load skipped: aid=${target} err=${err instanceof Error ? err.message : String(err)}`);
      return null;
    }
  }

  saveRecord(aid: string, fields: Record<string, unknown>): Record<string, unknown> {
    const target = String(aid ?? '').trim();
    if (!target) return {};
    try {
      const inputFields: Record<string, unknown> = { ...fields };
      const hasContent = Object.prototype.hasOwnProperty.call(inputFields, 'content') && inputFields.content !== undefined && inputFields.content !== null;
      let savedTo = '';
      const record = this._withRecordLock(target, () => {
        if (hasContent) {
          const content = String(inputFields.content ?? '');
          savedTo = this.writeContent(target, content);
          if (!inputFields.local_etag) inputFields.local_etag = AgentMdManager.contentEtag(content);
          if (!inputFields.fetched_at) inputFields.fetched_at = Date.now();
        }
        delete inputFields.content;
        const next: Record<string, unknown> = { ...this._readRecordUnlocked(target), aid: target };
        for (const [key, value] of Object.entries(inputFields)) {
          if (value !== undefined && value !== null) next[key] = value;
        }
        next.updated_at = Date.now();
        this._writeRecordUnlocked(target, next);
        return next;
      });
      const loaded: Record<string, unknown> = { ...record };
      if (hasContent) {
        loaded.content = String(fields.content ?? '');
        if (savedTo) loaded.saved_to = savedTo;
      } else {
        const current = this.loadRecord(target);
        if (current && typeof current.content === 'string') loaded.content = current.content;
      }
      this._cache.set(target, { ...loaded });
      return { ...loaded };
    } catch (err) {
      this._log.debug(`agent.md cache save skipped: aid=${target} err=${err instanceof Error ? err.message : String(err)}`);
      return {};
    }
  }

  async upload(content?: string | null): Promise<Record<string, unknown>> {
    const target = this._ownerAid();
    if (!target) throw new ValidationError('uploadAgentMd requires local AID');
    const current = this._currentAid();
    if (!current?.isPrivateKeyValid()) {
      throw new StateError('uploadAgentMd requires loaded AID with a valid private key');
    }
    const rawContent = content === undefined || content === null ? this.readContent(target) : String(content);
    if (!rawContent.trim()) throw new ValidationError('uploadAgentMd requires non-empty content');
    const signed = current.signAgentMd(rawContent);
    if (!signed.ok || !signed.data) {
      const message = (signed as { ok: false; error: { message: string } }).error?.message ?? 'agent.md signing failed';
      throw new ClientSignatureError(message);
    }

    const signedContent = signed.data.signed;
    const gatewayUrl = await this._resolveGateway(target);
    const token = await this._accessToken(target, gatewayUrl);
    const response = await requestText(this._url(target, gatewayUrl), {
      method: 'PUT',
      verifySsl: this._verifySsl,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'text/markdown; charset=utf-8',
      },
      body: signedContent,
      timeoutMs: DEFAULT_HTTP_TIMEOUT_MS,
      redirectsLeft: 0,
    });
    if (response.status === 404) {
      throw new NotFoundError(`agent.md endpoint not found for aid: ${target}`);
    }
    if (response.status < 200 || response.status >= 300) {
      const message = response.text.trim();
      throw new AUNError(`upload agent.md failed: HTTP ${response.status}${message ? ` - ${message}` : ''}`);
    }
    let payload: unknown;
    try {
      payload = JSON.parse(response.text || '{}') as unknown;
    } catch (err) {
      throw new AUNError(`upload agent.md returned invalid JSON payload: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (!isJsonObject(payload as JsonValue | object | null | undefined)) {
      throw new AUNError('upload agent.md returned invalid JSON payload');
    }
    const result = payload as Record<string, unknown>;
    this.saveRecord(target, {
      content: signedContent,
      local_etag: AgentMdManager.contentEtag(signedContent),
      remote_etag: String(result.etag ?? '').trim() || undefined,
      last_modified: String(result.last_modified ?? result.lastModified ?? '').trim(),
      fetched_at: Date.now(),
      checked_at: Date.now(),
      remote_status: String(result.etag ?? '').trim() ? 'found' : 'unknown',
      last_error: '',
    });
    return { ...result };
  }

  async download(aid?: string | null, timeoutMs = DEFAULT_HTTP_TIMEOUT_MS): Promise<AgentMdDownloadResult> {
    const target = this.safeAid(String(aid ?? this._ownerAid() ?? '').trim());
    const existing = this._downloadInflight.get(target);
    if (existing) return await existing;
    const task = (async () => {
      const release = await this._acquireDownloadSlot();
      try {
        return await this._downloadOnce(target, timeoutMs);
      } finally {
        release();
      }
    })();
    this._downloadInflight.set(target, task);
    task.finally(() => {
      if (this._downloadInflight.get(target) === task) this._downloadInflight.delete(target);
    }).catch(() => undefined);
    return await task;
  }

  async check(aid: string, ttlDays = 1): Promise<AgentMdCheckResult> {
    const target = this.safeAid(aid);
    const before = this.loadRecord(target) ?? {};
    const localEtag = String(before.local_etag ?? '').trim();
    const localFound = !!(Object.keys(before).length > 0 && (String(before.content ?? '') || localEtag));
    const remoteEtagCached = String(before.remote_etag ?? before.etag ?? '').trim();
    const lastModifiedCached = String(before.last_modified ?? '').trim();
    const checkedAtCached = Number(before.checked_at ?? before.fetched_at ?? 0) || 0;
    const cachedInSync = !!(localFound && localEtag && remoteEtagCached && localEtag === remoteEtagCached);
    if (cachedInSync && AgentMdManager.checkedAtFresh(checkedAtCached, ttlDays)) {
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
    const remoteMissingCached = String(before.remote_status ?? '') === 'missing';
    if (!localFound && !remoteEtagCached && remoteMissingCached && AgentMdManager.checkedAtFresh(checkedAtCached, ttlDays)) {
      return {
        aid: target,
        local_found: false,
        remote_found: false,
        local_etag: '',
        remote_etag: '',
        in_sync: false,
        needs_update: false,
        last_modified: '',
        status: 404,
        cached: true,
        verify_status: '',
        verify_error: '',
        ttl_days: Number(ttlDays) || 0,
      };
    }

    let remote: AgentMdHeadResult;
    try {
      remote = await this._head(target);
    } catch (err) {
      if (err instanceof NotFoundError) {
        remote = { aid: target, found: false, etag: '', last_modified: '', content_length: 0, status: 404 };
      } else {
        this.saveRecord(target, { checked_at: Date.now(), remote_status: 'error', last_error: err instanceof Error ? err.message : String(err) });
        throw err;
      }
    }
    const remoteFound = !!remote.found;
    const remoteEtag = String(remote.etag ?? '').trim();
    const lastModified = String(remote.last_modified ?? '').trim();
    const saved = this.loadRecord(target) ?? before;
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
      status: remote.status,
      cached: false,
      verify_status: String(saved.verify_status ?? before.verify_status ?? ''),
      verify_error: String(saved.verify_error ?? before.verify_error ?? ''),
      ttl_days: Number(ttlDays) || 0,
    };
  }

  observeMeta(aid: string, etag = '', lastModified = '', source = ''): void {
    const target = String(aid ?? '').trim();
    const remoteEtag = String(etag ?? '').trim();
    const remoteLastModified = String(lastModified ?? '').trim();
    if (!target || (!remoteEtag && !remoteLastModified)) return;
    const before = this.loadRecord(target) ?? {};
    const same =
      (!remoteEtag || String(before.remote_etag ?? '').trim() === remoteEtag) &&
      (!remoteLastModified || String(before.last_modified ?? '').trim() === remoteLastModified);
    let record: Record<string, unknown> = { ...before };
    if (!same || Object.keys(before).length === 0) {
      const fields: Record<string, unknown> = { observed_at: Date.now(), remote_status: 'found' };
      if (remoteEtag) fields.remote_etag = remoteEtag;
      if (remoteLastModified) fields.last_modified = remoteLastModified;
      record = this.saveRecord(target, fields) || record;
    }
    this._scheduleDownloadIfMissing(target, record, source);
    this._log.debug(`agent.md meta observed: aid=${target} etag=${remoteEtag || '-'} last_modified=${remoteLastModified || '-'} source=${source || '-'}`);
  }

  observeRpcMeta(meta: Record<string, unknown>, ownerAid?: string | null): void {
    if (!meta || typeof meta !== 'object') return;
    const owner = String(ownerAid ?? this._ownerAid() ?? '').trim();
    const etag = String(meta.agent_md_etag ?? '').trim();
    if (etag && owner) this.observeMeta(owner, etag, '', 'rpc.self');
    const etags = meta.agent_md_etags;
    if (isJsonObject(etags as JsonValue | object | null | undefined)) {
      for (const key of ['requester', 'peer', 'receiver', 'target', 'to', 'sender', 'from']) {
        const item = (etags as JsonObject)[key];
        if (!isJsonObject(item as JsonValue | object | null | undefined)) continue;
        const obj = item as JsonObject;
        this.observeMeta(
          String(obj.aid ?? ''),
          String(obj.etag ?? ''),
          String(obj.last_modified ?? obj.lastModified ?? ''),
          `rpc.${key}`,
        );
      }
    }
  }

  observeEnvelope(envelope: unknown): void {
    if (!isJsonObject(envelope as JsonValue | object | null | undefined)) return;
    const env = envelope as JsonObject;
    if (!isJsonObject(env.agent_md as JsonValue | object | null | undefined)) return;
    const agentMd = env.agent_md as JsonObject;
    if (!isJsonObject(agentMd.sender as JsonValue | object | null | undefined)) return;
    const sender = agentMd.sender as JsonObject;
    let senderAid = String(sender.aid ?? '').trim();
    if (!senderAid) {
      const aad = isJsonObject(env.aad as JsonValue | object | null | undefined) ? env.aad as JsonObject : {};
      senderAid = String(aad.from ?? env.from ?? '').trim();
    }
    this.observeMeta(
      senderAid,
      String(sender.etag ?? ''),
      String(sender.last_modified ?? sender.lastModified ?? ''),
      'envelope',
    );
  }

  eventSnapshot(aid?: string | null): { local_etag: string; remote_etag: string } | null {
    const target = String(aid ?? this._ownerAid() ?? '').trim();
    if (!target) return null;
    const record = this.loadRecord(target) ?? {};
    const localEtag = String(record.local_etag ?? '').trim();
    const remoteEtag = String(record.remote_etag ?? record.etag ?? '').trim();
    if (!localEtag && !remoteEtag) return null;
    return { local_etag: localEtag, remote_etag: remoteEtag };
  }

  private static checkedAtFresh(checkedAtMs: number, ttlDays: number): boolean {
    const days = Number(ttlDays || 0);
    if (!Number.isFinite(days) || days <= 0) return false;
    if (!Number.isFinite(checkedAtMs) || checkedAtMs <= 0) return false;
    return Date.now() - checkedAtMs <= days * 86400000;
  }

  private _ownerAid(): string {
    return String(this._ownerAidGetter?.() ?? '').trim();
  }

  private _currentAid(): AID | null {
    return this._currentAidGetter?.() ?? null;
  }

  private _url(aid: string, gatewayUrl: string): string {
    let host = this.safeAid(aid);
    if (this._discoveryPort && !host.includes(':')) host = `${host}:${this._discoveryPort}`;
    return `${agentMdSchemeFromGateway(gatewayUrl)}://${host}/agent.md`;
  }

  private async _resolveGateway(aid: string): Promise<string> {
    return String(await this._gatewayResolver?.(aid) ?? '');
  }

  private async _resolvePeer(aid: string): Promise<AID> {
    const current = this._currentAid();
    if (current?.aid === aid) return current;
    const peer = await this._peerResolver?.(aid);
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

  private async _head(aid: string): Promise<AgentMdHeadResult> {
    const target = this.safeAid(aid);
    const gatewayUrl = await this._resolveGateway(target);
    const response = await requestText(this._url(target, gatewayUrl), {
      method: 'HEAD',
      verifySsl: this._verifySsl,
      headers: { Accept: 'text/markdown' },
      timeoutMs: HEAD_HTTP_TIMEOUT_MS,
    });
    if (response.status === 404) {
      this.saveRecord(target, {
        remote_etag: '',
        last_modified: '',
        checked_at: Date.now(),
        remote_status: 'missing',
        last_error: '',
      });
      throw new NotFoundError(`agent.md not found for aid: ${target}`);
    }
    if (response.status < 200 || response.status >= 300) {
      throw new AUNError(`head agent.md failed: HTTP ${response.status}`);
    }
    const contentLength = Number.parseInt(headerValue(response.headers, 'content-length') || '0', 10) || 0;
    const data: AgentMdHeadResult = {
      aid: target,
      found: true,
      etag: headerValue(response.headers, 'etag'),
      last_modified: headerValue(response.headers, 'last-modified'),
      content_length: contentLength,
      status: response.status,
    };
    this.saveRecord(target, {
      remote_etag: data.etag,
      last_modified: data.last_modified,
      checked_at: Date.now(),
      remote_status: 'found',
      last_error: '',
    });
    return data;
  }

  private async _downloadOnce(target: string, timeoutMs: number): Promise<AgentMdDownloadResult> {
    this._log.debug(`downloadAgentMd enter: aid=${target}`);
    const gatewayUrl = await this._resolveGateway(target);
    const cached = this.loadRecord(target) ?? {};
    const headers: Record<string, string> = { Accept: 'text/markdown' };
    const etag = String(cached.remote_etag ?? cached.etag ?? cached.local_etag ?? '').trim();
    const lastModified = String(cached.last_modified ?? '').trim();

    let response = await requestText(this._url(target, gatewayUrl), {
      method: 'GET',
      verifySsl: this._verifySsl,
      headers,
      timeoutMs,
    });
    let reusedCachedNotModified = false;
    if (response.status === 304 && cached.content !== undefined && cached.content !== null) {
      reusedCachedNotModified = true;
      response = {
        ...response,
        text: String(cached.content),
        headers: {
          ...response.headers,
          ...(etag ? { ETag: etag } : {}),
          ...(lastModified ? { 'Last-Modified': lastModified } : {}),
        },
      };
    } else if (response.status === 304) {
      response = await requestText(this._url(target, gatewayUrl), {
        method: 'GET',
        verifySsl: this._verifySsl,
        headers: { Accept: 'text/markdown' },
        timeoutMs,
      });
    }
    if (response.status === 404) {
      this.saveRecord(target, { remote_status: 'missing', checked_at: Date.now(), last_error: '' });
      throw new NotFoundError(`agent.md not found for aid: ${target}`);
    }
    if ((response.status < 200 || response.status >= 300) && !reusedCachedNotModified) {
      const message = response.text.trim();
      throw new AUNError(`download agent.md failed: HTTP ${response.status}${message ? ` - ${message}` : ''}`);
    }

    const content = response.text;
    const peer = await this._resolvePeer(target);
    const verified = peer.verifyAgentMd(content);
    if (!verified.ok || !verified.data) {
      const message = (verified as { ok: false; error: { message: string } }).error?.message ?? 'agent.md verification failed';
      throw new AUNError(message);
    }
    const signature = { ...verified.data } as Record<string, unknown>;
    const statusText = String(signature.status ?? 'invalid');
    const reason = String(signature.reason ?? '').trim();
    const verification: AgentMdVerification = { status: statusText };
    if (reason) verification.reason = reason;
    const responseEtag = headerValue(response.headers, 'etag');
    const responseLastModified = headerValue(response.headers, 'last-modified');
    const localEtag = AgentMdManager.contentEtag(content);
    const saved = this.saveRecord(target, {
      content,
      local_etag: localEtag,
      remote_etag: responseEtag,
      last_modified: responseLastModified,
      fetched_at: Date.now(),
      checked_at: Date.now(),
      remote_status: 'found',
      verify_status: statusText,
      verify_error: reason,
      last_error: '',
    });
    const owner = this._ownerAid();
    let inSync: boolean | null = null;
    if (target === owner) {
      const remote = responseEtag || String(saved.remote_etag ?? '');
      inSync = localEtag && remote ? localEtag === remote : false;
    }
    this._log.debug(`downloadAgentMd exit: aid=${target} status=${statusText}`);
    return {
      aid: target,
      content,
      verification,
      signature,
      cert_pem: peer.certPem,
      etag: responseEtag,
      last_modified: responseLastModified,
      status: response.status,
      in_sync: inSync,
      saved_to: String(saved.saved_to ?? this.filePath(target)),
      save_error: null,
    };
  }

  private _hasLocalContent(aid: string, record?: Record<string, unknown> | null): boolean {
    if (record && typeof record.content === 'string' && record.content.length > 0) return true;
    try {
      return fs.existsSync(this.filePath(aid));
    } catch {
      return false;
    }
  }

  private _scheduleDownloadIfMissing(aid: string, record?: Record<string, unknown> | null, source = ''): void {
    const target = String(aid ?? '').trim();
    if (!target || this._hasLocalContent(target, record)) return;
    if (this._downloadInflight.has(target)) return;
    void this.download(target).catch((err) => {
      this.saveRecord(target, {
        last_error: err instanceof Error ? err.message : String(err),
        remote_status: 'found',
      });
      this._log.debug(`agent.md auto download failed: aid=${target} source=${source || '-'} err=${err instanceof Error ? err.message : String(err)}`);
    });
  }

  private async _acquireDownloadSlot(): Promise<() => void> {
    if (this._downloadActive < DOWNLOAD_CONCURRENCY) {
      this._downloadActive += 1;
      return () => this._releaseDownloadSlot();
    }
    await new Promise<void>((resolve) => {
      this._downloadWaiters.push(resolve);
    });
    return () => this._releaseDownloadSlot();
  }

  private _releaseDownloadSlot(): void {
    const next = this._downloadWaiters.shift();
    if (next) {
      next();
      return;
    }
    if (this._downloadActive > 0) this._downloadActive -= 1;
  }

  private _atomicWriteText(filePath: string, content: string): void {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const tmp = path.join(path.dirname(filePath), `.${path.basename(filePath)}.${process.pid}.${crypto.randomUUID()}.tmp`);
    let fd: number | null = null;
    try {
      fd = fs.openSync(tmp, 'w');
      fs.writeFileSync(fd, content, 'utf-8');
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = null;
      fs.renameSync(tmp, filePath);
      try {
        const dirFd = fs.openSync(path.dirname(filePath), 'r');
        try { fs.fsyncSync(dirFd); } finally { fs.closeSync(dirFd); }
      } catch {
        // best-effort fsync
      }
    } finally {
      if (fd !== null) {
        try { fs.closeSync(fd); } catch { /* ignore */ }
      }
      if (fs.existsSync(tmp)) {
        try { fs.unlinkSync(tmp); } catch { /* ignore */ }
      }
    }
  }

  private _sleepSync(ms: number): void {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  }

  private _withRecordLock<T>(aid: string, fn: () => T): T {
    const lockPath = path.join(path.dirname(this.metaPath(aid)), 'agentmd.json.lock');
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    const deadline = Date.now() + 5000;
    let fd: number | null = null;
    while (fd === null) {
      try {
        fd = fs.openSync(lockPath, 'wx');
        fs.writeFileSync(fd, `${process.pid}\n`, 'utf-8');
      } catch (err: any) {
        if (err?.code !== 'EEXIST' || Date.now() >= deadline) throw err;
        try {
          const st = fs.statSync(lockPath);
          if (Date.now() - st.mtimeMs > 30000) fs.unlinkSync(lockPath);
        } catch {
          // ignore stale lock cleanup failures
        }
        this._sleepSync(25);
      }
    }
    try {
      return fn();
    } finally {
      if (fd !== null) {
        try { fs.closeSync(fd); } catch { /* ignore */ }
      }
      try { fs.unlinkSync(lockPath); } catch { /* ignore */ }
    }
  }

  private _writeRecordUnlocked(aid: string, record: Record<string, unknown>): void {
    const payload: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(record)) {
      if (key !== 'content' && value !== undefined && value !== null) payload[key] = value;
    }
    payload.aid = this.safeAid(aid);
    this._atomicWriteText(this.metaPath(aid), `${JSON.stringify(payload, null, 2)}\n`);
  }

  private _readRecordUnlocked(aid: string): Record<string, unknown> {
    const filePath = this.metaPath(aid);
    if (!fs.existsSync(filePath)) return {};
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as unknown;
      if (!isJsonObject(parsed as JsonValue | object | null | undefined)) return {};
      const record: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
        if (key !== 'content') record[key] = value;
      }
      record.aid = this.safeAid(String(record.aid ?? aid));
      for (const key of ['fetched_at', 'observed_at', 'checked_at', 'updated_at']) {
        record[key] = Number(record[key] ?? 0) || 0;
      }
      return record;
    } catch (err) {
      this._log.warn(`agent.md metadata damaged, ignoring: aid=${aid} err=${err instanceof Error ? err.message : String(err)}`);
      return {};
    }
  }
}
