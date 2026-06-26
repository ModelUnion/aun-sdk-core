#!/usr/bin/env node

import 'fake-indexeddb/auto';
import * as http from 'node:http';
import * as https from 'node:https';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import { URL } from 'node:url';
import { AIDStore, AUNClient } from '../index.js';
import { publicKeyFingerprint } from '../cert-utils.js';
import type { JsonObject, RpcParams } from '../types.js';

type ClientInternals = {
  _configModel?: { requireForwardSecrecy?: boolean };
  _deviceId?: string;
  _slotId?: string;
  _identity?: JsonObject | null;
  _sessionParams?: JsonObject | null;
  _auth?: {
    loadIdentityOrNone?: (aid?: string) => JsonObject | null | Promise<JsonObject | null>;
  };
};

function installNodeBrowserShims(): void {
  const root = globalThis as unknown as Record<string, unknown>;
  if (!root.WebSocket) throw new Error('Node.js 22+ global WebSocket is required for the JS cross-sdk agent');
  if (!root.localStorage) {
    const data = new Map<string, string>();
    root.localStorage = {
      getItem: (key: string): string | null => data.get(String(key)) ?? null,
      setItem: (key: string, value: string): void => { data.set(String(key), String(value)); },
      removeItem: (key: string): void => { data.delete(String(key)); },
      clear: (): void => { data.clear(); },
      key: (index: number): string | null => [...data.keys()][index] ?? null,
      get length(): number { return data.size; },
    } as Storage;
  }
}

function envBool(name: string, fallback = false): boolean {
  const raw = process.env[name];
  if (raw == null) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(raw.trim().toLowerCase());
}

function textOf(value: unknown): string {
  return String(value ?? '');
}

function jsonObjectOf(value: unknown): JsonObject | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : null;
}

function withoutKeys(source: JsonObject, keys: string[]): JsonObject {
  const next = { ...source } as JsonObject;
  for (const key of keys) delete next[key];
  return next;
}

function accessTokenFromClient(client: AUNClient): string {
  const internals = client as unknown as ClientInternals & { accessToken?: unknown; access_token?: unknown };
  const direct = textOf(internals.accessToken ?? internals.access_token).trim();
  if (direct) return direct;
  const identityToken = textOf(internals._identity?.access_token).trim();
  if (identityToken) return identityToken;
  return textOf(internals._sessionParams?.access_token).trim();
}

function jsonSafe(value: unknown): unknown {
  try {
    JSON.stringify(value);
    return value;
  } catch {
    if (Array.isArray(value)) return value.map((item) => jsonSafe(item));
    if (value && typeof value === 'object') {
      const out: JsonObject = {};
      for (const [key, item] of Object.entries(value as JsonObject)) out[key] = jsonSafe(item) as never;
      return out;
    }
    return String(value);
  }
}

function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' || typeof value === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value as JsonObject;
    return `{${Object.keys(obj).sort().map((key) => `${stableStringify(key)}:${stableStringify(obj[key])}`).join(',')}}`;
  }
  return JSON.stringify(String(value));
}

function sha256Json(value: unknown): string {
  return crypto.createHash('sha256').update(stableStringify(jsonSafe(value)), 'utf-8').digest('hex');
}

async function readJson(req: http.IncomingMessage): Promise<JsonObject> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  if (!chunks.length) return {};
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf-8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as JsonObject : {};
  } catch {
    return {};
  }
}

function sendJson(res: http.ServerResponse, status: number, data: JsonObject): void {
  const body = JSON.stringify(jsonSafe(data));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
}

function envelopeMetadata(data: JsonObject): JsonObject {
  const e2ee = jsonObjectOf(data.e2ee);
  const protectedHeaders = jsonObjectOf(data.protected_headers) ?? jsonObjectOf(e2ee?.protected_headers);
  const payloadType = textOf(data.payload_type ?? protectedHeaders?.payload_type ?? e2ee?.payload_type).trim();
  const out: JsonObject = {};
  if (payloadType) out.payload_type = payloadType;
  if (protectedHeaders) out.protected_headers = jsonSafe(protectedHeaders) as JsonObject;
  return out;
}

class CrossSdkJsAgent {
  readonly language = 'js';
  readonly sdkVersion = 'unknown';
  readonly aid = textOf(process.env.AUN_TEST_AID || `cross-js-${crypto.randomUUID().slice(0, 8)}.agentid.pub`).trim();
  readonly issuer = textOf(process.env.AUN_TEST_ISSUER || 'agentid.pub').trim() || 'agentid.pub';
  readonly slotId = textOf(process.env.AUN_TEST_SLOT_ID || `cross-sdk-js-${crypto.randomUUID().slice(0, 8)}`).trim();
  readonly aunPath = textOf(process.env.AUN_TEST_AUN_PATH || process.env.AUN_DATA_ROOT || '/data/aun').trim();
  readonly debug = envBool('AUN_TEST_DEBUG', false);
  readonly client: AUNClient;
  ready = false;
  startupError = '';
  inbox: JsonObject[] = [];
  groupInbox: JsonObject[] = [];
  traces = new Map<string, JsonObject[]>();
  sendResults = new Map<string, JsonObject>();

  constructor() {
    this.client = new AUNClient();
    const internal = this.client as unknown as ClientInternals;
    if (internal._configModel) internal._configModel.requireForwardSecrecy = false;
  }

  async start(): Promise<void> {
    this.client.on('message.received', (msg: unknown) => {
      void this.storeInboxItem(this.normalizeMessage(msg, true));
    });
    this.client.on('message.undecryptable', (msg: unknown) => {
      void this.storeInboxItem(this.normalizeMessage(msg, false, 'undecryptable'));
    });
    this.client.on('group.message_created', (msg: unknown) => {
      void this.storeGroupInboxItem(this.normalizeGroupMessage(msg, true));
    });
    this.client.on('group.message_undecryptable', (msg: unknown) => {
      void this.storeGroupInboxItem(this.normalizeGroupMessage(msg, false, 'undecryptable'));
    });
    await this.ensureConnected();
    this.ready = true;
  }

  async close(): Promise<void> {
    try {
      await this.client.close();
    } catch {
      // 退出清理失败不影响容器关闭。
    }
  }

  aidStore(): AIDStore {
    return new AIDStore({
      aunPath: this.aunPath,
      encryptionSeed: '',
      slotId: this.slotId,
      verifySsl: false,
    });
  }

  async ensureConnected(): Promise<void> {
    const store = this.aidStore();
    try {
      const registered = await store.register(this.aid);
      if (!registered.ok) {
        const loaded = await store.load(this.aid);
        if (!loaded.ok) {
          throw new Error(`${registered.error.code}: ${registered.error.message}`);
        }
      }
      const loaded = await store.load(this.aid);
      if (!loaded.ok) {
        throw new Error(`load identity failed: ${loaded.error.code}: ${loaded.error.message}`);
      }
      this.client.loadIdentity(loaded.data.aid);
    } finally {
      store.close();
    }
    await this.client.connect({ auto_reconnect: false, background_sync: true });
  }

  async identity(): Promise<JsonObject> {
    const internal = this.client as unknown as ClientInternals;
    const loaded = await internal._auth?.loadIdentityOrNone?.(this.aid);
    const identity = internal._identity ?? loaded ?? {};
    const cert = textOf(identity.cert ?? identity.cert_pem ?? '');
    return {
      aid: this.aid,
      device_id: textOf(internal._deviceId ?? ''),
      slot_id: textOf(internal._slotId ?? this.slotId),
      issuer: this.issuer,
      public_key_fingerprint: cert ? await publicKeyFingerprint(cert) : '',
    };
  }

  recordTrace(traceId: string, item: JsonObject): void {
    if (!traceId) return;
    const current = this.traces.get(traceId) ?? [];
    current.push({
      ts: Date.now(),
      language: this.language,
      aid: this.aid,
      ...item,
    });
    this.traces.set(traceId, current);
  }

  async storeInboxItem(item: JsonObject): Promise<void> {
    this.inbox.push(item);
    if (this.inbox.length > 1000) this.inbox = this.inbox.slice(-1000);
    this.recordTrace(textOf(item.trace_id), { stage: 'receive', message: item });
  }

  async storeGroupInboxItem(item: JsonObject): Promise<void> {
    this.groupInbox.push(item);
    if (this.groupInbox.length > 1000) this.groupInbox = this.groupInbox.slice(-1000);
    this.recordTrace(textOf(item.trace_id), { stage: 'group_receive', message: item });
  }

  normalizeMessage(msg: unknown, decrypted: boolean, errorCode = ''): JsonObject {
    const data: JsonObject = jsonObjectOf(msg) ?? { raw: textOf(msg) };
    const payload = jsonObjectOf(data.payload) ?? {};
    const traceId = textOf(payload.trace_id ?? data.trace_id ?? '');
    const text = textOf(payload.text ?? data.text ?? '');
    return {
      trace_id: traceId,
      message_id: textOf(data.message_id ?? data.id ?? ''),
      from: textOf(data.from ?? data.from_aid ?? ''),
      to: textOf(data.to ?? data.to_aid ?? this.aid),
      text,
      decrypted,
      encrypted: Boolean(data.e2ee ?? data.encrypted),
      seq: Number(data.seq ?? data.message_seq ?? 0) || 0,
      ack_seq: Number(data.ack_seq ?? 0) || 0,
      error_code: errorCode,
      raw_sha256: sha256Json(data),
      ...envelopeMetadata(data),
    };
  }

  normalizeGroupMessage(msg: unknown, decrypted: boolean, errorCode = ''): JsonObject {
    const data: JsonObject = jsonObjectOf(msg) ?? { raw: textOf(msg) };
    const payload = jsonObjectOf(data.payload) ?? {};
    const traceId = textOf(payload.trace_id ?? data.trace_id ?? '');
    const text = textOf(payload.text ?? data.text ?? '');
    return {
      trace_id: traceId,
      group_id: textOf(data.group_id ?? ''),
      message_id: textOf(data.message_id ?? data.id ?? ''),
      from: textOf(data.from ?? data.from_aid ?? data.sender_aid ?? ''),
      text,
      decrypted,
      encrypted: Boolean(data.e2ee ?? data.encrypted),
      seq: Number(data.seq ?? data.message_seq ?? data.msg_seq ?? 0) || 0,
      error_code: errorCode,
      raw_sha256: sha256Json(data),
      ...envelopeMetadata(data),
    };
  }

  async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    try {
      if (req.method === 'GET' && url.pathname === '/health') {
        sendJson(res, this.startupError ? 503 : 200, {
          ok: !this.startupError,
          agent_ready: this.ready && ['ready', 'connected'].includes(textOf(this.client.state)),
          state: textOf(this.client.state),
          aid: this.aid,
          language: this.language,
          sdk_version: this.sdkVersion,
          startup_error: this.startupError,
        });
        return;
      }
      if (req.method === 'POST' && url.pathname === '/reset') {
        const body = await readJson(req);
        const traceId = textOf(body.trace_id ?? '');
        if (traceId) {
          this.inbox = this.inbox.filter((item) => item.trace_id !== traceId);
          this.groupInbox = this.groupInbox.filter((item) => item.trace_id !== traceId);
          this.traces.delete(traceId);
          this.sendResults.delete(traceId);
        } else {
          this.inbox = [];
          this.groupInbox = [];
          this.traces.clear();
          this.sendResults.clear();
        }
        sendJson(res, 200, { ok: true });
        return;
      }
      if (req.method === 'GET' && url.pathname === '/identity') {
        sendJson(res, 200, await this.identity());
        return;
      }
      if (req.method === 'POST' && url.pathname === '/send') {
        await this.send(req, res);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/ack') {
        await this.ack(req, res);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/pull') {
        await this.pull(req, res);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/group/create') {
        await this.groupCreate(req, res);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/group/call') {
        await this.groupCall(req, res);
        return;
      }
      if (req.method === 'GET' && url.pathname === '/group/ready') {
        await this.groupReady(url, res);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/group/send') {
        await this.groupSend(req, res);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/group/pull') {
        await this.groupPull(req, res);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/group/ack') {
        await this.groupAck(req, res);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/group/fs/call') {
        await this.groupFsCall(req, res);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/collab/call') {
        await this.collabCall(req, res);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/storage/call') {
        await this.storageCall(req, res);
        return;
      }
      if (req.method === 'GET' && url.pathname === '/inbox') {
        const traceId = textOf(url.searchParams.get('trace_id') ?? '');
        const fromAid = textOf(url.searchParams.get('from') ?? '');
        const limit = Number(url.searchParams.get('limit') ?? 20) || 20;
        let items = [...this.inbox];
        if (traceId) items = items.filter((item) => item.trace_id === traceId);
        if (fromAid) items = items.filter((item) => item.from === fromAid);
        sendJson(res, 200, { received: items.length > 0, items: items.slice(-limit) });
        return;
      }
      if (req.method === 'GET' && url.pathname === '/group/inbox') {
        const traceId = textOf(url.searchParams.get('trace_id') ?? '');
        const groupId = textOf(url.searchParams.get('group_id') ?? '');
        const fromAid = textOf(url.searchParams.get('from') ?? '');
        const limit = Number(url.searchParams.get('limit') ?? 20) || 20;
        let items = [...this.groupInbox];
        if (traceId) items = items.filter((item) => item.trace_id === traceId);
        if (groupId) items = items.filter((item) => item.group_id === groupId);
        if (fromAid) items = items.filter((item) => item.from === fromAid);
        sendJson(res, 200, { received: items.length > 0, items: items.slice(-limit) });
        return;
      }
      if (req.method === 'GET' && url.pathname.startsWith('/traces/')) {
        const traceId = decodeURIComponent(url.pathname.slice('/traces/'.length));
        sendJson(res, 200, { trace_id: traceId, items: this.traces.get(traceId) ?? [] });
        return;
      }
      if (req.method === 'GET' && url.pathname === '/logs') {
        const logDir = textOf(process.env.AUN_LOG_DIR || '/root/.aun/logs');
        let files: string[] = [];
        try {
          files = fs.existsSync(logDir)
            ? fs.readdirSync(logDir, { recursive: true }).map((p) => `${logDir}/${String(p)}`).slice(-20)
            : [];
        } catch {
          files = [];
        }
        sendJson(res, 200, { log_files: files, tail: [] });
        return;
      }
      sendJson(res, 404, { ok: false, error_code: 'not_found', error_message: url.pathname });
    } catch (err) {
      sendJson(res, 500, {
        ok: false,
        error_code: err instanceof Error ? err.name : 'Error',
        error_message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  async collabCall(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const traceId = textOf(body.trace_id || crypto.randomUUID().replace(/-/g, ''));
    const action = textOf(body.action).trim();
    const params = jsonObjectOf(body.params) ?? {};
    try {
      const result = await this.callCollabAction(action, params);
      const response: JsonObject = { ok: true, trace_id: traceId, action, result: jsonSafe(result) as never };
      this.recordTrace(traceId, { stage: 'collab_call', action, result: response });
      sendJson(res, 200, response);
    } catch (err) {
      const error: JsonObject = {
        ok: false,
        trace_id: traceId,
        action,
        error_code: err instanceof Error ? err.name : 'Error',
        error_message: err instanceof Error ? err.message : String(err),
      };
      this.recordTrace(traceId, { stage: 'collab_call_error', action, error });
      sendJson(res, 500, error);
    }
  }

  async groupCall(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const traceId = textOf(body.trace_id || crypto.randomUUID().replace(/-/g, ''));
    let method = textOf(body.method).trim();
    const action = textOf(body.action).trim();
    if (!method && action) method = action.startsWith('group.') ? action : `group.${action}`;
    const params = jsonObjectOf(body.params) ?? {};
    if (!method) {
      sendJson(res, 400, { ok: false, trace_id: traceId, error_code: 'bad_request', error_message: 'method is required' });
      return;
    }
    try {
      const result = await this.client.call(method, params as RpcParams);
      const response: JsonObject = { ok: true, trace_id: traceId, method, result: jsonSafe(result) as never };
      this.recordTrace(traceId, { stage: 'group_call', method, result: response });
      sendJson(res, 200, response);
    } catch (err) {
      const error: JsonObject = {
        ok: false,
        trace_id: traceId,
        method,
        error_code: err instanceof Error ? err.name : 'Error',
        error_message: err instanceof Error ? err.message : String(err),
      };
      this.recordTrace(traceId, { stage: 'group_call_error', method, error });
      sendJson(res, 500, error);
    }
  }

  async storageCall(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const traceId = textOf(body.trace_id || crypto.randomUUID().replace(/-/g, ''));
    const action = textOf(body.action).trim();
    const params = jsonObjectOf(body.params) ?? {};
    try {
      const result = await this.callStorageAction(action, params);
      const response: JsonObject = { ok: true, trace_id: traceId, action, result: jsonSafe(result) as never };
      this.recordTrace(traceId, { stage: 'storage_call', action, result: response });
      sendJson(res, 200, response);
    } catch (err) {
      const error: JsonObject = {
        ok: false,
        trace_id: traceId,
        action,
        error_code: err instanceof Error ? err.name : 'Error',
        error_message: err instanceof Error ? err.message : String(err),
      };
      this.recordTrace(traceId, { stage: 'storage_call_error', action, error });
      sendJson(res, 500, error);
    }
  }

  async groupFsCall(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const traceId = textOf(body.trace_id || crypto.randomUUID().replace(/-/g, ''));
    const action = textOf(body.action).trim();
    const params = jsonObjectOf(body.params) ?? {};
    const asGroupAid = textOf(body.as_group_aid || body.asGroupAid || params.as_group_aid || params.asGroupAid).trim();
    delete params.as_group_aid;
    delete params.asGroupAid;
    try {
      const result = await this.callGroupFsAction(action, params, asGroupAid);
      const response: JsonObject = { ok: true, trace_id: traceId, action, result: jsonSafe(result) as never };
      this.recordTrace(traceId, { stage: 'group_fs_call', action, as_group_aid: asGroupAid, result: response });
      sendJson(res, 200, response);
    } catch (err) {
      const error: JsonObject = {
        ok: false,
        trace_id: traceId,
        action,
        error_code: err instanceof Error ? err.name : 'Error',
        error_message: err instanceof Error ? err.message : String(err),
      };
      this.recordTrace(traceId, { stage: 'group_fs_call_error', action, as_group_aid: asGroupAid, error });
      sendJson(res, 500, error);
    }
  }

  async callCollabAction(action: string, params: JsonObject): Promise<unknown> {
    const collabRoot = textOf(params.collab_root ?? params.collabRoot);
    const doc = textOf(params.doc);
    const source = textOf(params.source);
    switch (action) {
      case 'ls':
      case 'ls-files':
        return await this.client.collab.lsFiles(collabRoot);
      case 'create':
        return await this.client.collab.create(collabRoot, doc, source);
      case 'read':
        return await this.client.collab.show(collabRoot, doc);
      case 'show':
        return await this.client.collab.show(collabRoot, doc, params.rev == null ? undefined : Number(params.rev));
      case 'submit':
        return await this.client.collab.commit(
          collabRoot,
          doc,
          source,
          Number(params.onto ?? params.base_version ?? params.baseVersion ?? 0) || 0,
          textOf(params.message ?? ''),
        );
      case 'commit':
        return await this.client.collab.commit(collabRoot, doc, source, Number(params.onto ?? params.base_version ?? params.baseVersion ?? 0) || 0, textOf(params.message ?? ''));
      case 'merge':
        return await this.client.collab.merge(collabRoot, doc, source, Number(params.onto ?? params.base_version ?? params.baseVersion ?? 0) || 0);
      case 'history':
      case 'log':
        return await this.client.collab.log(collabRoot, doc);
      case 'get':
        return await this.client.collab.show(collabRoot, doc, Number(params.version ?? 0) || 0);
      case 'diff':
        return await this.client.collab.diff(collabRoot, doc, Number(params.from ?? 0) || 0, Number(params.to ?? 0) || 0);
      case 'export':
        return await this.client.collab.clone(collabRoot, textOf(params.dest), false);
      case 'adopt':
        return await this.client.collab.clone(textOf(params.src), textOf(params.new_root ?? params.newRoot), true);
      case 'clone':
        return await this.client.collab.clone(textOf(params.src), textOf(params.dest), Boolean(params.reroot));
      case 'prune':
        return await this.client.collab.prune(collabRoot, doc);
      case 'ls-remote':
        return await this.client.collab.lsRemote(textOf(params.group_aid ?? params.groupAid));
      case 'unregister':
        return await this.client.collab.unregister(textOf(params.group_aid ?? params.groupAid), collabRoot);
      case 'set_acl':
        return await this.client.collab.setAcl(
          collabRoot,
          textOf(params.grantee_aid ?? params.granteeAID),
          {
            perms: textOf(params.perms || 'w'),
            expires_at: params.expires_at == null && params.expiresAt == null ? undefined : Number(params.expires_at ?? params.expiresAt),
            max_uses: params.max_uses == null && params.maxUses == null ? undefined : Number(params.max_uses ?? params.maxUses),
          },
        );
      case 'remove_acl':
        return await this.client.collab.removeAcl(collabRoot, textOf(params.grantee_aid ?? params.granteeAID));
      case 'tag.create':
        return await this.client.collab.tag.create(collabRoot, {
          message: textOf(params.message),
          major: Boolean(params.major),
        });
      case 'tag.list':
        return await this.client.collab.tag.list(collabRoot);
      case 'tag.show':
        return await this.client.collab.tag.show(collabRoot, textOf(params.version));
      case 'tag.diff':
        return await this.client.collab.tag.diff(collabRoot, textOf(params.version_a ?? params.versionA), textOf(params.version_b ?? params.versionB));
      case 'tag.restore':
        return await this.client.collab.tag.restore(collabRoot, textOf(params.version), { message: textOf(params.message) });
      case 'tag.rm':
        return await this.client.collab.tag.rm(collabRoot, textOf(params.version));
      case 'tag.prune':
        return await this.client.collab.tag.prune(collabRoot, {
          before: params.before == null ? null : Number(params.before),
          keep_last: params.keep_last == null && params.keepLast == null ? null : Number(params.keep_last ?? params.keepLast),
        });
      case 'gc':
        return await this.client.collab.gc(collabRoot, params.dry_run == null && params.dryRun == null ? true : Boolean(params.dry_run ?? params.dryRun));
      case 'reflog':
        return await this.client.collab.reflog(collabRoot, doc || undefined, Number(params.limit ?? 100) || 100);
      case 'reset':
        return await this.client.collab.revert(collabRoot, doc, Number(params.version ?? 0) || 0, textOf(params.message) || '');
      case 'revert':
        return await this.client.collab.revert(collabRoot, doc, Number(params.rev ?? params.version ?? 0) || 0, textOf(params.message) || '');
      case 'discover':
        return await this.client.collab.lsRemote(textOf(params.group_aid ?? params.groupAid));
      case 'unregister':
        return await this.client.collab.unregister(textOf(params.group_aid ?? params.groupAid), collabRoot);
      case 'snapshot.create':
        return await this.client.collab.tag.create(collabRoot, {
          message: textOf(params.message),
          major: Boolean(params.major),
        });
      case 'snapshot.list':
        return await this.client.collab.tag.list(collabRoot);
      case 'snapshot.show':
        return await this.client.collab.tag.show(collabRoot, textOf(params.version));
      case 'snapshot.diff':
        return await this.client.collab.tag.diff(collabRoot, textOf(params.version_a ?? params.versionA), textOf(params.version_b ?? params.versionB));
      case 'snapshot.restore':
        return await this.client.collab.tag.restore(collabRoot, textOf(params.version), { message: textOf(params.message) });
      case 'snapshot.rm':
        return await this.client.collab.tag.rm(collabRoot, textOf(params.version));
      case 'snapshot.prune':
        return await this.client.collab.tag.prune(collabRoot, {
          before: params.before == null ? null : Number(params.before),
          keep_last: params.keep_last == null && params.keepLast == null ? null : Number(params.keep_last ?? params.keepLast),
        });
      default:
        throw new Error(`unsupported collab action: ${action}`);
    }
  }

  async callGroupFsAction(action: string, params: JsonObject, asGroupAid = ''): Promise<unknown> {
    const groupFs = this.client.group.fs;
    let signingStore: AIDStore | null = null;
    const withSigning = (source: JsonObject): JsonObject => {
      const next = { ...source } as JsonObject;
      if (asGroupAid) {
        signingStore ??= this.aidStore();
        next.signAs = asGroupAid;
        (next as Record<string, unknown>).aidStore = signingStore;
      }
      return next;
    };
    const rawCall = async (method: string, source: JsonObject): Promise<unknown> => {
      const payload = { ...source } as RpcParams;
      if (asGroupAid) {
        signingStore ??= this.aidStore();
        const loaded = await signingStore.load(asGroupAid) as unknown as {
          ok?: boolean;
          data?: { aid?: unknown };
          error?: { message?: string };
        };
        if (!loaded.ok || !loaded.data?.aid) {
          throw new Error(loaded.error?.message || `signer identity not found: ${asGroupAid}`);
        }
        (payload as Record<string, unknown>)._client_signature_identity = loaded.data.aid;
      }
      return await this.client.call(method, payload);
    };
    const path = textOf(params.path).trim();
    const options = withSigning(params);
    delete options.path;
    try {
      switch (action) {
        case 'ls':
          return await groupFs.ls(path, options);
        case 'find':
          return await groupFs.find(path, options);
        case 'stat':
          return await groupFs.stat(path, options);
        case 'lstat':
          return await groupFs.lstat(path, options);
        case 'mkdir':
          return await groupFs.mkdir(path, { ...options, parents: Boolean(params.parents) });
        case 'set_acl':
          return await groupFs.setAcl(path, {
            ...options,
            grantee_aid: textOf(params.grantee_aid ?? params.granteeAid).trim() || 'role:admin',
            perms: textOf(params.perms).trim() || 'rwx',
          });
        case 'remove_acl':
          return await groupFs.removeAcl(path, {
            ...options,
            grantee_aid: textOf(params.grantee_aid ?? params.granteeAid).trim() || 'role:admin',
          });
        case 'get_acl':
          return await groupFs.getAcl(path, options);
        case 'list_acl':
          return await groupFs.listAcl(path, options);
        case 'rm':
          return await groupFs.rm(path, {
            ...options,
            recursive: Boolean(params.recursive),
            force: Boolean(params.force),
          });
        case 'cp': {
          let src: string | Uint8Array = textOf(params.src);
          const dst = textOf(params.dst);
          const cpOptions = withSigning(params);
          delete cpOptions.src;
          delete cpOptions.dst;
          delete cpOptions.src_text;
          if (params.src_text != null) {
            src = textOf(params.src_text);
          }
          const result = await groupFs.cp(src, dst || { type: 'bytes' }, cpOptions);
          return this.groupFsCpResponse(result, dst);
        }
        case 'mv':
          {
            const mvOptions = withSigning(params);
            delete mvOptions.src;
            delete mvOptions.dst;
            return await groupFs.mv(textOf(params.src), textOf(params.dst), mvOptions);
          }
        case 'df':
          return await groupFs.df(path || textOf(params.group_id), options);
        case 'mount':
          return await groupFs.mount(path, options);
        case 'umount':
          return await groupFs.umount(path, options);
        case 'raw':
          return await rawCall(textOf(params.method), withoutKeys(params, ['method']));
        case 'check_upload':
          return await rawCall('group.fs.check_upload', params);
        case 'create_upload_session':
          return await rawCall('group.fs.create_upload_session', params);
        case 'complete_upload':
          return await rawCall('group.fs.complete_upload', params);
        case 'create_download_ticket':
          return await rawCall('group.fs.create_download_ticket', params);
        default:
          throw new Error(`unsupported group fs action: ${action}`);
      }
    } finally {
      const storeToClose = signingStore as AIDStore | null;
      if (storeToClose) storeToClose.close();
    }
  }

  groupFsCpResponse(result: unknown, dst: string): JsonObject {
    const response: JsonObject = { raw: jsonSafe(result) as never };
    const resultObj = jsonObjectOf(result);
    const data: unknown = resultObj?.data;
    if (data instanceof ArrayBuffer) {
      const buffer = Buffer.from(new Uint8Array(data));
      response.content = buffer.toString('utf-8');
      response.content_base64 = buffer.toString('base64');
      response.size_bytes = buffer.byteLength;
    } else if (data instanceof Uint8Array || ArrayBuffer.isView(data)) {
      const view = data as ArrayBufferView;
      const buffer = Buffer.from(view.buffer, view.byteOffset, view.byteLength);
      response.content = buffer.toString('utf-8');
      response.content_base64 = buffer.toString('base64');
      response.size_bytes = buffer.byteLength;
    }
    const localPath = textOf(resultObj?.localPath ?? resultObj?.local_path ?? dst).trim();
    if (localPath && fs.existsSync(localPath) && fs.statSync(localPath).isFile()) {
      const buffer = fs.readFileSync(localPath);
      response.local_path = localPath;
      response.content = buffer.toString('utf-8');
      response.content_base64 = buffer.toString('base64');
      response.size_bytes = buffer.byteLength;
    }
    return response;
  }

  async callStorageAction(action: string, params: JsonObject): Promise<unknown> {
    const storage = this.client.storage;
    const path = textOf(params.path).trim();
    const owner = textOf(params.owner_aid ?? params.ownerAID).trim() || undefined;
    const bucket = textOf(params.bucket).trim() || 'default';
    const token = textOf(params.token).trim() || undefined;
    const src = textOf(params.src).trim();
    const dst = textOf(params.dst).trim();
    const objectKey = textOf(params.object_key ?? params.objectKey ?? path).replace(/^\/+/, '');
    switch (action) {
      case 'write_bytes':
        return await storage.writeBytes(
          path,
          params.content_base64 || params.contentBase64
            ? Buffer.from(textOf(params.content), 'base64')
            : textOf(params.content),
          {
            owner,
            bucket,
            contentType: textOf(params.content_type ?? params.contentType).trim() || 'text/plain',
            public: Boolean(params.public),
            overwrite: params.overwrite == null ? false : Boolean(params.overwrite),
          },
        );
      case 'read_bytes': {
        const data = await storage.readBytes(path, { owner, bucket, token });
        return {
          content: Buffer.from(data).toString('utf-8'),
          content_base64: Buffer.from(data).toString('base64'),
          size_bytes: data.byteLength,
        };
      }
      case 'create_download_ticket': {
        return await storage.lowlevel.createDownloadTicket({ owner, bucket, objectKey, token });
      }
      case 'download_text': {
        const url = textOf(params.url ?? params.download_url ?? params.downloadUrl).trim();
        if (!url) throw new Error('download_text requires url');
        return { content: await downloadText(url, accessTokenFromClient(this.client)) };
      }
      case 'set_acl':
        return await storage.setAcl(path, {
          owner,
          bucket,
          granteeAid: textOf(params.grantee_aid ?? params.granteeAID).trim(),
          perms: textOf(params.perms).trim(),
          expiresAt: params.expires_at == null && params.expiresAt == null ? undefined : Number(params.expires_at ?? params.expiresAt),
          maxUses: params.max_uses == null && params.maxUses == null ? undefined : Number(params.max_uses ?? params.maxUses),
        });
      case 'remove_acl':
        return await storage.removeAcl(path, {
          owner,
          bucket,
          granteeAid: textOf(params.grantee_aid ?? params.granteeAID).trim(),
        });
      case 'list':
        return await storage.list(path, {
          owner,
          bucket,
          page: Number(params.page ?? 1) || 1,
          size: Number(params.size ?? 100) || 100,
          marker: textOf(params.marker).trim() || undefined,
          long: Boolean(params.long),
          recursive: Boolean(params.recursive),
          token,
        });
      case 'find':
        return await storage.find(path, {
          owner,
          bucket,
          name: textOf(params.name).trim() || undefined,
          nodeType: textOf(params.node_type ?? params.nodeType).trim() || undefined,
          size: textOf(params.size_expr ?? params.sizeExpr).trim() || undefined,
          mtime: textOf(params.mtime).trim() || undefined,
          page: Number(params.page ?? 1) || 1,
          pageSize: Number(params.page_size ?? params.pageSize ?? 1000) || 1000,
          token,
        });
      case 'stat':
        return await storage.stat(path, { owner, bucket, token });
      case 'lstat':
        return await storage.lstat(path, { owner, bucket, token });
      case 'mkdir':
        return await storage.mkdir(path, { owner, bucket, parents: Boolean(params.parents) });
      case 'touch':
        return await storage.touch(path, {
          owner,
          bucket,
          parents: Boolean(params.parents),
          noCreate: Boolean(params.no_create ?? params.noCreate),
          mtime: params.mtime == null ? undefined : Number(params.mtime),
          followSymlinks: Boolean(params.follow_symlinks ?? params.followSymlinks),
        });
      case 'remove':
        return await storage.remove(path, { owner, bucket, recursive: Boolean(params.recursive) });
      case 'rename':
        return await storage.rename(src, dst, {
          owner,
          bucket,
          overwrite: Boolean(params.overwrite),
          expectedVersion: params.expected_version == null && params.expectedVersion == null ? undefined : Number(params.expected_version ?? params.expectedVersion),
        });
      case 'copy':
        return await storage.copy(src, dst, {
          owner,
          bucket,
          dstOwner: textOf(params.dst_owner_aid ?? params.dstOwnerAID ?? params.dstOwner).trim() || undefined,
          dstBucket: textOf(params.dst_bucket ?? params.dstBucket).trim() || undefined,
          overwrite: Boolean(params.overwrite),
          followSymlinks: Boolean(params.follow_symlinks ?? params.followSymlinks),
          recursive: Boolean(params.recursive),
        });
      case 'df':
        return await storage.df({ owner, bucket });
      case 'du':
        return await storage.du(path, {
          owner,
          bucket,
          maxDepth: params.max_depth == null && params.maxDepth == null ? undefined : Number(params.max_depth ?? params.maxDepth),
          pageSize: Number(params.page_size ?? params.pageSize ?? 1000) || 1000,
          token,
        });
      case 'symlink':
        return await storage.symlink(textOf(params.target), path, { owner, bucket, overwrite: Boolean(params.overwrite) });
      case 'readlink':
        return await storage.readlink(path, { owner, bucket });
      case 'repoint':
        return await storage.repoint(path, textOf(params.new_target ?? params.newTarget), {
          owner,
          bucket,
          expectedVersion: params.expected_version == null && params.expectedVersion == null ? undefined : Number(params.expected_version ?? params.expectedVersion),
        });
      case 'rename_symlink':
        return await storage.renameSymlink(src, dst, {
          owner,
          bucket,
          overwrite: Boolean(params.overwrite),
          expectedVersion: params.expected_version == null && params.expectedVersion == null ? undefined : Number(params.expected_version ?? params.expectedVersion),
        });
      case 'delete_symlink':
        return await storage.lowlevel.deleteSymlink({ owner, bucket, path: objectKey });
      case 'list_acl':
        return await storage.listAcl(path, { owner, bucket });
      case 'check_access':
        return await storage.checkAccess(path, {
          owner,
          bucket,
          operation: textOf(params.operation).trim() || 'read',
          token,
          followSymlinks: params.follow_symlinks == null && params.followSymlinks == null ? true : Boolean(params.follow_symlinks ?? params.followSymlinks),
        });
      case 'issue_token':
        return await storage.issueToken(path, {
          owner,
          bucket,
          expiresAt: params.expires_at == null && params.expiresAt == null ? undefined : Number(params.expires_at ?? params.expiresAt),
          maxReads: params.max_reads == null && params.maxReads == null ? undefined : Number(params.max_reads ?? params.maxReads),
        });
      case 'revoke_token':
        return await storage.revokeToken(path, { owner, bucket, token: textOf(params.token) });
      case 'list_tokens':
        return await storage.listTokens(path, { owner, bucket });
      case 'set_visibility': {
        const allowRoles = Array.isArray(params.allow_roles) ? params.allow_roles.map((item) => textOf(item)) : (Array.isArray(params.allowRoles) ? params.allowRoles.map((item) => textOf(item)) : undefined);
        return await storage.setVisibility(path, { owner, bucket, visibility: textOf(params.visibility).trim() || 'private', allowRoles });
      }
      case 'create_share_link': {
        const allowedAids = Array.isArray(params.allowed_aids) ? params.allowed_aids.map((item) => textOf(item)) : (Array.isArray(params.allowedAids) ? params.allowedAids.map((item) => textOf(item)) : undefined);
        return await storage.lowlevel.createShareLink({
          owner,
          bucket,
          objectKey,
          allowedAids,
          expireInSeconds: params.expire_in_seconds == null && params.expireInSeconds == null ? undefined : Number(params.expire_in_seconds ?? params.expireInSeconds),
          maxUses: params.max_uses == null && params.maxUses == null ? undefined : Number(params.max_uses ?? params.maxUses),
        });
      }
      case 'list_share_links':
        return await storage.lowlevel.listShareLinks({ owner, bucket, objectKey: objectKey || undefined });
      case 'revoke_share_link':
        return await storage.lowlevel.revokeShareLink({ shareId: textOf(params.share_id ?? params.shareId).trim() });
      case 'get_by_share': {
        const result = await storage.lowlevel.getByShare({ shareId: textOf(params.share_id ?? params.shareId).trim() });
        const resultObj = jsonObjectOf(result);
        const content = textOf(resultObj?.content);
        if (content) {
          try {
            const buffer = Buffer.from(content, 'base64');
            return { ...(resultObj ?? {}), content_text: buffer.toString('utf-8'), content_base64: buffer.toString('base64') };
          } catch {
            return result;
          }
        }
        return result;
      }
      case 'head_object':
        return await storage.lowlevel.headObject({ owner, bucket, objectKey, token });
      case 'list_objects':
        return await storage.lowlevel.listObjects({
          owner,
          bucket,
          prefix: textOf(params.prefix),
          page: Number(params.page ?? 1) || 1,
          size: Number(params.size ?? 100) || 100,
          marker: textOf(params.marker).trim() || undefined,
        });
      case 'list_prefixes':
        return await storage.lowlevel.listPrefixes({ owner, bucket, prefix: textOf(params.prefix), size: Number(params.size ?? 100) || 100 });
      case 'delete_object':
        return await storage.lowlevel.deleteObject({ owner, bucket, objectKey });
      case 'set_object_meta':
        return await storage.lowlevel.setObjectMeta({
          owner,
          bucket,
          objectKey,
          metadata: jsonObjectOf(params.metadata) ?? {},
          contentType: textOf(params.content_type ?? params.contentType).trim() || undefined,
          merge: params.merge == null ? true : Boolean(params.merge),
          expectedVersion: params.expected_version == null && params.expectedVersion == null ? undefined : Number(params.expected_version ?? params.expectedVersion),
        });
      case 'append_object':
        return await storage.lowlevel.appendObject({
          owner,
          bucket,
          objectKey,
          content: params.content_base64 || params.contentBase64 ? Buffer.from(textOf(params.content), 'base64') : Buffer.from(textOf(params.content), 'utf-8'),
          contentType: textOf(params.content_type ?? params.contentType).trim() || undefined,
          metadata: jsonObjectOf(params.metadata) ?? undefined,
          expectedVersion: params.expected_version == null && params.expectedVersion == null ? undefined : Number(params.expected_version ?? params.expectedVersion),
          isPublic: Boolean(params.public ?? params.isPublic),
        });
      case 'create_folder':
        return await storage.lowlevel.createFolder({ owner, bucket, path: objectKey, parents: Boolean(params.parents ?? params.mkdirs) });
      case 'list_children':
        return await storage.lowlevel.listChildren({
          owner,
          bucket,
          path: objectKey,
          nodeType: textOf(params.node_type ?? params.nodeType ?? params.type).trim() || 'all',
          page: Number(params.page ?? 1) || 1,
          size: Number(params.size ?? 50) || 50,
          orderBy: textOf(params.order_by ?? params.orderBy).trim() || undefined,
          order: textOf(params.order).trim() || undefined,
          includeMetadata: params.include_metadata == null && params.includeMetadata == null ? undefined : Boolean(params.include_metadata ?? params.includeMetadata),
          includeUrls: params.include_urls == null && params.includeUrls == null ? undefined : Boolean(params.include_urls ?? params.includeUrls),
        });
      case 'copy_object':
        return await storage.lowlevel.copyObject({
          owner,
          bucket,
          srcPath: textOf(params.src_path ?? params.srcPath ?? src).replace(/^\/+/, ''),
          dstPath: textOf(params.dst_path ?? params.dstPath ?? dst).replace(/^\/+/, ''),
          overwrite: Boolean(params.overwrite),
        });
      case 'move_object':
        return await storage.lowlevel.moveObject({
          owner,
          bucket,
          path: textOf(params.src_path ?? params.srcPath ?? src ?? objectKey).replace(/^\/+/, ''),
          dstParentPath: textOf(params.dst_parent_path ?? params.dstParentPath).replace(/^\/+/, '').replace(/\/+$/g, ''),
          newName: textOf(params.new_name ?? params.newName),
          overwrite: Boolean(params.overwrite),
          expectedVersion: params.expected_version == null && params.expectedVersion == null ? undefined : Number(params.expected_version ?? params.expectedVersion),
        });
      case 'batch_delete': {
        const items = Array.isArray(params.items) ? params.items.filter((item) => item && typeof item === 'object' && !Array.isArray(item)) as JsonObject[] : [];
        return await storage.lowlevel.batchDelete({ owner, bucket, items, recursive: Boolean(params.recursive) });
      }
      default:
        throw new Error(`unsupported storage action: ${action}`);
    }
  }

  async send(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const traceId = textOf(body.trace_id || crypto.randomUUID().replace(/-/g, ''));
    const messageId = textOf(body.message_id || `${traceId}-${crypto.randomUUID().slice(0, 8)}`);
    const target = textOf(body.to).trim();
    const text = textOf(body.text);
    const e2ee = body.e2ee !== false;
    if (!target) {
      sendJson(res, 400, { ok: false, error_code: 'bad_request', error_message: 'to is required' });
      return;
    }
    try {
      const result = await this.client.call('message.send', {
        to: target,
        payload: { type: 'text', text, trace_id: traceId, case_id: textOf(body.case_id || traceId) },
        encrypt: e2ee,
        message_id: messageId,
      });
      const resultObj = jsonObjectOf(result) ?? {};
      const response: JsonObject = {
        ok: true,
        trace_id: traceId,
        message_id: messageId,
        seq: Number(resultObj.seq ?? resultObj.message_seq ?? 0) || 0,
        encrypted: e2ee,
        result: jsonSafe(result) as never,
      };
      this.sendResults.set(traceId, response);
      this.recordTrace(traceId, { stage: 'send', target, message_id: messageId, result: response });
      sendJson(res, 200, response);
    } catch (err) {
      const error: JsonObject = {
        ok: false,
        trace_id: traceId,
        message_id: messageId,
        encrypted: e2ee,
        error_code: err instanceof Error ? err.name : 'Error',
        error_message: err instanceof Error ? err.message : String(err),
      };
      this.sendResults.set(traceId, error);
      this.recordTrace(traceId, { stage: 'send_error', target, message_id: messageId, error });
      sendJson(res, 500, error);
    }
  }

  async ack(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const seq = Number(body.seq ?? body.up_to_seq ?? 0) || 0;
    const params: RpcParams = {};
    if (seq > 0) params.seq = seq;
    try {
      const result = await this.client.call('message.ack', params);
      sendJson(res, 200, { ok: true, seq, result: jsonSafe(result) as never });
    } catch (err) {
      sendJson(res, 500, {
        ok: false,
        seq,
        error_code: err instanceof Error ? err.name : 'Error',
        error_message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  async pull(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const afterSeq = Number(body.after_seq ?? 0) || 0;
    const limit = Number(body.limit ?? 50) || 50;
    try {
      const result = await this.client.call('message.pull', { after_seq: afterSeq, limit });
      const resultObj = jsonObjectOf(result) ?? {};
      const messages = Array.isArray(resultObj.messages) ? resultObj.messages : [];
      for (const msg of messages) await this.storeInboxItem(this.normalizeMessage(msg, true));
      sendJson(res, 200, { ok: true, result: jsonSafe(result) as never });
    } catch (err) {
      sendJson(res, 500, {
        ok: false,
        error_code: err instanceof Error ? err.name : 'Error',
        error_message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  async groupCreate(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const traceId = textOf(body.trace_id || crypto.randomUUID().replace(/-/g, ''));
    const name = textOf(body.name || `cross-sdk-${traceId.slice(0, 8)}`);
    const members = Array.isArray(body.members) ? body.members.map((item) => textOf(item).trim()).filter(Boolean) : [];
    const params: RpcParams = { name, visibility: textOf(body.visibility || 'private') };
    const groupName = textOf(body.group_name ?? body.groupName ?? '').trim();
    if (groupName) params.group_name = groupName;
    const joinMode = textOf(body.join_mode || '').trim();
    if (joinMode) params.join_mode = joinMode;
    try {
      const createResult = groupName ? await this.client.createGroup(params) : await this.client.call('group.create', params);
      const groupId = extractGroupId(createResult);
      const groupAid = extractGroupAid(createResult);
      if (!groupId) throw new Error(`group.create did not return group_id: ${JSON.stringify(jsonSafe(createResult))}`);
      const addResults: unknown[] = [];
      for (const aid of members) {
        if (!aid || aid === this.aid) continue;
        const addResult = await this.client.call('group.add_member', { group_id: groupId, aid, role: 'member' });
        addResults.push(jsonSafe(addResult));
      }
      const response: JsonObject = {
        ok: true,
        trace_id: traceId,
        group_id: groupId,
        group_aid: groupAid,
        create_result: jsonSafe(createResult) as never,
        add_results: addResults as never,
      };
      this.recordTrace(traceId, { stage: 'group_create', group_id: groupId, result: response });
      sendJson(res, 200, response);
    } catch (err) {
      const error: JsonObject = {
        ok: false,
        trace_id: traceId,
        error_code: err instanceof Error ? err.name : 'Error',
        error_message: err instanceof Error ? err.message : String(err),
      };
      this.recordTrace(traceId, { stage: 'group_create_error', error });
      sendJson(res, 500, error);
    }
  }

  async groupReady(url: URL, res: http.ServerResponse): Promise<void> {
    const groupId = textOf(url.searchParams.get('group_id') ?? '').trim();
    const expected = textOf(url.searchParams.get('members') ?? this.aid).split(',').map((item) => item.trim()).filter(Boolean);
    const requireDevices = envBool('CROSS_SDK_GROUP_READY_REQUIRE_DEVICES', true);
    if (!groupId) {
      sendJson(res, 400, { ok: false, ready: false, error_code: 'bad_request', error_message: 'group_id is required' });
      return;
    }
    try {
      const bootstrap = await this.client.call('group.v2.bootstrap', { group_id: groupId });
      const boot = jsonObjectOf(bootstrap) ?? {};
      const committedRaw = Array.isArray(boot.committed_member_aids) ? boot.committed_member_aids : (Array.isArray(boot.member_aids) ? boot.member_aids : []);
      const committed = new Set(committedRaw.map((item) => textOf(item)));
      const devices = Array.isArray(boot.devices) ? boot.devices : [];
      const deviceAids = new Set(devices.map((item) => textOf(jsonObjectOf(item)?.aid)));
      const membershipOk = expected.every((aid) => committed.has(aid));
      const devicesOk = !requireDevices || expected.every((aid) => deviceAids.has(aid));
      sendJson(res, 200, {
        ok: true,
        ready: membershipOk && devicesOk,
        group_id: groupId,
        expected,
        committed_member_aids: [...committed].sort(),
        device_aids: [...deviceAids].sort(),
        pending_adds: Array.isArray(boot.pending_adds) ? boot.pending_adds : [],
        bootstrap: jsonSafe(bootstrap) as never,
      });
    } catch (err) {
      sendJson(res, 500, {
        ok: false,
        ready: false,
        error_code: err instanceof Error ? err.name : 'Error',
        error_message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  async groupSend(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const traceId = textOf(body.trace_id || crypto.randomUUID().replace(/-/g, ''));
    const messageId = textOf(body.message_id || `${traceId}-${crypto.randomUUID().slice(0, 8)}`);
    const groupId = textOf(body.group_id).trim();
    const text = textOf(body.text);
    const e2ee = body.e2ee !== false;
    if (!groupId) {
      sendJson(res, 400, { ok: false, error_code: 'bad_request', error_message: 'group_id is required' });
      return;
    }
    try {
      const result = await this.client.call('group.send', {
        group_id: groupId,
        payload: { type: 'text', text, trace_id: traceId, case_id: textOf(body.case_id || traceId) },
        encrypt: e2ee,
        message_id: messageId,
      });
      const resultObj = jsonObjectOf(result) ?? {};
      const response: JsonObject = {
        ok: true,
        trace_id: traceId,
        group_id: groupId,
        message_id: messageId,
        seq: Number(resultObj.seq ?? resultObj.message_seq ?? 0) || 0,
        encrypted: e2ee,
        result: jsonSafe(result) as never,
      };
      this.recordTrace(traceId, { stage: 'group_send', group_id: groupId, message_id: messageId, result: response });
      sendJson(res, 200, response);
    } catch (err) {
      const error: JsonObject = {
        ok: false,
        trace_id: traceId,
        group_id: groupId,
        message_id: messageId,
        encrypted: e2ee,
        error_code: err instanceof Error ? err.name : 'Error',
        error_message: err instanceof Error ? err.message : String(err),
      };
      this.recordTrace(traceId, { stage: 'group_send_error', group_id: groupId, message_id: messageId, error });
      sendJson(res, 500, error);
    }
  }

  async groupPull(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const groupId = textOf(body.group_id).trim();
    const afterSeq = Number(body.after_seq ?? 0) || 0;
    const limit = Number(body.limit ?? 50) || 50;
    if (!groupId) {
      sendJson(res, 400, { ok: false, error_code: 'bad_request', error_message: 'group_id is required' });
      return;
    }
    const result = await this.client.call('group.pull', { group_id: groupId, after_seq: afterSeq, limit });
    const messages = Array.isArray(jsonObjectOf(result)?.messages) ? jsonObjectOf(result)!.messages as unknown[] : [];
    for (const msg of messages) await this.storeGroupInboxItem(this.normalizeGroupMessage(msg, true));
    sendJson(res, 200, { ok: true, group_id: groupId, result: jsonSafe(result) as never });
  }

  async groupAck(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const groupId = textOf(body.group_id).trim();
    const seq = Number(body.seq ?? body.msg_seq ?? body.up_to_seq ?? 0) || 0;
    if (!groupId) {
      sendJson(res, 400, { ok: false, error_code: 'bad_request', error_message: 'group_id is required' });
      return;
    }
    const params: RpcParams = { group_id: groupId };
    if (seq > 0) {
      params.msg_seq = seq;
      params.up_to_seq = seq;
    }
    try {
      const result = await this.client.call('group.ack_messages', params);
      sendJson(res, 200, { ok: true, group_id: groupId, seq, result: jsonSafe(result) as never });
    } catch (err) {
      sendJson(res, 500, {
        ok: false,
        group_id: groupId,
        seq,
        error_code: err instanceof Error ? err.name : 'Error',
        error_message: err instanceof Error ? err.message : String(err),
      });
    }
  }

}

function extractGroupId(result: unknown): string {
  const obj = jsonObjectOf(result);
  if (!obj) return '';
  if (obj.group_id) return textOf(obj.group_id);
  const group = jsonObjectOf(obj.group);
  if (group?.group_id) return textOf(group.group_id);
  const member = jsonObjectOf(obj.member);
  if (member?.group_id) return textOf(member.group_id);
  return '';
}

function extractGroupAid(result: unknown): string {
  const obj = jsonObjectOf(result);
  if (!obj) return '';
  const group = jsonObjectOf(obj.group);
  return textOf(group?.group_aid ?? obj.group_aid).trim();
}

function shouldForwardBearerOnRedirect(current: URL, next: URL): boolean {
  if (current.origin === next.origin) return true;
  const currentHost = current.hostname.toLowerCase();
  const nextHost = next.hostname.toLowerCase();
  if (!nextHost.startsWith('storage.')) return false;
  const issuer = nextHost.slice('storage.'.length);
  return Boolean(issuer) && (currentHost === issuer || currentHost.endsWith(`.${issuer}`));
}

function downloadText(url: string, bearerToken = '', redirects = 0): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const client = parsed.protocol === 'https:' ? https : http;
    const headers = bearerToken ? { Authorization: `Bearer ${bearerToken}` } : undefined;
    const options: https.RequestOptions = parsed.protocol === 'https:'
      ? { rejectUnauthorized: false, headers }
      : { headers };
    const req = client.get(parsed, options, (resp) => {
      const status = resp.statusCode ?? 0;
      const location = typeof resp.headers.location === 'string' ? resp.headers.location : '';
      if ([301, 302, 303, 307, 308].includes(status) && location) {
        resp.resume();
        if (redirects >= 5) {
          reject(new Error(`download redirect limit exceeded url=${url}`));
          return;
        }
        const nextUrl = new URL(location, parsed).toString();
        const nextBearer = bearerToken && shouldForwardBearerOnRedirect(parsed, new URL(nextUrl)) ? bearerToken : '';
        downloadText(nextUrl, nextBearer, redirects + 1).then(resolve, reject);
        return;
      }
      const chunks: Buffer[] = [];
      resp.on('data', (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      resp.on('end', () => {
        if (status < 200 || status >= 300) {
          reject(new Error(`download failed status=${status} url=${url}`));
          return;
        }
        const content = Buffer.concat(chunks).toString('utf-8');
        if (!content) {
          reject(new Error(`download returned empty body status=${status} url=${url}`));
          return;
        }
        resolve(content);
      });
    });
    req.setTimeout(20000, () => {
      req.destroy(new Error('download timeout'));
    });
    req.on('error', reject);
  });
}

async function main(): Promise<void> {
  installNodeBrowserShims();
  const agent = new CrossSdkJsAgent();
  void agent.start().catch((err) => {
    agent.startupError = `${err instanceof Error ? err.name : 'Error'}: ${err instanceof Error ? err.message : String(err)}`;
    console.error(agent.startupError);
  });

  const host = textOf(process.env.AUN_CONTROL_HOST || '0.0.0.0');
  const port = Number(process.env.AUN_CONTROL_PORT || 9001) || 9001;
  const server = http.createServer((req, res) => {
    void agent.handle(req, res);
  });
  server.listen(port, host, () => {
    console.log(`cross-sdk js agent listening on ${host}:${port}`);
  });

  const shutdown = async (): Promise<void> => {
    server.close();
    await agent.close();
    process.exit(0);
  };
  process.on('SIGINT', () => { void shutdown(); });
  process.on('SIGTERM', () => { void shutdown(); });
}

void main();
