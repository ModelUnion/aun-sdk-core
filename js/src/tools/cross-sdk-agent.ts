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
      if (req.method === 'POST' && url.pathname === '/group/resources/init') {
        await this.groupResourcesInit(req, res);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/group/resources/put') {
        await this.groupResourcesPut(req, res);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/group/resources/mkdir') {
        await this.groupResourcesMkdir(req, res);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/group/resources/mount') {
        await this.groupResourcesMount(req, res);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/group/resources/read') {
        await this.groupResourcesRead(req, res);
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

  async callCollabAction(action: string, params: JsonObject): Promise<unknown> {
    const collabRoot = textOf(params.collab_root ?? params.collabRoot);
    const doc = textOf(params.doc);
    const source = textOf(params.source);
    switch (action) {
      case 'ls':
        return await this.client.collab.ls(collabRoot);
      case 'create':
        return await this.client.collab.create(collabRoot, doc, source);
      case 'read':
        return await this.client.collab.read(collabRoot, doc);
      case 'submit':
        return await this.client.collab.submit(collabRoot, doc, source, Number(params.base_version ?? params.baseVersion ?? 0) || 0);
      case 'merge':
        return await this.client.collab.merge(collabRoot, doc, source, Number(params.base_version ?? params.baseVersion ?? 0) || 0);
      case 'history':
        return await this.client.collab.history(collabRoot, doc);
      case 'get':
        return await this.client.collab.get(collabRoot, doc, Number(params.version ?? 0) || 0);
      case 'diff':
        return await this.client.collab.diff(collabRoot, doc, Number(params.from ?? 0) || 0, Number(params.to ?? 0) || 0);
      case 'export':
        return await this.client.collab.export(collabRoot, textOf(params.dest));
      case 'adopt':
        return await this.client.collab.adopt(textOf(params.src), textOf(params.new_root ?? params.newRoot));
      case 'prune':
        return await this.client.collab.prune(collabRoot, doc);
      case 'discover':
        return await this.client.collab.discover(textOf(params.group_aid ?? params.groupAid));
      case 'unregister':
        return await this.client.collab.unregister(textOf(params.group_aid ?? params.groupAid), collabRoot);
      case 'snapshot.create':
        return await this.client.collab.snapshot.create(collabRoot, {
          message: textOf(params.message),
          major: Boolean(params.major),
        });
      case 'snapshot.list':
        return await this.client.collab.snapshot.list(collabRoot);
      case 'snapshot.show':
        return await this.client.collab.snapshot.show(collabRoot, textOf(params.version));
      case 'snapshot.diff':
        return await this.client.collab.snapshot.diff(collabRoot, textOf(params.version_a ?? params.versionA), textOf(params.version_b ?? params.versionB));
      case 'snapshot.restore':
        return await this.client.collab.snapshot.restore(collabRoot, textOf(params.version), { message: textOf(params.message) });
      case 'snapshot.rm':
        return await this.client.collab.snapshot.rm(collabRoot, textOf(params.version));
      case 'snapshot.prune':
        return await this.client.collab.snapshot.prune(collabRoot, {
          before: params.before == null ? null : Number(params.before),
          keep_last: params.keep_last == null && params.keepLast == null ? null : Number(params.keep_last ?? params.keepLast),
        });
      case 'gc':
        return await this.client.collab.gc(collabRoot, params.dry_run == null && params.dryRun == null ? true : Boolean(params.dry_run ?? params.dryRun));
      case 'reflog':
        return await this.client.collab.reflog(collabRoot, doc || undefined, Number(params.limit ?? 100) || 100);
      case 'reset':
        return await this.client.collab.reset(collabRoot, doc, Number(params.version ?? 0) || 0, textOf(params.message) || '');
      default:
        throw new Error(`unsupported collab action: ${action}`);
    }
  }

  async callStorageAction(action: string, params: JsonObject): Promise<unknown> {
    const storage = this.client.storage;
    const path = textOf(params.path).trim();
    const owner = textOf(params.owner_aid ?? params.ownerAID).trim() || undefined;
    const bucket = textOf(params.bucket).trim() || 'default';
    const token = textOf(params.token).trim() || undefined;
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
            overwrite: params.overwrite == null ? true : Boolean(params.overwrite),
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
        const objectKey = textOf(params.object_key ?? params.objectKey ?? path).replace(/^\/+/, '');
        return await storage.lowlevel.createDownloadTicket({ owner, bucket, objectKey, token });
      }
      case 'download_text': {
        const url = textOf(params.url ?? params.download_url ?? params.downloadUrl).trim();
        if (!url) throw new Error('download_text requires url');
        return { content: await downloadText(url) };
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

  async groupResourcesInit(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const traceId = textOf(body.trace_id || crypto.randomUUID().replace(/-/g, ''));
    try {
      const store = this.aidStore();
      try {
        const result = await this.client.group.resources.initializeNamespace(body, {
          aidStore: store,
          connectOptions: { heartbeat_interval: 0 },
        });
        const response: JsonObject = { ok: true, trace_id: traceId, result: jsonSafe(result) as never };
        this.recordTrace(traceId, { stage: 'group_resources_init', result: response });
        sendJson(res, 200, response);
      } finally {
        store.close();
      }
    } catch (err) {
      const error: JsonObject = { ok: false, trace_id: traceId, error_code: err instanceof Error ? err.name : 'Error', error_message: err instanceof Error ? err.message : String(err) };
      this.recordTrace(traceId, { stage: 'group_resources_init_error', error });
      sendJson(res, 500, error);
    }
  }

  async groupResourcesPut(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const traceId = textOf(body.trace_id || crypto.randomUUID().replace(/-/g, ''));
    try {
      const store = this.aidStore();
      try {
        const pending = await this.client.group.resources.put(body);
        const pendingObj = jsonObjectOf(pending);
        const confirmed = Array.isArray(pendingObj?.pending_ops)
          ? await this.client.group.resources.executePendingOps(pendingObj, {
              aidStore: store,
              connectOptions: { heartbeat_interval: 0 },
            })
          : null;
        const response: JsonObject = { ok: true, trace_id: traceId, pending: jsonSafe(pending) as never, confirmed: jsonSafe(confirmed) as never };
        this.recordTrace(traceId, { stage: 'group_resources_put', result: response });
        sendJson(res, 200, response);
      } finally {
        store.close();
      }
    } catch (err) {
      const error: JsonObject = { ok: false, trace_id: traceId, error_code: err instanceof Error ? err.name : 'Error', error_message: err instanceof Error ? err.message : String(err) };
      this.recordTrace(traceId, { stage: 'group_resources_put_error', error });
      sendJson(res, 500, error);
    }
  }

  async groupResourcesMkdir(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const traceId = textOf(body.trace_id || crypto.randomUUID().replace(/-/g, ''));
    try {
      const result = await this.client.group.resources.createFolder(body);
      const response: JsonObject = { ok: true, trace_id: traceId, result: jsonSafe(result) as never };
      this.recordTrace(traceId, { stage: 'group_resources_mkdir', result: response });
      sendJson(res, 200, response);
    } catch (err) {
      const error: JsonObject = { ok: false, trace_id: traceId, error_code: err instanceof Error ? err.name : 'Error', error_message: err instanceof Error ? err.message : String(err) };
      this.recordTrace(traceId, { stage: 'group_resources_mkdir_error', error });
      sendJson(res, 500, error);
    }
  }

  async groupResourcesMount(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const traceId = textOf(body.trace_id || crypto.randomUUID().replace(/-/g, ''));
    try {
      const store = this.aidStore();
      try {
        const pending = await this.client.group.resources.mountObject(body);
        const pendingObj = jsonObjectOf(pending);
        if (!Array.isArray(pendingObj?.pending_ops)) {
          throw new Error(`group.resources.mount_object did not return pending_ops: ${JSON.stringify(jsonSafe(pending))}`);
        }
        const confirmed = await this.client.group.resources.executePendingOps(pendingObj, {
          aidStore: store,
          connectOptions: { heartbeat_interval: 0 },
        });
        const response: JsonObject = { ok: true, trace_id: traceId, pending: jsonSafe(pending) as never, confirmed: jsonSafe(confirmed) as never };
        this.recordTrace(traceId, { stage: 'group_resources_mount', result: response });
        sendJson(res, 200, response);
      } finally {
        store.close();
      }
    } catch (err) {
      const error: JsonObject = { ok: false, trace_id: traceId, error_code: err instanceof Error ? err.name : 'Error', error_message: err instanceof Error ? err.message : String(err) };
      this.recordTrace(traceId, { stage: 'group_resources_mount_error', error });
      sendJson(res, 500, error);
    }
  }

  async groupResourcesRead(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readJson(req);
    const traceId = textOf(body.trace_id || crypto.randomUUID().replace(/-/g, ''));
    try {
      const access = await this.client.group.resources.getAccess(body);
      const download = jsonObjectOf(jsonObjectOf(access)?.download) ?? {};
      const downloadUrl = textOf(download.download_url ?? download.downloadUrl).trim();
      if (!downloadUrl) throw new Error(`group.resources.get_access did not return download_url: ${JSON.stringify(jsonSafe(access))}`);
      const content = await downloadText(downloadUrl);
      const response: JsonObject = { ok: true, trace_id: traceId, content, access: jsonSafe(access) as never };
      this.recordTrace(traceId, { stage: 'group_resources_read', result: { ok: true, content_len: content.length } });
      sendJson(res, 200, response);
    } catch (err) {
      const error: JsonObject = { ok: false, trace_id: traceId, error_code: err instanceof Error ? err.name : 'Error', error_message: err instanceof Error ? err.message : String(err) };
      this.recordTrace(traceId, { stage: 'group_resources_read_error', error });
      sendJson(res, 500, error);
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

function downloadText(url: string, redirects = 0): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const client = parsed.protocol === 'https:' ? https : http;
    const options: https.RequestOptions = parsed.protocol === 'https:' ? { rejectUnauthorized: false } : {};
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
        downloadText(nextUrl, redirects + 1).then(resolve, reject);
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
