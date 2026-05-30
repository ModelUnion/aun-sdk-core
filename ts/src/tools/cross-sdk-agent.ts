#!/usr/bin/env node

import * as http from 'node:http';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import { URL } from 'node:url';
import { AUNClient } from '../client.js';
import { AIDStore } from '../aid-store.js';
import { certificateSha256Fingerprint } from '../crypto.js';
import type { JsonObject, RpcParams } from '../types.js';

interface ClientInternals {
  _gatewayUrl?: string | null;
  _configModel?: { requireForwardSecrecy?: boolean };
  _testSlotId?: string;
  _deviceId?: string;
  _slotId?: string;
  _state?: string;
  _identity?: JsonObject | null;
  _auth?: {
    loadIdentityOrNone?: (aid?: string) => JsonObject | null;
  };
}

function envBool(name: string, fallback = false): boolean {
  const raw = process.env[name];
  if (raw == null) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(raw.trim().toLowerCase());
}

function jsonSafe(value: unknown): unknown {
  try {
    JSON.stringify(value);
    return value;
  } catch {
    if (Array.isArray(value)) return value.map((item) => jsonSafe(item));
    if (value && typeof value === 'object') {
      const out: JsonObject = {};
      for (const [key, item] of Object.entries(value as JsonObject)) out[key] = jsonSafe(item) as any;
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

function textOf(value: unknown): string {
  return String(value ?? '');
}

function jsonObjectOf(value: unknown): JsonObject | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : null;
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

class CrossSdkTsAgent {
  readonly language = 'ts';
  readonly sdkVersion = 'unknown';
  readonly aid = textOf(process.env.AUN_TEST_AID || 'cross-ts.agentid.pub').trim();
  readonly issuer = textOf(process.env.AUN_TEST_ISSUER || 'agentid.pub').trim() || 'agentid.pub';
  readonly gatewayAid = textOf(process.env.AUN_GATEWAY_AID || `gateway.${this.issuer}`).trim();
  readonly gatewayUrl = textOf(process.env.AUN_GATEWAY_URL || '').trim();
  readonly slotId = textOf(process.env.AUN_TEST_SLOT_ID || `cross-sdk-ts-${crypto.randomUUID().slice(0, 8)}`).trim();
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
    internal._testSlotId = this.slotId;
    if (this.gatewayUrl) internal._gatewayUrl = this.gatewayUrl;
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

  async ensureConnected(): Promise<void> {
    const internal = this.client as unknown as ClientInternals;
    if (this.gatewayUrl) internal._gatewayUrl = this.gatewayUrl;
    const store = new AIDStore({
      aunPath: this.aunPath,
      encryptionSeed: '',
      slotId: this.slotId,
      debug: this.debug,
    });
    try {
      const registered = await store.register(this.aid);
      if (!registered.ok) {
        const loaded = store.load(this.aid);
        if (!loaded.ok) {
          throw new Error(`${registered.error.code}: ${registered.error.message}`);
        }
      }
    } catch (err) {
      const localIdentity = internal._auth?.loadIdentityOrNone?.(this.aid);
      if (!localIdentity) {
        throw new Error(`registerAid failed and no local identity exists: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    const loaded = store.load(this.aid);
    if (!loaded.ok) {
      throw new Error(`load identity failed: ${loaded.error.code}: ${loaded.error.message}`);
    }
    this.client.loadIdentity(loaded.data.aid);
    const internal2 = this.client as unknown as ClientInternals;
    if (this.gatewayUrl) internal2._gatewayUrl = this.gatewayUrl;
    await this.client.connect();
  }

  identity(): JsonObject {
    const internal = this.client as unknown as ClientInternals;
    const identity = internal._identity ?? internal._auth?.loadIdentityOrNone?.(this.aid) ?? {};
    const cert = textOf(identity.cert ?? identity.cert_pem ?? '');
    return {
      aid: this.aid,
      device_id: textOf(internal._deviceId ?? ''),
      slot_id: textOf(internal._slotId ?? this.slotId),
      issuer: this.issuer,
      public_key_fingerprint: cert ? certificateSha256Fingerprint(cert) : '',
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

  normalizeMessage(msg: unknown, decrypted: boolean, errorCode = ''): JsonObject {
    const data: JsonObject = msg && typeof msg === 'object' && !Array.isArray(msg) ? msg as JsonObject : { raw: textOf(msg) };
    const payload = data.payload && typeof data.payload === 'object' ? data.payload as JsonObject : {};
    const traceId = textOf(payload.trace_id ?? data.trace_id ?? '');
    const text = textOf(payload.text ?? data.text ?? '');
    const metadata = envelopeMetadata(data);
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
      ...metadata,
    };
  }

  normalizeGroupMessage(msg: unknown, decrypted: boolean, errorCode = ''): JsonObject {
    const data: JsonObject = msg && typeof msg === 'object' && !Array.isArray(msg) ? msg as JsonObject : { raw: textOf(msg) };
    const payload = data.payload && typeof data.payload === 'object' && !Array.isArray(data.payload) ? data.payload as JsonObject : {};
    const traceId = textOf(payload.trace_id ?? data.trace_id ?? '');
    const text = textOf(payload.text ?? data.text ?? '');
    const metadata = envelopeMetadata(data);
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
      ...metadata,
    };
  }

  async storeGroupInboxItem(item: JsonObject): Promise<void> {
    this.groupInbox.push(item);
    if (this.groupInbox.length > 1000) this.groupInbox = this.groupInbox.slice(-1000);
    this.recordTrace(textOf(item.trace_id), { stage: 'group_receive', message: item });
  }

  async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    try {
      if (req.method === 'GET' && url.pathname === '/health') {
        const state = textOf(this.client.state ?? (this.client as unknown as ClientInternals)._state ?? '');
        sendJson(res, this.startupError ? 503 : 200, {
          ok: !this.startupError,
          agent_ready: this.ready && (state === 'ready' || state === 'connected'),
          state,
          aid: this.aid,
          language: this.language,
          sdk_version: this.sdkVersion,
          gateway_url: textOf((this.client as unknown as ClientInternals)._gatewayUrl ?? ''),
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
        sendJson(res, 200, this.identity());
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
      if (req.method === 'GET' && url.pathname === '/inbox') {
        const traceId = textOf(url.searchParams.get('trace_id') ?? '');
        const fromAid = textOf(url.searchParams.get('from') ?? '');
        const limit = Number(url.searchParams.get('limit') ?? 20) || 20;
        let items = [...this.inbox];
        if (traceId) items = items.filter((item) => item.trace_id === traceId);
        if (fromAid) items = items.filter((item) => item.from === fromAid);
        items = items.slice(-limit);
        sendJson(res, 200, { received: items.length > 0, items });
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
        items = items.slice(-limit);
        sendJson(res, 200, { received: items.length > 0, items });
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
    const payload: JsonObject = {
      type: 'text',
      text,
      trace_id: traceId,
      case_id: textOf(body.case_id || traceId),
    };
    const params: RpcParams = {
      to: target,
      payload,
      encrypt: e2ee,
      message_id: messageId,
    };
    try {
      const result = await this.client.call('message.send', params);
      const resultObj = result && typeof result === 'object' ? result as JsonObject : {};
      const response: JsonObject = {
        ok: true,
        trace_id: traceId,
        message_id: messageId,
        seq: Number(resultObj.seq ?? resultObj.message_seq ?? 0) || 0,
        encrypted: e2ee,
        result: jsonSafe(result) as any,
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
      sendJson(res, 200, { ok: true, seq, result: jsonSafe(result) as any });
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
      const resultObj = result && typeof result === 'object' && !Array.isArray(result) ? result as JsonObject : {};
      const messages = Array.isArray(resultObj.messages) ? resultObj.messages : [];
      for (const msg of messages) {
        await this.storeInboxItem(this.normalizeMessage(msg, true));
      }
      sendJson(res, 200, { ok: true, result: jsonSafe(result) as any });
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
    const params: RpcParams = {
      name,
      visibility: textOf(body.visibility || 'private'),
    };
    const joinMode = textOf(body.join_mode || '').trim();
    if (joinMode) params.join_mode = joinMode;
    try {
      const createResult = await this.client.call('group.create', params);
      const groupId = this.extractGroupId(createResult);
      if (!groupId) throw new Error(`group.create did not return group_id: ${JSON.stringify(jsonSafe(createResult))}`);
      const addResults: unknown[] = [];
      for (const aid of members) {
        if (!aid || aid === this.aid) continue;
        const addResult = await this.client.call('group.add_member', {
          group_id: groupId,
          aid,
          role: 'member',
        });
        addResults.push(jsonSafe(addResult));
      }
      const response: JsonObject = {
        ok: true,
        trace_id: traceId,
        group_id: groupId,
        create_result: jsonSafe(createResult) as any,
        add_results: addResults as any,
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
    const expected = textOf(url.searchParams.get('members') ?? this.aid)
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean);
    const requireDevices = envBool('CROSS_SDK_GROUP_READY_REQUIRE_DEVICES', true);
    if (!groupId) {
      sendJson(res, 400, { ok: false, ready: false, error_code: 'bad_request', error_message: 'group_id is required' });
      return;
    }
    try {
      const bootstrap = await this.client.call('group.v2.bootstrap', { group_id: groupId }) as JsonObject;
      const committedRaw = Array.isArray(bootstrap.committed_member_aids)
        ? bootstrap.committed_member_aids
        : (Array.isArray(bootstrap.member_aids) ? bootstrap.member_aids : []);
      const committed = new Set(committedRaw.map((item) => textOf(item)));
      const devices = Array.isArray(bootstrap.devices) ? bootstrap.devices : [];
      const deviceAids = new Set(devices
        .filter((item) => item && typeof item === 'object' && !Array.isArray(item))
        .map((item) => textOf((item as JsonObject).aid)));
      const membershipOk = expected.every((aid) => committed.has(aid));
      const devicesOk = !requireDevices || expected.every((aid) => deviceAids.has(aid));
      sendJson(res, 200, {
        ok: true,
        ready: membershipOk && devicesOk,
        group_id: groupId,
        expected,
        committed_member_aids: [...committed].sort(),
        device_aids: [...deviceAids].sort(),
        pending_adds: Array.isArray(bootstrap.pending_adds) ? bootstrap.pending_adds : [],
        bootstrap: jsonSafe(bootstrap) as any,
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
    const payload: JsonObject = {
      type: 'text',
      text,
      trace_id: traceId,
      case_id: textOf(body.case_id || traceId),
    };
    try {
      const result = await this.client.call('group.send', {
        group_id: groupId,
        payload,
        encrypt: e2ee,
        message_id: messageId,
      });
      const resultObj = result && typeof result === 'object' && !Array.isArray(result) ? result as JsonObject : {};
      const response: JsonObject = {
        ok: true,
        trace_id: traceId,
        group_id: groupId,
        message_id: messageId,
        seq: Number(resultObj.seq ?? resultObj.message_seq ?? 0) || 0,
        encrypted: e2ee,
        result: jsonSafe(result) as any,
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
    const resultObj = result && typeof result === 'object' && !Array.isArray(result) ? result as JsonObject : {};
    const messages = Array.isArray(resultObj.messages) ? resultObj.messages : [];
    for (const msg of messages) {
      await this.storeGroupInboxItem(this.normalizeGroupMessage(msg, true));
    }
    sendJson(res, 200, { ok: true, group_id: groupId, result: jsonSafe(result) as any });
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
      sendJson(res, 200, { ok: true, group_id: groupId, seq, result: jsonSafe(result) as any });
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

  extractGroupId(result: unknown): string {
    if (!result || typeof result !== 'object' || Array.isArray(result)) return '';
    const obj = result as JsonObject;
    if (obj.group_id) return textOf(obj.group_id);
    const group = obj.group;
    if (group && typeof group === 'object' && !Array.isArray(group) && (group as JsonObject).group_id) {
      return textOf((group as JsonObject).group_id);
    }
    const member = obj.member;
    if (member && typeof member === 'object' && !Array.isArray(member) && (member as JsonObject).group_id) {
      return textOf((member as JsonObject).group_id);
    }
    return '';
  }
}

async function main(): Promise<void> {
  const agent = new CrossSdkTsAgent();
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
    console.log(`cross-sdk ts agent listening on ${host}:${port}`);
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
