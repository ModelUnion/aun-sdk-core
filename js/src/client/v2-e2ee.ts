import { importCertPublicKeyEcdsa } from '../crypto.js';
import { E2EEError, StateError, ValidationError } from '../errors.js';
import { normalizeGroupId } from '../group-id.js';
import {
  decryptMessage,
  encryptGroupMessage,
  encryptP2PMessage,
  type StateCommitmentAAD,
  type Target,
} from '../v2/e2ee/index.js';
import { V2Session, V2KeyStore } from '../v2/session/index.js';
import { isJsonObject, type JsonObject, type JsonValue, type RpcParams, type RpcResult } from '../types.js';
import type { ClientHost, ClientRuntime } from './runtime.js';

type BootstrapEntry = Record<string, any> & { cachedAt?: number };

interface V2WrapPolicy {
  protocol?: '1DH' | '3DH';
  scope?: 'aid' | 'device';
}

const V2_BOOTSTRAP_TTL_MS = 60 * 60 * 1000;
const V2_RETRYABLE_CODES = new Set([-33011, -33012, -33050, -33052, -33054]);

const MEMBERSHIP_ACTIONS = new Set([
  'member_added',
  'member_left',
  'member_removed',
  'role_changed',
  'owner_transferred',
  'joined',
  'join_approved',
  'invite_code_used',
]);

const JOIN_ACTIONS = new Set(['member_added', 'joined', 'join_approved', 'invite_code_used']);

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

async function pubDerMatchesFingerprint(pubDer: Uint8Array, certFingerprint?: string): Promise<boolean> {
  const expected = String(certFingerprint ?? '').trim().toLowerCase();
  if (!expected) return true;
  if (!expected.startsWith('sha256:')) return false;
  const expectedHex = expected.slice('sha256:'.length);
  if (![16, 64].includes(expectedHex.length) || !/^[0-9a-f]+$/.test(expectedHex)) return false;
  const digest = await crypto.subtle.digest('SHA-256', exactArrayBuffer(pubDer));
  const spkiHex = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
  return expectedHex.length === 16 ? spkiHex.slice(0, 16) === expectedHex : spkiHex === expectedHex;
}

function v2LeftPad32(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 32) return bytes;
  if (bytes.length > 32) return bytes.subarray(bytes.length - 32);
  const out = new Uint8Array(32);
  out.set(bytes, 32 - bytes.length);
  return out;
}

function v2B64ToBytes(value: string): Uint8Array {
  const bin = atob(value);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function v2B64uToBytes(value: string): Uint8Array {
  const std = String(value ?? '').replace(/-/g, '+').replace(/_/g, '/');
  const pad = std.length % 4 === 0 ? '' : '='.repeat(4 - (std.length % 4));
  return v2B64ToBytes(std + pad);
}

function formatE2EEError(error: unknown): Error | string {
  return error instanceof Error ? error : String(error);
}

function uuidV4(): string {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function truthyBool(value: unknown): boolean {
  if (value === true || value === 1) return true;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    return normalized === 'true' || normalized === '1' || normalized === 'yes' || normalized === 'on';
  }
  return false;
}

function metadataWithoutAuth(value: unknown): Record<string, unknown> | null {
  if (!isJsonObject(value as JsonValue | object | null | undefined)) return null;
  const body: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (key !== '_auth') body[key] = item;
  }
  return body;
}

function v2E2eeMeta(envelope: Record<string, unknown>): Record<string, unknown> {
  const suite = String(envelope.suite ?? '');
  const meta: Record<string, unknown> = {
    version: 'v2',
    suite,
    encryption_mode: `v2_${suite || 'unknown'}`,
    forward_secrecy: true,
  };
  const protectedHeaders = metadataWithoutAuth(envelope.protected_headers);
  if (protectedHeaders && Object.keys(protectedHeaders).length > 0) {
    meta.protected_headers = protectedHeaders;
  }
  const payloadType = String(envelope.payload_type ?? protectedHeaders?.payload_type ?? '').trim();
  if (payloadType) {
    meta.payload_type = payloadType;
  }
  const context = metadataWithoutAuth(envelope.context);
  if (context && Object.keys(context).length > 0) {
    meta.context = context;
  }
  const agentMd = metadataWithoutAuth(envelope.agent_md);
  if (agentMd && Object.keys(agentMd).length > 0) {
    meta.agent_md = agentMd;
  }
  return meta;
}

function attachV2EnvelopeMetadata(message: Record<string, unknown>, meta: Record<string, unknown> | null | undefined): void {
  if (!meta) return;
  const payloadType = typeof meta.payload_type === 'string' ? meta.payload_type.trim() : '';
  if (payloadType) message.payload_type = payloadType;
  if (isJsonObject(meta.protected_headers as JsonValue | object | null | undefined)) {
    message.protected_headers = { ...(meta.protected_headers as Record<string, unknown>) };
  }
  if (isJsonObject(meta.agent_md as JsonValue | object | null | undefined)) {
    message.agent_md = { ...(meta.agent_md as Record<string, unknown>) };
  }
}

function attachGatewayProximity(message: Record<string, unknown>, source: Record<string, unknown>): void {
  if (isJsonObject(source.proximity as JsonValue | object | null | undefined)) {
    message.proximity = { ...(source.proximity as Record<string, unknown>) };
  }
  for (const key of ['same_device', 'same_network', 'same_egress_ip'] as const) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      message[key] = source[key];
    }
  }
}

function getV2DeviceId(dev: Record<string, unknown>): { present: boolean; value: string } {
  if (Object.prototype.hasOwnProperty.call(dev, 'device_id')) {
    return { present: true, value: String(dev.device_id ?? '').trim() };
  }
  if (Object.prototype.hasOwnProperty.call(dev, 'owner_device_id')) {
    return { present: true, value: String(dev.owner_device_id ?? '').trim() };
  }
  return { present: false, value: '' };
}

function normalizeV2WrapPolicy(raw: unknown): V2WrapPolicy | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const obj = raw as Record<string, unknown>;
  let protocol = String(obj.protocol ?? '').trim().toUpperCase();
  let scope = String(obj.scope ?? '').trim().toLowerCase();
  if (scope !== 'aid' && scope !== 'device') {
    if (obj.per_aid_wrap === true) scope = 'aid';
    else if (obj.per_device_wrap === true) scope = 'device';
    else scope = '';
  }
  if (protocol !== '1DH' && protocol !== '3DH') protocol = '';
  if (scope === 'aid') protocol = '1DH';
  if (!protocol && !scope) return undefined;
  return {
    protocol: protocol ? protocol as '1DH' | '3DH' : undefined,
    scope: scope ? scope as 'aid' | 'device' : undefined,
  };
}

function v2WrapCapabilities(): Record<string, unknown> {
  return {
    version: 'v2.1',
    protocols: ['1DH', '3DH'],
    scopes: ['aid', 'device'],
    per_aid_wrap: true,
    per_device_wrap: true,
  };
}

function applyV2WrapPolicyToTargets(targets: Target[], policy?: V2WrapPolicy): Target[] {
  if (!policy) return targets;
  const normalized = targets.map((target) => {
    const row: Target = { ...target };
    if (policy.protocol === '1DH') {
      row.keySource = 'aid_master';
      row.spkPkDer = undefined;
      row.spkId = '';
    }
    return row;
  });
  if (policy.scope !== 'aid') return normalized;
  const collapsed = new Map<string, Target>();
  for (const target of normalized) {
    const key = `${target.aid}\u0000${target.role}`;
    if (!collapsed.has(key)) {
      collapsed.set(key, { ...target, deviceId: '' });
    }
  }
  return Array.from(collapsed.values());
}

export class V2E2EECoordinator {
  private readonly runtime: ClientRuntime;

  constructor(runtime: ClientRuntime) {
    this.runtime = runtime;
  }

  private get client(): ClientHost {
    return this.runtime.client;
  }

  private get bootstrapCache(): Map<string, BootstrapEntry> {
    const client = this.client;
    if (!(client._v2BootstrapCache instanceof Map)) {
      this.runtime.v2.setBootstrapCache(new Map<string, BootstrapEntry>());
    }
    return client._v2BootstrapCache as Map<string, BootstrapEntry>;
  }

  getBootstrapCacheEntry<T extends BootstrapEntry = BootstrapEntry>(key: string): T | undefined {
    return this.bootstrapCache.get(key) as T | undefined;
  }

  setBootstrapCacheEntry(key: string, entry: BootstrapEntry): void {
    this.bootstrapCache.set(key, entry);
  }

  deleteBootstrapCacheEntry(key: string): void {
    this.bootstrapCache.delete(key);
  }

  clearBootstrapCache(): void {
    this.bootstrapCache.clear();
  }

  pruneExpiredBootstrapCache(ttlMs: number, now = Date.now()): void {
    for (const [key, entry] of this.bootstrapCache) {
      if (now - Number(entry.cachedAt ?? 0) >= ttlMs) {
        this.bootstrapCache.delete(key);
      }
    }
  }

  async onConnected(opts: { backgroundSync: boolean }): Promise<void> {
    const client = this.client;
    try {
      await client._initV2Session();
    } catch (exc) {
      client._clientLog.warn(`V2 session init failed (non-fatal): ${formatE2EEError(exc)}`);
    }
    if (opts.backgroundSync && client._v2Session && typeof client._v2AutoConfirmPendingProposals === 'function') {
      client._safeAsync(client._v2AutoConfirmPendingProposals());
    }
  }

  async initV2Session(): Promise<void> {
    const client = this.client;
    if (!client._aid) return;
    const aidAtStart = client._aid;
    const deviceIdAtStart = client._deviceId;
    const currentAid = client._currentAid;
    const generationAtStart = Number(client._v2RuntimeGeneration ?? 0);
    const existing = client._v2Session;
    if (existing && existing.aid === aidAtStart && existing.deviceId === deviceIdAtStart) {
      return;
    }
    if (existing) {
      this.clearBootstrapCache();
    }

    const identityChanged = (): boolean =>
      client._aid !== aidAtStart
      || client._deviceId !== deviceIdAtStart
      || client._currentAid !== currentAid
      || Number(client._v2RuntimeGeneration ?? 0) !== generationAtStart;

    if (!currentAid?.privateKeyPem) {
      client._clientLog.warn('V2 session init skipped: no AID private key');
      return;
    }

    const pem = currentAid.privateKeyPem.trim();
    const pemBody = pem
      .replace(/-----BEGIN [^-]+-----/g, '')
      .replace(/-----END [^-]+-----/g, '')
      .replace(/\s+/g, '');
    const pkcs8Der = v2B64ToBytes(pemBody);

    const privKey = await crypto.subtle.importKey(
      'pkcs8',
      exactArrayBuffer(pkcs8Der),
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    );
    if (identityChanged()) return;
    const jwk = await crypto.subtle.exportKey('jwk', privKey) as JsonWebKey;
    if (identityChanged()) return;
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
      throw new Error('AID private key must be EC P-256');
    }
    if (!jwk.d || !jwk.x || !jwk.y) {
      throw new Error('AID private key jwk missing d/x/y');
    }
    const aidPriv = v2LeftPad32(v2B64uToBytes(jwk.d));

    const pubKey = await crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true },
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify'],
    );
    const aidPubDer = new Uint8Array(await crypto.subtle.exportKey('spki', pubKey));
    if (identityChanged()) return;

    let keyStore = client._v2KeyStore as V2KeyStore | undefined;
    const openedKeyStore = !keyStore;
    if (!keyStore) {
      keyStore = await V2KeyStore.open();
    }
    if (identityChanged()) {
      if (openedKeyStore) keyStore.close();
      return;
    }

    const session = new V2Session(
      keyStore,
      deviceIdAtStart,
      aidAtStart,
      aidPriv,
      aidPubDer,
    );

    await session.ensureRegistered(client._v2CallFn());
    if (identityChanged()) {
      if (openedKeyStore) keyStore.close();
      return;
    }
    this.runtime.v2.setSessionState(keyStore, session);
    client._clientLog.debug(`V2 session initialized aid=${aidAtStart} device=${deviceIdAtStart}`);
  }

  scheduleGroupSpkRegistration(groupId: string, opts: { reason: string }): void {
    const client = this.client;
    const gid = String(groupId ?? '').trim();
    if (!gid || !client._v2Session) return;
    const inflight = this.runtime.v2.groupSpkRegistrationInflight;
    if (inflight.has(gid)) return;
    inflight.add(gid);
    client._safeAsync((async () => {
      try {
        await client._v2Session.ensureGroupRegistered?.(gid, client._v2CallFn());
        client._clientLog.debug(`group SPK registered: group=${gid} reason=${opts.reason}`);
      } catch (exc) {
        client._clientLog.debug(`group SPK registration failed (non-fatal): group=${gid} reason=${opts.reason} err=${formatE2EEError(exc)}`);
      } finally {
        inflight.delete(gid);
      }
    })());
  }

  scheduleGroupSpkRotation(groupId: string, opts: { reason: string }): void {
    const client = this.client;
    const gid = String(groupId ?? '').trim();
    if (!gid || !client._v2Session) return;
    const inflight = this.runtime.v2.groupSpkRotationInflight;
    if (inflight.has(gid)) return;
    inflight.add(gid);
    client._safeAsync((async () => {
      try {
        await client._v2Session.rotateGroupSPK?.(gid, client._v2CallFn());
        client._clientLog.debug(`group SPK rotated: group=${gid} reason=${opts.reason}`);
      } catch (exc) {
        client._clientLog.debug(`group SPK rotation failed (non-fatal): group=${gid} reason=${opts.reason} err=${formatE2EEError(exc)}`);
      } finally {
        inflight.delete(gid);
      }
    })());
  }

  scheduleGroupSpkRegistrationAfterPeerFallback(groupId: string): void {
    const client = this.client;
    const gid = String(groupId ?? '').trim();
    if (!gid) return;
    const registered = this.runtime.v2.groupSpkPeerFallbackRegistered;
    if (registered.has(gid)) return;
    registered.add(gid);
    this.scheduleGroupSpkRegistration(gid, { reason: 'peer_device_prekey_fallback' });
  }

  async getV2SenderPubDer(fromAid: string, senderDeviceId: string, certFingerprint?: string): Promise<Uint8Array | null> {
    const client = this.client;
    const session = client._v2Session;
    if (!session || !fromAid) return null;
    let senderPubDer: Uint8Array | null = session.getPeerIK(fromAid, senderDeviceId);
    if (senderPubDer && await pubDerMatchesFingerprint(senderPubDer, certFingerprint)) return senderPubDer;

    try {
      const normalizedFp = String(certFingerprint ?? '').trim() || undefined;
      const certPem = await client._fetchPeerCert(fromAid, normalizedFp, 3000);
      const pubKey = await importCertPublicKeyEcdsa(certPem);
      senderPubDer = new Uint8Array(await crypto.subtle.exportKey('spki', pubKey));
      if (!await pubDerMatchesFingerprint(senderPubDer, certFingerprint)) return null;
      session.cachePeerIK(fromAid, senderDeviceId, senderPubDer);
      client._clientLog.debug(`V2 decrypt: sender IK fallback from PKI cert for ${fromAid}`);
      return senderPubDer;
    } catch (exc) {
      client._clientLog.warn(`V2 decrypt: PKI cert sender IK fallback failed for ${fromAid}: ${String(formatE2EEError(exc))}`);
      return null;
    }
  }

  pendingSenderIKMessageKey(msg: Record<string, unknown>, groupId: string): string {
    const client = this.client;
    const messageId = String(msg.message_id ?? '').trim();
    const seq = String(msg.seq ?? '').trim();
    const prefix = groupId ? `group:${groupId}` : `p2p:${client._aid ?? ''}`;
    return `${prefix}:${messageId || seq || Math.random().toString(36).slice(2)}`;
  }

  pendingSenderIKFetchKey(fromAid: string, senderDeviceId: string, groupId: string): string {
    return `${fromAid}#${senderDeviceId}#${groupId || ''}`;
  }

  scheduleSenderIKPending(args: {
    msg: Record<string, unknown>;
    fromAid: string;
    senderDeviceId: string;
    groupId: string;
  }): void {
    const client = this.client;
    const fromAid = String(args.fromAid ?? '').trim();
    if (!fromAid) return;
    const senderDeviceId = String(args.senderDeviceId ?? '');
    const groupId = String(args.groupId ?? '').trim();
    const messageKey = this.pendingSenderIKMessageKey(args.msg, groupId);
    client._v2SenderIKPending.set(messageKey, {
      msg: { ...args.msg },
      fromAid,
      senderDeviceId,
      groupId,
      createdAt: Date.now(),
    });
    client._clientLog.debug(`V2 decrypt pending sender IK: key=${messageKey} from=${fromAid} device=${senderDeviceId || '-'} group=${groupId || '<p2p>'} pending=${client._v2SenderIKPending.size}`);
    this.scheduleSenderIKFetch(fromAid, senderDeviceId, groupId);
  }

  scheduleSenderIKFetch(fromAid: string, senderDeviceId: string, groupId: string): void {
    const client = this.client;
    const fetchKey = this.pendingSenderIKFetchKey(fromAid, senderDeviceId, groupId);
    if (!fromAid || client._v2SenderIKFetching.has(fetchKey)) return;
    client._v2SenderIKFetching.add(fetchKey);
    client._safeAsync(this.resolveSenderIKPending(fromAid, senderDeviceId, groupId, fetchKey));
  }

  async resolveSenderIKPending(fromAid: string, senderDeviceId: string, groupId: string, fetchKey: string): Promise<void> {
    const client = this.client;
    try {
      const session = client._v2Session;
      if (session && fromAid) {
        try {
          const bs = await client.call('message.v2.bootstrap', {
            peer_aid: fromAid,
            e2ee_wrap_capabilities: v2WrapCapabilities(),
          }) as Record<string, unknown>;
          const peers = (Array.isArray(bs?.peer_devices) ? bs.peer_devices : []) as Array<Record<string, unknown>>;
          for (const dev of peers) client._cacheV2PeerIKFromDevice(dev, fromAid);
        } catch (exc) {
          client._clientLog.warn(`V2 sender IK pending bootstrap failed peer=${fromAid}: ${String(formatE2EEError(exc))}`);
        }
        if (groupId) {
          try {
            const gbs = await client.call('group.v2.bootstrap', {
              group_id: groupId,
              e2ee_wrap_capabilities: v2WrapCapabilities(),
            }) as Record<string, unknown>;
            const devices = (Array.isArray(gbs?.devices) ? gbs.devices : []) as Array<Record<string, unknown>>;
            const audit = (Array.isArray(gbs?.audit_recipients) ? gbs.audit_recipients : []) as Array<Record<string, unknown>>;
            for (const dev of devices) client._cacheV2PeerIKFromDevice(dev);
            for (const dev of audit) client._cacheV2PeerIKFromDevice(dev);
          } catch (exc) {
            client._clientLog.warn(`V2 sender IK pending group bootstrap failed group=${groupId}: ${String(formatE2EEError(exc))}`);
          }
        }
        if (!session.getPeerIK(fromAid, senderDeviceId)) {
          await this.getV2SenderPubDer(fromAid, senderDeviceId);
        }
      }

      const pendingItems = [...client._v2SenderIKPending.entries()].filter(([, entry]: [string, any]) =>
        entry.fromAid === fromAid && entry.senderDeviceId === senderDeviceId && entry.groupId === groupId);
      for (const [key, entry] of pendingItems) {
        let plaintext: Record<string, unknown> | null = null;
        try {
          plaintext = await client._decryptV2Message(entry.msg, false);
        } catch (exc) {
          client._clientLog.warn(`V2 sender IK pending retry raised: key=${key} err=${String(formatE2EEError(exc))}`);
        }
        client._v2SenderIKPending.delete(key);
        if (plaintext === null) {
          client._clientLog.debug(`V2 sender IK pending retry failed: key=${key}`);
          continue;
        }
        const seq = Number(entry.msg.seq ?? 0);
        if (entry.groupId) {
          plaintext.group_id = entry.groupId;
          await client._publishPulledMessage('group.message_created', `group:${entry.groupId}`, seq, plaintext);
        } else {
          await client._publishPulledMessage('message.received', `p2p:${client._aid ?? ''}`, seq, plaintext);
        }
        client._clientLog.debug(`V2 sender IK pending retry delivered: key=${key}`);
      }
    } finally {
      client._v2SenderIKFetching.delete(fetchKey);
    }
  }

  async sendV2(
    to: string,
    payload: Record<string, unknown>,
    opts?: { messageId?: string; timestamp?: number; protectedHeaders?: Record<string, unknown>; context?: Record<string, unknown> },
  ): Promise<unknown> {
    const client = this.client;
    await client._ensureV2SessionReady(
      'message.send',
      'V2 session not initialized; encrypted message.send requires V2 (V1 E2EE removed)',
    );
    const toAid = String(to ?? '').trim();
    if (!toAid) throw new ValidationError("message.send requires 'to'");
    if (!isJsonObject(payload)) throw new ValidationError('message.send payload must be a dict for V2 encryption');

    const attempt = async (useCache: boolean): Promise<unknown> => {
      const envelope = await client._buildV2P2PEnvelope({
        to: toAid,
        payload,
        messageId: opts?.messageId,
        timestamp: opts?.timestamp,
        protectedHeaders: opts?.protectedHeaders,
        context: opts?.context,
        useCache,
      });
      return client.call('message.send', {
        to: toAid,
        payload: envelope,
        encrypt: false,
      });
    };

    try {
      return await attempt(true);
    } catch (exc) {
      const excCode = (exc as any)?.code;
      if (V2_RETRYABLE_CODES.has(excCode)) {
        client._clientLog.debug(`V2 P2P speculative send rejected (code=${excCode}), refreshing bootstrap`);
        this.deleteBootstrapCacheEntry(toAid);
        return attempt(false);
      }
      throw exc;
    }
  }

  async pullV2(afterSeq = 0, limit = 50, opts?: { force?: boolean }): Promise<unknown[]> {
    const client = this.client;
    await client._ensureV2SessionReady('message.pull');
    const ns = client._aid ? `p2p:${client._aid}` : '';
    const decrypted: unknown[] = [];
    let nextAfterSeq = opts?.force ? afterSeq : (afterSeq || (ns ? client._seqTracker.getContiguousSeq(ns) : 0));
    let pageCount = 0;
    const maxPages = 100;

    while (pageCount < maxPages) {
      pageCount += 1;
      const result = await client._callRawV2Rpc('message.v2.pull', {
        after_seq: nextAfterSeq,
        limit,
        ...(opts?.force ? { force: true } : {}),
      }) as Record<string, unknown>;
      const messages = (Array.isArray(result?.messages) ? result.messages : []) as Array<Record<string, unknown>>;
      const seqs = messages
        .map((msg) => Number(msg.seq ?? 0))
        .filter((seq) => Number.isFinite(seq) && seq > 0);
      const pageContigBefore = ns ? client._seqTracker.getContiguousSeq(ns) : 0;
      const pageMaxSeq = seqs.length > 0 ? Math.max(...seqs) : nextAfterSeq;
      if (ns && seqs.length > 0) {
        client._seqTracker.forceContiguousSeq(ns, pageMaxSeq);
      }

      for (const msg of messages) {
        const seq = Number(msg.seq ?? 0);
        if (!Number.isFinite(seq) || seq <= 0) continue;

        const version = String(msg.version ?? 'v2');
        if (version === 'v1') {
          const legacy = isJsonObject(msg.legacy_v1 as JsonValue | object | null | undefined) ? msg.legacy_v1 as Record<string, unknown> : {};
          const legacyPayload = legacy.payload;
          const payloadType = isJsonObject(legacyPayload as JsonValue | object | null | undefined)
            ? String((legacyPayload as Record<string, unknown>).type ?? '').trim()
            : '';
          if (legacyPayload !== undefined && legacyPayload !== null
            && payloadType !== 'e2ee.encrypted' && payloadType !== 'e2ee.group_encrypted') {
            const v1Msg: Record<string, unknown> = {
              message_id: String(msg.message_id ?? ''),
              from: String(msg.from_aid ?? ''),
              to: String(legacy.to ?? client._aid ?? ''),
              seq: msg.seq,
              type: String(msg.type ?? ''),
              timestamp: msg.t_server,
              payload: legacyPayload,
              encrypted: false,
            };
            attachGatewayProximity(v1Msg, msg);
            const appEvent = client._delivery.p2pAppEventForMessage(v1Msg);
            if (ns) await client._publishPulledMessage(appEvent.event, ns, seq, appEvent.payload);
            else await client._publishAppEvent(appEvent.event, appEvent.payload);
            decrypted.push(v1Msg);
          } else {
            client._clientLog.debug(`message.v2.pull skipping V1 envelope seq=${seq} payload_type=${payloadType || '<none>'} (V1 E2EE removed)`);
          }
          continue;
        }

        if (version !== 'v2') {
          client._clientLog.debug(`message.v2.pull skipping non-V2 row seq=${seq} version=${String(msg.version ?? '')}`);
          continue;
        }

        const msgSpkId = String(msg.spk_id ?? '');
        if (msgSpkId && client._v2Session && !client._v2Session.isCurrentSPK(msgSpkId)) {
          client._v2Session.trackOldSPKMaxSeq(msgSpkId, seq);
        }
        const plaintext = await client._decryptV2Message(msg);
        if (plaintext === null) continue;
        if (ns) {
          await client._publishPulledMessage('message.received', ns, seq, plaintext);
          decrypted.push(plaintext);
        } else {
          await client._publishAppEvent('message.received', plaintext);
          decrypted.push(plaintext);
        }
      }

      const hasServerAckSeq = Object.prototype.hasOwnProperty.call(result, 'server_ack_seq');
      const serverAckSeq = Number(result.server_ack_seq ?? 0);
      if (ns && Number.isFinite(serverAckSeq) && serverAckSeq > 0) {
        const contig = client._seqTracker.getContiguousSeq(ns);
        if (contig < serverAckSeq) {
          client._clientLog.info(`message.v2.pull retention-floor advance: ns=${ns} contiguous=${contig} -> server_ack_seq=${serverAckSeq}`);
          client._seqTracker.forceContiguousSeq(ns, serverAckSeq);
        }
      }

      if (ns) {
        const ackSeq = client._seqTracker.getContiguousSeq(ns);
        const contigAdvanced = ackSeq !== pageContigBefore;
        if (contigAdvanced) {
          await client._drainOrderedMessages(ns);
          client._saveSeqTrackerState();
        }
        const ackNeeded = messages.length > 0
          && ackSeq > 0
          && (contigAdvanced || (hasServerAckSeq && ackSeq > serverAckSeq));
        if (ackNeeded) {
          await this.ackV2(ackSeq);
        }
      }

      const nextAfter = Math.max(pageMaxSeq, nextAfterSeq);
      if (messages.length === 0 || nextAfter <= nextAfterSeq || result.has_more === false) break;
      nextAfterSeq = nextAfter;
    }

    if (pageCount >= maxPages) {
      client._clientLog.warn(`message.v2.pull reached max_pages=${maxPages} after_seq=${nextAfterSeq}`);
    }
    return decrypted;
  }

  async ackV2(upToSeq?: number): Promise<unknown> {
    const client = this.client;
    const ns = client._aid ? `p2p:${client._aid}` : '';
    let seq = upToSeq ?? (ns ? client._seqTracker.getContiguousSeq(ns) : 0);
    if (seq <= 0) return { acked: 0 };
    seq = client._clampAckSeq('message.v2.ack', 'up_to_seq', ns, seq);
    const raw = await client._callRawV2Rpc('message.v2.ack', { up_to_seq: seq });
    const result: Record<string, unknown> = isJsonObject(raw as JsonValue | object | null | undefined)
      ? { ...(raw as Record<string, unknown>) }
      : { result: raw };
    let actualAckSeq = seq;
    if ('effective_ack_seq' in result) actualAckSeq = Number(result.effective_ack_seq ?? 0);
    else if ('ack_seq' in result) actualAckSeq = Number(result.ack_seq ?? 0);
    else if ('cursor' in result) actualAckSeq = Number(result.cursor ?? 0);
    if (!Number.isFinite(actualAckSeq)) actualAckSeq = seq;
    result.ack_seq = actualAckSeq;
    result.success = true;
    if (Number(result.acked ?? 0) === 0) result.acked = actualAckSeq;
    if (client._v2Session) {
      try {
        const destroyed = await client._v2Session.maybeDestroyOldSPKs(actualAckSeq);
        if (destroyed.length > 0) {
          client._clientLog.info(`V2 destroyed old SPKs after ack: ${destroyed.slice(0, 3)} (PFS)`);
        }
      } catch (exc) {
        client._clientLog.debug(`V2 SPK destroy failed (non-fatal): ${String(exc)}`);
      }
    }
    return result;
  }

  async sendGroupV2(
    groupId: string,
    payload: Record<string, unknown>,
    opts?: { messageId?: string; timestamp?: number; protectedHeaders?: Record<string, unknown>; context?: Record<string, unknown> },
  ): Promise<unknown> {
    const client = this.client;
    await client._ensureV2SessionReady(
      'group.send',
      'V2 session not initialized; encrypted group.send requires V2 (V1 E2EE removed)',
    );
    const gid = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!gid) throw new ValidationError("group.send requires 'group_id'");
    if (!isJsonObject(payload)) throw new ValidationError('group.send payload must be a dict for V2 encryption');

    const attempt = async (useCache: boolean): Promise<unknown> => {
      const envelope = await client._buildV2GroupEnvelope({
        groupId: gid,
        payload,
        messageId: opts?.messageId,
        timestamp: opts?.timestamp,
        protectedHeaders: opts?.protectedHeaders,
        context: opts?.context,
        useCache,
      });
      return client.call('group.v2.send', {
        group_id: gid,
        envelope,
      });
    };

    try {
      const result = await attempt(true);
      if (isJsonObject(result as JsonValue | object | null | undefined)) {
        const seq = Number((result as Record<string, unknown>).seq ?? 0);
        if (seq > 0) {
          const ns = `group:${gid}`;
          client._seqTracker.onMessageSeq(ns, seq);
          client._markPublishedSeq(ns, seq);
          client._saveSeqTrackerState();
        }
      }
      return result;
    } catch (exc) {
      const excCode = (exc as any)?.code;
      if (V2_RETRYABLE_CODES.has(excCode)) {
        client._clientLog.debug(`V2 group speculative send rejected (code=${excCode}), refreshing bootstrap`);
        this.deleteBootstrapCacheEntry(`group:${gid}`);
        const result = await attempt(false);
        if (isJsonObject(result as JsonValue | object | null | undefined)) {
          const seq = Number((result as Record<string, unknown>).seq ?? 0);
          if (seq > 0) {
            const ns = `group:${gid}`;
            client._seqTracker.onMessageSeq(ns, seq);
            client._markPublishedSeq(ns, seq);
            client._saveSeqTrackerState();
          }
        }
        return result;
      }
      throw exc;
    }
  }

  async pullGroupV2Internal(params: { group_id: string; after_seq: number; limit: number }): Promise<void> {
    await this.pullGroupV2(params.group_id, params.after_seq, params.limit);
  }

  async pullGroupV2(
    groupId: string,
    afterSeq = 0,
    limit = 50,
    opts?: { explicitAfterSeq?: boolean; cursorParams?: Record<string, unknown>; ownsCursor?: boolean },
  ): Promise<unknown[]> {
    const client = this.client;
    await client._ensureV2SessionReady('group.pull');
    const gid = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!gid) throw new ValidationError('group.pull requires group_id');
    const ns = `group:${gid}`;
    const decrypted: unknown[] = [];
    const cursorParams = opts?.cursorParams ?? {};
    const ownsCursor = opts?.ownsCursor !== false;
    let nextAfterSeq = opts?.explicitAfterSeq ? afterSeq : (afterSeq || client._seqTracker.getContiguousSeq(ns));
    let pageCount = 0;
    const maxPages = 100;

    while (pageCount < maxPages) {
      pageCount += 1;
      const result = await client._callRawV2Rpc('group.v2.pull', {
        group_id: gid,
        after_seq: nextAfterSeq,
        limit,
        ...cursorParams,
      }) as Record<string, unknown>;
      const messages = (Array.isArray(result?.messages) ? result.messages : []) as Array<Record<string, unknown>>;
      const seqs = messages
        .map((msg) => Number(msg.seq ?? 0))
        .filter((seq) => Number.isFinite(seq) && seq > 0);
      const pageContigBefore = client._seqTracker.getContiguousSeq(ns);
      const pageMaxSeq = seqs.length > 0 ? Math.max(...seqs) : nextAfterSeq;
      if (seqs.length > 0) {
        client._seqTracker.forceContiguousSeq(ns, pageMaxSeq);
      }

      for (const msg of messages) {
        const seq = Number(msg.seq ?? 0);
        if (!Number.isFinite(seq) || seq <= 0) continue;

        const version = String(msg.version ?? 'v2');
        if (version === 'v1') {
          const payload = msg.payload;
          const payloadObj = isJsonObject(payload as JsonValue | object | null | undefined) ? payload as Record<string, unknown> : null;
          if (payloadObj) {
            const payloadType = String(payloadObj.type ?? '').trim();
            if (payloadType !== 'e2ee.encrypted' && payloadType !== 'e2ee.group_encrypted') {
              const v1Msg: Record<string, unknown> = {
                message_id: String(msg.message_id ?? ''),
                from: String(msg.from_aid ?? ''),
                group_id: gid,
                seq: msg.seq,
                type: String(msg.type ?? ''),
                timestamp: msg.t_server,
                payload,
                encrypted: false,
              };
              attachGatewayProximity(v1Msg, msg);
              await client._publishPulledMessage('group.message_created', ns, seq, v1Msg);
              decrypted.push(v1Msg);
              continue;
            }
          } else if (payload !== undefined && payload !== null) {
            const v1Msg: Record<string, unknown> = {
              message_id: String(msg.message_id ?? ''),
              from: String(msg.from_aid ?? ''),
              group_id: gid,
              seq: msg.seq,
              type: String(msg.type ?? ''),
              timestamp: msg.t_server,
              payload,
              encrypted: false,
            };
            attachGatewayProximity(v1Msg, msg);
            await client._publishPulledMessage('group.message_created', ns, seq, v1Msg);
            decrypted.push(v1Msg);
            continue;
          }
          client._clientLog.debug(`group.v2.pull skipping V1 envelope group=${gid} seq=${seq} payload_type=${payloadObj ? String(payloadObj.type ?? '') : '<none>'} (V1 E2EE removed)`);
          continue;
        }

        if (version !== 'v2') {
          client._clientLog.debug(`group.v2.pull skipping non-V2 row group=${gid} seq=${seq} version=${String(msg.version ?? '')}`);
          continue;
        }

        const plaintext = await client._decryptV2Message(msg);
        if (plaintext === null) continue;
        plaintext.group_id = gid;
        await client._publishPulledMessage('group.message_created', ns, seq, plaintext);
        decrypted.push(plaintext);
      }

      const cursor = isJsonObject(result.cursor as JsonValue | object | null | undefined) ? result.cursor as Record<string, unknown> : null;
      const cursorCurrentSeq = Number(cursor?.current_seq ?? 0);
      if (Number.isFinite(cursorCurrentSeq) && cursorCurrentSeq > 0) {
        const contig = client._seqTracker.getContiguousSeq(ns);
        if (contig < cursorCurrentSeq) {
          client._clientLog.info(`group.v2.pull retention-floor advance: ns=${ns} contiguous=${contig} -> cursor.current_seq=${cursorCurrentSeq}`);
          client._seqTracker.forceContiguousSeq(ns, cursorCurrentSeq);
        }
      }

      const ackSeq = client._seqTracker.getContiguousSeq(ns);
      const contigAdvanced = ackSeq !== pageContigBefore;
      if (contigAdvanced) {
        await client._drainOrderedMessages(ns);
        client._saveSeqTrackerState();
      }
      const hasServerCursor = cursor !== null && Object.prototype.hasOwnProperty.call(cursor, 'current_seq');
      const ackNeeded = messages.length > 0
        && ackSeq > 0
        && ownsCursor
        && (contigAdvanced || (hasServerCursor && ackSeq > cursorCurrentSeq));
      if (ackNeeded) {
        await this.ackGroupV2(gid, ackSeq);
      }

      const nextAfter = Math.max(pageMaxSeq, nextAfterSeq);
      if (!ownsCursor) break;
      if (messages.length === 0 || nextAfter <= nextAfterSeq || result.has_more === false) break;
      nextAfterSeq = nextAfter;
    }

    if (pageCount >= maxPages) {
      client._clientLog.warn(`group.v2.pull reached max_pages=${maxPages} group=${gid} after_seq=${nextAfterSeq}`);
    }
    return decrypted;
  }

  async ackGroupV2(groupId: string, upToSeq?: number): Promise<unknown> {
    const client = this.client;
    const gid = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!gid) throw new ValidationError('group.ack_messages requires group_id');
    const ns = `group:${gid}`;
    let seq = Number(upToSeq ?? client._seqTracker.getContiguousSeq(ns));
    if (!Number.isFinite(seq) || seq <= 0) return { acked: 0 };
    seq = client._clampAckSeq('group.v2.ack', 'up_to_seq', ns, seq);
    return client._callRawV2Rpc('group.v2.ack', { group_id: gid, up_to_seq: seq });
  }

  async putMessageThoughtEncryptedV2(params: RpcParams): Promise<RpcResult> {
    const client = this.client;
    const toAid = String(params.to ?? '').trim();
    client._validateMessageRecipient(toAid);
    const payload = isJsonObject(params.payload as JsonValue | object | null | undefined) ? params.payload as JsonObject : null;
    if (!toAid) throw new ValidationError('message.thought.put requires to');
    if (payload === null) throw new ValidationError('message.thought.put payload must be an object when encrypt=true');
    const thoughtId = String(params.thought_id ?? '').trim() || `mt-${uuidV4()}`;
    const timestamp = Number(params.timestamp ?? Date.now());
    const protectedHeaders = client._protectedHeadersFromParams(params);
    client._logMessageDebug?.('thought-send-plaintext', 'message.thought.put.v2', 'message.thought.put', {
      to: toAid,
      thought_id: thoughtId,
      timestamp,
      payload,
    }, { payloadOverride: payload });

    const attempt = async (useCache: boolean): Promise<RpcResult> => {
      client._clientLog.debug(`message.thought.put attempt: to=${toAid}, thought_id=${thoughtId}, use_cache=${useCache}`);
      const context = isJsonObject(params.context as JsonValue | object | null | undefined) ? params.context as Record<string, unknown> : undefined;
      const envelope = await client._buildV2P2PEnvelope({
        to: toAid,
        payload,
        messageId: thoughtId,
        timestamp,
        useCache,
        protectedHeaders,
        context,
      });
      const sendParams: RpcParams = {
        to: toAid,
        payload: envelope as JsonObject,
        encrypted: true,
        thought_id: thoughtId,
        timestamp,
      };
      if ('context' in params) sendParams.context = params.context;
      await client._signClientOperation('message.thought.put', sendParams);
      client._logMessageDebug?.('thought-send-envelope', 'message.thought.put.v2', 'message.thought.put', sendParams, {
        payloadOverride: envelope,
        extra: { to: toAid, thought_id: thoughtId, use_cache: useCache },
      });
      const result = await client._transport.call('message.thought.put', sendParams);
      client._clientLog.debug(`message.thought.put ok: to=${toAid}, thought_id=${thoughtId}, use_cache=${useCache}`);
      return result as RpcResult;
    };

    try {
      return await attempt(true);
    } catch (exc) {
      const excCode = Number((exc as { code?: unknown })?.code);
      if (V2_RETRYABLE_CODES.has(excCode)) {
        client._clientLog.debug(`V2 P2P thought put speculative rejected (code=${String(excCode)}), refreshing bootstrap`);
        this.deleteBootstrapCacheEntry(toAid);
        return await attempt(false);
      }
      throw exc;
    }
  }

  async putGroupThoughtEncryptedV2(params: RpcParams): Promise<RpcResult> {
    const client = this.client;
    const groupId = String(params.group_id ?? '').trim();
    const payload = isJsonObject(params.payload as JsonValue | object | null | undefined) ? params.payload as JsonObject : null;
    if (!groupId) throw new ValidationError('group.thought.put requires group_id');
    if (payload === null) throw new ValidationError('group.thought.put payload must be an object when encrypt=true');
    const thoughtId = String(params.thought_id ?? '').trim() || `gt-${uuidV4()}`;
    const timestamp = Number(params.timestamp ?? Date.now());
    const protectedHeaders = client._protectedHeadersFromParams(params);
    client._logMessageDebug?.('thought-send-plaintext', 'group.thought.put.v2', 'group.thought.put', {
      group_id: groupId,
      thought_id: thoughtId,
      timestamp,
      payload,
    }, { payloadOverride: payload });

    const attempt = async (useCache: boolean): Promise<RpcResult> => {
      client._clientLog.debug(`group.thought.put attempt: group=${groupId}, thought_id=${thoughtId}, use_cache=${useCache}`);
      const context = isJsonObject(params.context as JsonValue | object | null | undefined) ? params.context as Record<string, unknown> : undefined;
      const envelope = await client._buildV2GroupEnvelope({
        groupId,
        payload,
        messageId: thoughtId,
        timestamp,
        useCache,
        protectedHeaders,
        context,
      });
      const sendParams: RpcParams = {
        group_id: groupId,
        payload: envelope as JsonObject,
        encrypted: true,
        thought_id: thoughtId,
        timestamp,
      };
      if ('context' in params) sendParams.context = params.context;
      await client._signClientOperation('group.thought.put', sendParams);
      client._logMessageDebug?.('thought-send-envelope', 'group.thought.put.v2', 'group.thought.put', sendParams, {
        payloadOverride: envelope,
        extra: { group_id: groupId, thought_id: thoughtId, use_cache: useCache },
      });
      const result = await client._transport.call('group.thought.put', sendParams);
      client._clientLog.debug(`group.thought.put ok: group=${groupId}, thought_id=${thoughtId}, use_cache=${useCache}`);
      return result as RpcResult;
    };

    try {
      return await attempt(true);
    } catch (exc) {
      const excCode = Number((exc as { code?: unknown })?.code);
      if (V2_RETRYABLE_CODES.has(excCode)) {
        client._clientLog.debug(`V2 group thought put speculative rejected (code=${String(excCode)}), refreshing bootstrap`);
        this.deleteBootstrapCacheEntry(`group:${groupId}`);
        return await attempt(false);
      }
      throw exc;
    }
  }

  async decryptGroupThoughts(result: JsonObject): Promise<JsonObject> {
    const client = this.client;
    client._clientLog.debug(`group.thought.get decrypt enter: found=${String(result.found ?? '')}, group=${String(result.group_id ?? '')}, sender=${String(result.sender_aid ?? '')}`);
    if (!result.found) {
      client._clientLog.debug('group.thought.get decrypt exit: not found');
      return { ...result, thoughts: [] as JsonValue[] };
    }
    const items = Array.isArray(result.thoughts) ? result.thoughts.filter(isJsonObject) : [];
    if (items.length === 0) {
      client._clientLog.debug('group.thought.get decrypt exit: empty thoughts');
      return { ...result, thoughts: [] as JsonValue[] };
    }
    const groupId = String(result.group_id ?? '');
    const senderAid = String(result.sender_aid ?? '');
    const thoughts: JsonObject[] = [];
    for (const item of items) {
      const payload = isJsonObject(item.payload as JsonValue | object | null | undefined) ? item.payload as JsonObject : null;
      const thoughtId = String(item.thought_id ?? item.message_id ?? '');
      const fromAid = String(item.from ?? item.sender_aid ?? senderAid);
      client._logMessageDebug?.('thought-get-raw', 'group.thought.get', 'group.thought.get', item, {
        extra: { group_id: groupId, thought_id: thoughtId, from: fromAid },
      });
      let decryptFailed = false;
      let decryptedPayload: JsonValue | object = payload ?? {};
      let e2ee: JsonValue | undefined;
      if (payload?.type === 'e2ee.group_encrypted' && String(payload.version ?? '') === 'v2') {
        e2ee = v2E2eeMeta(payload) as JsonValue;
        const plain = await client._decryptV2EnvelopeForThought({ envelope: payload, fromAid });
        if (plain === null) {
          decryptFailed = true;
          client._clientLog.debug(`group.thought.get decrypt returned null: group=${groupId}, thought_id=${thoughtId}, from=${fromAid}`);
        } else {
          decryptedPayload = plain;
          client._logMessageDebug?.('thought-decrypt-ok', 'group.thought.get', 'group.thought.get', {
            group_id: groupId,
            thought_id: thoughtId,
            from: fromAid,
            payload: plain,
          });
        }
      } else if (payload?.type === 'e2ee.group_encrypted') {
        decryptFailed = true;
        client._clientLog.debug(`group.thought.get unsupported encrypted payload: group=${groupId}, thought_id=${thoughtId}, type=${String(payload.type ?? '')}, version=${String(payload.version ?? '')}`);
      }
      const thought: JsonObject = {
        thought_id: thoughtId,
        message_id: thoughtId,
        payload: decryptFailed ? (payload ?? {}) : decryptedPayload as JsonValue,
        created_at: item.created_at,
      };
      if (e2ee !== undefined) {
        thought.e2ee = e2ee;
        if (isJsonObject(e2ee as JsonValue | object | null | undefined)) attachV2EnvelopeMetadata(thought, e2ee as Record<string, unknown>);
      }
      if (decryptFailed) thought.decrypt_failed = true;
      if ('context' in item) thought.context = item.context;
      client._logMessageDebug?.(decryptFailed ? 'thought-decrypt-fail' : 'thought-result', 'group.thought.get', 'group.thought.get', thought, {
        extra: { group_id: groupId, thought_id: thoughtId },
      });
      thoughts.push(thought);
    }
    client._clientLog.debug(`group.thought.get decrypt exit: group=${groupId}, total=${items.length}, returned=${thoughts.length}`);
    return { ...result, thoughts };
  }

  async decryptMessageThoughts(result: JsonObject): Promise<JsonObject> {
    const client = this.client;
    client._clientLog.debug(`message.thought.get decrypt enter: found=${String(result.found ?? '')}, peer=${String(result.peer_aid ?? '')}, sender=${String(result.sender_aid ?? '')}`);
    if (!result.found) {
      client._clientLog.debug('message.thought.get decrypt exit: not found');
      return { ...result, thoughts: [] as JsonValue[] };
    }
    const items = Array.isArray(result.thoughts) ? result.thoughts.filter(isJsonObject) : [];
    if (items.length === 0) {
      client._clientLog.debug('message.thought.get decrypt exit: empty thoughts');
      return { ...result, thoughts: [] as JsonValue[] };
    }
    const senderAid = String(result.sender_aid ?? '');
    const peerAid = String(result.peer_aid ?? '');
    const thoughts: JsonObject[] = [];
    for (const item of items) {
      const payload = isJsonObject(item.payload as JsonValue | object | null | undefined) ? item.payload as JsonObject : null;
      const thoughtId = String(item.thought_id ?? item.message_id ?? '');
      const fromAid = String(item.from ?? senderAid);
      const toAid = String(item.to ?? peerAid);
      client._logMessageDebug?.('thought-get-raw', 'message.thought.get', 'message.thought.get', item, {
        extra: { thought_id: thoughtId, from: fromAid, to: toAid },
      });
      let decryptFailed = false;
      let decryptedPayload: JsonValue | object = payload ?? {};
      let e2ee: JsonValue | undefined;
      if (payload?.type === 'e2ee.p2p_encrypted' && String(payload.version ?? '') === 'v2') {
        e2ee = v2E2eeMeta(payload) as JsonValue;
        const plain = await client._decryptV2EnvelopeForThought({ envelope: payload, fromAid });
        if (plain === null) {
          decryptFailed = true;
          client._clientLog.debug(`message.thought.get decrypt returned null: thought_id=${thoughtId}, from=${fromAid}, to=${toAid}`);
        } else {
          decryptedPayload = plain;
          client._logMessageDebug?.('thought-decrypt-ok', 'message.thought.get', 'message.thought.get', {
            thought_id: thoughtId,
            from: fromAid,
            to: toAid,
            payload: plain,
          });
        }
      } else if (payload?.type === 'e2ee.encrypted' || payload?.type === 'e2ee.p2p_encrypted') {
        decryptFailed = true;
        client._clientLog.debug(`message.thought.get unsupported encrypted payload: thought_id=${thoughtId}, type=${String(payload.type ?? '')}, version=${String(payload.version ?? '')}`);
      }
      const thought: JsonObject = {
        thought_id: thoughtId,
        message_id: thoughtId,
        from: fromAid,
        to: toAid,
        payload: decryptFailed ? (payload ?? {}) : decryptedPayload as JsonValue,
        created_at: item.created_at,
      };
      if (e2ee !== undefined) {
        thought.e2ee = e2ee;
        if (isJsonObject(e2ee as JsonValue | object | null | undefined)) attachV2EnvelopeMetadata(thought, e2ee as Record<string, unknown>);
      }
      if (decryptFailed) thought.decrypt_failed = true;
      if ('context' in item) thought.context = item.context;
      client._logMessageDebug?.(decryptFailed ? 'thought-decrypt-fail' : 'thought-result', 'message.thought.get', 'message.thought.get', thought, {
        extra: { thought_id: thoughtId },
      });
      thoughts.push(thought);
    }
    client._clientLog.debug(`message.thought.get decrypt exit: total=${items.length}, returned=${thoughts.length}`);
    return { ...result, thoughts };
  }

  async decryptV2EnvelopeForThought(opts: {
    envelope: Record<string, unknown>;
    fromAid: string;
  }): Promise<Record<string, unknown> | null> {
    const client = this.client;
    const session = client._v2Session;
    if (!session || !opts.envelope) return null;
    const envelope = opts.envelope;
    let spkId = '';
    let recipientKeySource = '';
    if (Array.isArray(envelope.recipients)) {
      for (const row of envelope.recipients) {
        if (!Array.isArray(row) || row.length < 6) continue;
        if (String(row[0] ?? '') === client._aid
          && (String(row[1] ?? '') === client._deviceId || String(row[1] ?? '') === '')) {
          spkId = String(row[5] ?? '');
          recipientKeySource = String(row[3] ?? '');
          break;
        }
      }
    }
    const aad = isJsonObject(envelope.aad as JsonValue | object | null | undefined) ? envelope.aad as JsonObject : {};
    const groupIdForKeys = String(aad.group_id ?? envelope.group_id ?? '').trim();
    let ikPriv: Uint8Array;
    let spkPriv: Uint8Array | undefined;
    try {
      if (groupIdForKeys) {
        const keys = await session.getGroupDecryptKeys(groupIdForKeys, spkId);
        ikPriv = keys.ikPriv;
        spkPriv = keys.spkPriv;
      } else {
        const keys = await session.getDecryptKeys(spkId);
        ikPriv = keys.ikPriv;
        spkPriv = keys.spkPriv;
      }
    } catch (exc) {
      client._clientLog.warn(`V2 thought decrypt: SPK lookup failed from=${opts.fromAid}, group=${groupIdForKeys || '<p2p>'}, spk_id=${spkId || '<empty>'}: ${String(formatE2EEError(exc))}`);
      return null;
    }
    const fromAid = String(opts.fromAid || aad.from || '').trim();
    const senderDeviceId = String(aad.from_device ?? '');
    const senderCertFingerprint = String(envelope.sender_cert_fingerprint ?? '').trim().toLowerCase();
    const senderPubDer = await this.getV2SenderPubDer(fromAid, senderDeviceId, senderCertFingerprint);
    if (!senderPubDer) {
      client._clientLog.warn(`V2 thought decrypt: no sender IK for ${fromAid} device=${senderDeviceId}`);
      this.scheduleSenderIKFetch(fromAid, senderDeviceId, groupIdForKeys);
      return null;
    }
    try {
      const plaintext = await decryptMessage(
        envelope,
        client._aid ?? '',
        client._deviceId,
        ikPriv,
        spkPriv,
        senderPubDer,
      );
      if (plaintext != null) {
        if (groupIdForKeys && recipientKeySource === 'group_device_prekey' && session.isLastUploadedGroupSPK(groupIdForKeys, spkId)) {
          this.scheduleGroupSpkRotation(groupIdForKeys, { reason: 'thought_group_spk_consumed' });
        } else if (groupIdForKeys && recipientKeySource === 'peer_device_prekey') {
          this.scheduleGroupSpkRegistrationAfterPeerFallback(groupIdForKeys);
        }
      }
      return plaintext;
    } catch (exc) {
      client._clientLog.warn(`V2 thought decrypt failed from=${fromAid}: ${String(formatE2EEError(exc))}`);
      return null;
    }
  }

  encryptedPushEnvelope(msg: Record<string, unknown>): Record<string, unknown> | null {
    if (this.isEncryptedEnvelopePayload(msg.payload)) return msg.payload as Record<string, unknown>;
    if (typeof msg.envelope_json === 'string' && msg.envelope_json.trim()) {
      try {
        const parsed = JSON.parse(msg.envelope_json) as unknown;
        if (this.isEncryptedEnvelopePayload(parsed)) return parsed as Record<string, unknown>;
      } catch {
        return null;
      }
    }
    return null;
  }

  isEncryptedPushMessage(msg: Record<string, unknown>): boolean {
    if (truthyBool(msg.encrypted)) return true;
    return this.encryptedPushEnvelope(msg) !== null;
  }

  isEncryptedEnvelopePayload(payload: unknown): boolean {
    if (!isJsonObject(payload as JsonValue | object | null | undefined)) return false;
    const envelope = payload as Record<string, unknown>;
    const payloadType = String(envelope.type ?? '').trim();
    if (payloadType.startsWith('e2ee.')) return true;
    if (!String(envelope.ciphertext ?? '').trim()) return false;
    return envelope.nonce !== undefined
      || envelope.tag !== undefined
      || envelope.recipient !== undefined
      || envelope.recipients !== undefined
      || envelope.wrapped_key !== undefined
      || envelope.recipients_digest !== undefined;
  }

  isV2EncryptedEnvelopePayload(envelope: Record<string, unknown> | null): envelope is Record<string, unknown> {
    if (!envelope) return false;
    const payloadType = String(envelope.type ?? '').trim();
    if (payloadType === 'e2ee.p2p_encrypted' || payloadType === 'e2ee.group_encrypted') return true;
    return String(envelope.version ?? '').trim().toLowerCase() === 'v2' && payloadType.startsWith('e2ee.');
  }

  safeUndecryptablePushEvent(msg: Record<string, unknown>, group: boolean): Record<string, unknown> {
    const event: Record<string, unknown> = {
      message_id: msg.message_id ?? null,
      from: msg.from ?? null,
      seq: msg.seq ?? null,
      timestamp: msg.timestamp ?? msg.t_server ?? null,
      device_id: msg.device_id ?? null,
      slot_id: msg.slot_id ?? null,
      _decrypt_error: 'encrypted push payload is not decryptable on raw push path',
      _decrypt_stage: 'push_envelope',
    };
    if (group) {
      event.group_id = msg.group_id ?? null;
    } else {
      event.to = msg.to ?? null;
    }
    const envelope = this.encryptedPushEnvelope(msg);
    if (envelope) {
      event._envelope_type = String(envelope.type ?? '');
      event._suite = String(envelope.suite ?? '');
      if (this.isV2EncryptedEnvelopePayload(envelope)) {
        attachV2EnvelopeMetadata(event, v2E2eeMeta(envelope));
      }
    }
    return event;
  }

  async decryptEncryptedPushPayload(msg: Record<string, unknown>, group: boolean): Promise<Record<string, unknown> | null> {
    const client = this.client;
    const envelope = this.encryptedPushEnvelope(msg);
    if (!this.isV2EncryptedEnvelopePayload(envelope)) return null;
    const aad = isJsonObject(envelope.aad as JsonValue | object | null | undefined) ? envelope.aad as Record<string, unknown> : {};
    const fromAid = String(msg.from_aid ?? msg.from ?? msg.sender_aid ?? aad.from ?? '').trim();
    const plaintext = await client._decryptV2EnvelopeForThought({ envelope, fromAid });
    if (!plaintext) return null;
    const e2eeMeta = v2E2eeMeta(envelope);
    const result: Record<string, unknown> = {
      message_id: String(msg.message_id ?? ''),
      from: fromAid,
      seq: msg.seq ?? null,
      timestamp: msg.t_server ?? msg.timestamp ?? null,
      payload: plaintext,
      encrypted: true,
      e2ee: e2eeMeta,
    };
    result.direction = fromAid && fromAid === client._aid ? 'outbound_sync' : 'inbound';
    if (msg.t_server !== undefined) result.t_server = msg.t_server;
    if (msg.device_id !== undefined) result.device_id = msg.device_id;
    if (msg.slot_id !== undefined) result.slot_id = msg.slot_id;
    attachGatewayProximity(result, msg);
    if (group) {
      result.group_id = msg.group_id ?? aad.group_id ?? envelope.group_id ?? null;
    } else {
      result.to = msg.to ?? client._aid ?? '';
    }
    attachV2EnvelopeMetadata(result, e2eeMeta);
    client._logMessageDebug?.('decrypt-ok', 'push.encrypted', group ? 'group.message_created' : 'message.received', result);
    return result;
  }

  async publishEncryptedPushAsUndecryptable(
    event: string,
    ns: string,
    seq: unknown,
    msg: Record<string, unknown>,
    group: boolean,
  ): Promise<boolean> {
    const client = this.client;
    const safeEvent = this.safeUndecryptablePushEvent(msg, group);
    client._logMessageDebug?.('decrypt-fail', 'push.encrypted', event, safeEvent);
    if (ns) {
      return await client._publishOrderedMessage(event, ns, seq, safeEvent);
    }
    await client._publishAppEvent(event, safeEvent, 'push');
    return true;
  }

  async publishEncryptedPushMessage(
    normalEvent: string,
    undecryptableEvent: string,
    ns: string,
    seq: unknown,
    msg: Record<string, unknown>,
    group: boolean,
  ): Promise<boolean> {
    const client = this.client;
    const decrypted = await this.decryptEncryptedPushPayload(msg, group);
    if (decrypted) {
      if (ns) return await client._publishOrderedMessage(normalEvent, ns, seq, decrypted);
      await client._publishAppEvent(normalEvent, decrypted, 'push');
      return true;
    }
    return await this.publishEncryptedPushAsUndecryptable(undecryptableEvent, ns, seq, msg, group);
  }

  async decryptV2PushMessage(data: unknown): Promise<Record<string, unknown> | null> {
    if (!isJsonObject(data as JsonValue | object | null | undefined)) return null;
    return await this.client._decryptV2Message(data as Record<string, unknown>);
  }

  async buildV2P2PEnvelope(opts: {
    to: string;
    payload: Record<string, unknown>;
    messageId?: string;
    timestamp?: number;
    useCache?: boolean;
    protectedHeaders?: Record<string, unknown>;
    context?: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    const client = this.client;
    if (!client._v2Session) {
      throw new StateError('V2 session not initialized');
    }
    const session = client._v2Session;
    const to = opts.to;
    const useCache = opts.useCache !== false;

    let peerDevices: Array<Record<string, unknown>> = [];
    let auditRaw: Array<Record<string, unknown>> = [];
    let wrapPolicy: V2WrapPolicy | undefined;
    const cached = useCache ? this.getBootstrapCacheEntry(to) : undefined;
    if (cached && (Date.now() - Number(cached.cachedAt ?? 0)) < V2_BOOTSTRAP_TTL_MS) {
      peerDevices = (cached.devices ?? []) as Array<Record<string, unknown>>;
      auditRaw = (cached.auditRecipients ?? []) as Array<Record<string, unknown>>;
      wrapPolicy = cached.wrapPolicy;
    } else {
      const bs = await client.call('message.v2.bootstrap', {
        peer_aid: to,
        e2ee_wrap_capabilities: v2WrapCapabilities(),
      }) as Record<string, unknown>;
      peerDevices = (Array.isArray(bs?.peer_devices) ? bs.peer_devices : []) as Array<Record<string, unknown>>;
      auditRaw = (Array.isArray(bs?.audit_recipients) ? bs.audit_recipients : []) as Array<Record<string, unknown>>;
      wrapPolicy = normalizeV2WrapPolicy(bs?.e2ee_wrap_policy);
      if (peerDevices.length > 0) {
        this.setBootstrapCacheEntry(to, {
          devices: peerDevices,
          auditRecipients: auditRaw,
          cachedAt: Date.now(),
          wrapPolicy,
        });
      }
    }

    if (peerDevices.length === 0) {
      throw new E2EEError(`V2 bootstrap: no devices found for ${to}`);
    }

    const targets: Target[] = [];
    for (const dev of peerDevices) {
      const devId = getV2DeviceId(dev);
      const target = await client._v2BuildTargetFromDevice({
        dev,
        aid: to,
        deviceId: devId.value,
        role: 'peer',
        defaultKeySource: 'peer_device_prekey',
      });
      if (target) targets.push(target);
    }
    for (const dev of auditRaw) {
      const target = await client._v2BuildTargetFromDevice({
        dev,
        aid: String(dev.aid ?? ''),
        deviceId: String(dev.device_id ?? ''),
        role: 'audit',
        defaultKeySource: 'peer_device_prekey',
      });
      if (target) targets.push(target);
    }

    if (client._aid && client._aid !== to) {
      try {
        const selfCached = this.getBootstrapCacheEntry(client._aid);
        let selfDevices: Array<Record<string, unknown>> = [];
        if (selfCached && (Date.now() - Number(selfCached.cachedAt ?? 0)) < V2_BOOTSTRAP_TTL_MS) {
          selfDevices = (selfCached.devices ?? []) as Array<Record<string, unknown>>;
        } else {
          const selfBs = await client.call('message.v2.bootstrap', {
            peer_aid: client._aid,
            e2ee_wrap_capabilities: v2WrapCapabilities(),
          }) as Record<string, unknown>;
          selfDevices = (Array.isArray(selfBs?.peer_devices) ? selfBs.peer_devices : []) as Array<Record<string, unknown>>;
          if (selfDevices.length > 0) {
            this.setBootstrapCacheEntry(client._aid, {
              devices: selfDevices,
              auditRecipients: [],
              cachedAt: Date.now(),
            });
          }
        }
        for (const dev of selfDevices) {
          const devId = getV2DeviceId(dev);
          if (!devId.present || devId.value === client._deviceId) continue;
          const target = await client._v2BuildTargetFromDevice({
            dev,
            aid: client._aid,
            deviceId: devId.value,
            role: 'self_sync',
            defaultKeySource: 'peer_device_prekey',
          });
          if (target) targets.push(target);
        }
      } catch (exc) {
        client._clientLog.debug(`V2 thought self-sync bootstrap failed (non-fatal): ${String(exc)}`);
      }
    }

    const sender = await session.getSenderIdentity();
    const sendTargets = applyV2WrapPolicyToTargets(targets, wrapPolicy);
    const envelope = await encryptP2PMessage(
      sender,
      { targets: sendTargets, auditRecipients: [] },
      opts.payload,
      { messageId: opts.messageId, timestamp: opts.timestamp, protectedHeaders: opts.protectedHeaders, context: opts.context },
    );
    return envelope;
  }

  async buildV2GroupEnvelope(opts: {
    groupId: string;
    payload: Record<string, unknown>;
    messageId?: string;
    timestamp?: number;
    useCache?: boolean;
    protectedHeaders?: Record<string, unknown>;
    context?: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    const client = this.client;
    if (!client._v2Session) {
      throw new StateError('V2 session not initialized');
    }
    const session = client._v2Session;
    const groupId = normalizeGroupId(opts.groupId) || String(opts.groupId ?? '').trim();
    if (!groupId) throw new ValidationError("group.send requires 'group_id'");
    const useCache = opts.useCache !== false;
    const cacheKey = `group:${groupId}`;

    let allDevices: Array<Record<string, unknown>> = [];
    let epoch = 0;
    let stateCommitment: Partial<StateCommitmentAAD> = { state_version: 0, state_hash: '', state_chain: '' };
    let auditRecipientsRaw: Array<Record<string, unknown>> = [];
    let wrapPolicy: V2WrapPolicy | undefined;

    const cached = useCache ? this.getBootstrapCacheEntry(cacheKey) : undefined;
    if (cached && (Date.now() - Number(cached.cachedAt ?? 0)) < V2_BOOTSTRAP_TTL_MS) {
      allDevices = (cached.devices ?? []) as Array<Record<string, unknown>>;
      epoch = Number(cached.epoch ?? 0) || 0;
      stateCommitment = cached.stateCommitment ?? { state_version: 0, state_hash: '', state_chain: '' };
      auditRecipientsRaw = (cached.auditRecipients ?? []) as Array<Record<string, unknown>>;
      wrapPolicy = cached.wrapPolicy;
    } else {
      const bs = await client.call('group.v2.bootstrap', {
        group_id: groupId,
        e2ee_wrap_capabilities: v2WrapCapabilities(),
      }) as Record<string, unknown>;
      allDevices = (Array.isArray(bs?.devices) ? bs.devices : []) as Array<Record<string, unknown>>;
      epoch = Number(bs?.epoch ?? 0);
      auditRecipientsRaw = (Array.isArray(bs?.audit_recipients) ? bs.audit_recipients : []) as Array<Record<string, unknown>>;
      wrapPolicy = normalizeV2WrapPolicy(bs?.e2ee_wrap_policy);
      await client._v2CheckFork(groupId, String(bs?.state_chain ?? ''));
      await client._v2VerifyStateSignature(groupId, bs);
      await client._publishV2GroupSecurityLevel(groupId, bs);
      stateCommitment = {
        state_version: Number(bs?.state_version ?? 0) || 0,
        state_hash: String(bs?.state_hash_signed ?? bs?.state_hash ?? ''),
        state_chain: String(bs?.state_chain ?? ''),
      };
      if (allDevices.length > 0) {
        this.setBootstrapCacheEntry(cacheKey, {
          devices: allDevices,
          auditRecipients: auditRecipientsRaw,
          cachedAt: Date.now(),
          epoch,
          stateCommitment,
          wrapPolicy,
        });
      }
      const pendingAdds = Array.isArray(bs?.pending_adds) ? bs.pending_adds : [];
      if (pendingAdds.length > 0 && client._v2Session) {
        client._v2MaybeTriggerAutoPropose(groupId);
      }
    }

    if (allDevices.length === 0) {
      throw new E2EEError(`V2 group bootstrap: no devices found for group ${groupId}`);
    }

    const targets: Target[] = [];
    for (const dev of allDevices) {
      const devAid = String(dev.aid ?? '').trim();
      const devId = getV2DeviceId(dev);
      if (devAid === client._aid && devId.present && devId.value === client._deviceId) continue;
      const role = devAid === client._aid ? 'self_sync' : 'member';
      const target = await client._v2BuildTargetFromDevice({
        dev,
        aid: devAid,
        deviceId: devId.value,
        role,
        defaultKeySource: 'peer_device_prekey',
      });
      if (target) targets.push(target);
    }

    if (targets.length === 0) {
      throw new E2EEError(`V2 group: no target devices for group ${groupId}`);
    }
    for (const dev of auditRecipientsRaw) {
      const target = await client._v2BuildTargetFromDevice({
        dev,
        aid: String(dev.aid ?? ''),
        deviceId: String(dev.device_id ?? ''),
        role: 'audit',
        defaultKeySource: 'peer_device_prekey',
      });
      if (target) targets.push(target);
    }

    const sender = await session.getSenderIdentity();
    const sendTargets = applyV2WrapPolicyToTargets(targets, wrapPolicy);
    const envelope = await encryptGroupMessage(
      sender,
      groupId,
      epoch,
      sendTargets,
      opts.payload,
      { messageId: opts.messageId, timestamp: opts.timestamp, protectedHeaders: opts.protectedHeaders, context: opts.context },
      stateCommitment as StateCommitmentAAD,
    );
    return envelope;
  }

  handleGroupChangedSpk(data: Record<string, any>, groupId: string, action: string): void {
    if (!this.client._v2Session || !groupId || !MEMBERSHIP_ACTIONS.has(action)) return;
    const joinedAid = String(data.joined_aid ?? data.member_aid ?? data.aid ?? '').trim();
    const actorAid = String(data.actor_aid ?? '').trim();
    const selfAid = String(this.client._aid ?? '').trim();
    const isSelfJoin = JOIN_ACTIONS.has(action) && !!selfAid && (
      joinedAid === selfAid ||
      (!joinedAid && (action === 'joined' || action === 'invite_code_used') && actorAid === selfAid)
    );
    if (isSelfJoin) {
      this.scheduleGroupSpkRegistration(groupId, { reason: `group_changed:${action}` });
    } else {
      this.scheduleGroupSpkRotation(groupId, { reason: `group_changed:${action}` });
    }
  }

  async handleV2EpochRotated(data: unknown): Promise<void> {
    const client = this.client;
    if (!data || typeof data !== 'object' || Array.isArray(data)) return;
    const d = data as Record<string, any>;
    const groupId = String(d.group_id ?? '').trim();
    if (!groupId) return;
    const epoch = d.epoch ?? 0;
    client._clientLog.debug(`_onV2EpochRotated: group=${groupId} epoch=${String(epoch)}`);
    this.deleteBootstrapCacheEntry(`group:${groupId}`);
    if (!client._v2Session) return;
    try {
      await client._v2Session.rotateSPK(client._v2CallFn());
      client._clientLog.info(`SPK rotated after epoch change: group=${groupId} epoch=${String(epoch)}`);
    } catch (exc) {
      client._clientLog.debug(`SPK rotation after epoch change failed (non-fatal): ${formatE2EEError(exc)}`);
    }
  }
}
