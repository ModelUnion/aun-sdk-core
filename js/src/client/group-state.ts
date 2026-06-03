import {
  base64ToUint8,
  ecdsaSignDer,
  ecdsaVerifyDer,
  importCertPublicKeyEcdsa,
  importPrivateKeyEcdsa,
  uint8ToBase64,
} from '../crypto.js';
import { E2EEError } from '../errors.js';
import type { EventPayload } from '../events.js';
import { normalizeGroupId } from '../group-id.js';
import {
  isJsonObject,
  type JsonObject,
  type JsonValue,
  type RpcParams,
} from '../types.js';
import { computeStateCommitment } from '../v2/state/index.js';
import type { ClientHost, ClientRuntime } from './runtime.js';

const MEMBERSHIP_MUTATION_METHODS = new Set([
  'group.create',
  'group.add_member',
  'group.kick',
  'group.remove_member',
  'group.leave',
  'group.review_join_request',
  'group.batch_review_join_request',
  'group.use_invite_code',
  'group.request_join',
]);

const SPK_REGISTRATION_MUTATION_METHODS = new Set([
  'group.create',
  'group.use_invite_code',
]);

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

const V2_SIG_CACHE_TTL_MS = 60 * 60 * 1000;
const V2_SIG_CACHE_MAX = 16_384;

function formatCaughtError(error: unknown): Error | string {
  return error instanceof Error ? error : String(error);
}

function stableStringify(obj: JsonValue | object | undefined): string {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'boolean' || typeof obj === 'number') return JSON.stringify(obj);
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(v => stableStringify(v)).join(',') + ']';
  }
  if (isJsonObject(obj)) {
    const entries = Object.keys(obj).sort()
      .filter(k => obj[k] !== undefined)
      .map(k => stableStringify(k) + ':' + stableStringify(obj[k]));
    return '{' + entries.join(',') + '}';
  }
  return JSON.stringify(obj);
}

function lengthPrefixedBytesKey(...parts: Uint8Array[]): Uint8Array {
  const encoder = new TextEncoder();
  const frames: Uint8Array[] = [];
  let total = 0;
  for (const part of parts) {
    const prefix = encoder.encode(`${part.byteLength}:`);
    const suffix = encoder.encode(';');
    frames.push(prefix, part, suffix);
    total += prefix.byteLength + part.byteLength + suffix.byteLength;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const frame of frames) {
    out.set(frame, offset);
    offset += frame.byteLength;
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function sortObjectKeys(obj: Record<string, unknown>): Record<string, unknown> {
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = obj[key];
  }
  return sorted;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim();
  if (!clean) return new Uint8Array();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function uint64BE(value: number): Uint8Array {
  const out = new Uint8Array(8);
  const view = new DataView(out.buffer);
  const normalized = Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;
  view.setBigUint64(0, BigInt(normalized), false);
  return out;
}

function lengthPrefixedTextKey(...parts: string[]): string {
  const encoder = new TextEncoder();
  return parts.map((part) => `${encoder.encode(part).byteLength}:${part};`).join('');
}

function v2WrapCapabilities(): JsonObject {
  return {
    version: 'v2.1',
    protocols: ['1DH', '3DH'],
    scopes: ['aid', 'device'],
    per_aid_wrap: true,
    per_device_wrap: true,
  };
}

async function computeStateHash(params: {
  groupId: string;
  stateVersion: number;
  keyEpoch: number;
  members: Array<{ aid: string; role: string }>;
  policy: Record<string, unknown>;
  prevStateHash: string;
}): Promise<string> {
  const sortedMembers = [...params.members].sort((a, b) => a.aid.localeCompare(b.aid));
  const membershipBlock = sortedMembers.map((m) => `${m.aid}:${m.role}`).join('|');
  const policyBlock = Object.keys(params.policy).length > 0
    ? JSON.stringify(sortObjectKeys(params.policy))
    : '';
  const prevBytes = params.prevStateHash ? hexToBytes(params.prevStateHash) : new Uint8Array(32);
  const sep = new Uint8Array([0x00]);
  const encoder = new TextEncoder();
  const chunks = [
    encoder.encode(params.groupId), sep,
    uint64BE(params.stateVersion), sep,
    uint64BE(params.keyEpoch), sep,
    encoder.encode(membershipBlock), sep,
    encoder.encode(policyBlock), sep,
    prevBytes,
  ];
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const data = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    data.set(chunk, offset);
    offset += chunk.length;
  }
  const digest = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(new Uint8Array(digest));
}

function normalizedGroupId(raw: unknown): string {
  const groupId = String(raw ?? '').trim();
  return normalizeGroupId(groupId) || groupId;
}

export class GroupStateCoordinator {
  private readonly runtime: ClientRuntime;

  constructor(runtime: ClientRuntime) {
    this.runtime = runtime;
  }

  private get client(): ClientHost {
    return this.runtime.client;
  }

  async postprocessResult(method: string, params: RpcParams, result: unknown): Promise<unknown> {
    const client = this.client;
    if (!MEMBERSHIP_MUTATION_METHODS.has(method) || !isJsonObject(result) || 'error' in result || !client._v2Session) {
      return result;
    }

    const groupId = this.extractGroupIdFromMutationResult(result, params);
    if (!groupId) {
      return result;
    }

    try {
      await client._v2AutoProposeState(groupId);
    } catch (exc) {
      client._clientLog?.debug?.(`V2 post-membership propose failed (non-fatal): group=${groupId} err=${formatCaughtError(exc)}`);
    }

    if (SPK_REGISTRATION_MUTATION_METHODS.has(method)) {
      client._v2E2EE?.scheduleGroupSpkRegistration?.(groupId, { reason: method });
    }

    return result;
  }

  handleGroupChangedV2Membership(data: JsonObject): void {
    const client = this.client;
    const groupId = normalizedGroupId(data.group_id);
    const action = String(data.action ?? '').trim();
    if (!groupId) {
      return;
    }

    client._v2E2EE?.deleteBootstrapCacheEntry?.(`group:${groupId}`);
    const membershipAction = MEMBERSHIP_ACTIONS.has(action);
    if (client._v2Session && (action === 'upsert' || membershipAction)) {
      client._safeAsync(client._v2AutoProposeState(groupId, { leaderDelay: true }));
    }
    client._v2E2EE?.handleGroupChangedSpk?.(data, groupId, action);
  }

  async onV2StateProposed(data: EventPayload): Promise<void> {
    const client = this.client;
    if (!isJsonObject(data) || !client._v2Session) return;
    const groupId = normalizedGroupId(data.group_id);
    if (!groupId) return;
    await client._dispatcher.publish('group.v2.state_proposed', data);
    try {
      await client._v2ConfirmPendingProposal(groupId);
    } catch (exc) {
      client._clientLog.debug(`V2 state_proposed handling failed (non-fatal): group=${groupId} err=${formatCaughtError(exc)}`);
    }
  }

  async onV2StateRetryNeeded(data: EventPayload): Promise<void> {
    const client = this.client;
    if (!isJsonObject(data) || !client._v2Session) return;
    const groupId = normalizedGroupId(data.group_id);
    if (!groupId) return;
    await client._dispatcher.publish('group.v2.state_retry_needed', data);
    try {
      await client._v2AutoProposeState(groupId, { leaderDelay: true });
    } catch (exc) {
      client._clientLog.debug(`V2 state_retry_needed handling failed (non-fatal): group=${groupId} err=${formatCaughtError(exc)}`);
    }
  }

  async onV2StateConfirmed(data: EventPayload): Promise<void> {
    const client = this.client;
    if (!isJsonObject(data)) return;
    const groupId = normalizedGroupId(data.group_id);
    if (groupId) {
      client._v2E2EE?.deleteBootstrapCacheEntry?.(`group:${groupId}`);
      client._v2AutoProposeLastSnapshot?.delete?.(groupId);
    }
    await client._dispatcher.publish('group.v2.state_confirmed', data);
  }

  async publishV2GroupSecurityLevel(groupId: string, bootstrap: Record<string, unknown>): Promise<void> {
    const client = this.client;
    const gid = normalizedGroupId(groupId);
    if (!gid) return;
    const level = String(bootstrap.e2ee_security_level ?? '').trim() || 'end_to_end';
    const securityLevels = this.runtime.groupState.securityLevels;
    const previous = securityLevels.get(gid);
    if (previous === level) return;
    securityLevels.set(gid, level);
    await client._dispatcher.publish('group.v2.security_level', {
      group_id: gid,
      level,
      warning: String(bootstrap.e2ee_security_warning ?? ''),
      previous_level: previous ?? null,
    });
  }

  async verifyStateSignature(groupId: string, bootstrap: Record<string, unknown>): Promise<void> {
    const client = this.client;
    const gid = normalizedGroupId(groupId);
    if (!gid || !bootstrap) return;
    const stateSignature = String(bootstrap.state_signature ?? '');
    const actorAid = String(bootstrap.state_actor_aid ?? '');
    const stateHashSigned = String(bootstrap.state_hash_signed ?? '');
    const membershipSnapshot = String(bootstrap.state_membership_snapshot ?? '');
    const stateVersion = Number(bootstrap.state_version ?? 0) || 0;
    if (stateVersion === 0 || !stateSignature || !actorAid) return;

    try {
      const signPayload = stableStringify({
        group_id: gid,
        membership_snapshot: membershipSnapshot,
        state_hash: stateHashSigned,
        state_version: stateVersion,
      });
      const signPayloadBytes = new TextEncoder().encode(signPayload);
      const sigBytes = base64ToUint8(stateSignature);
      const framedPayload = lengthPrefixedBytesKey(
        new TextEncoder().encode(actorAid),
        signPayloadBytes,
      );
      const cacheData = new Uint8Array(framedPayload.byteLength + sigBytes.byteLength);
      cacheData.set(framedPayload, 0);
      cacheData.set(sigBytes, framedPayload.byteLength);
      const cacheInput = cacheData.buffer.slice(
        cacheData.byteOffset,
        cacheData.byteOffset + cacheData.byteLength,
      ) as ArrayBuffer;
      const cacheHash = new Uint8Array(await crypto.subtle.digest('SHA-256', cacheInput));
      const cacheKey = bytesToHex(cacheHash);

      const sigCache = this.runtime.groupState.sigCache;
      const now = Date.now();
      const cachedExp = sigCache.get(cacheKey);
      if (cachedExp !== undefined && cachedExp > now) {
        client._clientLog.debug(`V2 state signature cache hit: group=${gid} sv=${stateVersion}`);
      } else {
        const certPem = await client._fetchPeerCert(actorAid);
        if (!certPem) {
          client._clientLog.warn(`V2 state verify: no cert for actor=${actorAid}, group=${gid}`);
          throw new E2EEError(`V2 state verify: cannot fetch actor cert for ${actorAid}`);
        }
        const pubKey = await importCertPublicKeyEcdsa(certPem);
        const ok = await ecdsaVerifyDer(pubKey, sigBytes, signPayloadBytes);
        if (!ok) {
          client._clientLog.warn(`V2 state signature verification FAILED: group=${gid} sv=${stateVersion} actor=${actorAid}`);
          throw new E2EEError('V2 state signature verification failed');
        }
        sigCache.set(cacheKey, now + V2_SIG_CACHE_TTL_MS);
        this.pruneSigCache(now);
        client._clientLog.debug(`V2 state signature verified: group=${gid} sv=${stateVersion} actor=${actorAid}`);
      }

      await this.checkMembershipTamper(gid, bootstrap, membershipSnapshot);
    } catch (exc) {
      if (exc instanceof E2EEError) throw exc;
      client._clientLog.warn(`V2 state signature verification failed: group=${gid} err=${formatCaughtError(exc)}`);
      throw new E2EEError(`V2 state signature verification failed: ${String(formatCaughtError(exc))}`);
    }
  }

  async checkFork(groupId: string, serverChain: string): Promise<void> {
    const client = this.client;
    const gid = normalizedGroupId(groupId);
    if (!gid || !serverChain) return;
    try {
      const stateChains = this.runtime.groupState.chains;
      const local = stateChains.get(gid);
      if (local === undefined) {
        stateChains.set(gid, [0, serverChain]);
        return;
      }
      const [localSv, localChain] = local;
      if (localChain === serverChain) return;

      try {
        const stateResp = await client.call('group.get_state', { group_id: gid }) as Record<string, unknown> | null;
        if (stateResp) {
          const serverSv = Number(stateResp.state_version ?? 0);
          if (serverSv > localSv) {
            stateChains.set(gid, [serverSv, serverChain]);
            return;
          }
          if (serverSv < localSv) {
            client._clientLog.warn(`V2 state chain rollback detected: group=${gid} server_sv=${serverSv} local_sv=${localSv}`);
          }
        }
      } catch {
        // get_state 失败时继续发布 fork 告警。
      }

      client._clientLog.warn(`V2 state chain fork detected: group=${gid} local_chain=${localChain.slice(0, 16)}... server_chain=${serverChain.slice(0, 16)}...`);
      await client._dispatcher.publish('group.v2.fork_detected', {
        group_id: gid,
        local_chain: localChain,
        server_chain: serverChain,
      });
    } catch (exc) {
      client._clientLog.debug(`V2 fork check failed (non-fatal): ${formatCaughtError(exc)}`);
    }
  }

  maybeTriggerAutoPropose(groupId: string): void {
    const client = this.client;
    const gid = normalizedGroupId(groupId);
    if (!gid) return;
    const lazyProposeTriggered = this.runtime.groupState.lazyProposeTriggered;
    const now = Date.now();
    const last = lazyProposeTriggered.get(gid) ?? 0;
    if (now - last < 10000) return;
    lazyProposeTriggered.set(gid, now);
    client._safeAsync(client._v2AutoProposeState(gid, { leaderDelay: true }));
  }

  async onGroupStateCommitted(data: EventPayload): Promise<void> {
    const client = this.client;
    const tStart = Date.now();
    const groupIdInit = String((data as Record<string, unknown> | null | undefined)?.group_id ?? '');
    client._clientLog.debug(`_onGroupStateCommitted enter: group_id=${groupIdInit} state_version=${String((data as Record<string, unknown> | null | undefined)?.state_version ?? '-')}`);
    try {
      if (!isJsonObject(data)) {
        client._clientLog.debug(`_onGroupStateCommitted exit: elapsed=${Date.now() - tStart}ms reason=non_object`);
        return;
      }
      const groupId = String(data.group_id ?? '').trim();
      if (!groupId) {
        client._clientLog.debug(`_onGroupStateCommitted exit: elapsed=${Date.now() - tStart}ms reason=no_group_id`);
        return;
      }

      const cs = data.client_signature;
      if (cs && isJsonObject(cs)) {
        if (client._shouldSkipEventSignature(data)) {
          delete data.client_signature;
        } else {
          const verified = await client._verifyEventSignature(data, cs);
          if (verified === false) {
            client._clientLog.warn(`state_committed committer signature verify failed group=%s${String(groupId)}`);
            return;
          }
          data._verified = verified;
        }
      }

      const stateVersion = Number(data.state_version ?? 0);
      const stateHash = String(data.state_hash ?? '').trim();
      const prevStateHash = String(data.prev_state_hash ?? '').trim();
      const keyEpoch = Number(data.key_epoch ?? 0);
      const membershipSnapshot = String(data.membership_snapshot ?? '').trim();
      const policySnapshot = String(data.policy_snapshot ?? '').trim();

      const loadFn = client._tokenStore.loadGroupState;
      const localState = loadFn
        ? await loadFn.call(client._tokenStore, groupId)
        : null;
      if (localState && localState.state_hash && localState.state_hash !== prevStateHash) {
        client._clientLog.warn(
          '[aun_core] state_hash 链不连续 group=%s local_sv=%d event_sv=%d',
          groupId, localState.state_version, stateVersion,
        );
        try {
          const serverState = await client._transport.call('group.get_state', { group_id: groupId });
          if (serverState && typeof (serverState as Record<string, unknown>).state_version !== 'undefined') {
            const serverObj = serverState as Record<string, unknown>;
            const sv = Number(serverObj.state_version);
            const sHash = String(serverObj.state_hash ?? '');
            const sEpoch = Number(serverObj.key_epoch ?? 0);
            const sMembersJson = String(serverObj.membership_snapshot ?? '');
            const sPolicyJson = String(serverObj.policy_snapshot ?? '');
            const sPrev = String(serverObj.prev_state_hash ?? '');
            if (sMembersJson && sHash) {
              const sMembers: Array<{ aid: string; role: string }> = sMembersJson ? JSON.parse(sMembersJson) : [];
              const sPolicy: Record<string, unknown> = sPolicyJson ? JSON.parse(sPolicyJson) : {};
              const computed = await computeStateHash({
                groupId, stateVersion: sv, keyEpoch: sEpoch,
                members: sMembers, policy: sPolicy, prevStateHash: sPrev,
              });
              if (computed !== sHash) {
                client._clientLog.warn(
                  '[aun_core] 回源 state_hash 验证失败 group=%s sv=%d expected=%s got=%s',
                  groupId, sv, sHash, computed,
                );
                return;
              }
            }

            const saveFn = client._tokenStore.saveGroupState;
            if (saveFn) {
              await saveFn.call(client._tokenStore, groupId, {
                group_id: groupId,
                state_version: sv,
                state_hash: sHash,
                key_epoch: sEpoch,
                membership_json: sMembersJson || membershipSnapshot,
                policy_json: sPolicyJson || policySnapshot,
                updated_at: Date.now(),
              });
            }
          }
        } catch (exc) {
          client._clientLog.warn(`state pull-back failed group=%s:${groupId} ${exc}`);
        }
        return;
      }

      const members: Array<{ aid: string; role: string }> = membershipSnapshot ? JSON.parse(membershipSnapshot) : [];
      const policy: Record<string, unknown> = policySnapshot ? JSON.parse(policySnapshot) : {};
      const computed = await computeStateHash({
        groupId, stateVersion, keyEpoch,
        members, policy, prevStateHash,
      });
      if (computed !== stateHash) {
        client._clientLog.warn(
          '[aun_core] state_hash 重算不匹配 group=%s sv=%d expected=%s got=%s',
          groupId, stateVersion, stateHash, computed,
        );
        return;
      }

      const saveFn = client._tokenStore.saveGroupState;
      if (saveFn) {
        await saveFn.call(client._tokenStore, groupId, {
          group_id: groupId,
          state_version: stateVersion,
          state_hash: stateHash,
          key_epoch: keyEpoch,
          membership_json: membershipSnapshot,
          policy_json: policySnapshot,
          updated_at: Date.now(),
        });
      }
      client._clientLog.debug(`_onGroupStateCommitted exit: elapsed=${Date.now() - tStart}ms group_id=${groupId}`);
    } catch (err) {
      client._clientLog.debug(`_onGroupStateCommitted exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  async autoProposeState(groupId: string, options?: { leaderDelay?: boolean }): Promise<void> {
    const client = this.client;
    const gid = normalizedGroupId(groupId);
    if (!gid) return;
    if (options?.leaderDelay) {
      const shouldContinue = await client._v2AutoProposeLeaderDelay(gid);
      if (!shouldContinue) return;
    }
    const inflight = client._v2AutoProposeInflight.get(gid);
    if (inflight) {
      client._v2AutoProposePending.add(gid);
      await inflight;
      return;
    }

    let resolveTask!: () => void;
    let rejectTask!: (error: unknown) => void;
    const task = new Promise<void>((resolve, reject) => {
      resolveTask = resolve;
      rejectTask = reject;
    });
    client._v2AutoProposeInflight.set(gid, task);
    void (async () => {
      try {
        do {
          client._v2AutoProposePending.delete(gid);
          await client._doV2AutoProposeState(gid);
        } while (client._v2AutoProposePending.delete(gid));
        resolveTask();
      } catch (exc) {
        rejectTask(exc);
      } finally {
        if (client._v2AutoProposeInflight.get(gid) === task) {
          client._v2AutoProposeInflight.delete(gid);
        }
        client._v2AutoProposePending.delete(gid);
      }
    })();
    try {
      await task;
    } finally {
      if (client._v2AutoProposeInflight.get(gid) === task) {
        client._v2AutoProposeInflight.delete(gid);
      }
      client._v2AutoProposePending.delete(gid);
    }
  }

  async leaderDelayMs(input: string): Promise<number> {
    const digest = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input)),
    );
    const first32 = new DataView(digest.buffer, digest.byteOffset, digest.byteLength)
      .getUint32(0, false);
    return 2000 + (first32 % 4000);
  }

  async autoProposeLeaderDelay(groupId: string): Promise<boolean> {
    const client = this.client;
    try {
      const membersResp = await client.call('group.get_online_members', { group_id: groupId }) as Record<string, unknown>;
      const members = (Array.isArray(membersResp?.members) ? membersResp.members
        : Array.isArray(membersResp?.items) ? membersResp.items
          : Array.isArray(membersResp?.online_members) ? membersResp.online_members : []) as Array<Record<string, unknown>>;
      const myAid = client._aid ?? '';
      let myRole = '';
      const onlineAdminAids = new Set<string>();
      for (const member of members) {
        const aid = String(member.aid ?? '').trim();
        const role = String(member.role ?? '').trim();
        if (!aid) continue;
        if ('online' in member && !Boolean(member.online)) continue;
        if (role === 'owner' || role === 'admin') onlineAdminAids.add(aid);
        if (aid === myAid) myRole = role;
      }
      if (myRole !== 'owner' && myRole !== 'admin') return false;

      const bootstrapResp = await client.call('group.v2.bootstrap', {
        group_id: groupId,
        e2ee_wrap_capabilities: v2WrapCapabilities(),
      }) as Record<string, unknown>;
      const devices = (Array.isArray(bootstrapResp?.devices) ? bootstrapResp.devices : []) as Array<Record<string, unknown>>;
      const candidates: string[] = [];
      for (const dev of devices) {
        const aid = String(dev.aid ?? '').trim();
        const hasDeviceId = 'device_id' in dev;
        const deviceId = String(dev.device_id ?? '').trim();
        if (aid && hasDeviceId && onlineAdminAids.has(aid)) {
          candidates.push(`${aid}\x1f${deviceId}`);
        }
      }
      if (candidates.length === 0) {
        for (const aid of [...onlineAdminAids].sort()) candidates.push(`${aid}\x1f`);
      }
      const myKey = `${myAid}\x1f${client._deviceId ?? ''}`;
      if (!candidates.includes(myKey)) candidates.push(myKey);
      const leader = [...new Set(candidates)].sort()[0];
      if (leader === myKey) {
        client._clientLog.debug(`V2 auto propose leader elected: group=${groupId} leader=${leader}`);
        return true;
      }

      const delayMs = await client._v2LeaderDelayMs(lengthPrefixedTextKey(groupId, myKey));
      client._clientLog.debug(`V2 auto propose non-leader delay: group=${groupId} leader=${leader} self=${myKey} delay_ms=${delayMs}`);
      await client._sleep(delayMs);
      return true;
    } catch (exc) {
      client._clientLog.debug(`V2 auto propose leader check failed, fallback immediate: group=${groupId} err=${formatCaughtError(exc)}`);
      return true;
    }
  }

  async verifyCommittedStateBase(groupId: string, stateResp: JsonObject): Promise<boolean> {
    const client = this.client;
    const currentSv = Number(stateResp.state_version ?? 0) || 0;
    if (currentSv <= 0) return true;
    const currentSh = String(stateResp.state_hash ?? '').trim();
    const membershipSnapshot = String(stateResp.membership_snapshot ?? '').trim();
    if (!currentSh || !membershipSnapshot) {
      client._clientLog.warn(`V2 committed state base incomplete: group=${groupId} sv=${currentSv}`);
      return false;
    }
    try {
      const parsed = JSON.parse(membershipSnapshot) as unknown;
      if (!isJsonObject(parsed)) {
        client._clientLog.warn(`V2 committed state base snapshot is not object: group=${groupId} sv=${currentSv}`);
        return false;
      }
      const computed = await computeStateCommitment(groupId, currentSv, parsed);
      if (computed !== currentSh) {
        client._clientLog.warn(`V2 committed state base hash mismatch: group=${groupId} sv=${currentSv}`);
        return false;
      }
      return true;
    } catch (exc) {
      client._clientLog.warn(`V2 committed state base verification failed: group=${groupId} sv=${currentSv} err=${formatCaughtError(exc)}`);
      return false;
    }
  }

  async doAutoProposeState(groupId: string): Promise<void> {
    const client = this.client;
    try {
      const membersResp = await client.call('group.get_members', { group_id: groupId }) as Record<string, unknown>;
      const members = (Array.isArray(membersResp?.members) ? membersResp.members
        : Array.isArray(membersResp?.items) ? membersResp.items : []) as Array<Record<string, unknown>>;
      const myAid = client._aid ?? '';
      let myRole = '';
      const memberAids: string[] = [];
      const adminAids: string[] = [];
      for (const m of members) {
        const aid = String(m.aid ?? '').trim();
        const role = String(m.role ?? '').trim();
        if (aid) {
          memberAids.push(aid);
          if (role === 'owner' || role === 'admin') adminAids.push(aid);
        }
        if (aid === myAid) myRole = role;
      }

      if (myRole !== 'owner' && myRole !== 'admin') return;

      const proposalResp = await client.call('group.v2.get_proposal', { group_id: groupId }) as Record<string, unknown> | null;
      if (proposalResp && typeof proposalResp === 'object') {
        const pendingProposal = proposalResp.proposal as Record<string, unknown> | null;
        if (pendingProposal && typeof pendingProposal === 'object' && String(pendingProposal.proposal_id ?? '').trim()) {
          const confirmed = await client._v2ConfirmPendingProposal(groupId);
          if (confirmed) return;
          const autoConfirmAt = Number(pendingProposal.auto_confirm_at ?? 0) || 0;
          const nowMs = Date.now();
          if (autoConfirmAt > nowMs) {
            const waitMs = Math.min(autoConfirmAt - nowMs + 500, 35000);
            client._clientLog.debug(`V2 auto propose: pending proposal exists, waiting ${waitMs}ms group=${groupId}`);
            await new Promise((r) => setTimeout(r, waitMs));
          }
        }
      }

      const bootstrapResp = await client.call('group.v2.bootstrap', {
        group_id: groupId,
        e2ee_wrap_capabilities: v2WrapCapabilities(),
      }) as Record<string, unknown>;
      const allDevices = (Array.isArray(bootstrapResp?.devices) ? bootstrapResp.devices : []) as Array<Record<string, unknown>>;
      const auditRecipients = (Array.isArray(bootstrapResp?.audit_recipients) ? bootstrapResp.audit_recipients : []) as Array<Record<string, unknown>>;
      const auditAidsList = [...new Set(
        auditRecipients.map(r => String(r.aid ?? '').trim()).filter(Boolean),
      )].sort();

      const membersWithDevices: Record<string, Array<{ device_id: string; ik_fp: string }>> = {};
      for (const aid of memberAids) membersWithDevices[aid] = [];
      for (const dev of allDevices) {
        const devAid = String(dev.aid ?? '').trim();
        if (devAid in membersWithDevices) {
          membersWithDevices[devAid].push({
            device_id: String(dev.device_id ?? ''),
            ik_fp: String(dev.ik_fp ?? ''),
          });
        }
      }

      const membersPayload = Object.entries(membersWithDevices).map(([aid, devices]) => ({
        aid,
        devices,
      }));

      const statePayload: Record<string, unknown> = {
        members: membersPayload,
        audit_aids: auditAidsList,
        admin_set: { admin_aids: adminAids.sort(), threshold: 1 },
        join_policy_hash: null,
        recovery_quorum: null,
        history_policy: 'recent_7_days',
        wrap_protocol: '3DH',
      };

      const stateResp = await client.call('group.get_state', { group_id: groupId }) as Record<string, unknown> | null;
      if (!stateResp || !isJsonObject(stateResp)) return;
      if (!(await this.verifyCommittedStateBase(groupId, stateResp))) return;
      const currentSv = Number(stateResp.state_version ?? 0);
      const currentSh = String(stateResp.state_hash ?? '');
      const keyEpoch = Number(stateResp.key_epoch ?? 0);

      const stateHash = await computeStateCommitment(groupId, currentSv + 1, statePayload);
      const membershipSnapshot = stableStringify(statePayload);
      const lastMembershipSnapshot = client._v2AutoProposeLastSnapshot.get(groupId);
      if (lastMembershipSnapshot === membershipSnapshot) {
        return;
      }
      const currentMembershipSnapshot = String(stateResp.membership_snapshot ?? '');
      if (currentMembershipSnapshot && currentMembershipSnapshot === membershipSnapshot) {
        client._v2AutoProposeLastSnapshot.set(groupId, membershipSnapshot);
        return;
      }
      let signature = '';
      const currentAid = client._currentAid;
      if (currentAid?.privateKeyPem) {
        try {
          const signPayloadObj = {
            group_id: groupId,
            membership_snapshot: membershipSnapshot,
            state_hash: stateHash,
            state_version: currentSv + 1,
          };
          const signPayload = stableStringify(signPayloadObj);
          const signPayloadBytes = new TextEncoder().encode(signPayload);
          const privKey = await importPrivateKeyEcdsa(currentAid.privateKeyPem);
          const sigBytes = await ecdsaSignDer(privKey, signPayloadBytes);
          signature = uint8ToBase64(sigBytes);
        } catch (sigExc) {
          client._clientLog.debug(`propose_state signature failed: ${sigExc}`);
        }
      }

      const proposeResult = await client.call('group.v2.propose_state', {
        group_id: groupId,
        state_version: currentSv + 1,
        key_epoch: keyEpoch,
        state_hash: stateHash,
        prev_state_hash: currentSh,
        membership_snapshot: membershipSnapshot,
        signature,
        reason: 'membership_changed',
        auto_confirm_seconds: 30,
      });
      client._clientLog.debug(`V2 auto propose_state: group=${groupId} sv=${currentSv + 1}`);
      const proposalId = isJsonObject(proposeResult) ? String(proposeResult.proposal_id ?? '').trim() : '';
      if (proposalId) {
        try {
          await client.call('group.v2.confirm_state', { proposal_id: proposalId });
          client._v2AutoProposeLastSnapshot.set(groupId, membershipSnapshot);
          client._clientLog.debug(`V2 auto confirm_state: group=${groupId} proposal=${proposalId}`);
        } catch (confirmExc) {
          client._clientLog.debug(`V2 auto confirm_state failed (non-fatal): group=${groupId} err=${confirmExc}`);
        }
      }
    } catch (exc) {
      client._clientLog.debug(`V2 auto propose_state failed (non-fatal): group=${groupId} err=${exc}`);
    }
  }

  async verifyPendingProposalAgainstBase(groupId: string, proposal: JsonObject, stateResp: JsonObject): Promise<boolean> {
    const client = this.client;
    if (!(await this.verifyCommittedStateBase(groupId, stateResp))) return false;
    const currentSv = Number(stateResp.state_version ?? 0) || 0;
    const currentSh = String(stateResp.state_hash ?? '').trim();
    const proposalSv = Number(proposal.state_version ?? 0) || 0;
    const proposalHash = String(proposal.state_hash ?? '').trim();
    const proposalPrev = String(proposal.prev_state_hash ?? '').trim();
    const membershipSnapshot = String(proposal.membership_snapshot ?? '').trim();
    if (proposalSv !== currentSv + 1 || proposalPrev !== currentSh || !proposalHash || !membershipSnapshot) {
      client._clientLog.warn(`V2 pending proposal base mismatch: group=${groupId} current_sv=${currentSv} proposal_sv=${proposalSv}`);
      return false;
    }
    try {
      const parsed = JSON.parse(membershipSnapshot) as unknown;
      if (!isJsonObject(parsed)) return false;
      const computed = await computeStateCommitment(groupId, proposalSv, parsed);
      if (computed !== proposalHash) {
        client._clientLog.warn(`V2 pending proposal hash mismatch: group=${groupId} proposal_sv=${proposalSv}`);
        return false;
      }
      return true;
    } catch (exc) {
      client._clientLog.warn(`V2 pending proposal verification failed: group=${groupId} err=${formatCaughtError(exc)}`);
      return false;
    }
  }

  async confirmPendingProposal(groupId: string): Promise<boolean> {
    const client = this.client;
    const proposalResp = await client.call('group.v2.get_proposal', { group_id: groupId }) as Record<string, unknown>;
    const proposal = isJsonObject(proposalResp?.proposal) ? proposalResp.proposal : null;
    const proposalId = proposal ? String(proposal.proposal_id ?? '').trim() : '';
    if (!proposal || !proposalId) return false;

    const stateResp = await client.call('group.get_state', { group_id: groupId }) as Record<string, unknown>;
    if (!isJsonObject(stateResp)) return false;
    const currentSv = Number(stateResp.state_version ?? 0) || 0;
    const proposalSv = Number(proposal.state_version ?? 0) || 0;
    if (proposalSv <= currentSv) {
      client._clientLog.debug(`V2 pending proposal already settled: group=${groupId} current_sv=${currentSv} proposal_sv=${proposalSv}`);
      return false;
    }
    if (!(await this.verifyPendingProposalAgainstBase(groupId, proposal, stateResp))) return false;

    await client.call('group.v2.confirm_state', { proposal_id: proposalId });
    client._clientLog.info(`V2 confirmed pending proposal: group=${groupId} proposal=${proposalId}`);
    return true;
  }

  async autoConfirmPendingProposals(): Promise<void> {
    const client = this.client;
    try {
      const myAid = client._aid ?? '';
      if (!myAid) return;
      const groupsResp = await client.call('group.list_my', {}) as Record<string, unknown>;
      const groups = (Array.isArray(groupsResp?.groups) ? groupsResp.groups
        : Array.isArray(groupsResp?.items) ? groupsResp.items : []) as Array<Record<string, unknown>>;
      for (const g of groups) {
        const gid = String(g.group_id ?? '').trim();
        const myRole = String(g.role ?? g.my_role ?? '').trim();
        if (!gid || (myRole !== 'owner' && myRole !== 'admin')) continue;
        try {
          const confirmed = await client._v2ConfirmPendingProposal(gid);
          if (!confirmed) {
            await client._v2AutoProposeState(gid);
          }
        } catch (exc) {
          client._clientLog.debug(`V2 auto confirm/propose failed (non-fatal): group=${gid} err=${exc}`);
        }
      }
    } catch (exc) {
      client._clientLog.debug(`V2 auto confirm pending proposals failed (non-fatal): ${exc}`);
    }
  }

  private extractGroupIdFromMutationResult(result: JsonObject, params: RpcParams): string {
    const client = this.client;
    const extracted = typeof client._extractGroupIdFromResult === 'function'
      ? client._extractGroupIdFromResult(result)
      : '';
    return normalizedGroupId(extracted || params.group_id || '');
  }

  private pruneSigCache(now: number): void {
    const client = this.client;
    if (!(client._v2SigCache instanceof Map) || client._v2SigCache.size <= V2_SIG_CACHE_MAX) return;
    const stale: string[] = [];
    for (const [key, exp] of client._v2SigCache) {
      if (exp <= now) stale.push(key);
    }
    for (const key of stale) client._v2SigCache.delete(key);
    if (client._v2SigCache.size <= V2_SIG_CACHE_MAX) return;
    const entries = [...client._v2SigCache.entries()].sort((a, b) => a[1] - b[1]);
    const evictCount = Math.floor(V2_SIG_CACHE_MAX / 4);
    for (let i = 0; i < evictCount && i < entries.length; i++) {
      client._v2SigCache.delete(entries[i][0]);
    }
  }

  private async checkMembershipTamper(
    groupId: string,
    bootstrap: Record<string, unknown>,
    membershipSnapshot: string,
  ): Promise<void> {
    const client = this.client;
    try {
      if (!membershipSnapshot.startsWith('[')) return;
      const signedSnapshot = JSON.parse(membershipSnapshot);
      if (!Array.isArray(signedSnapshot)) return;
      const serverMembers = new Set(
        Array.isArray(bootstrap.member_aids) ? (bootstrap.member_aids as string[]) : [],
      );
      const signedMembers = new Set(signedSnapshot);
      const extra: string[] = [];
      for (const m of serverMembers) {
        if (!signedMembers.has(m)) extra.push(m);
      }
      if (extra.length === 0) return;

      let mode = '';
      try {
        const reqResp = await client.call('group.get_join_requirements', { group_id: groupId }) as Record<string, unknown> | null;
        mode = isJsonObject(reqResp)
          ? String((reqResp as JsonObject).mode ?? '').trim()
          : '';
      } catch {
        mode = '';
      }
      if (mode !== 'open' && mode !== 'invite_code' && mode !== 'invite_only') {
        client._clientLog.warn(`V2 state tamper detected: group=${groupId} pending_extra=${extra.sort().join(',')} mode=${mode}`);
        await client._dispatcher.publish('group.v2.state_tampered', {
          group_id: groupId,
          pending_extra: extra.sort(),
          mode,
        });
      }
    } catch {
      // snapshot 解析失败不阻断已完成的签名验证。
    }
  }
}
