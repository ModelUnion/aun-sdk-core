import * as crypto from 'node:crypto';

import { E2EEError } from '../errors.js';
import { normalizeGroupId } from '../group-id.js';
import type { EventPayload } from '../events.js';
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

function lengthPrefixedBytesKey(...parts: Uint8Array[]): Buffer {
  const chunks: Buffer[] = [];
  for (const part of parts) {
    chunks.push(
      Buffer.from(`${part.byteLength}:`, 'ascii'),
      Buffer.from(part.buffer, part.byteOffset, part.byteLength),
      Buffer.from(';', 'ascii'),
    );
  }
  return Buffer.concat(chunks);
}

function lengthPrefixedTextKey(...parts: string[]): string {
  return parts.map((part) => `${Buffer.byteLength(part, 'utf8')}:${part};`).join('');
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

function computeStateHash(params: {
  groupId: string;
  stateVersion: number;
  keyEpoch: number;
  members: Array<{ aid: string; role: string }>;
  policy: Record<string, unknown>;
  prevStateHash: string;
}): string {
  const sortedMembers = [...params.members].sort((a, b) => a.aid.localeCompare(b.aid));
  const membershipBlock = sortedMembers.map(m => `${m.aid}:${m.role}`).join('|');
  const sortedPolicy: Record<string, unknown> = {};
  for (const key of Object.keys(params.policy).sort()) {
    sortedPolicy[key] = params.policy[key];
  }
  const policyBlock = Object.keys(params.policy).length > 0 ? JSON.stringify(sortedPolicy) : '';
  const prevBytes = params.prevStateHash ? Buffer.from(params.prevStateHash, 'hex') : Buffer.alloc(32);
  const svBuf = Buffer.alloc(8);
  svBuf.writeBigUInt64BE(BigInt(params.stateVersion));
  const keBuf = Buffer.alloc(8);
  keBuf.writeBigUInt64BE(BigInt(params.keyEpoch));
  const data = Buffer.concat([
    Buffer.from(params.groupId, 'utf-8'), Buffer.from([0x00]),
    svBuf, Buffer.from([0x00]),
    keBuf, Buffer.from([0x00]),
    Buffer.from(membershipBlock, 'utf-8'), Buffer.from([0x00]),
    Buffer.from(policyBlock, 'utf-8'), Buffer.from([0x00]),
    prevBytes,
  ]);
  return crypto.createHash('sha256').update(data).digest('hex');
}

function normalizedGroupId(raw: unknown): string {
  const groupId = String(raw ?? '').trim();
  return normalizeGroupId(groupId) || groupId;
}

function groupCacheIds(raw: unknown, groupId: string): string[] {
  const ids: string[] = [];
  for (const value of [groupId, String(raw ?? '').trim()]) {
    if (value && !ids.includes(value)) ids.push(value);
  }
  return ids;
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
    const resultObj = isJsonObject(result as JsonValue | object | null | undefined) ? result as JsonObject : null;
    if (!MEMBERSHIP_MUTATION_METHODS.has(method) || !resultObj || 'error' in resultObj || !client._v2Session) {
      return result;
    }

    const groupId = this.extractGroupIdFromMutationResult(resultObj, params);
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
    const rawGroupId = data.group_aid ?? data.group_id;
    const groupId = normalizedGroupId(rawGroupId);
    const action = String(data.action ?? '').trim();
    if (!groupId) {
      return;
    }

    for (const cacheGroupId of groupCacheIds(rawGroupId, groupId)) {
      client._v2E2EE?.deleteBootstrapCacheEntry?.(`group:${cacheGroupId}`);
    }
    const membershipAction = MEMBERSHIP_ACTIONS.has(action);
    if (client._v2Session && (action === 'upsert' || membershipAction)) {
      client._safeAsync(client._v2AutoProposeState(groupId, { leaderDelay: true }));
    }
    client._v2E2EE?.handleGroupChangedSpk?.(data, groupId, action);
  }

  async onV2StateProposed(data: EventPayload): Promise<void> {
    const client = this.client;
    const d = isJsonObject(data as JsonValue | object | null | undefined) ? data as JsonObject : null;
    if (!d || !client._v2Session) return;
    const groupId = normalizedGroupId(d.group_aid ?? d.group_id);
    if (!groupId) return;
    await client._dispatcher.publish('group.v2.state_proposed', d);
    try {
      await client._v2ConfirmPendingProposal(groupId);
    } catch (exc) {
      client._clientLog.debug(`V2 state_proposed handling failed (non-fatal): group=${groupId} err=${formatCaughtError(exc)}`);
    }
  }

  async onV2StateRetryNeeded(data: EventPayload): Promise<void> {
    const client = this.client;
    const d = isJsonObject(data as JsonValue | object | null | undefined) ? data as JsonObject : null;
    if (!d || !client._v2Session) return;
    const groupId = normalizedGroupId(d.group_aid ?? d.group_id);
    if (!groupId) return;
    await client._dispatcher.publish('group.v2.state_retry_needed', d);
    try {
      await client._v2AutoProposeState(groupId, { leaderDelay: true });
    } catch (exc) {
      client._clientLog.debug(`V2 state_retry_needed handling failed (non-fatal): group=${groupId} err=${formatCaughtError(exc)}`);
    }
  }

  async onV2StateConfirmed(data: EventPayload): Promise<void> {
    const client = this.client;
    const d = isJsonObject(data as JsonValue | object | null | undefined) ? data as JsonObject : null;
    if (!d) return;
    const rawGroupId = d.group_aid ?? d.group_id;
    const groupId = normalizedGroupId(rawGroupId);
    if (groupId) {
      for (const cacheGroupId of groupCacheIds(rawGroupId, groupId)) {
        client._v2E2EE?.deleteBootstrapCacheEntry?.(`group:${cacheGroupId}`);
      }
      client._v2AutoProposeLastSnapshot?.delete?.(groupId);
    }
    await client._dispatcher.publish('group.v2.state_confirmed', d);
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
      const sigBytes = Buffer.from(stateSignature, 'base64');
      const framedPayload = lengthPrefixedBytesKey(
        Buffer.from(actorAid, 'utf-8'),
        Buffer.from(signPayload, 'utf-8'),
      );
      const cacheKey = crypto.createHash('sha256')
        .update(framedPayload)
        .update(sigBytes)
        .digest('hex');

      const sigCache = this.runtime.groupState.sigCache;
      const now = Date.now();
      const cachedExp = sigCache.get(cacheKey);
      if (cachedExp === undefined || cachedExp <= now) {
        const certPem = await client._fetchPeerCert(actorAid);
        const cert = new crypto.X509Certificate(certPem);
        const ok = crypto.verify('SHA256', Buffer.from(signPayload, 'utf-8'), cert.publicKey, sigBytes);
        if (!ok) {
          throw new E2EEError(`V2 state signature verification failed: group=${gid} actor=${actorAid}`);
        }
        sigCache.set(cacheKey, now + V2_SIG_CACHE_TTL_MS);
        this.pruneSigCache(now);
      } else {
        client._clientLog.debug(`V2 state signature cache hit: group=${gid} sv=${stateVersion}`);
      }

      await this.checkMembershipTamper(gid, bootstrap, membershipSnapshot);
    } catch (exc) {
      if (exc instanceof E2EEError) throw exc;
      throw new E2EEError(`V2 state signature verification failed: ${formatCaughtError(exc)}`);
    }
  }

  async checkFork(groupId: string, serverChain: string): Promise<void> {
    const client = this.client;
    const gid = normalizedGroupId(groupId);
    if (!gid || !serverChain) return;
    try {
      const stateChains = this.runtime.groupState.chains;
      const local = stateChains.get(gid);
      if (!local) {
        stateChains.set(gid, [0, serverChain]);
        return;
      }
      const [localSv, localChain] = local;
      if (localChain === serverChain) return;
      try {
        const stateResp = await client.call('group.get_state', { group_id: gid });
        if (isJsonObject(stateResp as JsonValue | object | null | undefined)) {
          const serverSv = Number((stateResp as JsonObject).state_version ?? 0);
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
    if (!isJsonObject(data as JsonValue | object | null | undefined)) {
      client._clientLog.debug(`_onGroupStateCommitted exit: elapsed=${Date.now() - tStart}ms (non-object payload)`);
      return;
    }
    const d = data as JsonObject;
    const groupId = normalizedGroupId(d.group_aid ?? d.group_id);
    if (!groupId) {
      client._clientLog.debug(`_onGroupStateCommitted exit: elapsed=${Date.now() - tStart}ms (no group_id)`);
      return;
    }
    client._clientLog.debug(`_onGroupStateCommitted enter: group_id=${groupId}, state_version=${String(d.state_version ?? '')}`);
    try {
      const cs = d.client_signature;
      if (cs && isJsonObject(cs as JsonValue | object | null | undefined)) {
        if (client._shouldSkipEventSignature(d)) {
          delete d.client_signature;
        } else {
          const verified = await client._verifyEventSignatureAsync(d, cs);
          if (verified === false) {
            client._clientLog.warn(`state_committed committer signature verification failed group=${groupId}`);
            return;
          }
          d._verified = verified;
        }
      }

      const stateVersion = Number(d.state_version ?? 0);
      const stateHash = String(d.state_hash ?? '').trim();
      const prevStateHash = String(d.prev_state_hash ?? '').trim();
      const keyEpoch = Number(d.key_epoch ?? 0);
      const membershipSnapshot = String(d.membership_snapshot ?? '').trim();
      const policySnapshot = String(d.policy_snapshot ?? '').trim();

      const loadFn = client._tokenStore.loadGroupState;
      const localState = loadFn ? loadFn.call(client._tokenStore, groupId) : null;
      if (localState && localState.state_hash && localState.state_hash !== prevStateHash) {
        client._clientLog.warn(`state_hash chain discontinuous group=${groupId} local_sv=${localState.state_version} event_sv=${stateVersion}`);
        try {
          const serverState = await client._transport.call('group.get_state', { group_id: groupId });
          if (serverState && isJsonObject(serverState as JsonValue | object | null | undefined) && 'state_version' in serverState) {
            const stateObj = serverState as JsonObject;
            const sv = Number(stateObj.state_version ?? 0);
            const sHash = String(stateObj.state_hash ?? '');
            const sEpoch = Number(stateObj.key_epoch ?? 0);
            const sMembersJson = String(stateObj.membership_snapshot ?? '');
            const sPolicyJson = String(stateObj.policy_snapshot ?? '');
            const sPrev = String(stateObj.prev_state_hash ?? '');
            if (sMembersJson && sHash) {
              const sMembers: Array<{ aid: string; role: string }> = sMembersJson ? JSON.parse(sMembersJson) : [];
              const sPolicy: Record<string, unknown> = sPolicyJson ? JSON.parse(sPolicyJson) : {};
              const computed = computeStateHash({
                groupId, stateVersion: sv, keyEpoch: sEpoch,
                members: sMembers, policy: sPolicy, prevStateHash: sPrev,
              });
              if (computed !== sHash) {
                client._clientLog.warn(`backfill state_hash verification failed group=${groupId} sv=${sv} expected=${sHash} got=${computed}`);
                return;
              }
            }
            const saveFn = client._tokenStore.saveGroupState;
            if (saveFn) {
              saveFn.call(client._tokenStore, groupId, sv, sHash, sEpoch, sMembersJson || membershipSnapshot, sPolicyJson || policySnapshot);
            }
          }
        } catch (exc) {
          client._clientLog.warn(`state backfill failed group=${groupId}: ${formatCaughtError(exc)}`);
        }
        return;
      }

      const members: Array<{ aid: string; role: string }> = membershipSnapshot ? JSON.parse(membershipSnapshot) : [];
      const policy: Record<string, unknown> = policySnapshot ? JSON.parse(policySnapshot) : {};
      const computed = computeStateHash({
        groupId, stateVersion, keyEpoch,
        members, policy, prevStateHash,
      });
      if (computed !== stateHash) {
        client._clientLog.warn(`state_hash recompute mismatch group=${groupId} sv=${stateVersion} expected=${stateHash} got=${computed}`);
        return;
      }

      const saveFn = client._tokenStore.saveGroupState;
      if (saveFn) {
        saveFn.call(client._tokenStore, groupId, stateVersion, stateHash, keyEpoch, membershipSnapshot, policySnapshot);
      }
      client._clientLog.debug(`_onGroupStateCommitted exit: elapsed=${Date.now() - tStart}ms group=${groupId}`);
    } catch (err) {
      client._clientLog.debug(`_onGroupStateCommitted exit (error): elapsed=${Date.now() - tStart}ms group=${groupId} err=${err instanceof Error ? err.message : String(err)}`);
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

    let resolveTask: () => void;
    let rejectTask: (error: unknown) => void;
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
        resolveTask!();
      } catch (exc) {
        rejectTask!(exc);
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

  leaderDelayMs(input: string): number {
    let h = 2166136261;
    for (let i = 0; i < input.length; i++) {
      h ^= input.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return 2000 + ((h >>> 0) % 4000);
  }

  async autoProposeLeaderDelay(groupId: string): Promise<boolean> {
    const client = this.client;
    try {
      const membersResp = await client.call('group.get_online_members', { group_id: groupId });
      const members = isJsonObject(membersResp as JsonValue | object | null | undefined)
        ? (Array.isArray((membersResp as JsonObject).members) ? (membersResp as JsonObject).members
          : Array.isArray((membersResp as JsonObject).items) ? (membersResp as JsonObject).items
            : Array.isArray((membersResp as JsonObject).online_members) ? (membersResp as JsonObject).online_members : [])
        : [];
      if (!Array.isArray(members)) return true;

      const myAid = client._aid ?? '';
      let myRole = '';
      const onlineAdminAids = new Set<string>();
      for (const item of members) {
        if (!isJsonObject(item as JsonValue | object | null | undefined)) continue;
        const aid = String((item as JsonObject).aid ?? '').trim();
        const role = String((item as JsonObject).role ?? '').trim();
        if (!aid) continue;
        if ('online' in (item as JsonObject) && !Boolean((item as JsonObject).online)) continue;
        if (role === 'owner' || role === 'admin') onlineAdminAids.add(aid);
        if (aid === myAid) myRole = role;
      }
      if (myRole !== 'owner' && myRole !== 'admin') return false;

      const bootstrapResp = await client.call('group.v2.bootstrap', {
        group_id: groupId,
        e2ee_wrap_capabilities: v2WrapCapabilities(),
      });
      const devices = isJsonObject(bootstrapResp as JsonValue | object | null | undefined) && Array.isArray((bootstrapResp as JsonObject).devices)
        ? ((bootstrapResp as JsonObject).devices as unknown[]).filter((item): item is JsonObject => isJsonObject(item as JsonValue | object | null | undefined))
        : [];
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

      const delayMs = client._v2LeaderDelayMs(lengthPrefixedTextKey(groupId, myKey));
      client._clientLog.debug(`V2 auto propose non-leader delay: group=${groupId} leader=${leader} self=${myKey} delay_ms=${delayMs}`);
      await client._sleep(delayMs);
      return true;
    } catch (exc) {
      client._clientLog.debug(`V2 auto propose leader check failed, fallback immediate: group=${groupId} err=${formatCaughtError(exc)}`);
      return true;
    }
  }

  verifyCommittedStateBase(groupId: string, stateResp: JsonObject): boolean {
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
      const parsed = JSON.parse(membershipSnapshot) as JsonValue;
      if (!isJsonObject(parsed)) {
        client._clientLog.warn(`V2 committed state base snapshot is not object: group=${groupId} sv=${currentSv}`);
        return false;
      }
      const computed = computeStateCommitment(
        groupId,
        currentSv,
        parsed as Parameters<typeof computeStateCommitment>[2],
      );
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
      const myAid = client._aid ?? '';
      if (!myAid) return;

      const membersResp = await client.call('group.get_members', { group_id: groupId });
      const members = isJsonObject(membersResp as JsonValue | object | null | undefined)
        ? (Array.isArray((membersResp as JsonObject).members) ? (membersResp as JsonObject).members : (membersResp as JsonObject).items)
        : [];
      if (!Array.isArray(members)) return;

      let myRole = '';
      const memberAids: string[] = [];
      const adminAids: string[] = [];
      for (const item of members) {
        if (!isJsonObject(item as JsonValue | object | null | undefined)) continue;
        const aid = String((item as JsonObject).aid ?? '').trim();
        const role = String((item as JsonObject).role ?? '').trim();
        if (!aid) continue;
        memberAids.push(aid);
        if (role === 'owner' || role === 'admin') adminAids.push(aid);
        if (aid === myAid) myRole = role;
      }
      if (myRole !== 'owner' && myRole !== 'admin') return;

      const proposalResp = await client.call('group.v2.get_proposal', { group_id: groupId });
      if (isJsonObject(proposalResp as JsonValue | object | null | undefined)) {
        const pendingProposal = (proposalResp as JsonObject).proposal;
        if (isJsonObject(pendingProposal as JsonValue | object | null | undefined) && String((pendingProposal as JsonObject).proposal_id ?? '').trim()) {
          const confirmed = await client._v2ConfirmPendingProposal(groupId);
          if (confirmed) return;
          const autoConfirmAt = Number((pendingProposal as JsonObject).auto_confirm_at ?? 0) || 0;
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
      });
      const allDevices = isJsonObject(bootstrapResp as JsonValue | object | null | undefined) && Array.isArray((bootstrapResp as JsonObject).devices)
        ? ((bootstrapResp as JsonObject).devices as unknown[]).filter((item): item is JsonObject => isJsonObject(item as JsonValue | object | null | undefined))
        : [];
      const auditRecipients = isJsonObject(bootstrapResp as JsonValue | object | null | undefined) && Array.isArray((bootstrapResp as JsonObject).audit_recipients)
        ? ((bootstrapResp as JsonObject).audit_recipients as unknown[]).filter((item): item is JsonObject => isJsonObject(item as JsonValue | object | null | undefined))
        : [];
      const auditAids = [...new Set(
        auditRecipients.map((item) => String(item.aid ?? '').trim()).filter(Boolean),
      )].sort();

      const membersWithDevices: Record<string, Array<{ device_id: string; ik_fp: string }>> = {};
      for (const aid of memberAids) membersWithDevices[aid] = [];
      for (const dev of allDevices) {
        const aid = String(dev.aid ?? '').trim();
        if (aid in membersWithDevices) {
          membersWithDevices[aid].push({
            device_id: String(dev.device_id ?? ''),
            ik_fp: String(dev.ik_fp ?? ''),
          });
        }
      }
      const statePayload: Record<string, unknown> = {
        members: Object.entries(membersWithDevices).map(([aid, devices]) => ({ aid, devices })),
        audit_aids: auditAids,
        admin_set: { admin_aids: adminAids.sort(), threshold: 1 },
        join_policy_hash: null,
        recovery_quorum: null,
        history_policy: 'recent_7_days',
        wrap_protocol: '3DH',
      };

      const stateResp = await client.call('group.get_state', { group_id: groupId });
      if (!isJsonObject(stateResp as JsonValue | object | null | undefined)) return;
      if (!this.verifyCommittedStateBase(groupId, stateResp as JsonObject)) return;
      const currentSv = Number((stateResp as JsonObject).state_version ?? 0) || 0;
      const currentSh = String((stateResp as JsonObject).state_hash ?? '');
      const keyEpoch = Number((stateResp as JsonObject).key_epoch ?? 0) || 0;
      const stateHash = computeStateCommitment(groupId, currentSv + 1, statePayload);
      const membershipSnapshot = stableStringify(statePayload);
      const lastMembershipSnapshot = client._v2AutoProposeLastSnapshot.get(groupId);
      if (lastMembershipSnapshot === membershipSnapshot) return;

      const currentMembershipSnapshot = String((stateResp as JsonObject).membership_snapshot ?? '');
      if (currentMembershipSnapshot && currentMembershipSnapshot === membershipSnapshot) {
        client._v2AutoProposeLastSnapshot.set(groupId, membershipSnapshot);
        return;
      }

      let signature = '';
      const privateKeyPem = client._currentAid?.privateKeyPem ?? '';
      if (privateKeyPem) {
        try {
          const signPayload = stableStringify({
            group_id: groupId,
            membership_snapshot: membershipSnapshot,
            state_hash: stateHash,
            state_version: currentSv + 1,
          });
          const key = crypto.createPrivateKey(privateKeyPem);
          signature = crypto.sign('SHA256', Buffer.from(signPayload, 'utf-8'), key).toString('base64');
        } catch (exc) {
          client._clientLog.debug(`V2 propose_state signature failed: ${formatCaughtError(exc)}`);
        }
      }

      const propose = await client.call('group.v2.propose_state', {
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
      const proposalId = isJsonObject(propose as JsonValue | object | null | undefined) ? String((propose as JsonObject).proposal_id ?? '').trim() : '';
      if (proposalId) {
        try {
          await client.call('group.v2.confirm_state', { proposal_id: proposalId });
          client._v2AutoProposeLastSnapshot.set(groupId, membershipSnapshot);
        } catch (exc) {
          client._clientLog.debug(`V2 auto confirm_state failed (non-fatal): group=${groupId} err=${formatCaughtError(exc)}`);
        }
      }
    } catch (exc) {
      client._clientLog.debug(`V2 auto propose_state failed (non-fatal): group=${groupId} err=${formatCaughtError(exc)}`);
    }
  }

  verifyPendingProposalAgainstBase(groupId: string, proposal: JsonObject, stateResp: JsonObject): boolean {
    const client = this.client;
    if (!this.verifyCommittedStateBase(groupId, stateResp)) return false;
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
      const parsed = JSON.parse(membershipSnapshot) as JsonValue;
      if (!isJsonObject(parsed)) return false;
      const computed = computeStateCommitment(
        groupId,
        proposalSv,
        parsed as Parameters<typeof computeStateCommitment>[2],
      );
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
    const proposalResp = await client.call('group.v2.get_proposal', { group_id: groupId });
    const proposal = isJsonObject(proposalResp as JsonValue | object | null | undefined)
      && isJsonObject((proposalResp as JsonObject).proposal as JsonValue | object | null | undefined)
      ? (proposalResp as JsonObject).proposal as JsonObject
      : null;
    const proposalId = proposal ? String(proposal.proposal_id ?? '').trim() : '';
    if (!proposal || !proposalId) return false;

    const stateResp = await client.call('group.get_state', { group_id: groupId });
    if (!isJsonObject(stateResp as JsonValue | object | null | undefined)) return false;
    const currentSv = Number((stateResp as JsonObject).state_version ?? 0) || 0;
    const proposalSv = Number(proposal.state_version ?? 0) || 0;
    if (proposalSv <= currentSv) {
      client._clientLog.debug(`V2 pending proposal already settled: group=${groupId} current_sv=${currentSv} proposal_sv=${proposalSv}`);
      return false;
    }
    if (!this.verifyPendingProposalAgainstBase(groupId, proposal, stateResp as JsonObject)) return false;

    await client.call('group.v2.confirm_state', { proposal_id: proposalId });
    client._clientLog.info(`V2 confirmed pending proposal: group=${groupId} proposal=${proposalId}`);
    return true;
  }

  async autoConfirmPendingProposals(): Promise<void> {
    const client = this.client;
    try {
      const myAid = client._aid ?? '';
      if (!myAid) return;
      const groupsResp = await client.call('group.list_my', {});
      const groups = isJsonObject(groupsResp as JsonValue | object | null | undefined)
        ? (Array.isArray((groupsResp as JsonObject).groups) ? (groupsResp as JsonObject).groups : (groupsResp as JsonObject).items)
        : [];
      if (!Array.isArray(groups)) return;
      for (const group of groups) {
        if (!isJsonObject(group as JsonValue | object | null | undefined)) continue;
        const groupId = normalizedGroupId((group as JsonObject).group_aid ?? (group as JsonObject).group_id);
        const myRole = String((group as JsonObject).role ?? (group as JsonObject).my_role ?? '').trim();
        if (!groupId || (myRole !== 'owner' && myRole !== 'admin')) continue;
        try {
          const confirmed = await client._v2ConfirmPendingProposal(groupId);
          if (!confirmed) {
            await client._v2AutoProposeState(groupId);
          }
        } catch (exc) {
          client._clientLog.debug(`V2 auto confirm/propose failed (non-fatal): group=${groupId} err=${formatCaughtError(exc)}`);
        }
      }
    } catch (exc) {
      client._clientLog.debug(`V2 auto confirm pending proposals failed (non-fatal): ${formatCaughtError(exc)}`);
    }
  }

  private extractGroupIdFromMutationResult(result: JsonObject, params: RpcParams): string {
    const client = this.client;
    const extracted = typeof client._extractGroupIdFromResult === 'function'
      ? client._extractGroupIdFromResult(result)
      : '';
    return normalizedGroupId(extracted || params.group_aid || params.group_id || '');
  }

  private pruneSigCache(now: number): void {
    const client = this.client;
    if (!(client._v2SigCache instanceof Map) || client._v2SigCache.size <= V2_SIG_CACHE_MAX) return;
    for (const [key, exp] of client._v2SigCache) {
      if (exp <= now) client._v2SigCache.delete(key);
    }
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
      const signedMembers = new Set(signedSnapshot.map((item) => String(item)));
      const serverMembers = Array.isArray(bootstrap.member_aids)
        ? bootstrap.member_aids.map((item) => String(item))
        : [];
      const extra = serverMembers.filter((aid) => !signedMembers.has(aid));
      if (extra.length === 0) return;

      let mode = '';
      try {
        const resp = await client.call('group.get_settings', { group_id: groupId, keys: ['join.mode'] });
        const settings: Record<string, unknown> = {};
        if (isJsonObject(resp as JsonValue | object | null | undefined) && Array.isArray((resp as JsonObject).settings)) {
          for (const s of (resp as JsonObject).settings as unknown[]) {
            if (isJsonObject(s as JsonValue | object | null | undefined) && typeof (s as JsonObject).key === 'string') {
              settings[(s as JsonObject).key as string] = (s as JsonObject).value;
            }
          }
        }
        mode = String(settings['join.mode'] ?? '');
      } catch {
        mode = '';
      }
      if (!['open', 'invite_code', 'invite_only'].includes(mode)) {
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
