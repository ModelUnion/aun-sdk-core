/**
 * V2 E2EE Session Manager。
 *
 * 管理本设备的 IK/SPK 生命周期、服务端注册、加解密密钥获取。
 *
 * 设计要点：
 * - IK = AID 长期密钥（多设备共享 AID 身份），不独立生成
 * - SPK 设备级 P-256 密钥对，IK 签名背书
 * - SPK 销毁三重条件：
 *   - contig_seq >= 该 SPK 引用的最大 seq
 *   - 自最后一次见到该 spk_id >= 7 天
 *   - 不在最近 7 代保留窗口内
 * - 对端 IK 公钥缓存 TTL 1 小时
 * - SPK 注册：调 callFn("message.v2.put_peer_pk", ...)
 */

import { createHash } from 'node:crypto';
import { normalizeGroupId } from '../../group-id.js';
import { generateP256Keypair } from '../crypto/ecdh.js';
import { ecdsaSignRaw } from '../crypto/ecdsa.js';
import { V2KeyStore } from './keystore.js';

/** 对端 IK 公钥缓存 TTL（毫秒）。 */
export const PEER_KEY_CACHE_TTL_MS = 60 * 60 * 1000; // 1h
/** SPK 销毁安全窗口（毫秒）。 */
export const DESTROY_DELAY_MS = 7 * 24 * 60 * 60 * 1000; // 7 天
/** SPK 销毁时保留的最近代数。 */
export const RECENT_GENERATIONS = 7;
export const HARD_LIMIT_MS = 180 * 24 * 60 * 60 * 1000; // 180 天

/** 服务端 RPC 调用函数签名（与 Python `call_fn` 等价）。 */
export type CallFn = (
  method: string,
  params: Record<string, unknown>,
) => Promise<Record<string, unknown> | unknown>;

/** 加密所需的发送方身份。 */
export interface SenderIdentity {
  aid: string;
  deviceId: string;
  ikPriv: Uint8Array;
  ikPubDer: Uint8Array;
}

export class V2Session {
  private readonly _store: V2KeyStore;
  private readonly _deviceId: string;
  private readonly _aid: string;
  private readonly _ikPriv: Uint8Array;
  private readonly _ikPubDer: Uint8Array;

  private _spkId = '';
  private _spkPriv?: Uint8Array;
  private _spkPubDer?: Uint8Array;
  private _registered = false;

  // SPK 上传去重
  private _lastUploadedSPKId = '';
  private _lastUploadedGroupSPKIds = new Map<string, string>();

  private _peerIKCache = new Map<string, { pubDer: Uint8Array; cachedAt: number }>();
  private _verifiedSPKs = new Set<string>();
  private _oldSPKMaxSeq = new Map<string, { seq: number; lastSeenAt: number }>();
  private _spkCache = new Map<string, Uint8Array>();
  private _nowFn: () => number = () => Date.now();

  constructor(
    store: V2KeyStore,
    deviceId: string,
    aid: string,
    ikPriv: Uint8Array,
    ikPubDer: Uint8Array,
  ) {
    if (!ikPriv || !ikPubDer) {
      throw new Error('V2Session requires AID priv/pub keys (IK = AID identity)');
    }
    this._store = store;
    this._deviceId = deviceId;
    this._aid = aid;
    this._ikPriv = ikPriv;
    this._ikPubDer = ikPubDer;
    this._store.saveIK(this._deviceId, this._ikPriv, this._ikPubDer);
  }

  /** 测试用：注入虚拟时钟。 */
  _setNowFn(fn: () => number): void {
    this._nowFn = fn;
  }

  get deviceId(): string {
    return this._deviceId;
  }

  get aid(): string {
    return this._aid;
  }

  get currentSpkId(): string {
    return this._spkId;
  }

  get currentIkPubDer(): Uint8Array {
    return this._ikPubDer;
  }

  /** 暴露 store 便于测试（与 Python 同等私有约定）。 */
  get _storeForTest(): V2KeyStore {
    return this._store;
  }

  /** 加载或生成当前 SPK；IK 由构造函数注入，无需加载。 */
  ensureKeys(): void {
    if (this._spkPriv) return;
    const cur = this._store.loadCurrentSPK(this._deviceId);
    if (cur) {
      this._spkId = cur.spkId;
      this._spkPriv = cur.priv;
      this._spkPubDer = cur.pubDer;
      return;
    }
    this._generateNewSPK();
  }

  private _generateNewSPK(): void {
    const [priv, pubDer] = generateP256Keypair();
    const hashHex = createHash('sha256').update(pubDer).digest('hex');
    const spkId = `sha256:${hashHex.substring(0, 16)}`;
    this._store.saveSPK(this._deviceId, spkId, priv, pubDer);
    this._spkId = spkId;
    this._spkPriv = priv;
    this._spkPubDer = pubDer;
  }

  private _ikSPKId(): string {
    const hashHex = createHash('sha256').update(this._ikPubDer).digest('hex');
    return `sha256:${hashHex.substring(0, 16)}`;
  }

  private _groupKey(groupId: string): string {
    return normalizeGroupId(groupId) || String(groupId ?? '').trim();
  }

  private _groupLookupCandidates(groupId: string): string[] {
    const raw = String(groupId ?? '').trim();
    const normalized = this._groupKey(raw);
    const out: string[] = [];
    for (const item of [normalized, raw]) {
      if (item && !out.includes(item)) out.push(item);
    }
    return out;
  }

  private _normalizeGroupSPKLookup(groupId: string, spkId: string): { groupId: string; spkId: string } {
    const nul = spkId.indexOf('\0');
    if (nul < 0) return { groupId: this._groupKey(groupId), spkId };
    return { groupId: this._groupKey(spkId.slice(0, nul)), spkId: spkId.slice(nul + 1) };
  }

  /** 注册本设备 SPK 到服务端。IK = AID 长期密钥，无需注册。 */
  async ensureRegistered(callFn: CallFn): Promise<void> {
    if (this._registered) return;
    this.ensureKeys();
    const uploadedSPKId = this._store.loadLatestUploadedSPKId(this._deviceId);
    if (uploadedSPKId) {
      this._registered = true;
      this._lastUploadedSPKId = uploadedSPKId;
      return;
    }
    await this._registerSPK(callFn);
    this._store.markSPKUploaded(this._deviceId, this._spkId);
    this._registered = true;
    this._lastUploadedSPKId = this._spkId;
  }

  /** SPK 由 AID 私钥（IK）签名背书，并上报到 message.v2.put_peer_pk。 */
  private async _registerSPK(callFn: CallFn): Promise<void> {
    const spkTimestamp = Math.floor(this._nowFn() / 1000);
    const signData = Buffer.concat([
      Buffer.from(this._spkPubDer!),
      Buffer.from(this._spkId, 'utf-8'),
      Buffer.from(String(spkTimestamp), 'utf-8'),
    ]);
    const signature = ecdsaSignRaw(this._ikPriv, signData);
    await callFn('message.v2.put_peer_pk', {
      peer_aid: this._aid,
      key_source: 'peer_device_prekey',
      spk_id: this._spkId,
      spk_pk: Buffer.from(this._spkPubDer!).toString('base64'),
      spk_signature: Buffer.from(signature).toString('base64'),
      spk_timestamp: spkTimestamp,
    });
  }

  /** 返回加密所需的 sender 结构。 */
  getSenderIdentity(): SenderIdentity {
    this.ensureKeys();
    return {
      aid: this._aid,
      deviceId: this._deviceId,
      ikPriv: this._ikPriv,
      ikPubDer: this._ikPubDer,
    };
  }

  /**
   * 返回解密所需的私钥。
   * - spkId 空：1DH（仅 IK）
   * - spkId == 当前/历史 device SPK：对应 spkPriv
   * - spkId == IK 指纹：走 IK 特殊 fallback，返回 IK 私钥作为 spkPriv
   * - 否则：显式报 spk_missing
   */
  getDecryptKeys(spkId: string | null | undefined): { ikPriv: Uint8Array; spkPriv?: Uint8Array } {
    this.ensureKeys();
    if (!spkId) return { ikPriv: this._ikPriv };
    if (spkId === this._spkId) return { ikPriv: this._ikPriv, spkPriv: this._spkPriv };
    const cached = this._spkCache.get(spkId);
    if (cached) return { ikPriv: this._ikPriv, spkPriv: cached };
    const oldSPK = this._store.loadSPK(this._deviceId, spkId);
    if (oldSPK) {
      this._spkCache.set(spkId, oldSPK);
      return { ikPriv: this._ikPriv, spkPriv: oldSPK };
    }
    const ikAlias = this._store.loadIKSPK(this._deviceId, spkId);
    if (ikAlias) return { ikPriv: ikAlias.priv, spkPriv: ikAlias.priv };
    if (spkId === this._ikSPKId()) {
      this._store.saveIK(this._deviceId, this._ikPriv, this._ikPubDer);
      return { ikPriv: this._ikPriv, spkPriv: this._ikPriv };
    }
    throw new Error(`spk_missing: spk_id=${spkId}`);
  }

  /** 判断 spkId 是否命中当前活跃 SPK。 */
  isCurrentSPK(spkId: string | null | undefined): boolean {
    return Boolean(spkId) && spkId === this._spkId;
  }

  /** 跟踪每个旧 SPK 引用的最大 seq（用于销毁判定）。 */
  trackOldSPKMaxSeq(spkId: string, seq: number): void {
    if (!spkId || spkId === this._spkId) return;
    const cur = this._oldSPKMaxSeq.get(spkId);
    const curSeq = cur ? cur.seq : 0;
    if (seq > curSeq) {
      this._oldSPKMaxSeq.set(spkId, { seq, lastSeenAt: this._nowFn() });
    }
  }

  /**
   * contig_seq 已覆盖、超过 7 天安全窗口、且不在最近 7 代保留窗口内时销毁。
   *
   * 销毁条件（全部满足才销毁）：
   * - contig_seq >= 该 SPK 引用的最大 seq（接收方已消费完所有引用此 SPK 的消息）
   * - 自最后一次见到该 spk_id 引用 >= 7 天
   * - 不在最近 7 代 SPK 保留窗口内
   *
   * 7 天 + 7 代双兜底：低频群即便 contig_seq 已覆盖也至少留 7 代或 7 天，
   * 避免发送方陈旧 bootstrap 缓存导致新消息加密失败。
   */
  maybeDestroyOldSPKs(contigSeq: number): string[] {
    const destroyed: string[] = [];
    const now = this._nowFn();
    let recentKeep: Set<string>;
    try {
      recentKeep = new Set(this._store.listRecentSPKIds(this._deviceId, RECENT_GENERATIONS));
    } catch {
      recentKeep = new Set();
    }
    for (const [spkId, info] of Array.from(this._oldSPKMaxSeq.entries())) {
      if (spkId === this._spkId) continue;
      if (contigSeq < info.seq) continue;
      if (now - info.lastSeenAt < DESTROY_DELAY_MS) continue;
      if (recentKeep.has(spkId)) continue;
      try {
        this._store.deleteSPK(this._deviceId, spkId);
      } catch {
        // 忽略 delete 失败，但 _oldSPKMaxSeq 仍清理避免重复尝试
      }
      this._oldSPKMaxSeq.delete(spkId);
      destroyed.push(spkId);
    }

    // 180 天硬上限：无论是否被引用，超龄 SPK 强制销毁
    try {
      const expired = this._store.listExpiredSPKIds(this._deviceId, HARD_LIMIT_MS);
      for (const spkId of expired) {
        if (spkId === this._spkId) continue;
        try { this._store.deleteSPK(this._deviceId, spkId); } catch { /* ignore */ }
        this._oldSPKMaxSeq.delete(spkId);
        if (!destroyed.includes(spkId)) destroyed.push(spkId);
      }
    } catch { /* ignore */ }

    return destroyed;
  }

  /** 轮换 SPK：生成新 SPK 并上报到服务端。旧 SPK 保留本地用于解密。 */
  async rotateSPK(callFn: CallFn): Promise<void> {
    this._generateNewSPK();
    await this._registerSPK(callFn);
    this._store.markSPKUploaded(this._deviceId, this._spkId);
    this._lastUploadedSPKId = this._spkId;
  }

  cachePeerIK(peerAid: string, deviceId: string, ikPubDer: Uint8Array): void {
    this._peerIKCache.set(`${peerAid}#${deviceId}`, { pubDer: ikPubDer, cachedAt: this._nowFn() });
  }

  getPeerIK(peerAid: string, deviceId: string): Uint8Array | null {
    const key = `${peerAid}#${deviceId}`;
    const entry = this._peerIKCache.get(key);
    if (!entry) return null;
    if (this._nowFn() - entry.cachedAt >= PEER_KEY_CACHE_TTL_MS) {
      this._peerIKCache.delete(key);
      return null;
    }
    return entry.pubDer;
  }

  isPeerSPKVerified(peerAid: string, deviceId: string, spkId: string): boolean {
    return this._verifiedSPKs.has(`${peerAid}#${deviceId}#${spkId}`);
  }

  markPeerSPKVerified(peerAid: string, deviceId: string, spkId: string): void {
    this._verifiedSPKs.add(`${peerAid}#${deviceId}#${spkId}`);
  }

  // ── Group SPK 独立管理 ──────────────────────────────────────────

  /** 确保指定群有独立 group SPK，返回 { spkId, priv, pubDER }。 */
  ensureGroupSPK(groupId: string): { spkId: string; priv: Uint8Array; pubDer: Uint8Array } {
    this.ensureKeys();
    const gk = this._groupKey(groupId);
    for (const candidate of this._groupLookupCandidates(groupId)) {
      const cur = this._store.loadCurrentGroupSPK(this._deviceId, candidate);
      if (cur) return cur;
    }
    // 生成新 group SPK
    const [priv, pubDer] = generateP256Keypair();
    const hashHex = createHash('sha256').update(pubDer).digest('hex');
    const spkId = `sha256:${hashHex.substring(0, 16)}`;
    this._store.saveGroupSPK(this._deviceId, gk, spkId, priv, pubDer);
    return { spkId, priv, pubDer };
  }

  /** 注册指定群的 group SPK 到服务端。group 服务负责成员鉴权。 */
  async ensureGroupRegistered(groupId: string, callFn: CallFn): Promise<void> {
    const gk = this._groupKey(groupId);
    for (const candidate of this._groupLookupCandidates(groupId)) {
      const uploadedSPKId = this._store.loadLatestUploadedGroupSPKId(this._deviceId, candidate);
      if (uploadedSPKId) {
        this._lastUploadedGroupSPKIds.set(gk, uploadedSPKId);
        this._lastUploadedGroupSPKIds.set(candidate, uploadedSPKId);
        return;
      }
    }
    const { spkId, pubDer } = this.ensureGroupSPK(gk);
    await this._publishGroupSPK(gk, spkId, pubDer, callFn);
  }

  /** 轮换指定群的 group SPK，保留旧私钥用于缓存窗口内的历史 wrap 解密。 */
  async rotateGroupSPK(
    groupId: string,
    callFn: CallFn,
  ): Promise<{ spkId: string; priv: Uint8Array; pubDer: Uint8Array }> {
    this.ensureKeys();
    const gk = this._groupKey(groupId);
    const [priv, pubDer] = generateP256Keypair();
    const hashHex = createHash('sha256').update(pubDer).digest('hex');
    const spkId = `sha256:${hashHex.substring(0, 16)}`;
    this._store.saveGroupSPK(this._deviceId, gk, spkId, priv, pubDer);
    await this._publishGroupSPK(gk, spkId, pubDer, callFn);
    return { spkId, priv, pubDer };
  }

  /** 群消息解密按 group SPK -> device SPK -> IK fallback；仍找不到则显式报错。 */
  getGroupDecryptKeys(groupId: string, spkId: string): { ikPriv: Uint8Array; spkPriv: Uint8Array | null } {
    this.ensureKeys();
    if (!spkId) return { ikPriv: this._ikPriv, spkPriv: null };
    const lookup = this._normalizeGroupSPKLookup(this._groupKey(groupId), spkId);
    // 优先查 group SPK
    for (const candidate of this._groupLookupCandidates(lookup.groupId)) {
      const groupSPK = this._store.loadGroupSPK(this._deviceId, candidate, lookup.spkId);
      if (groupSPK) return { ikPriv: this._ikPriv, spkPriv: groupSPK };
    }
    // fallback 到 device SPK，再 fallback 到 IK 特殊 fallback（兼容历史消息）
    if (lookup.spkId === this._spkId) return { ikPriv: this._ikPriv, spkPriv: this._spkPriv ?? null };
    const oldSPK = this._store.loadSPK(this._deviceId, lookup.spkId);
    if (oldSPK) return { ikPriv: this._ikPriv, spkPriv: oldSPK };
    const ikAlias = this._store.loadIKSPK(this._deviceId, lookup.spkId);
    if (ikAlias) return { ikPriv: ikAlias.priv, spkPriv: ikAlias.priv };
    if (lookup.spkId === this._ikSPKId()) {
      this._store.saveIK(this._deviceId, this._ikPriv, this._ikPubDer);
      return { ikPriv: this._ikPriv, spkPriv: this._ikPriv };
    }
    throw new Error(`spk_missing: spk_id=${lookup.spkId}`);
  }

  /** 判断 spk_id 是否为本进程最后一次成功上传的 P2P SPK。 */
  isLastUploadedSPK(spkId: string): boolean {
    return Boolean(spkId) && spkId === this._lastUploadedSPKId;
  }

  /** 判断 spk_id 是否为本进程在该群最后一次成功上传的 group SPK。 */
  isLastUploadedGroupSPK(groupId: string, spkId: string): boolean {
    if (!spkId) return false;
    const lookup = this._normalizeGroupSPKLookup(this._groupKey(groupId), spkId);
    return this._groupLookupCandidates(lookup.groupId)
      .some((candidate) => this._lastUploadedGroupSPKIds.get(candidate) === lookup.spkId);
  }

  /** 签名并上传 group SPK 到 group.v2.put_group_pk。 */
  private async _publishGroupSPK(
    groupId: string,
    spkId: string,
    pubDer: Uint8Array,
    callFn: CallFn,
  ): Promise<void> {
    const gk = this._groupKey(groupId);
    const spkTimestamp = Math.floor(this._nowFn() / 1000);
    const signData = Buffer.concat([
      Buffer.from(pubDer),
      Buffer.from(spkId, 'utf-8'),
      Buffer.from(String(spkTimestamp), 'utf-8'),
    ]);
    const signature = ecdsaSignRaw(this._ikPriv, signData);
    await callFn('group.v2.put_group_pk', {
      group_id: gk,
      group_aid: gk,
      key_source: 'group_device_prekey',
      spk_id: spkId,
      spk_pk: Buffer.from(pubDer).toString('base64'),
      spk_signature: Buffer.from(signature).toString('base64'),
      spk_timestamp: spkTimestamp,
    });
    this._store.markGroupSPKUploaded(this._deviceId, gk, spkId);
    this._lastUploadedGroupSPKIds.set(gk, spkId);
    if (String(groupId ?? '').trim() && String(groupId ?? '').trim() !== gk) {
      this._lastUploadedGroupSPKIds.set(String(groupId ?? '').trim(), spkId);
    }
  }
}
