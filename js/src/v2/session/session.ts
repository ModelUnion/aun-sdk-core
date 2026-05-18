/**
 * AUN E2EE V2 Session Manager（浏览器版，全 async）。
 *
 * 与 Python `aun_core.v2.session.V2Session` 行为对齐：
 * - IK = AID 长期密钥（多设备共享 AID 身份），由构造函数注入，不独立生成
 * - SPK 设备级 P-256 密钥对，IK 签名背书
 * - SPK 销毁三重条件：
 *     contig_seq >= 该 SPK 引用的最大 seq
 *  && now - last_seen >= 7 小时
 *  && 不在最近 7 代保留窗口内
 * - 对端 IK 公钥缓存 TTL 1 小时
 * - SPK 注册：`callFn("message.v2.put_peer_pk", ...)`
 *
 * 浏览器目标：所有 store 调用均 `await`，签名走 noble（确定性 ECDSA）。
 */

import { generateP256Keypair, ecdsaSignRaw } from '../crypto/index';
import { V2KeyStore } from './keystore';

/** 对端 IK 公钥缓存 TTL（毫秒）。 */
export const PEER_KEY_CACHE_TTL_MS = 60 * 60 * 1000; // 1h
/** SPK 销毁安全窗口（毫秒）。 */
export const DESTROY_DELAY_MS = 7 * 60 * 60 * 1000; // 7h
/** SPK 销毁时保留的最近代数。 */
export const RECENT_GENERATIONS = 7;

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

/** 解密所需的私钥。 */
export interface DecryptKeys {
  ikPriv: Uint8Array;
  spkPriv?: Uint8Array;
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', data.slice().buffer);
  const arr = new Uint8Array(buf);
  let hex = '';
  for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, '0');
  return hex;
}

function bytesToBase64(b: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
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

  private _peerIKCache = new Map<string, { pubDer: Uint8Array; cachedAt: number }>();
  private _verifiedSPKs = new Set<string>();
  private _oldSPKMaxSeq = new Map<string, { seq: number; lastSeenAt: number }>();
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

  /** 暴露 store 以便测试（与 Python 同等私有约定）。 */
  get _storeForTest(): V2KeyStore {
    return this._store;
  }

  /** 加载或生成当前 SPK；IK 由构造函数注入，无需加载。 */
  async ensureKeys(): Promise<void> {
    if (this._spkPriv) return;
    const cur = await this._store.loadCurrentSPK(this._deviceId);
    if (cur) {
      this._spkId = cur.spkId;
      this._spkPriv = cur.priv;
      this._spkPubDer = cur.pubDer;
      return;
    }
    await this._generateNewSPK();
  }

  private async _generateNewSPK(): Promise<void> {
    const [priv, pubDer] = await generateP256Keypair();
    const hex = await sha256Hex(pubDer);
    const spkId = `sha256:${hex.substring(0, 16)}`;
    await this._store.saveSPK(this._deviceId, spkId, priv, pubDer);
    this._spkId = spkId;
    this._spkPriv = priv;
    this._spkPubDer = pubDer;
  }

  /** SPK 由 AID 私钥（IK）签名背书并上报到 message.v2.put_peer_pk。 */
  private async _registerSPK(callFn: CallFn): Promise<void> {
    const spkTimestamp = Math.floor(this._nowFn() / 1000);
    const enc = new TextEncoder();
    const signData = concatBytes(
      this._spkPubDer!,
      enc.encode(this._spkId),
      enc.encode(String(spkTimestamp)),
    );
    const signature = await ecdsaSignRaw(this._ikPriv, signData);
    await callFn('message.v2.put_peer_pk', {
      peer_aid: this._aid,
      key_source: 'peer_device_prekey',
      spk_id: this._spkId,
      spk_pk: bytesToBase64(this._spkPubDer!),
      spk_signature: bytesToBase64(signature),
      spk_timestamp: spkTimestamp,
    });
  }

  /** 注册本设备 SPK 到服务端。IK = AID 长期密钥，无需注册。幂等。 */
  async ensureRegistered(callFn: CallFn): Promise<void> {
    if (this._registered) return;
    await this.ensureKeys();
    await this._registerSPK(callFn);
    this._registered = true;
  }

  /** 返回加密所需的 sender 结构。 */
  async getSenderIdentity(): Promise<SenderIdentity> {
    await this.ensureKeys();
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
   * - spkId == 当前 SPK：当前 spkPriv
   * - 否则：从 store 加载旧 SPK 私钥（可能 undefined = 已销毁）
   */
  async getDecryptKeys(spkId: string | null | undefined): Promise<DecryptKeys> {
    await this.ensureKeys();
    if (!spkId) return { ikPriv: this._ikPriv };
    if (spkId === this._spkId) return { ikPriv: this._ikPriv, spkPriv: this._spkPriv };
    const oldSPK = await this._store.loadSPK(this._deviceId, spkId);
    if (!oldSPK) return { ikPriv: this._ikPriv };
    return { ikPriv: this._ikPriv, spkPriv: oldSPK };
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
   * contig_seq 已覆盖、超过 7h 安全窗口、且不在最近 7 代保留窗口内时销毁。
   *
   * 销毁条件（全部满足才销毁）：
   * - contig_seq >= 该 SPK 引用的最大 seq
   * - 自最后一次见到该 spk_id 引用 >= 7 小时
   * - 不在最近 7 代 SPK 保留窗口内
   */
  async maybeDestroyOldSPKs(contigSeq: number): Promise<string[]> {
    const destroyed: string[] = [];
    const now = this._nowFn();
    let recentKeep: Set<string>;
    try {
      recentKeep = new Set(
        await this._store.listRecentSPKIds(this._deviceId, RECENT_GENERATIONS),
      );
    } catch {
      // 列表失败时退化为空集，保持销毁行为可继续推进
      recentKeep = new Set();
    }
    for (const [spkId, info] of Array.from(this._oldSPKMaxSeq.entries())) {
      if (spkId === this._spkId) continue;
      if (contigSeq < info.seq) continue;
      if (now - info.lastSeenAt < DESTROY_DELAY_MS) continue;
      if (recentKeep.has(spkId)) continue;
      try {
        await this._store.deleteSPK(this._deviceId, spkId);
      } catch (err) {
        // 销毁失败时记录到控制台并跳过本轮，下次再重试
        // eslint-disable-next-line no-console
        console.warn('[V2Session] deleteSPK failed', { spkId, err });
        continue;
      }
      this._oldSPKMaxSeq.delete(spkId);
      destroyed.push(spkId);
    }
    return destroyed;
  }

  /** 轮换 SPK：生成新 SPK 并上报到服务端。旧 SPK 保留本地用于解密。 */
  async rotateSPK(callFn: CallFn): Promise<void> {
    await this._generateNewSPK();
    await this._registerSPK(callFn);
  }

  cachePeerIK(peerAid: string, deviceId: string, ikPubDer: Uint8Array): void {
    this._peerIKCache.set(`${peerAid}#${deviceId}`, {
      pubDer: ikPubDer,
      cachedAt: this._nowFn(),
    });
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
}
