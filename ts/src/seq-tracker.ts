// ── 消息序列号跟踪与空洞检测 ──────────────────────────────
//
// SeqTracker 维护按命名空间（group_id 或 conversation_id）分组的消息序列连续性。
// 用法：群消息 key = "group:" + groupId，P2P 消息 key = "p2p:" + myAid

import type { JsonObject } from './types.js';

const BACKOFF_INTERVALS = [1, 3, 10, 30, 60]; // 秒
// S2: 删除"probeCount >= 5 强制 resolved"的硬限制；仅用作 backoff 索引上限。
// resolved 只应由"完整补齐"或服务端明确 tombstone 驱动。
const MAX_PROBE_COUNT = 5;
// P1-07: receivedSeqs 内存保护上限，超过时触发 forceCompact 释放内存
const RECEIVED_SEQS_LIMIT = 5000;

interface GapProbe {
  gapStart: number;
  gapEnd: number;
  lastProbeAt: number; // Date.now() ms
  probeCount: number;
  resolved: boolean;
}

interface TrackerState {
  contiguousSeq: number;
  maxSeenSeq: number;
  receivedSeqs: Set<number>;
  pendingGaps: Map<string, GapProbe>; // key = "start:end"
}

function gapKey(start: number, end: number): string {
  return `${start}:${end}`;
}

/** 统一使用 Date.now() 返回绝对时间戳（毫秒），
 *  避免 performance.now()（相对时间）与 Date.now()（绝对时间）混用导致语义不一致。 */
function nowMs(): number {
  return Date.now();
}

export class SeqTracker {
  private _trackers: Map<string, TrackerState> = new Map();

  private _get(ns: string): TrackerState {
    let t = this._trackers.get(ns);
    if (!t) {
      t = { contiguousSeq: 0, maxSeenSeq: 0, receivedSeqs: new Set(), pendingGaps: new Map() };
      this._trackers.set(ns, t);
    }
    return t;
  }

  getContiguousSeq(ns: string): number {
    return this._get(ns).contiguousSeq;
  }

  getMaxSeenSeq(ns: string): number {
    return this._get(ns).maxSeenSeq;
  }

  /** Push 专用：只扩展上界 maxSeenSeq，不动 contiguousSeq。
   *
   * 语义：服务端告诉 SDK"我有 seq 这条消息"，SDK 仅更新已知上界。
   * 消息内容是否解密成功、是否进入连续前缀，由 pull/decrypt 路径决定。
   *
   * 防御：
   * - seq <= 0 直接忽略（防御负数/恶意值）
   * - 不会让 maxSeenSeq 倒退（仅取 max）
   */
  updateMaxSeen(ns: string, seq: number): void {
    if (seq <= 0) return;
    const t = this._get(ns);
    if (seq > t.maxSeenSeq) {
      t.maxSeenSeq = seq;
    }
  }

  /** S2: 从持久化（keystore 最近 ack seq）恢复 baseline，
   *  以便首条 push 消息能构造 [baseline+1, seq-1] 的历史 gap。
   *  必须在收到首条消息前调用。 */
  setBaseline(ns: string, baselineSeq: number): void {
    if (baselineSeq <= 0) return;
    const t = this._get(ns);
    if (t.contiguousSeq === 0 && t.maxSeenSeq === 0) {
      t.contiguousSeq = baselineSeq;
      t.maxSeenSeq = baselineSeq;
    }
  }

  /** 记录收到的 seq，返回 true 表示需要 pull 补齐空洞 */
  onMessageSeq(ns: string, seq: number): boolean {
    if (seq <= 0) return false;
    const t = this._get(ns);

    if (seq <= t.contiguousSeq) return false;

    // S2: 首次收到消息时，必须构造 [1, seq-1] 的历史 gap 来触发补洞，
    // 而不是把当前 seq 当成 baseline 丢弃历史。
    if (t.contiguousSeq === 0 && t.maxSeenSeq === 0) {
      if (seq === 1) {
        t.contiguousSeq = seq;
        t.maxSeenSeq = seq;
        return false;
      }
      t.maxSeenSeq = seq;
      t.receivedSeqs.add(seq);
      const histKey = gapKey(1, seq - 1);
      t.pendingGaps.set(histKey, {
        gapStart: 1, gapEnd: seq - 1,
        lastProbeAt: 0, probeCount: 0, resolved: false,
      });
      return true;
    }

    t.receivedSeqs.add(seq);
    t.maxSeenSeq = Math.max(t.maxSeenSeq, seq);

    // P1-07: 内存保护 — receivedSeqs 超限时强制推进 contiguousSeq 释放内存
    if (t.receivedSeqs.size > RECEIVED_SEQS_LIMIT) {
      this._forceCompact(t);
    }

    if (seq === t.contiguousSeq + 1) {
      t.contiguousSeq = seq;
      t.receivedSeqs.delete(seq);
      this._tryAdvance(t);
      return false;
    }

    // 空洞
    const gs = t.contiguousSeq + 1;
    const ge = seq - 1;
    const key = gapKey(gs, ge);

    const existing = t.pendingGaps.get(key);
    if (existing) {
      if (existing.resolved) {
        t.contiguousSeq = Math.max(t.contiguousSeq, existing.gapEnd);
        t.pendingGaps.delete(key);
        this._tryAdvance(t);
        return false;
      }
      if (!this._shouldProbe(existing)) return false;
    } else {
      t.pendingGaps.set(key, {
        gapStart: gs, gapEnd: ge,
        lastProbeAt: 0, probeCount: 0, resolved: false,
      });
    }
    return true;
  }

  /** pull 返回后更新 tracker 状态。
   *
   * afterSeq: pull 请求使用的 after_seq 参数。如果等于当前 contiguousSeq（gap fill 场景），
   * 直接把 pull 到的最大 seq 作为新的 contiguousSeq——服务端返回的就是当前可用的全部消息，
   * 中间的空洞是永久性的（竞态跳跃/未持久化/过期清理），不应阻塞后续消息投递。
   */
  onPullResult(ns: string, messages: JsonObject[], afterSeq?: number): void {
    const t = this._get(ns);
    const pulledSeqs = new Set<number>();
    for (const m of messages) {
      const s = typeof m.seq === 'number' && m.seq > 0 ? m.seq : m.event_seq;
      if (typeof s === 'number' && s > 0) pulledSeqs.add(s);
    }

    // 将 pulled 的 seq 加入 receivedSeqs
    for (const s of pulledSeqs) {
      t.receivedSeqs.add(s);
    }

    // gap fill 场景：从 contiguousSeq 开始 pull，直接推进到 pull 返回的最大 seq
    if (pulledSeqs.size > 0 && afterSeq !== undefined && afterSeq === t.contiguousSeq) {
      const maxPulled = Math.max(...pulledSeqs);
      if (maxPulled > t.contiguousSeq) {
        t.contiguousSeq = maxPulled;
        // 清理被跳过区间内的 pendingGaps
        for (const [key, probe] of t.pendingGaps) {
          if (probe.gapEnd <= t.contiguousSeq) {
            t.pendingGaps.delete(key);
          }
        }
        // 清理 receivedSeqs 中 <= contiguousSeq 的条目
        for (const s of t.receivedSeqs) {
          if (s <= t.contiguousSeq) t.receivedSeqs.delete(s);
        }
      }
    }

    const now = nowMs();
    for (const [key, probe] of t.pendingGaps) {
      if (probe.resolved) continue;
      probe.lastProbeAt = now;
      probe.probeCount += 1;

      let allCovered = true;
      for (let s = probe.gapStart; s <= probe.gapEnd; s++) {
        if (!pulledSeqs.has(s)) { allCovered = false; break; }
      }
      if (allCovered) {
        probe.resolved = true;
      }
      // S2: 不再因 probeCount >= 3 自动 resolved；仅由完整补齐 / 服务端 tombstone 驱动。
    }

    if (pulledSeqs.size) {
      t.maxSeenSeq = Math.max(t.maxSeenSeq, Math.max(...pulledSeqs));
    }
    this._tryAdvance(t);
  }

  /** P1-07: 内存保护 — 当 receivedSeqs 超过上限时，
   *  找到最小 seq 强制推进 contiguousSeq，释放已无意义的条目。 */
  private _forceCompact(t: TrackerState): void {
    if (t.receivedSeqs.size === 0) return;
    let minSeq = Infinity;
    for (const s of t.receivedSeqs) {
      if (s < minSeq) minSeq = s;
    }
    if (minSeq === Infinity) return;
    // 强制推进到 minSeq 前一位，再按连续前缀自然推进。
    t.contiguousSeq = minSeq - 1;
    // 清理被跳过区间内的 pendingGaps
    for (const [key, probe] of t.pendingGaps) {
      if (probe.gapEnd <= t.contiguousSeq) {
        t.pendingGaps.delete(key);
      }
    }
    // 清理 receivedSeqs 中 <= contiguousSeq 的条目
    for (const s of t.receivedSeqs) {
      if (s <= t.contiguousSeq) t.receivedSeqs.delete(s);
    }
    this._tryAdvance(t);
  }

  private _tryAdvance(t: TrackerState): void {
    // 先清理已解决的空洞
    let changed = true;
    while (changed) {
      changed = false;
      for (const [key, probe] of t.pendingGaps) {
        if (probe.resolved && probe.gapStart <= t.contiguousSeq + 1) {
          t.contiguousSeq = Math.max(t.contiguousSeq, probe.gapEnd);
          t.pendingGaps.delete(key);
          changed = true;
        }
      }
    }
    // 从 contiguous+1 逐个推进（检查 receivedSeqs）
    while (t.receivedSeqs.has(t.contiguousSeq + 1)) {
      t.contiguousSeq += 1;
      t.receivedSeqs.delete(t.contiguousSeq);
    }
  }

  private _shouldProbe(probe: GapProbe): boolean {
    // S2: 不再以 probeCount >= MAX_PROBE_COUNT 为由将 probe 置为 resolved。
    // 超出 backoff 表长度后按最长间隔持续重试。
    const now = nowMs();
    const idx = Math.min(probe.probeCount, BACKOFF_INTERVALS.length - 1);
    const interval = BACKOFF_INTERVALS[idx] * 1000; // 秒转毫秒
    return now - probe.lastProbeAt >= interval;
  }

  /** S2: 服务端明确告知某区间无消息（tombstone）→ 将 gap 标记为 resolved */
  markGapResolvedByTombstone(ns: string, gapStart: number, gapEnd: number): void {
    const t = this._get(ns);
    for (const [, probe] of t.pendingGaps) {
      if (probe.gapStart >= gapStart && probe.gapEnd <= gapEnd) {
        probe.resolved = true;
      }
    }
    this._tryAdvance(t);
  }

  /** Pull 专用：强制推进 contiguousSeq（已连续到达的下界）。
   *
   * 语义：用于 pull 返回 server_ack_seq 后跳过被 GC/已 ack 的历史区间。
   * 仅增不减（防御 server_ack 倒退）。
   *
   * 防御：
   * - seq <= 0 直接忽略（防御负数/恶意值）
   * - 仅推进，不倒退（与 maxSeenSeq 共同维护不变式 contiguousSeq ≤ maxSeenSeq）
   */
  forceContiguousSeq(ns: string, seq: number): void {
    if (seq <= 0) return;
    const t = this._get(ns);
    if (seq > t.contiguousSeq) {
      // 清除被跳过区间内的 pendingGaps
      for (const [key, probe] of t.pendingGaps) {
        if (probe.gapEnd <= seq) {
          t.pendingGaps.delete(key);
        }
      }
      // 清除被跳过区间内的 receivedSeqs
      for (const s of t.receivedSeqs) {
        if (s <= seq) t.receivedSeqs.delete(s);
      }
      t.contiguousSeq = seq;
      t.maxSeenSeq = Math.max(t.maxSeenSeq, seq);
      this._tryAdvance(t);
    }
  }

  /** 脏数据修复：允许 contiguousSeq 倒退到指定值。
   *
   * 仅在以下场景使用：
   * - Push 路径检测到 contiguousSeq > pushSeq（contiguousSeq 被之前的脏数据污染）
   * - 持久化恢复后发现 contiguousSeq > 服务端真实最大值
   *
   * 与 forceContiguousSeq 的区别：forceContiguousSeq 只增不减；本方法允许倒退修复。
   *
   * 防御：
   * - seq < 0 视为 0（不允许负数）
   * - 倒退后 receivedSeqs / pendingGaps 重置（已知状态作废）
   */
  repairContiguousSeq(ns: string, seq: number): void {
    if (seq < 0) seq = 0;
    const t = this._get(ns);
    if (seq < t.contiguousSeq) {
      // 倒退修复：重置 receivedSeqs（之前认为已收到的 seq 可能是脏数据）
      for (const s of t.receivedSeqs) {
        if (s <= seq) t.receivedSeqs.delete(s);
      }
      // 清除所有覆盖被倒退区间的 pendingGaps
      for (const [key, probe] of t.pendingGaps) {
        if (probe.gapStart <= seq) {
          t.pendingGaps.delete(key);
        }
      }
      t.contiguousSeq = seq;
      // maxSeenSeq 不动（push 已经告诉我们上界存在）
    }
  }

  /** 删除指定命名空间的所有跟踪状态（群组解散时使用） */
  removeNamespace(ns: string): void {
    this._trackers.delete(ns);
  }

  /** 导出各命名空间的 contiguousSeq，用于持久化 */
  exportState(): Record<string, number> {
    const result: Record<string, number> = {};
    for (const [ns, t] of this._trackers) {
      if (t.contiguousSeq > 0) result[ns] = t.contiguousSeq;
    }
    return result;
  }

  /** 从持久化数据恢复各命名空间的 contiguousSeq */
  restoreState(state: Record<string, number>): void {
    for (const [ns, seq] of Object.entries(state)) {
      if (typeof seq === 'number' && seq > 0) {
        const t = this._get(ns);
        t.contiguousSeq = Math.max(t.contiguousSeq, seq);
        t.maxSeenSeq = Math.max(t.maxSeenSeq, seq);
      }
    }
  }
}
