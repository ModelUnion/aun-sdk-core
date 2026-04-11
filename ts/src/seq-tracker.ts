// ── 消息序列号跟踪与空洞检测 ──────────────────────────────
//
// SeqTracker 维护按命名空间（group_id 或 conversation_id）分组的消息序列连续性。
// 用法：群消息 key = "group:" + groupId，P2P 消息 key = "p2p:" + myAid

import type { JsonObject } from './types.js';

const BACKOFF_INTERVALS = [1, 3, 10, 30, 60]; // 秒
const MAX_PROBE_COUNT = 5;

interface GapProbe {
  gapStart: number;
  gapEnd: number;
  lastProbeAt: number; // performance.now() ms
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

function nowMs(): number {
  return typeof performance !== 'undefined' ? performance.now() : Date.now();
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

  /** 记录收到的 seq，返回 true 表示需要 pull 补齐空洞 */
  onMessageSeq(ns: string, seq: number): boolean {
    if (seq <= 0) return false;
    const t = this._get(ns);

    if (seq <= t.contiguousSeq) return false;

    // 首次收到消息：以当前 seq 为基线，不创建历史空洞
    if (t.contiguousSeq === 0 && t.maxSeenSeq === 0) {
      t.contiguousSeq = seq;
      t.maxSeenSeq = seq;
      return false;
    }

    t.receivedSeqs.add(seq);
    t.maxSeenSeq = Math.max(t.maxSeenSeq, seq);

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

  /** pull 返回后更新 tracker 状态 */
  onPullResult(ns: string, messages: JsonObject[]): void {
    const t = this._get(ns);
    const pulledSeqs = new Set<number>();
    for (const m of messages) {
      const s = m.seq;
      if (typeof s === 'number' && s > 0) pulledSeqs.add(s);
    }

    const now = nowMs();
    for (const [key, probe] of t.pendingGaps) {
      if (probe.resolved) continue;
      probe.lastProbeAt = now;
      probe.probeCount += 1;

      let allCovered = true;
      let anyHit = false;
      for (let s = probe.gapStart; s <= probe.gapEnd; s++) {
        if (pulledSeqs.has(s)) { anyHit = true; }
        else { allCovered = false; }
      }
      if (allCovered) {
        probe.resolved = true;
      } else if (!anyHit && probe.probeCount >= 3) {
        probe.resolved = true;
      }
    }

    for (const s of pulledSeqs) {
      t.receivedSeqs.add(s);
    }

    if (pulledSeqs.size) {
      t.maxSeenSeq = Math.max(t.maxSeenSeq, Math.max(...pulledSeqs));
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
    if (probe.probeCount >= MAX_PROBE_COUNT) {
      probe.resolved = true;
      return false;
    }
    const now = nowMs();
    const idx = Math.min(probe.probeCount, BACKOFF_INTERVALS.length - 1);
    const interval = BACKOFF_INTERVALS[idx] * 1000; // 秒转毫秒
    return now - probe.lastProbeAt >= interval;
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
