/**
 * AUN E2EE V2: Recipients 排序与 Merkle Digest
 *
 * 规范引用：§5.3 / §10.3
 *
 * - 行排序：(aid asc, device_id asc, role asc) 字典序
 * - 每行固定 8 字段：[aid, device_id, role, key_source, fp, spk_id, wrap_nonce, wrapped_key]
 * - Digest = Merkle root（leaf/inner 各有独立前缀）
 * - 奇数节点复制最后一个
 */

import { createHash } from 'node:crypto';

const TEXT = new TextEncoder();
const LEAF_PREFIX: Uint8Array = TEXT.encode('AUN-V2-RCPT-LEAF-v1');
const NODE_PREFIX: Uint8Array = TEXT.encode('AUN-V2-RCPT-NODE-v1');

export interface ProofStep {
  sibling: string; // hex
  position: 'L' | 'R';
}

/** 按 (aid, device_id, role) 字典序稳定排序 recipients。 */
export function sortRecipients(rows: string[][]): string[][] {
  return [...rows].sort((a, b) => {
    const ka0 = a[0] ?? '';
    const kb0 = b[0] ?? '';
    if (ka0 !== kb0) return ka0 < kb0 ? -1 : 1;
    const ka1 = a[1] ?? '';
    const kb1 = b[1] ?? '';
    if (ka1 !== kb1) return ka1 < kb1 ? -1 : 1;
    const ka2 = a[2] ?? '';
    const kb2 = b[2] ?? '';
    if (ka2 !== kb2) return ka2 < kb2 ? -1 : 1;
    return 0;
  });
}

/**
 * wrap_nonce / wrapped_key 字段优先按 base64 解码，失败则按 utf-8 字节回退（与 Python 行为一致）。
 */
function decodeOrRaw(value: string): Uint8Array {
  if (!value) return new Uint8Array(0);
  // Node Buffer.from(..., 'base64') 对非法字符会忽略而非抛错，
  // 因此校验"再编码回去"是否一致来判断输入是否合法 base64。
  // 这与 Python base64.b64decode(value) 的行为相近：
  // 不合法时 Python 抛错 → 我们 fallback 到 utf-8。
  // 不过 Python 默认非严格模式也容错；这里采用与 Python 完全等价的判定：
  // 1) 仅含 base64 字符集 [A-Za-z0-9+/=]
  // 2) 长度是 4 的倍数
  // 否则按 utf-8 处理。
  if (isLikelyBase64(value)) {
    try {
      const decoded = Buffer.from(value, 'base64');
      // 双重校验：重编码与原值一致（忽略 padding 差异）。
      const reencoded = decoded.toString('base64');
      // 比较时归一化 padding：Python 会抛 binascii.Error 在 padding 不正确时。
      if (reencoded === value || reencoded.replace(/=+$/, '') === value.replace(/=+$/, '')) {
        return new Uint8Array(decoded);
      }
    } catch {
      /* fallthrough */
    }
  }
  return new Uint8Array(TEXT.encode(value));
}

function isLikelyBase64(s: string): boolean {
  if (s.length === 0) return false;
  if (s.length % 4 !== 0) return false;
  return /^[A-Za-z0-9+/]+={0,2}$/.test(s);
}

/** 计算单个 recipient 行的 leaf hash（32 字节）。 */
export function computeLeafHash(row: string[]): Uint8Array {
  const aid = TEXT.encode(String(row[0] ?? ''));
  const deviceId = TEXT.encode(String(row[1] ?? ''));
  const role = TEXT.encode(String(row[2] ?? ''));
  const keySource = TEXT.encode(String(row[3] ?? ''));
  const fp = TEXT.encode(String(row[4] ?? ''));
  const spkId = TEXT.encode(String(row[5] ?? ''));
  const wrapNonce = decodeOrRaw(String(row[6] ?? ''));
  const wrappedKey = decodeOrRaw(String(row[7] ?? ''));

  const h = createHash('sha256');
  h.update(LEAF_PREFIX);
  h.update(aid); h.update(Uint8Array.of(0));
  h.update(deviceId); h.update(Uint8Array.of(0));
  h.update(role); h.update(Uint8Array.of(0));
  h.update(keySource); h.update(Uint8Array.of(0));
  h.update(fp); h.update(Uint8Array.of(0));
  h.update(spkId); h.update(Uint8Array.of(0));
  h.update(wrapNonce);
  h.update(wrappedKey);
  return new Uint8Array(h.digest());
}

function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  const h = createHash('sha256');
  h.update(NODE_PREFIX);
  h.update(left);
  h.update(right);
  return new Uint8Array(h.digest());
}

function merkleRootFromLeaves(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 1) return leaves[0];
  let layer = [...leaves];
  while (layer.length > 1) {
    if (layer.length % 2 === 1) layer.push(layer[layer.length - 1]);
    const next: Uint8Array[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      next.push(nodeHash(layer[i], layer[i + 1]));
    }
    layer = next;
  }
  return layer[0];
}

/**
 * 计算 recipients 的 Merkle root（hex）。空列表返回空字符串（与 Python 一致）。
 */
export function computeMerkleRoot(rows: string[][]): string {
  if (rows.length === 0) return '';
  const leaves = rows.map(computeLeafHash);
  return Buffer.from(merkleRootFromLeaves(leaves)).toString('hex');
}

/** 兼容入口，等价 computeMerkleRoot。调用方应先调 sortRecipients。 */
export function computeRecipientsDigest(rows: string[][]): string {
  return computeMerkleRoot(rows);
}

/**
 * 为 targetIndex 行生成 Merkle proof（log N 步）。
 */
export function computeMerkleProof(rows: string[][], targetIndex: number): ProofStep[] {
  if (rows.length === 0 || targetIndex < 0 || targetIndex >= rows.length) return [];
  const leaves = rows.map(computeLeafHash);
  const proof: ProofStep[] = [];
  let layer = [...leaves];
  let idx = targetIndex;
  while (layer.length > 1) {
    if (layer.length % 2 === 1) layer.push(layer[layer.length - 1]);
    const siblingIdx = idx ^ 1;
    proof.push({
      sibling: Buffer.from(layer[siblingIdx]).toString('hex'),
      position: siblingIdx > idx ? 'R' : 'L',
    });
    const next: Uint8Array[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      next.push(nodeHash(layer[i], layer[i + 1]));
    }
    layer = next;
    idx = Math.floor(idx / 2);
  }
  return proof;
}

/**
 * 验证 leaf + proof 重建出的 root 与期望值一致。
 */
export function verifyMerkleProof(
  leaf: Uint8Array,
  proof: ProofStep[],
  expectedRootHex: string,
): boolean {
  if (!expectedRootHex) return false;
  let cur = leaf;
  for (const step of proof) {
    if (!/^[0-9a-fA-F]*$/.test(step.sibling) || step.sibling.length % 2 !== 0) return false;
    const sibling = Uint8Array.from(Buffer.from(step.sibling, 'hex'));
    if (step.position === 'L') {
      cur = nodeHash(sibling, cur);
    } else if (step.position === 'R') {
      cur = nodeHash(cur, sibling);
    } else {
      return false;
    }
  }
  return Buffer.from(cur).toString('hex') === expectedRootHex;
}
