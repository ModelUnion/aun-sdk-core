/**
 * AUN E2EE V2: Recipients 排序与 Digest（Merkle root）
 *
 * 规范引用: §10.3 / §5.3
 * - 二维数组（无 columns 表头）；行按 (aid asc, device_id asc, role asc) 排序
 * - 每行固定 8 字段: [aid, device_id, role, key_source, fp, spk_id, wrap_nonce, wrapped_key]
 * - leaf = SHA256(LEAF_PREFIX || canonical row binary fields)
 * - inner = SHA256(NODE_PREFIX || left || right)
 * - 奇数节点复制最后一个
 *
 * 浏览器实现：使用 WebCrypto subtle.digest('SHA-256')，全链路 async。
 * - wrap_nonce / wrapped_key 字段：优先 base64 解码（仅当长度为 4 的倍数且字符合法），
 *   失败时回退 UTF-8 字节，与 Python `_decode_or_raw` 对齐。
 */

const LEAF_PREFIX = new TextEncoder().encode('AUN-V2-RCPT-LEAF-v1');
const NODE_PREFIX = new TextEncoder().encode('AUN-V2-RCPT-NODE-v1');

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-256', data.slice().buffer);
  return new Uint8Array(buf);
}

function bytesToHex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}

function hexToBytes(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new Error('hex length must be even');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = parseInt(s.charAt(i * 2), 16);
    const lo = parseInt(s.charAt(i * 2 + 1), 16);
    if (Number.isNaN(hi) || Number.isNaN(lo)) throw new Error('invalid hex char');
    out[i] = (hi << 4) | lo;
  }
  return out;
}

function concat(...arrs: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let pos = 0;
  for (const a of arrs) {
    out.set(a, pos);
    pos += a.length;
  }
  return out;
}

/**
 * 与 Python `_decode_or_raw` 行为一致：
 *  - 空串 → 空 bytes
 *  - 长度为 4 的倍数且仅含 base64 字符 → atob 解码
 *  - 其他情况 → UTF-8 编码
 */
function decodeOrRaw(value: string): Uint8Array {
  if (!value) return new Uint8Array(0);
  // 标准 base64：A-Z a-z 0-9 + / =，长度必须是 4 的倍数
  if (value.length > 0 && value.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    try {
      const bin = atob(value);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    } catch {
      // fall through
    }
  }
  return new TextEncoder().encode(value);
}

/**
 * 按 (aid asc, device_id asc, role asc) 排序 recipients 行（不修改入参）。
 */
export function sortRecipients(rows: string[][]): string[][] {
  return [...rows].sort((a, b) => {
    if (a[0] !== b[0]) return a[0] < b[0] ? -1 : 1;
    if (a[1] !== b[1]) return a[1] < b[1] ? -1 : 1;
    if (a[2] !== b[2]) return a[2] < b[2] ? -1 : 1;
    return 0;
  });
}

/**
 * 计算单个 recipient 行的 leaf hash（32 字节）。
 */
export async function computeLeafHash(row: string[]): Promise<Uint8Array> {
  const enc = (s: string) => new TextEncoder().encode(s ?? '');
  const aid = enc(String(row[0] ?? ''));
  const deviceId = enc(String(row[1] ?? ''));
  const role = enc(String(row[2] ?? ''));
  const keySource = enc(String(row[3] ?? ''));
  const fp = enc(String(row[4] ?? ''));
  const spkId = enc(String(row.length > 5 ? row[5] : ''));
  const wrapNonce = decodeOrRaw(row.length > 6 ? String(row[6] ?? '') : '');
  const wrappedKey = decodeOrRaw(row.length > 7 ? String(row[7] ?? '') : '');

  const ZERO = Uint8Array.of(0);
  const data = concat(
    LEAF_PREFIX,
    aid,
    ZERO,
    deviceId,
    ZERO,
    role,
    ZERO,
    keySource,
    ZERO,
    fp,
    ZERO,
    spkId,
    ZERO,
    wrapNonce,
    wrappedKey,
  );
  return sha256(data);
}

async function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(NODE_PREFIX, left, right));
}

/**
 * Merkle root（hex），rows 必须已排序。
 */
export async function computeMerkleRoot(rows: string[][]): Promise<string> {
  if (rows.length === 0) return '';
  let layer: Uint8Array[] = [];
  for (const r of rows) layer.push(await computeLeafHash(r));

  while (layer.length > 1) {
    if (layer.length % 2 === 1) layer.push(layer[layer.length - 1]);
    const next: Uint8Array[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      next.push(await nodeHash(layer[i], layer[i + 1]));
    }
    layer = next;
  }
  return bytesToHex(layer[0]);
}

export interface ProofStep {
  sibling: string;
  position: 'L' | 'R';
}

/**
 * 为 targetIndex 行生成 Merkle proof。
 */
export async function computeMerkleProof(
  rows: string[][],
  targetIndex: number,
): Promise<ProofStep[]> {
  if (rows.length === 0 || targetIndex < 0 || targetIndex >= rows.length) return [];
  let layer: Uint8Array[] = [];
  for (const r of rows) layer.push(await computeLeafHash(r));

  let idx = targetIndex;
  const proof: ProofStep[] = [];
  while (layer.length > 1) {
    if (layer.length % 2 === 1) layer.push(layer[layer.length - 1]);
    const siblingIdx = idx ^ 1;
    proof.push({
      sibling: bytesToHex(layer[siblingIdx]),
      position: siblingIdx > idx ? 'R' : 'L',
    });
    const next: Uint8Array[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      next.push(await nodeHash(layer[i], layer[i + 1]));
    }
    layer = next;
    idx = Math.floor(idx / 2);
  }
  return proof;
}

/**
 * 验证 leaf + proof 重建出的 root 与期望值一致。
 */
export async function verifyMerkleProof(
  leaf: Uint8Array,
  proof: ProofStep[],
  expectedRootHex: string,
): Promise<boolean> {
  if (!expectedRootHex) return false;
  let cur = leaf;
  for (const step of proof) {
    let sibling: Uint8Array;
    try {
      sibling = hexToBytes(step.sibling);
    } catch {
      return false;
    }
    if (step.position === 'L') cur = await nodeHash(sibling, cur);
    else if (step.position === 'R') cur = await nodeHash(cur, sibling);
    else return false;
  }
  return bytesToHex(cur) === expectedRootHex;
}

/**
 * 计算 recipients_digest（Merkle root）。调用方 MUST 先调 sortRecipients。
 */
export async function computeRecipientsDigest(rows: string[][]): Promise<string> {
  return computeMerkleRoot(rows);
}
