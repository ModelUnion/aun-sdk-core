/**
 * GroupE2EEManager — 群组端到端加密管理器 + 纯函数
 *
 * 与 E2EEManager 平行：所有网络操作（P2P 发送、RPC 调用）由调用方负责。
 * 内置防重放、epoch 降级防护、密钥请求频率限制。
 */

import * as crypto from 'node:crypto';
import type { KeyStore } from './keystore/index.js';

import {
  E2EEError,
  E2EEGroupSecretMissingError,
} from './errors.js';
import {
  isJsonObject,
  type GroupOldEpochRecord,
  type GroupSecretMap,
  type GroupSecretRecord,
  type IdentityRecord,
  type JsonObject,
  type Message,
} from './types.js';

export interface LoadedGroupSecret {
  epoch: number;
  secret: Buffer;
  commitment: string;
  member_aids: string[];
}

// ── 辅助：证书 SHA-256 指纹 ──────────────────────────────────────

/** PEM 证书 → sha256:{hex} 指纹（与 Python/Go/JS SDK 一致） */
function certSha256Fingerprint(certPem: string | Buffer): string {
  const pem = typeof certPem === 'string' ? certPem : certPem.toString('utf-8');
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const der = Buffer.from(b64, 'base64');
  return `sha256:${crypto.createHash('sha256').update(der).digest('hex')}`;
}

// ── 常量 ───────────────────────────────────────────────────────

const SUITE = 'P256_HKDF_SHA256_AES_256_GCM';
const MODE_EPOCH_GROUP_KEY = 'epoch_group_key';

/** 群组消息 AAD 字段 */
const AAD_FIELDS_GROUP: readonly string[] = [
  'group_id', 'from', 'message_id', 'timestamp',
  'epoch', 'encryption_mode', 'suite',
] as const;

/** 群组消息 AAD 匹配字段 */
const AAD_MATCH_FIELDS_GROUP: readonly string[] = [
  'group_id', 'from', 'message_id',
  'epoch', 'encryption_mode', 'suite',
] as const;

/** 旧 epoch 默认保留 7 天 */
const OLD_EPOCH_RETENTION_SECONDS = 7 * 24 * 3600;

function loadKeyStoreGroupState(
  keystore: KeyStore,
  aid: string,
  groupId: string,
): GroupSecretRecord | null {
  if (typeof keystore.loadGroupSecretState === 'function') {
    return keystore.loadGroupSecretState(aid, groupId);
  }
  throw new Error('keystore 缺少 loadGroupSecretState 方法');
}

function loadAllKeyStoreGroupStates(
  keystore: KeyStore,
  aid: string,
): GroupSecretMap {
  if (typeof keystore.loadAllGroupSecretStates === 'function') {
    return keystore.loadAllGroupSecretStates(aid) ?? {};
  }
  throw new Error('keystore 缺少 loadAllGroupSecretStates 方法');
}

function saveKeyStoreGroupState(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  entry: GroupSecretRecord,
): void {
  if (typeof keystore.saveGroupSecretState === 'function') {
    keystore.saveGroupSecretState(aid, groupId, entry);
    return;
  }
  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} missing saveGroupSecretState method`);
}

function cleanupKeyStoreGroupOldEpochs(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  cutoffMs: number,
): number {
  if (typeof keystore.cleanupGroupOldEpochsState === 'function') {
    return keystore.cleanupGroupOldEpochsState(aid, groupId, cutoffMs);
  }

  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} missing cleanupGroupOldEpochsState method`);
}

function deleteKeyStoreGroupState(
  keystore: KeyStore,
  aid: string,
  groupId: string,
): void {
  if (typeof keystore.deleteGroupSecretState === 'function') {
    keystore.deleteGroupSecretState(aid, groupId);
    return;
  }
  // 降级：通过 saveGroupSecretState 写入空记录来"删除"
  if (typeof keystore.saveGroupSecretState === 'function') {
    keystore.saveGroupSecretState(aid, groupId, {} as any);
    return;
  }
  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} missing deleteGroupSecretState method`);
}

// ── 内部工具函数 ───────────────────────────────────────────────

/** HKDF-SHA256 派生密钥 */
function hkdfDeriveSync(ikm: Buffer, info: Buffer, length: number): Buffer {
  const derived = crypto.hkdfSync('sha256', ikm, Buffer.alloc(0), info, length);
  return Buffer.from(derived);
}

/** AES-256-GCM 加密 */
function aesGcmEncrypt(
  key: Buffer, plaintext: Buffer, aad: Buffer,
): { ciphertext: Buffer; tag: Buffer; nonce: Buffer } {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext: encrypted, tag, nonce };
}

/** AES-256-GCM 解密 */
function aesGcmDecrypt(
  key: Buffer, ciphertext: Buffer, tag: Buffer, nonce: Buffer, aad: Buffer,
): Buffer {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  decipher.setAAD(aad);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/** ECDSA-SHA256 签名 */
function ecdsaSign(privateKeyPem: string, data: Buffer): Buffer {
  const signer = crypto.createSign('SHA256');
  signer.update(data);
  signer.end();
  return signer.sign(privateKeyPem);
}

/** ECDSA-SHA256 验签 */
function ecdsaVerify(publicKey: crypto.KeyObject, signature: Buffer, data: Buffer): boolean {
  const verifier = crypto.createVerify('SHA256');
  verifier.update(data);
  verifier.end();
  return verifier.verify(publicKey, signature);
}

/** PEM 证书 → 公钥 KeyObject */
function pemToCertPublicKey(certPem: string | Buffer): crypto.KeyObject {
  const pem = typeof certPem === 'string' ? certPem : certPem.toString('utf-8');
  const x509 = new crypto.X509Certificate(pem);
  return x509.publicKey;
}

// ── 群组 AAD 工具 ─────────────────────────────────────────────

/** 群组 AAD 序列化（sorted keys, compact JSON） */
function aadBytesGroup(aad: JsonObject): Buffer {
  const obj: JsonObject = {};
  for (const field of AAD_FIELDS_GROUP) {
    obj[field] = aad[field] ?? null;
  }
  const sorted: JsonObject = {};
  for (const k of Object.keys(obj).sort()) {
    sorted[k] = obj[k];
  }
  return Buffer.from(JSON.stringify(sorted), 'utf-8');
}

/** 群组 AAD 字段匹配检查 */
function aadMatchesGroup(expected: JsonObject, actual: JsonObject): boolean {
  for (const f of AAD_MATCH_FIELDS_GROUP) {
    if (String(expected[f] ?? '') !== String(actual[f] ?? '')) {
      return false;
    }
  }
  return true;
}

// ── 群消息密钥派生 ────────────────────────────────────────────

/** 从 group_secret 派生单条群消息的加密密钥 */
function deriveGroupMsgKey(groupSecret: Buffer, groupId: string, messageId: string): Buffer {
  return hkdfDeriveSync(
    groupSecret,
    Buffer.from(`aun-group:${groupId}:msg:${messageId}`, 'utf-8'),
    32,
  );
}

// ── 纯函数：群组消息加解密 ────────────────────────────────────

/**
 * 加密群组消息，返回 e2ee.group_encrypted 信封。
 * senderPrivateKeyPem: 可选，传入时为密文附加发送方 ECDSA 签名。
 */
export function encryptGroupMessage(
  groupId: string,
  epoch: number,
  groupSecret: Buffer,
  payload: JsonObject,
  opts: {
    fromAid: string;
    messageId: string;
    timestamp: number;
    senderPrivateKeyPem?: string | null;
    senderCertPem?: string | null;
  },
): JsonObject {
  const msgKey = deriveGroupMsgKey(groupSecret, groupId, opts.messageId);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf-8');

  const aad: JsonObject = {
    group_id: groupId,
    from: opts.fromAid,
    message_id: opts.messageId,
    timestamp: opts.timestamp,
    epoch,
    encryption_mode: MODE_EPOCH_GROUP_KEY,
    suite: SUITE,
  };
  const aadBytes = aadBytesGroup(aad);
  const { ciphertext, tag, nonce } = aesGcmEncrypt(msgKey, plaintext, aadBytes);

  const envelope: JsonObject = {
    type: 'e2ee.group_encrypted',
    version: '1',
    encryption_mode: MODE_EPOCH_GROUP_KEY,
    suite: SUITE,
    epoch,
    nonce: nonce.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    tag: tag.toString('base64'),
    aad,
  };

  // 发送方签名
  if (opts.senderPrivateKeyPem) {
    const signPayload = Buffer.concat([ciphertext, tag, aadBytes]);
    const sig = ecdsaSign(opts.senderPrivateKeyPem, signPayload);
    envelope.sender_signature = sig.toString('base64');
    // 证书指纹（与 Python/Go/JS SDK 一致）
    if (opts.senderCertPem) {
      envelope.sender_cert_fingerprint = certSha256Fingerprint(opts.senderCertPem);
    }
  }

  return envelope;
}

/**
 * 解密群组消息。
 * groupSecrets: {epoch: groupSecretBytes} 映射。
 * requireSignature: 为 true 时（默认），若消息含签名但无证书可验证，或缺少签名，则拒绝。
 */
export function decryptGroupMessage(
  message: Message,
  groupSecrets: Map<number, Buffer>,
  senderCertPem?: string | null,
  opts?: { requireSignature?: boolean },
): Message | null {
  const requireSignature = opts?.requireSignature ?? true;
  const payload = isJsonObject(message.payload) ? message.payload : null;
  if (payload === null) return null;
  if (payload.type !== 'e2ee.group_encrypted') return null;

  const epoch = payload.epoch as number | undefined;
  if (epoch == null) return null;

  const groupSecret = groupSecrets.get(epoch);
  if (!groupSecret) return null;

  try {
    // 优先从 AAD 读取 group_id 和 message_id
    const aad = isJsonObject(payload.aad) ? payload.aad : undefined;
    const outerGroupId = (message.group_id as string) || '';

    let groupId: string;
    let messageId: string;
    let aadFrom = '';

    if (aad) {
      groupId = (aad.group_id as string) || outerGroupId;
      messageId = (aad.message_id as string) || (message.message_id as string) || '';
      aadFrom = (aad.from as string) || '';

      // 外层路由字段与 AAD 绑定校验
      if (outerGroupId && groupId !== outerGroupId) return null;
      if (aadFrom) {
        const outerFrom = (message.from as string) || '';
        const outerSender = (message.sender_aid as string) || '';
        if (outerFrom && outerFrom !== aadFrom) return null;
        if (outerSender && outerSender !== aadFrom) return null;
      }
    } else {
      groupId = outerGroupId;
      messageId = (message.message_id as string) || '';
    }

    if (!groupId || !messageId) return null;

    const msgKey = deriveGroupMsgKey(groupSecret, groupId, messageId);
    const nonce = Buffer.from(payload.nonce as string, 'base64');
    const ciphertext = Buffer.from(payload.ciphertext as string, 'base64');
    const tag = Buffer.from(payload.tag as string, 'base64');

    const aadBytes = aad ? aadBytesGroup(aad) : Buffer.alloc(0);
    const plaintext = aesGcmDecrypt(msgKey, ciphertext, tag, nonce, aadBytes);
    const decoded = JSON.parse(plaintext.toString('utf-8'));

    const result: Message = {
      ...message,
      payload: decoded,
      encrypted: true,
      e2ee: {
        encryption_mode: MODE_EPOCH_GROUP_KEY,
        suite: SUITE,
        epoch,
        sender_verified: false,
      },
    };

    // 发送方签名验证
    const senderSigB64 = payload.sender_signature as string | undefined;
    if (requireSignature) {
      if (!senderSigB64) return null;
      if (!senderCertPem) return null;
      try {
        const senderPub = pemToCertPublicKey(senderCertPem);
        const sigBytes = Buffer.from(senderSigB64, 'base64');
        const verifyPayload = Buffer.concat([ciphertext, tag, aadBytes]);
        if (!ecdsaVerify(senderPub, sigBytes, verifyPayload)) return null;
        if (isJsonObject(result.e2ee)) result.e2ee.sender_verified = true;
      } catch {
        return null;
      }
    } else if (senderCertPem) {
      // 非零信任模式但提供了证书：有证书时强制验签
      if (!senderSigB64) return null;
      try {
        const senderPub = pemToCertPublicKey(senderCertPem);
        const sigBytes = Buffer.from(senderSigB64, 'base64');
        const verifyPayload = Buffer.concat([ciphertext, tag, aadBytes]);
        if (!ecdsaVerify(senderPub, sigBytes, verifyPayload)) return null;
        if (isJsonObject(result.e2ee)) result.e2ee.sender_verified = true;
      } catch {
        return null;
      }
    }

    return result;
  } catch {
    return null;
  }
}

// ── Membership Commitment ─────────────────────────────────────

/**
 * 计算 Membership Commitment。
 * commitment = SHA-256(sort(aids).join("|") + "|" + epoch + "|" + groupId + "|" + SHA256(groupSecret).hex())
 */
export function computeMembershipCommitment(
  memberAids: string[], epoch: number, groupId: string, groupSecret: Buffer,
): string {
  const sortedAids = [...memberAids].sort();
  const secretHash = crypto.createHash('sha256').update(groupSecret).digest().toString('hex');
  const data = sortedAids.join('|') + '|' + epoch + '|' + groupId + '|' + secretHash;
  return crypto.createHash('sha256').update(data, 'utf-8').digest().toString('hex');
}

/**
 * 验证 Membership Commitment。
 * 1. 重算 commitment 是否匹配
 * 2. 检查 myAid 是否在 memberAids 中
 */
export function verifyMembershipCommitment(
  commitment: string,
  memberAids: string[],
  epoch: number,
  groupId: string,
  myAid: string,
  groupSecret: Buffer,
): boolean {
  if (!memberAids.includes(myAid)) return false;
  const expected = computeMembershipCommitment(memberAids, epoch, groupId, groupSecret);
  // 恒定时间比较（长度不同时直接返回 false）
  const a = Buffer.from(expected, 'utf-8');
  const b = Buffer.from(commitment, 'utf-8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ── Membership Manifest ───────────────────────────────────────

/** 构建 Membership Manifest（未签名） */
export function buildMembershipManifest(
  groupId: string,
  epoch: number,
  prevEpoch: number | null,
  memberAids: string[],
  opts?: {
    added?: string[];
    removed?: string[];
    initiatorAid?: string;
  },
): JsonObject {
  return {
    manifest_version: 1,
    group_id: groupId,
    epoch,
    prev_epoch: prevEpoch,
    member_aids: [...memberAids].sort(),
    added: [...(opts?.added ?? [])].sort(),
    removed: [...(opts?.removed ?? [])].sort(),
    initiator_aid: opts?.initiatorAid ?? '',
    issued_at: Date.now(),
  };
}

/** 序列化 manifest 为签名输入 */
function manifestSignData(manifest: JsonObject): Buffer {
  const fields = [
    String(manifest.manifest_version ?? 1),
    (manifest.group_id as string) ?? '',
    String(manifest.epoch ?? 0),
    String(manifest.prev_epoch ?? ''),
    ((manifest.member_aids as string[]) ?? []).join('|'),
    ((manifest.added as string[]) ?? []).join('|'),
    ((manifest.removed as string[]) ?? []).join('|'),
    (manifest.initiator_aid as string) ?? '',
    String(manifest.issued_at ?? 0),
  ];
  return Buffer.from(fields.join('\n'), 'utf-8');
}

/** 对 Membership Manifest 签名，返回带 signature 字段的新 manifest */
export function signMembershipManifest(
  manifest: JsonObject,
  privateKeyPem: string,
): JsonObject {
  const signData = manifestSignData(manifest);
  const sig = ecdsaSign(privateKeyPem, signData);
  return { ...manifest, signature: sig.toString('base64') };
}

/** 验证 Membership Manifest 签名 */
export function verifyMembershipManifest(
  manifest: JsonObject,
  initiatorCertPem: string,
): boolean {
  const sigB64 = manifest.signature as string | undefined;
  if (!sigB64) return false;
  try {
    const pubKey = pemToCertPublicKey(initiatorCertPem);
    const sigBytes = Buffer.from(sigB64, 'base64');
    const signData = manifestSignData(manifest);
    return ecdsaVerify(pubKey, sigBytes, signData);
  } catch {
    return false;
  }
}

// ── Group Secret 生命周期管理 ─────────────────────────────────

/** 存储 group_secret 到 keystore metadata */
export function storeGroupSecret(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  epoch: number,
  groupSecret: Buffer,
  commitment: string,
  memberAids: string[],
): boolean {
  const existing = loadKeyStoreGroupState(keystore, aid, groupId);
  if (existing && existing.epoch != null) {
    const localEpoch = existing.epoch as number;
    if (epoch < localEpoch) {
      return false;
    }
    if (epoch === localEpoch && typeof existing.secret === 'string') {
      const incomingSecret = groupSecret.toString('base64');
      if (existing.secret !== incomingSecret) {
        return false;
      }
      const oldMembers = [...((existing.member_aids as string[] | undefined) ?? [])].sort();
      const newMembers = [...memberAids].sort();
      if (JSON.stringify(oldMembers) !== JSON.stringify(newMembers) && newMembers.length > 0) {
        saveKeyStoreGroupState(keystore, aid, groupId, {
          ...existing,
          member_aids: newMembers,
          commitment,
          updated_at: Date.now(),
        });
      }
      return true;
    }
  }

  const current = existing ? { ...existing } : {};
  if (existing && existing.epoch !== epoch) {
    const oldEpochs = (existing.old_epochs as GroupOldEpochRecord[]) ?? [];
    const oldEntry: GroupOldEpochRecord = {
      epoch: existing.epoch,
      secret: existing.secret,
      commitment: existing.commitment,
      member_aids: existing.member_aids,
      updated_at: existing.updated_at,
      expires_at: ((existing.updated_at as number) || Date.now()) + OLD_EPOCH_RETENTION_SECONDS * 1000,
    };
    if ('secret_protection' in existing) {
      oldEntry.secret_protection = existing.secret_protection;
    }
    current.old_epochs = [...oldEpochs, oldEntry];
  }

  saveKeyStoreGroupState(keystore, aid, groupId, {
    epoch,
    secret: groupSecret.toString('base64'),
    commitment,
    member_aids: [...memberAids].sort(),
    updated_at: Date.now(),
    old_epochs: (current.old_epochs as GroupOldEpochRecord[] | undefined) ?? [],
  });
  return true;
}

/** 读取 group_secret */
export function loadGroupSecret(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  epoch?: number | null,
): LoadedGroupSecret | null {
  const entry = loadKeyStoreGroupState(keystore, aid, groupId) ?? undefined;
  if (!entry) return null;

  if (epoch == null || entry.epoch === epoch) {
    const secretStr = entry.secret as string | undefined;
    if (!secretStr) return null;
    return {
      epoch: entry.epoch as number,
      secret: Buffer.from(secretStr, 'base64'),
      commitment: String(entry.commitment ?? ''),
      member_aids: Array.isArray(entry.member_aids) ? entry.member_aids.map((item) => String(item)) : [],
    };
  }

  // 查 old_epochs
  const oldEpochs = (entry.old_epochs as GroupOldEpochRecord[]) ?? [];
  for (const old of oldEpochs) {
    if (old.epoch === epoch) {
      const secretStr = old.secret as string | undefined;
      if (!secretStr) return null;
      return {
        epoch: old.epoch as number,
        secret: Buffer.from(secretStr, 'base64'),
        commitment: String(old.commitment ?? ''),
        member_aids: Array.isArray(old.member_aids) ? old.member_aids.map((item) => String(item)) : [],
      };
    }
  }
  return null;
}

/** 加载某群组所有 epoch 的 group_secret */
export function loadAllGroupSecrets(
  keystore: KeyStore,
  aid: string,
  groupId: string,
): Map<number, Buffer> {
  const groupSecrets = loadAllKeyStoreGroupStates(keystore, aid);
  const entry = groupSecrets[groupId];
  if (!entry) return new Map();

  const result = new Map<number, Buffer>();
  const secretStr = entry.secret as string | undefined;
  if (secretStr && entry.epoch != null) {
    result.set(entry.epoch as number, Buffer.from(secretStr, 'base64'));
  }
  const oldEpochs = (entry.old_epochs as GroupOldEpochRecord[]) ?? [];
  for (const old of oldEpochs) {
    const oldSecret = old.secret as string | undefined;
    if (oldSecret && old.epoch != null) {
      result.set(old.epoch as number, Buffer.from(oldSecret, 'base64'));
    }
  }
  return result;
}

/** 清理过期的旧 epoch 记录。返回清理数量。 */
export function cleanupOldEpochs(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  retentionSeconds: number = OLD_EPOCH_RETENTION_SECONDS,
): number {
  const cutoffMs = Date.now() - retentionSeconds * 1000;
  return cleanupKeyStoreGroupOldEpochs(keystore, aid, groupId, cutoffMs);
}

/** 删除群组的所有密钥数据（群组解散时使用） */
export function deleteGroupSecret(
  keystore: KeyStore,
  aid: string,
  groupId: string,
): void {
  deleteKeyStoreGroupState(keystore, aid, groupId);
}

// ── GroupReplayGuard ──────────────────────────────────────────

/** 群组消息防重放守卫 */
export class GroupReplayGuard {
  private _seen = new Map<string, boolean>();
  private _maxSize: number;

  constructor(maxSize: number = 50000) {
    this._maxSize = maxSize;
  }

  /** 检查并记录。返回 true 表示首次（通过），false 表示重放（拒绝）。 */
  checkAndRecord(groupId: string, senderAid: string, messageId: string): boolean {
    const key = `${groupId}:${senderAid}:${messageId}`;
    if (this._seen.has(key)) return false;
    this._seen.set(key, true);
    this.trim();
    return true;
  }

  /** 仅检查是否已记录 */
  isSeen(groupId: string, senderAid: string, messageId: string): boolean {
    return this._seen.has(`${groupId}:${senderAid}:${messageId}`);
  }

  /** 仅记录，不检查 */
  record(groupId: string, senderAid: string, messageId: string): void {
    this._seen.set(`${groupId}:${senderAid}:${messageId}`, true);
    this.trim();
  }

  /** LRU 裁剪（供外部调用） */
  trim(): void {
    if (this._seen.size > this._maxSize) {
      const trimCount = this._seen.size - Math.floor(this._maxSize * 0.8);
      const iter = this._seen.keys();
      for (let i = 0; i < trimCount; i++) {
        const next = iter.next();
        if (next.done) break;
        this._seen.delete(next.value);
      }
    }
  }

  get size(): number {
    return this._seen.size;
  }
}

// ── GroupKeyRequestThrottle ──────────────────────────────────

/** 群组密钥请求/响应频率限制 */
export class GroupKeyRequestThrottle {
  private _last = new Map<string, number>();
  private _cooldown: number;

  constructor(cooldown: number = 30.0) {
    this._cooldown = cooldown;
  }

  /** 检查是否允许操作 */
  allow(key: string): boolean {
    const now = Date.now() / 1000;
    const last = this._last.get(key);
    if (last != null && (now - last) < this._cooldown) return false;
    this._last.set(key, now);
    return true;
  }

  reset(key: string): void {
    this._last.delete(key);
  }
}

// ── Group Key 分发与恢复协议 ──────────────────────────────────

/** 生成 32 字节随机 group_secret */
export function generateGroupSecret(): Buffer {
  return crypto.randomBytes(32);
}

/** 构建 group key 分发消息 payload */
export function buildKeyDistribution(
  groupId: string,
  epoch: number,
  groupSecret: Buffer,
  memberAids: string[],
  distributedBy: string,
  manifest?: JsonObject | null,
): JsonObject {
  const commitment = computeMembershipCommitment(memberAids, epoch, groupId, groupSecret);
  const result: JsonObject = {
    type: 'e2ee.group_key_distribution',
    group_id: groupId,
    epoch,
    group_secret: groupSecret.toString('base64'),
    commitment,
    member_aids: [...memberAids].sort(),
    distributed_by: distributedBy,
    distributed_at: Date.now(),
  };
  if (manifest) {
    result.manifest = manifest;
  }
  return result;
}

/** 处理收到的 group key 分发消息 */
export function handleKeyDistribution(
  message: Message | JsonObject,
  keystore: KeyStore,
  aid: string,
  initiatorCertPem?: string | null,
): boolean {
  const payload = 'group_id' in message
    ? message
    : (isJsonObject(message.payload) ? message.payload : message);

  const groupId = payload.group_id as string | undefined;
  const epoch = payload.epoch as number | undefined;
  const groupSecretB64 = payload.group_secret as string | undefined;
  const commitment = payload.commitment as string | undefined;
  const memberAids = (payload.member_aids as string[]) ?? [];

  if (!groupId || epoch == null || !groupSecretB64 || !commitment) return false;

  // 验证 Membership Manifest 签名
  const manifest = isJsonObject(payload.manifest) ? payload.manifest : undefined;
  if (initiatorCertPem) {
    if (!manifest) return false;
    if (!verifyMembershipManifest(manifest, initiatorCertPem)) return false;
    if (manifest.group_id !== groupId || manifest.epoch !== epoch) return false;
    const manifestMembers = [...((manifest.member_aids as string[]) ?? [])].sort();
    const payloadMembers = [...memberAids].sort();
    if (JSON.stringify(manifestMembers) !== JSON.stringify(payloadMembers)) return false;
  } else if (manifest) {
    if (manifest.group_id !== groupId || manifest.epoch !== epoch) return false;
    const manifestMembers = [...((manifest.member_aids as string[]) ?? [])].sort();
    const payloadMembers = [...memberAids].sort();
    if (JSON.stringify(manifestMembers) !== JSON.stringify(payloadMembers)) return false;
  }

  const groupSecret = Buffer.from(groupSecretB64, 'base64');

  // 验证 commitment
  if (!verifyMembershipCommitment(commitment, memberAids, epoch, groupId, aid, groupSecret)) {
    return false;
  }

  return storeGroupSecret(keystore, aid, groupId, epoch, groupSecret, commitment, memberAids);
}

/** 构建密钥请求 payload */
export function buildKeyRequest(
  groupId: string,
  epoch: number,
  requesterAid: string,
): JsonObject {
  return {
    type: 'e2ee.group_key_request',
    group_id: groupId,
    epoch,
    requester_aid: requesterAid,
  };
}

/** 处理收到的密钥请求 */
export function handleKeyRequest(
  request: Message | JsonObject,
  keystore: KeyStore,
  aid: string,
  currentMembers: string[],
): JsonObject | null {
  const payload = 'group_id' in request
    ? request
    : (isJsonObject(request.payload) ? request.payload : request);

  const requesterAid = payload.requester_aid as string | undefined;
  const groupId = payload.group_id as string | undefined;
  const epoch = payload.epoch as number | undefined;

  if (!requesterAid || !groupId || epoch == null) return null;

  // 验证请求者是群成员
  if (!currentMembers.includes(requesterAid)) return null;

  // 查本地密钥
  const secretData = loadGroupSecret(keystore, aid, groupId, epoch);
  if (!secretData) return null;

  let commitmentStr = secretData.commitment as string ?? '';
  const memberAids = (secretData.member_aids as string[]) ?? [];
  if (!commitmentStr) {
    commitmentStr = computeMembershipCommitment(
      memberAids.length > 0 ? memberAids : currentMembers,
      epoch, groupId, secretData.secret,
    );
  }

  return {
    type: 'e2ee.group_key_response',
    group_id: groupId,
    epoch,
    group_secret: secretData.secret.toString('base64'),
    commitment: commitmentStr,
    member_aids: memberAids.length > 0 ? memberAids : [...currentMembers].sort(),
  };
}

/** 处理收到的密钥响应 */
export function handleKeyResponse(
  response: Message | JsonObject,
  keystore: KeyStore,
  aid: string,
): boolean {
  const payload = 'group_id' in response
    ? response
    : (isJsonObject(response.payload) ? response.payload : response);

  const groupId = payload.group_id as string | undefined;
  const epoch = payload.epoch as number | undefined;
  const groupSecretB64 = payload.group_secret as string | undefined;
  const commitment = payload.commitment as string | undefined;
  const memberAids = (payload.member_aids as string[]) ?? [];

  if (!groupId || epoch == null || !groupSecretB64 || !commitment) return false;

  const groupSecret = Buffer.from(groupSecretB64, 'base64');

  if (!verifyMembershipCommitment(commitment, memberAids, epoch, groupId, aid, groupSecret)) {
    return false;
  }

  return storeGroupSecret(keystore, aid, groupId, epoch, groupSecret, commitment, memberAids);
}

// ── GroupE2EEManager 类 ───────────────────────────────────────

export class GroupE2EEManager {
  private _identityFn: () => IdentityRecord;
  private _keystore: KeyStore;
  private _replayGuard: GroupReplayGuard;
  private _requestThrottle: GroupKeyRequestThrottle;
  private _responseThrottle: GroupKeyRequestThrottle;
  private _senderCertResolver: ((aid: string) => string | null) | null;
  private _initiatorCertResolver: ((aid: string) => string | null) | null;

  constructor(opts: {
    identityFn: () => IdentityRecord;
    keystore: KeyStore;
    requestCooldown?: number;
    responseCooldown?: number;
    senderCertResolver?: (aid: string) => string | null;
    initiatorCertResolver?: (aid: string) => string | null;
  }) {
    this._identityFn = opts.identityFn;
    this._keystore = opts.keystore;
    this._replayGuard = new GroupReplayGuard();
    this._requestThrottle = new GroupKeyRequestThrottle(opts.requestCooldown ?? 30);
    this._responseThrottle = new GroupKeyRequestThrottle(opts.responseCooldown ?? 30);
    this._senderCertResolver = opts.senderCertResolver ?? null;
    this._initiatorCertResolver = opts.initiatorCertResolver ?? null;
  }

  // ── 密钥管理 ──────────────────────────────────────────

  /** 用当前身份私钥签名 manifest */
  private _signManifest(manifest: JsonObject): JsonObject {
    const identity = this._identityFn();
    const pkPem = identity.private_key_pem as string | undefined;
    if (!pkPem) return manifest;
    return signMembershipManifest(manifest, pkPem);
  }

  /** 创建首个 epoch。返回 {epoch, commitment, distributions: [{to, payload}]} */
  createEpoch(groupId: string, memberAids: string[]): JsonObject {
    const aid = this._currentAid();
    const gs = generateGroupSecret();
    const epoch = 1;
    const commitment = computeMembershipCommitment(memberAids, epoch, groupId, gs);
    storeGroupSecret(this._keystore, aid, groupId, epoch, gs, commitment, memberAids);
    const manifest = this._signManifest(buildMembershipManifest(
      groupId, epoch, null, memberAids, { initiatorAid: aid },
    ));
    const distPayload = buildKeyDistribution(groupId, epoch, gs, memberAids, aid, manifest);
    return {
      epoch,
      commitment,
      distributions: memberAids
        .filter(m => m !== aid)
        .map(m => ({ to: m, payload: distPayload })),
    };
  }

  /** 轮换 epoch（踢人/退出后调用） */
  rotateEpoch(groupId: string, memberAids: string[]): JsonObject {
    const aid = this._currentAid();
    const current = loadGroupSecret(this._keystore, aid, groupId);
    const prevEpoch = current ? Number(current.epoch) : null;
    const newEpoch = (prevEpoch ?? 0) + 1;
    const gs = generateGroupSecret();
    const commitment = computeMembershipCommitment(memberAids, newEpoch, groupId, gs);
    const stored = storeGroupSecret(this._keystore, aid, groupId, newEpoch, gs, commitment, memberAids);
    if (!stored) {
      throw new Error(`group ${groupId} epoch ${newEpoch} secret already exists or is newer; abort distribution`);
    }
    const manifest = this._signManifest(buildMembershipManifest(
      groupId, newEpoch, prevEpoch, memberAids, { initiatorAid: aid },
    ));
    const distPayload = buildKeyDistribution(groupId, newEpoch, gs, memberAids, aid, manifest);
    return {
      epoch: newEpoch,
      commitment,
      distributions: memberAids
        .filter(m => m !== aid)
        .map(m => ({ to: m, payload: distPayload })),
    };
  }

  /** 指定目标 epoch 号轮换（配合服务端 CAS 使用） */
  rotateEpochTo(
    groupId: string,
    newEpoch: number,
    memberAids: string[],
  ): JsonObject {
    const aid = this._currentAid();
    const gs = generateGroupSecret();
    const commitment = computeMembershipCommitment(memberAids, newEpoch, groupId, gs);
    const stored = storeGroupSecret(this._keystore, aid, groupId, newEpoch, gs, commitment, memberAids);
    if (!stored) {
      throw new Error(`group ${groupId} epoch ${newEpoch} secret already exists or is newer; abort distribution`);
    }
    const manifest = this._signManifest(buildMembershipManifest(
      groupId, newEpoch, newEpoch - 1, memberAids, { initiatorAid: aid },
    ));
    const distPayload = buildKeyDistribution(groupId, newEpoch, gs, memberAids, aid, manifest);
    return {
      epoch: newEpoch,
      commitment,
      distributions: memberAids
        .filter(m => m !== aid)
        .map(m => ({ to: m, payload: distPayload })),
    };
  }

  /** 加密群消息（含发送方签名）。无密钥时抛 E2EEGroupSecretMissingError。 */
  encrypt(groupId: string, payload: JsonObject): JsonObject {
    const aid = this._currentAid();
    const secretData = loadGroupSecret(this._keystore, aid, groupId);
    if (!secretData) {
      throw new E2EEGroupSecretMissingError(`no group secret for ${groupId}`);
    }
    const identity = this._identityFn();
    const senderPkPem = identity ? (identity.private_key_pem as string | undefined) ?? null : null;
    // TS-017: 签名失败必须阻止发送，不允许发出无签名的群消息
    if (!senderPkPem) {
      throw new E2EEError('sender identity private key unavailable for group message signing');
    }
    const senderCertPem = identity ? (identity.cert as string | undefined) ?? null : null;
    return encryptGroupMessage(
      groupId,
      secretData.epoch as number,
      secretData.secret,
      payload,
      {
        fromAid: aid,
        messageId: `gm-${crypto.randomUUID()}`,
        timestamp: Date.now(),
        senderPrivateKeyPem: senderPkPem,
        senderCertPem,
      },
    );
  }

  /** 解密单条群消息。内置防重放 + 发送方验签。 */
  decrypt(message: Message, opts?: { skipReplay?: boolean }): Message | null {
    const payload = isJsonObject(message.payload) ? message.payload : null;
    if (payload === null || payload.type !== 'e2ee.group_encrypted') {
      return message;
    }
    const groupId = (message.group_id as string) || '';
    const sender = (message.from as string) || (message.sender_aid as string) || '';

    // 防重放预检：优先使用 AAD 内 message_id
    const aad = isJsonObject(payload.aad) ? payload.aad : undefined;
    const aadMsgId = aad ? (aad.message_id as string ?? '') : '';
    const msgId = aadMsgId || (message.message_id as string) || '';
    if (!opts?.skipReplay && groupId && sender && msgId) {
      if (this._replayGuard.isSeen(groupId, sender, msgId)) {
        return null;
      }
    }

    // 解析发送方证书（零信任：无证书则拒绝）
    let senderCertPem: string | null = null;
    if (this._senderCertResolver && sender) {
      senderCertPem = this._senderCertResolver(sender);
    }
    if (!senderCertPem) return null;

    const allSecrets = loadAllGroupSecrets(this._keystore, this._currentAid(), groupId);
    if (allSecrets.size === 0) return null;
    const result = decryptGroupMessage(message, allSecrets, senderCertPem);

    // 解密成功后记录防重放
    if (result != null) {
      const finalMsgId = aadMsgId || (message.message_id as string) || '';
      if (!opts?.skipReplay && groupId && sender && finalMsgId) {
        this._replayGuard.record(groupId, sender, finalMsgId);
      }
    }
    return result;
  }

  /** 批量解密 */
  decryptBatch(messages: Message[], opts?: { skipReplay?: boolean }): Message[] {
    return messages.map(m => this.decrypt(m, opts) ?? m);
  }

  // ── 密钥协议消息处理 ──────────────────────────────────

  /**
   * 处理已解密的 P2P 密钥消息。
   * 返回 "distribution"/"request"/"response" 表示已成功处理。
   * 返回 "distribution_rejected"/"response_rejected" 表示被拒绝。
   * 返回 null 表示不是密钥消息。
   */
  handleIncoming(payload: JsonObject): string | null {
    const msgType = (payload.type as string) || '';
    const aid = this._currentAid();

    if (msgType === 'e2ee.group_key_distribution') {
      let initiatorCert: string | null = null;
      const distributedBy = (payload.distributed_by as string) || '';
      if (this._initiatorCertResolver && distributedBy) {
        initiatorCert = this._initiatorCertResolver(distributedBy);
      }
      const ok = handleKeyDistribution(payload, this._keystore, aid, initiatorCert);
      return ok ? 'distribution' : 'distribution_rejected';
    }
    if (msgType === 'e2ee.group_key_response') {
      const ok = handleKeyResponse(payload, this._keystore, aid);
      return ok ? 'response' : 'response_rejected';
    }
    if (msgType === 'e2ee.group_key_request') {
      return 'request';
    }
    return null;
  }

  /** 构建恢复请求。返回 {to, payload} 或 null（限流/无目标）。 */
  buildRecoveryRequest(
    groupId: string,
    epoch: number,
    senderAid?: string,
  ): JsonObject | null {
    const aid = this._currentAid();
    if (!this._requestThrottle.allow(`request:${groupId}:${epoch}`)) {
      return null;
    }
    let candidates: string[] = [];
    const secretData = loadGroupSecret(this._keystore, aid, groupId);
    if (secretData && (secretData.member_aids as string[] | undefined)?.length) {
      candidates = (secretData.member_aids as string[]).filter(m => m !== aid);
    }
    if (candidates.length === 0 && senderAid && senderAid !== aid) {
      candidates = [senderAid];
    }
    if (candidates.length === 0) return null;
    return { to: candidates[0], payload: buildKeyRequest(groupId, epoch, aid) };
  }

  /** 处理密钥请求。返回响应 payload（受频率限制 + 成员资格验证）。 */
  handleKeyRequestMsg(
    requestPayload: JsonObject,
    members: string[],
  ): JsonObject | null {
    const requester = (requestPayload.requester_aid as string) || '';
    const groupId = (requestPayload.group_id as string) || '';
    if (!requester || !groupId) return null;
    // 成员资格验证
    if (!members.includes(requester)) return null;
    if (!this._responseThrottle.allow(`response:${groupId}:${requester}`)) {
      return null;
    }
    return handleKeyRequest(requestPayload, this._keystore, this._currentAid(), members);
  }

  // ── 状态查询 ──────────────────────────────────────────

  /** 检查是否有群组密钥 */
  hasSecret(groupId: string): boolean {
    return loadGroupSecret(this._keystore, this._currentAid(), groupId) != null;
  }

  /** 获取当前 epoch */
  currentEpoch(groupId: string): number | null {
    const s = loadGroupSecret(this._keystore, this._currentAid(), groupId);
    return s ? (s.epoch as number) : null;
  }

  /** 获取群组成员 AID 列表 */
  getMemberAids(groupId: string): string[] {
    const s = loadGroupSecret(this._keystore, this._currentAid(), groupId);
    return s ? ((s.member_aids as string[]) ?? []) : [];
  }

  /** 加载群组密钥数据 */
  loadSecret(groupId: string, epoch?: number | null): LoadedGroupSecret | null {
    return loadGroupSecret(this._keystore, this._currentAid(), groupId, epoch);
  }

  /** 清理过期的旧 epoch */
  cleanup(groupId: string, retentionSeconds: number = OLD_EPOCH_RETENTION_SECONDS): void {
    cleanupOldEpochs(this._keystore, this._currentAid(), groupId, retentionSeconds);
  }

  /** 清理过期缓存（replay guard 等），供外部定时调用 */
  cleanExpiredCaches(): void {
    this._replayGuard.trim();
  }

  /** 删除群组的所有本地状态（群组解散时使用） */
  removeGroup(groupId: string): void {
    try {
      deleteGroupSecret(this._keystore, this._currentAid(), groupId);
    } catch {
      // keystore 不支持 delete 时忽略（降级方案已在 deleteKeyStoreGroupState 中处理）
    }
  }

  private _currentAid(): string {
    const identity = this._identityFn();
    const aid = identity.aid;
    if (!aid) throw new E2EEError('AID unavailable');
    return String(aid);
  }
}
