/**
 * GroupE2EEManager — 群组端到端加密管理器 + 纯函数
 *
 * 与 E2EEManager 平行：所有网络操作（P2P 发送、RPC 调用）由调用方负责。
 * 内置防重放、epoch 降级防护、密钥请求频率限制。
 */

import * as crypto from 'node:crypto';
import type { KeyStore } from './keystore/index.js';
import type { ProtectedHeadersInput } from './e2ee.js';

import {
  E2EEError,
  E2EEGroupSecretMissingError,
} from './errors.js';
import {
  isJsonObject,
  type GroupSecretRecord,
  type IdentityRecord,
  type JsonObject,
  type Message,
} from './types.js';
import type { ModuleLogger } from './logger.js';

const _noopLogger: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };

export interface LoadedGroupSecret {
  epoch: number;
  secret: Buffer;
  commitment: string;
  member_aids: string[];
  epoch_chain?: string;
  pending_rotation_id?: string;
  epoch_chain_unverified?: boolean;
  epoch_chain_unverified_reason?: string;
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

const AAD_OPTIONAL_FIELDS: readonly string[] = [
  'payload_type', 'protected_headers', 'context_type', 'context_id',
] as const;

const METADATA_AUTH_FIELD = '_auth';
const METADATA_AUTH_ALG = 'HMAC-SHA256';
const METADATA_KEY_DOMAIN = Buffer.from('aun-envelope-metadata-key-v1', 'utf-8');
const PROTECTED_HEADERS_DOMAIN = Buffer.from('aun-protected-headers-v1', 'utf-8');
const PROTECTED_CONTEXT_DOMAIN = Buffer.from('aun-protected-context-v1', 'utf-8');

/** 旧 epoch 默认保留 7 天 */
const OLD_EPOCH_RETENTION_SECONDS = 7 * 24 * 3600;

// ── ECIES (P-256 ECDH + HKDF-SHA256 + AES-256-GCM) ──────────

const ECIES_HKDF_INFO = Buffer.from('aun-epoch-key-ecies', 'utf-8');

/**
 * ECIES 加密：P-256 ECDH + HKDF-SHA256 + AES-256-GCM。
 * @param peerPubkeyBytes 65 字节未压缩 P-256 公钥 (0x04 开头)
 * @param plaintext 待加密明文
 * @returns ephemeral_pubkey(65B) || iv(12B) || ciphertext || tag(16B)
 */
export function eciesEncrypt(peerPubkeyBytes: Buffer, plaintext: Buffer): Buffer {
  // 生成临时密钥对
  const ephemeral = crypto.createECDH('prime256v1');
  ephemeral.generateKeys();
  const ephemeralPubBytes = ephemeral.getPublicKey(); // 65 字节未压缩

  // ECDH 共享密钥
  const shared = ephemeral.computeSecret(peerPubkeyBytes);

  // HKDF 派生 32 字节 AES 密钥
  const derived = crypto.hkdfSync('sha256', shared, Buffer.alloc(0), ECIES_HKDF_INFO, 32);
  const aesKey = Buffer.from(derived);

  // AES-256-GCM 加密
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 字节

  return Buffer.concat([ephemeralPubBytes, iv, encrypted, tag]);
}

/**
 * ECIES 解密：对应 eciesEncrypt。
 * @param privateKeyPem 自己的 PEM 格式 EC 私钥
 * @param ciphertext ephemeral_pubkey(65B) || iv(12B) || encrypted || tag(16B)
 * @returns 解密后的明文
 */
export function eciesDecrypt(privateKeyPem: string, ciphertext: Buffer): Buffer {
  if (ciphertext.length < 65 + 12 + 16) {
    throw new E2EEError('ECIES ciphertext too short');
  }
  const ephemeralPubBytes = ciphertext.subarray(0, 65);
  const iv = ciphertext.subarray(65, 77);
  const encryptedWithTag = ciphertext.subarray(77);
  const tag = encryptedWithTag.subarray(encryptedWithTag.length - 16);
  const encrypted = encryptedWithTag.subarray(0, encryptedWithTag.length - 16);

  // 从 PEM 私钥创建 ECDH 并计算共享密钥
  const privKeyObj = crypto.createPrivateKey(privateKeyPem);
  const ecdh = crypto.createECDH('prime256v1');
  // 从 JWK 提取私钥 d 值设置到 ECDH
  const jwk = privKeyObj.export({ format: 'jwk' });
  ecdh.setPrivateKey(Buffer.from(jwk.d!, 'base64url'));

  const shared = ecdh.computeSecret(ephemeralPubBytes);

  // HKDF 派生 AES 密钥
  const derived = crypto.hkdfSync('sha256', shared, Buffer.alloc(0), ECIES_HKDF_INFO, 32);
  const aesKey = Buffer.from(derived);

  // AES-256-GCM 解密
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

// ── Epoch Transcript Chain ────────────────────────────────────

const EPOCH_CHAIN_GENESIS_PREFIX = Buffer.from('aun-epoch-chain:genesis', 'utf-8');

/**
 * 计算 Epoch Transcript Chain。
 * genesis（prev_chain=null）使用固定前缀；后续 epoch 使用上一个 chain 的字节。
 */
export function computeEpochChain(
  prevChain: string | null,
  epoch: number,
  commitment: string,
  rotatorAid: string,
): string {
  const prefix = prevChain === null
    ? EPOCH_CHAIN_GENESIS_PREFIX
    : Buffer.from(prevChain, 'hex');
  const epochBuf = Buffer.alloc(4);
  epochBuf.writeUInt32BE(epoch, 0);
  const data = Buffer.concat([
    prefix,
    epochBuf,
    Buffer.from(commitment, 'utf-8'),
    Buffer.from(rotatorAid, 'utf-8'),
  ]);
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * 验证 Epoch Transcript Chain（常量时间比较）。
 */
export function verifyEpochChain(
  epochChain: string,
  prevChain: string | null,
  epoch: number,
  commitment: string,
  rotatorAid: string,
): boolean {
  const expected = computeEpochChain(prevChain, epoch, commitment, rotatorAid);
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(epochChain, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function loadKeyStoreGroupEpoch(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  epoch?: number | null,
): GroupSecretRecord | null {
  if (typeof keystore.loadGroupSecretEpoch === 'function') {
    return keystore.loadGroupSecretEpoch(aid, groupId, epoch);
  }
  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} missing loadGroupSecretEpoch method`);
}

function loadKeyStoreGroupEpochs(
  keystore: KeyStore,
  aid: string,
  groupId: string,
): GroupSecretRecord[] {
  if (typeof keystore.loadGroupSecretEpochs === 'function') {
    return keystore.loadGroupSecretEpochs(aid, groupId);
  }
  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} missing loadGroupSecretEpochs method`);
}

function storeKeyStoreGroupTransition(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  opts: {
    epoch: number;
    secret: string;
    commitment: string;
    memberAids: string[];
    epochChain?: string;
    pendingRotationId?: string;
    epochChainUnverified?: boolean | null;
    epochChainUnverifiedReason?: string | null;
  },
): boolean | null {
  if (typeof keystore.storeGroupSecretTransition !== 'function') return null;
  return keystore.storeGroupSecretTransition(aid, groupId, {
    ...opts,
    oldEpochRetentionMs: OLD_EPOCH_RETENTION_SECONDS * 1000,
  });
}

function storeKeyStoreGroupEpoch(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  opts: {
    epoch: number;
    secret: string;
    commitment: string;
    memberAids: string[];
    epochChain?: string;
    pendingRotationId?: string;
    epochChainUnverified?: boolean | null;
    epochChainUnverifiedReason?: string | null;
  },
): boolean | null {
  if (typeof keystore.storeGroupSecretEpoch !== 'function') return null;
  return keystore.storeGroupSecretEpoch(aid, groupId, {
    ...opts,
    oldEpochRetentionMs: OLD_EPOCH_RETENTION_SECONDS * 1000,
  });
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

function groupKeyResponseSignData(payload: JsonObject): Buffer {
  const fields = [
    String(payload.response_version ?? 1),
    String(payload.group_id ?? ''),
    String(payload.epoch ?? 0),
    String(payload.requester_aid ?? ''),
    String(payload.request_id ?? ''),
    String(payload.responder_aid ?? ''),
    String(payload.commitment ?? ''),
    [...((payload.member_aids as string[] | undefined) ?? [])].sort().join('|'),
    String(payload.issued_at ?? 0),
  ];
  return Buffer.from(fields.join('\n'), 'utf-8');
}

export function signGroupKeyResponse(payload: JsonObject, privateKeyPem: string): JsonObject {
  const signed: JsonObject = {
    ...payload,
    response_version: payload.response_version ?? 1,
    issued_at: payload.issued_at ?? Date.now(),
  };
  signed.response_signature = ecdsaSign(privateKeyPem, groupKeyResponseSignData(signed)).toString('base64');
  return signed;
}

export function verifyGroupKeyResponseSignature(payload: JsonObject, responderCertPem: string): boolean {
  const sigB64 = payload.response_signature as string | undefined;
  if (!sigB64) return false;
  try {
    return ecdsaVerify(pemToCertPublicKey(responderCertPem), Buffer.from(sigB64, 'base64'), groupKeyResponseSignData(payload));
  } catch {
    return false;
  }
}

/** PEM 证书 → 公钥 KeyObject */
function pemToCertPublicKey(certPem: string | Buffer): crypto.KeyObject {
  const pem = typeof certPem === 'string' ? certPem : certPem.toString('utf-8');
  const x509 = new crypto.X509Certificate(pem);
  return x509.publicKey;
}

// ── 群组 AAD 工具 ─────────────────────────────────────────────

function canonicalStringify(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (Array.isArray(value)) {
    return `[${value.map(item => canonicalStringify(item)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const pairs = Object.keys(record)
      .sort()
      .map(key => `${JSON.stringify(key)}:${canonicalStringify(record[key])}`);
    return `{${pairs.join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function hasOwn(obj: JsonObject, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function normalizeProtectedHeaderKey(key: unknown): string {
  const value = String(key ?? '').trim().toLowerCase();
  if (!value || !/^[a-z0-9_-]+$/.test(value)) {
    throw new E2EEError('protected header key must match [a-z0-9_-]+');
  }
  if (value === METADATA_AUTH_FIELD) {
    throw new E2EEError('protected header key is reserved');
  }
  return value;
}

function normalizeProtectedHeaders(headers: ProtectedHeadersInput): JsonObject {
  if (headers == null) return {};
  const toObject = (headers as { toObject?: () => Record<string, unknown> }).toObject;
  const raw = typeof toObject === 'function' ? toObject.call(headers) : headers;
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new E2EEError('protected_headers must be an object');
  }
  const result: JsonObject = {};
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    result[normalizeProtectedHeaderKey(key)] = value == null ? '' : String(value);
  }
  return result;
}

function copyOptionalEnvelopeMetadata(
  envelope: JsonObject,
  messageKey: Buffer,
  opts?: {
    payloadType?: unknown;
    protectedHeaders?: ProtectedHeadersInput;
    context?: unknown;
  },
): void {
  const payloadType = String(opts?.payloadType ?? '').trim();
  const protectedHeaders = normalizeProtectedHeaders(opts?.protectedHeaders);
  if (payloadType) {
    protectedHeaders.payload_type = payloadType;
  }
  if (Object.keys(protectedHeaders).length > 0) {
    envelope.protected_headers = withMetadataAuth(
      protectedHeaders,
      messageKey,
      PROTECTED_HEADERS_DOMAIN,
    );
  }
  const contextMetadata = normalizeContextMetadata(opts?.context);
  if (Object.keys(contextMetadata).length > 0) {
    envelope.context = withMetadataAuth(
      contextMetadata,
      messageKey,
      PROTECTED_CONTEXT_DOMAIN,
    );
  }
}

function metadataBody(metadata: Record<string, unknown>): JsonObject {
  const body: JsonObject = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (key !== METADATA_AUTH_FIELD) {
      body[key] = value as JsonObject[string];
    }
  }
  return body;
}

function metadataAuthTag(key: Buffer, domain: Buffer, body: JsonObject): Buffer {
  const metadataKey = crypto.createHmac('sha256', key).update(METADATA_KEY_DOMAIN).digest();
  return crypto.createHmac('sha256', metadataKey)
    .update(domain)
    .update(Buffer.from([0]))
    .update(Buffer.from(canonicalStringify(body), 'utf-8'))
    .digest();
}

function withMetadataAuth(metadata: JsonObject, key: Buffer, domain: Buffer): JsonObject {
  const body = metadataBody(metadata);
  if (Object.keys(body).length === 0) return {};
  const tag = metadataAuthTag(key, domain, body);
  return {
    ...body,
    [METADATA_AUTH_FIELD]: {
      alg: METADATA_AUTH_ALG,
      tag: tag.toString('base64'),
    },
  };
}

function verifyMetadataAuth(metadata: unknown, key: Buffer, domain: Buffer): boolean {
  if (metadata == null) return true;
  if (typeof metadata !== 'object' || Array.isArray(metadata)) return false;
  const record = metadata as Record<string, unknown>;
  const auth = record[METADATA_AUTH_FIELD];
  if (!auth || typeof auth !== 'object' || Array.isArray(auth)) return false;
  const authObj = auth as Record<string, unknown>;
  if (authObj.alg !== METADATA_AUTH_ALG) return false;
  if (typeof authObj.tag !== 'string' || !authObj.tag) return false;
  const body = metadataBody(record);
  if (Object.keys(body).length === 0) return false;
  const actual = Buffer.from(authObj.tag, 'base64');
  const expected = metadataAuthTag(key, domain, body);
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function verifyEnvelopeMetadataAuth(payload: JsonObject, messageKey: Buffer): boolean {
  return verifyMetadataAuth(payload.protected_headers, messageKey, PROTECTED_HEADERS_DOMAIN)
    && verifyMetadataAuth(payload.context, messageKey, PROTECTED_CONTEXT_DOMAIN);
}

function normalizeContextMetadata(context: unknown): JsonObject {
  if (!context || typeof context !== 'object' || Array.isArray(context)) return {};
  return metadataBody(context as Record<string, unknown>);
}

function exposedEnvelopeMetadata(metadata: unknown): JsonObject | undefined {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) return undefined;
  const body = metadataBody(metadata as Record<string, unknown>);
  return Object.keys(body).length > 0 ? body : undefined;
}

function validateDecryptedEnvelopeMetadata(
  decoded: unknown,
  payload: JsonObject,
  message?: Message | null,
): boolean {
  if (payload.protected_headers && typeof payload.protected_headers === 'object' && !Array.isArray(payload.protected_headers)) {
    const headers = metadataBody(payload.protected_headers as Record<string, unknown>);
    if (hasOwn(headers, 'payload_type')) {
      if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) return false;
      if (String((decoded as Record<string, unknown>).type ?? '') !== String(headers.payload_type ?? '')) {
        return false;
      }
    }
  }
  if (payload.context && typeof payload.context === 'object' && !Array.isArray(payload.context)) {
    const protectedContext = metadataBody(payload.context as Record<string, unknown>);
    const outerContext = normalizeContextMetadata(message?.context);
    if (canonicalStringify(outerContext) !== canonicalStringify(protectedContext)) return false;
  }
  return true;
}

/** 群组 AAD 序列化（sorted keys, compact JSON） */
function aadBytesGroup(aad: JsonObject): Buffer {
  const obj: JsonObject = {};
  for (const field of AAD_FIELDS_GROUP) {
    obj[field] = aad[field] ?? null;
  }
  return Buffer.from(canonicalStringify(obj), 'utf-8');
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
    protectedHeaders?: ProtectedHeadersInput;
    protected_headers?: ProtectedHeadersInput;
    headers?: ProtectedHeadersInput;
    context?: JsonObject | null;
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
  const envelope: JsonObject = {
    type: 'e2ee.group_encrypted',
    version: '1',
    encryption_mode: MODE_EPOCH_GROUP_KEY,
    suite: SUITE,
    epoch,
  };
  copyOptionalEnvelopeMetadata(envelope, msgKey, {
    payloadType: payload.type,
    protectedHeaders: opts.protectedHeaders ?? opts.protected_headers ?? opts.headers,
    context: opts.context ?? null,
  });
  const aadBytes = aadBytesGroup(aad);
  const { ciphertext, tag, nonce } = aesGcmEncrypt(msgKey, plaintext, aadBytes);

  envelope.nonce = nonce.toString('base64');
  envelope.ciphertext = ciphertext.toString('base64');
  envelope.tag = tag.toString('base64');
  envelope.aad = aad;

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
  opts?: { requireSignature?: boolean; logger?: ModuleLogger },
): Message | null {
  const requireSignature = opts?.requireSignature ?? true;
  const logger = opts?.logger;
  const payload = isJsonObject(message.payload) ? message.payload : null;
  if (payload === null) {
    logger?.warn(`decryptGroupMessage rejected: payload is not an object mid=${String(message.message_id ?? '')}`);
    return null;
  }
  if (payload.type !== 'e2ee.group_encrypted') {
    logger?.warn(`decryptGroupMessage rejected: unexpected payload.type=${String(payload.type)} mid=${String(message.message_id ?? '')}`);
    return null;
  }

  const epoch = payload.epoch as number | undefined;
  if (epoch == null) {
    logger?.warn(`decryptGroupMessage rejected: missing epoch mid=${String(message.message_id ?? '')}`);
    return null;
  }

  const groupSecret = groupSecrets.get(epoch);
  if (!groupSecret) {
    logger?.warn(`decryptGroupMessage rejected: no group secret for epoch=${epoch} mid=${String(message.message_id ?? '')}`);
    return null;
  }

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
      if (outerGroupId && groupId !== outerGroupId) {
        logger?.warn(`decryptGroupMessage rejected: outer group_id does not match aad.group_id outer=${outerGroupId} aad=${groupId}`);
        return null;
      }
      if (aadFrom) {
        const outerFrom = (message.from as string) || '';
        const outerSender = (message.sender_aid as string) || '';
        if (outerFrom && outerFrom !== aadFrom) {
          logger?.warn(`decryptGroupMessage rejected: outer from does not match aad.from outer=${outerFrom} aad=${aadFrom}`);
          return null;
        }
        if (outerSender && outerSender !== aadFrom) {
          logger?.warn(`decryptGroupMessage rejected: outer sender_aid does not match aad.from outer=${outerSender} aad=${aadFrom}`);
          return null;
        }
      }
    } else {
      groupId = outerGroupId;
      messageId = (message.message_id as string) || '';
    }

    if (!groupId || !messageId) {
      logger?.warn(`decryptGroupMessage rejected: missing group_id or message_id group=${groupId} mid=${messageId}`);
      return null;
    }

    const msgKey = deriveGroupMsgKey(groupSecret, groupId, messageId);
    const nonce = Buffer.from(payload.nonce as string, 'base64');
    const ciphertext = Buffer.from(payload.ciphertext as string, 'base64');
    const tag = Buffer.from(payload.tag as string, 'base64');

    if (!verifyEnvelopeMetadataAuth(payload, msgKey)) {
      logger?.warn(`decryptGroupMessage rejected: envelope metadata auth failed group=${groupId} mid=${messageId}`);
      return null;
    }
    const aadBytes = aad ? aadBytesGroup(aad) : Buffer.alloc(0);
    const plaintext = aesGcmDecrypt(msgKey, ciphertext, tag, nonce, aadBytes);
    const decoded = JSON.parse(plaintext.toString('utf-8'));
    if (!validateDecryptedEnvelopeMetadata(decoded, payload, message)) {
      logger?.warn(`decryptGroupMessage rejected: decrypted envelope metadata validation failed group=${groupId} mid=${messageId}`);
      return null;
    }

    const e2ee: JsonObject = {
      encryption_mode: MODE_EPOCH_GROUP_KEY,
      suite: SUITE,
      epoch,
      sender_verified: false,
    };
    const protectedHeaders = exposedEnvelopeMetadata(payload.protected_headers);
    if (protectedHeaders) e2ee.protected_headers = protectedHeaders;
    const context = exposedEnvelopeMetadata(payload.context);
    if (context) e2ee.context = context;

    const result: Message = {
      ...message,
      payload: decoded,
      encrypted: true,
      e2ee,
    };

    // 发送方签名验证
    const senderSigB64 = payload.sender_signature as string | undefined;
    if (requireSignature) {
      if (!senderSigB64) {
        logger?.warn(`decryptGroupMessage rejected: sender signature required but missing group=${groupId} mid=${messageId}`);
        return null;
      }
      if (!senderCertPem) {
        logger?.warn(`decryptGroupMessage rejected: sender signature required but senderCertPem missing group=${groupId} mid=${messageId}`);
        return null;
      }
      try {
        const senderPub = pemToCertPublicKey(senderCertPem);
        const sigBytes = Buffer.from(senderSigB64, 'base64');
        const verifyPayload = Buffer.concat([ciphertext, tag, aadBytes]);
        if (!ecdsaVerify(senderPub, sigBytes, verifyPayload)) {
          logger?.warn(`decryptGroupMessage rejected: sender signature verification failed group=${groupId} mid=${messageId}`);
          return null;
        }
        if (isJsonObject(result.e2ee)) result.e2ee.sender_verified = true;
      } catch (exc) {
        logger?.warn(`decryptGroupMessage rejected: sender signature verification threw group=${groupId} mid=${messageId} err=${String(exc)}`);
        return null;
      }
    } else if (senderCertPem) {
      // 非零信任模式但提供了证书：有证书时强制验签
      if (!senderSigB64) {
        logger?.warn(`decryptGroupMessage rejected: senderCertPem present but signature missing group=${groupId} mid=${messageId}`);
        return null;
      }
      try {
        const senderPub = pemToCertPublicKey(senderCertPem);
        const sigBytes = Buffer.from(senderSigB64, 'base64');
        const verifyPayload = Buffer.concat([ciphertext, tag, aadBytes]);
        if (!ecdsaVerify(senderPub, sigBytes, verifyPayload)) {
          logger?.warn(`decryptGroupMessage rejected: optional sender signature verification failed group=${groupId} mid=${messageId}`);
          return null;
        }
        if (isJsonObject(result.e2ee)) result.e2ee.sender_verified = true;
      } catch (exc) {
        logger?.warn(`decryptGroupMessage rejected: optional sender signature verification threw group=${groupId} mid=${messageId} err=${String(exc)}`);
        return null;
      }
    }

    return result;
  } catch (exc) {
    logger?.warn(`decryptGroupMessage rejected: decrypt threw mid=${String(message.message_id ?? '')} err=${String(exc)}`);
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

// ── State Hash ────────────────────────────────────────────────

/**
 * 计算群组状态哈希（链式）。
 * state_hash = SHA-256(group_id | 0x00 | state_version(u64be) | 0x00 |
 *   key_epoch(u64be) | 0x00 | membership_block | 0x00 | policy_block | 0x00 | prev_state_hash(32B))
 */
export function computeStateHash(params: {
  groupId: string;
  stateVersion: number;
  keyEpoch: number;
  members: Array<{ aid: string; role: string }>;
  policy: Record<string, unknown>;
  prevStateHash: string;
}): string {
  const { groupId, stateVersion, keyEpoch, members, policy, prevStateHash } = params;

  // 按 AID 排序，构建 membership_block
  const sorted = [...members].sort((a, b) => a.aid.localeCompare(b.aid));
  const membershipBlock = sorted.map(m => `${m.aid}:${m.role}`).join('|');

  // 按 key 排序的 canonical JSON（无空格）
  const sortedPolicy: Record<string, unknown> = {};
  for (const key of Object.keys(policy).sort()) {
    sortedPolicy[key] = policy[key];
  }
  const policyBlock = Object.keys(policy).length > 0 ? JSON.stringify(sortedPolicy) : '';

  // prev_state_hash: 32 字节，空则全零
  const prevBytes = prevStateHash
    ? Buffer.from(prevStateHash, 'hex')
    : Buffer.alloc(32);

  // state_version / key_epoch → uint64 big-endian
  const svBuf = Buffer.alloc(8);
  svBuf.writeBigUInt64BE(BigInt(stateVersion));
  const keBuf = Buffer.alloc(8);
  keBuf.writeBigUInt64BE(BigInt(keyEpoch));

  const data = Buffer.concat([
    Buffer.from(groupId, 'utf-8'), Buffer.from([0x00]),
    svBuf, Buffer.from([0x00]),
    keBuf, Buffer.from([0x00]),
    Buffer.from(membershipBlock, 'utf-8'), Buffer.from([0x00]),
    Buffer.from(policyBlock, 'utf-8'), Buffer.from([0x00]),
    prevBytes,
  ]);

  return crypto.createHash('sha256').update(data).digest('hex');
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
  epochChain?: string,
  pendingRotationId = '',
  epochChainUnverified?: boolean | null,
  epochChainUnverifiedReason?: string | null,
): boolean {
  const transitionResult = storeKeyStoreGroupTransition(keystore, aid, groupId, {
    epoch,
    secret: groupSecret.toString('base64'),
    commitment,
    memberAids: [...memberAids].sort(),
    epochChain,
    pendingRotationId,
    epochChainUnverified,
    epochChainUnverifiedReason,
  });
  if (transitionResult !== null) return transitionResult;
  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} missing storeGroupSecretTransition method`);
}

/** 保存指定 epoch key；低于 current 时写入 old epoch，不覆盖 current。 */
export function storeGroupSecretEpoch(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  epoch: number,
  groupSecret: Buffer,
  commitment: string,
  memberAids: string[],
  epochChain?: string,
  pendingRotationId = '',
  epochChainUnverified?: boolean | null,
  epochChainUnverifiedReason?: string | null,
): boolean {
  const secret = groupSecret.toString('base64');
  const members = [...memberAids].sort();
  const rowResult = storeKeyStoreGroupEpoch(keystore, aid, groupId, {
    epoch,
    secret,
    commitment,
    memberAids: members,
    epochChain,
    pendingRotationId,
    epochChainUnverified,
    epochChainUnverifiedReason,
  });
  if (rowResult !== null) return rowResult;
  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} missing storeGroupSecretEpoch method`);
}

/** 读取 group_secret */
export function loadGroupSecret(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  epoch?: number | null,
): LoadedGroupSecret | null {
  const entry = loadKeyStoreGroupEpoch(keystore, aid, groupId, epoch) ?? undefined;
  if (!entry) return null;

  const secretStr = entry.secret as string | undefined;
  if (!secretStr) return null;
  const loaded: LoadedGroupSecret = {
    epoch: entry.epoch as number,
    secret: Buffer.from(secretStr, 'base64'),
    commitment: String(entry.commitment ?? ''),
    member_aids: Array.isArray(entry.member_aids) ? entry.member_aids.map((item) => String(item)) : [],
  };
  if (typeof entry.epoch_chain === 'string') loaded.epoch_chain = entry.epoch_chain;
  if (typeof entry.pending_rotation_id === 'string') loaded.pending_rotation_id = entry.pending_rotation_id;
  if (typeof entry.epoch_chain_unverified === 'boolean') loaded.epoch_chain_unverified = entry.epoch_chain_unverified;
  if (typeof entry.epoch_chain_unverified_reason === 'string') {
    loaded.epoch_chain_unverified_reason = entry.epoch_chain_unverified_reason;
  }
  return loaded;
}

function assessIncomingEpochChain(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  epoch: number,
  commitment: string,
  incomingChain: string | undefined,
  rotationId: string,
  rotatorAid: string,
  source: string,
  logger: ModuleLogger = _noopLogger,
): { ok: boolean; unverified?: boolean | null; reason?: string | null } {
  const chain = (incomingChain ?? '').trim();
  const rid = rotationId.trim();
  const rotator = rotatorAid.trim();

  if (rid && !chain) {
    logger.warn(`[e2ee-group] rejecting rotation key missing epoch_chain source=${source} group=${groupId} epoch=${epoch} rotation=${rid}`);
    return { ok: false };
  }

  const current = loadGroupSecret(keystore, aid, groupId);
  if (current?.epoch === epoch) {
    const currentChain = current.epoch_chain ?? '';
    const currentPendingRotationId = current.pending_rotation_id ?? '';
    if (chain && currentChain === chain) return { ok: true };
    if (rid && chain && currentChain && currentChain !== chain) {
      if (!(currentPendingRotationId && currentPendingRotationId !== rid)) {
        logger.warn(`[e2ee-group] rejecting same-epoch chain fork source=${source} group=${groupId} epoch=${epoch} rotation=${rid}`);
        return { ok: false };
      }
    }
  }

  const prev = loadGroupSecret(keystore, aid, groupId, epoch - 1);
  const prevChain = prev?.epoch_chain ?? '';
  if (!chain) return { ok: true, unverified: true, reason: 'missing_epoch_chain' };
  if (!prevChain) return { ok: true, unverified: true, reason: 'missing_prev_chain' };
  if (!rotator) {
    if (rid) {
      logger.warn(`[e2ee-group] rejecting rotation key missing rotator_aid source=${source} group=${groupId} epoch=${epoch} rotation=${rid}`);
      return { ok: false };
    }
    return { ok: true, unverified: true, reason: 'missing_rotator_aid' };
  }
  if (!verifyEpochChain(chain, prevChain, epoch, commitment, rotator)) {
    if (rid) {
      logger.warn(`[e2ee-group] rejecting rotation key with failed epoch_chain verification source=${source} group=${groupId} epoch=${epoch} rotation=${rid}`);
      return { ok: false };
    }
    logger.warn(`[e2ee-group] epoch_chain verification failed, accepting as unverified for compatibility source=${source} group=${groupId} epoch=${epoch}`);
    return { ok: true, unverified: true, reason: 'chain_mismatch_legacy' };
  }
  if (!rid) return { ok: true, unverified: true, reason: 'missing_rotation_id' };
  return { ok: true, unverified: false };
}

/** 加载某群组所有 epoch 的 group_secret */
export function loadAllGroupSecrets(
  keystore: KeyStore,
  aid: string,
  groupId: string,
): Map<number, Buffer> {
  const result = new Map<number, Buffer>();
  for (const entry of loadKeyStoreGroupEpochs(keystore, aid, groupId)) {
    const secretStr = entry.secret as string | undefined;
    if (secretStr && entry.epoch != null) {
      result.set(entry.epoch as number, Buffer.from(secretStr, 'base64'));
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

/** 仅回滚指定 rotation 写入的本地 pending epoch key。 */
export function discardPendingGroupSecret(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  epoch: number,
  rotationId: string,
): boolean {
  const rid = rotationId.trim();
  if (!rid) return false;
  if (typeof keystore.discardPendingGroupSecretState === 'function') {
    return keystore.discardPendingGroupSecretState(aid, groupId, epoch, rid);
  }
  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} missing discardPendingGroupSecretState method`);
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
  epochChain?: string,
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
  if (epochChain !== undefined) {
    result.epoch_chain = epochChain;
  }
  return result;
}

/** 处理收到的 group key 分发消息 */
export function handleKeyDistribution(
  message: Message | JsonObject,
  keystore: KeyStore,
  aid: string,
  initiatorCertPem?: string | null,
  logger?: ModuleLogger,
): boolean {
  const payload = 'group_id' in message
    ? message
    : (isJsonObject(message.payload) ? message.payload : message);

  const groupId = payload.group_id as string | undefined;
  const epoch = payload.epoch as number | undefined;
  const groupSecretB64 = payload.group_secret as string | undefined;
  const commitment = payload.commitment as string | undefined;
  const memberAids = (payload.member_aids as string[]) ?? [];

  logger?.debug(`handleKeyDistribution enter: group=${String(groupId ?? '')}, epoch=${String(epoch ?? '')}, aid=${aid}, members=${memberAids.length}`);

  if (!groupId || epoch == null || !groupSecretB64 || !commitment) {
    logger?.warn(`handleKeyDistribution rejected: missing required fields group=${String(groupId ?? '')} epoch=${String(epoch ?? '')} has_secret=${!!groupSecretB64} has_commitment=${!!commitment}`);
    return false;
  }

  // 验证 Membership Manifest 签名
  const manifest = isJsonObject(payload.manifest) ? payload.manifest : undefined;
  if (initiatorCertPem) {
    if (!manifest) {
      logger?.warn(`handleKeyDistribution rejected: manifest required when initiatorCertPem present group=${groupId} epoch=${epoch}`);
      return false;
    }
    if (!verifyMembershipManifest(manifest, initiatorCertPem)) {
      logger?.warn(`handleKeyDistribution rejected: manifest signature verification failed group=${groupId} epoch=${epoch}`);
      return false;
    }
    if (manifest.group_id !== groupId || manifest.epoch !== epoch) {
      logger?.warn(`handleKeyDistribution rejected: manifest group_id/epoch mismatch group=${groupId} epoch=${epoch} manifest_group=${String(manifest.group_id)} manifest_epoch=${String(manifest.epoch)}`);
      return false;
    }
    const manifestMembers = [...((manifest.member_aids as string[]) ?? [])].sort();
    const payloadMembers = [...memberAids].sort();
    if (JSON.stringify(manifestMembers) !== JSON.stringify(payloadMembers)) {
      logger?.warn(`handleKeyDistribution rejected: manifest members mismatch payload members group=${groupId} epoch=${epoch}`);
      return false;
    }
  } else if (manifest) {
    if (manifest.group_id !== groupId || manifest.epoch !== epoch) {
      logger?.warn(`handleKeyDistribution rejected: manifest group_id/epoch mismatch (no cert) group=${groupId} epoch=${epoch}`);
      return false;
    }
    const manifestMembers = [...((manifest.member_aids as string[]) ?? [])].sort();
    const payloadMembers = [...memberAids].sort();
    if (JSON.stringify(manifestMembers) !== JSON.stringify(payloadMembers)) {
      logger?.warn(`handleKeyDistribution rejected: manifest members mismatch payload members (no cert) group=${groupId} epoch=${epoch}`);
      return false;
    }
  }

  const groupSecret = Buffer.from(groupSecretB64, 'base64');

  // 验证 commitment
  if (!verifyMembershipCommitment(commitment, memberAids, epoch, groupId, aid, groupSecret)) {
    logger?.warn(`handleKeyDistribution rejected: commitment verification failed group=${groupId} epoch=${epoch}`);
    return false;
  }

  const incomingChain = typeof payload.epoch_chain === 'string' ? payload.epoch_chain : undefined;
  const rotationId = typeof payload.rotation_id === 'string' ? payload.rotation_id : '';
  const chainAssessment = assessIncomingEpochChain(
    keystore,
    aid,
    groupId,
    epoch,
    commitment,
    incomingChain,
    rotationId,
    String(payload.distributed_by ?? payload.rotator_aid ?? ''),
    'key_distribution',
    logger,
  );
  if (!chainAssessment.ok) {
    logger?.warn(`handleKeyDistribution rejected: epoch chain assessment failed group=${groupId} epoch=${epoch} reason=${chainAssessment.reason ?? ''}`);
    return false;
  }

  return storeGroupSecret(
    keystore, aid, groupId, epoch, groupSecret, commitment, memberAids,
    incomingChain,
    rotationId,
    chainAssessment.unverified,
    chainAssessment.reason,
  );
}

/** 构建密钥请求 payload */
export function buildKeyRequest(
  groupId: string,
  epoch: number,
  requesterAid: string,
  requestId?: string,
): JsonObject {
  return {
    type: 'e2ee.group_key_request',
    group_id: groupId,
    epoch,
    requester_aid: requesterAid,
    request_id: requestId ?? crypto.randomUUID(),
    requested_at: Date.now(),
  };
}

/** 处理收到的密钥请求 */
export function handleKeyRequest(
  request: Message | JsonObject,
  keystore: KeyStore,
  aid: string,
  currentMembers: string[],
  privateKeyPem?: string | null,
  logger?: ModuleLogger,
): JsonObject | null {
  const payload = 'group_id' in request
    ? request
    : (isJsonObject(request.payload) ? request.payload : request);

  const requesterAid = payload.requester_aid as string | undefined;
  const groupId = payload.group_id as string | undefined;
  const epoch = payload.epoch as number | undefined;

  logger?.debug(`handleKeyRequest enter: group=${String(groupId ?? '')}, epoch=${String(epoch ?? '')}, requester=${String(requesterAid ?? '')}, aid=${aid}`);

  if (!requesterAid || !groupId || epoch == null) {
    logger?.warn(`handleKeyRequest rejected: missing required fields requester=${String(requesterAid ?? '')} group=${String(groupId ?? '')} epoch=${String(epoch ?? '')}`);
    return null;
  }

  // 验证请求者是群成员
  if (!currentMembers.includes(requesterAid)) {
    logger?.warn(`handleKeyRequest rejected: requester not in current members group=${groupId} requester=${requesterAid}`);
    return null;
  }

  // 查本地密钥
  const secretData = loadGroupSecret(keystore, aid, groupId, epoch);
  if (!secretData) {
    logger?.warn(`handleKeyRequest rejected: no local secret for epoch group=${groupId} epoch=${epoch}`);
    return null;
  }

  // 历史隔离：密钥存储中记录了该 epoch 的成员列表，
  // 若请求者不在该列表中，说明其不属于该 epoch，直接拒绝（不响应）。
  const memberAids = ((secretData.member_aids as string[]) ?? []).map(String).filter(Boolean).sort();
  if (memberAids.length > 0 && !memberAids.includes(requesterAid)) {
    logger?.warn(`handleKeyRequest rejected: requester not in epoch member list group=${groupId} epoch=${epoch} requester=${requesterAid}`);
    return null;
  }

  // 确定响应使用的成员列表：优先使用密钥存储中的成员列表，
  // 若为空（旧数据），则降级使用当前成员列表。
  const responseMemberAids = memberAids.length > 0
    ? memberAids
    : currentMembers.map(String).filter(Boolean).sort();

  // 若存储中无 commitment，按当前成员列表重新计算
  const commitmentStr = (secretData.commitment as string)
    || computeMembershipCommitment(responseMemberAids, epoch, groupId, secretData.secret);

  const response: JsonObject = {
    type: 'e2ee.group_key_response',
    group_id: groupId,
    epoch,
    group_secret: secretData.secret.toString('base64'),
    commitment: commitmentStr,
    member_aids: responseMemberAids,
    requester_aid: requesterAid,
    request_id: String(payload.request_id ?? ''),
    responder_aid: aid,
    issued_at: Date.now(),
  };
  // epoch_chain 始终包含（若有），供接收方验证历史轮转链
  if (secretData.epoch_chain !== undefined) {
    response.epoch_chain = secretData.epoch_chain;
  }
  return privateKeyPem ? signGroupKeyResponse(response, privateKeyPem) : response;
}

/** 处理收到的密钥响应 */
export function handleKeyResponse(
  response: Message | JsonObject,
  keystore: KeyStore,
  aid: string,
  opts?: {
    expectedRequest?: JsonObject | null;
    responderCertPem?: string | null;
    currentMembers?: string[];
    strict?: boolean;
    logger?: ModuleLogger;
  },
): boolean {
  const payload = 'group_id' in response
    ? response
    : (isJsonObject(response.payload) ? response.payload : response);

  const groupId = payload.group_id as string | undefined;
  const epoch = payload.epoch as number | undefined;
  const groupSecretB64 = payload.group_secret as string | undefined;
  const commitment = payload.commitment as string | undefined;
  const memberAids = (payload.member_aids as string[]) ?? [];

  const logger = opts?.logger;
  logger?.debug(`handleKeyResponse enter: group=${String(groupId ?? '')}, epoch=${String(epoch ?? '')}, responder=${String(payload.responder_aid ?? '')}, aid=${aid}, strict=${!!opts?.strict}`);

  if (!groupId || epoch == null || !groupSecretB64 || !commitment) {
    logger?.warn(`handleKeyResponse rejected: missing required fields group=${String(groupId ?? '')} epoch=${String(epoch ?? '')} has_secret=${!!groupSecretB64} has_commitment=${!!commitment}`);
    return false;
  }

  const expected = opts?.expectedRequest ?? null;
  if (expected) {
    if (payload.requester_aid !== aid) {
      logger?.warn(`handleKeyResponse rejected: requester_aid mismatch group=${groupId} epoch=${epoch} got=${String(payload.requester_aid)} expected=${aid}`);
      return false;
    }
    const expectedResponder = String(expected._expected_responder_aid ?? '');
    if (expectedResponder && payload.responder_aid !== expectedResponder) {
      logger?.warn(`handleKeyResponse rejected: responder_aid mismatch group=${groupId} epoch=${epoch} got=${String(payload.responder_aid)} expected=${expectedResponder}`);
      return false;
    }
    if (payload.request_id !== expected.request_id) {
      logger?.warn(`handleKeyResponse rejected: request_id mismatch group=${groupId} epoch=${epoch}`);
      return false;
    }
    if (payload.group_id !== expected.group_id) {
      logger?.warn(`handleKeyResponse rejected: group_id mismatch with expected request`);
      return false;
    }
    if (Number(payload.epoch ?? 0) !== Number(expected.epoch ?? 0)) {
      logger?.warn(`handleKeyResponse rejected: epoch mismatch with expected request group=${groupId}`);
      return false;
    }
  }

  const responderAid = String(payload.responder_aid ?? '');
  if (opts?.strict) {
    if (!responderAid || !opts.responderCertPem) {
      logger?.warn(`handleKeyResponse rejected (strict): missing responder aid or cert group=${groupId} epoch=${epoch}`);
      return false;
    }
    if ((opts.currentMembers?.length ?? 0) > 0 && !opts.currentMembers!.includes(responderAid)) {
      logger?.warn(`handleKeyResponse rejected (strict): responder not in current members group=${groupId} epoch=${epoch} responder=${responderAid}`);
      return false;
    }
    if (!verifyGroupKeyResponseSignature(payload, opts.responderCertPem)) {
      logger?.warn(`handleKeyResponse rejected (strict): response signature verification failed group=${groupId} epoch=${epoch} responder=${responderAid}`);
      return false;
    }
  } else if (opts?.responderCertPem && payload.response_signature) {
    if (!verifyGroupKeyResponseSignature(payload, opts.responderCertPem)) {
      logger?.warn(`handleKeyResponse rejected: response signature verification failed group=${groupId} epoch=${epoch} responder=${responderAid}`);
      return false;
    }
  }

  const groupSecret = Buffer.from(groupSecretB64, 'base64');

  if (!verifyMembershipCommitment(commitment, memberAids, epoch, groupId, aid, groupSecret)) {
    logger?.warn(`handleKeyResponse rejected: commitment verification failed group=${groupId} epoch=${epoch}`);
    return false;
  }

  const manifest = isJsonObject(payload.manifest) ? payload.manifest : null;
  if (manifest) {
    if (manifest.group_id !== groupId || manifest.epoch !== epoch) {
      logger?.warn(`handleKeyResponse rejected: manifest group_id/epoch mismatch group=${groupId} epoch=${epoch}`);
      return false;
    }
    const manifestMembers = Array.isArray(manifest.member_aids)
      ? manifest.member_aids.map((item) => String(item ?? '').trim()).filter(Boolean).sort()
      : [];
    const payloadMembers = memberAids.map((item) => String(item ?? '').trim()).filter(Boolean).sort();
    if (manifestMembers.length > 0 && manifestMembers.join('\n') !== payloadMembers.join('\n')) {
      logger?.warn(`handleKeyResponse rejected: manifest members mismatch payload members group=${groupId} epoch=${epoch}`);
      return false;
    }
  }

  const incomingChain = typeof payload.epoch_chain === 'string' ? payload.epoch_chain : undefined;
  const rotationId = typeof payload.rotation_id === 'string' ? payload.rotation_id : '';
  const chainAssessment = assessIncomingEpochChain(
    keystore,
    aid,
    groupId,
    epoch,
    commitment,
    incomingChain,
    rotationId,
    String(payload.distributed_by ?? payload.rotator_aid ?? payload.responder_aid ?? ''),
    'key_response',
    opts?.logger,
  );
  if (!chainAssessment.ok) {
    logger?.warn(`handleKeyResponse rejected: epoch chain assessment failed group=${groupId} epoch=${epoch} reason=${chainAssessment.reason ?? ''}`);
    return false;
  }

  return storeGroupSecretEpoch(
    keystore, aid, groupId, epoch, groupSecret, commitment, memberAids,
    incomingChain,
    rotationId,
    chainAssessment.unverified,
    chainAssessment.reason,
  );
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
  private _pendingKeyRequests: Map<string, JsonObject> = new Map();
  private _logger: ModuleLogger;

  constructor(opts: {
    identityFn: () => IdentityRecord;
    keystore: KeyStore;
    requestCooldown?: number;
    responseCooldown?: number;
    senderCertResolver?: (aid: string) => string | null;
    initiatorCertResolver?: (aid: string) => string | null;
    logger?: ModuleLogger;
  }) {
    this._identityFn = opts.identityFn;
    this._keystore = opts.keystore;
    this._replayGuard = new GroupReplayGuard();
    this._requestThrottle = new GroupKeyRequestThrottle(opts.requestCooldown ?? 30);
    this._responseThrottle = new GroupKeyRequestThrottle(opts.responseCooldown ?? 30);
    this._senderCertResolver = opts.senderCertResolver ?? null;
    this._initiatorCertResolver = opts.initiatorCertResolver ?? null;
    this._logger = opts.logger ?? _noopLogger;
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
    this._logger.debug(`create first epoch: groupId=${groupId}, members=${memberAids.length}, aid=${aid}`);
    const gs = generateGroupSecret();
    const epoch = 1;
    const commitment = computeMembershipCommitment(memberAids, epoch, groupId, gs);
    const epochChain = computeEpochChain(null, epoch, commitment, aid);
    storeGroupSecret(this._keystore, aid, groupId, epoch, gs, commitment, memberAids, epochChain);
    const manifest = this._signManifest(buildMembershipManifest(
      groupId, epoch, null, memberAids, { initiatorAid: aid },
    ));
    const distPayload = buildKeyDistribution(groupId, epoch, gs, memberAids, aid, manifest, epochChain);
    this._logger.debug(`create first epoch success: groupId=${groupId}, epoch=${epoch}`);
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
    this._logger.debug(`rotateEpoch start: groupId=${groupId}, prevEpoch=${prevEpoch}, newEpoch=${newEpoch}, members=${memberAids.length}`);
    const gs = generateGroupSecret();
    const commitment = computeMembershipCommitment(memberAids, newEpoch, groupId, gs);
    const prevChain = current?.epoch_chain ?? null;
    const epochChain = computeEpochChain(prevChain, newEpoch, commitment, aid);
    const stored = storeGroupSecret(this._keystore, aid, groupId, newEpoch, gs, commitment, memberAids, epochChain);
    if (!stored) {
      this._logger.warn(`rotateEpoch failed (epoch already exists or newer): groupId=${groupId}, newEpoch=${newEpoch}`);
      throw new Error(`group ${groupId} epoch ${newEpoch} secret already exists or is newer; abort distribution`);
    }
    const manifest = this._signManifest(buildMembershipManifest(
      groupId, newEpoch, prevEpoch, memberAids, { initiatorAid: aid },
    ));
    const distPayload = buildKeyDistribution(groupId, newEpoch, gs, memberAids, aid, manifest, epochChain);
    this._logger.debug(`rotateEpoch success: groupId=${groupId}, newEpoch=${newEpoch}`);
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
    opts?: { rotationId?: string; prevChainHint?: string | null },
  ): JsonObject {
    const aid = this._currentAid();
    this._logger.debug(`rotateEpochTo start: groupId=${groupId}, newEpoch=${newEpoch}, members=${memberAids.length}`);
    const current = loadGroupSecret(this._keystore, aid, groupId, newEpoch - 1)
      ?? loadGroupSecret(this._keystore, aid, groupId);
    const gs = generateGroupSecret();
    const commitment = computeMembershipCommitment(memberAids, newEpoch, groupId, gs);
    let prevChain = current?.epoch_chain ?? null;
    if (!prevChain && opts?.prevChainHint) {
      prevChain = opts.prevChainHint;
    }
    const epochChain = computeEpochChain(prevChain, newEpoch, commitment, aid);
    const rotationId = opts?.rotationId ?? '';
    const stored = storeGroupSecret(this._keystore, aid, groupId, newEpoch, gs, commitment, memberAids, epochChain, rotationId);
    if (!stored) {
      this._logger.warn(`rotateEpochTo failed (epoch already exists or newer): groupId=${groupId}, newEpoch=${newEpoch}`);
      throw new Error(`group ${groupId} epoch ${newEpoch} secret already exists or is newer; abort distribution`);
    }
    const manifest = this._signManifest(buildMembershipManifest(
      groupId, newEpoch, newEpoch - 1, memberAids, { initiatorAid: aid },
    ));
    const distPayload = buildKeyDistribution(groupId, newEpoch, gs, memberAids, aid, manifest, epochChain);
    if (rotationId) {
      distPayload.rotation_id = rotationId;
    }
    this._logger.debug(`rotateEpochTo success: groupId=${groupId}, newEpoch=${newEpoch}, rotationId=${rotationId}`);
    return {
      epoch: newEpoch,
      commitment,
      distributions: memberAids
        .filter(m => m !== aid)
        .map(m => ({ to: m, payload: distPayload })),
    };
  }

  discardPendingSecret(groupId: string, epoch: number, rotationId: string): boolean {
    return discardPendingGroupSecret(this._keystore, this._currentAid(), groupId, epoch, rotationId);
  }

  /** 加密群消息（含发送方签名）。无密钥时抛 E2EEGroupSecretMissingError。 */
  encrypt(groupId: string, payload: JsonObject, opts?: {
    protectedHeaders?: ProtectedHeadersInput;
    protected_headers?: ProtectedHeadersInput;
    headers?: ProtectedHeadersInput;
    context?: JsonObject | null;
    messageId?: string;
    timestamp?: number;
  }): JsonObject {
    const aid = this._currentAid();
    this._logger.debug(`group message encrypt start: groupId=${groupId}, aid=${aid}`);
    const secretData = loadGroupSecret(this._keystore, aid, groupId);
    if (!secretData) {
      this._logger.error(`group message encrypt failed: missing group secret, groupId=${groupId}`);
      throw new E2EEGroupSecretMissingError(`no group secret for ${groupId}`);
    }
    const identity = this._identityFn();
    const senderPkPem = identity ? (identity.private_key_pem as string | undefined) ?? null : null;
    // TS-017: 签名失败必须阻止发送，不允许发出无签名的群消息
    if (!senderPkPem) {
      throw new E2EEError('sender identity private key unavailable for group message signing');
    }
    const senderCertPem = identity ? (identity.cert as string | undefined) ?? null : null;
    const result = encryptGroupMessage(
      groupId,
      secretData.epoch as number,
      secretData.secret,
      payload,
      {
        fromAid: aid,
        messageId: opts?.messageId ?? `gm-${crypto.randomUUID()}`,
        timestamp: opts?.timestamp ?? Date.now(),
        senderPrivateKeyPem: senderPkPem,
        senderCertPem,
        protectedHeaders: opts?.protectedHeaders ?? opts?.protected_headers ?? opts?.headers,
        context: opts?.context ?? null,
      },
    );
    this._logger.debug(`group message encrypt success: groupId=${groupId}, epoch=${secretData.epoch}`);
    return result;
  }

  /** 使用指定 epoch 加密群消息。 */
  encryptWithEpoch(groupId: string, epoch: number, payload: JsonObject, opts?: {
    protectedHeaders?: ProtectedHeadersInput;
    protected_headers?: ProtectedHeadersInput;
    headers?: ProtectedHeadersInput;
    context?: JsonObject | null;
    messageId?: string;
    timestamp?: number;
  }): JsonObject {
    const aid = this._currentAid();
    const secretData = loadGroupSecret(this._keystore, aid, groupId, epoch);
    if (!secretData) {
      throw new E2EEGroupSecretMissingError(`no group secret for ${groupId} epoch ${epoch}`);
    }
    const identity = this._identityFn();
    const senderPkPem = identity ? (identity.private_key_pem as string | undefined) ?? null : null;
    if (!senderPkPem) {
      throw new E2EEError('sender identity private key unavailable for group message signing');
    }
    const senderCertPem = identity ? (identity.cert as string | undefined) ?? null : null;
    return encryptGroupMessage(
      groupId,
      secretData.epoch,
      secretData.secret,
      payload,
      {
        fromAid: aid,
        messageId: opts?.messageId ?? `gm-${crypto.randomUUID()}`,
        timestamp: opts?.timestamp ?? Date.now(),
        senderPrivateKeyPem: senderPkPem,
        senderCertPem,
        protectedHeaders: opts?.protectedHeaders ?? opts?.protected_headers ?? opts?.headers,
        context: opts?.context ?? null,
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
    this._logger.debug(`group message decrypt start: groupId=${groupId}, from=${sender}`);

    // 防重放预检：优先使用 AAD 内 message_id
    const aad = isJsonObject(payload.aad) ? payload.aad : undefined;
    const aadMsgId = aad ? (aad.message_id as string ?? '') : '';
    const msgId = aadMsgId || (message.message_id as string) || '';
    if (!opts?.skipReplay && groupId && sender && msgId) {
      if (this._replayGuard.isSeen(groupId, sender, msgId)) {
        this._logger.debug(`group message replay blocked: groupId=${groupId}, from=${sender}, mid=${msgId}`);
        // 返回原消息（不含 e2ee 字段），调用方可通过缺失 e2ee 识别 replay
        return message;
      }
    }

    // 解析发送方证书（零信任：无证书则拒绝）
    let senderCertPem: string | null = null;
    if (this._senderCertResolver && sender) {
      senderCertPem = this._senderCertResolver(sender);
    }
    if (!senderCertPem) {
      this._logger.warn(`group message decrypt rejected: sender cert unavailable, groupId=${groupId}, from=${sender}`);
      return null;
    }

    const allSecrets = loadAllGroupSecrets(this._keystore, this._currentAid(), groupId);
    if (allSecrets.size === 0) {
      this._logger.warn(`group message decrypt failed: no group secret, groupId=${groupId}`);
      return null;
    }
    const result = decryptGroupMessage(message, allSecrets, senderCertPem, { logger: this._logger });

    // 解密成功后记录防重放
    if (result != null) {
      const finalMsgId = aadMsgId || (message.message_id as string) || '';
      if (!opts?.skipReplay && groupId && sender && finalMsgId) {
        this._replayGuard.record(groupId, sender, finalMsgId);
      }
      this._logger.debug(`group message decrypt success: groupId=${groupId}, from=${sender}, mid=${msgId}`);
    } else {
      this._logger.warn(`group message decrypt failed: groupId=${groupId}, from=${sender}, mid=${msgId}`);
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
      const groupId = (payload.group_id as string) || '';
      const epoch = payload.epoch as number | undefined;
      const distributedBy = (payload.distributed_by as string) || '';
      this._logger.debug(`received key distribution: groupId=${groupId}, epoch=${epoch}, from=${distributedBy}`);
      let initiatorCert: string | null = null;
      if (this._initiatorCertResolver && distributedBy) {
        initiatorCert = this._initiatorCertResolver(distributedBy);
      }
      const ok = handleKeyDistribution(payload, this._keystore, aid, initiatorCert, this._logger);
      if (ok) {
        this._logger.debug(`key distribution handled successfully: groupId=${groupId}, epoch=${epoch}`);
      } else {
        this._logger.warn(`key distribution rejected: groupId=${groupId}, epoch=${epoch}, from=${distributedBy}`);
      }
      return ok ? 'distribution' : 'distribution_rejected';
    }
    if (msgType === 'e2ee.group_key_response') {
      const groupId = (payload.group_id as string) || '';
      const epoch = payload.epoch as number | undefined;
      this._logger.debug(`received key response: groupId=${groupId}, epoch=${epoch}`);
      const pendingKey = `${String(payload.group_id ?? '')}:${String(payload.epoch ?? '')}:${String(payload.request_id ?? '')}`;
      const expected = this._pendingKeyRequests.get(pendingKey) ?? null;
      if (expected === null) {
        this._logger.warn(`key response rejected (no matching request): groupId=${groupId}, epoch=${epoch}`);
        return 'response_rejected';
      }
      const responderAid = String(payload.responder_aid ?? '');
      const responderCertPem = responderAid && this._initiatorCertResolver
        ? this._initiatorCertResolver(responderAid)
        : null;
      const ok = handleKeyResponse(payload, this._keystore, aid, {
        expectedRequest: expected,
        responderCertPem,
        currentMembers: this.getMemberAids(String(payload.group_id ?? '')),
        strict: true,
        logger: this._logger,
      });
      if (ok && expected) this._pendingKeyRequests.delete(pendingKey);
      if (ok) {
        this._logger.debug(`key response handled successfully: groupId=${groupId}, epoch=${epoch}, responder=${responderAid}`);
      } else {
        this._logger.warn(`key response verification failed: groupId=${groupId}, epoch=${epoch}, responder=${responderAid}`);
      }
      return ok ? 'response' : 'response_rejected';
    }
    if (msgType === 'e2ee.group_key_request') {
      const groupId = (payload.group_id as string) || '';
      const requester = (payload.requester_aid as string) || '';
      this._logger.debug(`received key request: groupId=${groupId}, requester=${requester}, epoch=${payload.epoch}`);
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
    const payload = buildKeyRequest(groupId, epoch, aid);
    this.rememberKeyRequest(payload, candidates[0]);
    return { to: candidates[0], payload };
  }

  rememberKeyRequest(payload: JsonObject, expectedResponderAid?: string | null): void {
    if (payload.type !== 'e2ee.group_key_request') return;
    const requestId = String(payload.request_id ?? '');
    if (!requestId) return;
    this._pendingKeyRequests.set(
      `${String(payload.group_id ?? '')}:${String(payload.epoch ?? '')}:${requestId}`,
      expectedResponderAid ? { ...payload, _expected_responder_aid: expectedResponderAid } : { ...payload },
    );
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
    if (!members.includes(requester)) {
      this._logger.warn(`key request rejected (not a member): groupId=${groupId}, requester=${requester}`);
      return null;
    }
    if (!this._responseThrottle.allow(`response:${groupId}:${requester}`)) {
      this._logger.debug(`key request throttled: groupId=${groupId}, requester=${requester}`);
      return null;
    }
    const identity = this._identityFn();
    const privateKeyPem = identity.private_key_pem as string | undefined;
    if (!privateKeyPem) {
      this._logger.error(`key request handling failed: missing private key, groupId=${groupId}`);
      return null;
    }
    const response = handleKeyRequest(requestPayload, this._keystore, this._currentAid(), members, privateKeyPem, this._logger);
    if (response) {
      this._logger.debug(`key request responded: groupId=${groupId}, requester=${requester}, epoch=${requestPayload.epoch}`);
    } else {
      this._logger.warn(`key request handling failed (no local key or requester not in epoch members): groupId=${groupId}, requester=${requester}`);
    }
    return response;
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
    const result = loadGroupSecret(this._keystore, this._currentAid(), groupId, epoch);
    if (result) {
      this._logger.debug(`load group secret success: groupId=${groupId}, epoch=${result.epoch}`);
    } else {
      this._logger.debug(`load group secret not found: groupId=${groupId}, requestedEpoch=${epoch ?? 'latest'}`);
    }
    return result;
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

  /** 加载指定群组的所有 epoch 密钥。返回 Map<epoch, Buffer>。 */
  loadAllSecrets(groupId: string): Map<number, Buffer> {
    return loadAllGroupSecrets(this._keystore, this._currentAid(), groupId);
  }

  private _currentAid(): string {
    const identity = this._identityFn();
    const aid = identity.aid;
    if (!aid) throw new E2EEError('AID unavailable');
    return String(aid);
  }
}
