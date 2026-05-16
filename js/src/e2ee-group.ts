// ── GroupE2EEManager（群组端到端加密 — 浏览器 SubtleCrypto 实现）──
// 所有密码学操作均为异步（SubtleCrypto API 要求）

import type { ModuleLogger } from './logger.js';
import {
  E2EEError,
  E2EEGroupSecretMissingError,
} from './errors.js';
import { uint8ToBase64, base64ToUint8, pemToArrayBuffer, toBufferSource } from './crypto.js';
import {
  SUITE,
  _concatBytes as concatBytes,
  _certificateSha256Fingerprint as certificateSha256Fingerprint,
  _ecdsaSignDer as ecdsaSignDer,
  _ecdsaVerifyDer as ecdsaVerifyDer,
  _hkdfDerive as hkdfDerive,
  _aesGcmEncrypt as aesGcmEncrypt,
  _aesGcmDecrypt as aesGcmDecrypt,
  _randomNonce as randomNonce,
  _uuidV4 as uuidV4,
  _fingerprintSpki as fingerprintSpki,
  _importCertPublicKeyEcdsa as importCertPublicKeyEcdsa,
  _importPrivateKeyEcdsa as importPrivateKeyEcdsa,
  type ProtectedHeadersInput,
} from './e2ee.js';
import type { KeyStore } from './keystore/index.js';

const _noopLog: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };
// 顶层函数共享的模块 logger（client 构造时通过 setModuleLogger 注入）
let _moduleLog: ModuleLogger = _noopLog;
export function setModuleLogger(log: ModuleLogger): void { _moduleLog = log; }

import {
  isJsonObject,
  type GroupSecretRecord,
  type IdentityRecord,
  type JsonObject,
  type Message,
} from './types.js';

const _encoder = new TextEncoder();
const _decoder = new TextDecoder();

export interface LoadedGroupSecret {
  epoch: number;
  secret: Uint8Array;
  commitment: string;
  member_aids: string[];
  epoch_chain?: string;
  pending_rotation_id?: string;
  epoch_chain_unverified?: boolean;
  epoch_chain_unverified_reason?: string;
}

// ── ECIES (P-256 ECDH + HKDF-SHA256 + AES-256-GCM, SubtleCrypto) ──

const _ECIES_HKDF_INFO = _encoder.encode('aun-epoch-key-ecies');

/**
 * ECIES 加密（异步，SubtleCrypto）。
 * @param peerPubkeyBytes 65 字节未压缩 P-256 公钥 (0x04 开头)
 * @param plaintext 待加密明文
 * @returns ephemeral_pubkey(65B) || iv(12B) || ciphertext || tag(16B)
 */
export async function eciesEncrypt(peerPubkeyBytes: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  // 生成临时 ECDH 密钥对
  const ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  // 导出临时公钥（未压缩 65 字节）
  const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));

  // 导入对方公钥
  const peerKey = await crypto.subtle.importKey('raw', toBufferSource(peerPubkeyBytes), { name: 'ECDH', namedCurve: 'P-256' }, false, []);

  // ECDH 共享密钥
  const sharedBits = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, ephemeral.privateKey, 256);
  const shared = new Uint8Array(sharedBits);

  // HKDF 派生 32 字节 AES 密钥
  const hkdfKey = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: _ECIES_HKDF_INFO },
    hkdfKey, 256,
  );
  const aesKeyBytes = new Uint8Array(derivedBits);

  // AES-256-GCM 加密
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await crypto.subtle.importKey('raw', aesKeyBytes, 'AES-GCM', false, ['encrypt']);
  const ctBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: toBufferSource(iv), tagLength: 128 }, aesKey, toBufferSource(plaintext));
  const ctArr = new Uint8Array(ctBuf); // ciphertext + tag(16B)

  // 拼接: ephemeral_pubkey(65) || iv(12) || ciphertext+tag
  const result = new Uint8Array(65 + 12 + ctArr.length);
  result.set(ephPubRaw, 0);
  result.set(iv, 65);
  result.set(ctArr, 77);
  return result;
}

/**
 * ECIES 解密（异步，SubtleCrypto）。
 * @param privateKeyPem PEM 格式 EC 私钥
 * @param ciphertext ephemeral_pubkey(65B) || iv(12B) || encrypted+tag(16B)
 * @returns 解密后的明文
 */
export async function eciesDecrypt(privateKeyPem: string, ciphertext: Uint8Array): Promise<Uint8Array> {
  if (ciphertext.length < 65 + 12 + 16) {
    throw new E2EEError('ECIES ciphertext too short');
  }
  const ephPubBytes = ciphertext.slice(0, 65);
  const iv = ciphertext.slice(65, 77);
  const encryptedWithTag = ciphertext.slice(77);

  // 导入自己的私钥
  const privKeyDer = pemToArrayBuffer(privateKeyPem);
  const privKey = await crypto.subtle.importKey('pkcs8', privKeyDer, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);

  // 导入临时公钥
  const ephPubKey = await crypto.subtle.importKey('raw', toBufferSource(ephPubBytes), { name: 'ECDH', namedCurve: 'P-256' }, false, []);

  // ECDH 共享密钥
  const sharedBits = await crypto.subtle.deriveBits({ name: 'ECDH', public: ephPubKey }, privKey, 256);
  const shared = new Uint8Array(sharedBits);

  // HKDF 派生 AES 密钥
  const hkdfKey = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: _ECIES_HKDF_INFO },
    hkdfKey, 256,
  );
  const aesKeyBytes = new Uint8Array(derivedBits);

  // AES-256-GCM 解密（SubtleCrypto 要求 ciphertext+tag 拼接传入）
  const aesKey = await crypto.subtle.importKey('raw', aesKeyBytes, 'AES-GCM', false, ['decrypt']);
  const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: toBufferSource(iv), tagLength: 128 }, aesKey, toBufferSource(encryptedWithTag));
  return new Uint8Array(ptBuf);
}

// ── Epoch Transcript Chain 工具函数 ──────────────────────────

/** Genesis 前缀：aun-epoch-chain:genesis（UTF-8 字节） */
const _EPOCH_CHAIN_GENESIS_PREFIX: Uint8Array = _encoder.encode('aun-epoch-chain:genesis');

/** 将 hex 字符串解码为 Uint8Array */
function _hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('invalid hex string length');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

/** 将 Uint8Array 编码为 hex 字符串 */
function _bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** 将 4 字节大端整数编码为 Uint8Array */
function _uint32BE(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (n >>> 24) & 0xff;
  buf[1] = (n >>> 16) & 0xff;
  buf[2] = (n >>> 8) & 0xff;
  buf[3] = n & 0xff;
  return buf;
}

/**
 * 计算 Epoch Transcript Chain 哈希（异步，SubtleCrypto SHA-256）。
 * prev_chain=null 时使用 genesis 前缀，否则将 prev_chain hex 解码为字节。
 */
export async function computeEpochChain(
  prevChain: string | null,
  epoch: number,
  commitment: string,
  rotatorAid: string,
): Promise<string> {
  const prefix = prevChain === null ? _EPOCH_CHAIN_GENESIS_PREFIX : _hexToBytes(prevChain);
  const epochBytes = _uint32BE(epoch);
  const commitmentBytes = _encoder.encode(commitment);
  const rotatorBytes = _encoder.encode(rotatorAid);

  // 拼接：prefix || epoch(4B big-endian) || commitment(utf-8) || rotator_aid(utf-8)
  const data = new Uint8Array(
    prefix.length + epochBytes.length + commitmentBytes.length + rotatorBytes.length,
  );
  let offset = 0;
  data.set(prefix, offset); offset += prefix.length;
  data.set(epochBytes, offset); offset += epochBytes.length;
  data.set(commitmentBytes, offset); offset += commitmentBytes.length;
  data.set(rotatorBytes, offset);

  const digest = await crypto.subtle.digest('SHA-256', data);
  return _bytesToHex(new Uint8Array(digest));
}

/**
 * 验证 Epoch Chain（常量时间比较，防时序攻击）。
 * warn-only：调用方决定是否拒绝；此函数仅返回布尔值。
 */
export async function verifyEpochChain(
  epochChain: string,
  prevChain: string | null,
  epoch: number,
  commitment: string,
  rotatorAid: string,
): Promise<boolean> {
  const expected = await computeEpochChain(prevChain, epoch, commitment, rotatorAid);
  if (expected.length !== epochChain.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ epochChain.charCodeAt(i);
  }
  return diff === 0;
}

function groupKeyResponseSignData(payload: JsonObject): Uint8Array {
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
  return _encoder.encode(fields.join('\n'));
}

export async function signGroupKeyResponse(payload: JsonObject, privateKeyPem: string): Promise<JsonObject> {
  const signed: JsonObject = {
    ...payload,
    response_version: payload.response_version ?? 1,
    issued_at: payload.issued_at ?? Date.now(),
  };
  const privateKey = await importPrivateKeyEcdsa(privateKeyPem);
  signed.response_signature = uint8ToBase64(await ecdsaSignDer(privateKey, groupKeyResponseSignData(signed)));
  return signed;
}

export async function verifyGroupKeyResponseSignature(payload: JsonObject, responderCertPem: string): Promise<boolean> {
  const sigB64 = String(payload.response_signature ?? '');
  if (!sigB64) return false;
  try {
    const pub = await importCertPublicKeyEcdsa(responderCertPem);
    return await ecdsaVerifyDer(pub, base64ToUint8(sigB64), groupKeyResponseSignData(payload));
  } catch {
    return false;
  }
}

/** 群组加密模式 */
export const MODE_EPOCH_GROUP_KEY = 'epoch_group_key';

/** AAD 字段定义（群组） */
export const AAD_FIELDS_GROUP = [
  'group_id', 'from', 'message_id', 'timestamp',
  'epoch', 'encryption_mode', 'suite',
] as const;

/** AAD 匹配字段（群组，不含 timestamp） */
export const AAD_MATCH_FIELDS_GROUP = [
  'group_id', 'from', 'message_id',
  'epoch', 'encryption_mode', 'suite',
] as const;

const AAD_OPTIONAL_FIELDS = [
  'payload_type', 'protected_headers', 'context_type', 'context_id',
] as const;

const METADATA_AUTH_FIELD = '_auth';
const METADATA_AUTH_ALG = 'HMAC-SHA256';
const METADATA_KEY_DOMAIN = _encoder.encode('aun-envelope-metadata-key-v1');
const PROTECTED_HEADERS_DOMAIN = _encoder.encode('aun-protected-headers-v1');
const PROTECTED_CONTEXT_DOMAIN = _encoder.encode('aun-protected-context-v1');

/** 旧 epoch 默认保留时间（秒） */
export const OLD_EPOCH_RETENTION_SECONDS = 7 * 24 * 3600;

async function loadKeyStoreGroupEpoch(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  epoch?: number | null,
): Promise<GroupSecretRecord | null> {
  if (typeof keystore.loadGroupSecretEpoch === 'function') {
    return await keystore.loadGroupSecretEpoch(aid, groupId, epoch);
  }
  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} missing loadGroupSecretEpoch method`);
}

async function loadKeyStoreGroupEpochs(
  keystore: KeyStore,
  aid: string,
  groupId: string,
): Promise<GroupSecretRecord[]> {
  if (typeof keystore.loadGroupSecretEpochs === 'function') {
    return await keystore.loadGroupSecretEpochs(aid, groupId);
  }
  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} missing loadGroupSecretEpochs method`);
}

async function storeKeyStoreGroupTransition(
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
): Promise<boolean | null> {
  if (typeof keystore.storeGroupSecretTransition !== 'function') return null;
  return await keystore.storeGroupSecretTransition(aid, groupId, {
    ...opts,
    oldEpochRetentionMs: OLD_EPOCH_RETENTION_SECONDS * 1000,
  });
}

async function storeKeyStoreGroupEpoch(
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
): Promise<boolean | null> {
  if (typeof keystore.storeGroupSecretEpoch !== 'function') return null;
  return await keystore.storeGroupSecretEpoch(aid, groupId, {
    ...opts,
    oldEpochRetentionMs: OLD_EPOCH_RETENTION_SECONDS * 1000,
  });
}

async function cleanupKeyStoreGroupOldEpochs(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  cutoffMs: number,
): Promise<number> {
  if (typeof keystore.cleanupGroupOldEpochsState === 'function') {
    return await keystore.cleanupGroupOldEpochsState(aid, groupId, cutoffMs);
  }
  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} missing cleanupGroupOldEpochsState method`);
}

// ── 群组 AAD 工具 ────────────────────────────────────────────

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

function metadataBody(metadata: Record<string, unknown>): JsonObject {
  const body: JsonObject = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (key !== METADATA_AUTH_FIELD) {
      body[key] = value as JsonObject[string];
    }
  }
  return body;
}

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    toBufferSource(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', hmacKey, toBufferSource(data));
  return new Uint8Array(sig);
}

async function metadataAuthTag(key: Uint8Array, domain: Uint8Array, body: JsonObject): Promise<Uint8Array> {
  const metadataKey = await hmacSha256(key, METADATA_KEY_DOMAIN);
  return hmacSha256(
    metadataKey,
    concatBytes(domain, new Uint8Array([0]), _encoder.encode(canonicalStringify(body))),
  );
}

async function withMetadataAuth(metadata: JsonObject, key: Uint8Array, domain: Uint8Array): Promise<JsonObject> {
  const body = metadataBody(metadata);
  if (Object.keys(body).length === 0) return {};
  const tag = await metadataAuthTag(key, domain, body);
  return {
    ...body,
    [METADATA_AUTH_FIELD]: {
      alg: METADATA_AUTH_ALG,
      tag: uint8ToBase64(tag),
    },
  };
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

async function verifyMetadataAuth(metadata: unknown, key: Uint8Array, domain: Uint8Array): Promise<boolean> {
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
  let actual: Uint8Array;
  try {
    actual = base64ToUint8(authObj.tag);
  } catch {
    return false;
  }
  const expected = await metadataAuthTag(key, domain, body);
  return timingSafeEqual(actual, expected);
}

async function verifyEnvelopeMetadataAuth(payload: JsonObject, messageKey: Uint8Array): Promise<boolean> {
  return await verifyMetadataAuth(payload.protected_headers, messageKey, PROTECTED_HEADERS_DOMAIN)
    && await verifyMetadataAuth(payload.context, messageKey, PROTECTED_CONTEXT_DOMAIN);
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

async function copyOptionalEnvelopeMetadata(
  envelope: JsonObject,
  messageKey: Uint8Array,
  opts?: {
    payloadType?: unknown;
    protectedHeaders?: ProtectedHeadersInput;
    context?: unknown;
  },
): Promise<void> {
  const payloadType = String(opts?.payloadType ?? '').trim();
  const protectedHeaders = normalizeProtectedHeaders(opts?.protectedHeaders);
  if (payloadType) {
    protectedHeaders.payload_type = payloadType;
  }
  if (Object.keys(protectedHeaders).length > 0) {
    envelope.protected_headers = await withMetadataAuth(
      protectedHeaders,
      messageKey,
      PROTECTED_HEADERS_DOMAIN,
    );
  }
  const contextMetadata = normalizeContextMetadata(opts?.context);
  if (Object.keys(contextMetadata).length > 0) {
    envelope.context = await withMetadataAuth(
      contextMetadata,
      messageKey,
      PROTECTED_CONTEXT_DOMAIN,
    );
  }
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

/** 群组 AAD 序列化（排序键、紧凑 JSON） */
function aadBytesGroup(aad: JsonObject): Uint8Array {
  const obj: JsonObject = {};
  for (const field of AAD_FIELDS_GROUP) {
    obj[field] = aad[field] ?? null;
  }
  return _encoder.encode(canonicalStringify(obj));
}

/** 群组 AAD 字段匹配检查 */
function aadMatchesGroup(expected: JsonObject, actual: JsonObject): boolean {
  for (const f of AAD_MATCH_FIELDS_GROUP) {
    if (JSON.stringify(expected[f] ?? null) !== JSON.stringify(actual[f] ?? null)) {
      return false;
    }
  }
  return true;
}

// ── 群消息密钥派生 ────────────────────────────────────────────

/** 从 group_secret 派生单条群消息的加密密钥（异步） */
async function deriveGroupMsgKey(
  groupSecret: Uint8Array, groupId: string, messageId: string,
): Promise<Uint8Array> {
  return hkdfDerive(groupSecret, `aun-group:${groupId}:msg:${messageId}`);
}

// ── 群消息加解密（纯函数）────────────────────────────────────

/**
 * 加密群组消息，返回 e2ee.group_encrypted 信封（异步）。
 *
 * senderPrivateKeyPem: 可选，传入时为密文附加发送方 ECDSA 签名（不可否认性）。
 */
export async function encryptGroupMessage(
  groupId: string,
  epoch: number,
  groupSecret: Uint8Array,
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
): Promise<JsonObject> {
  const msgKey = await deriveGroupMsgKey(groupSecret, groupId, opts.messageId);
  const plaintext = _encoder.encode(JSON.stringify(payload));
  const nonce = randomNonce();

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
  await copyOptionalEnvelopeMetadata(envelope, msgKey, {
    payloadType: payload.type,
    protectedHeaders: opts.protectedHeaders ?? opts.protected_headers ?? opts.headers,
    context: opts.context ?? null,
  });
  const aadBytes = aadBytesGroup(aad);
  const [ciphertext, tag] = await aesGcmEncrypt(msgKey, nonce, plaintext, aadBytes);

  envelope.nonce = uint8ToBase64(nonce);
  envelope.ciphertext = uint8ToBase64(ciphertext);
  envelope.tag = uint8ToBase64(tag);
  envelope.aad = aad;

  // 发送方签名：对 ciphertext + tag + aad_bytes 签名（不可否认性）
  if (opts.senderPrivateKeyPem) {
    const signKey = await importPrivateKeyEcdsa(opts.senderPrivateKeyPem);
    const signPayload = concatBytes(ciphertext, tag, aadBytes);
    const sig = await ecdsaSignDer(signKey, signPayload);
    envelope.sender_signature = uint8ToBase64(sig);

    if (opts.senderCertPem) {
      envelope.sender_cert_fingerprint = await certificateSha256Fingerprint(opts.senderCertPem);
    }
  }

  return envelope;
}

/**
 * 解密群组消息（异步）。
 *
 * groupSecrets: {epoch: groupSecretBytes} 映射。
 * senderCertPem: 发送方证书，用于验证签名。
 * requireSignature: 为 true 时（默认），若消息缺少签名或无证书可验证则拒绝（零信任模式）。
 */
export async function decryptGroupMessage(
  message: Message,
  groupSecrets: Map<number, Uint8Array>,
  senderCertPem?: string | null,
  opts?: { requireSignature?: boolean },
): Promise<Message | null> {
  const requireSignature = opts?.requireSignature ?? true;
  const payload = isJsonObject(message.payload) ? message.payload : null;
  if (payload === null) return null;
  if (payload.type !== 'e2ee.group_encrypted') return null;

  const epoch = payload.epoch as number | undefined;
  if (epoch === undefined || epoch === null) return null;

  const groupSecret = groupSecrets.get(epoch);
  if (!groupSecret) {
    _moduleLog.warn('[aun_core.e2ee-group] group message decrypt failed: epoch key not found');
    return null;
  }

  try {
    // 优先从 AAD 读取 group_id 和 message_id（SDK 加密时的原始值）
    const aad = isJsonObject(payload.aad) ? payload.aad : undefined;
    const outerGroupId = String(message.group_id ?? '');
    let groupId: string;
    let messageId: string;
    let aadFrom = '';

    if (aad) {
      groupId = (aad.group_id ?? outerGroupId) as string;
      messageId = (aad.message_id ?? message.message_id ?? '') as string;
      aadFrom = (aad.from ?? '') as string;

      // 外层路由字段与 AAD 绑定校验
      if (outerGroupId && groupId !== outerGroupId) {
        _moduleLog.warn('[aun_core.e2ee-group] AAD group_id mismatches outer route');
        return null;
      }
      if (aadFrom) {
        const outerFrom = (message.from ?? '') as string;
        const outerSender = String(message.sender_aid ?? '');
        if (outerFrom && outerFrom !== aadFrom) {
          _moduleLog.warn('[aun_core.e2ee-group] AAD from mismatches outer from');
          return null;
        }
        if (outerSender && outerSender !== aadFrom) {
          _moduleLog.warn('[aun_core.e2ee-group] AAD sender_aid mismatches outer sender_aid');
          return null;
        }
      }
    } else {
      groupId = outerGroupId;
      messageId = (message.message_id ?? '') as string;
    }

    if (!groupId || !messageId) {
      _moduleLog.warn('[aun_core.e2ee-group] group message decrypt failed: missing groupId or messageId');
      return null;
    }

    const msgKey = await deriveGroupMsgKey(groupSecret, groupId, messageId);
    const nonce = base64ToUint8(payload.nonce as string);
    const ciphertext = base64ToUint8(payload.ciphertext as string);
    const tag = base64ToUint8(payload.tag as string);

    if (!await verifyEnvelopeMetadataAuth(payload, msgKey)) {
      return null;
    }
    // AAD 校验：直接用 payload 中的 AAD
    const aadBytes = aad ? aadBytesGroup(aad) : new Uint8Array(0);

    const plaintext = await aesGcmDecrypt(msgKey, nonce, ciphertext, tag, aadBytes);
    const decoded = JSON.parse(_decoder.decode(plaintext));
    if (!validateDecryptedEnvelopeMetadata(decoded, payload, message)) {
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
      // 零信任模式：必须有签名且有证书可验证
      if (!senderSigB64) {
        _moduleLog.warn(`reject group msg without sender signature (require_signature=true): group=${groupId} from=${aadFrom}`);
        return null;
      }
      if (!senderCertPem) {
        _moduleLog.warn(
          `拒绝群消息：有签名但无发送方证书可验证（零信任模式禁止跳过验签）: group=${groupId} from=${aadFrom}`,
        );
        return null;
      }
      const verified = await _verifySenderSigGroup(senderCertPem, senderSigB64, ciphertext, tag, aadBytes);
      if (!verified) {
        _moduleLog.warn(`group msg sender signature verify failed: group=${groupId} from=${aadFrom}`);
        return null;
      }
      if (isJsonObject(result.e2ee)) result.e2ee.sender_verified = true;
    } else if (senderCertPem) {
      // 非零信任模式但提供了证书：有证书时强制验签
      if (!senderSigB64) {
        _moduleLog.warn(`reject group msg without sender signature: group=${groupId} from=${aadFrom}`);
        return null;
      }
      const verified = await _verifySenderSigGroup(senderCertPem, senderSigB64, ciphertext, tag, aadBytes);
      if (!verified) {
        _moduleLog.warn(`group msg sender signature verify failed: group=${groupId} from=${aadFrom}`);
        return null;
      }
      if (isJsonObject(result.e2ee)) result.e2ee.sender_verified = true;
    }

    return result;
  } catch (exc) {
    _moduleLog.warn('[aun_core.e2ee-group] group message decrypt exception:', exc instanceof Error ? (exc.stack || exc.message) : String(exc));
    return null;
  }
}

/** 群消息发送方签名验证内部实现 */
async function _verifySenderSigGroup(
  senderCertPem: string,
  senderSigB64: string,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aadBytes: Uint8Array,
): Promise<boolean> {
  try {
    const senderPub = await importCertPublicKeyEcdsa(senderCertPem);
    const sigBytes = base64ToUint8(senderSigB64);
    const verifyPayload = concatBytes(ciphertext, tag, aadBytes);
    return ecdsaVerifyDer(senderPub, sigBytes, verifyPayload);
  } catch {
    return false;
  }
}

// ── Membership Manifest（成员变更授权证明）──────────────────

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
function manifestSignData(manifest: JsonObject): Uint8Array {
  const fields = [
    String(manifest.manifest_version ?? 1),
    (manifest.group_id ?? '') as string,
    String(manifest.epoch ?? 0),
    String(manifest.prev_epoch ?? ''),
    ((manifest.member_aids as string[]) ?? []).join('|'),
    ((manifest.added as string[]) ?? []).join('|'),
    ((manifest.removed as string[]) ?? []).join('|'),
    (manifest.initiator_aid ?? '') as string,
    String(manifest.issued_at ?? 0),
  ];
  return _encoder.encode(fields.join('\n'));
}

/** 对 Membership Manifest 签名（异步），返回带 signature 字段的新 manifest */
export async function signMembershipManifest(
  manifest: JsonObject,
  privateKeyPem: string,
): Promise<JsonObject> {
  const signKey = await importPrivateKeyEcdsa(privateKeyPem);
  const data = manifestSignData(manifest);
  const sig = await ecdsaSignDer(signKey, data);
  return { ...manifest, signature: uint8ToBase64(sig) };
}

/** 验证 Membership Manifest 签名（异步） */
export async function verifyMembershipManifest(
  manifest: JsonObject,
  initiatorCertPem: string,
): Promise<boolean> {
  const sigB64 = manifest.signature as string | undefined;
  if (!sigB64) return false;
  try {
    const pubKey = await importCertPublicKeyEcdsa(initiatorCertPem);
    const sigBytes = base64ToUint8(sigB64);
    const data = manifestSignData(manifest);
    return ecdsaVerifyDer(pubKey, sigBytes, data);
  } catch {
    return false;
  }
}

// ── Membership Commitment ────────────────────────────────────

/** 计算 Membership Commitment（异步，使用 SubtleCrypto SHA-256） */
export async function computeMembershipCommitment(
  memberAids: string[],
  epoch: number,
  groupId: string,
  groupSecret: Uint8Array,
): Promise<string> {
  const sortedAids = [...memberAids].sort();
  // SHA-256(group_secret)
  const secretHash = await crypto.subtle.digest('SHA-256', toBufferSource(groupSecret));
  const secretHex = Array.from(new Uint8Array(secretHash)).map(b => b.toString(16).padStart(2, '0')).join('');
  const data = sortedAids.join('|') + '|' + epoch + '|' + groupId + '|' + secretHex;
  const digest = await crypto.subtle.digest('SHA-256', toBufferSource(_encoder.encode(data)));
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** 验证 Membership Commitment（异步） */
export async function verifyMembershipCommitment(
  commitment: string,
  memberAids: string[],
  epoch: number,
  groupId: string,
  myAid: string,
  groupSecret: Uint8Array,
): Promise<boolean> {
  if (!memberAids.includes(myAid)) return false;
  const expected = await computeMembershipCommitment(memberAids, epoch, groupId, groupSecret);
  // 常量时间比较（防时序攻击）
  if (expected.length !== commitment.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ commitment.charCodeAt(i);
  }
  return diff === 0;
}

// ── Group State Hash ─────────────────────────────────────────

/** 将数值编码为 uint64 big-endian 8 字节 */
function _uint64BE(n: number): Uint8Array {
  const buf = new Uint8Array(8);
  // JS number 安全整数范围内，高 4 字节用 Math.floor(n / 2^32)
  const hi = Math.floor(n / 0x100000000);
  const lo = n >>> 0;
  buf[0] = (hi >>> 24) & 0xff;
  buf[1] = (hi >>> 16) & 0xff;
  buf[2] = (hi >>> 8) & 0xff;
  buf[3] = hi & 0xff;
  buf[4] = (lo >>> 24) & 0xff;
  buf[5] = (lo >>> 16) & 0xff;
  buf[6] = (lo >>> 8) & 0xff;
  buf[7] = lo & 0xff;
  return buf;
}

/** 递归排序 JSON 对象的 key（用于 canonical JSON） */
function _sortObjectKeys(obj: unknown): unknown {
  if (obj === null || obj === undefined || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(_sortObjectKeys);
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
    sorted[key] = _sortObjectKeys((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

/**
 * 计算群组状态哈希（异步，SubtleCrypto SHA-256）。
 *
 * state_hash = SHA-256(
 *   group_id | 0x00 |
 *   state_version (uint64 big-endian 8 bytes) | 0x00 |
 *   key_epoch (uint64 big-endian 8 bytes) | 0x00 |
 *   membership_block | 0x00 |
 *   policy_block | 0x00 |
 *   prev_state_hash (32 bytes, 全零表示创世)
 * )
 */
export async function computeStateHash(params: {
  groupId: string;
  stateVersion: number;
  keyEpoch: number;
  members: Array<{ aid: string; role: string }>;
  policy: Record<string, unknown>;
  prevStateHash: string;
}): Promise<string> {
  const { groupId, stateVersion, keyEpoch, members, policy, prevStateHash } = params;

  // 按 AID 排序，构建 membership_block
  const sorted = [...members].sort((a, b) => a.aid.localeCompare(b.aid));
  const membershipBlock = sorted.map(m => `${m.aid}:${m.role}`).join('|');

  // 按 key 递归排序的 canonical JSON（无空格）
  const policyBlock = Object.keys(policy).length > 0
    ? JSON.stringify(_sortObjectKeys(policy))
    : '';

  // prev_state_hash: 32 字节，空则全零
  const prevBytes = prevStateHash
    ? _hexToBytes(prevStateHash)
    : new Uint8Array(32);

  // state_version / key_epoch → uint64 big-endian
  const svBuf = _uint64BE(stateVersion);
  const keBuf = _uint64BE(keyEpoch);

  const sep = new Uint8Array([0x00]);
  const groupIdBytes = _encoder.encode(groupId);
  const membershipBytes = _encoder.encode(membershipBlock);
  const policyBytes = _encoder.encode(policyBlock);

  // 拼接所有字段
  const totalLen = groupIdBytes.length + 1
    + svBuf.length + 1
    + keBuf.length + 1
    + membershipBytes.length + 1
    + policyBytes.length + 1
    + prevBytes.length;
  const data = new Uint8Array(totalLen);
  let offset = 0;
  data.set(groupIdBytes, offset); offset += groupIdBytes.length;
  data.set(sep, offset); offset += 1;
  data.set(svBuf, offset); offset += svBuf.length;
  data.set(sep, offset); offset += 1;
  data.set(keBuf, offset); offset += keBuf.length;
  data.set(sep, offset); offset += 1;
  data.set(membershipBytes, offset); offset += membershipBytes.length;
  data.set(sep, offset); offset += 1;
  data.set(policyBytes, offset); offset += policyBytes.length;
  data.set(sep, offset); offset += 1;
  data.set(prevBytes, offset);

  const digest = await crypto.subtle.digest('SHA-256', data);
  return _bytesToHex(new Uint8Array(digest));
}

// ── Group Secret 生命周期管理 ────────────────────────────────

/**
 * per-group 异步串行化锁，保护 storeGroupSecret 的 load-check-save 原子性。
 * JS 单线程下 await 是协程切换点，两个并发 storeGroupSecret 可能读到相同旧状态。
 */
const _groupSecretLocks = new Map<string, Promise<unknown>>();
function withGroupSecretLock<T>(aid: string, groupId: string, fn: () => Promise<T>): Promise<T> {
  const key = `${aid}:${groupId}`;
  const prev = _groupSecretLocks.get(key) ?? Promise.resolve();
  const next = prev.then(fn, fn);
  _groupSecretLocks.set(key, next);
  // 清理已完成的锁条目，避免内存泄漏
  next.finally(() => {
    if (_groupSecretLocks.get(key) === next) {
      _groupSecretLocks.delete(key);
    }
  });
  return next;
}

/** 存储 group_secret 到 keystore metadata（异步） */
export async function storeGroupSecret(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  epoch: number,
  groupSecret: Uint8Array,
  commitment: string,
  memberAids: string[],
  epochChain?: string,
  pendingRotationId = '',
  epochChainUnverified?: boolean | null,
  epochChainUnverifiedReason?: string | null,
): Promise<boolean> {
  return withGroupSecretLock(aid, groupId, () =>
    _storeGroupSecretInner(
      keystore, aid, groupId, epoch, groupSecret, commitment, memberAids,
      epochChain, pendingRotationId, epochChainUnverified, epochChainUnverifiedReason,
    ),
  );
}

/** storeGroupSecret 内部实现（在锁保护下执行） */
async function _storeGroupSecretInner(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  epoch: number,
  groupSecret: Uint8Array,
  commitment: string,
  memberAids: string[],
  epochChain?: string,
  pendingRotationId = '',
  epochChainUnverified?: boolean | null,
  epochChainUnverifiedReason?: string | null,
): Promise<boolean> {
  const transitionResult = await storeKeyStoreGroupTransition(keystore, aid, groupId, {
    epoch,
    secret: uint8ToBase64(groupSecret),
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
export async function storeGroupSecretEpoch(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  epoch: number,
  groupSecret: Uint8Array,
  commitment: string,
  memberAids: string[],
  epochChain?: string,
  pendingRotationId = '',
  epochChainUnverified?: boolean | null,
  epochChainUnverifiedReason?: string | null,
): Promise<boolean> {
  return withGroupSecretLock(aid, groupId, async () => {
    const secret = uint8ToBase64(groupSecret);
    const members = [...memberAids].sort();
    const rowResult = await storeKeyStoreGroupEpoch(keystore, aid, groupId, {
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
  });
}

/** 读取 group_secret（异步） */
export async function loadGroupSecret(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  epoch?: number | null,
): Promise<LoadedGroupSecret | null> {
  const entry = await loadKeyStoreGroupEpoch(keystore, aid, groupId, epoch) ?? undefined;
  if (!entry) return null;

  const secretStr = entry.secret as string | undefined;
  if (!secretStr) return null;
  const loaded: LoadedGroupSecret = {
    epoch: entry.epoch as number,
    secret: base64ToUint8(secretStr),
    commitment: (entry.commitment ?? '') as string,
    member_aids: (entry.member_aids ?? []) as string[],
  };
  if (typeof entry.epoch_chain === 'string') loaded.epoch_chain = entry.epoch_chain;
  if (typeof entry.pending_rotation_id === 'string') loaded.pending_rotation_id = entry.pending_rotation_id;
  if (typeof entry.epoch_chain_unverified === 'boolean') loaded.epoch_chain_unverified = entry.epoch_chain_unverified;
  if (typeof entry.epoch_chain_unverified_reason === 'string') {
    loaded.epoch_chain_unverified_reason = entry.epoch_chain_unverified_reason;
  }
  return loaded;
}

async function assessIncomingEpochChain(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  epoch: number,
  commitment: string,
  incomingChain: string | undefined,
  rotationId: string,
  rotatorAid: string,
  source: string,
): Promise<{ ok: boolean; unverified?: boolean | null; reason?: string | null }> {
  const chain = (incomingChain ?? '').trim();
  const rid = rotationId.trim();
  const rotator = rotatorAid.trim();

  if (rid && !chain) {
    _moduleLog.warn(`[aun_core.e2ee-group] reject missing epoch_chain new rotation key source=${source} group=${groupId} epoch=${epoch} rotation=${rid}`);
    return { ok: false };
  }

  const current = await loadGroupSecret(keystore, aid, groupId);
  if (current?.epoch === epoch) {
    const currentChain = current.epoch_chain ?? '';
    const currentPendingRotationId = current.pending_rotation_id ?? '';
    if (chain && currentChain === chain) return { ok: true };
    if (rid && chain && currentChain && currentChain !== chain) {
      if (!(currentPendingRotationId && currentPendingRotationId !== rid)) {
        _moduleLog.warn(`[aun_core.e2ee-group] reject same epoch forked chain source=${source} group=${groupId} epoch=${epoch} rotation=${rid}`);
        return { ok: false };
      }
    }
  }

  const prev = await loadGroupSecret(keystore, aid, groupId, epoch - 1);
  const prevChain = prev?.epoch_chain ?? '';
  if (!chain) return { ok: true, unverified: true, reason: 'missing_epoch_chain' };
  if (!prevChain) return { ok: true, unverified: true, reason: 'missing_prev_chain' };
  if (!rotator) {
    if (rid) {
      _moduleLog.warn(`[aun_core.e2ee-group] reject missing rotator_aid new rotation key source=${source} group=${groupId} epoch=${epoch} rotation=${rid}`);
      return { ok: false };
    }
    return { ok: true, unverified: true, reason: 'missing_rotator_aid' };
  }
  if (!await verifyEpochChain(chain, prevChain, epoch, commitment, rotator)) {
    if (rid) {
      _moduleLog.warn(`[aun_core.e2ee-group] reject epoch_chain verify failed new rotation key source=${source} group=${groupId} epoch=${epoch} rotation=${rid}`);
      return { ok: false };
    }
    _moduleLog.warn(`[aun_core.e2ee-group] epoch_chain verify failed, accept in compat mode and mark unverified source=${source} group=${groupId} epoch=${epoch}`);
    return { ok: true, unverified: true, reason: 'chain_mismatch_legacy' };
  }
  if (!rid) return { ok: true, unverified: true, reason: 'missing_rotation_id' };
  return { ok: true, unverified: false };
}

/** 加载某群组所有 epoch 的 group_secret（异步） */
export async function loadAllGroupSecrets(
  keystore: KeyStore,
  aid: string,
  groupId: string,
): Promise<Map<number, Uint8Array>> {
  const result = new Map<number, Uint8Array>();
  for (const entry of await loadKeyStoreGroupEpochs(keystore, aid, groupId)) {
    const secretStr = entry.secret as string | undefined;
    if (secretStr && entry.epoch !== undefined && entry.epoch !== null) {
      result.set(entry.epoch as number, base64ToUint8(secretStr));
    }
  }
  return result;
}

/** 清理过期的旧 epoch 记录（异步）。返回清理数量。 */
export async function cleanupOldEpochs(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  retentionSeconds: number = OLD_EPOCH_RETENTION_SECONDS,
): Promise<number> {
  const cutoffMs = Date.now() - retentionSeconds * 1000;
  return await cleanupKeyStoreGroupOldEpochs(keystore, aid, groupId, cutoffMs);
}

/** 仅回滚指定 rotation 写入的本地 pending epoch key（异步） */
export async function discardPendingGroupSecret(
  keystore: KeyStore,
  aid: string,
  groupId: string,
  epoch: number,
  rotationId: string,
): Promise<boolean> {
  const rid = rotationId.trim();
  if (!rid) return false;
  if (typeof keystore.discardPendingGroupSecretState === 'function') {
    return await keystore.discardPendingGroupSecretState(aid, groupId, epoch, rid);
  }
  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} missing discardPendingGroupSecretState method`);
}

/** 删除群组的所有密钥数据（群组解散时使用，异步） */
export async function deleteGroupSecret(
  keystore: KeyStore,
  aid: string,
  groupId: string,
): Promise<void> {
  if (typeof keystore.deleteGroupSecretState === 'function') {
    await keystore.deleteGroupSecretState(aid, groupId);
    return;
  }
  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} missing deleteGroupSecretState method`);
}

// ── Group Key 分发与恢复协议 ────────────────────────────────

/** 生成 32 字节随机 group_secret */
export function generateGroupSecret(): Uint8Array {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
}

/** 构建 group key 分发消息 payload（异步） */
export async function buildKeyDistribution(
  groupId: string,
  epoch: number,
  groupSecret: Uint8Array,
  memberAids: string[],
  distributedBy: string,
  manifest?: JsonObject | null,
  epochChain?: string,
): Promise<JsonObject> {
  const commitment = await computeMembershipCommitment(memberAids, epoch, groupId, groupSecret);
  const result: JsonObject = {
    type: 'e2ee.group_key_distribution',
    group_id: groupId,
    epoch,
    group_secret: uint8ToBase64(groupSecret),
    commitment,
    member_aids: [...memberAids].sort(),
    distributed_by: distributedBy,
    distributed_at: Date.now(),
  };
  if (manifest) result.manifest = manifest;
  if (epochChain !== undefined) result.epoch_chain = epochChain;
  return result;
}

/** 处理收到的 group key 分发消息（异步） */
export async function handleKeyDistribution(
  message: Message | JsonObject,
  keystore: KeyStore,
  aid: string,
  initiatorCertPem?: string | null,
): Promise<boolean> {
  const payload = 'group_id' in message
    ? message
    : (isJsonObject(message.payload) ? message.payload : message);

  const groupId = payload.group_id as string | undefined;
  const epoch = payload.epoch as number | undefined;
  const groupSecretB64 = payload.group_secret as string | undefined;
  const commitment = payload.commitment as string | undefined;
  const memberAids = (payload.member_aids ?? []) as string[];
  const incomingEpochChain = (payload.epoch_chain as string | undefined) ?? undefined;

  if (!groupId || epoch === undefined || epoch === null || !groupSecretB64 || !commitment) return false;

  // 验证 Membership Manifest 签名
  const manifest = isJsonObject(payload.manifest) ? payload.manifest : undefined;
  if (initiatorCertPem) {
    if (!manifest) {
      _moduleLog.warn(`rejectno manifest  keydistribute: group=${groupId} epoch=${epoch}`);
      return false;
    }
    const valid = await verifyMembershipManifest(manifest, initiatorCertPem);
    if (!valid) {
      _moduleLog.warn(`group key distribution manifest signature verifyfailed: group=${groupId} epoch=${epoch}`);
      return false;
    }
    if (manifest.group_id !== groupId || manifest.epoch !== epoch) return false;
    if (JSON.stringify([...(manifest.member_aids as string[])].sort()) !== JSON.stringify([...memberAids].sort())) return false;
  } else if (manifest) {
    if (manifest.group_id !== groupId || manifest.epoch !== epoch) return false;
    if (JSON.stringify([...(manifest.member_aids as string[])].sort()) !== JSON.stringify([...memberAids].sort())) return false;
  }

  const groupSecret = base64ToUint8(groupSecretB64);

  // 验证 commitment
  const commitmentValid = await verifyMembershipCommitment(commitment, memberAids, epoch, groupId, aid, groupSecret);
  if (!commitmentValid) return false;

  const rotationId = typeof payload.rotation_id === 'string' ? payload.rotation_id : '';
  const chainAssessment = await assessIncomingEpochChain(
    keystore,
    aid,
    groupId,
    epoch,
    commitment,
    incomingEpochChain,
    rotationId,
    String(payload.distributed_by ?? payload.rotator_aid ?? ''),
    'key_distribution',
  );
  if (!chainAssessment.ok) return false;

  return storeGroupSecret(
    keystore,
    aid,
    groupId,
    epoch,
    groupSecret,
    commitment,
    memberAids,
    incomingEpochChain,
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
    request_id: requestId ?? uuidV4(),
    requested_at: Date.now(),
  };
}

/** 处理收到的密钥请求（异步） */
export async function handleKeyRequest(
  request: Message | JsonObject,
  keystore: KeyStore,
  aid: string,
  currentMembers: string[],
  privateKeyPem?: string | null,
): Promise<JsonObject | null> {
  const payload = 'group_id' in request
    ? request
    : (isJsonObject(request.payload) ? request.payload : request);

  const requesterAid = payload.requester_aid as string | undefined;
  const groupId = payload.group_id as string | undefined;
  const epoch = payload.epoch as number | undefined;

  if (!requesterAid || !groupId || epoch === undefined || epoch === null) return null;
  if (!currentMembers.includes(requesterAid)) return null;

  const secretData = await loadGroupSecret(keystore, aid, groupId, epoch);
  if (!secretData) return null;

  // P0 历史隔离：若本 epoch 的 member_aids 非空且 requester 不在其中，拒绝响应
  // 防止已退出成员通过 currentMembers 校验后拿到历史 epoch 密钥
  const memberAids = (secretData.member_aids ?? []).map(String).filter(Boolean).sort();
  if (memberAids.length > 0 && !memberAids.includes(requesterAid)) return null;

  const responseMemberAids = memberAids.length ? memberAids : currentMembers.map(String).filter(Boolean).sort();
  let commitment = secretData.commitment;
  if (!commitment) {
    commitment = await computeMembershipCommitment(
      responseMemberAids, epoch, groupId, secretData.secret,
    );
  }

  const response: JsonObject = {
    type: 'e2ee.group_key_response',
    group_id: groupId,
    epoch,
    group_secret: uint8ToBase64(secretData.secret),
    commitment,
    member_aids: responseMemberAids,
    requester_aid: requesterAid,
    request_id: String(payload.request_id ?? ''),
    responder_aid: aid,
    issued_at: Date.now(),
  };
  // epoch_chain 始终随响应携带（若存在），不再因兼容分支而省略
  if (secretData.epoch_chain !== undefined) {
    response.epoch_chain = secretData.epoch_chain;
  }
  return privateKeyPem ? await signGroupKeyResponse(response, privateKeyPem) : response;
}

/** 处理收到的密钥响应（异步） */
export async function handleKeyResponse(
  response: Message | JsonObject,
  keystore: KeyStore,
  aid: string,
  opts?: {
    expectedRequest?: JsonObject | null;
    responderCertPem?: string | null;
    currentMembers?: string[];
    strict?: boolean;
  },
): Promise<boolean> {
  const payload = 'group_id' in response
    ? response
    : (isJsonObject(response.payload) ? response.payload : response);

  const groupId = payload.group_id as string | undefined;
  const epoch = payload.epoch as number | undefined;
  const groupSecretB64 = payload.group_secret as string | undefined;
  const commitment = payload.commitment as string | undefined;
  const memberAids = (payload.member_aids ?? []) as string[];
  const incomingEpochChain = (payload.epoch_chain as string | undefined) ?? undefined;

  if (!groupId || epoch === undefined || epoch === null || !groupSecretB64 || !commitment) return false;

  const expected = opts?.expectedRequest ?? null;
  if (expected) {
    if (payload.requester_aid !== aid) return false;
    const expectedResponder = String(expected._expected_responder_aid ?? '');
    if (expectedResponder && payload.responder_aid !== expectedResponder) return false;
    if (payload.request_id !== expected.request_id) return false;
    if (payload.group_id !== expected.group_id) return false;
    if (Number(payload.epoch ?? 0) !== Number(expected.epoch ?? 0)) return false;
  }

  const responderAid = String(payload.responder_aid ?? '');
    if (opts?.strict) {
      if (!responderAid || !opts.responderCertPem) return false;
      if ((opts.currentMembers?.length ?? 0) > 0 && !opts.currentMembers!.includes(responderAid)) return false;
      if (!await verifyGroupKeyResponseSignature(payload, opts.responderCertPem)) return false;
    } else if (opts?.responderCertPem && payload.response_signature) {
    if (!await verifyGroupKeyResponseSignature(payload, opts.responderCertPem)) return false;
  }

  const groupSecret = base64ToUint8(groupSecretB64);
  const valid = await verifyMembershipCommitment(commitment, memberAids, epoch, groupId, aid, groupSecret);
  if (!valid) return false;

  const manifest = isJsonObject(payload.manifest) ? payload.manifest : null;
  if (manifest) {
    if (manifest.group_id !== groupId || manifest.epoch !== epoch) return false;
    const manifestMembers = Array.isArray(manifest.member_aids)
      ? manifest.member_aids.map((item) => String(item ?? '').trim()).filter(Boolean).sort()
      : [];
    const payloadMembers = memberAids.map((item) => String(item ?? '').trim()).filter(Boolean).sort();
    if (manifestMembers.length > 0 && manifestMembers.join('\n') !== payloadMembers.join('\n')) return false;
  }

  const rotationId = typeof payload.rotation_id === 'string' ? payload.rotation_id : '';
  const chainAssessment = await assessIncomingEpochChain(
    keystore,
    aid,
    groupId,
    epoch,
    commitment,
    incomingEpochChain,
    rotationId,
    String(payload.distributed_by ?? payload.rotator_aid ?? payload.responder_aid ?? ''),
    'key_response',
  );
  if (!chainAssessment.ok) return false;

  return storeGroupSecretEpoch(
    keystore,
    aid,
    groupId,
    epoch,
    groupSecret,
    commitment,
    memberAids,
    incomingEpochChain,
    rotationId,
    chainAssessment.unverified,
    chainAssessment.reason,
  );
}

/** epoch 降级检查 */
export function checkEpochDowngrade(
  messageEpoch: number,
  localLatestEpoch: number,
  opts?: { allowOldEpoch?: boolean },
): boolean {
  if (messageEpoch >= localLatestEpoch) return true;
  return opts?.allowOldEpoch ?? false;
}

// ── GroupReplayGuard ────────────────────────────────────────

/** 群组消息防重放守卫 */
export class GroupReplayGuard {
  private _seen: Map<string, boolean> = new Map();
  private _maxSize: number;

  constructor(maxSize = 10000) {
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

  /** 仅记录 */
  record(groupId: string, senderAid: string, messageId: string): void {
    this._seen.set(`${groupId}:${senderAid}:${messageId}`, true);
    this.trim();
  }

  /** LRU 裁剪（供外部调用） */
  trim(): void {
    if (this._seen.size > this._maxSize) {
      const trimCount = this._seen.size - Math.floor(this._maxSize * 0.8);
      const keys = [...this._seen.keys()].slice(0, trimCount);
      for (const k of keys) this._seen.delete(k);
    }
  }

  get size(): number {
    return this._seen.size;
  }
}

// ── GroupKeyRequestThrottle ──────────────────────────────────

/** 群组密钥请求/响应频率限制 */
export class GroupKeyRequestThrottle {
  private _last: Map<string, number> = new Map();
  private _cooldown: number;

  constructor(cooldown = 30.0) {
    this._cooldown = cooldown;
  }

  /** 检查是否允许操作。返回 true 并记录时间戳，或 false 表示被限制。 */
  allow(key: string): boolean {
    const now = Date.now() / 1000;
    const last = this._last.get(key);
    if (last !== undefined && (now - last) < this._cooldown) return false;
    this._last.set(key, now);
    return true;
  }

  reset(key: string): void {
    this._last.delete(key);
  }
}

// ── GroupE2EEManager 主类 ────────────────────────────────────

/**
 * 群组端到端加密管理器 — 浏览器 SubtleCrypto 实现。
 *
 * 与 E2EEManager 平行：所有网络操作（P2P 发送、RPC 调用）由调用方负责。
 * 内置防重放、epoch 降级防护、密钥请求频率限制。
 * 所有密码学操作均为异步。
 */
export class GroupE2EEManager {
  private _log: ModuleLogger = _noopLog;
  setLogger(log: ModuleLogger): void { this._log = log; }

  private _identityFn: () => IdentityRecord;
  private _keystoreRef: KeyStore;
  private _replayGuard: GroupReplayGuard;
  private _requestThrottle: GroupKeyRequestThrottle;
  private _responseThrottle: GroupKeyRequestThrottle;
  private _senderCertResolver: ((aid: string) => string | null) | null;
  private _initiatorCertResolver: ((aid: string) => string | null) | null;
  private _pendingKeyRequests: Map<string, JsonObject> = new Map();

  constructor(opts: {
    identityFn: () => IdentityRecord;
    keystore: KeyStore;
    requestCooldown?: number;
    responseCooldown?: number;
    senderCertResolver?: ((aid: string) => string | null) | null;
    initiatorCertResolver?: ((aid: string) => string | null) | null;
  }) {
    this._identityFn = opts.identityFn;
    this._keystoreRef = opts.keystore;
    this._replayGuard = new GroupReplayGuard();
    this._requestThrottle = new GroupKeyRequestThrottle(opts.requestCooldown ?? 30.0);
    this._responseThrottle = new GroupKeyRequestThrottle(opts.responseCooldown ?? 30.0);
    this._senderCertResolver = opts.senderCertResolver ?? null;
    this._initiatorCertResolver = opts.initiatorCertResolver ?? null;
  }

  // ── 密钥管理 ──────────────────────────────────────

  /** 用当前身份私钥签名 manifest */
  private async _signManifest(manifest: JsonObject): Promise<JsonObject> {
    const identity = this._identityFn();
    const pkPem = identity.private_key_pem as string | undefined;
    if (!pkPem) return manifest;
    return signMembershipManifest(manifest, pkPem);
  }

  /** 创建首个 epoch。返回 {epoch, commitment, distributions: [{to, payload}]}。 */
  async createEpoch(
    groupId: string,
    memberAids: string[],
  ): Promise<JsonObject> {
    const tStart = Date.now();
    this._log.debug(`createEpoch enter: group_id=${groupId} members=${memberAids.length}`);
    try {
      const aid = this._currentAid();
      const gs = generateGroupSecret();
      const epoch = 1;
      const commitment = await computeMembershipCommitment(memberAids, epoch, groupId, gs);
      const epochChain = await computeEpochChain(null, epoch, commitment, aid);
      await storeGroupSecret(this._keystoreRef, aid, groupId, epoch, gs, commitment, memberAids, epochChain);
      const manifest = await this._signManifest(buildMembershipManifest(
        groupId, epoch, null, memberAids, { initiatorAid: aid },
      ));
      const distPayload = await buildKeyDistribution(groupId, epoch, gs, memberAids, aid, manifest, epochChain);
      this._log.debug(`createEpoch exit: elapsed=${Date.now() - tStart}ms group_id=${groupId} epoch=${epoch}`);
      return {
        epoch,
        commitment,
        distributions: memberAids.filter(m => m !== aid).map(m => ({ to: m, payload: distPayload })),
      };
    } catch (err) {
      this._log.debug(`createEpoch exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 轮换 epoch（踢人/退出后调用） */
  async rotateEpoch(
    groupId: string,
    memberAids: string[],
  ): Promise<JsonObject> {
    const tStart = Date.now();
    this._log.debug(`rotateEpoch enter: group_id=${groupId} members=${memberAids.length}`);
    try {
      const aid = this._currentAid();
      const current = await loadGroupSecret(this._keystoreRef, aid, groupId);
      const prevEpoch = current ? current.epoch : null;
      const prevChain = current?.epoch_chain ?? null;
      const newEpoch = (prevEpoch ?? 0) + 1;
      const gs = generateGroupSecret();
      const commitment = await computeMembershipCommitment(memberAids, newEpoch, groupId, gs);
      const epochChain = await computeEpochChain(prevChain, newEpoch, commitment, aid);
      const stored = await storeGroupSecret(this._keystoreRef, aid, groupId, newEpoch, gs, commitment, memberAids, epochChain);
      if (!stored) {
        throw new Error(`group ${groupId} epoch ${newEpoch} secret already exists or is newer; abort distribution`);
      }
      const manifest = await this._signManifest(buildMembershipManifest(
        groupId, newEpoch, prevEpoch, memberAids, { initiatorAid: aid },
      ));
      const distPayload = await buildKeyDistribution(groupId, newEpoch, gs, memberAids, aid, manifest, epochChain);
      this._log.debug(`rotateEpoch exit: elapsed=${Date.now() - tStart}ms group_id=${groupId} epoch=${newEpoch}`);
      return {
        epoch: newEpoch,
        commitment,
        distributions: memberAids.filter(m => m !== aid).map(m => ({ to: m, payload: distPayload })),
      };
    } catch (err) {
      this._log.debug(`rotateEpoch exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 指定目标 epoch 号轮换（配合服务端 CAS 使用） */
  async rotateEpochTo(
    groupId: string,
    targetEpoch: number,
    memberAids: string[],
    opts?: { rotationId?: string; prevChainHint?: string | null },
  ): Promise<JsonObject> {
    const tStart = Date.now();
    this._log.debug(`rotateEpochTo enter: group_id=${groupId} target_epoch=${targetEpoch} members=${memberAids.length} rotation_id=${opts?.rotationId ?? ''}`);
    try {
      const aid = this._currentAid();
      const current = await loadGroupSecret(this._keystoreRef, aid, groupId, targetEpoch - 1)
        ?? await loadGroupSecret(this._keystoreRef, aid, groupId);
      let prevChain = current?.epoch_chain ?? null;
      if (!prevChain && opts?.prevChainHint) {
        prevChain = opts.prevChainHint;
      }
      const gs = generateGroupSecret();
      const commitment = await computeMembershipCommitment(memberAids, targetEpoch, groupId, gs);
      const epochChain = await computeEpochChain(prevChain, targetEpoch, commitment, aid);
      const rotationId = opts?.rotationId ?? '';
      const stored = await storeGroupSecret(
        this._keystoreRef,
        aid,
        groupId,
        targetEpoch,
        gs,
        commitment,
        memberAids,
        epochChain,
        rotationId,
      );
      if (!stored) {
        throw new Error(`group ${groupId} epoch ${targetEpoch} secret already exists or is newer; abort distribution`);
      }
      const manifest = await this._signManifest(buildMembershipManifest(
        groupId, targetEpoch, targetEpoch - 1, memberAids, { initiatorAid: aid },
      ));
      const distPayload = await buildKeyDistribution(groupId, targetEpoch, gs, memberAids, aid, manifest, epochChain);
      if (rotationId) {
        distPayload.rotation_id = rotationId;
      }
      this._log.debug(`rotateEpochTo exit: elapsed=${Date.now() - tStart}ms group_id=${groupId} epoch=${targetEpoch}`);
      return {
        epoch: targetEpoch,
        commitment,
        distributions: memberAids.filter(m => m !== aid).map(m => ({ to: m, payload: distPayload })),
      };
    } catch (err) {
      this._log.debug(`rotateEpochTo exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 手动存储 group_secret。返回 false 表示 epoch 降级被拒。 */
  async storeSecret(
    groupId: string,
    epoch: number,
    groupSecretBytes: Uint8Array,
    commitment: string,
    memberAids: string[],
    epochChain?: string,
  ): Promise<boolean> {
    return storeGroupSecret(
      this._keystoreRef, this._currentAid(), groupId, epoch,
      groupSecretBytes, commitment, memberAids, epochChain,
    );
  }

  async discardPendingSecret(groupId: string, epoch: number, rotationId: string): Promise<boolean> {
    return discardPendingGroupSecret(this._keystoreRef, this._currentAid(), groupId, epoch, rotationId);
  }

  async loadSecret(groupId: string, epoch?: number | null): Promise<{
    epoch: number; secret: Uint8Array; commitment: string; member_aids: string[]; epoch_chain?: string; pending_rotation_id?: string;
  } | null> {
    return loadGroupSecret(this._keystoreRef, this._currentAid(), groupId, epoch);
  }

  async loadAllSecrets(groupId: string): Promise<Map<number, Uint8Array>> {
    return loadAllGroupSecrets(this._keystoreRef, this._currentAid(), groupId);
  }

  async cleanup(groupId: string, retentionSeconds = OLD_EPOCH_RETENTION_SECONDS): Promise<number> {
    return cleanupOldEpochs(this._keystoreRef, this._currentAid(), groupId, retentionSeconds);
  }

  // ── 加解密 ────────────────────────────────────────

  /** 加密群消息（含发送方签名）。无密钥时抛 E2EEGroupSecretMissingError。 */
  async encrypt(
    groupId: string,
    payload: JsonObject,
    opts?: {
      messageId?: string;
      timestamp?: number;
      protectedHeaders?: ProtectedHeadersInput;
      protected_headers?: ProtectedHeadersInput;
      headers?: ProtectedHeadersInput;
      context?: JsonObject | null;
    },
  ): Promise<JsonObject> {
    const tStart = Date.now();
    this._log.debug(`encrypt enter: group_id=${groupId} mid=${opts?.messageId ?? '<auto>'}`);
    try {
      const aid = this._currentAid();
      const secretData = await loadGroupSecret(this._keystoreRef, aid, groupId);
      if (!secretData) {
        throw new E2EEGroupSecretMissingError(`no group secret for ${groupId}`);
      }
      const identity = this._identityFn();
      const senderPkPem = (identity?.private_key_pem as string | undefined) ?? null;
      const senderCertPem = (identity?.cert as string | undefined) ?? null;
      const result = await encryptGroupMessage(
        groupId, secretData.epoch, secretData.secret, payload, {
          fromAid: aid,
          messageId: opts?.messageId ?? `gm-${uuidV4()}`,
          timestamp: opts?.timestamp ?? Date.now(),
          senderPrivateKeyPem: senderPkPem,
          senderCertPem,
          protectedHeaders: opts?.protectedHeaders ?? opts?.protected_headers ?? opts?.headers,
          context: opts?.context ?? null,
        },
      );
      this._log.debug(`encrypt exit: elapsed=${Date.now() - tStart}ms group_id=${groupId} epoch=${secretData.epoch}`);
      return result;
    } catch (err) {
      this._log.debug(`encrypt exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 使用指定 epoch 加密群消息。 */
  async encryptWithEpoch(
    groupId: string,
    epoch: number,
    payload: JsonObject,
    opts?: {
      messageId?: string;
      timestamp?: number;
      protectedHeaders?: ProtectedHeadersInput;
      protected_headers?: ProtectedHeadersInput;
      headers?: ProtectedHeadersInput;
      context?: JsonObject | null;
    },
  ): Promise<JsonObject> {
    const tStart = Date.now();
    this._log.debug(`encryptWithEpoch enter: group_id=${groupId} epoch=${epoch} mid=${opts?.messageId ?? '<auto>'}`);
    try {
      const aid = this._currentAid();
      const secretData = await loadGroupSecret(this._keystoreRef, aid, groupId, epoch);
      if (!secretData) {
        throw new E2EEGroupSecretMissingError(`no group secret for ${groupId} epoch ${epoch}`);
      }
      const identity = this._identityFn();
      const senderPkPem = (identity?.private_key_pem as string | undefined) ?? null;
      if (!senderPkPem) {
        throw new E2EEError('sender identity private key unavailable for group message signing');
      }
      const senderCertPem = (identity?.cert as string | undefined) ?? null;
      const result = await encryptGroupMessage(
        groupId,
        secretData.epoch,
        secretData.secret,
        payload,
        {
          fromAid: aid,
          messageId: opts?.messageId ?? `gm-${uuidV4()}`,
          timestamp: opts?.timestamp ?? Date.now(),
          senderPrivateKeyPem: senderPkPem,
          senderCertPem,
          protectedHeaders: opts?.protectedHeaders ?? opts?.protected_headers ?? opts?.headers,
          context: opts?.context ?? null,
        },
      );
      this._log.debug(`encryptWithEpoch exit: elapsed=${Date.now() - tStart}ms group_id=${groupId} epoch=${secretData.epoch}`);
      return result;
    } catch (err) {
      this._log.debug(`encryptWithEpoch exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 解密单条群消息（异步）。内置防重放 + 发送方验签 + 外层字段校验。
   *
   * opts.skipReplay: 跳过防重放检查（用于 group.pull 场景）。
   */
  async decrypt(
    message: Message,
    opts?: { skipReplay?: boolean },
  ): Promise<Message | null> {
    const tStart = Date.now();
    const groupIdInit = String(message.group_id ?? '');
    const senderInit = String(message.from ?? message.sender_aid ?? '');
    const midInit = String(message.message_id ?? '');
    this._log.debug(`decrypt enter: group_id=${groupIdInit} from=${senderInit} mid=${midInit} skip_replay=${!!opts?.skipReplay}`);
    try {
      const payload = isJsonObject(message.payload) ? message.payload : null;
      if (payload === null || payload.type !== 'e2ee.group_encrypted') {
        this._log.debug(`decrypt exit: elapsed=${Date.now() - tStart}ms result=passthrough_not_encrypted`);
        return message;
      }
      const groupId = String(message.group_id ?? '');
      const sender = String(message.from ?? message.sender_aid ?? '');
      const skipReplay = opts?.skipReplay ?? false;

      // 防重放预检：优先使用 AAD 内 message_id
      const aad = isJsonObject(payload.aad) ? payload.aad : undefined;
      const aadMsgId = aad ? (aad.message_id ?? '') as string : '';
      const msgId = aadMsgId || (message.message_id ?? '') as string;
      if (!skipReplay && groupId && sender && msgId) {
        // 返回原消息（不含 e2ee 字段），调用方可通过缺失 e2ee 识别 replay
        if (this._replayGuard.isSeen(groupId, sender, msgId)) {
          this._log.debug(`decrypt exit: elapsed=${Date.now() - tStart}ms result=replay_skipped group_id=${groupId}`);
          return message;
        }
      }

      // 解析发送方证书（零信任：无证书则拒绝）
      let senderCertPem: string | null = null;
      if (this._senderCertResolver && sender) {
        senderCertPem = this._senderCertResolver(sender);
      }
      if (!senderCertPem) {
        this._log.warn(
          `拒绝群消息：无法获取发送方 ${sender} 的证书（零信任模式禁止跳过验签）: group=${groupId}`,
        );
        this._log.debug(`decrypt exit: elapsed=${Date.now() - tStart}ms result=rejected_no_sender_cert`);
        return null;
      }

      const allSecrets = await loadAllGroupSecrets(this._keystoreRef, this._currentAid(), groupId);
      if (!allSecrets.size) {
        this._log.debug(`decrypt exit: elapsed=${Date.now() - tStart}ms result=no_secrets group_id=${groupId}`);
        return null;
      }
      const result = await decryptGroupMessage(message, allSecrets, senderCertPem);

      // 解密成功后记录防重放
      if (result !== null) {
        const finalMsgId = aadMsgId || (message.message_id ?? '') as string;
        if (!skipReplay && groupId && sender && finalMsgId) {
          this._replayGuard.record(groupId, sender, finalMsgId);
        }
      }
      this._log.debug(`decrypt exit: elapsed=${Date.now() - tStart}ms result=${result !== null ? 'ok' : 'failed'} group_id=${groupId}`);
      return result;
    } catch (err) {
      this._log.debug(`decrypt exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 批量解密 */
  async decryptBatch(
    messages: Message[],
    opts?: { skipReplay?: boolean },
  ): Promise<Message[]> {
    const tStart = Date.now();
    this._log.debug(`decryptBatch enter: count=${messages.length} skip_replay=${!!opts?.skipReplay}`);
    try {
      const results: Message[] = [];
      for (const m of messages) {
        results.push((await this.decrypt(m, opts)) ?? m);
      }
      this._log.debug(`decryptBatch exit: elapsed=${Date.now() - tStart}ms count=${results.length}`);
      return results;
    } catch (err) {
      this._log.debug(`decryptBatch exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  // ── 密钥协议消息处理 ──────────────────────────────

  /**
   * 处理已解密的 P2P 密钥消息（异步）。
   *
   * 返回 "distribution"/"request"/"response" 表示已成功处理。
   * 返回 "distribution_rejected"/"response_rejected" 表示被拒绝。
   * 返回 null 表示不是密钥消息。
   */
  async handleIncoming(payload: JsonObject): Promise<string | null> {
    const tStart = Date.now();
    const msgType = (payload.type ?? '') as string;
    this._log.debug(`handleIncoming enter: type=${msgType} group_id=${String(payload.group_id ?? '')}`);
    try {
      const aid = this._currentAid();

      if (msgType === 'e2ee.group_key_distribution') {
        // 解析发起者证书用于 manifest 验证
        let initiatorCert: string | null = null;
        const distributedBy = (payload.distributed_by ?? '') as string;
        if (this._initiatorCertResolver && distributedBy) {
          initiatorCert = this._initiatorCertResolver(distributedBy);
        }
        const ok = await handleKeyDistribution(payload, this._keystoreRef, aid, initiatorCert);
        const r = ok ? 'distribution' : 'distribution_rejected';
        this._log.debug(`handleIncoming exit: elapsed=${Date.now() - tStart}ms result=${r}`);
        return r;
      }
      if (msgType === 'e2ee.group_key_response') {
        const pendingKey = `${String(payload.group_id ?? '')}:${String(payload.epoch ?? '')}:${String(payload.request_id ?? '')}`;
        const expected = this._pendingKeyRequests.get(pendingKey) ?? null;
        if (expected === null) {
          this._log.debug(`handleIncoming exit: elapsed=${Date.now() - tStart}ms result=response_rejected reason=no_pending`);
          return 'response_rejected';
        }
        const responderAid = String(payload.responder_aid ?? '');
        const responderCertPem = responderAid && this._initiatorCertResolver
          ? this._initiatorCertResolver(responderAid)
          : null;
        const ok = await handleKeyResponse(payload, this._keystoreRef, aid, {
          expectedRequest: expected,
          responderCertPem,
          currentMembers: await this.getMemberAids(String(payload.group_id ?? '')),
          strict: true,
        });
        if (ok && expected) this._pendingKeyRequests.delete(pendingKey);
        const r = ok ? 'response' : 'response_rejected';
        this._log.debug(`handleIncoming exit: elapsed=${Date.now() - tStart}ms result=${r}`);
        return r;
      }
      if (msgType === 'e2ee.group_key_request') {
        this._log.debug(`handleIncoming exit: elapsed=${Date.now() - tStart}ms result=request`);
        return 'request';
      }
      this._log.debug(`handleIncoming exit: elapsed=${Date.now() - tStart}ms result=null`);
      return null;
    } catch (err) {
      this._log.debug(`handleIncoming exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 构建恢复请求。返回 {to, payload} 或 null（限流/无目标）。 */
  async buildRecoveryRequest(
    groupId: string,
    epoch: number,
    opts?: { senderAid?: string },
  ): Promise<JsonObject | null> {
    const tStart = Date.now();
    this._log.debug(`buildRecoveryRequest enter: group_id=${groupId} epoch=${epoch} sender_hint=${opts?.senderAid ?? ''}`);
    try {
      const aid = this._currentAid();
      if (!this._requestThrottle.allow(`request:${groupId}:${epoch}`)) {
        this._log.debug(`buildRecoveryRequest exit: elapsed=${Date.now() - tStart}ms result=throttled`);
        return null;
      }
      let candidates: string[] = [];
      const secretData = await loadGroupSecret(this._keystoreRef, aid, groupId);
      if (secretData?.member_aids?.length) {
        candidates = secretData.member_aids.filter(m => m !== aid);
      }
      if (!candidates.length && opts?.senderAid && opts.senderAid !== aid) {
        candidates = [opts.senderAid];
      }
      if (!candidates.length) {
        this._log.debug(`buildRecoveryRequest exit: elapsed=${Date.now() - tStart}ms result=no_candidates`);
        return null;
      }
      const payload = buildKeyRequest(groupId, epoch, aid);
      this.rememberKeyRequest(payload, candidates[0]);
      this._log.debug(`buildRecoveryRequest exit: elapsed=${Date.now() - tStart}ms target=${candidates[0]}`);
      return { to: candidates[0], payload };
    } catch (err) {
      this._log.debug(`buildRecoveryRequest exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
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

  /** 处理密钥请求（受频率限制 + 成员资格验证） */
  async handleKeyRequestMsg(
    requestPayload: JsonObject,
    currentMembers: string[],
  ): Promise<JsonObject | null> {
    const tStart = Date.now();
    const requester = (requestPayload.requester_aid ?? '') as string;
    const groupId = (requestPayload.group_id ?? '') as string;
    this._log.debug(`handleKeyRequestMsg enter: group_id=${groupId} requester=${requester} members=${currentMembers.length}`);
    try {
      if (!requester || !groupId) {
        this._log.debug(`handleKeyRequestMsg exit: elapsed=${Date.now() - tStart}ms result=invalid_payload`);
        return null;
      }
      if (!currentMembers.includes(requester)) {
        this._log.warn(`reject key recover request: ${requester} not in group ${groupId}  current member list`);
        this._log.debug(`handleKeyRequestMsg exit: elapsed=${Date.now() - tStart}ms result=not_member`);
        return null;
      }
      if (!this._responseThrottle.allow(`response:${groupId}:${requester}`)) {
        this._log.debug(`handleKeyRequestMsg exit: elapsed=${Date.now() - tStart}ms result=throttled`);
        return null;
      }
      const identity = this._identityFn();
      const privateKeyPem = identity?.private_key_pem as string | undefined;
      if (!privateKeyPem) {
        this._log.debug(`handleKeyRequestMsg exit: elapsed=${Date.now() - tStart}ms result=no_private_key`);
        return null;
      }
      const result = await handleKeyRequest(
        requestPayload,
        this._keystoreRef,
        this._currentAid(),
        currentMembers,
        privateKeyPem,
      );
      this._log.debug(`handleKeyRequestMsg exit: elapsed=${Date.now() - tStart}ms result=${result !== null ? 'ok' : 'null'}`);
      return result;
    } catch (err) {
      this._log.debug(`handleKeyRequestMsg exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  // ── 状态查询 ──────────────────────────────────────

  async hasSecret(groupId: string): Promise<boolean> {
    const s = await loadGroupSecret(this._keystoreRef, this._currentAid(), groupId);
    return s !== null;
  }

  async currentEpoch(groupId: string): Promise<number | null> {
    const s = await loadGroupSecret(this._keystoreRef, this._currentAid(), groupId);
    return s ? s.epoch : null;
  }

  async getMemberAids(groupId: string): Promise<string[]> {
    const s = await loadGroupSecret(this._keystoreRef, this._currentAid(), groupId);
    return s ? s.member_aids : [];
  }

  /** 清理过期缓存（replay guard 等），供外部定时调用 */
  cleanExpiredCaches(): void {
    this._replayGuard.trim();
  }

  /** 删除群组的所有本地状态（群组解散时使用，异步） */
  async removeGroup(groupId: string): Promise<void> {
    try {
      await deleteGroupSecret(this._keystoreRef, this._currentAid(), groupId);
    } catch {
      // keystore 不支持 delete 时忽略（降级方案已在 deleteGroupSecret 中处理）
    }
  }

  // ── 内部工具 ──────────────────────────────────────

  private _currentAid(): string {
    const identity = this._identityFn();
    const aid = identity.aid;
    if (!aid) throw new E2EEError('AID unavailable');
    return String(aid);
  }
}
