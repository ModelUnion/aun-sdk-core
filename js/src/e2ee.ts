// ── E2EEManager（P2P 端到端加密 — 浏览器 SubtleCrypto 实现）──
// 所有密码学操作均为异步（SubtleCrypto API 要求）

import { E2EEDecryptFailedError, E2EEError } from './errors.js';
import type { ModuleLogger } from './logger.js';
import { uint8ToBase64, base64ToUint8, pemToArrayBuffer, p1363ToDer, toArrayBuffer, toBufferSource } from './crypto.js';
import type { KeyStore } from './keystore/index.js';
import type { IdentityRecord, JsonObject, Message, PrekeyRecord } from './types.js';


const _noopLog: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };
// 顶层函数共享的模块 logger（client 构造时通过 setModuleLogger 注入）
let _moduleLog: ModuleLogger = _noopLog;
export function setModuleLogger(log: ModuleLogger): void { _moduleLog = log; }

/** 加密套件标识 */
export const SUITE = 'P256_HKDF_SHA256_AES_256_GCM';

/** 加密模式 */
export const MODE_PREKEY_ECDH_V2 = 'prekey_ecdh_v2';
export const MODE_LONG_TERM_KEY = 'long_term_key';

/** AAD 字段定义（P2P） */
export const AAD_FIELDS_OFFLINE = [
  'from', 'to', 'message_id', 'timestamp',
  'encryption_mode', 'suite', 'ephemeral_public_key',
  'recipient_cert_fingerprint', 'sender_cert_fingerprint',
  'prekey_id',
] as const;

/** AAD 匹配字段（解密时校验，不含 timestamp） */
export const AAD_MATCH_FIELDS_OFFLINE = [
  'from', 'to', 'message_id',
  'encryption_mode', 'suite', 'ephemeral_public_key',
  'recipient_cert_fingerprint', 'sender_cert_fingerprint',
  'prekey_id',
] as const;

/** 兼容型可选 AAD 字段：存在时才参与 AAD，不为旧消息补 null。 */
export const AAD_OPTIONAL_FIELDS = [
  'payload_type', 'protected_headers', 'context_type', 'context_id',
] as const;

const METADATA_AUTH_FIELD = '_auth';
const METADATA_AUTH_ALG = 'HMAC-SHA256';
const METADATA_KEY_DOMAIN = new TextEncoder().encode('aun-envelope-metadata-key-v1');
const PROTECTED_HEADERS_DOMAIN = new TextEncoder().encode('aun-protected-headers-v1');
const PROTECTED_CONTEXT_DOMAIN = new TextEncoder().encode('aun-protected-context-v1');

/** prekey 私钥本地保留时间（秒） */
export const PREKEY_RETENTION_SECONDS = 7 * 24 * 3600;
export const PREKEY_MIN_KEEP_COUNT = 7;

export interface PrekeyMaterial extends JsonObject {
  prekey_id: string;
  public_key: string;
  signature: string;
  created_at?: number;
  device_id?: string;
  cert_fingerprint?: string;
}

interface LocalPrekeyRecord extends PrekeyRecord {
  private_key_pem?: string;
  created_at?: number;
  updated_at?: number;
  expires_at?: number;
}

type LocalPrekeyStore = Record<string, LocalPrekeyRecord>;

export type ProtectedHeadersInput = ProtectedHeaders | Record<string, unknown> | null | undefined;

/** 端到端保护的信封元数据，语义接近 HTTP headers。 */
export class ProtectedHeaders {
  private _items: Record<string, string> = {};

  constructor(values?: Record<string, unknown> | null) {
    if (values) {
      for (const [key, value] of Object.entries(values)) {
        this.set(key, value);
      }
    }
  }

  private static normalizeKey(key: unknown): string {
    const value = String(key ?? '').trim().toLowerCase();
    if (!value || !/^[a-z0-9_-]+$/.test(value)) {
      throw new E2EEError('protected header key must match [a-z0-9_-]+');
    }
    if (value === METADATA_AUTH_FIELD) {
      throw new E2EEError('protected header key is reserved');
    }
    return value;
  }

  set(key: string, value: unknown): this {
    this._items[ProtectedHeaders.normalizeKey(key)] = value == null ? '' : String(value);
    return this;
  }

  get(key: string, defaultValue: string | null = null): string | null {
    const normalized = ProtectedHeaders.normalizeKey(key);
    return Object.prototype.hasOwnProperty.call(this._items, normalized)
      ? this._items[normalized]
      : defaultValue;
  }

  remove(key: string): this {
    delete this._items[ProtectedHeaders.normalizeKey(key)];
    return this;
  }

  toObject(): Record<string, string> {
    return { ...this._items };
  }

  toJSON(): Record<string, string> {
    return this.toObject();
  }

  static from(values?: Record<string, unknown> | null): ProtectedHeaders {
    return new ProtectedHeaders(values ?? {});
  }
}

function prekeyCreatedMarker(prekeyData: LocalPrekeyRecord): number {
  return Number(prekeyData.created_at ?? prekeyData.updated_at ?? prekeyData.expires_at ?? 0);
}

function latestPrekeyIds(
  prekeys: LocalPrekeyStore,
  keepLatest: number,
): Set<string> {
  if (keepLatest <= 0) return new Set();
  return new Set(
    Object.entries(prekeys)
      .filter(([, data]) => typeof data === 'object' && data !== null)
      .sort((left, right) => {
        const markerDiff = prekeyCreatedMarker(right[1]) - prekeyCreatedMarker(left[1]);
        if (markerDiff !== 0) return markerDiff;
        return right[0].localeCompare(left[0]);
      })
      .slice(0, keepLatest)
      .map(([prekeyId]) => prekeyId),
  );
}

/** 加密结果信息 */
export interface EncryptResult {
  encrypted: boolean;
  forward_secrecy: boolean;
  mode: string;
  degraded: boolean;
  degradation_reason?: string;
}

async function loadKeyStorePrekeys(
  keystore: KeyStore,
  aid: string,
  deviceId = '',
): Promise<LocalPrekeyStore> {
  const normalizedDeviceId = String(deviceId ?? '').trim();
  if (typeof keystore.loadE2EEPrekeys === 'function') {
    return ((await keystore.loadE2EEPrekeys(aid, normalizedDeviceId)) ?? {}) as LocalPrekeyStore;
  }
  throw new Error('keystore 缺少 loadE2EEPrekeys 方法');
}

async function saveKeyStorePrekey(
  keystore: KeyStore,
  aid: string,
  deviceId: string,
  prekeyId: string,
  prekeyData: LocalPrekeyRecord,
): Promise<void> {
  const normalizedDeviceId = String(deviceId ?? '').trim();
  if (typeof keystore.saveE2EEPrekey === 'function') {
    await keystore.saveE2EEPrekey(aid, prekeyId, prekeyData, normalizedDeviceId);
    return;
  }
  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} 缺少 saveE2EEPrekey 方法`);
}

async function cleanupKeyStorePrekeys(
  keystore: KeyStore,
  aid: string,
  deviceId: string,
  cutoffMs: number,
  keepLatest = PREKEY_MIN_KEEP_COUNT,
): Promise<string[]> {
  const normalizedDeviceId = String(deviceId ?? '').trim();
  if (typeof keystore.cleanupE2EEPrekeys === 'function') {
    return (await keystore.cleanupE2EEPrekeys(aid, cutoffMs, keepLatest, normalizedDeviceId)) ?? [];
  }
  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} 缺少 cleanupE2EEPrekeys 方法`);
}

// ── 工具函数 ────────────────────────────────────────────────

const _encoder = new TextEncoder();
const _decoder = new TextDecoder();

/** 拼接多个 Uint8Array */
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.byteLength;
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.byteLength;
  }
  return result;
}

/** DER 签名转 IEEE P1363 格式（用于 SubtleCrypto 验签） */
function derToP1363(der: Uint8Array, coordLen = 32): Uint8Array {
  // 跳过 SEQUENCE 头
  if (der[0] !== 0x30) throw new E2EEError('无效 DER 签名: 缺少 SEQUENCE 标签');
  let pos = 2; // 跳过 30 + length

  // 读取 r
  if (der[pos] !== 0x02) throw new E2EEError('无效 DER 签名: 缺少 INTEGER 标签 (r)');
  pos++;
  const rLen = der[pos++];
  let rBytes = der.slice(pos, pos + rLen);
  pos += rLen;

  // 读取 s
  if (der[pos] !== 0x02) throw new E2EEError('无效 DER 签名: 缺少 INTEGER 标签 (s)');
  pos++;
  const sLen = der[pos++];
  let sBytes = der.slice(pos, pos + sLen);

  // 去掉前导 0x00（ASN.1 有符号整数的填充）
  if (rBytes.length > coordLen && rBytes[0] === 0) rBytes = rBytes.slice(1);
  if (sBytes.length > coordLen && sBytes[0] === 0) sBytes = sBytes.slice(1);

  // 左填充到 coordLen
  const result = new Uint8Array(coordLen * 2);
  result.set(rBytes, coordLen - rBytes.length);
  result.set(sBytes, coordLen * 2 - sBytes.length);
  return result;
}

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

function normalizeProtectedHeaders(headers: ProtectedHeadersInput): JsonObject {
  if (headers == null) return {};
  if (headers instanceof ProtectedHeaders) {
    return headers.toObject();
  }
  const toObject = (headers as { toObject?: () => Record<string, unknown> }).toObject;
  if (typeof toObject === 'function') {
    return new ProtectedHeaders(toObject.call(headers)).toObject();
  }
  if (typeof headers !== 'object' || Array.isArray(headers)) {
    throw new E2EEError('protected_headers must be an object');
  }
  return new ProtectedHeaders(headers as Record<string, unknown>).toObject();
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

function aadBytesWithOptionalFields(aad: JsonObject, baseFields: readonly string[]): Uint8Array {
  const obj: JsonObject = {};
  for (const field of baseFields) {
    obj[field] = aad[field] ?? null;
  }
  return _encoder.encode(canonicalStringify(obj));
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

/** AAD 序列化（排序键、紧凑 JSON） */
function aadBytesOffline(aad: JsonObject): Uint8Array {
  return aadBytesWithOptionalFields(aad, AAD_FIELDS_OFFLINE);
}

/** AAD 匹配检查（解密时校验） */
function aadMatchesOffline(expected: JsonObject, actual: JsonObject): boolean {
  for (const field of AAD_MATCH_FIELDS_OFFLINE) {
    // 宽松比较：JSON 序列化后对比
    if (JSON.stringify(expected[field] ?? null) !== JSON.stringify(actual[field] ?? null)) {
      return false;
    }
  }
  return true;
}

/** 从 PEM 证书中提取 SPKI 公钥字节（解析 X.509 DER 结构） */
function extractSpkiFromCertPem(certPem: string): ArrayBuffer {
  const der = pemToArrayBuffer(certPem);
  return extractSpkiFromCertDer(new Uint8Array(der));
}

/**
 * 从 X.509 DER 证书中提取 SubjectPublicKeyInfo 字段。
 * 简化解析：仅处理 P-256 ECDSA 证书（AUN 协议限定）。
 */
function extractSpkiFromCertDer(certDer: Uint8Array): ArrayBuffer {
  // X.509 结构: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
  // tbsCertificate: SEQUENCE { version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, ... }
  // 我们需要提取 subjectPublicKeyInfo 段

  // 递归查找 SPKI：P-256 SPKI 的 OID 前缀为 30 59 30 13 06 07 2a 86 48 ce 3d 02 01
  // 搜索模式：找到 P-256 的 AlgorithmIdentifier OID
  const ecOid = new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  const p256Oid = new Uint8Array([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);

  // 在 DER 中搜索 EC public key OID
  for (let i = 0; i < certDer.length - ecOid.length; i++) {
    let match = true;
    for (let j = 0; j < ecOid.length; j++) {
      if (certDer[i + j] !== ecOid[j]) { match = false; break; }
    }
    if (!match) continue;

    // 找到 EC OID，往前回溯找 SEQUENCE 起始
    // SPKI 格式: 30 <len> 30 <algLen> <ecOid> <p256Oid> 03 <bitStringLen> 00 <pubKeyBytes>
    // 向前查找最近的 0x30（SEQUENCE）
    for (let back = 1; back <= 4; back++) {
      const seqStart = i - back;
      if (seqStart < 0) continue;
      if (certDer[seqStart] !== 0x30) continue;

      // 解析 SEQUENCE 长度
      const seqLen = parseDerLength(certDer, seqStart + 1);
      if (seqLen === null) continue;
      const totalLen = 1 + seqLen.lenBytes + seqLen.value;
      // SPKI 应包含完整的 AlgorithmIdentifier + BIT STRING
      if (totalLen < 50 || totalLen > 120) continue;

      // 验证这确实是 SPKI（内部应包含 BIT STRING tag 0x03）
      const spkiCandidate = certDer.slice(seqStart, seqStart + totalLen);
      // 检查末尾附近有 BIT STRING
      let hasBitString = false;
      for (let k = 20; k < spkiCandidate.length - 10; k++) {
        if (spkiCandidate[k] === 0x03 && spkiCandidate[k + 2] === 0x00) {
          hasBitString = true;
          break;
        }
      }
      if (hasBitString) {
        return spkiCandidate.buffer.slice(
          spkiCandidate.byteOffset,
          spkiCandidate.byteOffset + spkiCandidate.byteLength,
        );
      }
    }
  }
  throw new E2EEError('无法从证书中提取 SPKI 公钥');
}

/** 解析 DER 长度字段 */
function parseDerLength(data: Uint8Array, offset: number): { value: number; lenBytes: number } | null {
  if (offset >= data.length) return null;
  const first = data[offset];
  if (first < 0x80) {
    return { value: first, lenBytes: 1 };
  }
  const numBytes = first & 0x7f;
  if (numBytes === 0 || numBytes > 4) return null;
  let value = 0;
  for (let i = 0; i < numBytes; i++) {
    if (offset + 1 + i >= data.length) return null;
    value = (value << 8) | data[offset + 1 + i];
  }
  return { value, lenBytes: 1 + numBytes };
}

/** 计算 SPKI 公钥的 SHA-256 指纹 */
async function fingerprintSpki(spkiBytes: ArrayBuffer): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', spkiBytes);
  const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `sha256:${hex}`;
}

/** 从 PEM 证书计算证书 SHA-256 指纹 */
async function fingerprintCertPem(certPem: string): Promise<string> {
  return certificateSha256Fingerprint(certPem);
}

/** 从 PEM 证书计算证书 SHA-256 指纹 */
async function certificateSha256Fingerprint(certPem: string): Promise<string> {
  const der = pemToArrayBuffer(certPem);
  const hash = await crypto.subtle.digest('SHA-256', der);
  const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `sha256:${hex}`;
}

/** 从 SPKI DER base64 计算公钥指纹 */
async function fingerprintDerB64(derB64: string): Promise<string> {
  const der = base64ToUint8(derB64);
  return fingerprintSpki(toArrayBuffer(der));
}

/** 导入 PEM 证书公钥为 ECDSA CryptoKey */
async function importCertPublicKeyEcdsa(certPem: string): Promise<CryptoKey> {
  const spki = extractSpkiFromCertPem(certPem);
  return crypto.subtle.importKey(
    'spki', spki,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, ['verify'],
  );
}

/** 导入 PEM 证书公钥为 ECDH CryptoKey */
async function importCertPublicKeyEcdh(certPem: string): Promise<CryptoKey> {
  const spki = extractSpkiFromCertPem(certPem);
  return crypto.subtle.importKey(
    'spki', spki,
    { name: 'ECDH', namedCurve: 'P-256' },
    true, [],
  );
}

/** 导入 SPKI DER base64 为 ECDH CryptoKey */
async function importSpkiDerB64Ecdh(derB64: string): Promise<CryptoKey> {
  const der = base64ToUint8(derB64);
  return crypto.subtle.importKey(
    'spki', toArrayBuffer(der),
    { name: 'ECDH', namedCurve: 'P-256' },
    true, [],
  );
}

/** 导入 SPKI DER base64 为 ECDSA CryptoKey */
async function importSpkiDerB64Ecdsa(derB64: string): Promise<CryptoKey> {
  const der = base64ToUint8(derB64);
  return crypto.subtle.importKey(
    'spki', toArrayBuffer(der),
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, ['verify'],
  );
}

/** 导入 PEM 私钥为 ECDSA CryptoKey */
/**
 * ECDSA 私钥导入缓存：避免每次签名都重复调用 crypto.subtle.importKey。
 * 缓存键为 PEM 字符串本身，identity 变更时新 PEM 自然不命中旧缓存。
 */
const _ecdsaKeyCache = new Map<string, CryptoKey>();

async function importPrivateKeyEcdsa(pem: string): Promise<CryptoKey> {
  const cached = _ecdsaKeyCache.get(pem);
  if (cached) return cached;
  const pkcs8 = pemToArrayBuffer(pem);
  const key = await crypto.subtle.importKey(
    'pkcs8', pkcs8,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, ['sign'],
  );
  _ecdsaKeyCache.set(pem, key);
  return key;
}

/** 导入 PEM 私钥为 ECDH CryptoKey */
async function importPrivateKeyEcdh(pem: string): Promise<CryptoKey> {
  const pkcs8 = pemToArrayBuffer(pem);
  return crypto.subtle.importKey(
    'pkcs8', pkcs8,
    { name: 'ECDH', namedCurve: 'P-256' },
    true, ['deriveBits'],
  );
}

/** ECDH 派生共享密钥（256 位） */
async function ecdhDeriveBits(privateKey: CryptoKey, publicKey: CryptoKey): Promise<Uint8Array> {
  const bits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey, 256,
  );
  return new Uint8Array(bits);
}

/** HKDF 派生密钥（256 位） */
async function hkdfDerive(ikm: Uint8Array, info: string): Promise<Uint8Array> {
  const ikmKey = await crypto.subtle.importKey('raw', toBufferSource(ikm), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: toBufferSource(new Uint8Array(0)),
      info: toBufferSource(_encoder.encode(info)),
    },
    ikmKey, 256,
  );
  return new Uint8Array(bits);
}

/** AES-GCM 加密，返回 [ciphertext, tag]（SubtleCrypto 将 tag 附加到末尾） */
async function aesGcmEncrypt(
  key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array,
): Promise<[Uint8Array, Uint8Array]> {
  const aesKey = await crypto.subtle.importKey('raw', toBufferSource(key), 'AES-GCM', false, ['encrypt']);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toBufferSource(nonce), additionalData: toBufferSource(aad), tagLength: 128 },
    aesKey, toBufferSource(plaintext),
  );
  const arr = new Uint8Array(ct);
  // SubtleCrypto 将 16 字节 tag 附加到 ciphertext 末尾
  return [arr.slice(0, -16), arr.slice(-16)];
}

/** AES-GCM 解密 */
async function aesGcmDecrypt(
  key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array, aad: Uint8Array,
): Promise<Uint8Array> {
  const aesKey = await crypto.subtle.importKey('raw', toBufferSource(key), 'AES-GCM', false, ['decrypt']);
  // SubtleCrypto 要求 ciphertext + tag 拼接传入
  const combined = concatBytes(ciphertext, tag);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toBufferSource(nonce), additionalData: toBufferSource(aad), tagLength: 128 },
    aesKey, toBufferSource(combined),
  );
  return new Uint8Array(pt);
}

/** ECDSA 签名（输出 DER 格式，兼容 Python/Go） */
async function ecdsaSignDer(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey, toBufferSource(data),
  );
  // SubtleCrypto 输出 P1363 格式，转换为 DER
  return p1363ToDer(new Uint8Array(sig));
}

/** ECDSA 验签（输入 DER 格式签名） */
async function ecdsaVerifyDer(
  publicKey: CryptoKey, signature: Uint8Array, data: Uint8Array,
): Promise<boolean> {
  // DER → P1363 用于 SubtleCrypto 验签
  const p1363 = derToP1363(signature);
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey, toBufferSource(p1363), toBufferSource(data),
  );
}

/** 生成 12 字节随机 nonce */
function randomNonce(): Uint8Array {
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);
  return nonce;
}

/** 生成 UUID v4 */
function uuidV4(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** 导入 X9.62 未压缩点为 ECDH CryptoKey（用于解密时导入临时公钥） */
async function importUncompressedPointEcdh(pointBytes: Uint8Array): Promise<CryptoKey> {
  // 将未压缩点（0x04 || x || y）包装为 SPKI 格式
  // P-256 SPKI = 固定头 + 未压缩点（65 字节）
  const spkiHeader = new Uint8Array([
    0x30, 0x59, // SEQUENCE (89 bytes)
    0x30, 0x13, // SEQUENCE (19 bytes) - AlgorithmIdentifier
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID: 1.2.840.10045.2.1 (EC)
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID: 1.2.840.10045.3.1.7 (P-256)
    0x03, 0x42, 0x00, // BIT STRING (66 bytes, 0 unused bits)
  ]);
  const spki = concatBytes(spkiHeader, pointBytes);
  return crypto.subtle.importKey(
    'spki', toArrayBuffer(spki),
    { name: 'ECDH', namedCurve: 'P-256' },
    true, [],
  );
}

// ── E2EEManager 主类 ────────────────────────────────────────

/**
 * P2P 端到端加密管理器 — 浏览器 SubtleCrypto 实现。
 *
 * 加密策略: prekey_ecdh_v2（四路 ECDH）→ long_term_key（二路 ECDH）两层降级。
 * I/O（获取 prekey、证书）由调用方（AUNClient）负责。
 * 内置本地防重放（seen set），裸 WebSocket 开发者无需额外实现。
 *
 * 所有密码学操作均为异步（SubtleCrypto 要求）。
 */
export class E2EEManager {
  private _log: ModuleLogger = _noopLog;
  setLogger(log: ModuleLogger): void { this._log = log; }

  private _identityFn: () => IdentityRecord;
  private _deviceIdFn: () => string;
  private _keystoreRef: KeyStore;
  /** 本地防重放 seen set */
  private _seenMessages: Map<string, boolean> = new Map();
  private _seenMaxSize = 50000;
  /** 对方 prekey 内存缓存 {peerAid: {prekey, expireAt}} */
  private _prekeyCache: Map<string, { prekey: PrekeyMaterial; expireAt: number }> = new Map();
  private _prekeyCacheTtl: number;
  /** 本地 prekey 私钥 PEM 内存缓存 {prekeyId: privateKeyPem} */
  private _localPrekeyCache: Map<string, string> = new Map();
  /** 防重放时间窗口（秒） */
  private _replayWindowSeconds: number;

  constructor(opts: {
    identityFn: () => IdentityRecord;
    deviceIdFn?: () => string;
    keystore: KeyStore;
    prekeyCacheTtl?: number;
    replayWindowSeconds?: number;
  }) {
    this._identityFn = opts.identityFn;
    this._deviceIdFn = opts.deviceIdFn ?? (() => '');
    this._keystoreRef = opts.keystore;
    this._prekeyCacheTtl = opts.prekeyCacheTtl ?? 3600;
    this._replayWindowSeconds = opts.replayWindowSeconds ?? 300;
  }

  // ── Prekey 缓存 ──────────────────────────────────

  /** 缓存对方的 prekey */
  cachePrekey(peerAid: string, prekey: PrekeyMaterial): void {
    this._prekeyCache.set(peerAid, {
      prekey,
      expireAt: Date.now() / 1000 + this._prekeyCacheTtl,
    });
  }

  /** 获取缓存的 prekey（过期返回 null） */
  getCachedPrekey(peerAid: string): PrekeyMaterial | null {
    const cached = this._prekeyCache.get(peerAid);
    if (!cached) return null;
    if (Date.now() / 1000 >= cached.expireAt) {
      this._prekeyCache.delete(peerAid);
      return null;
    }
    return cached.prekey;
  }

  /** 使 prekey 缓存失效 */
  invalidatePrekeyCache(peerAid: string): void {
    this._prekeyCache.delete(peerAid);
  }

  // ── 便利方法 ──────────────────────────────────────

  /**
   * 加密消息（便利方法）。
   * 调用方负责提前获取 peerCertPem 和 prekey（可选）。
   */
  async encryptMessage(
    toAid: string,
    payload: JsonObject,
    opts: {
      peerCertPem: string;
      prekey?: PrekeyMaterial | null;
      messageId?: string;
      timestamp?: number;
      protectedHeaders?: ProtectedHeadersInput;
      protected_headers?: ProtectedHeadersInput;
      headers?: ProtectedHeadersInput;
      context?: JsonObject | null;
    },
  ): Promise<[JsonObject, EncryptResult]> {
    const tStart = Date.now();
    this._log.debug(`encryptMessage enter: to_aid=${toAid} has_prekey=${!!opts.prekey}`);
    try {
      const messageId = opts.messageId ?? uuidV4();
      const timestamp = opts.timestamp ?? Date.now();
      const result = await this.encryptOutbound(toAid, payload, {
        peerCertPem: opts.peerCertPem,
        prekey: opts.prekey ?? null,
        messageId,
        timestamp,
        protectedHeaders: opts.protectedHeaders ?? opts.protected_headers ?? opts.headers,
        context: opts.context ?? null,
      });
      this._log.debug(`encryptMessage exit: elapsed=${Date.now() - tStart}ms to_aid=${toAid} mode=${result[1].mode}`);
      return result;
    } catch (err) {
      this._log.debug(`encryptMessage exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  // ── 加密 ──────────────────────────────────────────

  /**
   * 加密出站消息：有 prekey → prekey_ecdh_v2（四路 ECDH），无 prekey → long_term_key。
   *
   * 返回 [envelope, resultInfo]，resultInfo 包含加密状态详情。
   * prekey 传入时自动缓存；传入 null 时自动查缓存。
   */
  async encryptOutbound(
    peerAid: string,
    payload: JsonObject,
    opts: {
      peerCertPem: string;
      prekey?: PrekeyMaterial | null;
      messageId: string;
      timestamp: number;
      protectedHeaders?: ProtectedHeadersInput;
      protected_headers?: ProtectedHeadersInput;
      headers?: ProtectedHeadersInput;
      context?: JsonObject | null;
    },
  ): Promise<[JsonObject, EncryptResult]> {
    const tStart = Date.now();
    this._log.debug(`encryptOutbound enter: peer_aid=${peerAid} mid=${opts.messageId} has_prekey=${!!opts.prekey}`);
    try {
      let prekey = opts.prekey ?? null;

      // 传入 prekey → 缓存；传入 null → 查缓存
      if (prekey !== null) {
        this.cachePrekey(peerAid, prekey);
      } else {
        prekey = this.getCachedPrekey(peerAid);
      }

      if (prekey) {
        try {
          const envelope = await this._encryptWithPrekey(
            peerAid, payload, prekey, opts.peerCertPem,
            opts.messageId, opts.timestamp,
            opts.protectedHeaders ?? opts.protected_headers ?? opts.headers,
            opts.context ?? null,
          );
          this._log.debug(`encryptOutbound exit: elapsed=${Date.now() - tStart}ms peer_aid=${peerAid} mode=prekey_ecdh_v2`);
          return [envelope, {
            encrypted: true,
            forward_secrecy: true,
            mode: MODE_PREKEY_ECDH_V2,
            degraded: false,
          }];
        } catch (exc) {
          this._log.warn('prekey encrypt failed, degrade to long_term_key (no forward secrecy):', exc);
        }
      }

      const envelope = await this._encryptWithLongTermKey(
        peerAid, payload, opts.peerCertPem,
        opts.messageId, opts.timestamp,
        opts.protectedHeaders ?? opts.protected_headers ?? opts.headers,
        opts.context ?? null,
      );
      const degraded = prekey !== null; // 有 prekey 但失败了才算降级
      this._log.debug(`encryptOutbound exit: elapsed=${Date.now() - tStart}ms peer_aid=${peerAid} mode=long_term_key degraded=${degraded}`);
      return [envelope, {
        encrypted: true,
        forward_secrecy: false,
        mode: MODE_LONG_TERM_KEY,
        degraded,
        degradation_reason: degraded ? 'prekey_encrypt_failed' : 'no_prekey_available',
      }];
    } catch (err) {
      this._log.debug(`encryptOutbound exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 使用对方 prekey 加密（prekey_ecdh_v2 模式，四路 ECDH + 发送方签名）
   *
   * 四路 ECDH:
   *   DH1 = ECDH(ephemeral, peer_prekey)
   *   DH2 = ECDH(ephemeral, peer_identity)
   *   DH3 = ECDH(sender_identity, peer_prekey)    ← 绑定发送方身份
   *   DH4 = ECDH(sender_identity, peer_identity)   ← 双方身份互绑
   */
  private async _encryptWithPrekey(
    peerAid: string,
    payload: JsonObject,
    prekey: PrekeyMaterial,
    peerCertPem: string,
    messageId: string,
    timestamp: number,
    protectedHeaders?: ProtectedHeadersInput,
    context?: JsonObject | null,
  ): Promise<JsonObject> {
    // 导入对方 identity 公钥（ECDSA 用于验签，ECDH 用于密钥交换）
    const peerIdentityEcdsa = await importCertPublicKeyEcdsa(peerCertPem);
    const peerIdentityEcdh = await importCertPublicKeyEcdh(peerCertPem);
    const expectedCertFingerprint = String(prekey.cert_fingerprint ?? '').trim().toLowerCase();
    if (expectedCertFingerprint) {
      const actualCertFingerprint = await certificateSha256Fingerprint(peerCertPem);
      if (actualCertFingerprint !== expectedCertFingerprint) {
        throw new E2EEError('prekey cert fingerprint mismatch');
      }
    }

    // 验证 prekey 签名
    const prekeyId = prekey.prekey_id;
    const prekeyPubB64 = prekey.public_key;
    const createdAt = prekey.created_at;

    let signData: Uint8Array;
    if (createdAt !== undefined) {
      signData = _encoder.encode(`${prekeyId}|${prekeyPubB64}|${createdAt}`);
    } else {
      signData = _encoder.encode(`${prekeyId}|${prekeyPubB64}`);
    }

    const sigBytes = base64ToUint8(prekey.signature);
    const sigValid = await ecdsaVerifyDer(peerIdentityEcdsa, sigBytes, signData);
    if (!sigValid) {
      throw new E2EEError('prekey 签名验证失败');
    }

    // 导入对方 prekey 公钥（ECDH）
    const peerPrekeyEcdh = await importSpkiDerB64Ecdh(prekeyPubB64);

    // 加载发送方 identity 私钥
    const senderIdentityEcdhKey = await this._loadSenderIdentityPrivateEcdh();
    const senderSignKey = await this._loadSenderIdentityPrivateEcdsa();

    // 生成临时 ECDH 密钥对
    const ephemeral = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
    );
    // 导出临时公钥为 X9.62 未压缩点
    const ephRaw = await crypto.subtle.exportKey('raw', ephemeral.publicKey);
    const ephPublicBytes = new Uint8Array(ephRaw);

    // 四路 ECDH
    const dh1 = await ecdhDeriveBits(ephemeral.privateKey, peerPrekeyEcdh);
    const dh2 = await ecdhDeriveBits(ephemeral.privateKey, peerIdentityEcdh);
    const dh3 = await ecdhDeriveBits(senderIdentityEcdhKey, peerPrekeyEcdh);
    const dh4 = await ecdhDeriveBits(senderIdentityEcdhKey, peerIdentityEcdh);
    const combined = concatBytes(dh1, dh2, dh3, dh4);

    // HKDF
    const messageKey = await hkdfDerive(combined, `aun-prekey-v2:${prekeyId}`);

    // AES-GCM 加密
    const plaintext = _encoder.encode(JSON.stringify(payload));
    const nonce = randomNonce();

    const senderFingerprint = await this._localCertSha256Fingerprint() || await this._localIdentityFingerprint();
    const recipientFingerprint = await fingerprintCertPem(peerCertPem);
    const ephPkB64 = uint8ToBase64(ephPublicBytes);

    const aad: JsonObject = {
      from: this._currentAid(),
      to: peerAid,
      message_id: messageId,
      timestamp,
      encryption_mode: MODE_PREKEY_ECDH_V2,
      suite: SUITE,
      ephemeral_public_key: ephPkB64,
      recipient_cert_fingerprint: recipientFingerprint,
      sender_cert_fingerprint: senderFingerprint,
      prekey_id: prekeyId,
    };
    const envelope: JsonObject = {
      type: 'e2ee.encrypted',
      version: '1',
      encryption_mode: MODE_PREKEY_ECDH_V2,
      suite: SUITE,
      prekey_id: prekeyId,
      ephemeral_public_key: ephPkB64,
    };
    await copyOptionalEnvelopeMetadata(envelope, messageKey, {
      payloadType: payload.type,
      protectedHeaders,
      context,
    });
    const aadBytes = aadBytesOffline(aad);
    const [ciphertext, tag] = await aesGcmEncrypt(messageKey, nonce, plaintext, aadBytes);

    envelope.nonce = uint8ToBase64(nonce);
    envelope.ciphertext = uint8ToBase64(ciphertext);
    envelope.tag = uint8ToBase64(tag);
    envelope.aad = aad;

    // 发送方签名：对 ciphertext + tag + aad_bytes 签名（不可否认性）
    const signPayload = concatBytes(ciphertext, tag, aadBytes);
    const sig = await ecdsaSignDer(senderSignKey, signPayload);
    envelope.sender_signature = uint8ToBase64(sig);
    envelope.sender_cert_fingerprint = senderFingerprint;
    return envelope;
  }

  /**
   * 使用 2DH 加密（long_term_key 模式 + 发送方签名）
   *
   * 2DH:
   *   DH1 = ECDH(ephemeral, peer_identity)     ← 前向保密（每消息）
   *   DH2 = ECDH(sender_identity, peer_identity) ← 绑定双方身份
   */
  private async _encryptWithLongTermKey(
    peerAid: string,
    payload: JsonObject,
    peerCertPem: string,
    messageId: string,
    timestamp: number,
    protectedHeaders?: ProtectedHeadersInput,
    context?: JsonObject | null,
  ): Promise<JsonObject> {
    const peerIdentityEcdh = await importCertPublicKeyEcdh(peerCertPem);
    const senderIdentityEcdhKey = await this._loadSenderIdentityPrivateEcdh();
    const senderSignKey = await this._loadSenderIdentityPrivateEcdsa();

    // 生成临时 ECDH 密钥对
    const ephemeral = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
    );
    const ephRaw = await crypto.subtle.exportKey('raw', ephemeral.publicKey);
    const ephPublicBytes = new Uint8Array(ephRaw);

    // 2DH + HKDF
    const dh1 = await ecdhDeriveBits(ephemeral.privateKey, peerIdentityEcdh);
    const dh2 = await ecdhDeriveBits(senderIdentityEcdhKey, peerIdentityEcdh);
    const combined = concatBytes(dh1, dh2);
    const messageKey = await hkdfDerive(combined, 'aun-longterm-v2');

    // AES-GCM 加密
    const plaintext = _encoder.encode(JSON.stringify(payload));
    const nonce = randomNonce();

    const senderFingerprint = await this._localCertSha256Fingerprint() || await this._localIdentityFingerprint();
    const recipientFingerprint = await fingerprintCertPem(peerCertPem);
    const ephPkB64 = uint8ToBase64(ephPublicBytes);

    const aad: JsonObject = {
      from: this._currentAid(),
      to: peerAid,
      message_id: messageId,
      timestamp,
      encryption_mode: MODE_LONG_TERM_KEY,
      suite: SUITE,
      ephemeral_public_key: ephPkB64,
      recipient_cert_fingerprint: recipientFingerprint,
      sender_cert_fingerprint: senderFingerprint,
    };
    const envelope: JsonObject = {
      type: 'e2ee.encrypted',
      version: '1',
      encryption_mode: MODE_LONG_TERM_KEY,
      suite: SUITE,
      ephemeral_public_key: ephPkB64,
    };
    await copyOptionalEnvelopeMetadata(envelope, messageKey, {
      payloadType: payload.type,
      protectedHeaders,
      context,
    });
    const aadBytes = aadBytesOffline(aad);
    const [ciphertext, tag] = await aesGcmEncrypt(messageKey, nonce, plaintext, aadBytes);

    envelope.nonce = uint8ToBase64(nonce);
    envelope.ciphertext = uint8ToBase64(ciphertext);
    envelope.tag = uint8ToBase64(tag);
    envelope.aad = aad;

    // 发送方签名（不可否认性）
    const signPayload = concatBytes(ciphertext, tag, aadBytes);
    const sig = await ecdsaSignDer(senderSignKey, signPayload);
    envelope.sender_signature = uint8ToBase64(sig);
    envelope.sender_cert_fingerprint = senderFingerprint;
    return envelope;
  }

  // ── 解密 ──────────────────────────────────────────

  /**
   * 解密单条消息（内置本地防重放 + timestamp 窗口 + 发送方签名验证）。
   *
   * 返回解密后的 message 对象，或 null 表示失败/拒绝。
   * 非加密消息原样返回。
   *
   * opts.skipReplay: 跳过防重放和 timestamp 窗口检查（用于 message.pull 场景）。
   */
  async decryptMessage(
    message: Message,
    opts?: { skipReplay?: boolean },
  ): Promise<Message | null> {
    const tStart = Date.now();
    const mid = String(message.message_id ?? '');
    const fromAid = String(message.from ?? '');
    this._log.debug(`decryptMessage enter: from=${fromAid} mid=${mid} skip_replay=${!!opts?.skipReplay}`);
    try {
      const payload = message.payload as JsonObject | undefined;
      if (!payload || typeof payload !== 'object') {
        this._log.debug(`decryptMessage exit: elapsed=${Date.now() - tStart}ms result=passthrough_no_payload`);
        return message;
      }
      if (payload.type !== 'e2ee.encrypted') {
        this._log.debug(`decryptMessage exit: elapsed=${Date.now() - tStart}ms result=passthrough_not_encrypted`);
        return message;
      }
      if (message.encrypted === false) {
        this._log.debug(`decryptMessage exit: elapsed=${Date.now() - tStart}ms result=passthrough_flag_false`);
        return message;
      }
      if (!this._shouldDecryptForCurrentAid(message, payload)) {
        this._log.debug(`decryptMessage exit: elapsed=${Date.now() - tStart}ms result=passthrough_not_for_current_aid`);
        return message;
      }

      const skipReplay = opts?.skipReplay ?? false;

      if (!skipReplay) {
        // timestamp 窗口检查
        const ts = (message.timestamp ?? (payload.aad as JsonObject | undefined)?.timestamp) as number | undefined;
        if (typeof ts === 'number' && this._replayWindowSeconds > 0) {
          const nowMs = Date.now();
          const diffS = Math.abs(nowMs - ts) / 1000;
          if (diffS > this._replayWindowSeconds) {
            this._log.warn(
              `消息 timestamp 超出窗口 (${Math.round(diffS)}s > ${this._replayWindowSeconds}s)，拒绝: from=${message.from} mid=${message.message_id}`,
            );
            this._log.debug(`decryptMessage exit: elapsed=${Date.now() - tStart}ms result=rejected_timestamp_window`);
            return null;
          }
        }

        // 本地防重放：先检查，解密成功后再记录。
        const messageIdVal = message.message_id as string | undefined;
        const fromAidLocal = message.from as string | undefined;
        let seenKey = '';
        if (messageIdVal && fromAidLocal) {
          seenKey = `${fromAidLocal}:${messageIdVal}`;
          if (this._seenMessages.has(seenKey)) {
            this._log.debug(`decryptMessage exit: elapsed=${Date.now() - tStart}ms result=rejected_replay`);
            return null;
          }
        }
        const result = await this._decryptMessageInternal(message);
        if (result !== null && seenKey) {
          this._seenMessages.set(seenKey, true);
          this._trimSeenSet();
        }
        this._log.debug(`decryptMessage exit: elapsed=${Date.now() - tStart}ms result=${result !== null ? 'ok' : 'failed'}`);
        return result;
      }

      const result = await this._decryptMessageInternal(message);
      this._log.debug(`decryptMessage exit: elapsed=${Date.now() - tStart}ms result=${result !== null ? 'ok' : 'failed'} skip_replay=true`);
      return result;
    } catch (err) {
      this._log.debug(`decryptMessage exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 判断是否应该为当前 AID 解密（避免发送端回显消息误走解密） */
  private _shouldDecryptForCurrentAid(
    message: Message,
    payload: JsonObject,
  ): boolean {
    if (String(message.direction ?? '').trim().toLowerCase() === 'outbound_sync') {
      return true;
    }
    const currentAid = this._currentAid();
    if (!currentAid) return true;
    const targetAid = (
      message.to
      ?? (payload.aad as JsonObject | undefined)?.to
      ?? payload.to
    ) as string | undefined;
    if (!targetAid) return true;
    return String(targetAid) === String(currentAid);
  }

  /** 内部解密分发 */
  private async _decryptMessageInternal(
    message: Message,
  ): Promise<Message | null> {
    const payload = message.payload as JsonObject;

    // 验证发送方签名（适用于所有模式）
    try {
      await this._verifySenderSignature(payload, message);
    } catch (exc) {
      this._log.warn('sendersignature verifyfailed:', exc);
      return null;
    }

    const encryptionMode = payload.encryption_mode as string;
    if (encryptionMode === MODE_PREKEY_ECDH_V2) {
      return this._decryptMessagePrekeyV2(message);
    } else if (encryptionMode === MODE_LONG_TERM_KEY) {
      return this._decryptMessageLongTerm(message);
    } else {
      this._log.warn('unsupported encryption mode:', encryptionMode);
      return null;
    }
  }

  /** 验证发送方签名 */
  private async _verifySenderSignature(
    payload: JsonObject,
    message: Message,
  ): Promise<void> {
    const senderSigB64 = payload.sender_signature as string | undefined;
    if (!senderSigB64) {
      throw new E2EEDecryptFailedError('sender_signature missing: 拒绝无发送方签名的消息');
    }

    // 获取发送方公钥
    const fromAid = (message.from ?? (payload.aad as JsonObject | undefined)?.from) as string;
    if (!fromAid) throw new E2EEDecryptFailedError('from_aid missing in message');

    const senderCertFingerprint = String(
      payload.sender_cert_fingerprint ?? (payload.aad as JsonObject | undefined)?.sender_cert_fingerprint ?? '',
    ).trim().toLowerCase();
    const senderCertPem = await this._getSenderCert(fromAid, senderCertFingerprint || undefined);
    if (!senderCertPem) throw new E2EEDecryptFailedError(`sender cert not found for ${fromAid}`);

    const senderPubKey = await importCertPublicKeyEcdsa(senderCertPem);

    // 重建签名载荷
    const ciphertext = base64ToUint8(payload.ciphertext as string);
    const tag = base64ToUint8(payload.tag as string);
    const aad = payload.aad as JsonObject | undefined;
    const aadBytes = aad ? aadBytesOffline(aad) : new Uint8Array(0);
    const signPayload = concatBytes(ciphertext, tag, aadBytes);

    const sigBytes = base64ToUint8(senderSigB64);
    const valid = await ecdsaVerifyDer(senderPubKey, sigBytes, signPayload);
    if (!valid) {
      throw new E2EEDecryptFailedError('sender signature verification failed');
    }
  }

  /** 从 keystore 获取发送方证书 PEM */
  private async _getSenderCert(aid: string, certFingerprint?: string): Promise<string | null> {
    const certPem = await this._keystoreRef.loadCert(aid, certFingerprint);
    const normalized = String(certFingerprint ?? '').trim().toLowerCase();
    if (!certPem) return null;
    if (!normalized) return certPem;
    const actualFingerprint = await certificateSha256Fingerprint(certPem);
    return actualFingerprint === normalized ? certPem : null;
  }

  /** 解密 prekey_ecdh_v2 模式的消息（四路 ECDH） */
  private async _decryptMessagePrekeyV2(
    message: Message,
  ): Promise<Message | null> {
    const payload = message.payload as JsonObject;
    try {
      const ephPublicBytes = base64ToUint8(payload.ephemeral_public_key as string);
      const prekeyId = (payload.prekey_id ?? '') as string;
      const nonce = base64ToUint8(payload.nonce as string);
      const ciphertext = base64ToUint8(payload.ciphertext as string);
      const tag = base64ToUint8(payload.tag as string);

      // 加载 prekey 私钥
      const prekeyPrivatePem = await this._loadPrekeyPrivateKey(prekeyId);
      if (!prekeyPrivatePem) throw new E2EEError(`prekey not found: ${prekeyId}`);
      const prekeyPrivateEcdh = await importPrivateKeyEcdh(prekeyPrivatePem);

      // 加载接收方 identity 私钥
      const myAid = this._currentAid();
      if (!myAid) throw new E2EEError('AID unavailable');
      const keyPair = await this._keystoreRef.loadKeyPair(myAid);
      if (!keyPair || !keyPair.private_key_pem) throw new E2EEError('Identity private key not found');
      const myIdentityEcdh = await importPrivateKeyEcdh(keyPair.private_key_pem as string);

      // 获取发送方公钥（四路 ECDH 需要）
      const fromAid = (message.from ?? (payload.aad as JsonObject | undefined)?.from) as string;
      const senderCertFingerprint = String(
        payload.sender_cert_fingerprint ?? (payload.aad as JsonObject | undefined)?.sender_cert_fingerprint ?? '',
      ).trim().toLowerCase();
      const senderCertPem = await this._getSenderCert(fromAid, senderCertFingerprint || undefined);
      if (!senderCertPem) throw new E2EEError(`sender public key not found for ${fromAid}`);
      const senderPubEcdh = await importCertPublicKeyEcdh(senderCertPem);

      // 导入临时公钥
      const ephPubKey = await importUncompressedPointEcdh(ephPublicBytes);

      // 四路 ECDH + HKDF（接收方视角：prekey 和 identity 角色互换）
      const dh1 = await ecdhDeriveBits(prekeyPrivateEcdh, ephPubKey);
      const dh2 = await ecdhDeriveBits(myIdentityEcdh, ephPubKey);
      const dh3 = await ecdhDeriveBits(prekeyPrivateEcdh, senderPubEcdh);
      const dh4 = await ecdhDeriveBits(myIdentityEcdh, senderPubEcdh);
      const combined = concatBytes(dh1, dh2, dh3, dh4);
      const messageKey = await hkdfDerive(combined, `aun-prekey-v2:${prekeyId}`);

      // 验证 AAD 并解密
      const aad = payload.aad as JsonObject | undefined;
      let aadBytes: Uint8Array;
      if (aad) {
        const expectedAad = this._buildInboundAadOffline(message, payload);
        if (!aadMatchesOffline(expectedAad, aad)) {
          throw new E2EEDecryptFailedError('aad mismatch');
        }
        aadBytes = aadBytesOffline(aad);
      } else {
        aadBytes = new Uint8Array(0);
      }
      if (!await verifyEnvelopeMetadataAuth(payload, messageKey)) {
        throw new E2EEDecryptFailedError('envelope metadata auth failed');
      }
      const plaintext = await aesGcmDecrypt(messageKey, nonce, ciphertext, tag, aadBytes);

      const decoded = JSON.parse(_decoder.decode(plaintext));
      if (!validateDecryptedEnvelopeMetadata(decoded, payload, message)) {
        throw new E2EEDecryptFailedError('envelope metadata mismatch');
      }
      const e2ee: JsonObject = {
        encryption_mode: MODE_PREKEY_ECDH_V2,
        suite: (payload.suite as string) ?? SUITE,
        prekey_id: prekeyId,
      };
      const protectedHeaders = exposedEnvelopeMetadata(payload.protected_headers);
      if (protectedHeaders) e2ee.protected_headers = protectedHeaders;
      const context = exposedEnvelopeMetadata(payload.context);
      if (context) e2ee.context = context;
      return {
        ...message,
        payload: decoded,
        encrypted: true,
        e2ee,
      };
    } catch (exc) {
      if (exc instanceof E2EEError) {
        this._log.warn('prekey_ecdh_v2 decryptfailed (E2EE):', exc);
      } else {
        this._log.warn('prekey_ecdh_v2 decryptfailed:', exc);
      }
      return null;
    }
  }

  /** 解密 long_term_key 模式的消息（2DH） */
  private async _decryptMessageLongTerm(
    message: Message,
  ): Promise<Message | null> {
    const payload = message.payload as JsonObject;
    try {
      const ephPublicBytes = base64ToUint8(payload.ephemeral_public_key as string);
      const nonce = base64ToUint8(payload.nonce as string);
      const ciphertext = base64ToUint8(payload.ciphertext as string);
      const tag = base64ToUint8(payload.tag as string);

      // 加载接收方 identity 私钥
      const myAid = this._currentAid();
      if (!myAid) throw new E2EEError('AID unavailable');
      const keyPair = await this._keystoreRef.loadKeyPair(myAid);
      if (!keyPair || !keyPair.private_key_pem) throw new E2EEError('Private key not found');
      const myIdentityEcdh = await importPrivateKeyEcdh(keyPair.private_key_pem as string);

      // 获取发送方公钥（2DH 需要）
      const fromAid = (message.from ?? (payload.aad as JsonObject | undefined)?.from) as string;
      const senderCertFingerprint = String(
        payload.sender_cert_fingerprint ?? (payload.aad as JsonObject | undefined)?.sender_cert_fingerprint ?? '',
      ).trim().toLowerCase();
      const senderCertPem = await this._getSenderCert(fromAid, senderCertFingerprint || undefined);
      if (!senderCertPem) throw new E2EEError(`sender public key not found for ${fromAid}`);
      const senderPubEcdh = await importCertPublicKeyEcdh(senderCertPem);

      // 导入临时公钥
      const ephPubKey = await importUncompressedPointEcdh(ephPublicBytes);

      // 2DH + HKDF
      const dh1 = await ecdhDeriveBits(myIdentityEcdh, ephPubKey);
      const dh2 = await ecdhDeriveBits(myIdentityEcdh, senderPubEcdh);
      const combined = concatBytes(dh1, dh2);
      const messageKey = await hkdfDerive(combined, 'aun-longterm-v2');

      // 验证 AAD 并解密
      const aad = payload.aad as JsonObject | undefined;
      let aadBytes: Uint8Array;
      if (aad) {
        const expectedAad = this._buildInboundAadOffline(message, payload);
        if (!aadMatchesOffline(expectedAad, aad)) {
          throw new E2EEDecryptFailedError('aad mismatch');
        }
        aadBytes = aadBytesOffline(aad);
      } else {
        aadBytes = new Uint8Array(0);
      }
      if (!await verifyEnvelopeMetadataAuth(payload, messageKey)) {
        throw new E2EEDecryptFailedError('envelope metadata auth failed');
      }
      const plaintext = await aesGcmDecrypt(messageKey, nonce, ciphertext, tag, aadBytes);

      const decoded = JSON.parse(_decoder.decode(plaintext));
      if (!validateDecryptedEnvelopeMetadata(decoded, payload, message)) {
        throw new E2EEDecryptFailedError('envelope metadata mismatch');
      }
      const e2ee: JsonObject = {
        encryption_mode: MODE_LONG_TERM_KEY,
        suite: payload.suite as string,
      };
      const protectedHeaders = exposedEnvelopeMetadata(payload.protected_headers);
      if (protectedHeaders) e2ee.protected_headers = protectedHeaders;
      const context = exposedEnvelopeMetadata(payload.context);
      if (context) e2ee.context = context;
      return {
        ...message,
        payload: decoded,
        encrypted: true,
        e2ee,
      };
    } catch (exc) {
      if (exc instanceof E2EEError) {
        this._log.warn('long_term_key decryptfailed (E2EE):', exc);
      } else {
        this._log.warn('long_term_key decryptfailed:', exc);
      }
      return null;
    }
  }

  // ── AAD 工具 ─────────────────────────────────────

  /** 构建解密时的期望 AAD（接收方视角） */
  private _buildInboundAadOffline(
    message: Message,
    payload: JsonObject,
  ): JsonObject {
    const aad = payload.aad as JsonObject | undefined;
    return {
      from: message.from,
      to: message.to,
      message_id: message.message_id,
      timestamp: message.timestamp,
      encryption_mode: payload.encryption_mode,
      suite: (payload.suite as string) ?? SUITE,
      ephemeral_public_key: payload.ephemeral_public_key,
      recipient_cert_fingerprint: aad?.recipient_cert_fingerprint,
      sender_cert_fingerprint: payload.sender_cert_fingerprint ?? aad?.sender_cert_fingerprint,
      prekey_id: payload.prekey_id ?? aad?.prekey_id,
    };
  }

  // ── Prekey 生成 ──────────────────────────────────

  /**
   * 生成 prekey 材料并保存私钥到本地 keystore。
   *
   * 返回 { prekey_id, public_key, signature, created_at }，可直接用于 RPC 上传。
   */
  async generatePrekey(): Promise<PrekeyMaterial> {
    const tStart = Date.now();
    this._log.debug('generatePrekey enter');
    try {
      const aid = this._currentAid();
      if (!aid) throw new E2EEError('AID unavailable for prekey generation');
      const deviceId = this._currentDeviceId();

      // 生成新 ECDH 密钥对（标记为 ECDH 用途）
      const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
      );

      // 导出 SPKI 公钥（DER 格式）
      const spki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
      const publicKeyB64 = uint8ToBase64(new Uint8Array(spki));

      // 导出 PKCS8 私钥（PEM 格式存储）
      const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
      const privateKeyPem = arrayBufferToPemLocal(pkcs8, 'PRIVATE KEY');

      const prekeyId = uuidV4();
      const nowMs = Date.now();

      // 签名：prekey_id|public_key|created_at（绑定时间戳，防止旧 prekey 重放）
      const signData = _encoder.encode(`${prekeyId}|${publicKeyB64}|${nowMs}`);
      const senderSignKey = await this._loadSenderIdentityPrivateEcdsa();
      const sig = await ecdsaSignDer(senderSignKey, signData);
      const signatureB64 = uint8ToBase64(sig);

      await saveKeyStorePrekey(this._keystoreRef, aid, deviceId, prekeyId, {
        private_key_pem: privateKeyPem,
        created_at: nowMs,
        updated_at: nowMs,
      });

      // 内存缓存私钥 PEM
      this._localPrekeyCache.set(prekeyId, privateKeyPem);

      // 清理过期的旧 prekey
      await this._cleanupExpiredPrekeys(aid, deviceId);

      const result: PrekeyMaterial = {
        prekey_id: prekeyId,
        public_key: publicKeyB64,
        signature: signatureB64,
        created_at: nowMs,
      };
      const certFingerprint = await this._localCertSha256Fingerprint();
      if (certFingerprint) {
        result.cert_fingerprint = certFingerprint;
      }
      if (deviceId) {
        result.device_id = deviceId;
      }
      this._log.debug(`generatePrekey exit: elapsed=${Date.now() - tStart}ms aid=${aid} prekey_id=${prekeyId}`);
      return result;
    } catch (err) {
      this._log.debug(`generatePrekey exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 清理过期的本地 prekey 私钥 */
  private async _cleanupExpiredPrekeys(aid: string, deviceId: string): Promise<void> {
    const nowMs = Date.now();
    const cutoffMs = nowMs - PREKEY_RETENTION_SECONDS * 1000;
    const expired = await cleanupKeyStorePrekeys(this._keystoreRef, aid, deviceId, cutoffMs, PREKEY_MIN_KEEP_COUNT);
    if (expired.length > 0) {
      for (const pid of expired) {
        this._localPrekeyCache.delete(pid);
      }
    }
  }

  /** 从内存缓存或 keystore 加载 prekey 私钥 PEM */
  private async _loadPrekeyPrivateKey(prekeyId: string): Promise<string | null> {
    // 优先从内存缓存获取
    const cached = this._localPrekeyCache.get(prekeyId);
    if (cached) return cached;

    const aid = this._currentAid();
    if (!aid) return null;

    // 优先按 prekey_id 单点查询（IndexedDB 主键直查 O(log N)）。
    // 旧路径需要全量加载 prekey 池（prekey 数量大时是性能瓶颈），单查能直接命中信封里的目标 prekey。
    const byIdLoader = (this._keystoreRef as { loadE2EEPrekeyById?: (aid: string, prekeyId: string) => Promise<Record<string, unknown> | null> }).loadE2EEPrekeyById;
    if (typeof byIdLoader === 'function') {
      try {
        const byIdData = await byIdLoader.call(this._keystoreRef, aid, prekeyId);
        if (byIdData) {
          const pem = (byIdData as { private_key_pem?: unknown }).private_key_pem;
          if (typeof pem === 'string' && pem) {
            this._log.debug(`prekey ${prekeyId} by_id lookup hit`);
            this._localPrekeyCache.set(prekeyId, pem);
            return pem;
          }
        }
      } catch (err) {
        this._log.warn(`prekey ${prekeyId} by_id loader failed, falling back to full load: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    // 回退：旧版 keystore 没有 by_id 方法，或单查未命中 → 全量扫描（保持向后兼容）。
    const prekeys = await loadKeyStorePrekeys(this._keystoreRef, aid, this._currentDeviceId());
    const prekeyData = prekeys[prekeyId];
    if (!prekeyData) return null;
    const pem = prekeyData.private_key_pem as string | undefined;
    if (!pem) return null;

    // 回填内存缓存
    this._localPrekeyCache.set(prekeyId, pem);
    return pem;
  }

  // ── 内部工具 ──────────────────────────────────────

  private _currentAid(): string | null {
    const identity = this._identityFn();
    const aid = identity.aid;
    return typeof aid === 'string' ? aid : null;
  }

  private _currentDeviceId(): string {
    try {
      return String(this._deviceIdFn() ?? '').trim();
    } catch {
      return '';
    }
  }

  /** 加载发送方 identity 私钥（ECDH 用途） */
  private async _loadSenderIdentityPrivateEcdh(): Promise<CryptoKey> {
    const identity = this._identityFn();
    const pem = identity.private_key_pem as string | undefined;
    if (!pem) throw new E2EEError('sender identity private key unavailable');
    return importPrivateKeyEcdh(pem);
  }

  /** 加载发送方 identity 私钥（ECDSA 签名用途） */
  private async _loadSenderIdentityPrivateEcdsa(): Promise<CryptoKey> {
    const identity = this._identityFn();
    const pem = identity.private_key_pem as string | undefined;
    if (!pem) throw new E2EEError('sender identity private key unavailable');
    return importPrivateKeyEcdsa(pem);
  }

  /** 获取本地 identity 指纹（优先证书 DER SHA-256，缺失时回退到公钥指纹） */
  private async _localIdentityFingerprint(): Promise<string> {
    const identity = this._identityFn();
    // 优先用证书指纹（与 PKI 一致）
    const certPem = identity.cert as string | undefined;
    if (certPem) return fingerprintCertPem(certPem);
    // 无证书时回退到公钥 SPKI 指纹
    const pubDerB64 = identity.public_key_der_b64 as string | undefined;
    if (pubDerB64) return fingerprintDerB64(pubDerB64);
    // 从私钥导出公钥的 SPKI 指纹
    const pem = identity.private_key_pem as string | undefined;
    if (pem) {
      const pk = await crypto.subtle.importKey(
        'pkcs8', pemToArrayBuffer(pem),
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'],
      );
      const jwk = await crypto.subtle.exportKey('jwk', pk);
      const pubJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
      const pubKey = await crypto.subtle.importKey(
        'jwk', pubJwk,
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'],
      );
      const spki = await crypto.subtle.exportKey('spki', pubKey);
      return fingerprintSpki(spki);
    }
    throw new E2EEError('identity fingerprint unavailable');
  }

  /** 本地证书的 SHA-256 指纹（用于锁定证书版本） */
  private async _localCertSha256Fingerprint(): Promise<string> {
    const identity = this._identityFn();
    const certPem = identity.cert as string | undefined;
    if (!certPem) return '';
    return certificateSha256Fingerprint(certPem);
  }

  /** 裁剪 seen set */
  private _trimSeenSet(): void {
    if (this._seenMessages.size > this._seenMaxSize) {
      const trimCount = this._seenMessages.size - Math.floor(this._seenMaxSize * 0.8);
      const keys = [...this._seenMessages.keys()].slice(0, trimCount);
      for (const k of keys) {
        this._seenMessages.delete(k);
      }
    }
  }

  /** 清理过期的 prekey 缓存和 seen set 条目（供外部定时调用） */
  cleanExpiredCaches(): void {
    const now = Date.now() / 1000;
    // 清理过期的 prekey 缓存
    for (const [k, v] of this._prekeyCache) {
      if (now >= v.expireAt) this._prekeyCache.delete(k);
    }
    // 清理 seen set（LRU 裁剪）
    this._trimSeenSet();
  }
}

// ── 内部工具函数（PEM 生成） ────────────────────────────────

/** 将 ArrayBuffer 转为 PEM 格式（本地版本，避免循环依赖） */
function arrayBufferToPemLocal(buffer: ArrayBuffer, label: string): string {
  const b64 = uint8ToBase64(new Uint8Array(buffer));
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

// ── 导出额外工具（供 e2ee-group.ts 使用）──────────────────

export {
  aadBytesOffline as _aadBytesOffline,
  concatBytes as _concatBytes,
  ecdsaSignDer as _ecdsaSignDer,
  ecdsaVerifyDer as _ecdsaVerifyDer,
  hkdfDerive as _hkdfDerive,
  aesGcmEncrypt as _aesGcmEncrypt,
  aesGcmDecrypt as _aesGcmDecrypt,
  randomNonce as _randomNonce,
  uuidV4 as _uuidV4,
  fingerprintCertPem as _fingerprintCertPem,
  certificateSha256Fingerprint as _certificateSha256Fingerprint,
  fingerprintSpki as _fingerprintSpki,
  importCertPublicKeyEcdsa as _importCertPublicKeyEcdsa,
  importPrivateKeyEcdsa as _importPrivateKeyEcdsa,
  derToP1363 as _derToP1363,
};
