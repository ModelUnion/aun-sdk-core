/**
 * E2EEManager — 端到端加密管理器
 *
 * 加密策略：prekey_ecdh_v2（四路 ECDH）→ long_term_key（二路 ECDH）两层降级。
 * I/O（获取 prekey、证书）由调用方（AUNClient）负责。
 * 内置本地防重放（seen set），裸 WebSocket 开发者无需额外实现。
 */

import * as crypto from 'node:crypto';
import type { KeyStore } from './keystore/index.js';

import { E2EEError, E2EEDecryptFailedError } from './errors.js';
import type { IdentityRecord, JsonObject, Message, PrekeyRecord } from './types.js';

// ── 常量 ───────────────────────────────────────────────────────

export const SUITE = 'P256_HKDF_SHA256_AES_256_GCM';

/** 四路 ECDH：prekey + identity */
export const MODE_PREKEY_ECDH_V2 = 'prekey_ecdh_v2';
/** 降级：长期公钥加密 */
export const MODE_LONG_TERM_KEY = 'long_term_key';

/** 离线消息 AAD 字段 */
export const AAD_FIELDS_OFFLINE: readonly string[] = [
  'from', 'to', 'message_id', 'timestamp',
  'encryption_mode', 'suite', 'ephemeral_public_key',
  'recipient_cert_fingerprint', 'sender_cert_fingerprint',
  'prekey_id',
] as const;

/** 离线消息 AAD 匹配字段（不含 timestamp） */
export const AAD_MATCH_FIELDS_OFFLINE: readonly string[] = [
  'from', 'to', 'message_id',
  'encryption_mode', 'suite', 'ephemeral_public_key',
  'recipient_cert_fingerprint', 'sender_cert_fingerprint',
  'prekey_id',
] as const;

/** prekey 私钥本地保留时间（秒）— 7 天 */
const PREKEY_RETENTION_SECONDS = 7 * 24 * 3600;
const PREKEY_MIN_KEEP_COUNT = 7;

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

function loadKeyStorePrekeys(
  keystore: KeyStore,
  aid: string,
  deviceId = '',
): LocalPrekeyStore {
  const normalizedDeviceId = String(deviceId ?? '').trim();
  if (normalizedDeviceId && typeof keystore.loadE2EEPrekeysForDevice === 'function') {
    return (keystore.loadE2EEPrekeysForDevice(aid, normalizedDeviceId) ?? {}) as LocalPrekeyStore;
  }
  if (typeof keystore.loadE2EEPrekeys === 'function') {
    return (keystore.loadE2EEPrekeys(aid) ?? {}) as LocalPrekeyStore;
  }
  throw new Error('keystore 缺少 loadE2EEPrekeys 方法');
}

function saveKeyStorePrekey(
  keystore: KeyStore,
  aid: string,
  deviceId: string,
  prekeyId: string,
  prekeyData: LocalPrekeyRecord,
): void {
  const normalizedDeviceId = String(deviceId ?? '').trim();
  if (normalizedDeviceId && typeof keystore.saveE2EEPrekeyForDevice === 'function') {
    keystore.saveE2EEPrekeyForDevice(aid, normalizedDeviceId, prekeyId, prekeyData);
    return;
  }
  if (typeof keystore.saveE2EEPrekey === 'function') {
    keystore.saveE2EEPrekey(aid, prekeyId, prekeyData);
    return;
  }
  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} missing saveE2EEPrekey method`);
}

function cleanupKeyStorePrekeys(
  keystore: KeyStore,
  aid: string,
  deviceId: string,
  cutoffMs: number,
  keepLatest = PREKEY_MIN_KEEP_COUNT,
): string[] {
  const normalizedDeviceId = String(deviceId ?? '').trim();
  if (normalizedDeviceId && typeof keystore.cleanupE2EEPrekeysForDevice === 'function') {
    return keystore.cleanupE2EEPrekeysForDevice(aid, normalizedDeviceId, cutoffMs, keepLatest) ?? [];
  }
  if (typeof keystore.cleanupE2EEPrekeys === 'function') {
    return keystore.cleanupE2EEPrekeys(aid, cutoffMs, keepLatest) ?? [];
  }

  throw new Error(`keystore ${keystore.constructor?.name ?? 'unknown'} missing cleanupE2EEPrekeys method`);
}

// ── 工具函数 ───────────────────────────────────────────────────

/** 将 PEM 证书/公钥转为 KeyObject */
function pemToCertPublicKey(certPem: string | Buffer): crypto.KeyObject {
  const pem = typeof certPem === 'string' ? certPem : certPem.toString('utf-8');
  try {
    const x509 = new crypto.X509Certificate(pem);
    return x509.publicKey;
  } catch {
    return crypto.createPublicKey(pem);
  }
}

/** ECDH 共享密钥计算 */
function ecdhShared(privateKey: crypto.KeyObject, publicKey: crypto.KeyObject): Buffer {
  return crypto.diffieHellman({ privateKey, publicKey });
}

/** HKDF-SHA256 派生密钥 */
function hkdfDeriveSync(ikm: Buffer, info: Buffer, length: number): Buffer {
  // Node.js crypto.hkdfSync 在 v16+ 可用
  const derived = crypto.hkdfSync('sha256', ikm, Buffer.alloc(0), info, length);
  return Buffer.from(derived);
}

/** AES-256-GCM 加密，返回 {ciphertext, tag, nonce} */
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

/** 生成 ECDSA P-256 密钥对 */
function generateECKeyPair(): { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject } {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

/** 公钥 → DER SPKI 指纹 */
function fingerprintPublicKeyDer(derBytes: Buffer): string {
  const hash = crypto.createHash('sha256').update(derBytes).digest();
  return `sha256:${hash.toString('hex')}`;
}

/** KeyObject 公钥 → 指纹 */
function fingerprintKeyObject(pubKey: crypto.KeyObject): string {
  const der = pubKey.export({ type: 'spki', format: 'der' });
  return fingerprintPublicKeyDer(der as Buffer);
}

/** PEM 证书 → 证书 SHA-256 指纹 */
function fingerprintCertPem(certPem: string | Buffer): string {
  return certificateSha256Fingerprint(certPem);
}

/** PEM/DER 证书 → DER 字节 */
function certToDerBytes(certPem: string | Buffer): Buffer {
  const raw = Buffer.isBuffer(certPem) ? Buffer.from(certPem) : Buffer.from(certPem, 'utf-8');
  const text = raw.toString('utf-8');
  if (text.includes('-----BEGIN CERTIFICATE-----')) {
    const body = text
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\s+/g, '');
    if (!body) {
      throw new E2EEError('无效证书 PEM：缺少 base64 内容');
    }
    return Buffer.from(body, 'base64');
  }
  try {
    return new crypto.X509Certificate(raw).raw;
  } catch {
    return raw;
  }
}

/** PEM 证书 → 证书 SHA-256 指纹 */
function certificateSha256Fingerprint(certPem: string | Buffer): string {
  const der = certToDerBytes(certPem);
  const hash = crypto.createHash('sha256').update(der).digest('hex');
  return `sha256:${hash}`;
}

/** 公钥 KeyObject → 未压缩点（0x04 || x || y，65 字节） */
function publicKeyToUncompressedPoint(pubKey: crypto.KeyObject): Buffer {
  // 用 JWK 提取 x, y
  const jwk = pubKey.export({ format: 'jwk' }) as { x: string; y: string };
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  return Buffer.concat([Buffer.from([0x04]), x, y]);
}

/** 未压缩点 → KeyObject */
function uncompressedPointToPublicKey(point: Buffer): crypto.KeyObject {
  // 构造 JWK
  if (point[0] !== 0x04 || point.length !== 65) {
    throw new E2EEError('无效的未压缩公钥点格式');
  }
  const x = point.subarray(1, 33).toString('base64url');
  const y = point.subarray(33, 65).toString('base64url');
  return crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x, y },
    format: 'jwk',
  });
}

/** 离线消息 AAD → 排序紧凑 JSON bytes */
function aadBytesOffline(aad: JsonObject): Buffer {
  const obj: JsonObject = {};
  for (const field of AAD_FIELDS_OFFLINE) {
    obj[field] = aad[field] ?? null;
  }
  // sorted keys, compact JSON — 与 Python json.dumps(sort_keys=True, separators=(",",":")) 一致
  const sorted: JsonObject = {};
  for (const k of Object.keys(obj).sort()) {
    sorted[k] = obj[k];
  }
  return Buffer.from(JSON.stringify(sorted), 'utf-8');
}

/** AAD 匹配检查 */
function aadMatchesOffline(expected: JsonObject, actual: JsonObject): boolean {
  for (const field of AAD_MATCH_FIELDS_OFFLINE) {
    if (String(expected[field] ?? '') !== String(actual[field] ?? '')) {
      return false;
    }
  }
  return true;
}

// ── E2EEManager 类 ────────────────────────────────────────────

export class E2EEManager {
  private _identityFn: () => IdentityRecord;
  private _deviceIdFn: () => string;
  private _keystore: KeyStore;
  /** 本地防重放 seen set */
  private _seenMessages = new Map<string, boolean>();
  private _seenMaxSize = 50000;
  /** 对方 prekey 内存缓存（TTL） */
  private _prekeyCache = new Map<string, { prekey: PrekeyMaterial; expireAt: number }>();
  private _prekeyCacheTtl: number;
  /** 本地 prekey 私钥内存缓存 {prekeyId: privateKeyPem} */
  private _localPrekeyCache = new Map<string, string>();
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
    this._keystore = opts.keystore;
    this._prekeyCacheTtl = opts.prekeyCacheTtl ?? 3600;
    this._replayWindowSeconds = opts.replayWindowSeconds ?? 300;
  }

  // ── 便利方法 ──────────────────────────────────────────────

  /**
   * 加密消息（便利方法）。
   * 有 prekey 时用 prekey_ecdh_v2（四路 ECDH），无 prekey 时降级为 long_term_key。
   */
  encryptMessage(
    toAid: string,
    payload: JsonObject,
    opts: {
      peerCertPem: string;
      prekey?: PrekeyMaterial | null;
      messageId?: string;
      timestamp?: number;
    },
  ): [JsonObject, JsonObject] {
    const messageId = opts.messageId ?? crypto.randomUUID();
    const timestamp = opts.timestamp ?? Math.floor(Date.now());
    return this.encryptOutbound(
      toAid, payload, opts.peerCertPem,
      opts.prekey ?? null, messageId, timestamp,
    );
  }

  // ── 加密 ─────────────────────────────────────────────────

  /**
   * 加密出站消息：有 prekey → prekey_ecdh_v2（四路 ECDH），无 prekey → long_term_key。
   * 返回 [envelope, resultInfo]。
   */
  encryptOutbound(
    peerAid: string,
    payload: JsonObject,
    peerCertPem: string,
    prekey: PrekeyMaterial | null,
    messageId: string,
    timestamp: number,
  ): [JsonObject, JsonObject] {
    // 传入 prekey → 缓存；传入 null → 查缓存
    if (prekey != null) {
      this.cachePrekey(peerAid, prekey);
    } else {
      prekey = this.getCachedPrekey(peerAid);
    }

    if (prekey) {
      try {
        const envelope = this._encryptWithPrekey(
          peerAid, payload, prekey,
          peerCertPem, messageId, timestamp,
        );
        return [envelope, {
          encrypted: true,
          forward_secrecy: true,
          mode: MODE_PREKEY_ECDH_V2,
          degraded: false,
        }];
      } catch (exc) {
        // prekey 加密失败，降级到 long_term_key
      }
    }

    const envelope = this._encryptWithLongTermKey(
      peerAid, payload,
      peerCertPem, messageId, timestamp,
    );
    const degraded = prekey != null;
    return [envelope, {
      encrypted: true,
      forward_secrecy: false,
      mode: MODE_LONG_TERM_KEY,
      degraded,
      degradation_reason: degraded ? 'prekey_encrypt_failed' : 'no_prekey_available',
    }];
  }

  /** 使用对方 prekey 加密（prekey_ecdh_v2 模式，四路 ECDH + 发送方签名） */
  private _encryptWithPrekey(
    peerAid: string,
    payload: JsonObject,
    prekey: PrekeyMaterial,
    peerCertPem: string,
    messageId: string,
    timestamp: number,
  ): JsonObject {
    const peerIdentityPublic = pemToCertPublicKey(peerCertPem);
    const expectedCertFingerprint = String(prekey.cert_fingerprint ?? '').trim().toLowerCase();
    if (expectedCertFingerprint) {
      const actualCertFingerprint = certificateSha256Fingerprint(peerCertPem);
      if (actualCertFingerprint !== expectedCertFingerprint) {
        throw new E2EEError('prekey cert fingerprint mismatch');
      }
    }

    // 验证 prekey 签名
    const createdAt = prekey.created_at as number | undefined;
    let signData: Buffer;
    if (createdAt != null) {
      signData = Buffer.from(`${prekey.prekey_id}|${prekey.public_key}|${createdAt}`, 'utf-8');
    } else {
      signData = Buffer.from(`${prekey.prekey_id}|${prekey.public_key}`, 'utf-8');
    }
    const sigBytes = Buffer.from(prekey.signature as string, 'base64');
    if (!ecdsaVerify(peerIdentityPublic, sigBytes, signData)) {
      throw new E2EEError('prekey signature verification failed');
    }

    // 导入对方 prekey 公钥（DER SPKI）
    const peerPrekeyDer = Buffer.from(prekey.public_key as string, 'base64');
    const peerPrekeyPublic = crypto.createPublicKey({ key: peerPrekeyDer, format: 'der', type: 'spki' });

    // 加载发送方自己的 identity 私钥
    const senderIdentityPrivate = this._loadSenderIdentityPrivate();

    // 生成临时 ECDH 密钥对
    const { privateKey: ephemeralPrivate, publicKey: ephemeralPublic } = generateECKeyPair();
    const ephemeralPublicBytes = publicKeyToUncompressedPoint(ephemeralPublic);

    // 四路 ECDH + HKDF
    const dh1 = ecdhShared(ephemeralPrivate, peerPrekeyPublic);
    const dh2 = ecdhShared(ephemeralPrivate, peerIdentityPublic);
    const dh3 = ecdhShared(senderIdentityPrivate, peerPrekeyPublic);
    const dh4 = ecdhShared(senderIdentityPrivate, peerIdentityPublic);
    const combined = Buffer.concat([dh1, dh2, dh3, dh4]);
    const messageKey = hkdfDeriveSync(
      combined, Buffer.from(`aun-prekey-v2:${prekey.prekey_id}`, 'utf-8'), 32,
    );

    // AES-GCM 加密
    const plaintext = Buffer.from(JSON.stringify(payload), 'utf-8');
    const senderFingerprint = this._localCertSha256Fingerprint() || this._localIdentityFingerprint();
    const recipientFingerprint = fingerprintCertPem(peerCertPem);
    const ephemeralPkB64 = ephemeralPublicBytes.toString('base64');

    const aad: JsonObject = {
      from: this._currentAid(),
      to: peerAid,
      message_id: messageId,
      timestamp,
      encryption_mode: MODE_PREKEY_ECDH_V2,
      suite: SUITE,
      ephemeral_public_key: ephemeralPkB64,
      recipient_cert_fingerprint: recipientFingerprint,
      sender_cert_fingerprint: senderFingerprint,
      prekey_id: prekey.prekey_id,
    };
    const aadBytes = aadBytesOffline(aad);
    const { ciphertext, tag, nonce } = aesGcmEncrypt(messageKey, plaintext, aadBytes);

    const envelope: JsonObject = {
      type: 'e2ee.encrypted',
      version: '1',
      encryption_mode: MODE_PREKEY_ECDH_V2,
      suite: SUITE,
      prekey_id: prekey.prekey_id,
      ephemeral_public_key: ephemeralPkB64,
      nonce: nonce.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: tag.toString('base64'),
      aad,
    };

    // 发送方签名：对 ciphertext + tag + aad_bytes 签名（不可否认性）
    const signPayload = Buffer.concat([ciphertext, tag, aadBytes]);
    envelope.sender_signature = this._signBytes(signPayload);
    envelope.sender_cert_fingerprint = senderFingerprint;
    return envelope;
  }

  /** 使用 2DH 加密（long_term_key 模式 + 发送方签名） */
  private _encryptWithLongTermKey(
    peerAid: string,
    payload: JsonObject,
    peerCertPem: string,
    messageId: string,
    timestamp: number,
  ): JsonObject {
    const peerPublicKey = pemToCertPublicKey(peerCertPem);
    const senderIdentityPrivate = this._loadSenderIdentityPrivate();

    // 生成临时密钥对
    const { privateKey: ephemeralPrivate, publicKey: ephemeralPublic } = generateECKeyPair();
    const ephemeralPublicBytes = publicKeyToUncompressedPoint(ephemeralPublic);

    // 2DH + HKDF
    const dh1 = ecdhShared(ephemeralPrivate, peerPublicKey);
    const dh2 = ecdhShared(senderIdentityPrivate, peerPublicKey);
    const combined = Buffer.concat([dh1, dh2]);
    const messageKey = hkdfDeriveSync(
      combined, Buffer.from('aun-longterm-v2', 'utf-8'), 32,
    );

    const plaintext = Buffer.from(JSON.stringify(payload), 'utf-8');
    const senderFingerprint = this._localCertSha256Fingerprint() || this._localIdentityFingerprint();
    const recipientFingerprint = fingerprintCertPem(peerCertPem);
    const ephemeralPkB64 = ephemeralPublicBytes.toString('base64');

    const aad: JsonObject = {
      from: this._currentAid(),
      to: peerAid,
      message_id: messageId,
      timestamp,
      encryption_mode: MODE_LONG_TERM_KEY,
      suite: SUITE,
      ephemeral_public_key: ephemeralPkB64,
      recipient_cert_fingerprint: recipientFingerprint,
      sender_cert_fingerprint: senderFingerprint,
    };
    const aadBytes = aadBytesOffline(aad);
    const { ciphertext, tag, nonce } = aesGcmEncrypt(messageKey, plaintext, aadBytes);

    const envelope: JsonObject = {
      type: 'e2ee.encrypted',
      version: '1',
      encryption_mode: MODE_LONG_TERM_KEY,
      suite: SUITE,
      ephemeral_public_key: ephemeralPkB64,
      nonce: nonce.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: tag.toString('base64'),
      aad,
    };

    // 发送方签名（不可否认性）
    const signPayload = Buffer.concat([ciphertext, tag, aadBytes]);
    envelope.sender_signature = this._signBytes(signPayload);
    envelope.sender_cert_fingerprint = senderFingerprint;
    return envelope;
  }

  // ── 解密 ─────────────────────────────────────────────────

  /** 解密单条消息（便利方法，内置本地防重放 + timestamp 窗口） */
  decryptMessage(message: Message): Message | null {
    const payload = message.payload as JsonObject | undefined;
    if (!payload || typeof payload !== 'object') return message;
    if (payload.type !== 'e2ee.encrypted') return message;
    if (message.encrypted === false) return message;
    if (!this._shouldDecryptForCurrentAid(message, payload)) return message;

    // timestamp 窗口检查
    const ts = (message.timestamp ?? (payload.aad as JsonObject | undefined)?.timestamp) as number | undefined;
    if (typeof ts === 'number' && this._replayWindowSeconds > 0) {
      const nowMs = Date.now();
      const diffS = Math.abs(nowMs - ts) / 1000;
      if (diffS > this._replayWindowSeconds) {
        return null;
      }
    }

    // 本地防重放
    const messageId = message.message_id as string || '';
    const fromAid = message.from as string || '';
    if (messageId && fromAid) {
      const seenKey = `${fromAid}:${messageId}`;
      if (this._seenMessages.has(seenKey)) return null;
      this._seenMessages.set(seenKey, true);
      this._trimSeenSet();
    }

    return this._decryptMessage(message);
  }

  /** 解密入站消息（不消耗 seen set，用于 pull 场景） */
  _decryptMessage(message: Message): Message | null {
    const payload = message.payload as JsonObject;
    if (typeof payload === 'object' && !this._shouldDecryptForCurrentAid(message, payload)) {
      return message;
    }
    const encryptionMode = (payload.encryption_mode as string) || '';

    // 验证发送方签名（适用于所有模式）
    try {
      this._verifySenderSignature(payload, message);
    } catch {
      return null;
    }

    if (encryptionMode === MODE_PREKEY_ECDH_V2) {
      return this._decryptMessagePrekeyV2(message);
    } else if (encryptionMode === MODE_LONG_TERM_KEY) {
      return this._decryptMessageLongTerm(message);
    }
    return null;
  }

  /** 解密 prekey_ecdh_v2 模式的消息（四路 ECDH） */
  private _decryptMessagePrekeyV2(message: Message): Message | null {
    const payload = message.payload as JsonObject;
    try {
      const ephemeralPublicBytes = Buffer.from(payload.ephemeral_public_key as string, 'base64');
      const prekeyId = (payload.prekey_id as string) || '';
      const nonce = Buffer.from(payload.nonce as string, 'base64');
      const ciphertext = Buffer.from(payload.ciphertext as string, 'base64');
      const tag = Buffer.from(payload.tag as string, 'base64');

      // 加载 prekey 私钥
      const prekeyPrivateKey = this._loadPrekeyPrivateKey(prekeyId);
      if (!prekeyPrivateKey) {
        throw new E2EEError(`prekey not found: ${prekeyId}`);
      }

      // 加载接收方自己的 identity 私钥
      const myAid = this._currentAid();
      if (!myAid) throw new E2EEError('AID unavailable');
      const keyPair = this._keystore.loadKeyPair(myAid);
      if (!keyPair || !keyPair.private_key_pem) {
        throw new E2EEError('Identity private key not found');
      }
      const myIdentityPrivate = crypto.createPrivateKey(keyPair.private_key_pem as string);

      // 获取发送方公钥
      const fromAid = (message.from ?? (payload.aad as JsonObject | undefined)?.from) as string;
      const senderCertFingerprint = String(
        payload.sender_cert_fingerprint ?? (payload.aad as JsonObject | undefined)?.sender_cert_fingerprint ?? '',
      ).trim().toLowerCase();
      const senderPublicKey = this._loadSenderPublicKey(fromAid, senderCertFingerprint || undefined);
      if (!senderPublicKey) {
        throw new E2EEError(`sender public key not found for ${fromAid}`);
      }

      // 四路 ECDH + HKDF
      const ephemeralPublic = uncompressedPointToPublicKey(ephemeralPublicBytes);
      const dh1 = ecdhShared(prekeyPrivateKey, ephemeralPublic);
      const dh2 = ecdhShared(myIdentityPrivate, ephemeralPublic);
      const dh3 = ecdhShared(prekeyPrivateKey, senderPublicKey);
      const dh4 = ecdhShared(myIdentityPrivate, senderPublicKey);
      const combined = Buffer.concat([dh1, dh2, dh3, dh4]);
      const messageKey = hkdfDeriveSync(
        combined, Buffer.from(`aun-prekey-v2:${prekeyId}`, 'utf-8'), 32,
      );

      // 验证 AAD 并解密
      const aad = payload.aad as JsonObject | undefined;
      let aadBytes: Buffer;
      if (aad && typeof aad === 'object') {
        const expectedAad = this._buildInboundAadOffline(message, payload);
        if (!aadMatchesOffline(expectedAad, aad)) {
          throw new E2EEDecryptFailedError('aad mismatch');
        }
        aadBytes = aadBytesOffline(aad);
      } else {
        aadBytes = Buffer.alloc(0);
      }
      const plaintext = aesGcmDecrypt(messageKey, ciphertext, tag, nonce, aadBytes);
      const decoded = JSON.parse(plaintext.toString('utf-8'));

      return {
        ...message,
        payload: decoded,
        encrypted: true,
        e2ee: {
          encryption_mode: MODE_PREKEY_ECDH_V2,
          suite: (payload.suite as string) || SUITE,
          prekey_id: prekeyId,
        },
      };
    } catch {
      return null;
    }
  }

  /** 解密 long_term_key 模式的消息（2DH） */
  private _decryptMessageLongTerm(message: Message): Message | null {
    const payload = message.payload as JsonObject;
    try {
      const ephemeralPublicBytes = Buffer.from(payload.ephemeral_public_key as string, 'base64');
      const nonce = Buffer.from(payload.nonce as string, 'base64');
      const ciphertext = Buffer.from(payload.ciphertext as string, 'base64');
      const tag = Buffer.from(payload.tag as string, 'base64');

      const myAid = this._currentAid();
      if (!myAid) throw new E2EEError('AID unavailable');
      const keyPair = this._keystore.loadKeyPair(myAid);
      if (!keyPair || !keyPair.private_key_pem) {
        throw new E2EEError('Private key not found');
      }
      const privateKey = crypto.createPrivateKey(keyPair.private_key_pem as string);

      // 获取发送方公钥
      const fromAid = (message.from ?? (payload.aad as JsonObject | undefined)?.from) as string;
      const senderCertFingerprint = String(
        payload.sender_cert_fingerprint ?? (payload.aad as JsonObject | undefined)?.sender_cert_fingerprint ?? '',
      ).trim().toLowerCase();
      const senderPublicKey = this._loadSenderPublicKey(fromAid, senderCertFingerprint || undefined);
      if (!senderPublicKey) {
        throw new E2EEError(`sender public key not found for ${fromAid}`);
      }

      // 2DH + HKDF
      const ephemeralPublic = uncompressedPointToPublicKey(ephemeralPublicBytes);
      const dh1 = ecdhShared(privateKey, ephemeralPublic);
      const dh2 = ecdhShared(privateKey, senderPublicKey);
      const combined = Buffer.concat([dh1, dh2]);
      const messageKey = hkdfDeriveSync(
        combined, Buffer.from('aun-longterm-v2', 'utf-8'), 32,
      );

      const aad = payload.aad as JsonObject | undefined;
      let aadBytes: Buffer;
      if (aad && typeof aad === 'object') {
        const expectedAad = this._buildInboundAadOffline(message, payload);
        if (!aadMatchesOffline(expectedAad, aad)) {
          throw new E2EEDecryptFailedError('aad mismatch');
        }
        aadBytes = aadBytesOffline(aad);
      } else {
        aadBytes = Buffer.alloc(0);
      }
      const plaintext = aesGcmDecrypt(messageKey, ciphertext, tag, nonce, aadBytes);
      const decoded = JSON.parse(plaintext.toString('utf-8'));

      return {
        ...message,
        payload: decoded,
        encrypted: true,
        e2ee: {
          encryption_mode: MODE_LONG_TERM_KEY,
          suite: payload.suite as string,
        },
      };
    } catch {
      return null;
    }
  }

  // ── 发送方签名验证 ─────────────────────────────────────────

  private _verifySenderSignature(payload: JsonObject, message: Message): void {
    const senderSigB64 = payload.sender_signature as string | undefined;
    if (!senderSigB64) {
      throw new E2EEDecryptFailedError('sender_signature missing: 拒绝无发送方签名的消息');
    }

    const fromAid = (message.from ?? (payload.aad as JsonObject | undefined)?.from) as string;
    if (!fromAid) {
      throw new E2EEDecryptFailedError('from_aid missing in message');
    }

    const senderCertFingerprint = String(
      payload.sender_cert_fingerprint ?? (payload.aad as JsonObject | undefined)?.sender_cert_fingerprint ?? '',
    ).trim().toLowerCase();
    const senderCertPem = this._getSenderCert(fromAid, senderCertFingerprint || undefined);
    if (!senderCertPem) {
      throw new E2EEDecryptFailedError(`sender cert not found for ${fromAid}`);
    }

    const senderPublicKey = pemToCertPublicKey(senderCertPem);

    // 重建签名载荷
    const ciphertextBuf = Buffer.from(payload.ciphertext as string, 'base64');
    const tagBuf = Buffer.from(payload.tag as string, 'base64');
    const aad = payload.aad as JsonObject | undefined;
    const aadBytes = (aad && typeof aad === 'object') ? aadBytesOffline(aad) : Buffer.alloc(0);
    const signPayload = Buffer.concat([ciphertextBuf, tagBuf, aadBytes]);

    const sigBytes = Buffer.from(senderSigB64, 'base64');
    if (!ecdsaVerify(senderPublicKey, sigBytes, signPayload)) {
      throw new E2EEDecryptFailedError('sender signature verification failed');
    }
  }

  // ── Prekey 缓存 ────────────────────────────────────────────

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

  /** 使指定 peer 的 prekey 缓存失效 */
  invalidatePrekeyCahce(peerAid: string): void {
    this._prekeyCache.delete(peerAid);
  }

  // ── Prekey 生成 ──────────────────────────────────────────

  /**
   * 生成 prekey 材料并保存私钥到本地 keystore。
   * 返回 {prekey_id, public_key, signature, created_at}，可直接用于 RPC 上传。
   */
  generatePrekey(): PrekeyMaterial {
    const aid = this._currentAid();
    if (!aid) throw new E2EEError('AID unavailable for prekey generation');
    const deviceId = this._currentDeviceId();

    // 生成新 prekey
    const { privateKey, publicKey } = generateECKeyPair();
    const publicDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    const prekeyId = crypto.randomUUID();
    const publicKeyB64 = publicDer.toString('base64');
    const nowMs = Date.now();

    // 签名：prekey_id|public_key|created_at
    const signDataBuf = Buffer.from(`${prekeyId}|${publicKeyB64}|${nowMs}`, 'utf-8');
    const signature = this._signBytes(signDataBuf);

    // 保存私钥到本地 keystore
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;

    saveKeyStorePrekey(this._keystore, aid, deviceId, prekeyId, {
      private_key_pem: privateKeyPem,
      created_at: nowMs,
      updated_at: nowMs,
    });

    // 内存缓存私钥
    this._localPrekeyCache.set(prekeyId, privateKeyPem);

    // 清理过期的旧 prekey 私钥
    this._cleanupExpiredPrekeys(aid, deviceId);

    const result: PrekeyMaterial = {
      prekey_id: prekeyId,
      public_key: publicKeyB64,
      signature,
      created_at: nowMs,
    };
    const certFingerprint = this._localCertSha256Fingerprint();
    if (certFingerprint) {
      result.cert_fingerprint = certFingerprint;
    }
    if (deviceId) {
      result.device_id = deviceId;
    }
    return result;
  }

  /** 清理本地过期的 prekey 私钥 */
  private _cleanupExpiredPrekeys(aid: string, deviceId: string): void {
    const nowMs = Date.now();
    const cutoffMs = nowMs - PREKEY_RETENTION_SECONDS * 1000;
    const expired = cleanupKeyStorePrekeys(this._keystore, aid, deviceId, cutoffMs, PREKEY_MIN_KEEP_COUNT);
    if (expired.length > 0) {
      for (const pid of expired) {
        this._localPrekeyCache.delete(pid);
      }
    }
  }

  /** 从内存缓存或 keystore 加载 prekey 私钥 */
  private _loadPrekeyPrivateKey(prekeyId: string): crypto.KeyObject | null {
    // 优先从内存缓存获取
    const cachedPem = this._localPrekeyCache.get(prekeyId);
    if (cachedPem) {
      return crypto.createPrivateKey(cachedPem);
    }

    const aid = this._currentAid();
    if (!aid) return null;
    const prekeys = loadKeyStorePrekeys(this._keystore, aid, this._currentDeviceId());
    const prekeyData = prekeys[prekeyId];
    if (!prekeyData) return null;
    const privateKeyPem = prekeyData.private_key_pem as string | undefined;
    if (!privateKeyPem) return null;

    try {
      const pk = crypto.createPrivateKey(privateKeyPem);
      this._localPrekeyCache.set(prekeyId, privateKeyPem);
      return pk;
    } catch {
      return null;
    }
  }

  // ── 证书指纹工具 ────────────────────────────────────────

  /** 从 PEM 证书计算公钥指纹 */
  static fingerprintCertPem(certPem: string): string {
    return fingerprintCertPem(certPem);
  }

  /** 公钥 DER bytes → 指纹 */
  static fingerprintDerPublicKey(derBytes: Buffer): string {
    return fingerprintPublicKeyDer(derBytes);
  }

  // ── 内部工具 ─────────────────────────────────────────────

  /** 仅解密发给当前 AID 的消息 */
  private _shouldDecryptForCurrentAid(
    message: Message,
    payload: JsonObject,
  ): boolean {
    if (String(message.direction ?? '').trim().toLowerCase() === 'outbound_sync') {
      return true;
    }
    const currentAid = this._currentAid();
    if (!currentAid) return true;
    const targetAid =
      (message.to as string) ||
      (payload.aad as JsonObject | undefined)?.to as string ||
      (payload.to as string);
    if (!targetAid) return true;
    return String(targetAid) === String(currentAid);
  }

  /** LRU 裁剪 seen set */
  private _trimSeenSet(): void {
    if (this._seenMessages.size > this._seenMaxSize) {
      const trimCount = this._seenMessages.size - Math.floor(this._seenMaxSize * 0.8);
      const iter = this._seenMessages.keys();
      for (let i = 0; i < trimCount; i++) {
        const next = iter.next();
        if (next.done) break;
        this._seenMessages.delete(next.value);
      }
    }
  }

  /** 获取当前 AID */
  private _currentAid(): string | null {
    const identity = this._identityFn();
    const aid = identity.aid;
    return aid ? String(aid) : null;
  }

  private _currentDeviceId(): string {
    try {
      return String(this._deviceIdFn() ?? '').trim();
    } catch {
      return '';
    }
  }

  /** 获取发送方证书 */
  private _getSenderCert(aid: string, certFingerprint?: string): string | null {
    const certPem = this._keystore.loadCert(aid, certFingerprint);
    const normalized = String(certFingerprint ?? '').trim().toLowerCase();
    if (!certPem) return null;
    if (!normalized) return certPem;
    return certificateSha256Fingerprint(certPem) === normalized ? certPem : null;
  }

  /** 获取发送方的 identity 公钥（从本地证书缓存） */
  private _loadSenderPublicKey(aid: string | null, certFingerprint?: string): crypto.KeyObject | null {
    if (!aid) return null;
    const certPem = this._getSenderCert(aid, certFingerprint);
    if (!certPem) return null;
    try {
      return pemToCertPublicKey(certPem);
    } catch {
      return null;
    }
  }

  /** 用当前身份私钥签名 */
  private _signBytes(data: Buffer): string {
    const identity = this._identityFn();
    const privateKeyPem = identity.private_key_pem as string | undefined;
    if (!privateKeyPem) {
      throw new E2EEError('identity private key unavailable');
    }
    return ecdsaSign(privateKeyPem, data).toString('base64');
  }

  /** 加载发送方自己的 identity 私钥 */
  private _loadSenderIdentityPrivate(): crypto.KeyObject {
    const identity = this._identityFn();
    const privateKeyPem = identity.private_key_pem as string | undefined;
    if (!privateKeyPem) {
      throw new E2EEError('sender identity private key unavailable');
    }
    return crypto.createPrivateKey(privateKeyPem);
  }

  /** 本地 identity 指纹（优先证书 DER SHA-256，缺失时回退到公钥指纹） */
  private _localIdentityFingerprint(): string {
    // 优先用证书指纹（与 PKI 一致）
    const identity = this._identityFn();
    const cert = identity.cert as string | undefined;
    if (cert) {
      return certificateSha256Fingerprint(cert);
    }
    // 无证书时回退到公钥 SPKI 指纹
    const publicKeyDerB64 = identity.public_key_der_b64 as string | undefined;
    if (publicKeyDerB64) {
      return fingerprintPublicKeyDer(Buffer.from(publicKeyDerB64, 'base64'));
    }
    const privateKeyPem = identity.private_key_pem as string | undefined;
    if (privateKeyPem) {
      const pk = crypto.createPrivateKey(privateKeyPem);
      const pubKey = crypto.createPublicKey(pk);
      return fingerprintKeyObject(pubKey);
    }
    throw new E2EEError('identity fingerprint unavailable');
  }

  /** 本地证书指纹（优先证书 SHA-256，缺失时回退到 identity 公钥指纹） */
  private _localCertFingerprint(): string {
    return this._localCertSha256Fingerprint() || this._localIdentityFingerprint();
  }

  /** 本地证书的 SHA-256 指纹（用于锁定证书版本） */
  private _localCertSha256Fingerprint(): string {
    const identity = this._identityFn();
    const cert = identity.cert as string | undefined;
    if (!cert) return '';
    return certificateSha256Fingerprint(cert);
  }

  /** 构建接收端 AAD */
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
      suite: (payload.suite as string) || SUITE,
      ephemeral_public_key: payload.ephemeral_public_key,
      recipient_cert_fingerprint: this._localCertFingerprint(),
      sender_cert_fingerprint: (payload.sender_cert_fingerprint ?? aad?.sender_cert_fingerprint) as string | undefined,
      prekey_id: (payload.prekey_id ?? aad?.prekey_id) as string | undefined,
    };
  }

  /** 清理过期的 prekey 缓存条目（供外部定时调用） */
  cleanExpiredCaches(): void {
    const now = Date.now() / 1000;
    for (const [k, v] of this._prekeyCache) {
      if (now >= v.expireAt) this._prekeyCache.delete(k);
    }
  }
}
