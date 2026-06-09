// ── AuthFlow（认证流程 — 浏览器完整实现）─────────────────
// 负责 AID 注册、login1/login2 双阶段认证、证书链验证、token 管理。
// 浏览器环境使用原生 WebSocket + fetch + SubtleCrypto。

import type { TokenStore } from './keystore/index.js';
import type { ModuleLogger } from './logger.js';
import { CryptoProvider, base64ToUint8, uint8ToBase64, pemToArrayBuffer, toBufferSource } from './crypto.js';
import { AuthError, IdentityConflictError, StateError, ValidationError, mapRemoteError } from './errors.js';
import { ROOT_CA_PEM } from './certs/root.js';
import { VERSION as AUN_SDK_VERSION } from './version.js';

const _noopLog: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };
const AUN_SDK_LANG = 'javascript';
const SENSITIVE_RPC_LOG_KEYS = new Set([
  'access_token',
  'refresh_token',
  'kite_token',
  'token',
]);

function redactRpcLogPayload(value: unknown, key: string = '', depth: number = 0): unknown {
  const keyLower = key.toLowerCase();
  if (SENSITIVE_RPC_LOG_KEYS.has(keyLower) || keyLower.endsWith('_token')) {
    const text = String(value ?? '');
    return text ? `<redacted len=${text.length}>` : '';
  }
  if (depth >= 6) return '<max-depth>';
  if (Array.isArray(value)) {
    return value.map((item) => redactRpcLogPayload(item, '', depth + 1));
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [childKey, childValue] of Object.entries(value as Record<string, unknown>)) {
      out[childKey] = redactRpcLogPayload(childValue, childKey, depth + 1);
    }
    return out;
  }
  return value;
}

import {
  isJsonObject,
  type IdentityRecord,
  type JsonObject,
  type JsonValue,
  type RpcMessage,
  type RpcParams,
  type RpcResult,
} from './types.js';

// ── ASN.1 / PEM 工具 ────────────────────────────────────

/** 拆分 PEM bundle 为独立的 PEM 字符串数组 */
function splitPemBundle(bundle: string): string[] {
  const marker = '-----END CERTIFICATE-----';
  const certs: string[] = [];
  for (const part of bundle.split(marker)) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    certs.push(`${trimmed}\n${marker}\n`);
  }
  return certs;
}

/** 将 DER 格式的 ECDSA 签名转为 IEEE P1363 格式（SubtleCrypto 需要） */
function derToP1363(der: Uint8Array, curveLen: number = 32): Uint8Array {
  // DER: 0x30 <len> 0x02 <rLen> <r> 0x02 <sLen> <s>
  if (der[0] !== 0x30) throw new AuthError('无效的 DER 签名格式');
  let offset = 2;
  // 跳过可能的多字节长度
  if (der[1] & 0x80) offset += (der[1] & 0x7f);

  if (der[offset] !== 0x02) throw new AuthError('DER 签名缺少 r INTEGER 标签');
  const rLen = der[offset + 1];
  const rBytes = der.slice(offset + 2, offset + 2 + rLen);
  offset += 2 + rLen;

  if (der[offset] !== 0x02) throw new AuthError('DER 签名缺少 s INTEGER 标签');
  const sLen = der[offset + 1];
  const sBytes = der.slice(offset + 2, offset + 2 + sLen);

  // 去前导零并填充到 curveLen
  const r = padToLength(trimSignedIntLeadingZeros(rBytes), curveLen);
  const s = padToLength(trimSignedIntLeadingZeros(sBytes), curveLen);

  const result = new Uint8Array(curveLen * 2);
  result.set(r, 0);
  result.set(s, curveLen);
  return result;
}

/** 去除 ASN.1 有符号整数的前导零 */
function trimSignedIntLeadingZeros(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  return bytes.slice(start);
}

/** 将字节数组左侧填零至指定长度 */
function padToLength(bytes: Uint8Array, len: number): Uint8Array {
  if (bytes.length >= len) return bytes.slice(bytes.length - len);
  const padded = new Uint8Array(len);
  padded.set(bytes, len - bytes.length);
  return padded;
}

// ── 简化版 X.509 DER 解析 ───────────────────────────────

/** 解析后的证书信息（浏览器端简化版） */
interface ParsedCert {
  /** 原始 PEM 文本 */
  pem: string;
  /** TBS (To Be Signed) 证书字节 */
  tbsBytes: Uint8Array;
  /** 签名字节（DER 编码） */
  signatureBytes: Uint8Array;
  /** 签名算法 OID */
  signatureAlgorithmOid: string;
  /** 序列号（十六进制小写） */
  serialHex: string;
  /** Subject CN（可能为空） */
  subjectCN: string;
  /** Issuer DN 原始字节（用于比较） */
  issuerRaw: Uint8Array;
  /** Subject DN 原始字节（用于比较） */
  subjectRaw: Uint8Array;
  /** 有效期开始（UNIX 时间戳） */
  notBefore: number;
  /** 有效期结束（UNIX 时间戳） */
  notAfter: number;
  /** 是否为 CA 证书 */
  isCA: boolean;
  /** SPKI 公钥字节 */
  spkiBytes: Uint8Array;
}

interface AuthContext extends JsonObject {
  token?: string;
  identity?: IdentityRecord;
  hello?: JsonObject;
}

interface TransportLike {
  call(method: string, params: RpcParams): Promise<RpcResult>;
}

const CERT_CLOCK_SKEW_SECONDS = 300;

/** 读取 ASN.1 TLV 的 tag 和长度，返回 [tag, 值起始偏移, 值长度] */
function readTlv(data: Uint8Array, offset: number): [number, number, number] {
  const tag = data[offset];
  let lenOffset = offset + 1;
  let length: number;

  if (data[lenOffset] & 0x80) {
    const numBytes = data[lenOffset] & 0x7f;
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = (length << 8) | data[lenOffset + 1 + i];
    }
    lenOffset += 1 + numBytes;
  } else {
    length = data[lenOffset];
    lenOffset += 1;
  }
  return [tag, lenOffset, length];
}

/** 获取 TLV 完整范围（包含 tag + length + value） */
function getTlvFullRange(data: Uint8Array, offset: number): [number, number] {
  const [, valueStart, valueLen] = readTlv(data, offset);
  return [offset, valueStart + valueLen];
}

/** 解析 ASN.1 UTCTime 或 GeneralizedTime 为 UNIX 时间戳 */
function parseAsn1Time(data: Uint8Array, offset: number): number {
  const [tag, valueStart, valueLen] = readTlv(data, offset);
  const timeStr = new TextDecoder().decode(data.slice(valueStart, valueStart + valueLen));

  if (tag === 0x17) {
    // UTCTime: YYMMDDHHMMSSZ
    let year = parseInt(timeStr.substring(0, 2), 10);
    year += year >= 50 ? 1900 : 2000;
    const month = parseInt(timeStr.substring(2, 4), 10) - 1;
    const day = parseInt(timeStr.substring(4, 6), 10);
    const hour = parseInt(timeStr.substring(6, 8), 10);
    const minute = parseInt(timeStr.substring(8, 10), 10);
    const second = parseInt(timeStr.substring(10, 12), 10);
    return Date.UTC(year, month, day, hour, minute, second) / 1000;
  } else if (tag === 0x18) {
    // GeneralizedTime: YYYYMMDDHHMMSSZ
    const year = parseInt(timeStr.substring(0, 4), 10);
    const month = parseInt(timeStr.substring(4, 6), 10) - 1;
    const day = parseInt(timeStr.substring(6, 8), 10);
    const hour = parseInt(timeStr.substring(8, 10), 10);
    const minute = parseInt(timeStr.substring(10, 12), 10);
    const second = parseInt(timeStr.substring(12, 14), 10);
    return Date.UTC(year, month, day, hour, minute, second) / 1000;
  }
  throw new AuthError('不支持的 ASN.1 时间格式');
}

/** 解析 OID 字节为点分字符串 */
function parseOid(data: Uint8Array): string {
  if (data.length === 0) return '';
  const components: number[] = [];
  // 第一个字节编码前两个组件
  components.push(Math.floor(data[0] / 40));
  components.push(data[0] % 40);
  let value = 0;
  for (let i = 1; i < data.length; i++) {
    value = (value << 7) | (data[i] & 0x7f);
    if (!(data[i] & 0x80)) {
      components.push(value);
      value = 0;
    }
  }
  return components.join('.');
}

/** 在 ASN.1 SEQUENCE 中查找特定 OID 对应的值 */
function findOidValue(data: Uint8Array, targetOid: string): Uint8Array | null {
  for (let i = 0; i < data.length - 4; i++) {
    if (data[i] === 0x06) {
      // OID tag
      const oidLen = data[i + 1];
      if (i + 2 + oidLen > data.length) continue;
      const oid = parseOid(data.slice(i + 2, i + 2 + oidLen));
      if (oid === targetOid) {
        const valOffset = i + 2 + oidLen;
        if (valOffset < data.length) {
          const [, vs, vl] = readTlv(data, valOffset);
          return data.slice(vs, vs + vl);
        }
      }
    }
  }
  return null;
}

/** 从 DER 数据中查找 CN（Common Name, OID 2.5.4.3）的 UTF8/PrintableString 值 */
function extractCN(subjectRaw: Uint8Array): string {
  // CN OID: 2.5.4.3 → 编码为 55 04 03
  const cnOid = '2.5.4.3';
  const value = findOidValue(subjectRaw, cnOid);
  if (!value) return '';
  return new TextDecoder().decode(value);
}

/** 解析 PEM 证书为结构化数据（简化版 X.509 DER 解析） */
function parseCertDer(pem: string): ParsedCert {
  const derBuf = pemToArrayBuffer(pem);
  const der = new Uint8Array(derBuf);

  // 顶层 SEQUENCE
  const [, certValueStart, certValueLen] = readTlv(der, 0);

  // TBSCertificate（第一个子 SEQUENCE）
  const [tbsStart, tbsEnd] = getTlvFullRange(der, certValueStart);
  const tbsBytes = der.slice(tbsStart, tbsEnd);

  const [, tbsValueStart] = readTlv(der, certValueStart);
  let pos = tbsValueStart;

  // 版本号（可选，EXPLICIT [0]）— 跳过整个 [0] TLV
  if (der[pos] === 0xa0) {
    const [, versionVs, versionVl] = readTlv(der, pos);
    pos = versionVs + versionVl;
  }

  // 序列号（INTEGER）
  const [, serialStart, serialLen] = readTlv(der, pos);
  const serialBytes = der.slice(serialStart, serialStart + serialLen);
  const serialHex = Array.from(serialBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  pos = serialStart + serialLen;

  // 签名算法（SEQUENCE）
  const [, sigAlgStart, sigAlgLen] = readTlv(der, pos);
  // 提取内部 OID
  const [, sigOidStart, sigOidLen] = readTlv(der, sigAlgStart);
  const signatureAlgorithmOid = parseOid(der.slice(sigOidStart, sigOidStart + sigOidLen));
  pos = sigAlgStart + sigAlgLen;

  // Issuer（SEQUENCE）
  const [issuerFullStart, issuerFullEnd] = getTlvFullRange(der, pos);
  const issuerRaw = der.slice(issuerFullStart, issuerFullEnd);
  pos = issuerFullEnd;

  // Validity（SEQUENCE）
  const [, validityStart, validityLen] = readTlv(der, pos);
  const notBefore = parseAsn1Time(der, validityStart);
  // notBefore 的完整 TLV 结尾就是 notAfter 的起始位置
  const [, nbVs, nbVl] = readTlv(der, validityStart);
  const notAfter = parseAsn1Time(der, nbVs + nbVl);
  pos = validityStart + validityLen;

  // Subject（SEQUENCE）
  const [subjectFullStart, subjectFullEnd] = getTlvFullRange(der, pos);
  const subjectRaw = der.slice(subjectFullStart, subjectFullEnd);
  const subjectCN = extractCN(subjectRaw);
  pos = subjectFullEnd;

  // SubjectPublicKeyInfo（SEQUENCE）
  const [spkiFullStart, spkiFullEnd] = getTlvFullRange(der, pos);
  const spkiBytes = der.slice(spkiFullStart, spkiFullEnd);
  pos = spkiFullEnd;

  // 检查 BasicConstraints（在 extensions 中）
  let isCA = false;
  // extensions 在 [3] EXPLICIT 中
  const extensionsSearchStart = pos;
  const extensionsSearchEnd = tbsEnd;
  // 搜索 BasicConstraints OID: 2.5.29.19 → 55 1D 13
  const bcOidBytes = new Uint8Array([0x55, 0x1d, 0x13]);
  for (let i = extensionsSearchStart; i < extensionsSearchEnd - 3; i++) {
    if (der[i] === bcOidBytes[0] && der[i + 1] === bcOidBytes[1] && der[i + 2] === bcOidBytes[2]) {
      // 找到 BasicConstraints OID，在后续字节中搜索 BOOLEAN TRUE (01 01 FF)
      const searchEnd = Math.min(i + 20, extensionsSearchEnd);
      for (let j = i + 3; j < searchEnd - 2; j++) {
        if (der[j] === 0x01 && der[j + 1] === 0x01 && der[j + 2] === 0xff) {
          isCA = true;
          break;
        }
      }
      break;
    }
  }

  // 签名算法（第二个，在 TBS 之后）
  const sigAlg2Pos = tbsEnd;
  const [, sigAlg2Start, sigAlg2Len] = readTlv(der, sigAlg2Pos);
  const signaturePos = sigAlg2Start + sigAlg2Len;

  // 签名值（BIT STRING）
  const [, sigBitsStart, sigBitsLen] = readTlv(der, signaturePos);
  // BIT STRING 第一个字节是 unused bits 数量
  const signatureBytes = der.slice(sigBitsStart + 1, sigBitsStart + sigBitsLen);

  return {
    pem,
    tbsBytes,
    signatureBytes,
    signatureAlgorithmOid,
    serialHex,
    subjectCN,
    issuerRaw,
    subjectRaw,
    notBefore,
    notAfter,
    isCA,
    spkiBytes,
  };
}

// ── 签名验证 ────────────────────────────────────────────

/** 确定签名算法的哈希和曲线长度 */
function getSignatureParams(oid: string): { hash: string; curveLen: number; curveName: string } {
  // ecdsa-with-SHA256: 1.2.840.10045.4.3.2
  if (oid === '1.2.840.10045.4.3.2') return { hash: 'SHA-256', curveLen: 32, curveName: 'P-256' };
  // ecdsa-with-SHA384: 1.2.840.10045.4.3.3
  if (oid === '1.2.840.10045.4.3.3') return { hash: 'SHA-384', curveLen: 48, curveName: 'P-384' };
  // ecdsa-with-SHA512: 1.2.840.10045.4.3.4
  if (oid === '1.2.840.10045.4.3.4') return { hash: 'SHA-512', curveLen: 66, curveName: 'P-521' };
  throw new AuthError(`不支持的签名算法 OID: ${oid}`);
}

/** 使用 SubtleCrypto 验证证书签名 */
async function verifyCertSignature(
  issuerSpkiDer: Uint8Array,
  cert: ParsedCert,
): Promise<void> {
  const params = getSignatureParams(cert.signatureAlgorithmOid);
  let pubKey: CryptoKey;
  try {
    pubKey = await crypto.subtle.importKey(
      'spki',
      toBufferSource(issuerSpkiDer),
      { name: 'ECDSA', namedCurve: params.curveName },
      false,
      ['verify'],
    );
  } catch {
    throw new AuthError('导入签发者公钥失败');
  }

  const p1363Sig = derToP1363(cert.signatureBytes, params.curveLen);
  const valid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: params.hash },
    pubKey,
    toBufferSource(p1363Sig),
    toBufferSource(cert.tbsBytes),
  );
  if (!valid) throw new AuthError('证书签名验证失败');
}

/** 使用 SubtleCrypto 验证通用 ECDSA 签名（用于 client_nonce 验证等） */
async function verifyEcdsaSignature(
  spkiDer: Uint8Array,
  signatureDer: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  // 自动检测曲线
  let pubKey: CryptoKey;
  let curveLen: number;
  let hash: string;
  try {
      pubKey = await crypto.subtle.importKey(
        'spki', toBufferSource(spkiDer), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'],
      );
    curveLen = 32;
    hash = 'SHA-256';
  } catch {
    try {
      pubKey = await crypto.subtle.importKey(
        'spki', toBufferSource(spkiDer), { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify'],
      );
      curveLen = 48;
      hash = 'SHA-384';
    } catch {
      return false;
    }
  }

  const p1363Sig = derToP1363(signatureDer, curveLen);
  return crypto.subtle.verify({ name: 'ECDSA', hash }, pubKey, toBufferSource(p1363Sig), toBufferSource(data));
}

// ── Gateway URL 工具 ────────────────────────────────────

/** 将 WebSocket URL 转为对应的 HTTP URL */
function gatewayHttpUrl(gatewayUrl: string, path: string): string {
  try {
    const parsed = new URL(gatewayUrl);
    const scheme = parsed.protocol === 'wss:' ? 'https:' : 'http:';
    return `${scheme}//${parsed.host}${path}`;
  } catch {
    // 降级处理
    const httpUrl = gatewayUrl
      .replace(/^wss:/, 'https:')
      .replace(/^ws:/, 'http:');
    const urlObj = new URL(httpUrl);
    urlObj.pathname = path;
    urlObj.search = '';
    urlObj.hash = '';
    return urlObj.toString();
  }
}

// ── AuthFlow 主类 ───────────────────────────────────────

/**
 * 认证流程管理器 — 负责 AID 注册、登录、token 管理。
 *
 * 完整实现：
 *   - PKI 证书链验证（链验证 + CRL + OCSP + AID 绑定）
 *   - login1/login2 双阶段认证
 *   - token 刷新
 *   - 证书自动续期
 */
export class AuthFlow {
  private _log: ModuleLogger = _noopLog;
  setLogger(log: ModuleLogger): void { this._log = log; }

  private static readonly _INSTANCE_STATE_FIELDS = [
    'access_token',
    'refresh_token',
    'kite_token',
    'access_token_expires_at',
  ] as const;

  private _tokenStore: TokenStore;
  private _crypto: CryptoProvider;
  private _aid: string | null;
  private _deviceId: string;
  private _slotId: string;
  private _rootCaPem: string | null;
  private _verifySsl: boolean;
  private _memIdentity: IdentityRecord | null = null;

  // 缓存
  private _rootCerts: ParsedCert[] | null = null;
  private _gatewayChainCache: Map<string, string[]> = new Map();
  private _gatewayCrlCache: Map<string, { revokedSerials: Set<string>; nextRefreshAt: number }> = new Map();
  private _gatewayOcspCache: Map<string, Map<string, { status: string; nextRefreshAt: number }>> = new Map();
  private _chainVerifiedCache: Map<string, number> = new Map();
  private _chainCacheTtl: number;
  private _gatewayCaVerified: Map<string, boolean> = new Map();

  constructor(opts: {
    tokenStore: TokenStore;
    crypto: CryptoProvider;
    aid?: string | null;
    deviceId?: string;
    slotId?: string;
    rootCaPem?: string | null;
    verifySsl?: boolean;
    chainCacheTtl?: number;
  }) {
    this._tokenStore = opts.tokenStore;
    this._crypto = opts.crypto;
    this._aid = opts.aid ?? null;
    this._deviceId = String(opts.deviceId ?? '').trim();
    this._slotId = String(opts.slotId ?? '').trim();
    this._rootCaPem = opts.rootCaPem ?? null;
    this._verifySsl = opts.verifySsl ?? true;
    this._chainCacheTtl = opts.chainCacheTtl ?? 86400;
  }

  // ── 公开 API ──────────────────────────────────────

  /** 注入内存私钥，禁止 AuthFlow 内部再走 tokenStore 解密 */
  setIdentity(identity: IdentityRecord | null): void {
    this._memIdentity = identity;
    if (identity?.aid) this._aid = String(identity.aid);
  }

  /** 加载本地身份信息 */
  async loadIdentity(aid?: string): Promise<IdentityRecord> {
    const tStart = Date.now();
    this._log.debug(`loadIdentity enter: aid=${aid ?? '<current>'}`);
    try {
      const identity = await this._loadIdentityOrRaise(aid);
      const cert = await this._tokenStore.loadCert(identity.aid as string);
      if (cert) identity.cert = cert;
      const instanceState = await this._loadInstanceState(identity.aid as string);
      if (instanceState) {
        for (const key of AuthFlow._INSTANCE_STATE_FIELDS) {
          if (key in instanceState) {
            (identity as Record<string, unknown>)[key] = instanceState[key];
          }
        }
      }
      this._log.debug(`loadIdentity exit: elapsed=${Date.now() - tStart}ms aid=${identity.aid} has_cert=${!!identity.cert}`);
      return identity;
    } catch (err) {
      this._log.debug(`loadIdentity exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 加载身份，不存在时返回 null */
  async loadIdentityOrNull(aid?: string): Promise<IdentityRecord | null> {
    try {
      return await this.loadIdentity(aid);
    } catch {
      return null;
    }
  }

  /** 与 Node/TS SDK 对齐的别名：加载身份，不存在时返回 null */
  async loadIdentityOrNone(aid?: string): Promise<IdentityRecord | null> {
    return await this.loadIdentityOrNull(aid);
  }

  /** 获取 access_token 过期时间 */
  getAccessTokenExpiry(identity: IdentityRecord): number | null {
    const expiresAt = identity.access_token_expires_at;
    if (typeof expiresAt === 'number') return expiresAt;
    return null;
  }

  setInstanceContext(opts: { deviceId: string; slotId?: string }): void {
    this._deviceId = String(opts.deviceId ?? '').trim();
    this._slotId = String(opts.slotId ?? '').trim();
  }

  /**
   * 认证已有 AID — login1/login2 双阶段流程。
   *
   * 优先复用 tokenStore 里的 cached access_token（未过期且有 refresh_token），
   * 避免每次 authenticate 都走两阶段重登的网络往返。与 Python SDK 行为对齐。
   */
  async authenticate(gatewayUrl: string, aid?: string): Promise<JsonObject> {
    const tStart = Date.now();
    this._log.debug(`authenticate enter: aid=${aid ?? '<current>'} gateway=${gatewayUrl}`);
    try {
      const identity = await this._loadIdentityOrRaise(aid);

      // 优先复用 cached access_token（未过期且有 refresh_token）
      // 避免每次调 authenticate 都走两阶段重登
      // _loadIdentityOrRaise 只使用注入的内存私钥；token 拆到 instance_state，
      // 这里需要主动 _loadInstanceState 才能复用 cached token。
      const instanceState = await this._loadInstanceState(identity.aid as string);
      const identityWithState: IdentityRecord = instanceState
        ? { ...identity, ...instanceState }
        : identity;
      const cachedToken = this._getCachedAccessToken(identityWithState);
      const cachedRefresh = String(identityWithState.refresh_token ?? '');
      if (cachedToken && cachedRefresh) {
        this._log.debug(`authenticate reusing cached token: aid=${identity.aid} expires_at=${identityWithState.access_token_expires_at}`);
        this._aid = identity.aid as string;
        return {
          aid: identity.aid,
          access_token: cachedToken,
          refresh_token: cachedRefresh,
          expires_at: identityWithState.access_token_expires_at,
          gateway: gatewayUrl,
        };
      }

      if (!identity.cert) {
        // 尝试下载恢复证书
        try {
          const recovered = await this._recoverCertViaDownload(gatewayUrl, identity);
          Object.assign(identity, recovered);
          await this._persistIdentity(identity);
        } catch (e) {
          throw new StateError(
            `local certificate missing and recovery failed: ${e}. ` +
            `Run auth.registerAid() to register a new identity.`,
          );
        }
      }

      // 防线 B：发起两步登录前显式校验 cert 公钥与本地 keypair 公钥一致
      this._assertCertMatchesLocalKeypair(identity);

      let login: JsonObject;
      try {
        login = await this._login(gatewayUrl, identity);
      } catch (e) {
        // 注册和登录彻底分离：登录失败绝不触发自动注册。
        throw e;
      }
      this._rememberTokens(identity, login);
      await this._validateNewCert(identity, gatewayUrl);
      await this._persistIdentity(identity);
      this._aid = identity.aid as string;
      this._log.debug(`authenticate exit: elapsed=${Date.now() - tStart}ms aid=${identity.aid}`);
      return {
        aid: identity.aid,
        access_token: identity.access_token,
        refresh_token: identity.refresh_token,
        expires_at: identity.access_token_expires_at,
        gateway: gatewayUrl,
      };
    } catch (err) {
      this._log.debug(`authenticate exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 确保已认证。注册和登录彻底分离：无身份或无 cert 直接抛错。
   */
  async ensureAuthenticated(gatewayUrl: string): Promise<AuthContext> {
    const tStart = Date.now();
    this._log.debug(`ensureAuthenticated enter: gateway=${gatewayUrl}`);
    try {
      const identity = await this._loadIdentityOrRaise();
      if (!identity.cert) {
        throw new StateError(
          `local identity for aid ${identity.aid} has no certificate; ` +
          `call auth.authenticate() to attempt cert recovery, or auth.registerAid() if this is a fresh registration.`,
        );
      }
      // 防线 B：发起两步登录前显式校验
      this._assertCertMatchesLocalKeypair(identity);

      const login = await this._login(gatewayUrl, identity);
      this._rememberTokens(identity, login);
      await this._validateNewCert(identity, gatewayUrl);
      await this._persistIdentity(identity);

      const token = (identity.access_token || identity.token || identity.kite_token) as string;
      if (!token) throw new AuthError('login2 did not return access token');
      this._log.debug(`ensureAuthenticated exit: elapsed=${Date.now() - tStart}ms aid=${identity.aid}`);
      return { token, identity };
    } catch (err) {
      this._log.debug(`ensureAuthenticated exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 使用已有 token 初始化 WebSocket 会话。
   */
  async initializeWithToken(
    transport: TransportLike,
    challenge: RpcMessage | null,
    accessToken: string,
    opts?: {
      deviceId?: string;
      slotId?: string;
      deliveryMode?: JsonObject | null;
      connectionKind?: string;
      shortTtlMs?: number;
      extraInfo?: Record<string, unknown>;
    },
  ): Promise<JsonObject> {
    const tStart = Date.now();
    this._log.debug(`initializeWithToken enter: device_id=${opts?.deviceId ?? this._deviceId} slot_id=${opts?.slotId ?? this._slotId}`);
    try {
      const params = isJsonObject(challenge?.params) ? challenge.params : {};
      const nonce = String(params.nonce ?? '');
      if (!nonce) throw new AuthError('gateway challenge missing nonce');
      this.setInstanceContext({
        deviceId: String(opts?.deviceId ?? this._deviceId ?? ''),
        slotId: String(opts?.slotId ?? this._slotId ?? ''),
      });
      const hello = await this._initializeSession(transport, nonce, accessToken, {
        deviceId: String(opts?.deviceId ?? this._deviceId ?? ''),
        slotId: String(opts?.slotId ?? this._slotId ?? ''),
        deliveryMode: opts?.deliveryMode ?? null,
        connectionKind: opts?.connectionKind ?? 'long',
        shortTtlMs: opts?.shortTtlMs ?? 0,
        extraInfo: opts?.extraInfo,
      });
      this._log.debug(`initializeWithToken exit: elapsed=${Date.now() - tStart}ms`);
      return hello;
    } catch (err) {
      this._log.debug(`initializeWithToken exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 连接会话 — 多策略认证：显式 token → 缓存 token → refresh → 重新登录。
   */
  async connectSession(
    transport: TransportLike,
    challenge: RpcMessage | null,
    gatewayUrl: string,
    accessToken?: string | {
      accessToken?: string;
      deviceId?: string;
      slotId?: string;
      deliveryMode?: JsonObject | null;
      connectionKind?: string;
      shortTtlMs?: number;
      extraInfo?: Record<string, unknown>;
    },
  ): Promise<AuthContext> {
    const tStart = Date.now();
    const explicitTokenInput = isJsonObject(accessToken) ? !!(accessToken as any).accessToken : !!accessToken;
    this._log.debug(`connectSession enter: gateway=${gatewayUrl} has_explicit_token=${explicitTokenInput}`);
    try {
      const params = isJsonObject(challenge?.params) ? challenge.params : {};
      const nonce = String(params.nonce ?? '');
      if (!nonce) throw new AuthError('gateway challenge missing nonce');

      const connectOptions = (isJsonObject(accessToken)
        ? accessToken
        : { accessToken }) as {
            accessToken?: string;
            deviceId?: string;
            slotId?: string;
            deliveryMode?: JsonObject | null;
            connectionKind?: string;
            shortTtlMs?: number;
            extraInfo?: Record<string, unknown>;
          };
      const deviceId = String(connectOptions.deviceId ?? this._deviceId ?? '');
      const slotId = String(connectOptions.slotId ?? this._slotId ?? '');
      const deliveryMode = connectOptions.deliveryMode ?? null;
      const connectionKind = connectOptions.connectionKind ?? 'long';
      const shortTtlMs = connectOptions.shortTtlMs ?? 0;
      const extraInfo = connectOptions.extraInfo;
      this.setInstanceContext({ deviceId, slotId });

      let identity: IdentityRecord | null;
      try {
        identity = await this.loadIdentity();
      } catch {
        identity = null;
      }

      // 策略 1: 显式 token
      const explicitToken = String(connectOptions.accessToken ?? '');
      if (explicitToken && identity !== null) {
        try {
          const hello = await this._initializeSession(transport, nonce, explicitToken, {
            deviceId,
            slotId,
            deliveryMode,
            connectionKind,
            shortTtlMs,
            extraInfo,
          });
          identity.access_token = explicitToken;
          await this._persistIdentity(identity);
          this._log.debug(`connectSession exit: elapsed=${Date.now() - tStart}ms strategy=explicit_token aid=${identity.aid}`);
          return { token: explicitToken, identity, hello };
        } catch (e) {
          if (!(e instanceof AuthError)) throw e;
          // 显式 token 失败，继续尝试其他方式
        }
      }

      // 无本地身份 — 先注册 + 登录
      if (identity === null) {
        const authContext = await this.ensureAuthenticated(gatewayUrl);
        const token = authContext.token as string;
        const hello = await this._initializeSession(transport, nonce, token, {
          deviceId,
          slotId,
          deliveryMode,
          connectionKind,
          shortTtlMs,
          extraInfo,
        });
        this._log.debug(`connectSession exit: elapsed=${Date.now() - tStart}ms strategy=ensure_authenticated`);
        return { ...authContext, hello };
      }

      // 策略 2: 缓存 token
      const cachedToken = this._getCachedAccessToken(identity);
      if (cachedToken) {
        try {
          const hello = await this._initializeSession(transport, nonce, cachedToken, {
            deviceId,
            slotId,
            deliveryMode,
            connectionKind,
            shortTtlMs,
            extraInfo,
          });
          this._log.debug(`connectSession exit: elapsed=${Date.now() - tStart}ms strategy=cached_token aid=${identity.aid}`);
          return { token: cachedToken, identity, hello };
        } catch (e) {
          if (!(e instanceof AuthError)) throw e;
          // 缓存 token 失败，尝试刷新
        }
      }

      // 策略 3: refresh token
      const refreshToken = String(identity.refresh_token ?? '');
      if (refreshToken) {
        try {
          identity = await this.refreshCachedTokens(gatewayUrl, identity);
          const refreshedToken = this._getCachedAccessToken(identity);
          if (refreshedToken) {
            const hello = await this._initializeSession(transport, nonce, refreshedToken, {
              deviceId,
              slotId,
              deliveryMode,
              connectionKind,
              shortTtlMs,
              extraInfo,
            });
            this._log.debug(`connectSession exit: elapsed=${Date.now() - tStart}ms strategy=refresh aid=${identity.aid}`);
            return { token: refreshedToken, identity, hello };
          }
        } catch (e) {
          if (!(e instanceof AuthError)) throw e;
          if (this._refreshFailureRequiresRelogin(e)) {
            await this._clearCachedTokens(identity, e.message);
          }
          // refresh 失败，重新登录
        }
      }

      // 策略 4: 重新登录
      const login = await this.authenticate(gatewayUrl, identity.aid as string | undefined);
      const token = String(login.access_token ?? '');
      if (!token) throw new AuthError('authenticate did not return access_token');
      const hello = await this._initializeSession(transport, nonce, token, {
        deviceId,
        slotId,
        deliveryMode,
        connectionKind,
        shortTtlMs,
        extraInfo,
      });
      identity = await this.loadIdentity(identity.aid as string | undefined);
      this._log.debug(`connectSession exit: elapsed=${Date.now() - tStart}ms strategy=re_login aid=${identity.aid}`);
      return { token, identity, hello };
    } catch (err) {
      this._log.debug(`connectSession exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 刷新 token。
   */
  async refreshCachedTokens(
    gatewayUrl: string,
    identity: IdentityRecord,
  ): Promise<IdentityRecord> {
    const tStart = Date.now();
    this._log.debug(`refreshCachedTokens enter: aid=${identity.aid} gateway=${gatewayUrl}`);
    try {
      const refreshToken = String(identity.refresh_token ?? '');
      if (!refreshToken) {
        await this._clearCachedTokens(identity, 'missing refresh_token');
        throw new AuthError('missing refresh_token');
      }
      const refreshed = await this._refreshAccessToken(gatewayUrl, refreshToken, identity);
      this._rememberTokens(identity, refreshed);
      await this._validateNewCert(identity, gatewayUrl);
      await this._persistIdentity(identity);
      this._log.debug(`refreshCachedTokens exit: elapsed=${Date.now() - tStart}ms aid=${identity.aid}`);
      return identity;
    } catch (err) {
      if (this._refreshFailureRequiresRelogin(err)) {
        await this._clearCachedTokens(identity, err instanceof Error ? err.message : String(err));
      }
      this._log.debug(`refreshCachedTokens exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 统一的对端证书验证入口：时间有效性 + 链验证 + CRL + OCSP + AID 绑定。
   */
  async verifyPeerCertificate(
    gatewayUrl: string,
    certPem: string,
    expectedAid: string,
  ): Promise<void> {
    const tStart = Date.now();
    this._log.debug(`verifyPeerCertificate enter: aid=${expectedAid} gateway=${gatewayUrl}`);
    try {
      const cert = parseCertDer(certPem);
      const now = Date.now() / 1000;
      ensureCertTimeValid(cert, 'peer certificate', now);
      await this._verifyAuthCertChain(gatewayUrl, cert, expectedAid);
      try {
        await this._verifyAuthCertRevocation(gatewayUrl, cert, expectedAid);
      } catch (e) {
        const errMsg = e instanceof Error ? e.message : String(e);
        if (/revoked/i.test(errMsg)) throw e instanceof AuthError ? e : new AuthError(errMsg);
        this._log.warn('[aun_core.auth] CRL check unavailable, degrade and continue:', errMsg);
      }
      try {
        await this._verifyAuthCertOcsp(gatewayUrl, cert, expectedAid);
      } catch (e) {
        const errMsg = e instanceof Error ? e.message : String(e);
        if (/revoked/i.test(errMsg)) throw e instanceof AuthError ? e : new AuthError(errMsg);
        this._log.warn('[aun_core.auth] OCSP check unavailable, degrade and continue:', errMsg);
      }
      if (cert.subjectCN !== expectedAid) {
        throw new AuthError(`peer cert CN mismatch: expected ${expectedAid}, got ${cert.subjectCN || 'none'}`);
      }
      this._log.debug(`verifyPeerCertificate exit: elapsed=${Date.now() - tStart}ms aid=${expectedAid}`);
    } catch (err) {
      this._log.debug(`verifyPeerCertificate exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  // ── 内部方法：短连接 RPC ──────────────────────────

  /** 打开原生 WebSocket，接收 challenge，发送 JSON-RPC，接收响应，关闭 */
  private async _shortRpc(
    gatewayUrl: string,
    method: string,
    params: RpcParams,
  ): Promise<JsonObject> {
    return new Promise((resolve, reject) => {
      let ws: WebSocket;
      try {
        ws = new WebSocket(gatewayUrl);
      } catch (e) {
        reject(new AuthError(`WebSocket 连接失败: ${gatewayUrl}`));
        return;
      }
      let receivedChallenge = false;
      const timeout = globalThis.setTimeout(() => {
        try { ws.close(); } catch { /* 忽略 */ }
        reject(new AuthError(`shortRpc 超时: ${method}`));
      }, 10000);

      ws.onopen = () => { /* 等待首条消息 */ };

      ws.onerror = () => {
        globalThis.clearTimeout(timeout);
        reject(new AuthError(`WebSocket 连接错误: ${gatewayUrl}`));
      };

      ws.onclose = () => {
        if (!receivedChallenge) {
          globalThis.clearTimeout(timeout);
          reject(new AuthError(`WebSocket 在收到 challenge 前关闭`));
        }
      };

      ws.onmessage = (event) => {
        try {
          const msg = typeof event.data === 'string' ? JSON.parse(event.data) : event.data;
          if (!receivedChallenge) {
            // 首条消息是 challenge，忽略并发送 RPC 请求
            receivedChallenge = true;
            const requestPayload = JSON.stringify({
              jsonrpc: '2.0',
              id: `pre-${method}`,
              method,
              params,
            });
            this._log.debug(`short RPC request full: ${JSON.stringify(redactRpcLogPayload(JSON.parse(requestPayload)))}`);
            ws.send(requestPayload);
            return;
          }
          // 第二条消息是 RPC 响应
          globalThis.clearTimeout(timeout);
          this._log.debug(`short RPC response full: method=${method} ${JSON.stringify(redactRpcLogPayload(msg))}`);
          try { ws.close(); } catch { /* 忽略 */ }

          if (msg.error) {
            reject(mapRemoteError(msg.error));
            return;
          }
          const result = msg.result;
          if (!isJsonObject(result)) {
            reject(new ValidationError(`invalid pre-auth response for ${method}`));
            return;
          }
          if (result.success === false) {
            reject(new AuthError(String(result.error ?? `${method} failed`), { data: result }));
            return;
          }
          resolve(result);
        } catch (e) {
          globalThis.clearTimeout(timeout);
          try { ws.close(); } catch { /* 忽略 */ }
          reject(e instanceof Error ? e : new AuthError(String(e)));
        }
      };
    });
  }

  // ── 内部方法：HTTP 请求 ───────────────────────────

  /** fetch GET 返回文本 */
  private async _fetchText(url: string): Promise<string> {
    // 兼容旧浏览器，不使用 AbortSignal.timeout（Chrome 103+ 才支持）
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    try {
      const resp = await fetch(url, { signal: controller.signal });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return await resp.text();
    } catch (e) {
      throw new AuthError(`failed to fetch ${url}: ${e}`);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /** fetch GET 返回 JSON */
  private async _fetchJson(url: string): Promise<JsonObject> {
    // 兼容旧浏览器，不使用 AbortSignal.timeout（Chrome 103+ 才支持）
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    try {
      const resp = await fetch(url, { signal: controller.signal });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const payload = await resp.json();
      if (!isJsonObject(payload)) {
        throw new AuthError(`invalid JSON payload from ${url}`);
      }
      return payload;
    } catch (e) {
      if (e instanceof AuthError) throw e;
      throw new AuthError(`failed to fetch ${url}: ${e}`);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * 从服务端下载指定 AID 的证书（公开 API）。
   *
   * @param gatewayUrl - Gateway WebSocket URL
   * @param aid - 目标 AID
   * @returns 证书 PEM 字符串，如果 AID 未注册则返回 null
   *
   * @example
   * ```typescript
   * const cert = await auth.fetchPeerCert('wss://gateway.example.com', 'alice.aid.com');
   * if (cert) {
   *   console.log('Alice is registered');
   * }
   * ```
   */
  async fetchPeerCert(gatewayUrl: string, aid: string): Promise<string | null> {
    return this._downloadRegisteredCert(gatewayUrl, aid);
  }

  /** 下载服务端当前登记的证书（内部实现）；未注册返回 null */
  private async _downloadRegisteredCert(gatewayUrl: string, aid: string): Promise<string | null> {
    const certUrl = gatewayHttpUrl(gatewayUrl, `/pki/cert/${aid}`);
    try {
      const certPem = await this._fetchText(certUrl);
      if (!certPem || !certPem.includes('BEGIN CERTIFICATE')) return null;
      return certPem;
    } catch {
      return null;
    }
  }

  /** 防线 B：cert 公钥必须与本地 keypair 公钥一致，否则拒绝登录 */
  private _assertCertMatchesLocalKeypair(identity: IdentityRecord): void {
    const aid = identity.aid ?? '?';
    const certPem = identity.cert as string | undefined;
    const localPubB64 = identity.public_key_der_b64 as string | undefined;
    if (!certPem || !localPubB64) {
      throw new AuthError(
        `identity for aid ${aid} missing cert or public key; refusing to start two-phase login`,
      );
    }
    const cert = parseCertDer(certPem);
    const certSpkiB64 = uint8ToBase64(cert.spkiBytes);
    if (certSpkiB64 !== localPubB64) {
      throw new AuthError(
        `local certificate public key does not match local keypair for aid ${aid}; ` +
        `refusing to start two-phase login. Run auth.registerAid() to repair identity.`,
      );
    }
  }

  /** 下载已注册证书恢复本地状态 */
  private async _recoverCertViaDownload(
    gatewayUrl: string,
    identity: IdentityRecord,
  ): Promise<IdentityRecord> {
    const certUrl = gatewayHttpUrl(gatewayUrl, `/pki/cert/${identity.aid}`);
    const certPem = await this._fetchText(certUrl);
    if (!certPem || !certPem.includes('BEGIN CERTIFICATE')) {
      throw new AuthError(`failed to download certificate for ${identity.aid}`);
    }

    // 验证下载证书的公钥与本地密钥对匹配
    const downloadedCert = parseCertDer(certPem);
    const downloadedSpkiB64 = uint8ToBase64(downloadedCert.spkiBytes);
    const localPubB64 = String(identity.public_key_der_b64 ?? '');
    if (localPubB64 && downloadedSpkiB64 !== localPubB64) {
      throw new AuthError(
        `downloaded certificate public key does not match local key pair for ${identity.aid}.`,
      );
    }

    return { ...identity, cert: certPem };
  }

  // ── 内部方法：登录流程 ────────────────────────────

  private async _login(
    gatewayUrl: string,
    identity: IdentityRecord,
  ): Promise<JsonObject> {
    const clientNonce = this._crypto.newClientNonce();

    // Phase 1: 发送 AID + 证书 + client_nonce
    const phase1 = await this._shortRpc(gatewayUrl, 'auth.aid_login1', {
      aid: identity.aid,
      cert: identity.cert,
      client_nonce: clientNonce,
    });

    // 验证服务端响应（证书链 + client_nonce 签名）
    await this._verifyPhase1Response(gatewayUrl, phase1, clientNonce);

    // Phase 2: 签名 server nonce
    const [signature, clientTime] = await this._crypto.signLoginNonce(
      identity.private_key_pem as string,
      phase1.nonce as string,
    );

    const phase2 = await this._shortRpc(gatewayUrl, 'auth.aid_login2', {
      aid: identity.aid,
      request_id: phase1.request_id,
      nonce: phase1.nonce,
      client_time: clientTime,
      signature,
    });

    return phase2;
  }

  /** 刷新 access token */
  private async _refreshAccessToken(
    gatewayUrl: string,
    refreshToken: string,
    identity?: IdentityRecord,
  ): Promise<JsonObject> {
    const params: JsonObject = {
      refresh_token: refreshToken,
      sdk_lang: AUN_SDK_LANG,
      sdk_version: AUN_SDK_VERSION,
    };
    if (identity) {
      const aid = String(identity.aid ?? '').trim();
      const deviceId = String((identity as JsonObject).device_id ?? '').trim();
      const slotId = String((identity as JsonObject).slot_id ?? '').trim();
      const accessToken = String(identity.access_token ?? '').trim();
      if (aid) params.aid = aid;
      if (deviceId) params.device_id = deviceId;
      if (slotId) params.slot_id = slotId;
      if (accessToken) params.access_token = accessToken;
      if (typeof identity.access_token_expires_at === 'number') {
        params.access_token_expires_at = identity.access_token_expires_at;
      }
    }
    const result = await this._shortRpc(gatewayUrl, 'auth.refresh_token', params);
    if (!result.success) {
      throw new AuthError(String(result.error ?? 'refresh failed'), { data: result });
    }
    return result;
  }

  /** 初始化 WebSocket 会话（auth.connect RPC） */
  private async _initializeSession(
    transport: TransportLike,
    nonce: string,
    token: string,
    opts?: {
      deviceId?: string;
      slotId?: string;
      deliveryMode?: JsonObject | null;
      connectionKind?: string;
      shortTtlMs?: number;
      extraInfo?: Record<string, unknown>;
    },
  ): Promise<JsonObject> {
    const connectionKind = opts?.connectionKind ?? 'long';
    const shortTtlMs = opts?.shortTtlMs ?? 0;
    const extraInfo = opts?.extraInfo ?? {};
    // _capabilities 来自 extra_info；可选覆盖默认能力声明，不会透传到服务端
    const overrideCaps = (extraInfo as Record<string, unknown>)._capabilities;
    const capabilities = isJsonObject(overrideCaps) ? overrideCaps : {
      e2ee: true,
      group_e2ee: true,
      // AUN E2EE V2: 默认仅声明 V2 能力（V2-only 客户端）
      supported_p2p_e2ee: ['e2ee_v2'],
      supported_group_e2ee: ['group_e2ee_v2'],
    };
    const request: Record<string, any> = {
      nonce,
      auth: { method: 'kite_token', token },
      protocol: { min: '1.0', max: '1.0' },
      device: { id: String(opts?.deviceId ?? this._deviceId ?? ''), type: 'sdk' },
      client: {
        slot_id: String(opts?.slotId ?? this._slotId ?? ''),
        sdk_lang: AUN_SDK_LANG,
        sdk_version: AUN_SDK_VERSION,
      },
      delivery_mode: opts?.deliveryMode ?? { mode: 'fanout' },
      capabilities,
    };
    // 长短连接选项：默认 long 时不写入 options（保持 wire 兼容）
    if (connectionKind === 'short') {
      const options: Record<string, any> = { kind: 'short' };
      if (shortTtlMs > 0) {
        options.short_ttl_ms = shortTtlMs;
      }
      request.options = options;
    }
    // extra_info：应用层自定义信息（PID/HOME/备注等），踢人时透传给被踢方
    // _ 前缀字段是内部覆盖字段，不透传到服务端
    if (extraInfo && Object.keys(extraInfo).length > 0) {
      const filtered: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(extraInfo)) {
        if (!k.startsWith('_')) filtered[k] = v;
      }
      if (Object.keys(filtered).length > 0) {
        request.extra_info = filtered;
      }
    }
    this._log.debug(`auth.connect send: device_id=${opts?.deviceId ?? ''} slot_id=${opts?.slotId ?? ''} kind=${connectionKind}`);
    const result = await transport.call('auth.connect', request as RpcParams);

    const status = isJsonObject(result) ? result.status : undefined;
    if (status !== 'ok') {
      throw new AuthError(`initialize failed: ${JSON.stringify(result)}`);
    }
    return isJsonObject(result) ? (result as JsonObject) : ({} as JsonObject);
  }

  // ── 内部方法：Phase 1 响应验证 ────────────────────

  private async _verifyPhase1Response(
    gatewayUrl: string,
    result: JsonObject,
    clientNonce: string,
  ): Promise<void> {
    const authCertPem = String(result.auth_cert ?? '');
    const signatureB64 = String(result.client_nonce_signature ?? '');
    if (!authCertPem) throw new AuthError('aid_login1 missing auth_cert');
    if (!signatureB64) throw new AuthError('aid_login1 missing client_nonce_signature');

    let authCert: ParsedCert;
    try {
      authCert = parseCertDer(authCertPem);
    } catch {
      throw new AuthError('aid_login1 returned invalid auth_cert');
    }

    // 验证证书链
    await this._verifyAuthCertChain(gatewayUrl, authCert);
    // 验证 CRL
    try {
      await this._verifyAuthCertRevocation(gatewayUrl, authCert);
    } catch (e) {
      const errMsg = e instanceof Error ? e.message : String(e);
      if (/revoked/i.test(errMsg)) throw e instanceof AuthError ? e : new AuthError(errMsg);
      this._log.warn('[aun_core.auth] CRL check unavailable, degrade and continue:', errMsg);
    }
    // 验证 OCSP
    try {
      await this._verifyAuthCertOcsp(gatewayUrl, authCert);
    } catch (e) {
      const errMsg = e instanceof Error ? e.message : String(e);
      if (/revoked/i.test(errMsg)) throw e instanceof AuthError ? e : new AuthError(errMsg);
      this._log.warn('[aun_core.auth] OCSP check unavailable, degrade and continue:', errMsg);
    }

    // 验证 client_nonce 签名
    try {
      const sigBytes = base64ToUint8(signatureB64);
      const dataBytes = new TextEncoder().encode(clientNonce);
      const valid = await verifyEcdsaSignature(authCert.spkiBytes, sigBytes, dataBytes);
      if (!valid) throw new Error('signature invalid');
    } catch {
      throw new AuthError('aid_login1 server auth signature verification failed');
    }
  }

  // ── 内部方法：证书链验证 ──────────────────────────

  private async _verifyAuthCertChain(
    gatewayUrl: string,
    authCert: ParsedCert,
    chainAid: string = '',
  ): Promise<void> {
    // 检查缓存
    const cachedAt = this._chainVerifiedCache.get(authCert.serialHex);
    const now = Date.now() / 1000;
    if (cachedAt && now - cachedAt < this._chainCacheTtl) return;

    ensureCertTimeValid(authCert, 'auth certificate', now);

    const chain = await this._loadGatewayCaChain(gatewayUrl, chainAid);
    if (!chain.length) {
      throw new AuthError('unable to verify auth certificate chain: missing CA chain');
    }

    const cacheKey = chainAid ? `${gatewayUrl}:${chainAid}` : gatewayUrl;

    // 快速路径：CA 链已预验证过
    if (this._gatewayCaVerified.get(cacheKey)) {
      const issuer = chain[0];
      ensureCertTimeValid(issuer, 'Issuer CA', now);
      if (!issuer.isCA) throw new AuthError('Issuer CA is not marked as CA (fast path)');
      if (!arraysEqual(authCert.issuerRaw, issuer.subjectRaw)) {
        throw new AuthError('auth certificate issuer mismatch');
      }
      await verifyCertSignature(issuer.spkiBytes, authCert);
      this._chainVerifiedCache.set(authCert.serialHex, Date.now() / 1000);
      return;
    }

    // 完整验证路径
    let current = authCert;
    for (let i = 0; i < chain.length; i++) {
      const caCert = chain[i];
      ensureCertTimeValid(caCert, `CA certificate[${i}]`, now);
      if (!arraysEqual(current.issuerRaw, caCert.subjectRaw)) {
        throw new AuthError(`auth certificate issuer mismatch at chain level ${i}`);
      }
      if (!caCert.isCA) {
        throw new AuthError(`CA certificate[${i}] is not marked as CA`);
      }
      await verifyCertSignature(caCert.spkiBytes, current);
      current = caCert;
    }

    // 验证根证书自签名
    const root = chain[chain.length - 1];
    if (!arraysEqual(root.issuerRaw, root.subjectRaw)) {
      throw new AuthError('auth certificate chain root is not self-signed');
    }
    await verifyCertSignature(root.spkiBytes, root);

    // 验证根证书在受信列表中
    const trustedRoots = this._loadTrustedRoots();
    const rootSpkiB64 = uint8ToBase64(root.spkiBytes);
    const isTrusted = trustedRoots.some(
      (trusted) => uint8ToBase64(trusted.spkiBytes) === rootSpkiB64
        && trusted.subjectCN === root.subjectCN,
    );
    if (!isTrusted) {
      throw new AuthError('auth certificate chain is not anchored by a trusted root');
    }

    this._chainVerifiedCache.set(authCert.serialHex, Date.now() / 1000);
    this._gatewayCaVerified.set(cacheKey, true);
  }

  /** 加载 Gateway CA 链（带缓存） */
  private async _loadGatewayCaChain(gatewayUrl: string, chainAid: string = ''): Promise<ParsedCert[]> {
    const cacheKey = chainAid ? `${gatewayUrl}:${chainAid}` : gatewayUrl;
    let cached = this._gatewayChainCache.get(cacheKey);
    if (!cached) {
      cached = await this._fetchGatewayCaChain(gatewayUrl);
      this._gatewayChainCache.set(cacheKey, cached);
    }
    return cached.map((pem) => parseCertDer(pem));
  }

  /** 从 Gateway PKI 端点下载 CA 链 */
  private async _fetchGatewayCaChain(gatewayUrl: string): Promise<string[]> {
    const url = gatewayHttpUrl(gatewayUrl, '/pki/chain');
    const text = await this._fetchText(url);
    return splitPemBundle(text);
  }

  // ── 内部方法：CRL 验证 ────────────────────────────

  private async _verifyAuthCertRevocation(
    gatewayUrl: string,
    authCert: ParsedCert,
    chainAid: string = '',
  ): Promise<void> {
    const chain = await this._loadGatewayCaChain(gatewayUrl, chainAid);
    if (!chain.length) {
      throw new AuthError('unable to verify auth certificate revocation: missing issuer certificate');
    }

    // 跨域场景：CRL 请求发到 peer 所在域
    let crlGatewayUrl = gatewayUrl;
    if (chainAid && chainAid.includes('.')) {
      const peerIssuer = chainAid.split('.').slice(1).join('.');
      const match = gatewayUrl.match(/gateway\.([^:/]+)/);
      const localIssuer = match ? match[1] : '';
      if (localIssuer && peerIssuer !== localIssuer) {
        crlGatewayUrl = gatewayUrl.replace(`gateway.${localIssuer}`, `gateway.${peerIssuer}`);
      }
    }

    const revokedSerials = await this._loadGatewayRevokedSerials(crlGatewayUrl, chain[0]);
    if (revokedSerials.has(authCert.serialHex.toLowerCase())) {
      throw new AuthError('auth certificate has been revoked');
    }
  }

  /** 加载 Gateway 吊销列表（带缓存） */
  private async _loadGatewayRevokedSerials(
    gatewayUrl: string,
    issuerCert: ParsedCert,
  ): Promise<Set<string>> {
    const cached = this._gatewayCrlCache.get(gatewayUrl);
    const now = Date.now() / 1000;
    if (cached && cached.nextRefreshAt > now) {
      return cached.revokedSerials;
    }
    const fresh = await this._fetchGatewayCrl(gatewayUrl, issuerCert);
    this._gatewayCrlCache.set(gatewayUrl, fresh);
    return fresh.revokedSerials;
  }

  /** 从 Gateway PKI 端点获取并验证 CRL */
  private async _fetchGatewayCrl(
    gatewayUrl: string,
    issuerCert: ParsedCert,
  ): Promise<{ revokedSerials: Set<string>; nextRefreshAt: number }> {
    const url = gatewayHttpUrl(gatewayUrl, '/pki/crl.json');
    const payload = await this._fetchJson(url);

    // 简化 CRL 验证：JSON 格式 CRL
    // payload 包含 revoked_serials 数组和签名
    const revokedList = payload.revoked_serials;
    const revokedSerials = new Set<string>();
    if (Array.isArray(revokedList)) {
      for (const s of revokedList) {
        revokedSerials.add(String(s).toLowerCase());
      }
    }

    // 验证 CRL 签名（如果有 crl_pem）
    const crlPem = String(payload.crl_pem ?? '');
    if (crlPem) {
      // CRL PEM 中包含签名信息，由签发者签名
      // 浏览器端简化处理：验证签名数据和签发者公钥
      const signatureB64 = String(payload.signature ?? '');
      const signedDataB64 = String(payload.signed_data ?? '');
      if (signatureB64 && signedDataB64) {
        const sigBytes = base64ToUint8(signatureB64);
        const dataBytes = base64ToUint8(signedDataB64);
        const valid = await verifyEcdsaSignature(issuerCert.spkiBytes, sigBytes, dataBytes);
        if (!valid) throw new AuthError('gateway CRL signature verification failed');
      }
    }

    // 过期时间（最多缓存 24 小时）
    const now = Date.now() / 1000;
    let nextRefreshAt = Number(payload.next_update ?? 0);
    if (!nextRefreshAt) nextRefreshAt = now + 300;
    nextRefreshAt = Math.min(nextRefreshAt, now + 86400);

    return { revokedSerials, nextRefreshAt };
  }

  // ── 内部方法：OCSP 验证 ───────────────────────────

  private async _verifyAuthCertOcsp(
    gatewayUrl: string,
    authCert: ParsedCert,
    chainAid: string = '',
  ): Promise<void> {
    const chain = await this._loadGatewayCaChain(gatewayUrl, chainAid);
    if (!chain.length) {
      throw new AuthError('unable to verify auth certificate OCSP status: missing issuer certificate');
    }
    const status = await this._loadGatewayOcspStatus(gatewayUrl, authCert, chain[0]);
    if (status === 'revoked') throw new AuthError('auth certificate OCSP status is revoked');
    if (status !== 'good') throw new AuthError(`auth certificate OCSP status is ${status}`);
  }

  /** 加载 OCSP 状态（带缓存） */
  private async _loadGatewayOcspStatus(
    gatewayUrl: string,
    authCert: ParsedCert,
    issuerCert: ParsedCert,
  ): Promise<string> {
    const serialHex = authCert.serialHex.toLowerCase();
    let gatewayCache = this._gatewayOcspCache.get(gatewayUrl);
    if (!gatewayCache) {
      gatewayCache = new Map();
      this._gatewayOcspCache.set(gatewayUrl, gatewayCache);
    }
    const cached = gatewayCache.get(serialHex);
    const now = Date.now() / 1000;
    if (cached && cached.nextRefreshAt > now) {
      return cached.status;
    }
    const fresh = await this._fetchGatewayOcspStatus(gatewayUrl, authCert, issuerCert);
    gatewayCache.set(serialHex, fresh);
    return fresh.status;
  }

  /** 从 Gateway PKI 端点获取并验证 OCSP 状态 */
  private async _fetchGatewayOcspStatus(
    gatewayUrl: string,
    authCert: ParsedCert,
    issuerCert: ParsedCert,
  ): Promise<{ status: string; nextRefreshAt: number }> {
    const serialHex = authCert.serialHex.toLowerCase();
    const url = gatewayHttpUrl(gatewayUrl, `/pki/ocsp/${serialHex}`);
    const payload = await this._fetchJson(url);

    const status = String(payload.status ?? '');
    const ocspB64 = String(payload.ocsp_response ?? '');
    if (!ocspB64) throw new AuthError('gateway OCSP endpoint returned no ocsp_response');

    // 简化 OCSP 验证：检查 JSON 响应中的签名
    const signatureB64 = String(payload.signature ?? '');
    const signedDataB64 = String(payload.signed_data ?? '');
    if (signatureB64 && signedDataB64) {
      const sigBytes = base64ToUint8(signatureB64);
      const dataBytes = base64ToUint8(signedDataB64);
      const valid = await verifyEcdsaSignature(issuerCert.spkiBytes, sigBytes, dataBytes);
      if (!valid) throw new AuthError('gateway OCSP signature verification failed');
    }

    // 检查 serial 匹配
    const respSerial = String(payload.serial ?? '').toLowerCase();
    if (respSerial && respSerial !== serialHex) {
      throw new AuthError('gateway OCSP response serial mismatch');
    }

    const effectiveStatus = status || 'unknown';

    const now = Date.now() / 1000;
    let nextRefreshAt = Number(payload.next_update ?? 0);
    if (!nextRefreshAt) nextRefreshAt = now + 300;
    nextRefreshAt = Math.min(nextRefreshAt, now + 86400);

    return { status: effectiveStatus, nextRefreshAt };
  }

  // ── 内部方法：受信根证书 ──────────────────────────

  /** 重新解析信任根证书，供导入新根证书后刷新使用。 */
  reloadTrustedRoots(): number {
    this._rootCerts = null;
    this._gatewayCaVerified.clear();
    this._chainVerifiedCache.clear();
    const roots = this._loadTrustedRoots();
    return roots.length;
  }

  /** 运行时追加根证书 PEM（追加到用户自定义根证书中） */
  addTrustedRootPem(pem: string): void {
    this._rootCaPem = this._rootCaPem ? this._rootCaPem + '\n' + pem : pem;
    // 清空缓存，下次验证时重新加载
    this._rootCerts = null;
    this._gatewayCaVerified.clear();
    this._chainVerifiedCache.clear();
  }

  private _loadTrustedRoots(): ParsedCert[] {
    if (this._rootCerts) return this._rootCerts;

    const roots: ParsedCert[] = [];
    // 加载内置根证书
    if (ROOT_CA_PEM) {
      for (const pem of splitPemBundle(ROOT_CA_PEM)) {
        try {
          roots.push(parseCertDer(pem));
        } catch { /* 跳过无法解析的证书 */ }
      }
    }
    // 加载用户指定的根证书
    if (this._rootCaPem) {
      for (const pem of splitPemBundle(this._rootCaPem)) {
        try {
          const cert = parseCertDer(pem);
          // 去重
          const spkiB64 = uint8ToBase64(cert.spkiBytes);
          if (!roots.some((r) => uint8ToBase64(r.spkiBytes) === spkiB64)) {
            roots.push(cert);
          }
        } catch { /* 跳过 */ }
      }
    }

    if (!roots.length) {
      throw new AuthError('no trusted roots available for auth certificate verification');
    }
    this._rootCerts = roots;
    return roots;
  }

  // ── 内部方法：Token 管理 ──────────────────────────

  private _rememberTokens(identity: IdentityRecord, authResult: JsonObject): void {
    const accessToken = authResult.access_token ?? authResult.token ?? authResult.kite_token;
    const refreshToken = authResult.refresh_token;
    const expiresIn = authResult.expires_in;

    if (typeof accessToken === 'string' && accessToken) identity.access_token = accessToken;
    if (typeof refreshToken === 'string' && refreshToken) identity.refresh_token = refreshToken;
    if (typeof authResult.token === 'string' && authResult.token) identity.kite_token = authResult.token;
    if (typeof expiresIn === 'number' && expiresIn > 0) {
      identity.access_token_expires_at = Math.floor(Date.now() / 1000 + expiresIn);
    } else if (typeof accessToken === 'string' && accessToken) {
      identity.access_token_expires_at = Math.floor(Date.now() / 1000 + 3600);
    }
    // login2 响应含 new_cert 时（证书过半自动续期），暂存待验证
    const newCert = authResult.new_cert;
    if (typeof newCert === 'string' && newCert) identity._pending_new_cert = newCert;
    // 服务端返回 active_cert 用于同步本地 cert.pem
    const activeCert = authResult.active_cert;
    if (typeof activeCert === 'string' && activeCert) identity._pending_active_cert = activeCert;
  }

  private _refreshFailureRequiresRelogin(err: unknown): boolean {
    if (!(err instanceof AuthError)) return false;
    const data = err.data;
    if (isJsonObject(data)) {
      if (data.relogin_required === true) return true;
      const error = String(data.error ?? '').trim().toLowerCase();
      return ['missing refresh_token', 'invalid_or_expired_refresh_token', 'refresh not supported'].includes(error);
    }
    const message = err.message.trim().toLowerCase();
    return ['missing refresh_token', 'invalid_or_expired_refresh_token', 'refresh not supported'].includes(message);
  }

  private async _clearCachedTokens(identity: IdentityRecord, reason: string = ''): Promise<void> {
    const aid = String(identity.aid ?? '');
    const hadToken = Boolean(
      identity.access_token ||
      identity.refresh_token ||
      identity.kite_token ||
      identity.token ||
      identity.access_token_expires_at,
    );
    if (!hadToken) return;
    identity.access_token = '';
    identity.refresh_token = '';
    identity.kite_token = '';
    identity.token = '';
    identity.access_token_expires_at = 0;
    try {
      await this._persistIdentity(identity);
      this._log.warn(`cleared cached tokens after refresh failure: aid=${aid} reason=${reason}`);
    } catch (persistErr) {
      this._log.warn(`failed to persist token cleanup: aid=${aid} err=${persistErr instanceof Error ? persistErr.message : String(persistErr)}`);
    }
  }

  /** 验证服务端返回的 new_cert，通过后正式接受 */
  private async _validateNewCert(
    identity: IdentityRecord,
    gatewayUrl: string = '',
  ): Promise<void> {
    const newCertPem = identity._pending_new_cert;
    delete identity._pending_new_cert;
    if (!newCertPem || typeof newCertPem !== 'string') return;

    try {
      const cert = parseCertDer(newCertPem);
      const aid = String(identity.aid ?? '');

      // 1. CN 必须匹配当前 AID
      if (cert.subjectCN !== aid) {
        throw new AuthError(`new_cert CN mismatch: expected ${aid}, got ${cert.subjectCN || 'none'}`);
      }

      // 2. 公钥必须匹配本地私钥
      const localPubB64 = String(identity.public_key_der_b64 ?? '');
      if (localPubB64) {
        const certSpkiB64 = uint8ToBase64(cert.spkiBytes);
        if (certSpkiB64 !== localPubB64) {
          throw new AuthError('new_cert public key does not match local identity key');
        }
      }

      // 3. 时间有效性
      ensureCertTimeValid(cert, 'new_cert', Date.now() / 1000);

      // 4. 完整证书链验证 + CRL/OCSP
      if (gatewayUrl) {
        await this._verifyAuthCertChain(gatewayUrl, cert);
        try {
          await this._verifyAuthCertRevocation(gatewayUrl, cert);
        } catch (e) {
          const errMsg = e instanceof Error ? e.message : String(e);
          if (/revoked/i.test(errMsg)) throw e instanceof AuthError ? e : new AuthError(errMsg);
          this._log.warn('[aun_core.auth] CRL check unavailable, degrade and continue:', errMsg);
        }
        try {
          await this._verifyAuthCertOcsp(gatewayUrl, cert);
        } catch (e) {
          const errMsg = e instanceof Error ? e.message : String(e);
          if (/revoked/i.test(errMsg)) throw e instanceof AuthError ? e : new AuthError(errMsg);
          this._log.warn('[aun_core.auth] OCSP check unavailable, degrade and continue:', errMsg);
        }
      }

      // 验证通过，正式接受
      identity.cert = newCertPem;
    } catch (e) {
      // 验证失败，静默拒绝（不影响主流程）
      this._log.warn(`reject server-returned new_cert (${identity.aid}):`, e);
    }

    // active_cert 同步：验证公钥匹配后更新本地 cert
    const activeCertPem = identity._pending_active_cert;
    delete identity._pending_active_cert;
    if (typeof activeCertPem === 'string' && activeCertPem) {
      try {
        const actCert = parseCertDer(activeCertPem);
        const localPubB64 = String(identity.public_key_der_b64 ?? '');
        if (localPubB64) {
          const actSpkiB64 = uint8ToBase64(actCert.spkiBytes);
          if (actSpkiB64 === localPubB64) {
            identity.cert = activeCertPem;
          } else {
            this._log.warn(`[auth] active_cert public key mismatches local private key, reject sync (aid=${identity.aid})`);
          }
        }
      } catch (e) {
        this._log.warn(`[auth] active_cert sync exception (${identity.aid}):`, e);
      }
    }
  }

  /** 获取缓存的有效 access_token */
  private _getCachedAccessToken(identity: IdentityRecord): string {
    const accessToken = String(identity.access_token ?? '');
    if (!accessToken) return '';
    const expiresAt = identity.access_token_expires_at;
    if (typeof expiresAt === 'number' && expiresAt <= Date.now() / 1000 + 30) {
      return '';
    }
    return accessToken;
  }

  // ── 内部方法：身份管理 ────────────────────────────

  // AID name 验证：4-64 字符，仅 [a-z0-9_-]，首字符不为 -，不以 guest 开头
  private static readonly _AID_NAME_RE = /^[a-z0-9_][a-z0-9_-]{3,63}$/;

  static _validateAidName(aid: string): void {
    const name = aid.includes('.') ? aid.split('.')[0] : aid;
    if (!AuthFlow._AID_NAME_RE.test(name)) {
      throw new ValidationError(
        `Invalid AID name '${name}': must be 4-64 characters, only [a-z0-9_-], cannot start with '-'`,
      );
    }
    if (name.startsWith('guest')) {
      throw new ValidationError("AID name must not start with 'guest'");
    }
  }

  /** 确保本地有密钥对（没有则生成） */
  // （_ensureLocalIdentity 已移除：注册和登录彻底分离，
  // 登录路径绝不再隐式生成密钥；新身份必须由应用层显式调 registerAid）

  /** 加载身份，不存在或半成品时抛出异常 */
  private async _loadIdentityOrRaise(aid?: string): Promise<IdentityRecord> {
    const requestedAid = aid ?? this._aid;

    // 优先路径：使用注入的内存 identity（私钥已由上层身份存储加载后传入）
    if (this._memIdentity) {
      const mem = this._memIdentity;
      if (requestedAid && String(mem.aid ?? '') !== requestedAid) {
        throw new StateError(`identity mismatch: requested ${requestedAid}, loaded ${mem.aid}`);
      }
      if (!mem.private_key_pem || !mem.public_key_der_b64) {
        throw new StateError(`injected identity for aid ${mem.aid} is incomplete (missing keypair)`);
      }
      if (requestedAid) this._aid = requestedAid;
      return { ...mem };
    }

    if (requestedAid) {
      throw new StateError(
        `no injected identity for aid ${requestedAid}; call AUNClient.loadIdentity(aid) first`,
      );
    }
    throw new StateError('no local identity found, call AUNClient.loadIdentity(aid) first');
  }

  // （_ensureIdentity 已移除：注册和登录彻底分离）

  private async _loadInstanceState(aid: string): Promise<IdentityRecord | null> {
    if (typeof this._tokenStore.loadInstanceState !== 'function') {
      return null;
    }
    return (await this._tokenStore.loadInstanceState(aid, this._deviceId, this._slotId)) as IdentityRecord | null;
  }

  private async _persistIdentity(identity: IdentityRecord): Promise<void> {
    const aid = String(identity.aid ?? '');
    if (!aid) {
      throw new StateError('identity missing aid');
    }

    const instanceState: IdentityRecord = {};
    const instanceStateRecord = instanceState as Record<string, JsonValue | undefined>;
    const persistedRecord = { ...identity } as Record<string, JsonValue | undefined>;
    for (const key of AuthFlow._INSTANCE_STATE_FIELDS) {
      if (key in persistedRecord) {
        instanceStateRecord[key] = persistedRecord[key];
        delete persistedRecord[key];
      }
    }

    const certPem = String(persistedRecord.cert ?? '');
    if (certPem) {
      await this._tokenStore.saveCert(aid, certPem);
    }

    // 实例级字段已拆分到 instance_state，无需从共享 metadata 清理

    if (Object.keys(instanceState).length === 0 || typeof this._tokenStore.updateInstanceState !== 'function') {
      return;
    }
    await this._tokenStore.updateInstanceState(aid, this._deviceId, this._slotId, (current) => {
      Object.assign(current, instanceState);
      return current;
    });
  }

  /** 清理过期的 gateway 缓存条目（供外部定时调用） */
  cleanExpiredCaches(): void {
    const now = Date.now();
    for (const [k, v] of this._gatewayCrlCache) {
      if (v.nextRefreshAt <= now) this._gatewayCrlCache.delete(k);
    }
    for (const [k, v] of this._gatewayOcspCache) {
      for (const [serial, entry] of v) {
        if (entry.nextRefreshAt <= now) v.delete(serial);
      }
      if (v.size === 0) this._gatewayOcspCache.delete(k);
    }
    for (const [k, v] of this._chainVerifiedCache) {
      if (now - v >= 300_000) this._chainVerifiedCache.delete(k);
    }
  }
}

// ── 工具函数 ────────────────────────────────────────────

/** 检查证书时间有效性 */
function ensureCertTimeValid(cert: ParsedCert, label: string, now: number): void {
  if (now + CERT_CLOCK_SKEW_SECONDS < cert.notBefore) throw new AuthError(`${label} is not yet valid`);
  if (now - CERT_CLOCK_SKEW_SECONDS > cert.notAfter) throw new AuthError(`${label} has expired`);
}

/** 比较两个 Uint8Array 是否相等 */
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
