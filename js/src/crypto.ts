// ── 密码学提供者（浏览器 SubtleCrypto 实现）──────────────
// 所有操作均为异步（SubtleCrypto API 要求）

/** Base64 编码（浏览器兼容） */
function uint8ToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/** Base64 解码（浏览器兼容） */
function base64ToUint8(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** 将 ArrayBuffer 转为 PEM 格式字符串 */
function arrayBufferToPem(buffer: ArrayBuffer, label: string): string {
  const b64 = uint8ToBase64(new Uint8Array(buffer));
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

/** 从 PEM 字符串中提取 DER 数据 */
function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s/g, '');
  const bytes = base64ToUint8(b64);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function toArrayBuffer(bytes: Uint8Array | ArrayBuffer | ArrayBufferLike): ArrayBuffer {
  if (bytes instanceof ArrayBuffer) {
    return bytes.slice(0);
  }
  const cloned = Uint8Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
  return cloned.buffer.slice(cloned.byteOffset, cloned.byteOffset + cloned.byteLength) as ArrayBuffer;
}

function toBufferSource(bytes: Uint8Array | ArrayBuffer | ArrayBufferLike): BufferSource {
  if (bytes instanceof ArrayBuffer) {
    return bytes.slice(0);
  }
  return Uint8Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
}

/** 密码学提供者 — 使用浏览器 SubtleCrypto 实现 P-256 ECDSA */
export class CryptoProvider {
  static readonly curveName = 'P-256';

  /**
   * 生成 P-256 ECDSA 密钥对（异步）。
   * 返回 { private_key_pem, public_key_der_b64, curve }
   */
  async generateIdentity(): Promise<{
    private_key_pem: string;
    public_key_der_b64: string;
    curve: string;
  }> {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, // extractable
      ['sign', 'verify'],
    );

    // 导出 PKCS8 私钥
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const privateKeyPem = arrayBufferToPem(pkcs8, 'PRIVATE KEY');

    // 导出 SPKI 公钥（DER 格式，base64 编码）
    const spki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const publicKeyDerB64 = uint8ToBase64(new Uint8Array(spki));

    return {
      private_key_pem: privateKeyPem,
      public_key_der_b64: publicKeyDerB64,
      curve: CryptoProvider.curveName,
    };
  }

  generateIdentityAsync(): Promise<{
    private_key_pem: string;
    public_key_der_b64: string;
    curve: string;
  }> {
    return this.generateIdentity();
  }

  /**
   * 签名登录 nonce（异步）。
   * 返回 [signatureBase64, clientTime]
   *
   * 签名数据格式: "{nonce}:{clientTime}"
   * 使用 ECDSA + SHA-256
   */
  async signLoginNonce(
    privateKeyPem: string,
    nonce: string,
    clientTime?: string,
  ): Promise<[string, string]> {
    const usedTime = clientTime ?? String(Math.floor(Date.now() / 1000));
    const signData = new TextEncoder().encode(`${nonce}:${usedTime}`);

    // 导入 PEM 私钥
    const pkcs8 = pemToArrayBuffer(privateKeyPem);
    const cryptoKey = await crypto.subtle.importKey(
      'pkcs8',
      pkcs8,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    );

    // 签名（SubtleCrypto 返回 IEEE P1363 格式，与 Python cryptography DER 不同）
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      cryptoKey,
      signData,
    );

    // 将 P1363 格式转为 DER 格式（与 Python SDK 兼容）
    const derSignature = p1363ToDer(new Uint8Array(signature));
    return [uint8ToBase64(derSignature), usedTime];
  }

  signLoginNonceAsync(
    privateKeyPem: string,
    nonce: string,
    clientTime?: string,
  ): Promise<[string, string]> {
    return this.signLoginNonce(privateKeyPem, nonce, clientTime);
  }

  /** 生成客户端 nonce（12 字节随机数的 base64 编码） */
  newClientNonce(): string {
    const bytes = new Uint8Array(12);
    crypto.getRandomValues(bytes);
    return uint8ToBase64(bytes);
  }
}

// ── 签名格式转换工具 ──────────────────────────────────────

/**
 * 将 IEEE P1363 格式签名转为 DER 格式。
 * SubtleCrypto 输出 P1363（r || s 固定长度拼接），
 * Python cryptography 使用 DER（ASN.1 编码）。
 */
function p1363ToDer(p1363: Uint8Array): Uint8Array {
  const halfLen = p1363.length / 2;
  const r = trimLeadingZeros(p1363.slice(0, halfLen));
  const s = trimLeadingZeros(p1363.slice(halfLen));

  // 若最高位为 1 需要前导 0x00（ASN.1 有符号整数）
  const rPadded = r[0] & 0x80 ? new Uint8Array([0, ...r]) : r;
  const sPadded = s[0] & 0x80 ? new Uint8Array([0, ...s]) : s;

  const rTlv = new Uint8Array([0x02, rPadded.length, ...rPadded]);
  const sTlv = new Uint8Array([0x02, sPadded.length, ...sPadded]);

  const sequenceLen = rTlv.length + sTlv.length;
  const der = new Uint8Array(2 + sequenceLen);
  der[0] = 0x30; // SEQUENCE
  der[1] = sequenceLen;
  der.set(rTlv, 2);
  der.set(sTlv, 2 + rTlv.length);
  return der;
}

/** 将 DER 格式 ECDSA 签名转为 IEEE P1363。 */
function derToP1363(der: Uint8Array, coordLen = 32): Uint8Array {
  if (der[0] !== 0x30) throw new Error('invalid DER signature: missing SEQUENCE');
  let offset = 2;
  if (der[1] & 0x80) {
    const lenBytes = der[1] & 0x7f;
    offset = 2 + lenBytes;
  }
  if (der[offset] !== 0x02) throw new Error('invalid DER signature: missing r');
  const rLen = der[offset + 1];
  let r = der.slice(offset + 2, offset + 2 + rLen);
  offset += 2 + rLen;
  if (der[offset] !== 0x02) throw new Error('invalid DER signature: missing s');
  const sLen = der[offset + 1];
  let s = der.slice(offset + 2, offset + 2 + sLen);
  while (r.length > 1 && r[0] === 0) r = r.slice(1);
  while (s.length > 1 && s[0] === 0) s = s.slice(1);
  if (r.length > coordLen || s.length > coordLen) {
    throw new Error('invalid DER signature: coordinate too long');
  }
  const out = new Uint8Array(coordLen * 2);
  out.set(r, coordLen - r.length);
  out.set(s, coordLen * 2 - s.length);
  return out;
}

/** 去除前导零字节（保留至少一个字节） */
function trimLeadingZeros(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start++;
  }
  return bytes.slice(start);
}

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

function readDerTlvRange(
  data: Uint8Array,
  offset: number,
  expectedTag?: number,
): { fullStart: number; valueStart: number; valueEnd: number; fullEnd: number; tag: number } | null {
  if (offset >= data.length) return null;
  const tag = data[offset];
  if (expectedTag !== undefined && tag !== expectedTag) return null;
  const len = parseDerLength(data, offset + 1);
  if (!len) return null;
  const valueStart = offset + 1 + len.lenBytes;
  const valueEnd = valueStart + len.value;
  if (valueStart > data.length || valueEnd > data.length) return null;
  return { fullStart: offset, valueStart, valueEnd, fullEnd: valueEnd, tag };
}

function skipDerTlv(data: Uint8Array, offset: number, expectedTag?: number): number | null {
  const tlv = readDerTlvRange(data, offset, expectedTag);
  return tlv?.fullEnd ?? null;
}

function extractSpkiFromCertPem(certPem: string): ArrayBuffer {
  const certDer = new Uint8Array(pemToArrayBuffer(certPem));

  const cert = readDerTlvRange(certDer, 0, 0x30);
  if (!cert) {
    throw new Error('unable to extract SPKI public key from certificate');
  }

  const tbs = readDerTlvRange(certDer, cert.valueStart, 0x30);
  if (!tbs) {
    throw new Error('unable to extract SPKI public key from certificate');
  }

  let pos = tbs.valueStart;
  if (certDer[pos] === 0xa0) {
    const next = skipDerTlv(certDer, pos, 0xa0);
    if (next === null || next > tbs.valueEnd) {
      throw new Error('unable to extract SPKI public key from certificate');
    }
    pos = next;
  }

  for (const tag of [0x02, 0x30, 0x30, 0x30, 0x30]) {
    const next = skipDerTlv(certDer, pos, tag);
    if (next === null || next > tbs.valueEnd) {
      throw new Error('unable to extract SPKI public key from certificate');
    }
    pos = next;
  }

  const spki = readDerTlvRange(certDer, pos, 0x30);
  if (!spki || spki.fullEnd > tbs.valueEnd) {
    throw new Error('unable to extract SPKI public key from certificate');
  }
  const spkiDer = certDer.slice(spki.fullStart, spki.fullEnd);
  return spkiDer.buffer.slice(
    spkiDer.byteOffset,
    spkiDer.byteOffset + spkiDer.byteLength,
  ) as ArrayBuffer;
}

async function certificateSha256Fingerprint(certPem: string): Promise<string> {
  const der = pemToArrayBuffer(certPem);
  const hash = await crypto.subtle.digest('SHA-256', der);
  const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `sha256:${hex}`;
}

async function importCertPublicKeyEcdsa(certPem: string): Promise<CryptoKey> {
  const spki = extractSpkiFromCertPem(certPem);
  return crypto.subtle.importKey(
    'spki',
    spki,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify'],
  );
}

const ecdsaKeyCache = new Map<string, CryptoKey>();

async function importPrivateKeyEcdsa(pem: string): Promise<CryptoKey> {
  const cached = ecdsaKeyCache.get(pem);
  if (cached) return cached;
  const pkcs8 = pemToArrayBuffer(pem);
  const key = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign'],
  );
  ecdsaKeyCache.set(pem, key);
  return key;
}

async function ecdsaSignDer(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    toBufferSource(data),
  );
  return p1363ToDer(new Uint8Array(sig));
}

async function ecdsaVerifyDer(
  publicKey: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  const p1363 = derToP1363(signature);
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    toBufferSource(p1363),
    toBufferSource(data),
  );
}

// 导出工具函数，供其他模块使用
export {
  uint8ToBase64,
  base64ToUint8,
  arrayBufferToPem,
  pemToArrayBuffer,
  p1363ToDer,
  derToP1363,
  toArrayBuffer,
  toBufferSource,
  certificateSha256Fingerprint,
  importCertPublicKeyEcdsa,
  importPrivateKeyEcdsa,
  ecdsaSignDer,
  ecdsaVerifyDer,
};
