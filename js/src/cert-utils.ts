import {
  base64ToUint8,
  certificateSha256Fingerprint,
  ecdsaSignDer,
  ecdsaVerifyDer,
  importCertPublicKeyEcdsa,
  importPrivateKeyEcdsa,
  pemToArrayBuffer,
  uint8ToBase64,
} from './crypto.js';

const AGENT_MD_SIGNATURE_MARKER = '<!-- AUN-SIGNATURE';
const AGENT_MD_SIGNATURE_RE = /^<!-- AUN-SIGNATURE\r?\n(?<body>[\s\S]*?)\r?\n-->\s*$/;
const FINGERPRINT_HEX_RE = /^[0-9a-f]+$/;

export function normalizeFingerprintHex(value: string | null | undefined): string {
  let text = String(value ?? '').trim().toLowerCase();
  if (text.startsWith('sha256:')) text = text.slice('sha256:'.length);
  text = text.replace(/:/g, '');
  if (![16, 64].includes(text.length) || !FINGERPRINT_HEX_RE.test(text)) return '';
  return text;
}

export async function publicKeyFingerprint(certPem: string): Promise<string> {
  const spkiB64 = publicKeyDerB64(certPem);
  if (!spkiB64) return '';
  const spkiBytes = base64ToUint8(spkiB64);
  const spkiInput = spkiBytes.buffer.slice(
    spkiBytes.byteOffset,
    spkiBytes.byteOffset + spkiBytes.byteLength,
  ) as ArrayBuffer;
  const digest = await crypto.subtle.digest('SHA-256', spkiInput);
  const hex = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
  return `sha256:${hex}`;
}

export async function certMatchesFingerprint(certPem: string, fingerprint: string | null | undefined): Promise<boolean> {
  const expected = normalizeFingerprintHex(fingerprint);
  if (!expected) return false;
  const derHex = (await certificateSha256Fingerprint(certPem)).slice('sha256:'.length);
  const spki = await publicKeyFingerprint(certPem);
  const spkiHex = spki ? spki.slice('sha256:'.length) : '';
  if (expected.length === 16) return derHex.slice(0, 16) === expected || spkiHex.slice(0, 16) === expected;
  return derHex === expected || spkiHex === expected;
}

export async function publicKeyMatchesFingerprint(certPem: string, fingerprint: string | null | undefined): Promise<boolean> {
  const expected = normalizeFingerprintHex(fingerprint);
  if (!expected) return false;
  const spki = await publicKeyFingerprint(certPem);
  const spkiHex = spki ? spki.slice('sha256:'.length) : '';
  if (expected.length === 16) return spkiHex.slice(0, 16) === expected;
  return spkiHex === expected;
}

export function parseAgentMdTailSignature(content: string): { payload: string; fields: Record<string, string> | null; parseError?: string } {
  const idx = content.lastIndexOf(AGENT_MD_SIGNATURE_MARKER);
  if (idx < 0) return { payload: content, fields: null };
  if (idx > 0 && content[idx - 1] !== '\n' && content[idx - 1] !== '\r') return { payload: content, fields: null };
  const tail = content.slice(idx);
  const match = tail.match(AGENT_MD_SIGNATURE_RE);
  if (!match) return { payload: content.slice(0, idx), fields: null, parseError: 'malformed signature block' };
  const fields: Record<string, string> = {};
  for (const rawLine of match.groups?.body?.split(/\r?\n/) ?? []) {
    const line = rawLine.trim();
    if (!line) continue;
    const colon = line.indexOf(':');
    if (colon < 0) return { payload: content.slice(0, idx), fields: null, parseError: `malformed signature field: ${line}` };
    fields[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
  }
  for (const req of ['cert_fingerprint', 'timestamp', 'signature']) {
    if (!fields[req]) return { payload: content.slice(0, idx), fields: null, parseError: `signature block missing ${req}` };
  }
  if (!normalizeFingerprintHex(fields.cert_fingerprint)) {
    return { payload: content.slice(0, idx), fields: null, parseError: 'invalid cert_fingerprint' };
  }
  if (fields.public_key_fingerprint && !normalizeFingerprintHex(fields.public_key_fingerprint)) {
    return { payload: content.slice(0, idx), fields: null, parseError: 'invalid public_key_fingerprint' };
  }
  if (!Number.isFinite(Number(fields.timestamp))) {
    return { payload: content.slice(0, idx), fields: null, parseError: 'invalid timestamp' };
  }
  return { payload: content.slice(0, idx), fields };
}

export function normalizeAgentMdPayload(content: string): string {
  let payload = parseAgentMdTailSignature(String(content ?? '')).payload;
  if (payload && !payload.endsWith('\n') && !payload.endsWith('\r')) payload += '\n';
  return payload;
}

export function buildAgentMdSignatureBlock(
  certFingerprint: string,
  timestamp: number,
  signatureB64: string,
  publicKeyFp = '',
): string {
  const lines = [
    AGENT_MD_SIGNATURE_MARKER,
    `cert_fingerprint: ${certFingerprint}`,
  ];
  if (publicKeyFp) lines.push(`public_key_fingerprint: ${publicKeyFp}`);
  lines.push(`timestamp: ${Math.trunc(timestamp)}`, `signature: ${signatureB64}`, '-->');
  return lines.join('\n');
}

export function extractAgentMdAid(payload: string): string {
  const lines = payload.replace(/^\ufeff/, '').split(/\r?\n/);
  if (!lines.length || lines[0].trim() !== '---') return '';
  for (const line of lines.slice(1)) {
    const t = line.trim();
    if (t === '---') break;
    if (t.startsWith('aid:')) {
      let v = t.slice(4).trim();
      if (v.length >= 2 && v[0] === v[v.length - 1] && (v[0] === '"' || v[0] === "'")) v = v.slice(1, -1);
      return v.trim();
    }
  }
  return '';
}

function readDerLength(data: Uint8Array, offset: number): { value: number; lenBytes: number } | null {
  if (offset >= data.length) return null;
  const first = data[offset]!;
  if (first < 0x80) return { value: first, lenBytes: 1 };
  const numBytes = first & 0x7f;
  if (numBytes === 0 || numBytes > 4) return null;
  let value = 0;
  for (let i = 0; i < numBytes; i++) value = (value << 8) | data[offset + 1 + i]!;
  return { value, lenBytes: 1 + numBytes };
}

function readDerTlv(data: Uint8Array, offset: number): { tag: number; valueStart: number; valueEnd: number; fullEnd: number } | null {
  const len = readDerLength(data, offset + 1);
  if (!len) return null;
  const valueStart = offset + 1 + len.lenBytes;
  const valueEnd = valueStart + len.value;
  if (valueEnd > data.length) return null;
  return { tag: data[offset]!, valueStart, valueEnd, fullEnd: valueEnd };
}

export function publicKeyDerB64(certPem: string): string {
  const certDer = new Uint8Array(pemToArrayBuffer(certPem));
  const cert = readDerTlv(certDer, 0);
  if (!cert || cert.tag !== 0x30) return '';
  const tbs = readDerTlv(certDer, cert.valueStart);
  if (!tbs || tbs.tag !== 0x30) return '';
  let pos = tbs.valueStart;
  if (certDer[pos] === 0xa0) pos = readDerTlv(certDer, pos)?.fullEnd ?? pos;
  for (let i = 0; i < 5; i++) pos = readDerTlv(certDer, pos)?.fullEnd ?? pos;
  const spki = readDerTlv(certDer, pos);
  if (!spki || spki.tag !== 0x30) return '';
  return uint8ToBase64(certDer.slice(pos, spki.fullEnd));
}

// ── 证书元数据解析（subject CN / issuer CN / 有效期）────────────────

/** 从 Name(SEQUENCE) 范围内提取 CN（OID 2.5.4.3 = 55 04 03）。失败返回 ''。 */
function extractCommonName(der: Uint8Array, nameStart: number, nameEnd: number): string {
  let pos = nameStart;
  while (pos < nameEnd) {
    const set = readDerTlv(der, pos);
    if (!set || set.tag !== 0x31) break;
    let rpos = set.valueStart;
    while (rpos < set.valueEnd) {
      const seq = readDerTlv(der, rpos);
      if (!seq || seq.tag !== 0x30) break;
      const oid = readDerTlv(der, seq.valueStart);
      if (oid && oid.tag === 0x06) {
        const isCN = oid.valueEnd - oid.valueStart === 3
          && der[oid.valueStart] === 0x55 && der[oid.valueStart + 1] === 0x04 && der[oid.valueStart + 2] === 0x03;
        if (isCN) {
          const val = readDerTlv(der, oid.fullEnd);
          if (val) return new TextDecoder().decode(der.slice(val.valueStart, val.valueEnd));
        }
      }
      rpos = seq.fullEnd;
    }
    pos = set.fullEnd;
  }
  return '';
}

/** 解析 UTCTime(0x17) / GeneralizedTime(0x18) 为 Date。失败返回 null。 */
function parseDerTime(der: Uint8Array, offset: number): Date | null {
  const tlv = readDerTlv(der, offset);
  if (!tlv) return null;
  const raw = new TextDecoder().decode(der.slice(tlv.valueStart, tlv.valueEnd));
  if (tlv.tag === 0x17) {
    // UTCTime: YYMMDDHHMMSSZ
    const yy = parseInt(raw.slice(0, 2), 10);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    const ms = Date.UTC(year, parseInt(raw.slice(2, 4), 10) - 1, parseInt(raw.slice(4, 6), 10),
      parseInt(raw.slice(6, 8), 10), parseInt(raw.slice(8, 10), 10), parseInt(raw.slice(10, 12), 10));
    return Number.isNaN(ms) ? null : new Date(ms);
  }
  if (tlv.tag === 0x18) {
    // GeneralizedTime: YYYYMMDDHHMMSSZ
    const ms = Date.UTC(parseInt(raw.slice(0, 4), 10), parseInt(raw.slice(4, 6), 10) - 1, parseInt(raw.slice(6, 8), 10),
      parseInt(raw.slice(8, 10), 10), parseInt(raw.slice(10, 12), 10), parseInt(raw.slice(12, 14), 10));
    return Number.isNaN(ms) ? null : new Date(ms);
  }
  return null;
}

export interface CertMetadata {
  subject: string;
  issuer: string;
  notBefore: Date;
  notAfter: Date;
}

/**
 * 从证书 PEM 解析元数据：subject CN、issuer CN、有效期。
 * 对齐 Python（cert_common_name）/ Go（Subject.CommonName / Issuer.CommonName）。
 * 解析失败的字段降级为空串 / epoch Date，不抛异常。
 */
export function parseCertMetadata(certPem: string): CertMetadata {
  const fallback: CertMetadata = { subject: '', issuer: '', notBefore: new Date(0), notAfter: new Date(0) };
  try {
    const der = new Uint8Array(pemToArrayBuffer(certPem));
    const cert = readDerTlv(der, 0);
    if (!cert || cert.tag !== 0x30) return fallback;
    const tbs = readDerTlv(der, cert.valueStart);
    if (!tbs || tbs.tag !== 0x30) return fallback;
    let pos = tbs.valueStart;
    if (der[pos] === 0xa0) pos = readDerTlv(der, pos)?.fullEnd ?? pos; // version
    pos = readDerTlv(der, pos)?.fullEnd ?? pos; // serialNumber
    pos = readDerTlv(der, pos)?.fullEnd ?? pos; // signature AlgId

    const issuer = readDerTlv(der, pos);
    if (!issuer || issuer.tag !== 0x30) return fallback;
    const issuerCN = extractCommonName(der, issuer.valueStart, issuer.valueEnd);
    pos = issuer.fullEnd;

    const validity = readDerTlv(der, pos);
    if (!validity || validity.tag !== 0x30) return fallback;
    const notBefore = parseDerTime(der, validity.valueStart);
    const nb = readDerTlv(der, validity.valueStart);
    const notAfter = nb ? parseDerTime(der, nb.fullEnd) : null;
    pos = validity.fullEnd;

    const subject = readDerTlv(der, pos);
    if (!subject || subject.tag !== 0x30) return fallback;
    const subjectCN = extractCommonName(der, subject.valueStart, subject.valueEnd);

    return {
      subject: subjectCN,
      issuer: issuerCN,
      notBefore: notBefore ?? new Date(0),
      notAfter: notAfter ?? new Date(0),
    };
  } catch {
    return fallback;
  }
}

export async function signBytes(privateKeyPem: string, payload: Uint8Array): Promise<string> {
  const key = await importPrivateKeyEcdsa(privateKeyPem);
  return uint8ToBase64(await ecdsaSignDer(key, payload));
}

export async function verifySignatureWithCert(certPem: string, signatureB64: string, data: Uint8Array): Promise<boolean> {
  try {
    const key = await importCertPublicKeyEcdsa(certPem);
    return await ecdsaVerifyDer(key, base64ToUint8(signatureB64), data);
  } catch {
    return false;
  }
}

export { certificateSha256Fingerprint as certFingerprint };
