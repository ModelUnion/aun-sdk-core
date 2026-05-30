/**
 * 证书与签名工具函数 — 对齐 Python SDK _cert_utils.py
 * 从 namespaces/auth.ts 提取的纯函数，供 AID/AIDStore 使用。
 */

import { createSign, createVerify, X509Certificate, createHash } from 'node:crypto';
import { certificateSha256Fingerprint } from './crypto.js';

const AGENT_MD_SIGNATURE_MARKER = '<!-- AUN-SIGNATURE';
const AGENT_MD_SIGNATURE_RE = /^<!-- AUN-SIGNATURE\r?\n(?<body>[\s\S]*?)\r?\n-->\s*$/;
const AGENT_MD_FINGERPRINT_RE = /^sha256:[0-9a-f]{64}$/;

/** 解析 agent.md 尾部签名块 */
export function parseAgentMdTailSignature(content: string): {
  payload: string;
  fields: Record<string, string> | null;
  parseError?: string;
} {
  const idx = content.lastIndexOf(AGENT_MD_SIGNATURE_MARKER);
  if (idx < 0) return { payload: content, fields: null };
  if (idx > 0 && content[idx - 1] !== '\n' && content[idx - 1] !== '\r') {
    return { payload: content, fields: null };
  }
  const tail = content.slice(idx);
  const match = tail.match(AGENT_MD_SIGNATURE_RE);
  if (!match) {
    return { payload: content.slice(0, idx), fields: null, parseError: 'malformed signature block' };
  }
  const fields: Record<string, string> = {};
  for (const rawLine of match.groups?.body?.split(/\r?\n/) ?? []) {
    const line = rawLine.trim();
    if (!line) continue;
    const colon = line.indexOf(':');
    if (colon < 0) {
      return { payload: content.slice(0, idx), fields: null, parseError: `malformed signature field: ${line}` };
    }
    fields[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
  }
  for (const req of ['cert_fingerprint', 'timestamp', 'signature']) {
    if (!fields[req]) {
      return { payload: content.slice(0, idx), fields: null, parseError: `signature block missing ${req}` };
    }
  }
  if (!AGENT_MD_FINGERPRINT_RE.test(fields.cert_fingerprint.toLowerCase())) {
    return { payload: content.slice(0, idx), fields: null, parseError: 'invalid cert_fingerprint' };
  }
  if (!Number.isFinite(Number(fields.timestamp))) {
    return { payload: content.slice(0, idx), fields: null, parseError: 'invalid timestamp' };
  }
  return { payload: content.slice(0, idx), fields };
}

/** 从 agent.md frontmatter 提取 aid 字段 */
export function extractAgentMdAid(payload: string): string {
  const lines = payload.replace(/^﻿/, '').split(/\r?\n/);
  if (!lines.length || lines[0].trim() !== '---') return '';
  for (const line of lines.slice(1)) {
    const t = line.trim();
    if (t === '---') break;
    if (t.startsWith('aid:')) {
      let v = t.slice(4).trim();
      if (v.length >= 2 && v[0] === v[v.length - 1] && (v[0] === '"' || v[0] === "'")) {
        v = v.slice(1, -1);
      }
      return v.trim();
    }
  }
  return '';
}

/** 规范化 agent.md payload（去除签名块，确保末尾换行） */
export function normalizeAgentMdPayload(content: string): string {
  let payload = parseAgentMdTailSignature(String(content ?? '')).payload;
  if (payload && !payload.endsWith('\n') && !payload.endsWith('\r')) payload += '\n';
  return payload;
}

/** 构造 agent.md 签名块 */
export function buildAgentMdSignatureBlock(certFingerprint: string, timestamp: number, signatureB64: string): string {
  return [
    '<!-- AUN-SIGNATURE',
    `cert_fingerprint: ${certFingerprint}`,
    `timestamp: ${Math.trunc(timestamp)}`,
    `signature: ${signatureB64}`,
    '-->',
  ].join('\n');
}

/** 使用私钥签名（ECDSA P-256 SHA-256，DER 编码输出） */
export function signBytes(privateKeyPem: string, payload: Buffer): Buffer {
  const signer = createSign('SHA256');
  signer.update(payload);
  signer.end();
  return signer.sign(privateKeyPem);
}

/** 使用证书公钥验签 */
export function verifySignatureWithCert(certPem: string, signature: Buffer, data: Buffer): boolean {
  try {
    const cert = new X509Certificate(certPem);
    const verifier = createVerify('SHA256');
    verifier.update(data);
    verifier.end();
    return verifier.verify(cert.publicKey, signature);
  } catch {
    return false;
  }
}

/** 获取证书 Subject CN */
export function certCommonName(certPem: string, issuer = false): string {
  try {
    const cert = new X509Certificate(certPem);
    const dn = issuer ? cert.issuer : cert.subject;
    const match = dn.match(/(?:^|,\s*)CN=([^,\n]+)/);
    return match?.[1]?.trim() ?? '';
  } catch {
    return '';
  }
}

/** 检查证书有效期，返回 '' | 'expired' | 'not_yet_valid' */
export function certTimeError(certPem: string): '' | 'expired' | 'not_yet_valid' {
  try {
    const cert = new X509Certificate(certPem);
    const now = Date.now();
    if (now < new Date(cert.validFrom).getTime()) return 'not_yet_valid';
    if (now > new Date(cert.validTo).getTime()) return 'expired';
    return '';
  } catch {
    return 'expired';
  }
}

/** 获取证书公钥 DER base64 */
export function publicKeyDerB64(certPem: string): string {
  try {
    const cert = new X509Certificate(certPem);
    return cert.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  } catch {
    return '';
  }
}

/** 证书 SHA-256 指纹（复用 crypto.ts 的实现） */
export { certificateSha256Fingerprint as certFingerprint };
