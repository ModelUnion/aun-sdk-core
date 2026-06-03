/**
 * AID 值对象 — 对齐 Python SDK aid.py
 * 不可变，持有证书 + 可选私钥，提供密码学操作。
 */

import { X509Certificate } from 'node:crypto';
import * as codes from './error-codes.js';
import {
  buildAgentMdSignatureBlock,
  certMatchesFingerprint,
  certCommonName,
  certFingerprint as _certFingerprint,
  extractAgentMdAid,
  normalizeAgentMdPayload,
  parseAgentMdTailSignature,
  publicKeyFingerprint,
  publicKeyMatchesFingerprint,
  publicKeyDerB64,
  signBytes,
  verifySignatureWithCert,
} from './cert-utils.js';
import { type Result, resultErr, resultOk } from './result.js';

export interface VerifyResult {
  status: 'verified' | 'invalid' | 'unsigned';
  payload: string;
  aid?: string;
  cert_fingerprint?: string;
  public_key_fingerprint?: string;
  timestamp?: number;
  reason?: string;
}

export class AID {
  readonly aid: string;
  readonly aunPath: string;
  readonly certPem: string;
  readonly deviceId: string;
  readonly slotId: string;
  readonly verifySsl: boolean;
  readonly rootCaPath: string | null;
  readonly debug: boolean;

  /** AIDStore 加载时注入的明文私钥 PEM，供 AUNClient 直接使用（无需 seed）。*/
  readonly privateKeyPem: string;
  private readonly _certValid: boolean;
  private readonly _privateKeyValid: boolean;

  private constructor(params: {
    aid: string;
    aunPath: string;
    certPem: string;
    privateKeyPem: string | null;
    certValid: boolean;
    privateKeyValid: boolean;
    deviceId?: string;
    slotId?: string;
    verifySsl?: boolean;
    rootCaPath?: string | null;
    debug?: boolean;
  }) {
    this.aid = params.aid;
    this.aunPath = params.aunPath;
    this.certPem = params.certPem;
    this.deviceId = params.deviceId ?? '';
    this.slotId = params.slotId ?? 'default';
    this.verifySsl = params.verifySsl ?? false;
    this.rootCaPath = params.rootCaPath ?? null;
    this.debug = params.debug ?? false;
    this._certValid = params.certValid;
    this._privateKeyValid = params.privateKeyValid;
    this.privateKeyPem = params.privateKeyPem ?? '';
  }

  static _create(params: {
    aid: string;
    aunPath: string;
    certPem: string;
    privateKeyPem: string | null;
    certValid: boolean;
    privateKeyValid: boolean;
    deviceId?: string;
    slotId?: string;
    verifySsl?: boolean;
    rootCaPath?: string | null;
    debug?: boolean;
  }): AID {
    return new AID(params);
  }

  get publicKey(): string {
    return publicKeyDerB64(this.certPem);
  }

  get certSubject(): string {
    return certCommonName(this.certPem);
  }

  get certNotBefore(): Date {
    return new Date(new X509Certificate(this.certPem).validFrom);
  }

  get certNotAfter(): Date {
    return new Date(new X509Certificate(this.certPem).validTo);
  }

  get certIssuer(): string {
    return certCommonName(this.certPem, true);
  }

  get certFingerprint(): string {
    return _certFingerprint(this.certPem);
  }

  isCertValid(): boolean {
    return this._certValid;
  }

  isPrivateKeyValid(): boolean {
    return this._privateKeyValid;
  }

  sign(payload: Buffer | string): Result<{ signature: string }> {
    if (!this._privateKeyValid || !this.privateKeyPem) {
      return resultErr(codes.PRIVATE_KEY_NOT_VALID, 'private key is not valid');
    }
    try {
      const data = typeof payload === 'string' ? Buffer.from(payload, 'utf-8') : payload;
      const sig = signBytes(this.privateKeyPem, data);
      return resultOk({ signature: sig.toString('base64') });
    } catch (exc) {
      return resultErr(codes.SIGNATURE_OPERATION_ERROR, String(exc), exc);
    }
  }

  verify(payload: Buffer | string, signature: string): Result<{ valid: boolean }> {
    if (!this._certValid) {
      return resultErr(codes.CERT_NOT_VALID, 'certificate is not valid');
    }
    try {
      const data = typeof payload === 'string' ? Buffer.from(payload, 'utf-8') : payload;
      const sigBuf = Buffer.from(signature, 'base64');
      const valid = verifySignatureWithCert(this.certPem, sigBuf, data);
      return resultOk({ valid });
    } catch (exc) {
      return resultErr(codes.VERIFICATION_OPERATION_ERROR, String(exc), exc);
    }
  }

  signAgentMd(content: string): Result<{ signed: string }> {
    if (!this._privateKeyValid || !this.privateKeyPem) {
      return resultErr(codes.PRIVATE_KEY_NOT_VALID, 'private key is not valid');
    }
    try {
      const payload = normalizeAgentMdPayload(content);
      const sig = signBytes(this.privateKeyPem, Buffer.from(payload, 'utf-8'));
      const block = buildAgentMdSignatureBlock(
        this.certFingerprint,
        Math.trunc(Date.now() / 1000),
        sig.toString('base64'),
        publicKeyFingerprint(this.certPem),
      );
      return resultOk({ signed: payload + block });
    } catch (exc) {
      return resultErr(codes.SIGNATURE_OPERATION_ERROR, String(exc), exc);
    }
  }

  verifyAgentMd(content: string): Result<VerifyResult> {
    if (!this._certValid) {
      return resultErr(codes.CERT_NOT_VALID, 'certificate is not valid');
    }
    try {
      const { payload, fields, parseError } = parseAgentMdTailSignature(String(content ?? ''));
      if (fields === null) {
        if (parseError == null) {
          return resultOk({ status: 'unsigned', payload });
        }
        return resultOk({ status: 'invalid', payload, reason: parseError });
      }

      const payloadAid = extractAgentMdAid(payload);
      if (payloadAid && payloadAid !== this.aid) {
        return resultOk({ status: 'invalid', payload, aid: payloadAid, reason: 'aid mismatch' });
      }
      if (!certMatchesFingerprint(this.certPem, fields.cert_fingerprint)) {
        return resultOk({ status: 'invalid', payload, aid: this.aid, reason: 'certificate fingerprint mismatch' });
      }
      const publicKeyFp = String(fields.public_key_fingerprint ?? '').trim();
      if (publicKeyFp && !publicKeyMatchesFingerprint(this.certPem, publicKeyFp)) {
        return resultOk({ status: 'invalid', payload, aid: this.aid, reason: 'public key fingerprint mismatch' });
      }

      const sigBuf = Buffer.from(fields.signature, 'base64');
      const valid = verifySignatureWithCert(this.certPem, sigBuf, Buffer.from(payload, 'utf-8'));
      if (!valid) {
        return resultOk({
          status: 'invalid',
          payload,
          aid: this.aid,
          cert_fingerprint: fields.cert_fingerprint,
          timestamp: Number(fields.timestamp),
          reason: 'signature verification failed',
        });
      }

      return resultOk({
        status: 'verified',
        payload,
        aid: this.aid,
        cert_fingerprint: fields.cert_fingerprint,
        public_key_fingerprint: publicKeyFp,
        timestamp: Number(fields.timestamp),
      });
    } catch (exc) {
      return resultErr(codes.VERIFICATION_OPERATION_ERROR, String(exc), exc);
    }
  }
}
