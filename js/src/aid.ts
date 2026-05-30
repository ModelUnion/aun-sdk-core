import * as codes from './error-codes.js';
import {
  buildAgentMdSignatureBlock,
  certFingerprint,
  extractAgentMdAid,
  normalizeAgentMdPayload,
  parseAgentMdTailSignature,
  parseCertMetadata,
  publicKeyDerB64,
  signBytes,
  verifySignatureWithCert,
} from './cert-utils.js';
import { resultErr, resultOk, type Result } from './result.js';

export interface VerifyResult {
  status: 'verified' | 'invalid' | 'unsigned';
  payload: string;
  aid?: string;
  cert_fingerprint?: string;
  timestamp?: number;
  reason?: string;
}

export class AID {
  readonly aid: string;
  readonly aunPath: string;
  readonly certPem: string;
  readonly publicKey: string;
  readonly certSubject: string;
  readonly certNotBefore: Date;
  readonly certNotAfter: Date;
  readonly certIssuer: string;
  readonly deviceId: string;
  readonly slotId: string;
  private readonly _privateKeyPem: string | null;
  private readonly _certValid: boolean;
  private readonly _privateKeyValid: boolean;
  private _certFingerprint = '';

  private constructor(params: { aid: string; aunPath: string; certPem: string; privateKeyPem: string | null; certValid: boolean; privateKeyValid: boolean; deviceId?: string; slotId?: string }) {
    this.aid = params.aid;
    this.aunPath = params.aunPath;
    this.deviceId = params.deviceId ?? '';
    this.slotId = params.slotId ?? 'default';
    this.certPem = params.certPem;
    this.publicKey = publicKeyDerB64(params.certPem);
    const meta = parseCertMetadata(params.certPem);
    this.certSubject = meta.subject;
    this.certIssuer = meta.issuer;
    this.certNotBefore = meta.notBefore;
    this.certNotAfter = meta.notAfter;
    this._privateKeyPem = params.privateKeyPem;
    this._certValid = params.certValid;
    this._privateKeyValid = params.privateKeyValid;
  }

  static async create(params: { aid: string; aunPath: string; certPem: string; privateKeyPem: string | null; certValid: boolean; privateKeyValid: boolean; deviceId?: string; slotId?: string }): Promise<AID> {
    const aid = new AID(params);
    aid._certFingerprint = await certFingerprint(params.certPem);
    return aid;
  }

  get certFingerprint(): string {
    return this._certFingerprint;
  }

  isCertValid(): boolean {
    return this._certValid;
  }

  isPrivateKeyValid(): boolean {
    return this._privateKeyValid;
  }

  async sign(payload: Uint8Array | string): Promise<Result<{ signature: string }>> {
    if (!this._privateKeyValid || !this._privateKeyPem) return resultErr(codes.PRIVATE_KEY_NOT_VALID, 'private key is not valid');
    try {
      const data = typeof payload === 'string' ? new TextEncoder().encode(payload) : payload;
      return resultOk({ signature: await signBytes(this._privateKeyPem, data) });
    } catch (exc) {
      return resultErr(codes.SIGNATURE_OPERATION_ERROR, String(exc), exc);
    }
  }

  async verify(payload: Uint8Array | string, signature: string): Promise<Result<{ valid: boolean }>> {
    if (!this._certValid) return resultErr(codes.CERT_NOT_VALID, 'certificate is not valid');
    try {
      const data = typeof payload === 'string' ? new TextEncoder().encode(payload) : payload;
      return resultOk({ valid: await verifySignatureWithCert(this.certPem, signature, data) });
    } catch (exc) {
      return resultErr(codes.VERIFICATION_OPERATION_ERROR, String(exc), exc);
    }
  }

  async signAgentMd(content: string): Promise<Result<{ signed: string }>> {
    if (!this._privateKeyValid || !this._privateKeyPem) return resultErr(codes.PRIVATE_KEY_NOT_VALID, 'private key is not valid');
    try {
      const payload = normalizeAgentMdPayload(content);
      const signature = await signBytes(this._privateKeyPem, new TextEncoder().encode(payload));
      return resultOk({ signed: payload + buildAgentMdSignatureBlock(this.certFingerprint, Date.now() / 1000, signature) });
    } catch (exc) {
      return resultErr(codes.SIGNATURE_OPERATION_ERROR, String(exc), exc);
    }
  }

  async verifyAgentMd(content: string): Promise<Result<VerifyResult>> {
    if (!this._certValid) return resultErr(codes.CERT_NOT_VALID, 'certificate is not valid');
    try {
      const { payload, fields, parseError } = parseAgentMdTailSignature(String(content ?? ''));
      if (!fields) return resultOk(parseError ? { status: 'invalid', payload, reason: parseError } : { status: 'unsigned', payload });
      const payloadAid = extractAgentMdAid(payload);
      if (payloadAid && payloadAid !== this.aid) return resultOk({ status: 'invalid', payload, aid: payloadAid, reason: 'aid mismatch' });
      if (fields.cert_fingerprint.toLowerCase() !== this.certFingerprint.toLowerCase()) {
        return resultOk({ status: 'invalid', payload, aid: this.aid, reason: 'certificate fingerprint mismatch' });
      }
      const valid = await verifySignatureWithCert(this.certPem, fields.signature, new TextEncoder().encode(payload));
      return resultOk(valid
        ? { status: 'verified', payload, aid: this.aid, cert_fingerprint: fields.cert_fingerprint, timestamp: Number(fields.timestamp) }
        : { status: 'invalid', payload, aid: this.aid, cert_fingerprint: fields.cert_fingerprint, timestamp: Number(fields.timestamp), reason: 'signature verification failed' });
    } catch (exc) {
      return resultErr(codes.VERIFICATION_OPERATION_ERROR, String(exc), exc);
    }
  }
}
