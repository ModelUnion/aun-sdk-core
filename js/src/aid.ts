import * as codes from './error-codes.js';
import {
  buildAgentMdSignatureBlock,
  certMatchesFingerprint,
  certFingerprint,
  extractAgentMdAid,
  normalizeAgentMdPayload,
  parseAgentMdTailSignature,
  parseCertMetadata,
  publicKeyFingerprint,
  publicKeyMatchesFingerprint,
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
  public_key_fingerprint?: string;
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
  readonly verifySsl: boolean;
  readonly rootCaPath: string | null;
  readonly debug: boolean;
  /** AIDStore 加载时注入的明文私钥 PEM，供 AUNClient 直接使用（无需 seed）。*/
  readonly privateKeyPem: string;
  private readonly _certValid: boolean;
  private readonly _privateKeyValid: boolean;
  private _certFingerprint = '';

  private constructor(params: { aid: string; aunPath: string; certPem: string; privateKeyPem: string | null; certValid: boolean; privateKeyValid: boolean; deviceId?: string; slotId?: string; verifySsl?: boolean; rootCaPath?: string | null; debug?: boolean }) {
    this.aid = params.aid;
    this.aunPath = params.aunPath;
    this.deviceId = params.deviceId ?? '';
    this.slotId = params.slotId ?? 'default';
    this.verifySsl = params.verifySsl ?? true;
    this.rootCaPath = params.rootCaPath ?? null;
    this.debug = params.debug ?? false;
    this.certPem = params.certPem;
    this.publicKey = publicKeyDerB64(params.certPem);
    const meta = parseCertMetadata(params.certPem);
    this.certSubject = meta.subject;
    this.certIssuer = meta.issuer;
    this.certNotBefore = meta.notBefore;
    this.certNotAfter = meta.notAfter;
    this.privateKeyPem = params.privateKeyPem ?? '';
    this._certValid = params.certValid;
    this._privateKeyValid = params.privateKeyValid;
  }

  static async create(params: { aid: string; aunPath: string; certPem: string; privateKeyPem: string | null; certValid: boolean; privateKeyValid: boolean; deviceId?: string; slotId?: string; verifySsl?: boolean; rootCaPath?: string | null; debug?: boolean }): Promise<AID> {
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
    if (!this._privateKeyValid || !this.privateKeyPem) return resultErr(codes.PRIVATE_KEY_NOT_VALID, 'private key is not valid');
    try {
      const data = typeof payload === 'string' ? new TextEncoder().encode(payload) : payload;
      return resultOk({ signature: await signBytes(this.privateKeyPem, data) });
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
    if (!this._privateKeyValid || !this.privateKeyPem) return resultErr(codes.PRIVATE_KEY_NOT_VALID, 'private key is not valid');
    try {
      const payload = normalizeAgentMdPayload(content);
      const signature = await signBytes(this.privateKeyPem, new TextEncoder().encode(payload));
      return resultOk({
        signed: payload + buildAgentMdSignatureBlock(
          this.certFingerprint,
          Date.now() / 1000,
          signature,
          await publicKeyFingerprint(this.certPem),
        ),
      });
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
      if (!(await certMatchesFingerprint(this.certPem, fields.cert_fingerprint))) {
        return resultOk({ status: 'invalid', payload, aid: this.aid, reason: 'certificate fingerprint mismatch' });
      }
      const publicKeyFp = String(fields.public_key_fingerprint ?? '').trim();
      if (publicKeyFp && !(await publicKeyMatchesFingerprint(this.certPem, publicKeyFp))) {
        return resultOk({ status: 'invalid', payload, aid: this.aid, reason: 'public key fingerprint mismatch' });
      }
      const valid = await verifySignatureWithCert(this.certPem, fields.signature, new TextEncoder().encode(payload));
      return resultOk(valid
        ? { status: 'verified', payload, aid: this.aid, cert_fingerprint: fields.cert_fingerprint, public_key_fingerprint: publicKeyFp, timestamp: Number(fields.timestamp) }
        : { status: 'invalid', payload, aid: this.aid, cert_fingerprint: fields.cert_fingerprint, timestamp: Number(fields.timestamp), reason: 'signature verification failed' });
    } catch (exc) {
      return resultErr(codes.VERIFICATION_OPERATION_ERROR, String(exc), exc);
    }
  }
}
