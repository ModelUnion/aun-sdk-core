/**
 * E2EE 测试辅助工具
 *
 * 提供生成密钥对、自签证书、FakeKeystore 等测试基础设施。
 */

import * as crypto from 'node:crypto';
import type { KeyStore } from '../../src/keystore/index.js';
import { E2EEManager } from '../../src/e2ee.js';

// ── FakeKeystore ──────────────────────────────────────────────

export class FakeKeystore implements KeyStore {
  _metadata: Record<string, Record<string, unknown>> = {};
  _keyPairs: Record<string, Record<string, unknown>> = {};
  _certs: Record<string, string> = {};
  _identities: Record<string, Record<string, unknown>> = {};

  loadMetadata(aid: string): Record<string, unknown> | null {
    return this._metadata[aid] ?? null;
  }
  saveMetadata(aid: string, meta: Record<string, unknown>): void {
    this._metadata[aid] = meta;
  }
  loadKeyPair(aid: string): Record<string, unknown> | null {
    return this._keyPairs[aid] ?? null;
  }
  saveKeyPair(aid: string, keyPair: Record<string, unknown>): void {
    this._keyPairs[aid] = keyPair;
  }
  loadCert(aid: string): string | null {
    return this._certs[aid] ?? null;
  }
  saveCert(aid: string, certPem: string): void {
    this._certs[aid] = certPem;
  }
  deleteKeyPair(aid: string): void {
    delete this._keyPairs[aid];
  }
  loadIdentity(aid: string): Record<string, unknown> | null {
    return this._identities[aid] ?? null;
  }
  saveIdentity(aid: string, identity: Record<string, unknown>): void {
    this._identities[aid] = identity;
  }
  deleteIdentity(aid: string): void {
    delete this._identities[aid];
  }
}

// ── 密钥和证书生成 ────────────────────────────────────────────

/** 生成 ECDSA P-256 密钥对 */
export function generateECKeypair(): { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject } {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

/** 生成自签 X.509 证书 */
export function makeSelfSignedCert(privateKey: crypto.KeyObject, cn: string = 'test'): string {
  // Node.js 没有内置的 X.509 证书生成器，使用 openssl 兼容的方式
  // 这里用一个简化方法：创建 CSR 然后自签
  // 实际上 Node 18+ 没有简便 API，我们用 forge 风格的 hack
  // 改用 crypto.createCertificate（Node 不支持），所以用 spawn openssl 或模拟

  // 最简方案：使用 Node.js crypto 的底层接口手动构造证书
  // 由于 Node.js 标准库没有证书签发 API，这里构造一个最小的自签证书

  const publicKey = crypto.createPublicKey(privateKey);
  const pubDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;

  // 使用 ASN.1 DER 手动构造自签证书
  const cert = buildSelfSignedCert(privateKey, pubDer, cn);
  return cert;
}

/** 构建身份信息对象 */
export function buildIdentity(
  aid: string,
  privateKey: crypto.KeyObject,
): Record<string, unknown> {
  const publicKey = crypto.createPublicKey(privateKey);
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const pubDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  return {
    aid,
    private_key_pem: privPem,
    public_key_der_b64: pubDer.toString('base64'),
  };
}

/** 创建一对 sender/receiver 的 E2EEManager + 证书 */
export function makeE2EEPair(): {
  senderMgr: E2EEManager;
  receiverMgr: E2EEManager;
  senderKey: crypto.KeyObject;
  receiverKey: crypto.KeyObject;
  senderCert: string;
  receiverCert: string;
  senderKs: FakeKeystore;
  receiverKs: FakeKeystore;
  senderIdentity: Record<string, unknown>;
  receiverIdentity: Record<string, unknown>;
} {
  const { privateKey: senderKey } = generateECKeypair();
  const { privateKey: receiverKey } = generateECKeypair();

  const senderIdentity = buildIdentity('sender.test', senderKey);
  const receiverIdentity = buildIdentity('receiver.test', receiverKey);

  const senderKs = new FakeKeystore();
  const receiverKs = new FakeKeystore();

  senderKs._keyPairs['sender.test'] = {
    private_key_pem: senderIdentity.private_key_pem,
    public_key_der_b64: senderIdentity.public_key_der_b64,
  };
  receiverKs._keyPairs['receiver.test'] = {
    private_key_pem: receiverIdentity.private_key_pem,
    public_key_der_b64: receiverIdentity.public_key_der_b64,
  };

  const senderMgr = new E2EEManager({
    identityFn: () => senderIdentity,
    keystore: senderKs,
  });
  const receiverMgr = new E2EEManager({
    identityFn: () => receiverIdentity,
    keystore: receiverKs,
  });

  const senderCert = makeSelfSignedCert(senderKey, 'sender.test');
  const receiverCert = makeSelfSignedCert(receiverKey, 'receiver.test');

  // 每个 keystore 保存对方的证书（用于签名验证）
  senderKs._certs['receiver.test'] = receiverCert;
  receiverKs._certs['sender.test'] = senderCert;

  return {
    senderMgr, receiverMgr,
    senderKey, receiverKey,
    senderCert, receiverCert,
    senderKs, receiverKs,
    senderIdentity, receiverIdentity,
  };
}

/** 生成 prekey 并用 identity 私钥签名 */
export function makePrekey(
  identityPrivateKey: crypto.KeyObject,
  opts?: { createdAt?: number },
): { prekey: Record<string, unknown>; prekeyPrivateKey: crypto.KeyObject } {
  const { privateKey: prekeyPrivateKey, publicKey: prekeyPublicKey } = generateECKeypair();
  const prekeyPubDer = prekeyPublicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const prekeyId = crypto.randomUUID();
  const publicKeyB64 = prekeyPubDer.toString('base64');
  const createdAt = opts?.createdAt;

  let signData: string;
  if (createdAt != null) {
    signData = `${prekeyId}|${publicKeyB64}|${createdAt}`;
  } else {
    signData = `${prekeyId}|${publicKeyB64}`;
  }

  const signer = crypto.createSign('SHA256');
  signer.update(signData);
  signer.end();
  const signature = signer.sign(identityPrivateKey);

  const prekey: Record<string, unknown> = {
    prekey_id: prekeyId,
    public_key: publicKeyB64,
    signature: signature.toString('base64'),
  };
  if (createdAt != null) {
    prekey.created_at = createdAt;
  }

  return { prekey, prekeyPrivateKey };
}

// ── ASN.1 DER 证书构造 ───────────────────────────────────────

// 以下为最小化的 X.509 v3 自签证书 DER 编码构造函数
// 用于测试目的，生产环境应使用正规 CA

function buildSelfSignedCert(
  privateKey: crypto.KeyObject,
  subjectPublicKeyDer: Buffer,
  cn: string,
): string {
  const now = new Date();
  const notBefore = now;
  const notAfter = new Date(now.getTime() + 365 * 24 * 3600 * 1000);

  // 序列号（随机 8 字节正整数）
  const serialBytes = crypto.randomBytes(8);
  serialBytes[0] &= 0x7f; // 确保正数

  // 签名算法标识符（ecdsaWithSHA256: 1.2.840.10045.4.3.2）
  const sigAlgOid = Buffer.from([
    0x30, 0x0a, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
  ]);

  // Issuer = Subject = CN=<cn>
  const cnBytes = Buffer.from(cn, 'utf-8');
  const cnAttr = derSequence(Buffer.concat([
    derSet(Buffer.concat([
      derSequence(Buffer.concat([
        // OID 2.5.4.3 (id-at-commonName)
        Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]),
        derUtf8String(cnBytes),
      ])),
    ])),
  ]));

  // 有效期
  const validity = derSequence(Buffer.concat([
    derUtcTime(notBefore),
    derUtcTime(notAfter),
  ]));

  // BasicConstraints 扩展: CA:TRUE
  const basicConstraintsExt = derSequence(Buffer.concat([
    // OID 2.5.29.19 (id-ce-basicConstraints)
    Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x13]),
    // critical: TRUE
    Buffer.from([0x01, 0x01, 0xff]),
    // extnValue: SEQUENCE { BOOLEAN TRUE }
    derOctetString(derSequence(Buffer.from([0x01, 0x01, 0xff]))),
  ]));

  const extensions = Buffer.concat([
    // [3] EXPLICIT SEQUENCE OF Extension
    derContextConstructed(3, derSequence(basicConstraintsExt)),
  ]);

  // TBSCertificate
  const tbs = derSequence(Buffer.concat([
    // version [0] EXPLICIT INTEGER v3(2)
    derContextConstructed(0, derInteger(Buffer.from([0x02]))),
    // serialNumber
    derInteger(serialBytes),
    // signature algorithm
    sigAlgOid,
    // issuer
    cnAttr,
    // validity
    validity,
    // subject
    cnAttr,
    // subjectPublicKeyInfo
    subjectPublicKeyDer,
    // extensions
    extensions,
  ]));

  // 签名
  const signer = crypto.createSign('SHA256');
  signer.update(tbs);
  signer.end();
  const sigDer = signer.sign(privateKey);

  // Certificate = SEQUENCE { TBS, SignatureAlgorithm, Signature }
  const certDer = derSequence(Buffer.concat([
    tbs,
    sigAlgOid,
    derBitString(sigDer),
  ]));

  // PEM 编码
  const b64 = certDer.toString('base64');
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.substring(i, i + 64));
  }
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}

// ── DER 编码辅助 ──────────────────────────────────────────────

function derLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  if (len < 0x100) return Buffer.from([0x81, len]);
  return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function derTag(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function derSequence(content: Buffer): Buffer {
  return derTag(0x30, content);
}

function derSet(content: Buffer): Buffer {
  return derTag(0x31, content);
}

function derInteger(value: Buffer): Buffer {
  // 确保正整数的前导 0
  if (value[0] & 0x80) {
    value = Buffer.concat([Buffer.from([0x00]), value]);
  }
  return derTag(0x02, value);
}

function derBitString(content: Buffer): Buffer {
  // padding bits = 0
  return derTag(0x03, Buffer.concat([Buffer.from([0x00]), content]));
}

function derOctetString(content: Buffer): Buffer {
  return derTag(0x04, content);
}

function derUtf8String(content: Buffer): Buffer {
  return derTag(0x0c, content);
}

function derUtcTime(date: Date): Buffer {
  const y = date.getUTCFullYear() % 100;
  const m = date.getUTCMonth() + 1;
  const d = date.getUTCDate();
  const h = date.getUTCHours();
  const min = date.getUTCMinutes();
  const s = date.getUTCSeconds();
  const str = [
    y.toString().padStart(2, '0'),
    m.toString().padStart(2, '0'),
    d.toString().padStart(2, '0'),
    h.toString().padStart(2, '0'),
    min.toString().padStart(2, '0'),
    s.toString().padStart(2, '0'),
    'Z',
  ].join('');
  return derTag(0x17, Buffer.from(str, 'ascii'));
}

function derContextConstructed(tag: number, content: Buffer): Buffer {
  return derTag(0xa0 | tag, content);
}
