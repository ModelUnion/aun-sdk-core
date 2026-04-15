import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';

function stableStringify(obj: unknown): string {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (typeof obj === 'number' || typeof obj === 'boolean') return String(obj);
  if (Array.isArray(obj)) return '[' + obj.map((value) => stableStringify(value)).join(',') + ']';
  if (typeof obj === 'object') {
    const record = obj as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return '{' + keys.map((key) => `${stableStringify(key)}:${stableStringify(record[key])}`).join(',') + '}';
  }
  return JSON.stringify(obj);
}

function sha256Hex(text: string): string {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

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
  if (value[0] & 0x80) {
    value = Buffer.concat([Buffer.from([0x00]), value]);
  }
  return derTag(0x02, value);
}

function derBitString(content: Buffer): Buffer {
  return derTag(0x03, Buffer.concat([Buffer.from([0x00]), content]));
}

function derOctetString(content: Buffer): Buffer {
  return derTag(0x04, content);
}

function derUtf8String(content: Buffer): Buffer {
  return derTag(0x0c, content);
}

function derUtcTime(date: Date): Buffer {
  const year = date.getUTCFullYear() % 100;
  const parts = [
    String(year).padStart(2, '0'),
    String(date.getUTCMonth() + 1).padStart(2, '0'),
    String(date.getUTCDate()).padStart(2, '0'),
    String(date.getUTCHours()).padStart(2, '0'),
    String(date.getUTCMinutes()).padStart(2, '0'),
    String(date.getUTCSeconds()).padStart(2, '0'),
    'Z',
  ];
  return derTag(0x17, Buffer.from(parts.join(''), 'utf8'));
}

function derContextConstructed(tagNumber: number, content: Buffer): Buffer {
  return derTag(0xa0 + tagNumber, content);
}

function makeSelfSignedCert(privateKey: crypto.KeyObject, cn: string): string {
  const publicKeyDer = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }) as Buffer;
  const serialBytes = crypto.randomBytes(16);
  const notBefore = new Date(Date.now() - 60_000);
  const notAfter = new Date(Date.now() + 3600_000);
  const sigAlgOid = Buffer.from([
    0x30, 0x0a, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
  ]);

  const cnBytes = Buffer.from(cn, 'utf8');
  const name = derSequence(Buffer.concat([
    derSet(Buffer.concat([
      derSequence(Buffer.concat([
        Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]),
        derUtf8String(cnBytes),
      ])),
    ])),
  ]));

  const validity = derSequence(Buffer.concat([
    derUtcTime(notBefore),
    derUtcTime(notAfter),
  ]));

  const basicConstraintsExt = derSequence(Buffer.concat([
    Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x13]),
    Buffer.from([0x01, 0x01, 0xff]),
    derOctetString(derSequence(Buffer.from([0x01, 0x01, 0xff]))),
  ]));

  const extensions = derContextConstructed(3, derSequence(basicConstraintsExt));

  const tbs = derSequence(Buffer.concat([
    derContextConstructed(0, derInteger(Buffer.from([0x02]))),
    derInteger(serialBytes),
    sigAlgOid,
    name,
    validity,
    name,
    publicKeyDer,
    extensions,
  ]));

  const signer = crypto.createSign('SHA256');
  signer.update(tbs);
  signer.end();
  const sigDer = signer.sign(privateKey);

  const certDer = derSequence(Buffer.concat([
    tbs,
    sigAlgOid,
    derBitString(sigDer),
  ]));
  const b64 = certDer.toString('base64');
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}

function certFingerprint(certPem: string): string {
  const der = Buffer.from(certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  return `sha256:${crypto.createHash('sha256').update(der).digest('hex')}`;
}

function buildSignedEvent(material: {
  aid: string;
  certPem: string;
  privateKey: crypto.KeyObject;
}): { event: Record<string, unknown>; cs: Record<string, unknown> } {
  const event = {
    group_id: 'g-1',
    action: 'member_added',
    aid: 'member.agentid.pub',
    role: 'member',
  };
  const timestamp = String(Math.floor(Date.now() / 1000));
  const paramsHash = sha256Hex(stableStringify(event));
  const signData = `${'group.add_member'}|${material.aid}|${timestamp}|${paramsHash}`;
  const signature = crypto.sign('sha256', Buffer.from(signData, 'utf8'), material.privateKey).toString('base64');
  return {
    event,
    cs: {
      aid: material.aid,
      _method: 'group.add_member',
      cert_fingerprint: certFingerprint(material.certPem),
      timestamp,
      params_hash: paramsHash,
      signature,
    },
  };
}

describe('浏览器群事件验签', () => {
  it('有缓存证书且签名正确时应返回 true', async () => {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const certPem = makeSelfSignedCert(privateKey, 'alice.agentid.pub');
    const client = new AUNClient({ aun_path: '/tmp/aun-js-signature' }, true);
    const { event, cs } = buildSignedEvent({
      aid: 'alice.agentid.pub',
      certPem,
      privateKey,
    });

    (client as any)._certCache.set(`${cs.aid}#${cs.cert_fingerprint}`, {
      certPem,
      validatedAt: Date.now() / 1000,
      refreshAfter: Date.now() / 1000 + 300,
    });

    await expect((client as any)._verifyEventSignature(event, cs)).resolves.toBe(true);
  });

  it('签名被篡改时应返回 false', async () => {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const certPem = makeSelfSignedCert(privateKey, 'alice.agentid.pub');
    const client = new AUNClient({ aun_path: '/tmp/aun-js-signature' }, true);
    const { event, cs } = buildSignedEvent({
      aid: 'alice.agentid.pub',
      certPem,
      privateKey,
    });
    const tampered = { ...cs, signature: String(cs.signature).slice(0, -4) + 'AAAA' };

    (client as any)._certCache.set(`${cs.aid}#${cs.cert_fingerprint}`, {
      certPem,
      validatedAt: Date.now() / 1000,
      refreshAfter: Date.now() / 1000 + 300,
    });

    await expect((client as any)._verifyEventSignature(event, tampered)).resolves.toBe(false);
  });

  it('没有缓存证书时应返回 pending', async () => {
    const client = new AUNClient({ aun_path: '/tmp/aun-js-signature' }, true);
    (client as any)._fetchPeerCert = async () => '';
    const result = await (client as any)._verifyEventSignature(
      { group_id: 'g-1', action: 'member_added' },
      {
        aid: 'alice.agentid.pub',
        _method: 'group.add_member',
        cert_fingerprint: 'sha256:test',
        timestamp: '1',
        params_hash: 'abc',
        signature: 'ZmFrZQ==',
      },
    );
    expect(result).toBe('pending');
  });
});
