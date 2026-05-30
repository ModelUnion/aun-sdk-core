/**
 * P0 修复测试：
 * 1. AIDStore.load() 完整校验（有效期、CN、私钥解析、sign/verify 自检）
 * 2. retry_backoff 状态可达
 * 3. 重连/错误 getter
 */
import 'fake-indexeddb/auto';
import crypto from 'node:crypto';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AIDStore, AUNClient, ConnectionState, IndexedDBKeyStore } from '../../src/index.js';
import * as codes from '../../src/error-codes.js';

// ── DER 构建工具（与 aid-store-refactor.test.ts 相同） ──────────
function derLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  if (len < 0x100) return Buffer.from([0x81, len]);
  return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
}
function derTag(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}
function derSequence(c: Buffer): Buffer { return derTag(0x30, c); }
function derSet(c: Buffer): Buffer { return derTag(0x31, c); }
function derInteger(v: Buffer): Buffer {
  if (v[0]! & 0x80) v = Buffer.concat([Buffer.from([0x00]), v]);
  return derTag(0x02, v);
}
function derBitString(c: Buffer): Buffer { return derTag(0x03, Buffer.concat([Buffer.from([0x00]), c])); }
function derOctetString(c: Buffer): Buffer { return derTag(0x04, c); }
function derUtf8String(c: Buffer): Buffer { return derTag(0x0c, c); }
function derUtcTime(date: Date): Buffer {
  const p = [
    String(date.getUTCFullYear() % 100).padStart(2, '0'),
    String(date.getUTCMonth() + 1).padStart(2, '0'),
    String(date.getUTCDate()).padStart(2, '0'),
    String(date.getUTCHours()).padStart(2, '0'),
    String(date.getUTCMinutes()).padStart(2, '0'),
    String(date.getUTCSeconds()).padStart(2, '0'),
    'Z',
  ];
  return derTag(0x17, Buffer.from(p.join(''), 'utf8'));
}
function derContextConstructed(n: number, c: Buffer): Buffer { return derTag(0xa0 + n, c); }

const SIG_ALG_OID = Buffer.from([0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);

/** 构造自签名证书，cn 可与 aid 不同，有效期可自定义 */
function makeCert(opts: {
  aid: string;
  cn?: string;
  notBefore?: Date;
  notAfter?: Date;
}): { cert: string; private_key_pem: string; public_key_der_b64: string } {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicKeyDer = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }) as Buffer;
  const cn = opts.cn ?? opts.aid;
  const now = Date.now();
  const notBefore = opts.notBefore ?? new Date(now - 60_000);
  const notAfter = opts.notAfter ?? new Date(now + 3_600_000);
  const name = derSequence(derSet(derSequence(
    Buffer.concat([Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]), derUtf8String(Buffer.from(cn, 'utf8'))])
  )));
  const tbs = derSequence(Buffer.concat([
    derContextConstructed(0, derInteger(Buffer.from([0x02]))),
    derInteger(crypto.randomBytes(16)),
    SIG_ALG_OID,
    name,
    derSequence(Buffer.concat([derUtcTime(notBefore), derUtcTime(notAfter)])),
    name,
    publicKeyDer,
  ]));
  const signer = crypto.createSign('SHA256');
  signer.update(tbs);
  signer.end();
  const certDer = derSequence(Buffer.concat([tbs, SIG_ALG_OID, derBitString(signer.sign(privateKey))]));
  const b64 = certDer.toString('base64');
  const cert = `-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n`;
  return {
    cert,
    private_key_pem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    public_key_der_b64: publicKeyDer.toString('base64'),
  };
}

async function storeIdentity(aid: string, identity: { cert: string; private_key_pem: string; public_key_der_b64: string }): Promise<AIDStore> {
  const keyStore = new IndexedDBKeyStore({ encryptionSeed: 'test-seed' });
  await keyStore.saveIdentity(aid, { ...identity, aid });
  return new AIDStore({ aunPath: 'browser-aun-p0', encryptionSeed: 'test-seed' });
}

// ── 1. AIDStore.load() 完整校验 ──────────────────────────────────

describe('P0-load-01: 证书有效期检查', () => {
  it('证书已过期 → CERT_EXPIRED', async () => {
    const aid = 'alice.aid.com';
    const identity = makeCert({
      aid,
      notBefore: new Date(Date.now() - 7_200_000),
      notAfter: new Date(Date.now() - 3_600_000), // 1 小时前过期
    });
    const store = await storeIdentity(aid, identity);
    const result = await store.load(aid);
    expect(result.ok).toBe(false);
    expect(result.ok ? null : (result as any).error.code).toBe(codes.CERT_EXPIRED);
  });

  it('证书尚未生效 → CERT_NOT_YET_VALID', async () => {
    const aid = 'bob.aid.com';
    const identity = makeCert({
      aid,
      notBefore: new Date(Date.now() + 3_600_000), // 1 小时后才生效
      notAfter: new Date(Date.now() + 7_200_000),
    });
    const store = await storeIdentity(aid, identity);
    const result = await store.load(aid);
    expect(result.ok).toBe(false);
    expect(result.ok ? null : (result as any).error.code).toBe(codes.CERT_NOT_YET_VALID);
  });

  it('证书有效期正常 → ok', async () => {
    const aid = 'carol.aid.com';
    const identity = makeCert({ aid });
    const store = await storeIdentity(aid, identity);
    const result = await store.load(aid);
    expect(result.ok).toBe(true);
  });
});

describe('P0-load-02: CN 校验', () => {
  it('证书 CN 与 aid 不匹配 → CERT_CHAIN_BROKEN', async () => {
    const aid = 'dave.aid.com';
    const identity = makeCert({ aid, cn: 'evil.aid.com' }); // CN 故意不同
    const store = await storeIdentity(aid, identity);
    const result = await store.load(aid);
    expect(result.ok).toBe(false);
    expect(result.ok ? null : (result as any).error.code).toBe(codes.CERT_CHAIN_BROKEN);
  });

  it('证书 CN 与 aid 匹配 → ok', async () => {
    const aid = 'eve.aid.com';
    const identity = makeCert({ aid });
    const store = await storeIdentity(aid, identity);
    const result = await store.load(aid);
    expect(result.ok).toBe(true);
  });
});

describe('P0-load-03: 私钥解析错误捕获', () => {
  it('私钥 PEM 损坏 → PRIVATE_KEY_PARSE_ERROR', async () => {
    const aid = 'frank.aid.com';
    const identity = makeCert({ aid });
    const keyStore = new IndexedDBKeyStore({ encryptionSeed: 'test-seed' });
    // 存入损坏的私钥
    await keyStore.saveIdentity(aid, {
      ...identity,
      aid,
      private_key_pem: '-----BEGIN PRIVATE KEY-----\nINVALID_BASE64!!!\n-----END PRIVATE KEY-----\n',
    });
    const store = new AIDStore({ aunPath: 'browser-aun-p0', encryptionSeed: 'test-seed' });
    const result = await store.load(aid);
    expect(result.ok).toBe(false);
    expect(result.ok ? null : (result as any).error.code).toBe(codes.PRIVATE_KEY_PARSE_ERROR);
  });
});

describe('P0-load-04: 私钥-证书配对自检', () => {
  it('私钥与证书公钥不匹配 → KEYPAIR_MISMATCH', async () => {
    const aid = 'grace.aid.com';
    const identity1 = makeCert({ aid });
    const identity2 = makeCert({ aid }); // 另一对密钥
    const keyStore = new IndexedDBKeyStore({ encryptionSeed: 'test-seed' });
    // 存入 identity1 的证书 + identity2 的私钥（不匹配）
    await keyStore.saveIdentity(aid, {
      aid,
      cert: identity1.cert,
      private_key_pem: identity2.private_key_pem,
      public_key_der_b64: identity2.public_key_der_b64, // 故意不同
    });
    const store = new AIDStore({ aunPath: 'browser-aun-p0', encryptionSeed: 'test-seed' });
    const result = await store.load(aid);
    expect(result.ok).toBe(false);
    expect(result.ok ? null : (result as any).error.code).toBe(codes.KEYPAIR_MISMATCH);
  });

  it('私钥与证书公钥匹配但 public_key_der_b64 字段缺失 → 仍通过自检', async () => {
    const aid = 'henry.aid.com';
    const identity = makeCert({ aid });
    const keyStore = new IndexedDBKeyStore({ encryptionSeed: 'test-seed' });
    // 不存 public_key_der_b64，只存私钥和证书
    await keyStore.saveIdentity(aid, {
      aid,
      cert: identity.cert,
      private_key_pem: identity.private_key_pem,
    });
    const store = new AIDStore({ aunPath: 'browser-aun-p0', encryptionSeed: 'test-seed' });
    const result = await store.load(aid);
    expect(result.ok).toBe(true);
  });
});

// ── 2. retry_backoff 状态可达 ────────────────────────────────────

describe('P0-retry-01: STATE_TO_PUBLIC 包含 retry_backoff', () => {
  it('STATE_TO_PUBLIC["retry_backoff"] === ConnectionState.RETRY_BACKOFF', async () => {
    // 动态 import 避免 tree-shaking
    const { STATE_TO_PUBLIC } = await import('../../src/types.js');
    expect(STATE_TO_PUBLIC['retry_backoff']).toBe(ConnectionState.RETRY_BACKOFF);
  });
});

describe('P0-retry-02: 重连循环经过 retry_backoff 状态', () => {
  it('断网后重连循环先进入 retry_backoff 再进入 reconnecting', async () => {
    const client = new AUNClient();
    const states: string[] = [];
    client.on('state_change', (payload: any) => {
      states.push(payload.state);
    });

    // 模拟已连接状态，然后触发断线重连
    (client as any)._state = 'connected';
    (client as any)._sessionParams = { access_token: 'tok', gateway: 'wss://127.0.0.1:1/aun' };
    (client as any)._sessionOptions = {
      auto_reconnect: true,
      heartbeat_interval: 30,
      token_refresh_before: 1800,
      retry: { initial_delay: 0.01, max_delay: 0.01, max_attempts: 1 },
      timeouts: { connect: 1, call: 1, http: 1 },
    };

    // 触发断线处理
    await (client as any)._handleTransportDisconnect(new Error('network error'), 1006);

    // 等待重连循环至少运行一轮（最多 500ms）
    await new Promise(r => setTimeout(r, 300));

    expect(states).toContain(ConnectionState.RETRY_BACKOFF);
    // retry_backoff 必须在 reconnecting 之前出现
    const backoffIdx = states.indexOf(ConnectionState.RETRY_BACKOFF);
    const reconnectingIdx = states.indexOf(ConnectionState.RECONNECTING);
    if (reconnectingIdx >= 0) {
      expect(backoffIdx).toBeLessThan(reconnectingIdx);
    }
  }, 5000);
});

// ── 3. 重连/错误 getter ──────────────────────────────────────────

describe('P0-getters-01: 初始值', () => {
  it('nextRetryAt 初始为 null', () => {
    const client = new AUNClient();
    expect(client.nextRetryAt).toBeNull();
  });
  it('nextRetryInSeconds 初始为 null', () => {
    const client = new AUNClient();
    expect(client.nextRetryInSeconds).toBeNull();
  });
  it('retryAttempt 初始为 0', () => {
    const client = new AUNClient();
    expect(client.retryAttempt).toBe(0);
  });
  it('retryMaxAttempts 初始为 0', () => {
    const client = new AUNClient();
    expect(client.retryMaxAttempts).toBe(0);
  });
  it('lastError 初始为 null', () => {
    const client = new AUNClient();
    expect(client.lastError).toBeNull();
  });
  it('lastErrorCode 初始为 null', () => {
    const client = new AUNClient();
    expect(client.lastErrorCode).toBeNull();
  });
});

describe('P0-getters-02: isOnline 包含 RETRY_BACKOFF', () => {
  it('state=retry_backoff 时 isOnline 为 true', () => {
    const client = new AUNClient();
    (client as any)._state = 'retry_backoff';
    expect(client.isOnline).toBe(true);
  });
});

describe('P0-getters-03: nextRetryAt 仅在 retry_backoff 时非 null', () => {
  it('state=retry_backoff 且 _nextRetryAt 已设置时 nextRetryAt 返回 Date', () => {
    const client = new AUNClient();
    (client as any)._state = 'retry_backoff';
    const future = new Date(Date.now() + 5000);
    (client as any)._nextRetryAt = future;
    expect(client.nextRetryAt).toEqual(future);
  });

  it('state=reconnecting 时 nextRetryAt 返回 null（即使 _nextRetryAt 有值）', () => {
    const client = new AUNClient();
    (client as any)._state = 'reconnecting';
    (client as any)._nextRetryAt = new Date(Date.now() + 5000);
    expect(client.nextRetryAt).toBeNull();
  });
});
