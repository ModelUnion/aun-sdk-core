/**
 * E2EE 单元测试 — 覆盖 prekey_ecdh_v2（四路 ECDH）/ long_term_key 两级降级、AAD、防重放。
 *
 * 测试策略：用真实密码学原语，E2EEManager 为纯工具类，无 RPC mock。
 */

import { describe, it, expect } from 'vitest';
import * as crypto from 'node:crypto';
import {
  AAD_FIELDS_OFFLINE,
  AAD_MATCH_FIELDS_OFFLINE,
  MODE_LONG_TERM_KEY,
  MODE_PREKEY_ECDH_V2,
  SUITE,
  E2EEManager,
} from '../../src/e2ee.js';
import { makeE2EEPair, makePrekey, FakeKeystore } from './helpers.js';
import type { JsonObject, Message } from '../../src/types.js';

// ── AAD 测试 ──────────────────────────────────────────────────

describe('AAD 方法', () => {
  it('AAD_FIELDS_OFFLINE 包含 10 个字段', () => {
    expect(AAD_FIELDS_OFFLINE.length).toBe(10);
    expect(AAD_FIELDS_OFFLINE).toContain('encryption_mode');
    expect(AAD_FIELDS_OFFLINE).toContain('recipient_cert_fingerprint');
    expect(AAD_FIELDS_OFFLINE).toContain('sender_cert_fingerprint');
    expect(AAD_FIELDS_OFFLINE).toContain('prekey_id');
  });

  it('AAD_MATCH_FIELDS_OFFLINE 不含 timestamp', () => {
    expect(AAD_MATCH_FIELDS_OFFLINE).not.toContain('timestamp');
    // 但包含 from, to, message_id 等
    expect(AAD_MATCH_FIELDS_OFFLINE).toContain('from');
    expect(AAD_MATCH_FIELDS_OFFLINE).toContain('to');
    expect(AAD_MATCH_FIELDS_OFFLINE).toContain('message_id');
  });
});

// ── Prekey 加密测试 ───────────────────────────────────────────

describe('prekey_ecdh_v2 加密', () => {
  it('prekey 加密信封包含正确字段', () => {
    const { senderMgr, receiverKey, receiverCert } = makeE2EEPair();
    const { prekey } = makePrekey(receiverKey);
    const mid = crypto.randomUUID();
    const ts = Date.now();

    const [envelope, info] = senderMgr.encryptOutbound(
      'receiver.test', { text: 'hello' }, receiverCert,
      prekey, mid, ts,
    );
    expect(info.encrypted).toBe(true);
    expect(info.mode).toBe(MODE_PREKEY_ECDH_V2);
    expect(envelope.encryption_mode).toBe(MODE_PREKEY_ECDH_V2);
    expect(envelope.prekey_id).toBe(prekey.prekey_id);
    expect(envelope.ephemeral_public_key).toBeTruthy();
    const aad = envelope.aad as JsonObject;
    expect(aad.encryption_mode).toBe(MODE_PREKEY_ECDH_V2);
  });

  it('prekey 加解密往返成功', () => {
    const { senderMgr, receiverMgr, receiverKey, receiverCert, receiverKs } = makeE2EEPair();
    const { prekey, prekeyPrivateKey } = makePrekey(receiverKey);

    // 将 prekey 私钥存入 receiver keystore
    const privPem = prekeyPrivateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    receiverKs._prekeys['receiver.test'] = {
      [prekey.prekey_id as string]: { private_key_pem: privPem, created_at: Date.now() },
    };

    const payload = { text: 'prekey roundtrip' };
    const mid = crypto.randomUUID();
    const ts = Date.now();

    const [envelope] = senderMgr.encryptOutbound(
      'receiver.test', payload, receiverCert, prekey, mid, ts,
    );

    const message = {
      message_id: mid, from: 'sender.test', to: 'receiver.test',
      timestamp: ts, seq: 1, payload: envelope, encrypted: true,
    };

    const result = receiverMgr.decryptMessage(message);
    expect(result).not.toBeNull();
    expect((result as Message).payload).toEqual(payload);
    const e2ee = (result as Message).e2ee as JsonObject;
    expect(e2ee.encryption_mode).toBe(MODE_PREKEY_ECDH_V2);
  });
});

// ── long_term_key 加密测试 ────────────────────────────────────

describe('long_term_key 加密', () => {
  it('long_term_key 信封包含正确的 AAD 字段', () => {
    const { senderMgr, receiverCert } = makeE2EEPair();
    const mid = crypto.randomUUID();
    const ts = Date.now();

    const [envelope, info] = senderMgr.encryptOutbound(
      'receiver.test', { text: 'hello' }, receiverCert, null, mid, ts,
    );
    expect(info.mode).toBe(MODE_LONG_TERM_KEY);
    expect(envelope.encryption_mode).toBe(MODE_LONG_TERM_KEY);
    const aad = envelope.aad as JsonObject;
    // long_term_key 的 AAD 应包含除 prekey_id 外的所有字段
    for (const field of AAD_FIELDS_OFFLINE) {
      if (field === 'prekey_id') continue;
      expect(aad[field]).toBeDefined();
    }
  });

  it('long_term_key 加解密往返成功', () => {
    const { senderMgr, receiverMgr, receiverCert } = makeE2EEPair();

    const payload = { text: 'long term roundtrip' };
    const mid = crypto.randomUUID();
    const ts = Date.now();

    const [envelope] = senderMgr.encryptOutbound(
      'receiver.test', payload, receiverCert, null, mid, ts,
    );

    const message = {
      message_id: mid, from: 'sender.test', to: 'receiver.test',
      timestamp: ts, seq: 1, payload: envelope, encrypted: true,
    };

    const result = receiverMgr.decryptMessage(message);
    expect(result).not.toBeNull();
    expect((result as Message).payload).toEqual(payload);
    const e2ee = (result as Message).e2ee as JsonObject;
    expect(e2ee.encryption_mode).toBe(MODE_LONG_TERM_KEY);
  });
});

// ── 两级降级测试 ─────────────────────────────────────────────

describe('encryptOutbound 降级策略', () => {
  it('有 prekey 时使用 prekey_ecdh_v2', () => {
    const { senderMgr, receiverKey, receiverCert } = makeE2EEPair();
    const { prekey } = makePrekey(receiverKey);
    const mid = crypto.randomUUID();
    const ts = Date.now();

    const [envelope, info] = senderMgr.encryptOutbound(
      'receiver.test', { text: 'test' }, receiverCert, prekey, mid, ts,
    );
    expect(info.mode).toBe(MODE_PREKEY_ECDH_V2);
    expect(info.forward_secrecy).toBe(true);
    expect(info.degraded).toBe(false);
    expect(envelope.encryption_mode).toBe(MODE_PREKEY_ECDH_V2);
  });

  it('无 prekey 时降级到 long_term_key', () => {
    const { senderMgr, receiverCert } = makeE2EEPair();
    const mid = crypto.randomUUID();
    const ts = Date.now();

    const [envelope, info] = senderMgr.encryptOutbound(
      'receiver.test', { text: 'test' }, receiverCert, null, mid, ts,
    );
    expect(info.mode).toBe(MODE_LONG_TERM_KEY);
    expect(info.forward_secrecy).toBe(false);
    expect(envelope.encryption_mode).toBe(MODE_LONG_TERM_KEY);
  });
});

// ── 本地防重放测试 ────────────────────────────────────────────

describe('本地防重放', () => {
  it('重复消息被拦截', () => {
    const { senderMgr, receiverMgr, receiverCert } = makeE2EEPair();

    const payload = { text: 'test replay' };
    const mid = crypto.randomUUID();
    const ts = Date.now();

    const [envelope] = senderMgr.encryptOutbound(
      'receiver.test', payload, receiverCert, null, mid, ts,
    );
    const message = {
      message_id: mid, from: 'sender.test', to: 'receiver.test',
      timestamp: ts, seq: 1, payload: envelope, encrypted: true,
    };

    // 第一次解密成功
    const result1 = receiverMgr.decryptMessage(message);
    expect(result1).not.toBeNull();
    expect((result1 as Message).payload).toEqual(payload);

    // 第二次重放被拦截（返回 null）
    const result2 = receiverMgr.decryptMessage(message);
    expect(result2).toBeNull();
  });

  it('seen set 超过上限时自动裁剪', () => {
    const { receiverMgr } = makeE2EEPair();
    // 通过内部访问设置小的上限
    const mgr = receiverMgr as unknown as { _seenMessages: Map<string, boolean>; _seenMaxSize: number; _trimSeenSet: () => void };
    mgr._seenMaxSize = 100;
    for (let i = 0; i < 120; i++) {
      mgr._seenMessages.set(`sender:msg_${i}`, true);
    }
    mgr._trimSeenSet();
    expect(mgr._seenMessages.size).toBe(80);
    // 最新的应保留
    expect(mgr._seenMessages.has('sender:msg_119')).toBe(true);
    // 最旧的应被清理
    expect(mgr._seenMessages.has('sender:msg_0')).toBe(false);
  });
});

// ── Prekey 生成测试 ───────────────────────────────────────────

describe('generatePrekey', () => {
  it('生成 prekey 后私钥存入 keystore', () => {
    const { receiverMgr, receiverKs } = makeE2EEPair();

    const result = receiverMgr.generatePrekey();
    expect(result.prekey_id).toBeTruthy();
    expect(result.public_key).toBeTruthy();
    expect(result.signature).toBeTruthy();
    expect(result.cert_fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/);

    const prekeys = receiverKs.loadE2EEPrekeys('receiver.test');
    expect(Object.keys(prekeys).length).toBe(1);
    const pid = Object.keys(prekeys)[0];
    expect(prekeys[pid].private_key_pem).toBeTruthy();
    expect(prekeys[pid].created_at).toBeTruthy();
  });

  it('生成的 prekey 包含 created_at 时间戳', () => {
    const { receiverMgr } = makeE2EEPair();
    const result = receiverMgr.generatePrekey();
    expect(result.created_at).toBeTruthy();
    expect(typeof result.created_at).toBe('number');
    expect(result.created_at as number).toBeGreaterThan(0);
    expect(result.cert_fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('本地清理应保留最新 7 个 prekey', () => {
    const { receiverMgr, receiverKs } = makeE2EEPair();
    const oldBase = Date.now() - (8 * 24 * 3600 * 1000);

    for (let i = 0; i < 8; i += 1) {
      receiverKs.saveE2EEPrekey('receiver.test', `old-${i}`, {
        private_key_pem: `OLD-${i}`,
        created_at: oldBase + i,
      });
    }

    const prekey = receiverMgr.generatePrekey();
    const prekeys = receiverKs.loadE2EEPrekeys('receiver.test');

    expect(prekeys[prekey.prekey_id as string]).toBeDefined();
    expect(Object.keys(prekeys)).toHaveLength(7);
    expect(prekeys['old-0']).toBeUndefined();
    expect(prekeys['old-1']).toBeUndefined();
    expect(prekeys['old-2']).toBeDefined();
  });

  it('prekey 证书指纹不匹配时降级到 long_term_key', () => {
    const { senderMgr, receiverKey, receiverCert } = makeE2EEPair();
    const { prekey } = makePrekey(receiverKey);
    prekey.cert_fingerprint = `sha256:${'0'.repeat(64)}`;

    const [_envelope, info] = senderMgr.encryptOutbound(
      'receiver.test',
      { text: 'hello' },
      receiverCert,
      prekey,
      crypto.randomUUID(),
      Date.now(),
    );
    expect(info.mode).toBe('long_term_key');
    expect(info.degraded).toBe(true);
    expect(info.degradation_reason).toBe('prekey_encrypt_failed');
  });
});

// ── decrypt_message 便利方法测试 ──────────────────────────────

describe('decryptMessage', () => {
  it('明文消息直接透传', () => {
    const { receiverMgr } = makeE2EEPair();
    const message = { seq: 1, payload: { text: 'hello' } };
    const result = receiverMgr.decryptMessage(message);
    expect(result).not.toBeNull();
    expect((result as Message).payload).toEqual({ text: 'hello' });
  });

  it('加密消息被自动解密', () => {
    const { senderMgr, receiverMgr, receiverCert } = makeE2EEPair();

    const payload = { text: 'secret' };
    const mid = crypto.randomUUID();
    const ts = Date.now();
    const [envelope] = senderMgr.encryptOutbound(
      'receiver.test', payload, receiverCert, null, mid, ts,
    );
    const message = {
      message_id: mid, from: 'sender.test', to: 'receiver.test',
      timestamp: ts, seq: 1, payload: envelope, encrypted: true,
    };

    const result = receiverMgr.decryptMessage(message);
    expect(result).not.toBeNull();
    expect((result as Message).payload).toEqual(payload);
  });

  it('发送方不解密自己发出的消息（目标不是自己）', () => {
    const { senderMgr, receiverKey, receiverCert } = makeE2EEPair();
    const { prekey } = makePrekey(receiverKey);
    const mid = crypto.randomUUID();
    const ts = Date.now();

    const [envelope] = senderMgr.encryptOutbound(
      'receiver.test', { text: 'self echo' }, receiverCert,
      prekey, mid, ts,
    );
    const outboundCopy = {
      message_id: mid, from: 'sender.test', to: 'receiver.test',
      timestamp: ts, seq: 1, payload: envelope, encrypted: true,
    };

    // sender 的 decryptMessage 应直接返回原消息（to != sender.test）
    const result = senderMgr.decryptMessage(outboundCopy);
    expect(result).toEqual(outboundCopy);
  });
});

// ── prekey 加密失败降级日志测试（TS-014）────────────────────────

describe('prekey 加密失败降级日志（TS-014）', () => {
  it('prekey 加密失败时应输出包含异常信息的警告日志', () => {
    const { senderMgr, receiverKey, receiverCert } = makeE2EEPair();
    const { prekey } = makePrekey(receiverKey);
    // 伪造 cert_fingerprint 触发 prekey 加密失败
    prekey.cert_fingerprint = `sha256:${'0'.repeat(64)}`;

    const warnArgs: unknown[][] = [];
    const origWarn = console.warn;
    console.warn = (...args: unknown[]) => { warnArgs.push(args); };

    try {
      const [_envelope, info] = senderMgr.encryptOutbound(
        'receiver.test', { text: 'test' }, receiverCert,
        prekey, crypto.randomUUID(), Date.now(),
      );
      // 应降级到 long_term_key
      expect(info.mode).toBe(MODE_LONG_TERM_KEY);
      expect(info.degraded).toBe(true);
      // 验证 warn 被调用且包含异常对象
      const prekeyWarn = warnArgs.find(args =>
        typeof args[0] === 'string' && args[0].includes('prekey 加密失败'));
      expect(prekeyWarn).toBeDefined();
      // 最后一个参数应为异常对象（非空）
      expect(prekeyWarn!.length).toBeGreaterThanOrEqual(2);
      expect(prekeyWarn![prekeyWarn!.length - 1]).toBeTruthy();
    } finally {
      console.warn = origWarn;
    }
  });
});

// ── 解密失败行为测试（TS-015）────────────────────────────────

describe('decryptMessage 解密失败行为（TS-015）', () => {
  it('篡改密文时 decryptMessage 应返回 null（不投递密文给应用层）', () => {
    const { senderMgr, receiverMgr, receiverKey, receiverCert, receiverKs } = makeE2EEPair();
    const { prekey, prekeyPrivateKey } = makePrekey(receiverKey);
    const privPem = prekeyPrivateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    receiverKs._prekeys['receiver.test'] = {
      [prekey.prekey_id as string]: { private_key_pem: privPem, created_at: Date.now() },
    };
    const mid = crypto.randomUUID();
    const ts = Date.now();
    const [envelope] = senderMgr.encryptOutbound('receiver.test', { text: 'hi' }, receiverCert, prekey, mid, ts);
    // 篡改密文
    const tampered = { ...envelope, ciphertext: 'AAAAAAAAAAAAAAAA' };
    const msg: Message = { message_id: mid, from: 'sender.test', to: 'receiver.test', timestamp: ts, seq: 1, payload: tampered, encrypted: true };
    const result = receiverMgr.decryptMessage(msg);
    // 解密失败应返回 null，调用方（client.ts）据此触发 undecryptable 事件
    expect(result).toBeNull();
  });

  it('prekey_ecdh_v2 解密失败时应输出包含上下文信息的警告日志', () => {
    const { senderMgr, receiverMgr, receiverKey, receiverCert, receiverKs } = makeE2EEPair();
    const { prekey, prekeyPrivateKey } = makePrekey(receiverKey);
    const privPem = prekeyPrivateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    receiverKs._prekeys['receiver.test'] = {
      [prekey.prekey_id as string]: { private_key_pem: privPem, created_at: Date.now() },
    };
    const mid = crypto.randomUUID();
    const ts = Date.now();
    const [envelope] = senderMgr.encryptOutbound('receiver.test', { text: 'hi' }, receiverCert, prekey, mid, ts);
    // 篡改 nonce（不影响签名验证，但解密会失败）
    const tampered = { ...envelope, nonce: Buffer.from(crypto.randomBytes(12)).toString('base64') };
    const msg: Message = { message_id: mid, from: 'sender.test', to: 'receiver.test', timestamp: ts, seq: 1, payload: tampered, encrypted: true };

    const warnArgs: unknown[][] = [];
    const origWarn = console.warn;
    console.warn = (...args: unknown[]) => { warnArgs.push(args); };

    try {
      receiverMgr.decryptMessage(msg);
      // 应有包含 mode/from/message_id 的解密失败日志
      const decryptWarn = warnArgs.find(args =>
        typeof args[0] === 'string' && args[0].includes('解密失败'));
      expect(decryptWarn).toBeDefined();
      // 日志中应包含 mode、from、message_id 等上下文
      const logStr = String(decryptWarn![0]);
      expect(logStr).toContain('prekey_ecdh_v2');
      expect(logStr).toContain('sender.test');
      expect(logStr).toContain(mid);
    } finally {
      console.warn = origWarn;
    }
  });

  it('long_term_key 解密失败时应输出包含上下文信息的警告日志', () => {
    const { senderMgr, receiverMgr, receiverCert } = makeE2EEPair();
    const mid = crypto.randomUUID();
    const ts = Date.now();
    const [envelope] = senderMgr.encryptOutbound('receiver.test', { text: 'hi' }, receiverCert, null, mid, ts);
    // 篡改 nonce（不影响签名验证，但解密会失败）
    const tampered = { ...envelope, nonce: Buffer.from(crypto.randomBytes(12)).toString('base64') };
    const msg: Message = { message_id: mid, from: 'sender.test', to: 'receiver.test', timestamp: ts, seq: 1, payload: tampered, encrypted: true };

    const warnArgs: unknown[][] = [];
    const origWarn = console.warn;
    console.warn = (...args: unknown[]) => { warnArgs.push(args); };

    try {
      receiverMgr.decryptMessage(msg);
      // 应有包含 mode/from/message_id 的解密失败日志
      const decryptWarn = warnArgs.find(args =>
        typeof args[0] === 'string' && args[0].includes('解密失败'));
      expect(decryptWarn).toBeDefined();
      const logStr = String(decryptWarn![0]);
      expect(logStr).toContain('long_term_key');
      expect(logStr).toContain('sender.test');
      expect(logStr).toContain(mid);
    } finally {
      console.warn = origWarn;
    }
  });
});

describe('指纹工具方法', () => {
  it('fingerprintCertPem 返回证书 SHA-256 指纹', () => {
    const { senderCert } = makeE2EEPair();
    const fp = E2EEManager.fingerprintCertPem(senderCert);
    expect(fp).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('同一证书的指纹稳定一致', () => {
    const { senderCert } = makeE2EEPair();
    const fp1 = E2EEManager.fingerprintCertPem(senderCert);
    const fp2 = E2EEManager.fingerprintCertPem(senderCert);
    expect(fp1).toBe(fp2);
  });
});
