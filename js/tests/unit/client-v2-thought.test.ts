// ── client V2 thought 单元测试 ──────────────────────────────
// 验证 message.thought.put / group.thought.put 在 V2 session 就绪时
// 走 V2 多设备 wrap envelope 路径，envelope.type 为 e2ee.p2p_encrypted /
// e2ee.group_encrypted 且包含 recipients[]。
// 与 Python tests/e2e_test_v2_thought.py 对齐。

import 'fake-indexeddb/auto';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AUNClient } from '../../src/client.js';
import { V2KeyStore, V2Session } from '../../src/v2/session/index.js';
import { generateP256Keypair } from '../../src/v2/crypto/ecdh.js';
import { ecdsaSignRaw } from '../../src/v2/crypto/ecdsa.js';

async function newClientWithV2(aid: string, deviceId = 'dev-self'): Promise<AUNClient> {
  const client = new AUNClient();
  (client as any)._state = 'connected';
  (client as any)._aid = aid;
  (client as any)._deviceId = deviceId;

  // 构造一个真实的 V2Session（IK 用真随机 keypair）
  const store = await V2KeyStore.open();
  const [ikPriv, ikPub] = await generateP256Keypair();
  const session = new V2Session(store, deviceId, aid, ikPriv, ikPub);
  await session.ensureKeys();
  // 跳过 ensure_registered（registerSPK 触发 RPC，不在单元测试内必要）
  (session as any)._registered = true;
  (client as any)._v2Session = session;
  (client as any)._v2KeyStore = store;
  return client;
}

function uint8ToB64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function signedSPKFields(ikPriv: Uint8Array, spkPub: Uint8Array): Promise<Record<string, unknown>> {
  const hex = bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', spkPub.slice().buffer)));
  const spkId = `sha256:${hex.substring(0, 16)}`;
  const spkTimestamp = 1700000000;
  const encoder = new TextEncoder();
  const signData = concatBytes(spkPub, encoder.encode(spkId), encoder.encode(String(spkTimestamp)));
  const signature = await ecdsaSignRaw(ikPriv, signData);
  return {
    spk_id: spkId,
    spk_signature: uint8ToB64(signature),
    spk_timestamp: spkTimestamp,
  };
}

describe('AUNClient V2 thought', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('message.thought.put 在 V2 session 就绪时构造 V2 envelope，type=e2ee.p2p_encrypted 含 recipients[]', async () => {
    const client = await newClientWithV2('alice.aid.com', 'dev-alice');
    const bobAid = 'bob.aid.com';

    // bootstrap → 一个 bob 设备 + 一个 self（alice 自身设备数：仅当前一台，self_sync 跳过）
    const callMock = vi.spyOn(client as any, 'call').mockImplementation(async (method: any, params: any): Promise<any> => {
      if (method === 'message.v2.bootstrap') {
        const peerAid = String((params as any).peer_aid);
        if (peerAid === bobAid) {
          // 用真实 ik_pk 的 bob 设备
          // 注意：buildV2P2PEnvelope 需要 SubjectPublicKeyInfo DER；用真随机生成
          return Promise.resolve({});  // 占位，下面动态替换
        }
        if (peerAid === 'alice.aid.com') {
          return Promise.resolve({ peer_devices: [] });  // 自身只有当前设备
        }
      }
      return Promise.resolve({});
    });

    // 因为我们需要真实的 IK SPKI DER 才能加密，构造 bob 设备 keypair 并替换 mock
    const [bobIkPriv, bobIkPub] = await generateP256Keypair();
    const [, bobSpkPub] = await generateP256Keypair();
    const bobIkB64 = uint8ToB64(bobIkPub);
    const bobSpkB64 = uint8ToB64(bobSpkPub);
    const bobSPK = await signedSPKFields(bobIkPriv, bobSpkPub);
    vi.spyOn(client as any, '_v2TrustedIKPubDer').mockResolvedValue(bobIkPub);

    callMock.mockImplementation(async (method: any, params: any): Promise<any> => {
      if (method === 'message.v2.bootstrap') {
        const peerAid = String((params as any).peer_aid);
        if (peerAid === bobAid) {
          return {
            peer_devices: [{
              device_id: 'dev-bob-1',
              ik_pk: bobIkB64,
              spk_pk: bobSpkB64,
              ...bobSPK,
              key_source: 'peer_device_prekey',
            }],
            audit_recipients: [],
          };
        }
        if (peerAid === 'alice.aid.com') {
          return { peer_devices: [], audit_recipients: [] };
        }
      }
      return {};
    });

    let lastSendParams: any = null;
    (client as any)._transport = {
      call: vi.fn().mockImplementation((_method: string, sendParams: any) => {
        lastSendParams = sendParams;
        return Promise.resolve({ stored_count: 1 });
      }),
    };

    vi.spyOn(client as any, '_signClientOperation').mockResolvedValue(undefined);
    vi.spyOn(client as any, '_validateOutboundCall').mockReturnValue(undefined);
    vi.spyOn(client as any, '_injectMessageCursorContext').mockReturnValue(undefined);

    // 真正的入口：通过 client.call 直接调用 _putMessageThoughtEncryptedV2
    // 注：原 call 已被 mock 拦截，所以这里直接调内部方法
    const result: any = await (client as any)._putMessageThoughtEncryptedV2({
      to: bobAid,
      thought_id: 'mt-test-1',
      payload: { type: 'thought', text: 'hello' },
      context: { type: 'run', id: 'run-1' },
    });

    expect(result).toEqual({ stored_count: 1 });
    expect(lastSendParams).toBeTruthy();
    expect(lastSendParams.to).toBe(bobAid);
    expect(lastSendParams.thought_id).toBe('mt-test-1');
    expect(lastSendParams.encrypted).toBe(true);
    expect(lastSendParams.context).toEqual({ type: 'run', id: 'run-1' });

    const env = lastSendParams.payload;
    expect(env).toBeTruthy();
    expect(env.type).toBe('e2ee.p2p_encrypted');
    expect(env.version).toBe('v2');
    expect(Array.isArray(env.recipients)).toBe(true);
    expect(env.recipients.length).toBeGreaterThanOrEqual(1);
  });

  it('group.thought.put 在 V2 session 就绪时构造 V2 envelope，type=e2ee.group_encrypted 含 recipients[]', async () => {
    const client = await newClientWithV2('alice.aid.com', 'dev-alice');
    const groupId = 'group:test-1';

    // 构造 bob 设备 keypair（必须真实 SPKI，否则 encrypt_group_message 会失败）
    const [bobIkPriv, bobIkPub] = await generateP256Keypair();
    const [, bobSpkPub] = await generateP256Keypair();
    const bobIkB64 = uint8ToB64(bobIkPub);
    const bobSpkB64 = uint8ToB64(bobSpkPub);
    const bobSPK = await signedSPKFields(bobIkPriv, bobSpkPub);
    vi.spyOn(client as any, '_v2TrustedIKPubDer').mockResolvedValue(bobIkPub);

    const callMock = vi.spyOn(client as any, 'call').mockImplementation(async (method: any, _params: any): Promise<any> => {
      if (method === 'group.v2.bootstrap') {
        return {
          devices: [{
            aid: 'bob.aid.com',
            device_id: 'dev-bob-1',
            ik_pk: bobIkB64,
            spk_pk: bobSpkB64,
            ...bobSPK,
            key_source: 'peer_device_prekey',
          }],
          epoch: 1,
          audit_recipients: [],
          state_version: 0,
          state_hash: '',
          state_chain: '',
          e2ee_security_level: 'transport',
          e2ee_security_warning: 'open group uses transport fallback',
        };
      }
      return {};
    });
    callMock; // 抑制未使用警告

    let lastSendParams: any = null;
    (client as any)._transport = {
      call: vi.fn().mockImplementation((_method: string, sendParams: any) => {
        lastSendParams = sendParams;
        return Promise.resolve({ ok: true });
      }),
    };
    vi.spyOn(client as any, '_signClientOperation').mockResolvedValue(undefined);
    vi.spyOn(client as any, '_v2CheckFork').mockResolvedValue(undefined);
    vi.spyOn(client as any, '_v2VerifyStateSignature').mockResolvedValue(undefined);
    const publishSpy = vi.spyOn((client as any)._dispatcher, 'publish');

    const result: any = await (client as any)._putGroupThoughtEncryptedV2({
      group_id: groupId,
      thought_id: 'gt-test-1',
      payload: { type: 'thought', text: 'group hello' },
      context: { type: 'run', id: 'g-run-1' },
    });
    expect(result).toEqual({ ok: true });
    expect(lastSendParams.group_id).toBe(groupId);
    expect(lastSendParams.thought_id).toBe('gt-test-1');
    expect(lastSendParams.encrypted).toBe(true);
    const env = lastSendParams.payload;
    expect(env.type).toBe('e2ee.group_encrypted');
    expect(env.version).toBe('v2');
    expect(Array.isArray(env.recipients)).toBe(true);
    expect(env.recipients.length).toBeGreaterThanOrEqual(1);
    expect(publishSpy).toHaveBeenCalledWith('group.v2.security_level', {
      group_id: groupId,
      level: 'transport',
      warning: 'open group uses transport fallback',
      previous_level: null,
    });
  });

  it('call("message.thought.put") 在 V2 session 就绪时路由到 V2 加密路径', async () => {
    const client = await newClientWithV2('alice.aid.com', 'dev-alice');
    const v2Spy = vi.spyOn(client as any, '_putMessageThoughtEncryptedV2').mockResolvedValue({ stored_count: 1 });

    await client.call('message.thought.put', {
      to: 'bob.aid.com',
      thought_id: 'mt-1',
      context: { type: 'run', id: 'r1' },
      payload: { type: 'thought', text: 'x' },
    });
    expect(v2Spy).toHaveBeenCalled();
    expect((client as any)._putMessageThoughtEncrypted).toBeUndefined();
  });

  it('call("group.thought.put") 在 V2 session 就绪时路由到 V2 加密路径', async () => {
    const client = await newClientWithV2('alice.aid.com', 'dev-alice');
    const v2Spy = vi.spyOn(client as any, '_putGroupThoughtEncryptedV2').mockResolvedValue({ ok: true });

    await client.call('group.thought.put', {
      group_id: 'g1',
      thought_id: 'gt-1',
      context: { type: 'run', id: 'r1' },
      payload: { type: 'thought', text: 'x' },
    });
    expect(v2Spy).toHaveBeenCalled();
    expect((client as any)._putGroupThoughtEncrypted).toBeUndefined();
  });

  it('call("message.thought.put") 没有 V2 session 时拒绝 V1 回退', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'alice.aid.com';

    await expect(client.call('message.thought.put', {
      to: 'bob.aid.com',
      thought_id: 'mt-1',
      context: { type: 'run', id: 'r1' },
      payload: { type: 'thought', text: 'x' },
    })).rejects.toThrow('V2 session not initialized');
  });
});
