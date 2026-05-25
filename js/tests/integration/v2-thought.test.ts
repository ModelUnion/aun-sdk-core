/**
 * V2 thought 集成测试（mock transport）
 *
 * 这个文件不依赖真实 Gateway/Docker，使用 mock transport 验证
 * V2 thought put 的端到端行为：
 *   1. envelope 类型 = e2ee.p2p_encrypted / e2ee.group_encrypted
 *   2. envelope 含 recipients[]，per-device wrap
 *   3. envelope 透传到服务端 thought.put RPC
 *   4. payload 经过 V2 加解密 round-trip 后，明文一致
 *
 * 真实双端 V2 thought 测试见 tests/e2e-browser/v2-thought.spec.ts。
 */

import 'fake-indexeddb/auto';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AUNClient } from '../../src/client.js';
import { V2KeyStore, V2Session } from '../../src/v2/session/index.js';
import { generateP256Keypair } from '../../src/v2/crypto/ecdh.js';
import { ecdsaSignRaw } from '../../src/v2/crypto/ecdsa.js';
import { decryptMessage } from '../../src/v2/e2ee/decrypt.js';

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

async function newClientWithV2(aid: string, deviceId = 'dev-self'): Promise<{
  client: AUNClient;
  store: V2KeyStore;
  ikPriv: Uint8Array;
  ikPub: Uint8Array;
  session: V2Session;
}> {
  const client = new AUNClient();
  (client as any)._state = 'connected';
  (client as any)._aid = aid;
  (client as any)._deviceId = deviceId;

  const store = await V2KeyStore.open();
  const [ikPriv, ikPub] = await generateP256Keypair();
  const session = new V2Session(store, deviceId, aid, ikPriv, ikPub);
  await session.ensureKeys();
  (session as any)._registered = true;
  (client as any)._v2Session = session;
  (client as any)._v2KeyStore = store;
  return { client, store, ikPriv, ikPub, session };
}

describe('V2 thought 集成测试（mock transport）', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('P2P thought.put: envelope 含 recipients[] 且单设备解密一致', async () => {
    const aliceCtx = await newClientWithV2('alice.aid.com', 'dev-alice');
    const bobAid = 'bob.aid.com';

    // Bob 真实 V2 keypair（IK + SPK），用于解密验证
    const [bobIkPriv, bobIkPub] = await generateP256Keypair();
    const [bobSpkPriv, bobSpkPub] = await generateP256Keypair();
    const bobIkB64 = uint8ToB64(bobIkPub);
    const bobSpkB64 = uint8ToB64(bobSpkPub);
    const bobSPK = await signedSPKFields(bobIkPriv, bobSpkPub);
    vi.spyOn(aliceCtx.client as any, '_v2TrustedIKPubDer').mockResolvedValue(bobIkPub);

    vi.spyOn(aliceCtx.client as any, 'call').mockImplementation(async (method: any, params: any): Promise<any> => {
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
    (aliceCtx.client as any)._transport = {
      call: vi.fn().mockImplementation((_method: string, sendParams: any) => {
        lastSendParams = sendParams;
        return Promise.resolve({ stored_count: 1 });
      }),
    };
    vi.spyOn(aliceCtx.client as any, '_signClientOperation').mockResolvedValue(undefined);

    const plaintextPayload = { type: 'thought', text: 'hello bob from V2 thought' };
    await (aliceCtx.client as any)._putMessageThoughtEncryptedV2({
      to: bobAid,
      thought_id: 'mt-int-1',
      payload: plaintextPayload,
    });

    expect(lastSendParams).toBeTruthy();
    const env = lastSendParams.payload;
    expect(env.type).toBe('e2ee.p2p_encrypted');
    expect(env.version).toBe('v2');
    expect(Array.isArray(env.recipients)).toBe(true);
    expect(env.recipients.length).toBe(1);

    // Bob 解密 envelope
    const decrypted = await decryptMessage(
      env,
      bobAid,
      'dev-bob-1',
      bobIkPriv,
      bobSpkPriv,
      aliceCtx.ikPub,
    );
    expect(decrypted).toEqual(plaintextPayload);
  });

  it('Group thought.put: envelope 含 recipients[] 且 Bob 设备解密一致', async () => {
    const aliceCtx = await newClientWithV2('alice.aid.com', 'dev-alice');
    const groupId = 'group-int-1';

    const [bobIkPriv, bobIkPub] = await generateP256Keypair();
    const [bobSpkPriv, bobSpkPub] = await generateP256Keypair();
    const bobIkB64 = uint8ToB64(bobIkPub);
    const bobSpkB64 = uint8ToB64(bobSpkPub);
    const bobSPK = await signedSPKFields(bobIkPriv, bobSpkPub);
    vi.spyOn(aliceCtx.client as any, '_v2TrustedIKPubDer').mockResolvedValue(bobIkPub);

    vi.spyOn(aliceCtx.client as any, 'call').mockImplementation(async (method: any): Promise<any> => {
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
        };
      }
      return {};
    });

    let lastSendParams: any = null;
    (aliceCtx.client as any)._transport = {
      call: vi.fn().mockImplementation((_method: string, sendParams: any) => {
        lastSendParams = sendParams;
        return Promise.resolve({ ok: true });
      }),
    };
    vi.spyOn(aliceCtx.client as any, '_signClientOperation').mockResolvedValue(undefined);
    vi.spyOn(aliceCtx.client as any, '_v2CheckFork').mockResolvedValue(undefined);
    vi.spyOn(aliceCtx.client as any, '_v2VerifyStateSignature').mockResolvedValue(undefined);

    const plaintextPayload = { type: 'thought', text: 'group V2 thought hi' };
    await (aliceCtx.client as any)._putGroupThoughtEncryptedV2({
      group_id: groupId,
      thought_id: 'gt-int-1',
      payload: plaintextPayload,
    });

    const env = lastSendParams.payload;
    expect(env.type).toBe('e2ee.group_encrypted');
    expect(env.version).toBe('v2');
    expect(Array.isArray(env.recipients)).toBe(true);
    expect(env.recipients.length).toBe(1);

    const decrypted = await decryptMessage(
      env, 'bob.aid.com', 'dev-bob-1',
      bobIkPriv, bobSpkPriv, aliceCtx.ikPub,
    );
    expect(decrypted).toEqual(plaintextPayload);
  });
});
