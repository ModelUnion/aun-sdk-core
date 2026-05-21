/**
 * AUN E2EE V2: 加解密引擎类型定义
 *
 * 与 Python `aun_core.v2.e2ee.encrypt_p2p` / `encrypt_group` / `decrypt` 对齐。
 */

export const SUITE_NAME = 'P256_HKDF_SHA256_AES_256_GCM' as const;

/** 发送方身份。 */
export interface Sender {
  /** 发送方 AID。 */
  aid: string;
  /** 发送方 device_id。 */
  deviceId: string;
  /** 32 字节 P-256 私钥标量（AID 主私钥）。 */
  ikPriv: Uint8Array;
  /** SPKI DER 编码的公钥（用于签名指纹计算）。 */
  ikPubDer: Uint8Array;
}

/** 接收方目标设备。 */
export interface Target {
  aid: string;
  deviceId: string;
  /** "peer" | "member" | "self_sync" | "audit" 等。 */
  role: string;
  /** "peer_device_prekey" | "group_device_prekey" | "aid_master"。 */
  keySource: string;
  /** 接收方 IK 公钥（DER SPKI）。 */
  ikPkDer: Uint8Array;
  /** 接收方 SPK 公钥（DER SPKI）；undefined 表示走 1DH 路径。 */
  spkPkDer?: Uint8Array;
  /** SPK 标识；3DH 时为非空字符串，1DH 时为空串/未定义。 */
  spkId?: string;
}

/** 接收方集合（P2P）。 */
export interface TargetSet {
  /** 普通接收设备。 */
  targets: Target[];
  /** 监管方设备（可选）。 */
  auditRecipients?: Target[];
}

/** 加密可选参数。 */
export interface EncryptOptions {
  /** 消息 ID；不传则自动生成 `m-{uuid4 hex}`。 */
  messageId?: string;
  /** 时间戳（毫秒）；不传则用 Date.now()。 */
  timestamp?: number;
  /** 受保护头部（HMAC 签名后附加到 envelope.protected_headers）。 */
  protectedHeaders?: Record<string, unknown>;
  /** 上下文元数据（HMAC 签名后附加到 envelope.context）。 */
  context?: Record<string, unknown>;
}

/** Group AAD 中的 state_commitment 子结构。 */
export interface StateCommitmentAAD {
  state_version: number;
  state_hash: string;
  state_chain: string;
}
