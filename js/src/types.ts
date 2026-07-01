// ── AUN 协议类型定义 ──────────────────────────────────────

/** JSON 原子值 */
export type JsonPrimitive = string | number | boolean | null;

/** JSON 对象 */
export interface JsonObject {
  [key: string]: JsonValue | undefined;
}

/** JSON 数组 */
export interface JsonArray extends Array<JsonValue> {}

/** JSON 值类型 */
export type JsonValue = JsonPrimitive | JsonObject | JsonArray;

/** AUNClient 连接状态枚举 — 对齐 Python/TS SDK */
export enum ConnectionState {
  NO_IDENTITY = 'no_identity',
  STANDBY = 'standby',
  AUTHENTICATED = 'authenticated',
  CONNECTING = 'connecting',
  READY = 'ready',
  RETRY_BACKOFF = 'retry_backoff',
  RECONNECTING = 'reconnecting',
  CONNECTION_FAILED = 'connection_failed',
  CLOSED = 'closed',
}

export const STATE_TO_PUBLIC: Record<string, ConnectionState> = {
  idle: ConnectionState.NO_IDENTITY,
  authenticating: ConnectionState.CONNECTING,
  connected: ConnectionState.READY,
  disconnected: ConnectionState.STANDBY,
  terminal_failed: ConnectionState.CONNECTION_FAILED,
  retry_backoff: ConnectionState.RETRY_BACKOFF,
  reconnecting: ConnectionState.RECONNECTING,
};

/** 判断值是否为普通 JSON 对象 */
export function isJsonObject(value: unknown): value is JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** RPC 参数 */
export interface RpcParams extends JsonObject {}

/** RPC 返回值 */
export type RpcResult = JsonValue;

/** RPC 错误对象 */
export interface RpcErrorObject extends JsonObject {
  code?: number;
  message?: string;
  data?: JsonValue;
}

/** RPC 消息 */
export interface RpcMessage extends JsonObject {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: JsonObject;
  result?: RpcResult;
  error?: RpcErrorObject;
}

/** Gateway 条目 */
export interface GatewayEntry extends JsonObject {
  url?: string;
  priority?: number;
}

/** Gateway 发现文档 */
export interface GatewayDiscoveryDocument extends JsonObject {
  gateways?: GatewayEntry[];
}

/** 身份密钥对记录 */
export interface KeyPairRecord extends JsonObject {
  private_key_pem?: string;
  public_key_der_b64?: string;
  curve?: string;
}

/** metadata 记录 */
export interface MetadataRecord extends JsonObject {
  access_token?: string;
  refresh_token?: string;
  kite_token?: string;
}

/** 身份记录 */
export interface IdentityRecord extends MetadataRecord, KeyPairRecord {
  aid?: string;
  cert?: string;
  cert_pem?: string;
  token?: string;
  token_exp?: number;
  expires_at?: number;
}

/** SecretStore 加密记录 */
export interface SecretRecord extends JsonObject {
  scheme?: string;
  name?: string;
  persisted?: boolean;
  nonce?: string;
  ciphertext?: string;
  tag?: string;
  iv?: string;
}

/** 投递模式 */
export type DeliveryMode = 'fanout' | 'queue';

/** 消息类型 */
export interface Message extends JsonObject {
  message_id?: string;
  seq?: number;
  to?: string;
  from?: string;
  /** 群组消息的群组 ID */
  group_id?: string;
  /** 群组消息的目标态群 AID */
  group_aid?: string;
  /** 群组消息的发送方 AID（服务端注入） */
  sender_aid?: string;
  type?: string;
  payload?: JsonValue;
  encrypted?: boolean;
  delivery_mode?: DeliveryMode;
  timestamp?: number;
  e2ee?: JsonObject;
}

/** 发送结果 */
export interface SendResult extends JsonObject {
  ok?: boolean;
  message_id?: string;
  group_id?: string;
  group_aid?: string;
  seq?: number;
  timestamp?: number;
  status?: 'sent' | 'delivered' | 'duplicate';
  delivery_mode?: DeliveryMode;
}

/** 群组信息 */
export interface GroupInfo extends JsonObject {
  group_id?: string;
  group_aid?: string;
  name?: string;
  owner_aid?: string;
  created_by?: string;
  type?: string;
  status?: string;
  avatar?: string;
  announcement?: string;
  member_count?: number;
  created_at?: number;
  updated_at?: number;
  settings?: JsonObject;
}

/** 群成员信息 */
export interface GroupMemberInfo extends JsonObject {
  group_id?: string;
  group_aid?: string;
  aid?: string;
  role?: string;
  member_type?: string;
  status?: string;
  joined_at?: number;
  updated_at?: number;
  last_ack_seq?: number;
  last_pull_at?: number;
}

/** 群消息结构 */
export interface GroupMessage extends Message {
  group_id?: string;
  group_aid?: string;
  sender_aid?: string;
}

/** ACK 结果 */
export interface AckResult extends JsonObject {
  success?: boolean;
  ack_seq?: number;
}

/** 拉取结果 */
export interface PullResult extends JsonObject {
  messages?: Message[];
  count?: number;
  latest_seq?: number;
}
