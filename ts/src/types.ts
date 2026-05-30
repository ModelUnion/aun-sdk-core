/**
 * AUN SDK 核心类型定义
 */

/** JSON 原子值 */
export type JsonPrimitive = string | number | boolean | null;

/** JSON 对象 */
export interface JsonObject {
  [key: string]: JsonValue | undefined;
}

/** JSON 数组 */
export interface JsonArray extends Array<JsonValue> {}

/** JSON 值 */
export type JsonValue = JsonPrimitive | JsonObject | JsonArray;

/** P2P 投递模式 */
export type DeliveryMode = 'fanout' | 'queue';

/** 判断值是否为普通 JSON 对象 */
export function isJsonObject(value: JsonValue | object | null | undefined): value is JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** AUNClient 连接状态枚举 — 对齐 Python SDK types.py */
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

/** 内部状态 → 公开状态映射 */
export const STATE_TO_PUBLIC: Record<string, ConnectionState> = {
  no_identity: ConnectionState.NO_IDENTITY,
  standby: ConnectionState.STANDBY,
  authenticated: ConnectionState.AUTHENTICATED,
  connecting: ConnectionState.CONNECTING,
  ready: ConnectionState.READY,
  retry_backoff: ConnectionState.RETRY_BACKOFF,
  reconnecting: ConnectionState.RECONNECTING,
  connection_failed: ConnectionState.CONNECTION_FAILED,
  closed: ConnectionState.CLOSED,
  idle: ConnectionState.NO_IDENTITY,
  authenticating: ConnectionState.CONNECTING,
  connected: ConnectionState.READY,
  disconnected: ConnectionState.STANDBY,
  terminal_failed: ConnectionState.CONNECTION_FAILED,
};

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

/** 消息结构 */
export interface Message extends JsonObject {
  message_id?: string;
  seq?: number;
  from?: string;
  to?: string;
  type?: string;
  payload?: JsonValue;
  encrypted?: boolean;
  delivery_mode?: DeliveryMode;
  timestamp?: number;
  e2ee?: JsonObject;
  group_id?: string;
  sender_aid?: string;
  direction?: string;
}

/** 发送结果 */
export interface SendResult extends JsonObject {
  ok?: boolean;
  message_id?: string;
  seq?: number;
  timestamp?: number;
  status?: 'sent' | 'delivered' | 'duplicate';
  delivery_mode?: DeliveryMode;
}

/** 确认结果 */
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
