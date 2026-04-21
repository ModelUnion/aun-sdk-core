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

/** 连接状态 */
export type ConnectionState =
  | 'idle'
  | 'connecting'
  | 'authenticating'
  | 'connected'
  | 'disconnected'
  | 'reconnecting'
  | 'terminal_failed'
  | 'closed';

/** 判断值是否为普通 JSON 对象 */
export function isJsonObject(value: JsonValue | object | null | undefined): value is JsonObject {
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

/** E2EE prekey 记录 */
export interface PrekeyRecord extends JsonObject {
  prekey_id?: string;
  public_key?: string;
  signature?: string;
  private_key_pem?: string;
  created_at?: number;
  updated_at?: number;
  expires_at?: number;
}

/** prekey 映射 */
export type PrekeyMap = Record<string, PrekeyRecord>;

/** 群组旧 epoch 记录 */
export interface GroupOldEpochRecord extends JsonObject {
  epoch?: number;
  secret?: string;
  commitment?: string;
  member_aids?: string[];
  secret_protection?: JsonObject;
  created_at?: number;
  updated_at?: number;
  expires_at?: number;
}

/** 群组密钥状态 */
export interface GroupSecretRecord extends JsonObject {
  group_id?: string;
  epoch?: number;
  secret?: string;
  commitment?: string;
  member_aids?: string[];
  updated_at?: number;
  secret_protection?: JsonObject;
  old_epochs?: GroupOldEpochRecord[];
}

/** 群组密钥状态映射 */
export type GroupSecretMap = Record<string, GroupSecretRecord>;

/** metadata 记录 */
export interface MetadataRecord extends JsonObject {
  access_token?: string;
  refresh_token?: string;
  kite_token?: string;
  e2ee_prekeys?: PrekeyMap;
  e2ee_sessions?: JsonObject[];
  group_secrets?: GroupSecretMap;
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

/** E2EE session 记录 */
export interface SessionRecord extends JsonObject {
  session_id?: string;
  key?: string;
  key_protection?: JsonObject;
  peer_aid?: string;
  created_at?: number;
  updated_at?: number;
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
  seq?: number;
  timestamp?: number;
  status?: 'sent' | 'delivered' | 'duplicate';
  delivery_mode?: DeliveryMode;
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
