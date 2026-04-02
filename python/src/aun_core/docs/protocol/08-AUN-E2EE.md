# AUN-E2EE 扩展规范

> 版本：2.0-draft
> 状态：规范性文档
> 适用范围：AUN 客户端 SDK、客户端应用、跨语言实现
> 不适用范围：Gateway、Message 模块的加解密实现
> 定位：**独立安全层**，横跨 `gateway`、`peer`、`relay` 三种连接模式

---

## 1. 目标与边界

AUN-E2EE 定义 AUN 客户端之间的端到端消息层加密协议。

本规范的目标是：

- 让 A 与 B 在现有 `message.send` / `event/message.received` 之上实现端到端加密
- 让 Gateway、Message 模块仅看到最小必要路由元数据和密文 payload
- 为各语言 SDK 提供统一的密文格式、降级策略、重放保护和错误语义

服务端职责为：

- 认证发送方
- 校验消息路由权限
- 透传 `encrypted: true` 的 payload
- 存储和转发密文 payload
- 存储和分发接收方预存的临时公钥（Prekey）

---

## 2. 与 AUN-Core 的关系

AUN-E2EE 是 Layer 3 扩展协议，建立在以下核心能力之上：

- `message.send`
- `event/message.received`
- `message.pull`
- AID + 证书链身份体系

密文消息通过普通 `message.send` 承载；Gateway 和 Message 模块无需识别其内部字段。

---

## 3. 明文信封与密文载荷

### 3.1 明文信封

以下字段必须保持为服务端可见的明文，以便进行路由和离线存储：

- `to`
- `persist`
- `encrypted`
- `message_id`
- `timestamp`
- `type`

### 3.2 密文载荷

业务内容位于 `payload` 中，由发送方客户端在调用 `message.send` 前完成加密。服务端不负责加解密，不验证 `payload` 是否真的是密文。

---

## 4. 术语

### 4.1 Prekey

接收方预先生成的临时 ECDH 密钥对。公钥（附身份签名）上传到服务端，私钥保存在本地。发送方获取后用于 ECDH 密钥协商。Prekey 不消耗（可多次读取），定期轮换。

### 4.2 密文消息

通过 `message.send` 传输的加密业务消息，`encrypted` 必须为 `true`，`payload.type` 必须为 `e2ee.encrypted`。

---

## 5. 算法套件

### 5.1 实现要求

所有 AUN-E2EE 实现：

- **MUST** 支持 `P-256 + HKDF-SHA256 + AES-256-GCM`
- **MAY** 支持其他套件

### 5.2 套件标识

- `P256_HKDF_SHA256_AES_256_GCM`（必须支持）

### 5.3 身份绑定

- 发送方 **MUST** 用接收方证书验证 prekey 签名
- Prekey 签名格式：`sign(identity_private_key, "prekey_id|public_key_b64")`
- 仅交换公钥而不做签名验证的实现**不符合本规范**

---

## 6. 加密模式

AUN-E2EE 支持两种加密模式，SDK 自动按优先级选择。

### 6.1 模式 1：prekey_ecdh（优先）

**条件**：服务端有接收方的 prekey

**流程**：
1. 发送方获取接收方 prekey（含签名）
2. 用接收方证书验证 prekey 签名
3. 生成临时 ECDH 密钥对
4. 临时私钥 + 接收方 prekey 公钥 → ECDH → shared_secret
5. HKDF(shared_secret, info="aun-prekey:{prekey_id}") → message_key
6. AES-256-GCM(message_key, plaintext, AAD) → ciphertext + tag

**安全特性**：
- 前向安全（临时密钥用完即丢）
- 一消息一密钥（每条消息独立临时密钥对）
- 支持接收方离线

### 6.2 模式 2：long_term_key（降级）

**条件**：接收方无 prekey，但有证书

**流程**：
1. 发送方获取接收方证书
2. 生成随机会话密钥
3. 通过 ECIES 用接收方长期公钥加密会话密钥
4. AES-256-GCM(session_key, plaintext, AAD) → ciphertext + tag

**安全特性**：
- 一消息一密钥（每条消息独立会话密钥）
- 无前向安全（长期私钥泄露则历史消息可解密）
- 支持接收方离线

### 6.3 模式选择策略

SDK **MUST** 按以下优先级自动选择：

1. **优先**：prekey_ecdh（服务端有接收方 prekey）
2. **降级**：long_term_key（无 prekey 时）

---

## 7. 密文 payload 格式

### 7.1 prekey_ecdh 格式

```json
{
  "type": "e2ee.encrypted",
  "version": "1",
  "encryption_mode": "prekey_ecdh",
  "suite": "P256_HKDF_SHA256_AES_256_GCM",
  "prekey_id": "uuid",
  "ephemeral_public_key": "base64(X9.62 uncompressed point)",
  "nonce": "base64(12 bytes)",
  "ciphertext": "base64",
  "tag": "base64(16 bytes)",
  "aad": {
    "from": "alice.agentid.pub",
    "to": "bob.agentid.pub",
    "message_id": "uuid",
    "timestamp": 1710504000000,
    "encryption_mode": "prekey_ecdh",
    "suite": "P256_HKDF_SHA256_AES_256_GCM",
    "ephemeral_public_key": "base64",
    "recipient_cert_fingerprint": "sha256:..."
  }
}
```

### 7.2 long_term_key 格式

```json
{
  "type": "e2ee.encrypted",
  "version": "1",
  "encryption_mode": "long_term_key",
  "suite": "P256_HKDF_SHA256_AES_256_GCM",
  "ephemeral_public_key": "base64",
  "encrypted_session_key": "base64(nonce + AEAD ciphertext)",
  "nonce": "base64(12 bytes)",
  "ciphertext": "base64",
  "tag": "base64(16 bytes)",
  "aad": {
    "from": "alice.agentid.pub",
    "to": "bob.agentid.pub",
    "message_id": "uuid",
    "timestamp": 1710504000000,
    "encryption_mode": "long_term_key",
    "suite": "P256_HKDF_SHA256_AES_256_GCM",
    "ephemeral_public_key": "base64",
    "recipient_cert_fingerprint": "sha256:..."
  }
}
```

### 7.3 AAD 字段

两种模式使用相同的 AAD 字段集：

| 字段 | 说明 |
|------|------|
| `from` | 发送方 AID |
| `to` | 接收方 AID |
| `message_id` | 消息唯一标识 |
| `timestamp` | 发送时间戳（ms） |
| `encryption_mode` | 加密模式 |
| `suite` | 算法套件 |
| `ephemeral_public_key` | 发送方临时公钥 |
| `recipient_cert_fingerprint` | 接收方证书公钥指纹 |

AAD 序列化方式：按 key 字典序排列的 JSON，`ensure_ascii=False, sort_keys=True, separators=(",",":")`。

AAD 匹配校验时 **MAY** 跳过 `timestamp`（服务端可能替换外层时间戳）。

---

## 8. Prekey 管理

### 8.1 接收方职责

- **MUST** 上线后上传 prekey
- **SHOULD** 定期轮换 prekey（建议每小时）
- **MUST** 用身份私钥签名 prekey：`sign("prekey_id|public_key_b64")`
- **MUST** 保留旧 prekey 私钥至少 7 天（解密在途消息）

### 8.2 服务端职责

- **MUST** 存储接收方最新的 prekey
- **MUST** 提供 `message.e2ee.get_prekey` 和 `message.e2ee.put_prekey` RPC
- Prekey 不消耗（读取不删除），由接收方主动覆盖更新

### 8.3 Prekey RPC

**上传 prekey**：

```json
{"method": "message.e2ee.put_prekey", "params": {
  "prekey_id": "uuid",
  "public_key": "base64(DER SubjectPublicKeyInfo)",
  "signature": "base64(ECDSA signature)"
}}
```

**获取对方 prekey**：

```json
{"method": "message.e2ee.get_prekey", "params": {"aid": "bob.agentid.pub"}}
// 返回: {"found": true, "prekey": {"prekey_id": "...", "public_key": "...", "signature": "..."}}
```

---

## 9. 重放保护

### 9.1 本地防重放

- 接收方 **MUST** 维护本地 `seen_messages` 集合
- 以 `{sender_aid}:{message_id}` 为 key 去重
- 同一 key 的消息 **MUST** 被拒绝

### 9.2 服务端防重放（可选增强）

- 接收方 **MAY** 调用 `message.e2ee.record_replay_guard` RPC 进行跨进程防重放
- 参数：`sender_aid`, `message_id`, `encryption_mode`, `timestamp_ms`, `ephemeral_pk_hash`
- 返回 `duplicate: true` 表示消息已被处理

### 9.3 防篡改

- 所有路由关键字段纳入 AAD，任何篡改导致 AEAD 解密失败
- 接收方 **MUST** 校验 AAD 中 `from`、`to`、`message_id`、`encryption_mode`、`suite`、`ephemeral_public_key`、`recipient_cert_fingerprint` 与 payload 一致

---

## 10. 安全约定

- 加密失败时 **MUST NOT** 静默降级为明文
- 临时密钥用完即丢
- Prekey 私钥 **SHOULD** 加密存储
- 每条消息使用独立的临时密钥对和 nonce

---

## 11. 变更记录

| 版本 | 日期 | 变更 |
|------|------|------|
| 2.0-draft | 2026-04 | 简化为 prekey_ecdh + long_term_key 两级降级；移除在线协商（ephemeral_ecdh）；移除会话状态机；E2EEManager 退化为纯工具类 |
| 1.0-draft | — | 初始版本，三级降级（ephemeral_ecdh + prekey + long_term_key） |
