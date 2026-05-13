# AUN E2EE 公钥直接加密方案（规范）

> 版本：1.3-draft  
> 日期：2026-05-13  
> 状态：规范草案  
> 适用范围：AUN 客户端 SDK、AUN 群服务端、跨语言实现  
> 替代规范：`08-AUN-E2EE.md`、`08-AUN-E2EE-Group.md`  
> 相关文档：
> 
> -   设计讨论：`草案-E2EE-公钥直接加密方案.md`
> -   新旧对比：`对比-E2EE新旧方案对比.md`
> -   旧方案问题：`议题-E2EE移动端性能与可用性分析.md`

---

## 1. 目标与范围

### 1.1 目标

为 AUN 网络内 Agent 之间的消息通信提供端到端加密，覆盖：

-   一对一 P2P 通信
-   群组通信（≤ 200 人）
-   **合规监管接收**：所有消息（加密或明文）均可被部署方配置的监管方接收

并满足以下工程约束：

-   不依赖任何成员此刻在线
-   不依赖历史状态（每条消息自包含解密所需信息）
-   服务端零信任（不持有任何私钥）
-   移动端后台断连场景下仍可正常工作
-   **监管方对普通客户端业务层不可见**：SDK 内部处理，业务层和 UI 无法感知监管方存在

### 1.2 非目标

-   **消息级前向安全（PFS）**：本方案明确放弃，详见 §2
-   **超过 200 人的大群加密**：协议层降级为明文
-   **多设备独立密钥**：所有设备共用同一 AID 私钥（AUN 现有约束）

---

## 2. 设计哲学

### 2.1 放弃 PFS 的论证

PFS 仅在以下条件**同时成立**时有意义：

1.  攻击者此刻拿不到设备
2.  受害者本地不留消息明文
3.  密文在网络/服务端被长期存档
4.  长期私钥在"未来"才泄露

但 AUN 场景下：

-   Agent 上下文需要保留消息历史 → 本地必然明文存档
-   AID 私钥泄露 = Agent 身份被冒充 → 已是身份灾难，"历史消息附带可解"是二阶损失
-   现行方案的 PFS 已为可用性打折（prekey 私钥保留 7 天）

**结论**：PFS 在 AUN 实际威胁模型下价值有限，放弃它换取大幅简化的协议和移动端可用性是合理取舍。

### 2.2 核心立场

| 原则 | 含义 |
| --- | --- |
| 每条消息自包含 | 解密所需的所有材料（除接收方私钥外）都在消息里 |
| 不存在群共享密钥 | 没有 group_secret / epoch / 邮箱 / 密钥恢复 |
| 服务端零信任 | 服务端只按清单路由，不持有私钥，不参与密钥协商 |
| 静态密钥复用 | ECDH 共享秘密永久缓存，每条消息靠 HKDF info 派生独立密钥 |

---

## 3. 身份与密钥分层

### 3.1 三层密钥架构

| 层级 | 用途 | 数量 | 生命周期 | 参与日常加解密？ |
| --- | --- | --- | --- | --- |
| AID 主密钥 | 身份根，签名所有下级密钥 | 1 个/Agent | 跟随 AID 证书 | 仅签名 |
| Peer 密钥 | P2P 通信加密 | 每对 Peer 1 对 | 长期复用，可独立轮换 | 是 |
| 群内密钥 | 群组通信加密 | 每群 1 对 | 入群时生成，退群清除 | 是 |

**关键性质**：日常加解密**不使用** AID 主私钥，主密钥的暴露面降到最低。

### 3.2 密钥生成与发布

#### 3.2.1 Peer 密钥

Alice 首次准备和 Bob 通信时：

1.  本地生成 P-256 密钥对，称 `Alice@Bob`（私钥留本地）
2.  用 AID 主私钥对 `peer_pk || peer_aid || created_at` 签名背书
3.  调用 `message.e2ee.put_peer_pk` 上传到服务端 Peer 公钥表
4.  Bob 同理生成 `Bob@Alice`

服务端 Peer 公钥表按 `{owner_aid, peer_aid}` 索引：每个 owner 给每个 peer **独立一对密钥**，不共享。

#### 3.2.2 群内密钥

成员加入群时：

1.  本地生成 P-256 密钥对，称 `member@group`
2.  用 AID 主私钥对 `group_pk || aid || group_id || created_at` 签名背书
3.  调用 `group.e2ee.put_member_pk` 上传到群服务端成员表

#### 3.2.3 公钥指纹

所有公钥使用 **SHA-256 前 64 位截断指纹**：

```
fingerprint = "sha256:" + SHA256(DER(public_key))[0..16]   // 16 hex chars

```

例：`sha256:a3b2c1d4e5f60718`

抗碰撞强度 32 bit，仅作查表 key，不参与密码学认证。

### 3.3 密钥轮换

| 触发 | 处理 |
| --- | --- |
| AID 主密钥轮换 | 重新签发所有下级 Peer/群内密钥的背书，上传更新；不强制生成新通信密钥 |
| Peer 密钥轮换 | 本地重生成 + 上传新公钥；对端通过 fingerprint 不匹配懒加载新公钥 |
| 群内密钥轮换 | 同上，触发 members_changed 事件通知群内 |

**Peer / 群内密钥轮换触发时机**：
-   用户手动触发（怀疑泄露时）
-   AID 主密钥轮换后手动级联
-   设备更换时（旧设备私钥不可转移到新设备的场景）
-   **不建议定时自动轮换**——无 PFS 追求下，定期轮换只增加协议噪音，不提供额外安全

旧密钥**立即作废**，无 grace period——本地消息已明文保存，无需保留旧私钥解历史密文。

---

## 4. 算法套件

### 4.1 必须支持

```
P256_HKDF_SHA256_AES_256_GCM

```

-   椭圆曲线：P-256 (secp256r1)
-   密钥协商：ECDH
-   密钥派生：HKDF-SHA256
-   对称加密：AES-256-GCM（AEAD，128 位 tag）
-   签名：ECDSA-SHA256，**RAW 编码**（`r || s`，共 64 字节；非 DER）

### 4.3 字节级编码约定

统一以下字节级细节，保证跨语言实现一致：

| 项 | 约定 |
| --- | --- |
| ECDSA 签名 | RAW 编码 = `r (32B) || s (32B)` = 64 字节定长；base64 后 88 字符 |
| ECDH 输出 | 取椭圆曲线点的 X 坐标字节（32 字节），不含前缀 |
| 公钥序列化（上传/缓存） | DER SubjectPublicKeyInfo |
| 公钥指纹 | `SHA256(DER 公钥)[0..16]` 前 16 hex 字符 |
| `recipients_digest` | 字节串形式为 **hex 解码后的 32 字节 raw binary**（不是 hex 字符串的 UTF-8 字节） |
| 消息 ID | `p2p-{uuid4}` / `gm-{uuid4}` |
| 时间戳 | 毫秒级 Unix 整数 |

### 4.2 可选扩展

实现 MAY 支持其他套件，通过 envelope 中 `suite` 字段标识。本规范仅定义上述必选套件的细节。

---

## 5. P2P 加密

### 5.1 与群聊统一的 Hybrid 模式

P2P 消息与群聊消息**使用完全相同的加密机制（Hybrid 多收件人加密）**，仅 RPC 方法分开（`message.send` vs `group.send`）。本章只列出 P2P 特有字段，加密/解密细节详见 §6。

P2P 消息的 recipients 数组**至少包含**：
-   1 个业务对端（role=`peer`）
-   0~N 个监管方（role=`audit`，由 SDK 自动注入，对业务层不可见，见 §12）

### 5.2 共享秘密推导

**发送方对对端**：

```
shared_secret = ECDH(Alice@Bob 会话私钥, Bob@Alice 会话公钥)
```

**发送方对监管方**（监管方没有会话密钥）：

```
shared_secret = ECDH(Alice@Bob 会话私钥, 监管方 AID 主公钥)
```

**对端接收方**：

```
shared_secret = ECDH(Bob@Alice 会话私钥, Alice@Bob 会话公钥)
```

**监管方接收**（监管方用自己的 AID 主私钥）：

```
shared_secret = ECDH(监管方 AID 主私钥, Alice@Bob 会话公钥)
```

所有共享秘密本地缓存复用。

### 5.3 P2P 消息结构

```json
{
  "type": "e2ee.p2p_encrypted",
  "version": "1",
  "suite": "P256_HKDF_SHA256_AES_256_GCM",
  "msg_type": "original",
  "t_send": 1710504000000,
  "t_supplement": null,
  "t_server": null,
  "nonce": "base64(12B)",
  "ciphertext": "base64",
  "tag": "base64(16B)",
  "sender_signature": "base64(ECDSA-SHA256)",
  "sender_cert_fingerprint": "sha256:64hex",
  "sender_peer_pk_fingerprint": "sha256:16hex",
  "recipients_digest": "64hex",
  "aad": {
    "from": "alice.agentid.pub",
    "to": "bob.agentid.pub",
    "message_id": "p2p-uuid",
    "timestamp": 1710504000000,
    "suite": "P256_HKDF_SHA256_AES_256_GCM"
  },
  "recipients": {
    "columns": ["aid", "role", "fp", "nonce", "wrapped_key"],
    "rows": [
      ["bob.agentid.pub", "peer", "sha256:16hex", "base64(12B)", "base64(48B)"]
      // 监管方行由服务端配置后由 SDK 注入，业务层不可见
    ]
  }
}
```

| 字段 | 说明 |
| --- | --- |
| msg_type | `original` 或 `supplement`（P2P 极少用补发，但协议允许） |
| t_send / t_supplement / t_server | 同群聊语义 |
| sender_peer_pk_fingerprint | 发送方自己用于本次加密的 Peer 公钥指纹（对端用它识别用哪版对端公钥做 ECDH） |
| recipients.rows[].fp（第 3 列） | 对端 = 对端 `Bob@Alice` 公钥指纹；监管方 = 监管方 AID 证书指纹 |
| recipients_digest | 覆盖**完整** recipients 表（含监管方）的 SHA-256 |

### 5.4 P2P 加密流程

与群聊一致（见 §6.3），仅差异在 `info` 串：

```
info = "aun-p2p:" + message_id + ":" + recipient.aid
```

### 5.5 P2P 解密流程

与群聊解密（§6.5）一致，业务成员看到的 `recipient` 字段仅含自己一项（服务端按需投递时剔除其他项含监管方项）。

对端解密成功；监管方用 AID 主私钥按同样流程解密。

---

## 6. 群聊加密（Hybrid 模式）

### 6.1 核心思路

每条群消息使用一次性"主对称密钥"加密正文，主密钥被为每个成员独立封装为"小包"。

### 6.2 共享秘密推导

发送方 Alice 给群成员 X 推导共享秘密：

```
shared_secret_AX = ECDH(Alice@group 私钥, X@group 公钥)

```

接收方 X 收到 Alice 发的消息：

```
shared_secret_AX = ECDH(X@group 私钥, Alice@group 公钥)

```

**该共享秘密对每对成员永久不变**，本地缓存复用。

### 6.3 消息加密流程

```
1. message_id = "gm-" + uuid()
2. master_key = random(32)
3. nonce = random(12)
4. aad_bytes = canonical_json(aad)
5. ciphertext, tag = AES-256-GCM(master_key, nonce, plaintext, aad_bytes)

6. 对每个目标成员 X（含监管方）:
     // 普通成员: 用 X 的群内公钥
     // 监管方:   用监管方的 AID 主公钥（监管方无群内密钥）
     shared_X = ECDH(Alice@group 私钥, X 的对应公钥)   // 缓存命中则查表
     wrap_key_X = HKDF-SHA256(
       ikm    = shared_X,
       salt   = None,
       info   = "aun-group:" + group_id + ":msg:" + message_id + ":" + X.aid,
       length = 32
     )
     wrap_nonce_X = random(12)
     wrapped_key_X = AES-256-GCM(wrap_key_X, wrap_nonce_X, master_key, "")
     // master_key 是 32 字节 + 16 字节 GCM tag = 48 字节密文

     row_X = [
       X.aid,                          // 第 0 列: aid
       "member" | "audit",             // 第 1 列: role
       对应公钥的 64 位截断指纹,        // 第 2 列: fp
       base64(wrap_nonce_X),           // 第 3 列: nonce
       base64(wrapped_key_X)           // 第 4 列: wrapped_key
     ]

7. recipients = {
     "columns": ["aid", "role", "fp", "nonce", "wrapped_key"],
     "rows": [row_1, row_2, ..., row_N, ...监管方行]
   }
   rows 按第 0 列（aid）字典序升序排序（监管方与成员混合排序）

8. recipients_digest = SHA-256(canonical_json(recipients)).hex()
   // 具体规则见 §7.3，canonical_json 按 §7.2

9. signature = ECDSA-SHA256-RAW(
     AID 主私钥,
     ciphertext || tag || aad_bytes || recipients_digest_bytes
   )
   // recipients_digest_bytes = hex_decode(recipients_digest) → 32 字节 raw binary

```

### 6.4 群消息结构

```json
{
  "type": "e2ee.group_encrypted",
  "version": "1",
  "suite": "P256_HKDF_SHA256_AES_256_GCM",
  "msg_type": "original",
  "t_send": 1710504000000,
  "t_supplement": null,
  "t_server": null,
  "nonce": "base64(12B)",
  "ciphertext": "base64",
  "tag": "base64(16B)",
  "sender_signature": "base64(ECDSA-SHA256)",
  "sender_cert_fingerprint": "sha256:64hex",
  "recipients_digest": "64hex",
  "members_version": 42,
  "aad": {
    "group_id": "g-abc123.agentid.pub",
    "from": "alice.agentid.pub",
    "message_id": "gm-uuid",
    "timestamp": 1710504000000,
    "suite": "P256_HKDF_SHA256_AES_256_GCM"
  },
  "recipients": {
    "columns": ["aid", "role", "fp", "nonce", "wrapped_key"],
    "rows": [
      ["bob.agentid.pub",   "member", "sha256:a3b2c1d4e5f60718", "base64(12B)", "base64(48B)"],
      ["carol.agentid.pub", "member", "sha256:b4c3d2e1f6071829", "base64(12B)", "base64(48B)"]
      // 监管方行由 SDK 自动注入，业务层不可见
    ]
  }
}

```
| 字段 | 说明 |
| --- | --- |
| msg_type | `original`（原始消息）或 `supplement`（补发消息） |
| t_send | 发送方本地时间，原始消息发送时间。补发消息**保持原值不变**（用于 `uncovered_members` 时间基准过滤） |
| t_supplement | 补发消息发送时间（发送方本地）；原始消息为 `null` |
| t_server | 服务端收到消息的时间。**原始消息发送时为 `null`**，由服务端在 RPC 响应中回填 |
| members_version | 发送方本地已知的群成员版本号；用于服务端 delta 同步 |
| recipients_digest | 规范化 recipients 表（含监管方）的 SHA-256 完整指纹（hex） |
| recipients.columns | 表头列名固定顺序：`["aid", "role", "fp", "nonce", "wrapped_key"]` |
| recipients.rows | 每行对应一个收件人；`role` 取值 `member`（群成员）或 `audit`（监管方） |
| recipients.rows[].fp（第 3 列） | 群成员 = 群内公钥指纹；监管方 = AID 证书指纹 |
| aad.timestamp | 与 `t_send` 一致的毫秒级 Unix 时间戳；服务端 ±5 分钟新鲜度校验 |

**recipients 表头格式说明**：相比传统字典数组，每行节省约 44 字节字段名开销。200 人群消息从 ~35 KB 降到 ~26 KB，降幅 25%。表头列名 `columns` 顺序**固定**，不得调整。

### 6.5 群消息解密流程

按需投递场景下，接收方拿到的不是完整 `recipients`，而是服务端定制的单项 `recipient`（dict 格式，见 §6.6.2）。

```
1. 取出投递包中的 recipient 字段（dict: aid, role, fp, nonce, wrapped_key）
2. 校验 recipient.aid == self.aid，否则拒绝（不属于本人）
3. 通过 recipient.fp 找本地 self@group 私钥版本
4. 通过 aad.from + sender_cert_fingerprint 找发送方证书 + 发送方 group_pk
5. shared = ECDH(self@group 私钥, 发送方 group_pk)
6. wrap_key = HKDF(shared, info="aun-group:{group_id}:msg:{message_id}:{self.aid}")
7. master_key = AES-256-GCM-Decrypt(wrap_key, recipient.nonce, recipient.wrapped_key, "")
8. plaintext = AES-256-GCM-Decrypt(master_key, nonce, ciphertext, tag, aad_bytes)
9. 验证 sender_signature 覆盖 ciphertext || tag || aad_bytes || recipients_digest_bytes
   // recipients_digest 直接信任消息中携带的值（§7.4）
10. 防重放：检查 {group_id, sender_aid, message_id} 不在 seen 集合

```

任一步失败 → 拒绝消息，不消费。

监管方解密流程相同，区别在第 5 步用 AID 主私钥而非 group 私钥（详见 §12.5）。

### 6.6 服务端按需投递（必需）

服务端**必须**实施按需投递，不得全广播。

#### 6.6.1 服务端处理

收到 `group.send` 后：

```
1. 校验 t_send（补发为 t_supplement）在服务端当前时间 ±5 分钟内
2. 校验 from == 发送方认证 AID
3. 校验发送方仍是群成员，否则返回 not_member 错误
4. 从 recipients.rows 按 role 分两组（第 1 列）:
     - role=member 项：业务成员
     - role=audit  项：监管方
5. 校验监管方覆盖：
     - 服务端配置生效的 audit_aids = 群级配置 ∪ 全局配置（剔除证书已吊销的 AID）
     - role=audit 行的 AID（第 0 列）集合 MUST 等于上述生效列表
     - 不一致 → 返回 -33011 E2EE_MISSING_AUDIT_RECIPIENT
6. 比对业务成员行每项 fp（第 2 列）vs 成员表中该成员当前群内公钥指纹：
     - 不匹配 → 加入 cert_rotated 列表，附带服务端记录的新指纹
     - 该 aid 已非群成员 → 加入 dropped_ghosts 列表
7. 计算 uncovered_members = 群成员中 joined_at ≤ t_send
                           且不在 role=member 行中的成员
8. 对每个有效业务成员，定制投递包：
     公共部分：type/version/suite/nonce/ciphertext/tag/
              sender_signature/sender_cert_fingerprint/
              recipients_digest/aad/msg_type/t_send/t_supplement/t_server
     私有部分：该业务成员对应的 recipient entry（dict 格式，见 §6.6.2）
              （监管方行被剔除，业务成员看不到监管方存在）
9. 对每个监管方，定制投递包到该监管方的消息队列：
     公共部分：同上 + sender_session_pk（见 §12.5）
     私有部分：仅该监管方对应的 recipient entry（role=audit）
10. 服务端不修改 recipients_digest，不重签名
11. 回复发送方响应（见 §6.7.2，响应中不含监管方信息）

```

#### 6.6.2 接收方收到的投递包结构

服务端按需投递时，把发送方上行的 `recipients` 拆开，仅保留接收方自己那一行，并以 **dict 格式**（不是表头+行列表）放入 `recipient`（单数）字段：

```json
{
  "type": "e2ee.group_encrypted",
  "version": "1",
  "suite": "P256_HKDF_SHA256_AES_256_GCM",
  "msg_type": "original",
  "t_send": 1710504000000,
  "t_supplement": null,
  "t_server": 1710504000234,
  "nonce": "...",
  "ciphertext": "...",
  "tag": "...",
  "sender_signature": "...",
  "sender_cert_fingerprint": "...",
  "recipients_digest": "...",
  "aad": { ... },
  "recipient": {
    "aid": "self.aid",
    "role": "member",
    "fp": "...",
    "nonce": "...",
    "wrapped_key": "..."
  },
  "seq": 12345,
  "server_time": 1710504001234
}

```

| 字段 | 说明 |
| --- | --- |
| recipient | 单项 dict 格式（不是 columns+rows）；按需投递只有一行，dict 比列表更直观 |
| seq | 服务端为该接收方消息队列分配的顺序号（不入签名域） |
| server_time | 服务端实际投递时间（不入签名域） |

监管方收到的投递包结构相同，区别是：
-   `recipient.role = "audit"`
-   多一个 `sender_session_pk` 字段（DER 编码的发送方群内公钥），见 §12.5

### 6.7 冲突处理与二次补发

#### 6.7.1 请求

`group.send` 请求体包含完整 envelope（§6.4）+ `members_version` 字段。其中：
-   `t_send` 由发送方填写（原始消息为发送时间，补发消息保持原值不变）
-   `t_supplement` 仅补发时填写
-   `t_server` 在请求中**必须**为 `null`（保留位）

#### 6.7.2 响应

```json
{
  "message_id": "gm-uuid",
  "status": "accepted",
  "msg_type": "original",
  "t_server": 1710504000234,
  "request_members_version": 42,
  "server_members_version": 45,
  "members_delta": {
    "added": [
      {
        "aid": "carol.agentid.pub",
        "group_pk": "base64(DER)",
        "fp": "sha256:...",
        "joined_at": 1710503999000
      }
    ],
    "removed": ["bob.agentid.pub"],
    "cert_changed": [
      {
        "aid": "dave.agentid.pub",
        "new_fp": "sha256:...",
        "new_group_pk": "base64(DER)"
      }
    ]
  },
  "delivered_count": 18,
  "dropped_ghosts": ["bob.agentid.pub"],
  "cert_rotated": [
    {
      "aid": "dave.agentid.pub",
      "new_fp": "sha256:...",
      "new_group_pk": "base64(DER)"
    }
  ],
  "uncovered_members": [
    {
      "aid": "carol.agentid.pub",
      "fp": "sha256:...",
      "group_pk": "base64(DER)"
    }
  ]
}

```
| 字段 | 含义 |
| --- | --- |
| msg_type | 回显本次请求的消息类型（`original` / `supplement`） |
| t_server | 服务端收到消息的时间（毫秒）；客户端用作消息时序基准与本地存档 |
| request_members_version | 回显发送方本次请求的版本号 |
| server_members_version | 服务端当前生效版本号（取 `changed_at ≤ t_server` 的最大版本） |
| members_delta | 两个版本之间的合并差集；包含 `added` / `removed` / `cert_changed` 三组；`{"need_full_sync": true}` 表示差距超出 changelog 窗口 |
| delivered_count | 计划投递的业务成员人数（不含监管方） |
| dropped_ghosts | recipients 中已非群成员的 AID |
| cert_rotated | recipients 中指纹过期的成员 + 服务端已知的新公钥（**仅本次清单内的项**） |
| uncovered_members | `joined_at ≤ t_send` 但 recipients 漏掉的成员 + 公钥 |

#### 6.7.3 发送方对响应的处理

1.  本地存档原始消息时回填 `t_server`
2.  应用 `members_delta` 到本地缓存，更新本地 `members_version`
3.  对 `cert_rotated`：用响应附带的新公钥替换本地缓存（新公钥附 AID 主签名背书，需验证）
4.  对 `uncovered_members`：缓存其 group_pk
5.  若 `cert_rotated ∪ uncovered_members` 非空 → 触发**一次**补发

#### 6.7.4 二次补发

补发消息 = 原消息的同一条，**仅以下变化**：

-   `msg_type`：`supplement`
-   `t_supplement`：填补发时刻
-   `t_send`：**保持原值不变**（用于 `uncovered_members` 时间基准过滤）
-   `recipients`：仅含 `cert_rotated ∪ uncovered_members`
-   `recipients_digest` 与 `sender_signature`：按新清单重新计算、重新签名

**不变**：`message_id`、`ciphertext`、`tag`、`aad`、`master_key`。

服务端**完全无状态**处理：按清单投递即可，不依赖"原消息是否存在"上下文。

每个接收方仅会收到一次（原消息或补发其中之一）。

#### 6.7.5 收敛性与硬上限

`uncovered_members` 以 `t_send` 为时间基准过滤——目标群体在发消息瞬间固定，不随后续成员加入变化。

**协议硬约束：每条消息最多补发 1 次**（即原消息 + 1 次补发，共 2 轮）。

补发响应中若仍有非空 `cert_rotated` / `uncovered_members`，客户端**禁止**再次补发，停止并上报业务层。这是极端罕见场景（短时间内多次证书轮换或群急剧变动），由业务层决定是否整体重发。

#### 6.7.6 发送方已非成员

服务端检测到发送方非当前群成员：

```json
{
  "error": "not_member",
  "server_members_version": 45
}

```

客户端应停止对该群发送并通知用户。不进入 delta / 补发流程。

#### 6.7.7 时间戳新鲜度

服务端 **MUST** 校验 `t_send` 在服务端当前时间 ±5 分钟（补发消息以 `t_supplement` 为准校验）。越界即拒绝（防止重放、防止客户端篡改时间戳操纵 `uncovered_members` 过滤基准）。

### 6.8 成员管理

#### 6.8.1 成员版本号与 changelog

**成员版本号**是单调递增的整数，服务端为每个群维护。每次成员变更（加入 / 退出 / 踢出 / 通信证书或身份证书更换）版本号 +1。

**每条变更记录**持久化一行 JSON（建议 `members_changelog.jsonl` 追加写）：

```json
{
  "version": 45,
  "changed_at": 1710504000000,
  "full_members": ["alice.agentid.pub", "bob.agentid.pub", "carol.agentid.pub"],
  "added": ["carol.agentid.pub"],
  "removed": ["dave.agentid.pub"],
  "cert_changed": ["bob.agentid.pub"]
}
```

| 字段 | 含义 |
|---|---|
| version | 该版本号 |
| changed_at | 该版本生效的服务端时间（毫秒） |
| full_members | 该版本下的完整成员 AID 列表 |
| added | 本次新增的成员 |
| removed | 本次移除的成员 |
| cert_changed | 本次更换了通信证书或身份证书的成员 |

**内存缓存**只保留最新版本 + 最近 N 条变更记录（用于响应 delta 查询），历史版本从持久化文件恢复即可。

#### 6.8.2 服务端版本确定（关键）

服务端收到 `group.send` 时：

```
t_server = 服务端当前时间
server_effective_version = max(v) where changelog[v].changed_at ≤ t_server
```

即：**服务端生效版本 = 消息到达时间之前的最后一个版本号**。响应中 `server_members_version` 填这个值。

这样无论客户端用的 `members_version` 是 42、还是最新的 45，服务端都能基于同一个"消息时刻快照"计算 delta。

#### 6.8.3 delta 合并

服务端生成响应 `members_delta` 时，合并 `request_members_version + 1` 到 `server_effective_version` 之间所有变更记录：

-   `added`：期间加入且当前仍在的
-   `removed`：期间移除且当前仍不在的
-   `cert_changed`：期间更换过证书且当前仍在的

若差距超过 changelog 保留窗口（建议最近 200 次），响应：
```json
"members_delta": {"need_full_sync": true}
```
客户端应调用 `group.get_members` 全量同步。

#### 6.8.4 `group.members_changed` 事件

服务端在成员变更时主动推送：

```json
{
  "event": "group.members_changed",
  "group_id": "g-abc123.agentid.pub",
  "version": 46,
  "changed_at": 1710504050000,
  "added": [
    {
      "aid": "...",
      "group_pk": "...",
      "fp": "...",
      "joined_at": 1710504050000
    }
  ],
  "removed": ["..."],
  "cert_changed": [
    {
      "aid": "...",
      "new_fp": "...",
      "new_group_pk": "..."
    }
  ]
}

```

#### 6.8.5 群规模上限

-   **硬上限 200 人**
-   超过 200 人的群，协议层拒绝 `group.send` 携带加密 envelope，业务层降级为明文

#### 6.8.6 changelog 签名（防服务端篡改成员表）

**威胁**：服务端可以在成员表里悄悄加一个攻击者 AID（含伪造的群内公钥），下发给客户端时客户端会把它当合法成员，加密时将 wrapped_key 一并包给攻击者，攻击者即可解密群消息。

**防御**：每条 changelog 记录由**群主或管理员**用 AID 主私钥签名。客户端按策略选择是否信任某个版本。

**签名输入**（Canonical JSON，按 §7.2 规则）：

```
sign_data = canonical_json({
  "group_id": "g-abc123.agentid.pub",
  "version": 45,
  "changed_at": 1710504000000,
  "full_members": [...],
  "added": [...],
  "removed": [...],
  "cert_changed": [...]
})

signature = ECDSA-SHA256-RAW(签名者 AID 主私钥, sign_data)
```

**签名者规则**：

| 场景 | 签名者 |
| --- | --- |
| 创世版本（建群第 1 版） | 群主自己 |
| 后续任意版本 | 群主或任意管理员（单签即可） |

**签名时机**：
-   管理员执行加人/踢人/批准入群操作时，签发对应新版本
-   管理员收到 `members_changed` 事件且自己是群主/管理员时，自动 catch-up 签名
-   管理员发现存在"未签名且将过 24 小时"的版本时，主动签发

签名后通过 `group.e2ee.put_members_signature` RPC 上传到群服务端。

**签名验证**：

客户端验签失败（签名存在但无效）**等效于未签名处理**（不直接拒绝该版本，进入 §6.8.7 的客户端选择流程）。

**群管理员最低数量**：群主本身就是管理员。删除最后一个管理员（即删除群主）等同于**解散群**，协议允许但业务层必须明确告知用户。

#### 6.8.7 客户端选择 members_version 规则

客户端发送消息前选择使用哪个 `members_version`：

```
让 latest_signed = 所有已签名且验签通过的版本中 version 最大的
让 latest_any    = changelog 中 version 最大的（无论是否已签名）

if latest_any == latest_signed:
    # 已签名就是最新
    use_version = latest_signed
elif now() - latest_any.changed_at >= 24h:
    # 未签名版本已经过 24 小时观察期，视为可信（假设管理员有足够时间反应）
    use_version = latest_any
else:
    # 未签名版本在 24 小时观察期内，不可信，回退到最近的已签名版本
    use_version = latest_signed
```

**设计意图**：管理员对成员变更签名是**主动的**。如果 24 小时内都没有管理员签名，要么是他们故意不签（拒绝该变更），要么是服务端伪造的变更（管理员根本不知道）。24 小时容忍窗口给真实管理员留出反应时间——在 AUN 里管理员全员 24 小时失联是极小概率事件。

**边界**：若 `latest_signed` 也不存在（创世版本都未签名），客户端拒绝发送，报错 `-33013 E2EE_MEMBERS_VERSION_UNSIGNED`。

### 6.9 端到端典型时序

#### 6.9.1 群聊正常发送

```
Alice                          群服务端                       Bob              监管方
─────────────────────────────────────────────────────────────────────────────────────
组装 envelope（含完整
recipients：业务+监管）
ECDSA 签名
group.send (envelope, members_version=42)
─────────────────────────────>
                               校验 t_send / 监管覆盖 /
                               按需投递
                               <───────────────  公共部分 + Bob 单项 recipient
                               <───────────────────────────────────  公共部分 + 监管单项 +
                                                                     sender_session_pk
                               t_server 回填
<──────────────── RPC 响应（t_server, members_delta, ...）
本地存档 t_server
                                                          ECDH + 解密 + 验签
                                                                                  ECDH + 解密 + 验签
```

#### 6.9.2 触发补发

```
Alice                          群服务端                       Bob          Carol（新加入）
─────────────────────────────────────────────────────────────────────────────────────
group.send (envelope, members_version=42)
─────────────────────────────>
                               检测 Carol 是 uncovered_member
                               （joined_at < t_send 且不在清单）
                               按现有清单投递给 Bob
                               <─────────────────  公共部分 + Bob 项
<──── 响应（uncovered_members=[Carol], cert_rotated=[]）

补发 envelope：
- t_send 不变 / msg_type=supplement / t_supplement=now()
- recipients = [Carol 项]
- 重算 digest + 重签名
group.send (补发 envelope)
─────────────────────────────>
                               按 [Carol] 投递
                                                                          公共部分 + Carol 项 ──>
<──── 响应（uncovered_members=[], cert_rotated=[]）
```

#### 6.9.3 changelog 签名 catch-up

```
Admin（Alice）                 群服务端                       客户端（Bob）
─────────────────────────────────────────────────────────────────────
                               收到群人员加入事件，version=46
                               生成未签名版本
                               推送 group.members_changed (version=46) 到所有成员
                               ──────────────────────────>
                                                          看到未签名版本 46
                                                          按 §6.8.7：在 24h 内回退到 latest_signed=45
推送收到 + 自己是 owner
对 version 46 计算签名
group.e2ee.put_members_signature
─────────────────────────────>
                               存档 + 推送 members_changed 二次更新
                               ───────────────────────────>
                                                          验签通过 → 升级 latest_signed=46
                                                          下次发送即可使用 version=46
```

---

## 7. 签名机制

### 7.1 签名域

```
P2P 和群聊统一：  ECDSA(AID 主私钥, ciphertext || tag || aad_bytes || recipients_digest_bytes)

```

每条消息**仅签名一次**，所有接收方共用同一份签名验证。补发消息需重新计算 digest 并重签名（因 recipients 变化）。

### 7.2 Canonical JSON（用于 AAD 与 recipients 序列化）

1.  所有对象（包括嵌套）的键按 Unicode 码点升序排列（递归）
2.  紧凑格式：`,` 和 `:` 分隔，无空白
3.  UTF-8 直接输出，非 ASCII 字符 **MUST NOT** 转义为 `\uXXXX`
4.  整数值不带小数点
5.  布尔值小写 `true`/`false`，空值 `null`

Python 等价：`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`

### 7.3 recipients_digest 计算

recipients 采用表头 + 行的紧凑格式（见 §5.3 / §6.4）。digest 计算的输入为整个 `recipients` 对象按 §7.2 Canonical JSON 序列化后的字节。

```
1. rows 按第 0 列（aid）字典序升序排序
2. canonical_form = canonical_json({
     "columns": ["aid", "role", "fp", "nonce", "wrapped_key"],
     "rows": [[...], [...], ...]
   })
3. recipients_digest = SHA-256(canonical_form).hex()  // 64 hex chars
```

**关键约束**：
-   `columns` 顺序固定为 `["aid", "role", "fp", "nonce", "wrapped_key"]`，不得调整
-   每行长度必须等于 5
-   整个对象（键、数组）按 §7.2 递归排序规范化

### 7.4 验签

接收方：

1.  取消息中的 `aad` 重新做 canonical 序列化得 `aad_bytes'`
2.  取消息中的 `recipients_digest`
3.  用发送方 AID 证书公钥验证 `sender_signature` 覆盖 `ciphertext || tag || aad_bytes' || recipients_digest_bytes`

按需投递场景下，接收方仅有自己那项 recipient，**不重算 recipients_digest**——直接信任消息中携带的值。digest 入签名域，篡改即破签。

---

## 8. 防重放

### 8.1 消息去重

接收方维护本地 `seen_messages` 集合：

-   P2P：key = `{sender_aid}:{message_id}`
-   群聊：key = `{group_id}:{sender_aid}:{message_id}`

同一 key 的消息 **MUST** 被拒绝。

### 8.2 时间戳新鲜度

服务端在收到 `group.send` / `message.send` 时校验 `t_send`（补发消息以 `t_supplement` 为准）在当前时间 ±5 分钟。越界拒绝。

接收方解密时**不强制** timestamp 校验（消息可能在队列中等待较久）。

### 8.3 seen 窗口大小

-   内存中至少保留最近 50000 条记录
-   持久化保留最近 7 天的 `{sender_aid, message_id}` 哈希
-   超过窗口的"旧消息"按异常处理（拒绝或告警）

---

## 9. 服务端 RPC 列表

### 9.1 P2P 密钥管理

| RPC | 用途 |
| --- | --- |
| message.e2ee.put_peer_pk | 上传/更新本端给对端的 Peer 公钥 |
| message.e2ee.get_peer_pk | 拉取对端给本端发布的 Peer 公钥 |
| message.e2ee.bootstrap | 首次与某对端通信时初始化：返回监管方列表 + 证书 |

#### put_peer_pk

```json
请求 {
  "peer_aid": "bob.agentid.pub",
  "peer_pk": "base64(DER SubjectPublicKeyInfo)",
  "fp": "sha256:16hex",
  "created_at": 1710504000000,
  "signature": "base64(AID 主私钥 RAW 签名 of peer_pk||peer_aid||created_at)"
}
响应 { "ok": true }

```

#### get_peer_pk

```json
请求 { "owner_aid": "alice.agentid.pub", "peer_aid": "bob.agentid.pub" }
响应 {
  "found": true,
  "peer_pk": "base64",
  "fp": "sha256:16hex",
  "created_at": 1710504000000,
  "signature": "base64(RAW 64B)"
}

```

#### bootstrap

P2P 场景下首次准备与某对端通信时调用，返回服务端当前对该 P2P 通道生效的监管方列表 + 证书。

```json
请求 { "peer_aid": "bob.agentid.pub" }
响应 {
  "audit_aids": ["audit1.regulator.pub", ...],
  "audit_certs": {
    "audit1.regulator.pub": "base64(PEM 证书)",
    ...
  },
  "audit_ttl_seconds": 86400
}

```

证书已吊销的 AID **MUST** 被服务端剔除不返回。

### 9.2 群内密钥管理

| RPC | 用途 |
| --- | --- |
| group.e2ee.put_member_pk | 入群时上传成员的群内公钥 |
| group.get_members | 拉取群成员列表 + 监管方列表 + changelog 签名 |
| group.e2ee.put_members_signature | 群主/管理员对某 changelog 版本签名后上传 |

#### put_member_pk

```json
请求 {
  "group_id": "g-abc123.agentid.pub",
  "group_pk": "base64(DER)",
  "fp": "sha256:16hex",
  "created_at": 1710504000000,
  "signature": "base64(AID 主私钥 RAW 签名 of group_pk||aid||group_id||created_at)"
}
响应 { "ok": true }

```

#### get_members

```json
请求 { "group_id": "g-abc123.agentid.pub" }
响应 {
  "members_version": 45,
  "members_version_signature": {
    "signed_by": "alice.agentid.pub",
    "signer_role": "owner",
    "signature": "base64(RAW 64B)"
  },
  "members": [
    {
      "aid": "bob.agentid.pub",
      "group_pk": "base64",
      "fp": "sha256:16hex",
      "joined_at": 1710504000000,
      "signature": "base64"
    }
  ],
  "audit_aids": ["audit1.regulator.pub"],
  "audit_certs": {
    "audit1.regulator.pub": "base64(PEM)"
  },
  "audit_ttl_seconds": 86400
}

```

字段说明：
-   `members_version_signature`：本版本号的群主/管理员签名（缺失则该版本未签名，客户端按 §6.8.6 处理）
-   `members`：服务端**不含**监管方（监管方不计入成员）
-   `audit_aids` / `audit_certs`：当前生效的监管方列表与证书

#### put_members_signature

群主或管理员对 changelog 中某个版本签名后上传：

```json
请求 {
  "group_id": "g-abc123.agentid.pub",
  "version": 45,
  "signed_by": "alice.agentid.pub",
  "signer_role": "owner",
  "signature": "base64(RAW 64B)"
}
响应 { "ok": true }

```

服务端 **MUST** 校验：
-   `signed_by` 是当前群主或管理员
-   签名验证通过（按 §6.8.7 签名输入计算）
-   失败则拒绝

### 9.3 消息发送

| RPC | 用途 |
| --- | --- |
| message.send | 发送 P2P 消息 |
| group.send | 发送群消息（含 members_version） |

`group.send` 响应见 §6.7.2。

### 9.4 取消的 RPC（与旧方案对比）

新方案不再使用以下旧方案 RPC：

-   `message.e2ee.put_prekey` / `get_prekey`
-   `message.e2ee.record_replay_guard`
-   `group.e2ee.get_epoch` / `rotate_epoch`
-   `group.e2ee.key_request` / `key_response`

### 9.5 取消的协议层字段

-   **`client_signature`**：旧方案要求 `group.send` / `group.kick` 等 RPC 附带客户端操作签名。新方案**取消此字段**——`sender_signature`（ECDSA over `ciphertext || tag || aad || recipients_digest`）已完整覆盖消息内容与完整性，客户端操作签名属于重复保护。减少协议噪音。

---

## 10. 客户端缓存

### 10.1 必须维护的本地状态

```
keystore/
├── aid_main.key                    # AID 主私钥
├── peer_keys/
│   └── {peer_aid}.key              # Alice@{peer_aid} 的私钥
└── group_keys/
    └── {group_id}.key              # Alice@{group_id} 的私钥

caches/
├── peer_pk_cache/                  # 对端 Peer 公钥
│   └── {peer_aid} → {peer_pk, fp, expire_at}
├── group_member_cache/             # 群成员表 + changelog
│   └── {group_id} → {
│         members_version,
│         members_version_signature,    # 最新签名（若有）
│         members: [{aid, group_pk, fp, joined_at}],
│         changelog: [{version, changed_at, full_members, added, removed, cert_changed, signature}]
│       }
├── audit_cache/                    # 监管方（对业务层不可见）
│   ├── p2p_audit_aids              # P2P 通道生效的监管方列表
│   ├── group_audit_aids/{group_id} # 群级生效的监管方列表
│   └── audit_certs/{aid}           # 监管方 AID 证书（验签用）
├── shared_secret_cache/            # ECDH 缓存（可选优化）
│   └── {pub_key_fp} → {shared_secret_bytes}
├── cert_cache/                     # 对端 AID 证书（验签用）
│   └── {aid}:{cert_fp} → {cert_pem}
└── seen_messages/                  # 防重放
    └── {sender_aid, message_id} → {timestamp}

```

### 10.2 缓存 TTL 与失效

| 缓存 | TTL | 失效触发 |
| --- | --- | --- |
| Peer 公钥 | 长期（≥ 7 天） | 收到 cert_rotated / 解密失败懒加载 |
| 群成员表（含 changelog） | 长期 | members_changed 事件 / 响应中的 members_delta |
| 共享秘密（shared_secret） | 同源公钥的 TTL | 公钥失效则共享秘密失效 |
| AID 证书 | 10 分钟（匹配现行实现） | 解密失败懒加载 |
| 监管方列表（audit_aids）| 24 小时 | 收到 -33011 错误自动刷新；过期前主动刷新 |
| 监管方证书（audit_certs）| 同 audit_aids | 同上 |
| seen_messages | 7 天 | 自动过期 |

### 10.3 冷启动流程

新加入群组时：

1.  `group.get_members` 拉取完整成员列表（含所有 group_pk）
2.  本地建立群成员表缓存
3.  验证每项的 AID 主签名背书
4.  （可选）预热 shared_secret 缓存

200 人群冷启动一次性流量约 1 MB，一次完成，之后零拉取。

---

## 11. 安全属性

### 11.1 保证的属性

| 属性 | 机制 |
| --- | --- |
| 机密性 | ECDH + AES-GCM；服务端无私钥 |
| 完整性 | AES-GCM AEAD tag |
| 防篡改 | aad 字段入签名域；recipients_digest 入签名域 |
| 防伪造 | 发送方 AID 主私钥签名；接收方查证书验签 |
| 防重放 | seen_messages + t_send 新鲜度 |
| 防服务端注入虚假成员 | changelog 签名（§6.8.6）+ 24 小时观察窗口（§6.8.7） |
| 防服务端篡改清单 | recipients_digest 入签名域 |
| 防客户端伪造 digest | 签名覆盖 digest；伪造导致验签失败；不产生实际损害 |
| 密钥隔离 | Peer/群内密钥与 AID 主密钥分层；泄露作用域限于该对 Peer / 该群 |

### 11.2 明确放弃的属性

| 属性 | 为什么放弃 |
| --- | --- |
| 消息级前向安全（PFS） | §2 论证：本地明文存档使 PFS 实际意义有限 |
| Post-compromise security | 同上 |
| 选择性 DoS 检测 | 接收方按需投递，无法独立验证清单完整性；可被动检测（解密失败） |

### 11.3 已知边界场景

| 场景 | 处理 |
| --- | --- |
| AID 主私钥泄露 | 等同身份冒充，必须吊销证书 + 全网络警告；本方案保护范围以外 |
| 监管方 AID 私钥泄露 | 所有经过该监管方的历史消息可被解；HSM / MPC 保管 + 定期轮换（§12.10）|
| 管理员全员 24 小时以上失联 | 客户端仍按 §6.8.7 回退到最近已签名版本；服务端伪造版本可被发现 |
| 设备丢失 | 用户必须执行 AID 证书轮换；丢失设备本地明文无法远程清除 |
| 服务端故意丢弃某成员投递 | DoS，无法防御（任何 IM 通用问题） |
| 时钟严重偏差（>5 分钟） | 消息被服务端拒绝；客户端需 NTP 同步 |

---

## 12. 监管方机制

### 12.1 动机与原则

AUN 协议允许部署方配置**监管方 AID**，用于合规监管场景。核心原则：

| 原则 | 说明 |
|---|---|
| 业务不可见 | 监管方对业务层 API、UI、普通成员（含群主 / 管理员）**完全不可见**；SDK 内部处理 |
| 不占成员名额 | 监管方不计入群成员数，不在 `group.get_members` 的 `members` 数组返回 |
| 无需入群 | 监管方本身不执行"加入群"操作；SDK 感知到后自动加密给它 |
| 全局通信密钥 | 监管方**所有群、所有 P2P 共用同一对 AID 通信公私钥**（即其 AID 主密钥） |
| 覆盖加密与明文 | 加密消息按 recipients 加密投递；明文消息服务端直接复制副本到监管方队列 |
| 双服务端独立配置 | 消息服务端和群服务端**各自**独立配置 audit_aids |

### 12.2 配置项

**消息服务端**（处理 P2P `message.send`）：
```
message.audit_aids = ["audit1.regulator.pub", "audit2.regulator.pub", ...]
```

**群服务端**（处理 `group.send`）：
```
group.audit_aids.global = [...]      # 全局兜底
group.audit_aids.per_group[group_id] = [...]   # 群级（可选，扩充全局）
```

生效列表 = 群级 ∪ 全局（并集）

### 12.3 监管方列表发现（客户端）

**首次获取**：
| 场景 | 接口 |
|---|---|
| P2P | `message.e2ee.bootstrap(peer_aid)` → `{audit_aids, audit_certs}` |
| 群聊 | `group.get_members(group_id)` 响应新增字段 `{audit_aids, audit_certs}` |

`audit_certs` 包含每个监管方的 AID 证书 PEM，客户端验证证书链后缓存。

**缓存与刷新**：
-   客户端本地缓存 `audit_aids` 列表及证书，**默认 TTL 24 小时**
-   过期后下次需要用时重新获取
-   不主动推送变更——当配置修改时，最坏影响是 24 小时内客户端按旧列表加密

### 12.4 证书吊销处理

-   服务端在下发 `audit_aids` 时，**自动剔除证书已吊销/过期的 AID**——效果等同于从配置中移除
-   客户端不直接感知吊销事件；只要下次拉取时服务端不返回该 AID 即可
-   若某监管方拒绝接收消息（队列投递失败等），服务端**忽略**该失败，不影响业务消息的正常投递

### 12.5 加密路径的监管方处理

#### SDK 加密时

```
1. SDK 从本地缓存读取当前会话的 audit_aids 与 audit_certs
2. 对每个监管方 A：
     shared_A = ECDH(发送方会话私钥, 监管方 AID 主公钥)
     wrap_key_A = HKDF(shared_A, info=<同普通成员 info 串>)
     wrapped_key_A = AES-GCM(wrap_key_A, master_key)
     生成 recipient 项：
       { aid: A.aid, role: "audit", fp: A 的 AID 证书指纹, nonce, wrapped_key }
3. 监管方项与业务成员项一起放入 recipients，按 aid 字典序排序
4. 计算 recipients_digest 时监管方项一并覆盖
```

#### 服务端按需投递时

-   对业务成员：投递包中的 `recipient` 字段**仅含该业务成员自己一项**，不含监管方项（成员看不到监管方）
-   对监管方：投递包中的 `recipient` 字段**仅含该监管方一项**，投递到监管方消息队列

#### 监管方解密

监管方收到投递包后，**服务端在投递给监管方时附加 `sender_session_pk` 字段**（DER 编码的发送方会话公钥）：
-   群聊：发送方在该群的群内公钥
-   P2P：发送方的 Peer 公钥（对应 `sender_peer_pk_fingerprint`）

`sender_session_pk` 不入签名域（监管方需要它才能解密）；**监管方 MUST 用 `sender_cert_fingerprint` 验证发送方证书** + 用证书绑定的 AID 主签名背书验证 `sender_session_pk` 真实属于发送方。

监管方用**自己的 AID 主私钥**做 ECDH：

```
1. 取 recipient.nonce 和 recipient.wrapped_key
2. shared = ECDH(self AID 主私钥, sender_session_pk)
3. wrap_key = HKDF(shared, info="aun-group:{group_id}:msg:{message_id}:{self.aid}")
                                                          ↑ 监管方自己的 AID
4. master_key = AES-GCM-Decrypt(wrap_key, recipient.nonce, recipient.wrapped_key, "")
5. plaintext = AES-GCM-Decrypt(master_key, nonce, ciphertext, tag, aad_bytes)
6. 验发送方 sender_signature 覆盖 ciphertext || tag || aad_bytes || recipients_digest_bytes
```

注意 info 串中的 recipient.aid 是**监管方自己的 AID**，发送方加密时与监管方解密时使用相同 info，派生出相同 wrap_key。

### 12.6 明文消息的监管

当消息不走 E2EE 加密（协议层明文）时：

-   发送方直接 `message.send` / `group.send` 提交明文 payload（`encrypted: false`）
-   服务端落地时，按 §12.2 配置**自动复制明文副本**到每个监管方的消息队列
-   副本不修改 `from` / `timestamp`，仅在内部元数据标记 `audit_copy: true`
-   发送方和业务成员**完全无感知**

### 12.7 服务端校验

**`group.send` 落地校验**：
```
SDK 提交的 recipients 中，role=audit 的 AID 集合 MUST 等于服务端当前生效的 audit_aids。
不一致 → 返回 -33011 E2EE_MISSING_AUDIT_RECIPIENT
```

这确保恶意/旧版客户端无法绕过监管发送加密消息。

**`message.send` 落地校验**：
同上，适用 P2P 的 message.audit_aids 配置。

### 12.8 配置变更

运维侧更新 `audit_aids` 配置后：
-   服务端立即生效，新到达的消息按新列表校验
-   客户端缓存过期（最长 24 小时）后拉到新列表
-   缓存过期前客户端按旧列表加密 → 服务端可能因"缺少新监管方"而拒绝 → 客户端收到错误后主动刷新 audit_aids 重试

即：`-33011 E2EE_MISSING_AUDIT_RECIPIENT` 是客户端触发 audit_aids 缓存刷新的信号之一。

### 12.9 数量上限

建议单个配置项 `audit_aids` **不超过 5 个**。超过会放大消息体积（每个监管方增加约 126 字节 / recipients 一行）且增加 SDK ECDH 开销。

### 12.10 安全考虑

| 风险 | 缓解 |
|---|---|
| 监管方 AID 私钥泄露 | HSM / MPC 分片保管；定期轮换（轮换即 AID 证书轮换，客户端懒加载） |
| 监管方滥用权限 | 治理层审计 + 访问日志 + 多方签名 |
| 监管方单点故障 | 监管方只是消息收件人，不是网关；其离线/拒收不阻塞业务消息投递 |
| 恶意客户端绕过监管 | 服务端强制校验 recipients 中 role=audit 覆盖配置列表 |
| 监管方 AID 被冒充 | 客户端首次获取时验证证书链；`audit_certs` 由 AUN 信任根签发 |

---

## 13. 性能指标

### 13.1 RPC 次数

| 场景 | RPC 数 |
| --- | --- |
| P2P 热路径（缓存命中） | 1 |
| P2P 冷启动（首次给某对端发） | 2（get_peer_pk + send） |
| 群聊热路径（缓存命中） | 1 |
| 群聊补发 | +1 |

### 13.2 消息体积（正文 100 字节，recipients 表头格式）

体积合成公式：

```
total = 固定头部 (~500 B)
      + recipients 表头开销 (~60 B：columns 字段定义)
      + N × 行开销 (~126 B/行：[aid, role, fp, nonce, wrapped_key])
```

每行小包（`[aid, role, fp, nonce, wrapped_key]` 列表，含逗号和方括号）≈ **126 字节/项**，比字典格式节省 ~44 字节。

| 场景 | 体积 |
| --- | --- |
| P2P（含 1 监管方，N=2） | ~1 KB |
| 群聊 100 人（发送方上行，含 1 监管方，N=101） | ~14 KB |
| 群聊 200 人（发送方上行，含 1 监管方，N=201） | ~26 KB |
| 群聊 200 人（每接收方下行，按需投递） | ~820 B |

每多一个监管方，发送方上行消息增加约 ~126 字节（业务成员收到的下行包不变，因为业务成员看不到监管方）。

### 13.3 CPU（单条消息）

| 操作 | 桌面 | 移动端 |
| --- | --- | --- |
| 单次 ECDH | ~60 μs | ~300 μs |
| 单次 ECDSA 签名/验签 | ~80 μs | ~400 μs |
| AES-256-GCM | <10 μs/KB | <50 μs/KB |
| 200 人群发送（首次，全量 ECDH） | ~12 ms | ~60 ms |
| 200 人群发送（缓存命中） | ~1 ms | ~5 ms |
| 200 人群接收（仅自己一项） | ~0.2 ms | ~1 ms |

---

## 14. 错误码

| 错误码 | 名称 | 说明 |
| --- | --- | --- |
| -33001 | E2EE_DECRYPT_FAILED | AEAD 解密失败 |
| -33002 | E2EE_SIGNATURE_INVALID | 发送方签名验证失败 |
| -33003 | E2EE_REPLAY_DETECTED | 消息已在 seen 集合中 |
| -33004 | E2EE_TIMESTAMP_OUT_OF_WINDOW | 时间戳超出 ±5 分钟新鲜度窗口 |
| -33005 | E2EE_PEER_PK_NOT_FOUND | 服务端 Peer 公钥表查无此项 |
| -33006 | E2EE_FINGERPRINT_MISMATCH | 公钥指纹不匹配 |
| -33007 | E2EE_NOT_MEMBER | 发送方非群成员 |
| -33008 | E2EE_GROUP_TOO_LARGE | 群规模超过 200 人，加密被拒绝 |
| -33009 | E2EE_RECIPIENT_NOT_IN_LIST | 接收方 AID 不在 recipients 中 |
| -33010 | E2EE_DIGEST_MISMATCH | recipients_digest 与签名不匹配（仅全广播下接收方使用） |
| -33011 | E2EE_MISSING_AUDIT_RECIPIENT | recipients 中缺少服务端配置的监管方 AID |
| -33012 | E2EE_SUPPLEMENT_LIMIT_EXCEEDED | 补发次数超过协议硬上限（每条消息最多补发 1 次） |
| -33013 | E2EE_MEMBERS_VERSION_UNSIGNED | 无任何已签名的 members_version 可用（如创世版本未签名） |

---

## 15. 实现要求

### 15.1 MUST

-   实现 §4.1 的必选算法套件 + §4.3 字节级编码约定（ECDSA RAW 等）
-   服务端实现 §6.6 的按需投递，不得全广播
-   服务端投递给业务成员时**剔除监管方 recipient 项**（§12.5）
-   服务端投递给监管方时附加 `sender_session_pk`（§12.5）
-   服务端校验 recipients 中 role=audit 覆盖配置的 audit_aids（§12.7）
-   明文消息服务端自动复制到监管方队列（§12.6）
-   实现 §7.2 的 Canonical JSON 序列化
-   实现 §6.7.7 的 t_send 新鲜度校验
-   实现 §8 的防重放
-   实现 §6.8.6 的 changelog 签名机制（群主/管理员签发 + 客户端按 §6.8.7 选择版本）
-   群规模超过 200 人时拒绝加密发送
-   SDK 对业务层 API 隐藏监管方存在（不暴露 audit_aids、不在 UI 展示）

### 15.2 SHOULD

-   实现 shared_secret 缓存优化
-   实现 `group.members_changed` 事件订阅
-   实现冷启动预热
-   SDK 收到 `-33011` 错误时自动刷新 audit_aids 缓存并重试

### 15.3 MAY

-   支持除必选套件外的其他算法套件
-   实现 Merkle Tree 替代 recipients_digest（向前兼容预留）

---

## 16. 与旧方案的不兼容

本方案**不向后兼容**旧 E2EE 方案：

-   envelope 结构不同
-   RPC 集合不同
-   协议状态机不同

**部署策略**：
-   **同一 AUN 网络（同 Gateway 簇）内所有节点必须同期升级**——客户端 SDK、消息服务端、群服务端协同切换
-   跨 AUN 网络通信时，跨网关协议各自维持本地协议版本，需要在网关间消息中转层做协议转换或拒绝跨版本消息
-   产品发布窗口内一次切换，不维护新旧并存代码

---

## 17. 待解决议题

以下议题留待实现阶段细化：

1.  `bulk_get_certs` **RPC 参数与分页策略**：200 人群 ~1 MB 证书数据是否分页
2.  **证书缓存 TTL 微调**：除事件驱动失效外是否加定期强制刷新
3.  **changelog 窗口取值**：建议 200 次，实现可调
4.  **时钟偏差容忍**：若 ±5 分钟在某些场景过严，是否引入客户端报时同步机制
5.  **跨域成员的指纹同步**：成员属于其他 Gateway 时，群服务端如何获取其最新指纹
6.  **Peer 密钥生命周期管理**：是否支持多设备协同（同 AID 多设备分别用各自 Peer 密钥还是共享）
7.  **大规模监管方（>5）的优化路径**：是否引入"监管方组" + 只对组代表加密的机制
8.  **离线监管方的消息队列保留策略**：监管方长期不上线时队列保留期限与告警机制
9.  **多签 changelog 扩展**：未来如需要可扩展为多管理员签名（M-of-N）替代单签
10. **catch-up 签名时序边界**：管理员上线发现历史多个版本未签时的批量签发流程

---

## 18. 变更记录

| 版本 | 日期 | 变更 |
| --- | --- | --- |
| 1.3-draft | 2026-05-13 | 修复扫读发现的 21 条问题；ECDSA 编码定为 RAW；新增 §3.3 Peer 密钥轮换触发条件、§4.3 字节级编码约定、§6.5 解密流程改为按需投递单项格式、§6.8.6/§6.8.7 changelog 签名机制（群主/管理员单签 + 24h 容忍窗口）、§6.9 端到端时序图、§9.1 bootstrap RPC、§9.2 put_members_signature RPC、§9.5 取消 client_signature、§12.5 监管方解密路径细化（sender_session_pk）、§16 多网关协同策略；新增错误码 -33013；统一时间戳字段为 t_send/t_supplement；议题列表扩展到 10 条 |
| 1.2-draft | 2026-05-13 | recipients 改为表头+行列表格式（节省 25% 体积）；新增 msg_type / t_send / t_supplement / t_server 时间字段；§6.7 响应回填 t_server；§6.8 members_version 完整语义（changelog 持久化 + 内存缓存 + delta 合并 + cert_changed 字段）；补发硬上限明确为 1 次；§13 体积数据重算（200 人群 ~26 KB）；新增 -33012 错误码 |
| 1.1-draft | 2026-05-13 | P2P 改为 Hybrid 模式（与群聊统一）；新增 §12 监管方机制（独立 AID、双服务端配置、业务不可见、全局通信密钥、明文也监管）；recipients 增加 role 字段；新增 `-33011` 错误码；§15 实现要求增加监管相关条目 |
| 1.0-draft | 2026-05-13 | 初稿；整合 草案-E2EE-公钥直接加密方案.md v0.8-draft 与 对比-E2EE新旧方案对比.md v1.3 的全部讨论结论 |
