# E2EE 新旧方案机制与对比

> 状态：方案对比
> 日期：2026-05-13
> 新方案详情：`草案-E2EE-公钥直接加密方案.md`
> 旧方案规范：`08-AUN-E2EE.md`（P2P）、`08-AUN-E2EE-Group.md`（群组）
> 相关议题：`议题-E2EE移动端性能与可用性分析.md`

---

## 1. 概述

AUN 现行 E2EE 方案（v2.0-draft）在移动端群聊场景出现严重可用性问题：
- 群聊热路径 5 RPC，epoch 不对齐时退化为 N 次 + 5 秒阻塞
- 密钥分发硬绑定 P2P 通道 → 必须有在线成员响应
- 移动端后台即断连 → "在线成员"长期接近 0 → 密钥恢复常年超时

新方案（v1.0-draft）从第一性原理重新设计：**放弃 PFS 追求，用"直接加密 + 混合封装"替代"共享密钥 + epoch 轮换"**，使每条消息自包含所需解密信息，不依赖任何在线成员，不依赖历史状态。

本文档对比两个方案的工作机制、性能特征和权衡取舍。

---

## 2. 旧方案工作机制

### 2.1 P2P 加密（prekey_ecdh_v2）

**前置**：接收方 Bob 上线时生成一对临时密钥（prekey），公钥 + 自身证书签名上传到服务端。私钥本地保留 7 天。

**Alice 发送给 Bob**：

1. 拉 Bob 的 prekey 公钥（1 RPC：`message.e2ee.get_prekey`）
2. 拉 Bob 的 AID 证书（1 HTTP + PKI 链 + CRL + OCSP 验证）
3. 临时生成一对 ephemeral ECC 密钥
4. **四路 ECDH** 派生消息密钥：
   - DH1 = ECDH(ephemeral, Bob_prekey_pub)
   - DH2 = ECDH(ephemeral, Bob_identity_pub)
   - DH3 = ECDH(Alice_identity, Bob_prekey_pub)
   - DH4 = ECDH(Alice_identity, Bob_identity_pub)
   - message_key = HKDF(DH1 || DH2 || DH3 || DH4)
5. AES-GCM 加密正文
6. ECDSA 签名
7. 发送（1 RPC：`message.send`）

**热路径 3 RPC（首次）/ 1 RPC（缓存命中）。**

**Bob 接收**：
1. 用 prekey 私钥 + Alice identity 公钥 + Alice ephemeral 公钥 完成对偶 ECDH
2. HKDF → message_key
3. AES-GCM 解密 + 验签

**特点**：
- 发送方 ephemeral 私钥用完即丢 → 前向安全（PFS）成立
- 接收方 prekey 私钥保留 7 天 → 7 天内 PFS 打折
- 对端离线也能发（prekey 已上传服务端）

**问题**：
- 冷启动 3 RPC + PKI 全链验证
- Prekey 有生命周期，需定期轮换（服务端压力）
- 跨设备场景要维护 `device_prekeys` 数组

---

### 2.2 群组加密（Epoch Group Key）

**核心概念**：群内成员共享一把 32 字节 `group_secret`，用 `epoch` 版本号管理轮换。每条消息用 HKDF 从 group_secret 派生独立密钥。

**发送消息**：

1. 预检本地 epoch vs 服务端 epoch（1 RPC：`group.e2ee.get_epoch`）
2. 预检成员 `min_read_epoch` 下限（2 RPC：`get_epoch` + `group.get_members`）
3. 取 committed epoch 快照（1 RPC：`get_epoch`，**第三次**）
4. HKDF(group_secret, info="...message_id...") → msg_key
5. AES-GCM 加密 + 签名
6. 调用 `group.send`（1 RPC）+ 客户端签名 + 签名校验

**热路径 5 RPC**。

**成员变更必须 epoch 轮换**：
- 加人、踢人、定时 → 必须生成新 group_secret，epoch +1
- 通过 `group.e2ee.rotate_epoch` RPC 做 CAS 提交
- 对每个成员通过 **P2P E2EE 通道**单独发送 `e2ee.group_key_distribution` 消息（每成员一次 `message.send`）
- 附带 Membership Manifest（签名的成员变更授权凭证）

**离线成员恢复密钥**：
- 成员上线发现本地 epoch 落后 → 遍历候选成员发 `e2ee.group_key_request`
- 在线成员验证请求者身份 → 回 `e2ee.group_key_response`
- 轮询最多 5 秒；无人响应 → `StateError`

**问题（对应 `议题-E2EE移动端性能与可用性分析.md`）**：

| 场景 | 消耗 |
|---|---|
| epoch 不对齐 | 6~N RPC + 5 秒阻塞 |
| 密钥恢复 | 每 150ms 一次 `get_epoch`，最多 33 次；外加多成员 P2P 请求；对端必须在线 |
| 长期离线后上线 | 错过 N 次轮换 → 需要依赖在线成员补 → **常态失败** |
| 移动端后台 | WebSocket 断开 → 密钥恢复路径断 → 群消息发送/解密失败 |

---

### 2.3 旧方案的核心困境

1. **"在线成员响应"是硬依赖**——协议禁止服务端持有 group_secret，密钥分发只能走 P2P E2EE；移动端后台断连场景下这条路径经常断
2. **Epoch 强一致性代价高**——每次发送都要预检/同步，热路径 5 RPC
3. **PFS 追求与移动端可用性本质冲突**——prekey 维护 + epoch 轮换都是为 PFS 付出的代价

---

## 3. 新方案工作机制

### 3.1 核心立场

| 原则 | 含义 |
|---|---|
| 放弃 PFS | 本地消息明文保存，网络密文 PFS 无实际意义 |
| 放弃群共享密钥 | 无 group_secret / epoch / 邮箱 / 密钥恢复 |
| 每条消息自包含 | 不依赖在线成员，不依赖历史状态 |
| 服务端零信任 | 不持有任何私钥，只按清单路由 |

### 3.2 身份密钥分层

| 层级 | 作用 | 生命周期 |
|---|---|---|
| **AID 主密钥** | 身份根，只用来签名和给下级密钥背书 | 跟随 AID 证书 |
| **通信密钥**（Peer 密钥 / 群内密钥） | 每个通信作用域一对，实际参与加密 | Peer/群内独立生成，可独立轮换 |

**关键**：日常加解密不使用 AID 主私钥。AID 主密钥仅在：
- 签名消息
- 给通信密钥做背书
- 轮换时签发新通信密钥

主密钥的日常暴露面极小，泄露概率大幅下降。

### 3.3 P2P 消息流程

**密钥发布**：Alice 首次和 Bob 建立 P2P 时，生成 `Alice@Bob` 密钥对（私钥留本地，公钥附 AID 主私钥签名后上传服务端 Peer 公钥表）。Bob 同理生成 `Bob@Alice`。

**Alice 发给 Bob**：

1. 拉 Bob 发布给 Alice 的 Peer 公钥（首次 1 RPC，之后缓存）
2. **ECDH**：`Alice@Bob` 私钥 × `Bob@Alice` 公钥 → 共享秘密
3. **共享秘密永久缓存**，后续消息零 ECDH
4. HKDF：`info = "aun-p2p:{message_id}"` → 消息密钥
5. AES-GCM 加密正文
6. AID 主私钥 ECDSA 签名
7. 发送（1 RPC：`message.send`）

**Bob 接收**：
1. `Bob@Alice` 私钥 × `Alice@Bob` 公钥 → 同一共享秘密（查缓存）
2. HKDF 同 info → 同一消息密钥
3. 解密 + 验签

**热路径 1 RPC**。零一次性密钥，零协商，零握手。

### 3.4 群聊消息流程（Hybrid 加密）

**密钥发布**：成员进群时生成"群内密钥对"，公钥 + AID 主私钥签名 + 指纹上传群服务端成员表。

**Alice 发群消息**：

1. 生成本条消息的 **主对称密钥**（32 字节随机）
2. 用主密钥 AES-GCM 加密正文一次
3. 对群内每个成员 X：
   - `Alice 群内私钥 × X 群内公钥` → 共享秘密（首次计算，缓存复用）
   - HKDF：`info = "aun-group:{group_id}:msg:{message_id}:{X_aid}"` → 小钥匙
   - 小钥匙 AES-GCM 加密主密钥 → wrapped_key
4. 组装清单：每项 `{aid, peer_group_pk_fingerprint (64bit), nonce, wrapped_key}`
5. 计算 `recipients_digest` = 规范化清单的 SHA-256
6. AID 主私钥签名 = ECDSA(`ciphertext || tag || aad_bytes || recipients_digest`)
7. 发送 `group.send`（1 RPC）

**X 接收**：
1. 在清单找自己 AID 的项
2. `X 群内私钥 × Alice 群内公钥` → 同一共享秘密（查缓存）
3. HKDF 同 info → 同一小钥匙
4. 解 wrapped_key 得主密钥
5. 用主密钥解正文
6. 验发送方签名

**热路径 1 RPC**。

### 3.5 服务端按需投递

服务端收到完整 envelope 后，先验 `recipients_digest` 入签名域，为每个成员定制投递包：

```
公共部分：ciphertext + tag + aad + recipients_digest + signature  (~500 B)
成员私有部分：该成员的一项小包                                    (~150 B)
```

**每成员下行 ~650 字节**，不是全广播 32 KB。

### 3.6 冲突处理与二次补发

请求带 `members_version`（本地已知版本），响应带：
- `request_members_version` / `server_members_version` / `members_delta`
- `cert_rotated`：指纹过期的成员，附新指纹
- `uncovered_members`：`joined_at ≤ aad.timestamp` 但清单漏掉的成员
- `dropped_ghosts` / `delivered_count`

**补发**：同 `message_id` 的另一次 `group.send`，清单 = `cert_rotated ∪ uncovered_members`，重算 digest 重签名，其他不变。**硬上限 1 次**（数学上必然收敛）。

服务端 `aad.timestamp` ±5 分钟窗口校验。

### 3.7 规模上限

- **硬上限 200 人**
- 超过即拒绝加密，协议层降级为明文

---

## 4. 核心流程对比

### 4.1 P2P 发送一条消息

| 步骤 | 旧方案 | 新方案 |
|---|---|---|
| 获取对方密钥材料 | 拉 prekey（RPC）+ 拉证书（HTTP+PKI） | 拉 Peer 公钥（RPC） |
| 密钥协商 | 生成 ephemeral + 四路 ECDH + HKDF | 查共享秘密缓存 + HKDF |
| 加密 | AES-GCM | AES-GCM |
| 签名 | ECDSA + prekey 签名验证 | ECDSA |
| 发送 | `message.send` | `message.send` |
| **首次 RPC 数** | **3** + PKI | 1（若 Peer 公钥已缓存）/ 2（未缓存） |
| **热路径 RPC 数** | **1** | **1** |

### 4.2 群聊发送一条消息

| 步骤 | 旧方案 | 新方案 |
|---|---|---|
| 预检 epoch | get_epoch ×3 + get_members | — |
| 密钥准备 | HKDF(group_secret, msg_id) | 对每成员：ECDH（缓存）+ HKDF |
| 加密 | 正文一次 AES-GCM | 正文一次 AES-GCM + 每成员一次 wrap_key |
| 签名 | ECDSA + 客户端签名 | ECDSA（覆盖 digest） |
| 发送 | `group.send` | `group.send`（带 members_version） |
| **热路径 RPC 数** | **5** | **1** |

### 4.3 成员变更

| 场景 | 旧方案 | 新方案 |
|---|---|---|
| 踢人 | epoch+1 → admin 必须在线 → 对每剩余成员 P2P 发 group_key_distribution → 离线成员永远收不到新密钥 | 下一条消息清单里不放他即可；数学上天然排除 |
| 加人 | 同上 + 新成员通过 P2P E2EE 收到新 epoch 密钥 | 新成员公钥上传群成员表，下一条消息自动包含 |
| 证书轮换 | 加密消息解密失败懒加载拉新证书 | 服务端指纹不匹配 → cert_rotated 响应 → 自动补发 |
| 成员长期离线后上线 | **常态失败**：无在线成员响应 key_request | **不受影响**：历史消息自含所有密钥材料，上线后逐条独立解密 |

---

## 5. 新旧方案优劣对比

### 5.1 性能与可用性

| 指标 | 旧方案 | 新方案 | 变化 |
|---|---:|---:|:---:|
| P2P 热路径 RPC | 1 | 1 | ─ |
| P2P 冷启动 RPC | 3 + PKI | 1~2 | ⬇️ |
| 群聊热路径 RPC | 5 | 1 | ⬇️ 80% |
| epoch 不对齐恢复 | 6~N RPC + 5s 阻塞 | 不存在 | 消除 |
| 依赖对端在线 | 是（key_request） | **否** | 消除 |
| 移动端离线后上线 | 常态失败 | 正常工作 | 质变 |
| 单条消息体积（200 人） | ~1 KB | ~32 KB | ⬆️ 32× |
| 总带宽/条（含分发摊销） | ~201 KB | ~162 KB | ⬇️ 20% |
| 发送方 CPU（200 人） | ~1 ms | ~5 ms（首次）/ <1 ms（缓存） | ≈ |
| 接收方 CPU | ~1 ms | ~0.2 ms | ⬇️ |

### 5.2 安全性

| 属性 | 旧方案 | 新方案 |
|---|---|---|
| 消息级前向安全（PFS） | ✅ P2P 有 / 群聊 epoch 级 | ❌ 放弃（见 §2 论证本地明文使 PFS 鸡肋） |
| 防中间人 | ✅ | ✅ |
| 防服务端篡改消息正文 | ✅（AEAD） | ✅（AEAD） |
| 防服务端篡改清单 | ✅（Group Manifest 签名） | ✅（digest 入签名域） |
| 防重放 | ✅ | ✅ |
| 身份密钥泄露影响范围 | 所有历史消息 | 仅对应 Peer / 群；AID 主密钥泄露仍全域影响 |
| 发送方身份认证 | ECDSA + 证书链 | ECDSA + 证书链 |

### 5.3 协议复杂度

| 维度 | 旧方案 | 新方案 |
|---|---|---|
| 状态机 | epoch + manifest + mailbox + pending_rotation + key_request | 无，每条消息自包含 |
| 服务端持有的密钥材料 | group_secret 相关 commitment / CAS 状态 | 仅指纹（明文） |
| 客户端状态 | 每群维护 `{epoch, secret, old_epochs, commitment, members}` | 每群维护 `{members + 公钥指纹}` + 共享秘密缓存 |
| 协议 RPC 数量 | get_epoch / rotate_epoch / put_prekey / get_prekey / record_replay_guard / key_request 等 | send + get_members + get_peer_pk + put_peer_pk |
| 边界场景 | 密钥分发失败 / 恢复超时 / 多 admin 并发轮换 CAS 冲突 | 补发 1 次收敛 / 冲突拒绝退出 |

### 5.4 工程落地

| 维度 | 旧方案 | 新方案 |
|---|---|---|
| 实现复杂度 | 高（多阶段状态机、分层 RPC、异步恢复路径） | 低（无状态路径为主） |
| 调试成本 | epoch 不一致需要查 changelog / pending rotation / recovery inflight | 消息自包含，问题容易定位 |
| 单元测试可行性 | 需要模拟多客户端 + 服务端 CAS | 单消息端到端可单测 |
| 跨语言实现 | 复杂（多状态需要各语言同步） | 简单 |
| 迁移成本 | — | 不共存，产品位发布，无屎山包袱 |

### 5.5 关键权衡总结

**新方案的取舍**：

✅ **换来**：
- 彻底解决移动端离线场景的可用性问题
- 协议复杂度大幅下降
- 不依赖任何在线成员
- RPC 次数从 5 降到 1
- 密钥作用域隔离（Peer/群内密钥独立）

❌ **代价**：
- 放弃消息级 PFS（但 §2 论证在本地明文保存场景下无实际意义）
- 单条群消息体积膨胀 32 倍（32 KB vs 1 KB），但**总带宽反而下降**（因为不再需要 epoch 轮换的密钥分发流量）
- 群规模硬上限 200 人（超过降级为明文，适配 Agent 群的实际规模）

### 5.6 场景匹配度

| 场景 | 旧方案 | 新方案 |
|---|:---:|:---:|
| 桌面端常驻 IM | ✅ 适合 | ✅ 适合 |
| 移动端常驻 IM | ⚠️ 后台断连失败 | ✅ 适合 |
| Agent 异步通信 | ❌ 自主模式和 epoch 强一致冲突 | ✅ 完美匹配 |
| 大群广播（>1000 人） | ⚠️ 可扩展但 PFS 工程代价高 | ❌ 超过 200 降级明文 |
| 高敏感对抗场景（国家级对手） | ✅ PFS 有防御价值 | ⚠️ 需评估是否满足威胁模型 |

AUN 目标场景是 **Agent 为主的异步社交通信**，新方案在这个目标下全面占优。

---

## 6. 消息结构与体积精算

### 6.1 旧方案群聊消息结构

旧方案群消息体积**与群人数无关**——所有成员共享 group_secret，消息里不含 per-member 数据。

```json
{
  "type": "e2ee.group_encrypted",
  "version": "1",
  "encryption_mode": "epoch_group_key",
  "suite": "P256_HKDF_SHA256_AES_256_GCM",
  "epoch": 3,
  "nonce": "base64(12B)",
  "ciphertext": "base64(正文密文)",
  "tag": "base64(16B)",
  "sender_signature": "base64(ECDSA-SHA256 ~72B DER)",
  "sender_cert_fingerprint": "sha256:64hex",
  "aad": {
    "group_id": "g-abc123.agentid.pub",
    "from": "alice.agentid.pub",
    "message_id": "gm-550e8400-...",
    "timestamp": 1710504000000,
    "epoch": 3,
    "encryption_mode": "epoch_group_key",
    "suite": "P256_HKDF_SHA256_AES_256_GCM"
  }
}
```

**字段体积明细**（JSON 编码后，含字段名、引号、逗号）：

| 字段 | 原始字节 | JSON 编码后 |
|---|---:|---:|
| type + version + encryption_mode + suite | — | ~130 B |
| epoch | — | ~12 B |
| nonce（12B raw） | 12 | ~25 B |
| ciphertext（正文 100B → 密文 ~100B） | ~100 | ~160 B |
| tag（16B raw） | 16 | ~30 B |
| sender_signature（~72B DER） | ~72 | ~120 B |
| sender_cert_fingerprint | — | ~80 B |
| aad 对象 | — | ~300 B |
| JSON 结构字符 | — | ~20 B |
| **合计（正文 100 字节时）** | — | **~877 B ≈ 1 KB** |

**注意**：这 1 KB 是"日常发送"的体积。但旧方案的 **epoch 轮换分发**（每次成员变更时）需要对每个成员单独发一条 P2P E2EE 消息（~700 B/人），200 人群一次轮换 = ~140 KB 额外流量。

---

### 6.2 新方案群聊消息结构

新方案群消息体积**与群人数线性相关**——每成员一个小包。

```json
{
  "type": "e2ee.group_encrypted",
  "version": "1",
  "suite": "P256_HKDF_SHA256_AES_256_GCM",
  "nonce": "base64(12B)",
  "ciphertext": "base64(正文密文)",
  "tag": "base64(16B)",
  "sender_signature": "base64(ECDSA-SHA256 ~72B DER)",
  "sender_cert_fingerprint": "sha256:16hex",
  "recipients_digest": "64hex(SHA-256)",
  "members_version": 42,
  "aad": {
    "group_id": "g-abc123.agentid.pub",
    "from": "alice.agentid.pub",
    "message_id": "gm-550e8400-...",
    "timestamp": 1710504000000,
    "suite": "P256_HKDF_SHA256_AES_256_GCM"
  },
  "recipients": [
    {
      "aid": "bob.agentid.pub",
      "fp": "sha256:a3b2c1d4e5f60718",
      "nonce": "base64(12B)",
      "wrapped_key": "base64(48B)"
    },
    {
      "aid": "carol.agentid.pub",
      "fp": "sha256:b4c3d2e1f6071829",
      "nonce": "base64(12B)",
      "wrapped_key": "base64(48B)"
    }
  ]
}
```

**固定部分字段体积**（与群人数无关）：

| 字段 | 原始字节 | JSON 编码后 |
|---|---:|---:|
| type + version + suite | — | ~100 B |
| nonce（12B raw） | 12 | ~25 B |
| ciphertext（正文 100B → 密文 ~100B） | ~100 | ~160 B |
| tag（16B raw） | 16 | ~30 B |
| sender_signature（~72B DER） | ~72 | ~120 B |
| sender_cert_fingerprint（64 位截断） | — | ~45 B |
| recipients_digest（SHA-256 hex） | 32 | ~80 B |
| members_version | — | ~20 B |
| aad 对象 | — | ~250 B |
| JSON 结构字符 | — | ~20 B |
| **固定部分合计** | — | **~850 B** |

**每成员小包字段体积**：

| 字段 | 原始字节 | JSON 编码后 |
|---|---:|---:|
| aid（典型 ~20 字符） | ~20 | ~30 B |
| fp（64 位截断：`sha256:` + 16 hex） | 8 | ~35 B |
| nonce（12B raw） | 12 | ~25 B |
| wrapped_key（32B 主密钥 + 16B GCM tag = 48B raw） | 48 | ~75 B |
| JSON 结构字符（`{},`） | — | ~5 B |
| **单项合计** | — | **~170 B** |

---

### 6.3 新方案 P2P 消息结构

P2P 消息 = 群聊消息的 N=1 退化版，无 `recipients` 数组（直接内联）：

```json
{
  "type": "e2ee.encrypted",
  "version": "1",
  "suite": "P256_HKDF_SHA256_AES_256_GCM",
  "nonce": "base64(12B)",
  "ciphertext": "base64(正文密文)",
  "tag": "base64(16B)",
  "sender_signature": "base64(ECDSA-SHA256)",
  "sender_cert_fingerprint": "sha256:16hex",
  "peer_pk_fingerprint": "sha256:16hex",
  "aad": {
    "from": "alice.agentid.pub",
    "to": "bob.agentid.pub",
    "message_id": "uuid",
    "timestamp": 1710504000000,
    "suite": "P256_HKDF_SHA256_AES_256_GCM"
  }
}
```

P2P 消息**不含 wrapped_key**——因为只有一个收件人，消息密钥直接由 ECDH 共享秘密 + HKDF 派生，不需要"主密钥 + 小包"两层结构。

**P2P 消息体积**（正文 100 字节）：~700 B

---

### 6.4 交互时序

#### P2P 发送（新方案）

```
Alice                          服务端                          Bob
──────────────────────────────────────────────────────────────────
[首次] get_peer_pk(Bob)  ──→
                         ←──  Bob@Alice 公钥 + 指纹
                              (缓存，后续不再拉)

[每条消息]
  共享秘密 = 缓存查表
  msg_key = HKDF(共享秘密, message_id)
  密文 = AES-GCM(msg_key, 正文)
  签名 = ECDSA(AID 主私钥, 密文||tag||aad)

  message.send(envelope) ──→
                              存入 Bob 消息队列
                         ←──  {message_id, status: ok}

                              ──→  推送/Bob 上线 pull
                                   Bob 解密：
                                     共享秘密 = 缓存查表
                                     msg_key = HKDF(共享秘密, message_id)
                                     明文 = AES-GCM-Decrypt
                                     验签
```

#### 群聊发送（新方案）

```
Alice                          群服务端                        Bob/Carol/...
──────────────────────────────────────────────────────────────────────────
[进群时]
  生成群内密钥对
  put_group_pk(group_id, pk, sig) ──→
                                      存入成员表

[首次发消息前]
  get_members(group_id)  ──→
                         ←──  成员列表 + 各成员群内公钥 + 指纹
                              (缓存，后续靠 members_changed 事件增量更新)

[每条消息]
  主密钥 = random(32B)
  密文 = AES-GCM(主密钥, 正文)
  for 每成员 X:
    共享秘密 = 缓存查表（首次 ECDH 后永久缓存）
    小钥匙 = HKDF(共享秘密, group_id:message_id:X_aid)
    wrapped_key = AES-GCM(小钥匙, 主密钥)
  digest = SHA-256(规范化清单)
  签名 = ECDSA(AID 主私钥, 密文||tag||aad||digest)

  group.send(envelope, members_version) ──→
                                            校验 timestamp ±5min
                                            比对清单 vs 成员表
                                            按需投递（每人只发公共部分 + 自己的小包）
                         ←──  {message_id, server_members_version,
                               members_delta, cert_rotated,
                               uncovered_members, delivered_count}

  [若 cert_rotated / uncovered_members 非空]
    拉新证书 / 新成员公钥
    重算清单 + digest + 签名
    group.send(补发) ──→
                         ←──  响应（应为空）

                                            ──→  推送/成员上线 pull
                                                 X 解密：
                                                   找自己的小包
                                                   共享秘密 = 缓存查表
                                                   小钥匙 = HKDF(...)
                                                   主密钥 = AES-GCM-Decrypt(wrapped_key)
                                                   明文 = AES-GCM-Decrypt(密文)
                                                   验签
```

#### 旧方案群聊发送（对比）

```
Alice                          群服务端                        Bob
──────────────────────────────────────────────────────────────────────
[epoch 轮换时 — 每次成员变更]
  group.e2ee.rotate_epoch ──→
                          ←──  CAS 成功
  for 每成员 X:
    P2P E2EE message.send(group_key_distribution) ──→ X
    (每人一条完整 P2P 加密消息，含 prekey 协商)

[每条消息]
  group.e2ee.get_epoch ──→         ← RPC 1
                       ←──
  group.e2ee.get_epoch ──→         ← RPC 2
  group.get_members    ──→         ← RPC 3
                       ←──
  group.e2ee.get_epoch ──→         ← RPC 4（committed epoch）
                       ←──
  msg_key = HKDF(group_secret, message_id)
  密文 = AES-GCM(msg_key, 正文)
  签名 = ECDSA + client_signature

  group.send(envelope) ──→         ← RPC 5
                       ←──

[Bob 离线期间发生 epoch 轮换后上线]
  收到新 epoch 消息 → 解密失败
  group.e2ee.get_epoch ──→
  message.send(key_request) ──→ 候选成员
  ... 轮询 150ms × 33 次 ...
  [若无人响应] → StateError，消息永久丢失
```

---

### 6.5 单条消息体积精算对比

**假设正文 100 字节（约 50 个汉字）**

#### 旧方案

| 组成 | 体积 | 说明 |
|---|---:|---|
| 固定 envelope | ~877 B | 与群人数无关 |
| per-member 数据 | 0 | group_secret 预分发，消息不含 |
| **总计** | **~1 KB** | 不随群人数变化 |

#### 新方案

| 组成 | 体积 | 说明 |
|---|---:|---|
| 固定 envelope | ~850 B | 与群人数无关 |
| per-member 小包 | N × 170 B | 每成员一项 |
| recipients 数组 JSON 开销 | ~30 B | `"recipients":[...]` |
| **总计** | **850 + 30 + N×170** | 线性增长 |

#### 按群规模对比

| 群规模 | 旧方案 | 新方案 | 新/旧 倍数 |
|---:|---:|---:|---:|
| P2P（1 人） | ~700 B | ~700 B | 1× |
| 10 人 | ~1 KB | **~2.6 KB** | 2.6× |
| 50 人 | ~1 KB | **~9.4 KB** | 9.4× |
| 100 人 | ~1 KB | **~18 KB** | 18× |
| 200 人 | ~1 KB | **~35 KB** | 35× |

#### 但考虑 epoch 轮换的摊销成本

旧方案每次成员变更需要 epoch 轮换分发（对每成员发一条 P2P E2EE 消息 ~700 B）：

| 群规模 | 旧方案轮换一次的额外流量 | 新方案额外流量 |
|---:|---:|---:|
| 100 人 | ~70 KB | 0 |
| 200 人 | ~140 KB | 0 |

#### 群服务器总流量对比（关键）

群服务器视角的真实流量 = **上行**（发送方→服务器）+ **下行**（服务器→所有成员）。

新方案的下行有两种实现路径：
- **全广播**（naive 实现）：服务端把完整 envelope 发给每个成员
- **按需投递**（必需的工程实现）：服务端为每个成员定制投递包，只发公共部分（~650 B）+ 该成员自己的小包（~170 B），每人下行 ~820 B

假设场景：**每天 100 条消息 + 5 次成员变更**

##### 100 人群

| 方案 | 上行 | 下行 | **总流量** |
|---|---:|---:|---:|
| 旧方案 | 100×1 KB + 5×70 KB（轮换）= 0.45 MB | 100×100×1 KB + 轮换 = ~10 MB | **~10.5 MB** |
| 新方案 · 全广播 | 100×18 KB = 1.8 MB | 100×100×18 KB = **180 MB** | ~182 MB ❌ |
| 新方案 · 按需投递 | 1.8 MB | 100×100×820 B = 8.2 MB | **~10 MB** ✅ |

##### 200 人群

| 方案 | 上行 | 下行 | **总流量** |
|---|---:|---:|---:|
| 旧方案 | 100×1 KB + 5×140 KB = 0.8 MB | 100×200×1 KB + 轮换 = ~21 MB | **~21.5 MB** |
| 新方案 · 全广播 | 100×35 KB = 3.5 MB | 100×200×35 KB = **700 MB** | ~704 MB ❌ |
| 新方案 · 按需投递 | 3.5 MB | 100×200×820 B = 16.4 MB | **~20 MB** ✅ |

#### 关键结论

1. **按需投递不是锦上添花，是新方案落地的工程前提**——不做这层优化，200 人群下行直接爆 700 MB/天
2. 做了按需投递后，**新方案总流量与旧方案基本持平**（200 人群：新 20 MB vs 旧 21.5 MB），甚至略低
3. 旧方案的"消息小"优势被 epoch 轮换的额外流量大幅抵消，且其轮换流量依赖在线成员接收——移动端常态失败
4. 新方案的真正代价是 **发送方上行**（200 人群 3.5 MB/天 vs 旧方案 0.8 MB/天，约 4 倍），移动端弱网上行链路是关注点

---

### 6.6 服务端按需投递后的实际下行带宽

新方案服务端不需要把完整 35 KB 广播给每个人——按需投递后每人只收到：

| 组成 | 体积 |
|---|---:|
| 公共部分（ciphertext + tag + aad + digest + signature） | ~650 B |
| 自己的小包 | ~170 B |
| **每人下行** | **~820 B** |

| 群规模 | 上行（发送方→服务端） | 下行总量（服务端→全体） | 每人下行 |
|---:|---:|---:|---:|
| 100 人 | 18 KB | ~82 KB | ~820 B |
| 200 人 | 35 KB | ~164 KB | ~820 B |

对比旧方案（日常消息）：

| 群规模 | 旧方案上行 | 旧方案下行总量 | 旧方案每人下行 |
|---:|---:|---:|---:|
| 100 人 | ~1 KB | ~100 KB | ~1 KB |
| 200 人 | ~1 KB | ~200 KB | ~1 KB |

**下行总量两方案接近**（新方案 164 KB vs 旧方案 200 KB）。差异主要在**上行**：新方案发送方要上传 35 KB，旧方案只上传 1 KB。移动端弱网上行是瓶颈时需注意。

---

### 6.7 签名机制与投递方式的关系

一个常见疑问：**全广播和按需投递下，发送方的签名是否需要为每个接收方分别签一次？**

**答：不需要。发送方只签一次，所有接收方用同一份签名验证。**

#### 签名域回顾

```
sender_signature = ECDSA(AID 主私钥, ciphertext || tag || aad_bytes || recipients_digest)
```

签名覆盖的四项内容（密文、tag、AAD、清单摘要）**对所有接收方完全一致**，无论投递方式如何。

#### 两种投递下接收方看到的差异

| 接收方拿到的内容 | 全广播 | 按需投递 |
|---|---|---|
| 公共部分（含 digest、签名） | ✅ 完整 | ✅ 完整 |
| 完整清单（所有成员小包） | ✅ 全部 | ❌ 仅自己一项 |
| 验签 | ✅ 可独立完成 | ✅ 可独立完成 |
| 重算 digest 比对 | ✅ 可独立完成 | ❌ 无完整清单 |
| 自己那项是否被签名覆盖 | ✅ 可验证 | ❌ 不可验证 |

#### 攻击检测能力对比

| 攻击 | 全广播下 | 按需投递下 |
|---|:---:|:---:|
| 服务端伪造接收方（添项） | ✅ 破签 | ✅ 破签 |
| 服务端篡改正文密文 | ✅ AEAD tag 失败 | ✅ AEAD tag 失败 |
| 服务端替换某成员的 wrapped_key | ✅ 破签（digest 变） | ⚠️ 该成员 ECDH 配不上 → 解密失败（被动检测） |
| 服务端丢弃某成员的整项 | ✅ 破签（digest 变） | ❌ 接收方不知道（DoS） |
| 替换接收方 A 的小包为 B 的 | ✅ 全员可比对 | ⚠️ A 解密失败（被动检测） |

**保密性在两种投递下都不受损**——服务端没有群内私钥，无法生成"既能让接收方成功 ECDH 又匹配 digest"的伪造小包。

**按需投递下接收方失去的是"清单一致性证据"**——无法独立证明"我这项确实在原始签名清单里"。但所有失去的能力，要么是 **DoS（无法防御）**，要么转化为 **被动检测（解密失败）**。

#### 为什么不为每个接收方单独签

如果给每个接收方单独签名（比如签 `ciphertext || tag || aad || my_aid || my_wrapped_key`）：

- ❌ 发送方 N 次 ECDSA 签名（200 人群移动端 ~100 ms CPU）
- ❌ 每接收方多 ~120 字节签名 → 200 人群多 24 KB
- ❌ 失去群体一致性证据（每人收到的签名内容都不同，无法横向比对）
- ❌ 增加协议复杂度（接收方需要知道签名域里包含什么）

**收益为零**——签名 N 次防御不了的攻击，签 1 次也防御不了；签 1 次能防御的攻击，签 N 次没有更强。

#### 进阶：Merkle Tree（未采用）

如果将来需要在按需投递下恢复"自己那项被签名覆盖"的可验证性，可用 Merkle Tree 替代单一 digest：

```
recipients_merkle_root = MerkleRoot(按 AID 排序的每项小包哈希)
```

每接收方多带 `log₂(N)` 个哈希（200 人 ~8 个 = 256 字节），可独立验证自己那项在树中。

**当前方案不采用**，因为：
1. 增加实现复杂度（规范化树结构、路径顺序、空节点）
2. 跨语言一致性成本高
3. 当前 DoS 类攻击的检测价值有限——服务端能做的恶意行为已被保密性 + AEAD + 主签名的组合大部分挡住
4. 收益与代价不匹配

只有未来出现"服务端故意对特定成员隐瞒消息"这类**针对性 DoS 攻击**进入威胁模型时，再启用 Merkle Tree 即可——digest 字段格式可向前兼容扩展。

#### 结论

| 维度 | 设计选择 |
|---|---|
| 签名次数 | 每条消息 **1 次**，与群人数无关 |
| 签名内容 | `ciphertext + tag + aad + recipients_digest`，对所有接收方相同 |
| 投递方式 | 服务端按需投递（推荐），影响接收方"清单可见性"，不影响"消息真实性验证" |
| 验签操作 | 接收方均可独立完成，无需协调其他成员 |

---

## 7. 结论

**新方案建议替换旧方案**，理由：

1. 直接命中旧方案在移动端 + Agent 异步场景下的致命可用性问题
2. 协议复杂度大幅下降，长期维护和跨语言实现成本低
3. 放弃的 PFS 在 AUN 实际威胁模型下价值有限（§2 详细论证）
4. 总带宽、CPU、可用性多项指标综合占优
5. 产品位发布窗口内可直接切换，无需兼容旧协议

待落地的剩余工作：
- 议题 #2 `bulk_get_certs` RPC 参数与分页
- 议题 #3 证书/群内公钥缓存 TTL
- 议题 #5 防重放 seen 窗口
- §6 列的 7 条审查遗留问题

---

## 8. 变更记录

| 版本 | 日期 | 变更 |
|---|---|---|
| 1.3 | 2026-05-13 | 新增 §6.7 签名机制与投递方式的关系：明确签名一次即可覆盖所有接收方、两种投递下攻击检测能力对比、为何不采用 Merkle Tree |
| 1.2 | 2026-05-13 | §6.5 重写：修正日均流量对比，区分"全广播 vs 按需投递"，明确按需投递是方案落地前提而非可选优化 |
| 1.1 | 2026-05-13 | 新增 §6 消息结构与体积精算（字段级体积分解、交互时序图、100/200 人群对比、按需投递下行带宽） |
| 1.0 | 2026-05-13 | 初版，整合至 `草案-E2EE-公钥直接加密方案.md` v0.8-draft 的讨论结论 |


