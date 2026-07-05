# AUN-E2EE 群组扩展规范

> 版本：2.0-draft
> 状态：规范性文档
> 适用范围：AUN 客户端 SDK、客户端应用、跨语言实现
> 不适用范围：Group Service 服务端加解密实现
> 前置依赖：当前 P2P V2 链路见 [E2EE_V2消息通信时序图](../sdk/E2EE_V2消息通信时序图.md) 和 [05-E2EE加密通信](../sdk/05-E2EE加密通信.md)；旧 P2P 信封见 [08-AUN-E2EE](./08-AUN-E2EE.md)；群组基础语义见 [10-Group-子协议](./10-Group-子协议.md)。
> 定位：**群组消息端到端加密层**，基于 per-message 密钥 + per-recipient 包裹机制

---

## 1. 目标与边界

本规范定义 AUN 群组成员之间的端到端消息加密协议（V2，当前唯一在用版本）。

### 1.1 目标

- 让群组内的 N 个成员在现有 `group.send` / `group.v2.send` / `event/group.message_created` 之上实现端到端加密
- 让 Group Service 仅看到最小必要路由元数据和密文 payload
- 每条消息使用独立密钥，接收方按设备分别持有密钥包裹（wrap），不依赖群级共享对称密钥
- 为各语言 SDK 提供统一的群组密文格式、成员状态签名机制和恢复语义

### 1.2 服务端职责

Group Service **只做**：

- 认证发送方（JWT token / AID 证书）
- 校验群成员权限
- 存储共享密文体（`v2_group_messages`）和逐设备密钥包裹（`v2_group_wraps`）
- 校验消息结构完整性（recipients 排序、digest、必要审计包裹等）
- 维护群成员状态的签名版本链（`state_version`/`state_chain`），提供分叉检测的比对基准
- 广播加密消息通知，按设备分发对应的密钥包裹

Group Service **绝不做**：

- 加解密群消息
- 持有或管理消息密钥、成员密钥明文
- 参与密钥协商或密钥派生

### 1.3 设计原则

| 原则 | 说明 |
|------|------|
| **消息级密钥** | 每条消息使用独立随机密钥，发送方一次性会话密钥用完即弃，不维护群级长期对称密钥 |
| **复用 V2 设备密钥体系** | 接收方设备密钥包裹基于当前 E2EE V2 的 IK/SPK 机制；群内优先使用 `group_device_prekey`，缺少群内设备 Prekey 时可回退到该设备已注册的 P2P Prekey |
| **不信任服务端** | 消息密钥从未经过服务端明文；接收方按设备分别持有的密钥包裹只有对应设备的私钥能解开 |
| **成员状态可验证** | 群成员集合与权限的变更通过签名的状态版本链（state_version/state_chain）記录，接收方可据此检测状态分叉或篡改 |

---

## 2. 与 AUN-Core 的关系

AUN-E2EE-Group 建立在以下核心能力之上：

- **P2P E2EE V2**：设备 Prekey（IK/SPK）注册与管理机制、recipient wrap、AAD 序列化规则（Canonical JSON）均与 SDK V2 多设备 wrap 保持一致
- **Group 子协议**（[10-Group-子协议](./10-Group-子协议.md)）：群组管理、成员管理、消息传输
- **AID + 证书链身份体系**：成员身份验证

群组密文消息通过 `group.v2.send` 提交，`group.send` 承载明文/兼容路径；Group Service 无需识别密文 payload 内部字段。

---

## 3. 术语

### 3.1 Epoch

群密钥版本号（uint32，从 1 开始）。用于在消息 AAD 中标记消息所属的密钥轮换周期，服务端据此拒绝使用过期版本发送的消息，与下方 State Version 是两条独立轨道。

### 3.2 State Version / State Chain

群成员状态（成员列表、管理员集合、审计接收者等）的签名版本号（uint32，从 0 开始，未签名任何状态时为 0）。每次 owner/admin 提交并确认一次成员状态变更，版本递增。`state_chain` 是历次已确认状态的链式记录，客户端可据此检测服务端是否篡改历史或出现并发分叉。

### 3.3 State Commitment

对当前群成员集合、管理员集合、审计接收者等状态字段的摘要值，绑定到 `epoch`，写入每条加密消息的 AAD 中，使消息与发送时刻的群状态可验证关联。

### 3.4 Recipients Digest

一条群消息的所有设备密钥包裹（recipient 行）经排序后计算得到的摘要根值，纳入发送方签名覆盖范围，用于防止服务端在按设备拆分投递时篡改或替换某个接收方的密钥包裹。

### 3.5 密文群消息

通过 `group.v2.send` 传输的加密群消息，`payload.type` **MUST** 为 `e2ee.group_encrypted`。

---

## 4. 密钥体系概述

### 4.1 密钥层次

| 密钥 | 生成方 | 生命周期 | 说明 |
|------|--------|---------|------|
| 消息密钥（对称） | 发送方，每条消息独立生成 | 单条消息 | 用于加密消息正文，从不直接传输，按接收方设备分别用密钥包裹机制加密后随消息一起发送 |
| 发送方一次性会话密钥 | 发送方，每条消息独立生成 | 单条消息 | 用于与接收方设备的长期身份/Prekey 做密钥协商，加密后即可丢弃 |
| 接收方设备身份密钥（IK） | 接收方，AID 级别 | 长期 | 与 AID 身份证书绑定 |
| 接收方设备 Prekey（SPK） | 接收方，设备级别 | 定期轮换 | 群内设备 Prekey（`group_device_prekey`）通过 `group.v2.put_group_pk` 注册；缺失时回退到该设备已注册的 P2P Prekey，此时安全强度降级为仅身份密钥参与协商 |

具体的密钥协商组合方式（是否使用 SPK、密钥派生的哈希函数与输入构成）与当前 P2P V2 recipient wrap 机制一致，本规范不重复列出精确公式，实现请参照 SDK V2 时序文档及各语言 SDK 的密码学模块源码。

### 4.2 每条消息的密钥包裹

一条加密群消息只加密一次消息正文，但会为每个当前应接收该消息的设备分别生成一份密钥包裹（recipient wrap），使得只有对应设备的私钥能解出消息密钥。密钥包裹按角色分类：

- `member`：普通群成员设备
- `self_sync`：发送方自己在其他设备上的同步副本
- `audit`：群配置的审计接收者（如有），用于合规场景下的旁路可见性，不改变成员关系

---

## 5. 消息生命周期

### 5.1 Bootstrap（发送前的成员/密钥快照）

发送方在加密消息前调用 `group.v2.bootstrap` 获取：

- 当前所有（committed）成员的设备身份/Prekey 公钥列表
- 当前 `epoch`
- 当前 `state_version` / `state_hash` / `state_chain`
- `committed_member_aids`：已通过状态签名确认的成员
- `pending_adds` / `pending_removes`：尚未签名确认的成员变更
- `e2ee_security_level`：`end_to_end`（正常受控群）或 `transport`（open/邀请码等任何人可自由加入的群，此时密钥包裹接收方集合不与"被授权成员"强绑定，安全强度退化为等价于传输层加密，不构成严格端到端）

对于设置了成员审批（private/approval/closed）的群，尚未完成状态签名确认的新成员（pending）不会出现在 bootstrap 返回的设备列表中，发送方因而不会为其生成密钥包裹，实现了"未确认成员收不到密文"的天然隔离。SDK 通常对 bootstrap 结果做短期缓存，成员或状态变更后需要刷新。

### 5.2 加密与发送

1. 发送方生成本条消息的消息密钥与一次性会话密钥
2. 构造 AAD（含 `group_id`、`epoch`、`message_id`、发送方身份、`state_commitment` 等，详见 §7）
3. 用消息密钥对正文做认证加密，AAD 参与认证但不加密
4. 为 bootstrap 返回的每个目标设备生成密钥包裹（消息密钥被目标设备的密钥协商结果加密）
5. 对所有密钥包裹排序后计算 Recipients Digest，随同密文一起纳入发送方签名
6. 调用 `group.v2.send` 提交完整信封（含密文、AAD、Recipients Digest、发送方签名、所有密钥包裹）

服务端收到后校验成员资格、`epoch` 是否为当前值、密钥包裹排序与 Recipients Digest 是否自洽、必要审计包裹是否齐全，通过后落库并按设备拆分推送。

### 5.3 拉取与解密

接收方通过 `group.v2.pull` 按设备拉取属于自己的消息（服务端只返回该设备自己的那一份密钥包裹，可附带 Merkle 证明用于验证该包裹确实是发送方原始签名集合的一部分而未被服务端替换）。接收方：

1. 验证发送方签名（覆盖密文、AAD、Recipients Digest）
2. 用本机私钥解出分配给自己的消息密钥
3. 用消息密钥解密正文并校验 AAD 一致性

解密失败的常见原因：使用了已轮换的旧 Prekey、bootstrap 快照过期导致密钥包裹面向错误的设备、或密文/AAD 被篡改。恢复方式通常是刷新 bootstrap 后等待下一条消息，或依赖服务端 `group.v2.pull` 的历史消息重新拉取。

### 5.4 拉取确认

接收方通过 `group.v2.ack` 提交已消费到的消息序号游标，用于服务端做 retention 与增量拉取范围计算。

---

## 6. 成员状态签名（State Version）

### 6.1 目的

群成员集合、管理员集合等状态信息如果只由服务端记录，无法防止服务端篡改或伪造。V2 引入 owner/admin 对状态变更进行签名确认的两阶段流程，使状态变更可追溯、可验证、且能检测并发冲突。

### 6.2 两阶段流程

1. **提案**（`group.v2.propose_state`）：owner/admin 提交目标 `state_version`、状态摘要（`state_hash`）、成员快照，并附上覆盖这些字段的签名。首次状态签名（`state_version = 1`）**MUST** 由 owner 发起，此后 owner/admin 均可发起。服务端记录为待确认提案，设有自动确认超时。
2. **确认**（`group.v2.confirm_state`）：发起者（或后续管理员）提交提案 ID 完成确认，服务端以比较并交换（CAS）方式原子推进 `state_version`，若确认前已有其他提案抢先生效则确认失败，需要基于最新状态重新发起。

该机制保证并发的状态变更提案中至多一个能生效，避免服务端或多个管理员产生分叉的成员视图。

### 6.3 分叉检测

客户端在 bootstrap 时获得当前 `state_chain`，与本地已知的历史链做连续性比对；若发现不连续或矛盾，视为潜在的服务端篡改或并发冲突信号，应用层应提示用户或拒绝基于该状态发送敏感消息。

### 6.4 Pending 成员语义

新加入但尚未被状态签名确认的成员（`pending_adds`）在成员审批类群组（private/approval/closed）中不会出现在 bootstrap 的设备列表里，因而无法接收此前及此后（直到状态确认）发出的加密消息；在开放加入类群组（open/邀请码）中不做此限制，此时群组的 `e2ee_security_level` 会被标记为 `transport`（见 §5.1），提示这类群组的加密强度弱于严格端到端。

---

## 7. 消息格式与 AAD

### 7.1 AAD 关键字段

| 字段 | 说明 |
|------|------|
| `group_id` | 群组唯一标识 |
| `from` / `from_device` | 发送方 AID 与设备标识 |
| `message_id` | 消息唯一标识，发送方生成，参与认证 |
| `epoch` | 消息所属的密钥版本号 |
| `state_commitment` | 绑定发送时刻的成员状态摘要（`state_version`/`state_hash`/`state_chain`） |

AAD 采用 Canonical JSON 序列化（递归键排序、UTF-8 直出、紧凑格式），规则与当前 SDK V2 recipient wrap 实现保持一致。

### 7.2 外层信封

密文 payload 通过 `group.v2.send` 的 `envelope` 参数提交；接收方通过 `group.v2.pull` 按设备取回，返回内容包含该设备自己的密钥包裹与（如适用）该包裹在原始签名集合中的完整性证明。

---

## 8. 密钥恢复与历史访问

- 接收方若因设备 Prekey 轮换、bootstrap 快照过期等原因暂时无法解密某条消息，通常的恢复路径是刷新 bootstrap 快照后重试，而非向对端请求补发密钥（V2 不存在需要跨端口头传递的群级共享密钥）。
- 新成员加入前发出的历史消息，其密钥包裹集合本就不包含新成员设备，因此新成员天然无法解密加入前的历史消息，无需额外的"历史隔离"机制。

---

## 9. 客户端密钥存储

- 发送方一次性会话密钥用后即弃，不持久化。
- 接收方的设备身份密钥（IK）与设备 Prekey（SPK）私钥由本地 V2 key store 保存，并按平台能力使用本地密钥保护；明文私钥不得落入服务端。
- 消息密钥本身不需要持久化——每条消息独立生成、独立解出、用后即弃；除非应用层自行缓存明文消息以支持离线查看。

---

## 10. 防重放与防篡改

### 10.1 防篡改

AAD 覆盖所有路由关键字段（`group_id`、`from`、`epoch`、`message_id`、`state_commitment`），任何篡改导致认证加密校验失败而拒绝解密；发送方签名进一步覆盖密文、AAD 与 Recipients Digest，防止服务端在拆分投递时替换或增删某个接收方的密钥包裹。

### 10.2 防重放

- 接收方 **MUST** 维护本地去重集合，以 `{group_id}:{from}:{message_id}` 为 key 拒绝重复消息。
- `group.v2.send` 的时间戳需在合理新鲜度窗口内，超出窗口的请求会被服务端拒绝。

### 10.3 Epoch/State 校验

- 服务端拒绝 `epoch` 与当前群密钥版本不一致的发送请求，客户端遇到此类拒绝应刷新 bootstrap 后重试。
- 接收方应校验消息 AAD 中的 `state_commitment` 与本地已知状态链一致，不一致时视为潜在分叉信号。

---

## 11. 安全约定

### 11.1 通用约定

- 加密失败时 **MUST NOT** 静默降级为明文
- 每条消息使用独立的随机密钥与随机 nonce
- 密钥材料 **MUST** 由密码学安全随机数生成器生成
- 实现 **MUST NOT** 在日志中输出消息密钥或密钥包裹解密结果

### 11.2 客户端操作签名

`client_signature` 是 Gateway / 服务端用于校验客户端业务操作来源的签名，不等同于 E2EE 信封里的 `sender_signature`。当前 Gateway 语义如下：

- `group.send` / `group.v2.send` / `group.v2.pull` / `group.v2.ack` 等常规消息 RPC 在连接级认证身份与 RPC 参数声明身份一致时，使用连接级身份 fast path，不重复执行 ECDSA 验签。
- 群管理、成员变更、状态提交、E2EE bootstrap / state proposal 等敏感操作仍可要求或验证 `client_signature`。
- 如果 RPC 参数中的 `aid` / `device_id` / `slot_id` 等身份声明与连接级身份不一致，Gateway 必须要求 `client_signature` 并完成验签；签名 AID 与连接 AID 不一致时只允许明确支持能力身份的命名空间。
- 客户端主动携带 `client_signature` 时，Gateway 会按当前缓存策略验证签名并向下游注入已验证上下文。

E2EE 安全性仍由接收端验证 `sender_signature`、AAD、recipient proof / digest 和 state commitment 保证；Gateway 不应移除 E2EE 信封中的签名字段。

### 11.3 成员移除后的安全保证

- 成员被踢出或退出后，后续消息 bootstrap 不再包含其设备，因而无法为其生成新的密钥包裹；已离开成员无法解密移除后发出的消息。
- 已离开成员此前收到的历史消息密钥包裹不受影响（历史消息本就已经解密完成或本地缓存）。

---

## 12. 安全属性分析

### 12.1 安全属性总览

| 属性 | 表现 | 说明 |
|------|:----:|------|
| **消息级前向安全** | ✅ | 每条消息使用独立密钥，发送方一次性会话密钥用后即弃 |
| **防中间人** | ✅ | 密钥协商基于已认证的设备身份密钥与 Prekey |
| **防服务端注入** | ⚠️ | State Commitment 绑定消息到特定的已签名成员状态，State Chain 提供分叉检测，但完整防护依赖应用层对状态链连续性的主动校验 |
| **防篡改** | ✅ | AAD 覆盖所有路由关键字段，发送方签名覆盖密文与 Recipients Digest |
| **防重放** | ✅ | 本地去重 + 时间戳新鲜度窗口 |
| **成员变更后的密钥隔离** | ✅ | 密钥包裹按当前 bootstrap 快照生成，新成员收不到历史消息包裹，被移除成员收不到后续消息包裹 |

### 12.2 与 V1（已禁用）的本质差异

V1 机制（Epoch Group Key：群级共享对称密钥 `group_secret` + 版本号 `epoch` + 通过 P2P 通道向每个成员分发同一把密钥）已在线上全面禁用，不再是当前协议的一部分。V2 用"每条消息独立密钥 + 逐设备密钥包裹"取代了群级共享密钥模型，因此不再需要 V1 中用于同步 `epoch` 的一次性 CAS 轮换 RPC；群成员/权限的变更改由 §6 的状态签名两阶段流程记录和验证。

---

## 13. 错误码

| 错误码 | 名称 | 说明 |
|--------|------|------|
| -32040 | `E2EE_GROUP_KEY_MISSING` | 找不到属于本设备的密钥包裹 |
| -32041 | `E2EE_GROUP_EPOCH_MISMATCH` | 消息 epoch 与服务端当前值不匹配 |
| -32042 | `E2EE_GROUP_STATE_MISMATCH` | State Commitment / State Chain 校验失败 |
| -32044 | `E2EE_GROUP_DECRYPT_FAILED` | 群消息解密失败 |

---

## 14. 变更记录

| 版本 | 日期 | 变更 |
|------|------|------|
| 2.0-draft | 2026-07 | 重写为 V2 机制（消息级密钥 + 逐设备密钥包裹 + 状态签名两阶段流程），移除已禁用的 V1 Epoch Group Key 机制描述 |
| 1.0-draft-r5 | 2026-04 | （V1，已废弃）成员加入改为 MUST 轮换 epoch；服务端以 `min_read_epoch` 约束新成员加入前历史访问 |
| 1.0-draft-r4 | 2026-04 | （V1，已废弃）新增 Epoch CAS 轮换 RPC 的 rotation_signature 要求 |
| 1.0-draft-r3 | 2026-04 | （V1，已废弃）Membership Commitment 绑定 group_secret 哈希；新增 Membership Manifest 签名机制 |
| 1.0-draft-r2 | 2026-04 | （V1，已废弃）group_e2ee 默认值改为 true；补充成员加入轮换策略 |
| 1.0-draft-r1 | 2026-04 | （V1，已废弃）修正 Membership Commitment 命名与 message_id 来源 |
| 1.0-draft | 2026-04 | （V1，已废弃）初始版本：Epoch Group Key 机制 |
