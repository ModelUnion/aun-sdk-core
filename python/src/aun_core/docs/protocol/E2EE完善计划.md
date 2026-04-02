# E2EE 完善计划

## 目标

把当前“文档中的三级降级策略”真正落地为可运行能力：

1. 模式 1：在线协商 `ephemeral_ecdh`
2. 模式 2：预存临时公钥 `prekey`
3. 模式 3：长期公钥 `long_term_key`

并保证三件事同时成立：

1. AUN 服务端真的支持 `prekey` 生命周期管理
2. `aun-core` 真正按 1 -> 2 -> 3 自动选择
3. 协议文档、SDK 文档、skill 文档都只描述已实现行为

## 总体判断

最合适的落点不是新开一个独立 E2EE 服务，而是以 [extensions/services/message/entry.py](/D:/modelunion/kite/extensions/services/message/entry.py) + [extensions/services/message/db.py](/D:/modelunion/kite/extensions/services/message/db.py) 为主承载。

原因：

1. `message` 服务已经负责收件人维度的离线消息、持久化、`seq`、`pull` 和 `encrypted` 透传。
2. `prekey` 本质上也是“按收件人管理的一次性安全元数据”，和消息离线队列天然同域。
3. gateway 只是 RPC 转发和 PKI HTTP 入口，不适合承担 prekey 状态管理。
4. CA/Auth 现有能力已经能提供证书下载与验证链，不必把 prekey 生命周期塞进 CA。

## 需要修改的模块

必须修改：

1. [extensions/services/message/entry.py](/D:/modelunion/kite/extensions/services/message/entry.py)
2. [extensions/services/message/db.py](/D:/modelunion/kite/extensions/services/message/db.py)
3. [extensions/services/message/module.md](/D:/modelunion/kite/extensions/services/message/module.md)
4. [extensions/services/message/message_config.json](/D:/modelunion/kite/extensions/services/message/message_config.json)
5. [aun-sdk-core/python/src/aun_core/e2ee.py](/D:/modelunion/kite/aun-sdk-core/python/src/aun_core/e2ee.py)
6. [aun-sdk-core/python/src/aun_core/client.py](/D:/modelunion/kite/aun-sdk-core/python/src/aun_core/client.py) 或对应命名空间暴露层
7. Python SDK 文档与示例
8. `aun-skill` 对应文档

大概率需要小改：

1. [extensions/services/gateway/ws_server.py](/D:/modelunion/kite/extensions/services/gateway/ws_server.py)
2. [tests/unit/test_message_module.py](/D:/modelunion/kite/tests/unit/test_message_module.py)
3. 新增 message 模块测试、SDK 单测、E2E 测试

通常不需要改：

1. CA 证书签发主流程
2. storage 服务
3. group 服务
4. auth 服务主认证流程

## 推荐实施顺序

不要先改 SDK。先把服务端最小闭环做出来，再接 SDK。

推荐顺序：

1. 冻结协议和报文
2. 落服务端 DB 和 RPC
3. 做服务端单测/模块测
4. 再改 `aun-core`
5. 再做 SDK 单测/E2E
6. 最后回写文档

## Phase 0：先冻结协议，不写代码

这一步必须先做，不然后面会一直返工。

### 需要冻结的协议点

1. `prekey` 模式的精确定义
2. `prekey bundle` 的字段
3. 服务端 RPC 名称和出入参
4. prekey 的消费语义
5. 错误码
6. AAD 字段
7. 重放保护规则
8. 并发行为

### 建议冻结为下面这套

#### 1. Prekey bundle

建议最小 bundle：

- `prekey_id`
- `public_key`
- `signature`
- `created_at`
- `expires_at` 可选
- `curve`
- `suite`
- `cert` 不建议重复返回，发送方已可通过 `/pki/cert/{aid}` 拉

如果要降低一次 RPC 往返，可允许 `get_prekey` 返回：

- `prekey`
- `cert_pem`
- `cert_fingerprint`

但这会让 message 服务依赖 cert 数据复制。更稳妥的是仍由 SDK 走现有 cert 拉取路径。

#### 2. RPC

建议挂在 `message` 域，不新增 `e2ee.*` 顶级域。

推荐方法名：

- `message.e2ee.upload_prekeys`
- `message.e2ee.get_prekey`
- `message.e2ee.prekey_status`

这样最符合当前模块边界。

如果为了兼容已有文档，也可以注册：

- `e2ee.upload_prekeys`
- `e2ee.get_prekey`
- `e2ee.prekey_status`

但这意味着 message 模块要在 registry 中额外挂一个新域，维护成本更高。建议统一收敛到 `message.e2ee.*`。

#### 3. 消费语义

`get_prekey(aid)` 必须是“取一个并原子标记已分配/已消费”的语义，不能只是读。

推荐状态机：

- `available`
- `reserved`
- `consumed`
- `expired`

如果系统简单，可以直接：

- `available`
- `used`

但要确保并发取 key 时不重复发放。

#### 4. 重放保护

模式 2 不再靠 `counter`，而靠：

- `message_id` 去重
- `prekey_id` 一次性使用
- 可选时间窗校验

#### 5. AAD

模式 2 最好固定为：

- `from`
- `to`
- `message_id`
- `timestamp`
- `encryption_mode`
- `suite`
- `prekey_id`

模式 3：

- `from`
- `to`
- `message_id`
- `timestamp`
- `encryption_mode`
- `suite`
- `ephemeral_public_key`
- `recipient_cert_fingerprint`

这点必须先定，因为现在代码和文档已经不一致。

#### 6. 模式 2 / 模式 3 的防重放与防篡改

模式 2 和模式 3 不能只做到“能解密”，还必须补齐消息级状态和字段认证绑定。

模式 2 需要：

- `message_id` 去重
- `prekey_id` 一次性消费
- `timestamp` 时间窗校验
- 外层 `prekey_id`、`encryption_mode`、`suite` 与 AAD 强一致

模式 3 需要：

- `message_id` 去重
- `timestamp` 时间窗校验
- `ephemeral_public_key` 纳入 AAD 并参与去重状态
- `recipient_cert_fingerprint` 纳入 AAD，用于绑定接收方长期身份

接收端至少要持久化：

- 已处理的 `message_id`
- 已消费的 `prekey_id`（模式 2）
- 可选：`from + ephemeral_public_key + message_id` 组合哈希（模式 3）

发送端和接收端都必须做：

- 外层 envelope 与 AAD 的逐字段一致性校验
- 模式 2 的 prekey 签名校验
- 模式 3 的接收方证书/公钥指纹绑定校验

如果这部分不先冻结，后面的 DB、RPC、SDK 和测试都会继续分叉。

## Phase 1：服务端最小闭环

目标：先让系统具备真实 `prekey` 存储与发放能力，但不碰现有消息主路径。

### 1. 数据库改造

主文件：[extensions/services/message/db.py](/D:/modelunion/kite/extensions/services/message/db.py)

当前已有表：

- `messages`
- `inbox_seq`

建议新增表：

### `e2ee_prekeys`

字段建议：

- `id` BIGINT AUTO_INCREMENT
- `aid` VARCHAR(255) NOT NULL
- `prekey_id` VARCHAR(64) NOT NULL
- `public_key` TEXT NOT NULL
- `signature` TEXT NOT NULL
- `curve` VARCHAR(32) NOT NULL DEFAULT 'P-256'
- `suite` VARCHAR(64) NOT NULL
- `status` VARCHAR(16) NOT NULL DEFAULT 'available'
- `created_at_ms` BIGINT NOT NULL
- `expires_at_ms` BIGINT NULL
- `reserved_at_ms` BIGINT NULL
- `used_at_ms` BIGINT NULL
- `reserved_by_message_id` VARCHAR(64) NULL

索引建议：

- UNIQUE (`prekey_id`)
- INDEX (`aid`, `status`, `created_at_ms`)
- INDEX (`aid`, `expires_at_ms`)

### 可选表：`e2ee_prekey_audit`

如果要可追踪性，可额外加：

- `prekey_id`
- `aid`
- `action`
- `message_id`
- `timestamp_ms`

但第一版可以不加。

### DB 方法新增

在 [extensions/services/message/db.py](/D:/modelunion/kite/extensions/services/message/db.py) 增加：

- `insert_prekeys(aid, prekeys)`
- `claim_one_prekey(aid, now_ms)`
- `get_prekey_status(aid, now_ms)`
- `mark_prekey_used(prekey_id, message_id)` 可选
- `cleanup_expired_prekeys(now_ms)`
- `delete_old_used_prekeys(...)` 可选

关键点：

`claim_one_prekey` 必须原子化，不能先查再改。要么用事务 + `SELECT ... FOR UPDATE`，要么用单条更新语句锁定一行。

另外需要新增消息级防重放状态：

- `message_replay_guard` 表，或在现有消息元数据层增加去重索引
- 至少记录 `recipient_aid`、`sender_aid`、`message_id`、`timestamp_ms`、`encryption_mode`
- 模式 3 如要增强，可追加 `ephemeral_public_key_hash`

如果不想新建表，也至少要在持久化消息层保证：

- 同一接收者视角下不会重复接受同一个 `(from_aid, message_id)`
- 模式 2 的 `prekey_id` 消费与消息成功处理之间具备一致性

### 2. Message 模块 RPC 扩展

主文件：[extensions/services/message/entry.py](/D:/modelunion/kite/extensions/services/message/entry.py)

新增 handler：

- `_rpc_e2ee_upload_prekeys`
- `_rpc_e2ee_get_prekey`
- `_rpc_e2ee_prekey_status`

并在 handler map 注册。

推荐入参：

`message.e2ee.upload_prekeys`

- `_auth.aid` 必须存在
- `prekeys: [{prekey_id, public_key, signature, created_at, expires_at?, curve?, suite}]`

返回：

- `accepted`
- `rejected`
- `total`

`message.e2ee.get_prekey`

- `aid`

返回：

- `found: true/false`
- `prekey: {...}` 或 `null`

`message.e2ee.prekey_status`

- 空参数，默认看当前 `_auth.aid`
- 或允许管理员指定 `aid`

返回：

- `total`
- `available`
- `used`
- `expired`
- `min_available_threshold` 可选

### 3. 配置项

主文件：[extensions/services/message/message_config.json](/D:/modelunion/kite/extensions/services/message/message_config.json)

建议新增：

- `e2ee_prekey_min_available`
- `e2ee_prekey_default_batch`
- `e2ee_prekey_expire_hours`
- `e2ee_prekey_cleanup_interval_minutes`

### 4. 后台清理

在 message 模块现有 cleanup 机制里加入：

- 清理过期 prekeys
- 可选清理长期 used prekeys

这个逻辑放在已有后台任务框架里最自然。

## Phase 2：服务端协议一致性与安全补齐

目标：不是只“能存取 prekey”，而是保证行为可安全依赖。

### 1. 上传校验

`upload_prekeys` 不能盲收，至少要校验：

1. `prekey_id` 格式
2. `public_key` 编码合法
3. `signature` 存在
4. `curve` / `suite` 与当前实现匹配
5. prekey 数量上限
6. 同一 `prekey_id` 不重复插入

### 2. 取 key 策略

要明确定义：

1. 优先返回最新还是最旧的 `available`
2. 是否跳过即将过期的 key
3. 是否允许同 aid 并发 claim 多个
4. 如果 key 不足，是返回 `found=false` 还是报错

建议第一版：

- 按 `created_at_ms ASC`
- 跳过过期
- 事务内 claim 一条
- 无可用 key 返回 `found=false`
- 成功 claim 后，后续要么在消息处理成功后标记 `used`，要么直接在 claim 时进入不可再次领取状态

### 2.1 防重放状态策略

需要明确：

1. `message_id` 去重状态由谁维护
2. 去重状态保存多久
3. 失败解密是否占用去重状态
4. 模式 2 的 `prekey_id` 在“领取成功但消息未送达”时如何恢复

建议第一版：

- `message_id` 去重状态由接收端 SDK 持久化为主，服务端辅助保证不重复持久化
- 去重状态 TTL 至少覆盖离线消息 TTL
- 只有解密成功后才写入“已处理 message_id”
- `prekey_id` 一旦被服务端领取，不回滚为 `available`；如发送失败，依赖后续补充 prekey

### 3. 观测性

新增日志和状态输出：

- 当前 available 数
- 每次 claim 记录
- low watermark 告警
- replay reject 次数
- timestamp 超窗拒绝次数
- AAD / envelope 不一致拒绝次数

模块 `status` 可以增加：

- `e2ee_prekey_available`
- `e2ee_prekey_total`
- `e2ee_replay_reject_total`
- `e2ee_aad_mismatch_total`

## Phase 3：AUN SDK / aun-core 改造

核心文件：[aun-sdk-core/python/src/aun_core/e2ee.py](/D:/modelunion/kite/aun-sdk-core/python/src/aun_core/e2ee.py)

这一步才是真正让文档里的“三级降级”成立。

### 1. 先修现有结构问题

当前最明显的问题：

1. 代码只有 `ephemeral_ecdh` 和 `long_term_key` 两条路径，没有 `prekey`
2. 模式 2 / 模式 3 AAD 处理还没拆清

所以第一步不是直接塞 `prekey`，而是先重构加密选择器。

同时要补齐模式 2 / 模式 3 的完整防重放和防篡改状态机，不能只新增一个 `prekey` 分支。

### 2. 把 `encrypt_outbound()` 改成明确的策略分发器

建议改成：

- `_try_existing_session_mode1()`
- `_try_negotiate_mode1(timeout=...)`
- `_try_prekey_mode2()`
- `_encrypt_mode3_long_term_key()`

外层流程：

1. 如果有可用 session，用模式 1
2. 没有 session，则尝试短超时协商模式 1
3. 超时或不可达，再尝试 `prekey`
4. `prekey` 不可用，再走 `long_term_key`

### 3. 新增 prekey 相关 SDK API

建议公开：

- `upload_prekeys(count=10, *, expires_in_hours=None)`
- `get_prekey_status()`
- `replenish_prekeys(target=15)`

内部辅助：

- `_generate_prekey()`
- `_sign_prekey(public_key_bytes)`
- `_fetch_peer_prekey(peer_aid)`
- `_encrypt_with_prekey(...)`
- `_decrypt_with_prekey(...)`

### 4. 新增本地 prekey 私钥存储

现有 keystore 只存 identity 和 session metadata，不足以承载 prekey 私钥生命周期。

要新增本地元数据区：

- `e2ee_prekeys_private`
- 以 `prekey_id -> private_key` 存储
- 被消费后删除
- 过期后清理

建议依然走现有 keystore metadata，而不是另起存储系统。

### 5. 模式 2 报文格式

建议最终 envelope：

- `type = e2ee.encrypted`
- `version = 1`
- `encryption_mode = prekey`
- `prekey_id`
- `ephemeral_public_key`
- `encrypted_session_key`
- `suite`
- `nonce`
- `ciphertext`
- `tag`
- `aad`

这里建议保留 `ephemeral_public_key`。即使文档当前没完全统一，也应让模式 2 拥有标准 ECIES 材料，避免实现歧义。

`aad` 至少应包含：

- `from`
- `to`
- `message_id`
- `timestamp`
- `encryption_mode`
- `suite`
- `prekey_id`

### 6. 模式 2 解密路径

接收端收到 `prekey` 模式消息：

1. 从 envelope 读出 `prekey_id`
2. 从本地 prekey 私钥池找到对应私钥
3. 解出 session key
4. 用 AAD 解密 payload
5. 删除该 `prekey_id` 对应私钥
6. 记录已消费状态

并补充：

7. 记录 `message_id` 去重状态
8. 如果 `prekey_id` 已不存在或已消费，明确报 `replay_detected` / `prekey_consumed`

### 7. 自动补充策略

SDK 可以提供“建议”自动补充，但不要在所有场景默认后台偷偷做网络调用。

建议：

- 提供显式 API
- 提供可选配置 `auto_replenish_prekeys`
- 默认关闭自动后台补充，避免不可预期行为

### 8. 模式 3 报文与解密要求

模式 3 envelope 除现有字段外，还应把以下内容绑定进 `aad`：

- `encryption_mode`
- `suite`
- `ephemeral_public_key`
- `recipient_cert_fingerprint`

接收端收到模式 3 消息时，需要：

1. 校验外层 envelope 与 AAD 一致
2. 校验 `recipient_cert_fingerprint` 与当前解密身份匹配
3. 解密成功后记录 `message_id` 去重状态
4. 根据 `timestamp` 做时间窗校验

### 9. SDK 本地状态存储

除了 `e2ee_sessions`，还要新增：

- `e2ee_prekeys_private`
- `e2ee_seen_message_ids`
- 可选：`e2ee_mode3_seen_ephemeral_hashes`

其中：

- `e2ee_prekeys_private` 用于模式 2 解密
- `e2ee_seen_message_ids` 用于模式 2/3 的重放检测
- `e2ee_mode3_seen_ephemeral_hashes` 用于增强模式 3 的重复密文检测

## Phase 4：Gateway / RPC 暴露层

gateway 改动不会很大。

主文件：[extensions/services/gateway/ws_server.py](/D:/modelunion/kite/extensions/services/gateway/ws_server.py)

### 必要改动

1. 确保新的 RPC 方法可正常透传到 message 模块
2. 如果有 RPC 权限白名单或 method 校验，要把 `message.e2ee.*` 纳入
3. 如果控制台或 discovery 需要显示能力，可增加 capability 暴露

### 不需要做的事

1. 不要在 gateway 缓存 prekey
2. 不要在 gateway 解析 E2EE payload
3. 不要在 gateway 引入 prekey DB

gateway 只应继续做：

- 认证后的 RPC 路由
- PKI HTTP 证书下载

## Phase 5：文档回写

只有在 Phase 1-4 完成后才能改回文档。

### 协议文档

要更新：

- `08-AUN-E2EE.md`
- `附录L-E2EE实现指南.md`

必须与最终 RPC、AAD、报文字段完全一致。

### SDK 文档

要更新：

- Python SDK `05-E2EE加密通信.md`
- API 手册
- 示例

重点是保证文档里提到的 API 真存在。

### aun-skill 文档

它应从 SDK 文档同步生成或至少逐项核对，不要再手写漂移。

## 数据库迁移计划

建议分两次迁移。

### Migration 1：新增表，不影响旧逻辑

新增 `e2ee_prekeys` 表和索引。
这一步完全向前兼容。

### Migration 2：清理策略和统计优化

上线后再根据真实负载补：

- used key 清理索引
- status 统计优化索引
- 审计表

不要一开始就做复杂 schema。

## RPC 设计建议

推荐最终暴露为：

### 服务端 RPC

- `message.e2ee.upload_prekeys`
- `message.e2ee.get_prekey`
- `message.e2ee.prekey_status`

### SDK 内部调用

- `client.call("message.e2ee.upload_prekeys", ...)`
- `client.call("message.e2ee.get_prekey", ...)`
- `client.call("message.e2ee.prekey_status", ...)`

如果为了兼容现有文档还要保留旧名，可以在 message 模块里做 alias：

- `e2ee.upload_prekeys -> message.e2ee.upload_prekeys`
- `e2ee.get_prekey -> message.e2ee.get_prekey`
- `e2ee.prekey_status -> message.e2ee.prekey_status`

但不建议长期双轨。

## 测试计划

这是必须重点补的，不然 E2EE 这种东西很容易“看起来能跑”。

### A. 服务端单元测试

新增或扩展：

- [tests/unit/test_message_module.py](/D:/modelunion/kite/tests/unit/test_message_module.py)

建议覆盖：

1. `upload_prekeys` 成功插入
2. 重复 `prekey_id` 被拒绝
3. `get_prekey` 原子 claim
4. 并发 claim 不重复返回
5. 过期 prekey 不返回
6. `prekey_status` 统计正确
7. cleanup 能清理 expired/used
8. 同一 `(from_aid, message_id)` 不会被重复接受
9. 同一 `prekey_id` 不会被重复消费
10. 模式 2 / 3 的重放守卫状态可清理

如果 DB 层逻辑比较多，单独新增：

- `tests/unit/test_message_prekey_db.py`

### B. Message 模块测试

如果保留模块级测试套件，新增：

- `tests/module/test_message_e2ee_prekey.py`

覆盖：

1. RPC 注册成功
2. 认证用户可上传自己的 prekeys
3. A 用户不能上传到 B 用户名下
4. `get_prekey` 返回结构正确
5. 无可用 key 时 `found=false`
6. 模式 2 的 `prekey_id` 不会并发重复发放
7. replay / timestamp reject 统计可见

### C. SDK 单元测试

新增：

- `aun-sdk-core/python/tests/unit/test_e2ee.py`

覆盖：

1. 有现有 session 时走模式 1
2. 协商超时但有 prekey 时走模式 2
3. 无 prekey 时走模式 3
4. 模式 2 envelope 字段正确
5. 模式 2 解密成功后删除本地 prekey 私钥
6. 模式 2 AAD mismatch 解密失败
7. `upload_prekeys` / `get_prekey_status` / `replenish_prekeys` 调用正确 RPC
8. 模式 2 `message_id` 重放会被拒绝
9. 模式 3 `message_id` 重放会被拒绝
10. 模式 3 `recipient_cert_fingerprint` 不匹配会被拒绝
11. 模式 2 / 3 超出时间窗会被拒绝

### D. 端到端 E2E

新增或扩展：

- `tests/e2e/test_message_sdk_e2e.py`
- 单独新增 `tests/e2e/test_message_e2ee_prekey_sdk.py`

至少覆盖：

1. 双方在线，首条消息走模式 1
2. 对端离线但已上传 prekeys，首条消息走模式 2
3. 对端离线且 prekey 池为空，走模式 3
4. 同一个 `prekey_id` 不会被重复消费
5. 重放旧模式 2 报文时解密失败
6. 证书仍通过现有 `/pki/cert/{aid}` 下载校验
7. 文档里的完整三级降级示例真实通过
8. 重放旧模式 3 报文时解密失败
9. 篡改模式 2 的 `prekey_id` / `suite` / `encryption_mode` 会被拒绝
10. 篡改模式 3 的 `ephemeral_public_key` / `recipient_cert_fingerprint` 会被拒绝

### E. 回归测试

必须确认不破坏现有：

1. `message.send`
2. `message.pull`
3. 非加密消息
4. 现有模式 1 会话复用
5. 现有模式 3 离线长期公钥加密

## 推荐阶段拆分

### 第一阶段：服务端基础能力

交付物：

- prekey 表
- upload/get/status 三个 RPC
- 单测通过

不改 SDK 自动策略。

### 第二阶段：SDK 接入 prekey

交付物：

- `aun-core` 能用 prekey
- `encrypt_outbound()` 真正变成 1 -> 2 -> 3
- SDK 单测通过

### 第三阶段：E2E 与文档收口

交付物：

- 端到端测试
- 更新协议文档 / SDK 文档 / skill 文档
- 删除“未实现 API”描述

## 风险点

1. 最大风险不是密码学，而是并发 claim prekey 的一致性。
2. 第二个风险是本地 prekey 私钥生命周期管理，删早了会解不开，删晚了会破坏一次性语义。
3. 第三个风险是文档继续先于实现漂移，所以文档必须最后回写。
4. 第四个风险是模式 2 / 模式 3 AAD 和 envelope 字段若不先冻结，SDK 和服务端会再分叉一次。
5. 第五个风险是模式 2 / 模式 3 没有 counter，若不补持久化去重状态，就无法真正防重放。

## 建议的实际开工顺序

1. 先定最终 RPC 名称和 envelope/AAD
2. 改 [extensions/services/message/db.py](/D:/modelunion/kite/extensions/services/message/db.py)
3. 改 [extensions/services/message/entry.py](/D:/modelunion/kite/extensions/services/message/entry.py)
4. 补 message 单测
5. 再改 [aun-sdk-core/python/src/aun_core/e2ee.py](/D:/modelunion/kite/aun-sdk-core/python/src/aun_core/e2ee.py)
6. 补 SDK 单测
7. 补 E2E
8. 最后统一文档

## 方法级执行清单

下面这一节把改造拆到文件和方法级别，按这个顺序实施时，能够尽量减少返工。

### Stage A：先冻结接口和错误语义

这一阶段不写主逻辑，只把接口面敲定。

#### A1. 协议层冻结项

需要最终确认：

1. 是否统一采用 `message.e2ee.*` 作为正式 RPC 名称
2. 是否保留 `e2ee.*` 兼容别名
3. `prekey` 状态机到底采用 `available/reserved/used/expired` 还是简化版
4. `message_id` 去重范围是“全局唯一”还是“发送方维度唯一”
5. `timestamp` 默认时间窗大小
6. `recipient_cert_fingerprint` 的计算方式
7. 模式 3 是否把 `ephemeral_public_key` 原文放进 AAD，还是放其摘要

建议最终冻结：

- 正式 RPC：`message.e2ee.upload_prekeys` / `message.e2ee.get_prekey` / `message.e2ee.prekey_status`
- 兼容别名：可短期保留 `e2ee.*`
- `message_id`：发送方维度唯一即可
- 时间窗：300 秒
- 模式 3 AAD：优先放 `ephemeral_public_key` 原文，减少歧义

#### A2. 建议新增错误码

服务端和 SDK 统一新增或映射：

- `E2EE_PREKEY_NOT_FOUND`
- `E2EE_PREKEY_ALREADY_USED`
- `E2EE_REPLAY_DETECTED`
- `E2EE_MESSAGE_EXPIRED`
- `E2EE_AAD_MISMATCH`
- `E2EE_RECIPIENT_BINDING_FAILED`
- `E2EE_PREKEY_SIGNATURE_INVALID`

#### A3. 建议统一错误返回结构

服务端 RPC 建议统一返回 JSON-RPC error，`message`/SDK 内部错误名保持一致：

```json
{
  "code": -32022,
  "message": "E2EE_REPLAY_DETECTED",
  "data": {
    "reason": "message_id_already_seen",
    "message_id": "msg-123",
    "aid": "bob.aid.pub"
  }
}
```

建议错误码映射：

| 业务错误 | JSON-RPC code | 说明 |
|---|---:|---|
| `E2EE_PREKEY_NOT_FOUND` | `-32020` | 无可用 prekey |
| `E2EE_PREKEY_ALREADY_USED` | `-32021` | prekey 已被消费 |
| `E2EE_REPLAY_DETECTED` | `-32022` | 命中 replay guard |
| `E2EE_MESSAGE_EXPIRED` | `-32023` | 超出时间窗 |
| `E2EE_AAD_MISMATCH` | `-32024` | AAD 与 envelope 不一致 |
| `E2EE_RECIPIENT_BINDING_FAILED` | `-32025` | 接收方身份绑定失败 |
| `E2EE_PREKEY_SIGNATURE_INVALID` | `-32026` | prekey 签名无效 |

### Stage B：Message DB 改造

主文件：[extensions/services/message/db.py](/D:/modelunion/kite/extensions/services/message/db.py)

#### B1. `init()` 中新增表

在现有 `CREATE TABLE messages` / `inbox_seq` 后新增：

1. `e2ee_prekeys`
2. `e2ee_replay_guard`

建议 `e2ee_replay_guard` 字段：

- `id` BIGINT AUTO_INCREMENT
- `recipient_aid` VARCHAR(255) NOT NULL
- `sender_aid` VARCHAR(255) NOT NULL
- `message_id` VARCHAR(64) NOT NULL
- `encryption_mode` VARCHAR(32) NOT NULL
- `timestamp_ms` BIGINT NOT NULL
- `ephemeral_public_key_hash` VARCHAR(128) NULL
- `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP

索引建议：

- UNIQUE (`recipient_aid`, `sender_aid`, `message_id`)
- INDEX (`recipient_aid`, `created_at`)
- INDEX (`recipient_aid`, `encryption_mode`, `created_at`)

建议 SQL 草案：

```sql
CREATE TABLE IF NOT EXISTS `e2ee_prekeys` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `aid` VARCHAR(255) NOT NULL,
  `prekey_id` VARCHAR(64) NOT NULL,
  `public_key` TEXT NOT NULL,
  `signature` TEXT NOT NULL,
  `curve` VARCHAR(32) NOT NULL DEFAULT 'P-256',
  `suite` VARCHAR(64) NOT NULL,
  `status` VARCHAR(16) NOT NULL DEFAULT 'available',
  `created_at_ms` BIGINT NOT NULL,
  `expires_at_ms` BIGINT NULL,
  `reserved_at_ms` BIGINT NULL,
  `used_at_ms` BIGINT NULL,
  `reserved_by_message_id` VARCHAR(64) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_prekey_id` (`prekey_id`),
  KEY `idx_prekey_aid_status_created` (`aid`, `status`, `created_at_ms`),
  KEY `idx_prekey_aid_expires` (`aid`, `expires_at_ms`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

```sql
CREATE TABLE IF NOT EXISTS `e2ee_replay_guard` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `recipient_aid` VARCHAR(255) NOT NULL,
  `sender_aid` VARCHAR(255) NOT NULL,
  `message_id` VARCHAR(64) NOT NULL,
  `encryption_mode` VARCHAR(32) NOT NULL,
  `timestamp_ms` BIGINT NOT NULL,
  `ephemeral_public_key_hash` VARCHAR(128) NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_replay_guard` (`recipient_aid`, `sender_aid`, `message_id`),
  KEY `idx_replay_recipient_created` (`recipient_aid`, `created_at`),
  KEY `idx_replay_recipient_mode_created` (`recipient_aid`, `encryption_mode`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

#### B2. 在 `MessageDB` 中新增方法

建议新增以下方法：

1. `async def insert_prekeys(self, aid: str, prekeys: list[dict]) -> dict`
2. `async def claim_one_prekey(self, aid: str, now_ms: int) -> dict | None`
3. `async def get_prekey_status(self, aid: str, now_ms: int) -> dict`
4. `async def mark_prekey_used(self, prekey_id: str, used_at_ms: int, *, message_id: str | None = None) -> bool`
5. `async def mark_prekey_expired(self, now_ms: int, batch_size: int = 500) -> int`
6. `async def record_replay_guard(self, recipient_aid: str, sender_aid: str, message_id: str, encryption_mode: str, timestamp_ms: int, *, ephemeral_public_key_hash: str | None = None) -> bool`
7. `async def has_replay_guard(self, recipient_aid: str, sender_aid: str, message_id: str) -> bool`
8. `async def cleanup_replay_guard(self, older_than_ms: int, batch_size: int = 1000) -> int`

建议签名：

```python
async def insert_prekeys(self, aid: str, prekeys: list[dict[str, object]]) -> dict[str, int]:
    ...

async def claim_one_prekey(self, aid: str, now_ms: int) -> dict[str, object] | None:
    ...

async def get_prekey_status(self, aid: str, now_ms: int) -> dict[str, int]:
    ...

async def mark_prekey_used(
    self,
    prekey_id: str,
    used_at_ms: int,
    *,
    message_id: str | None = None,
) -> bool:
    ...

async def cleanup_expired_prekeys(self, now_ms: int, batch_size: int = 500) -> int:
    ...

async def record_replay_guard(
    self,
    recipient_aid: str,
    sender_aid: str,
    message_id: str,
    encryption_mode: str,
    timestamp_ms: int,
    *,
    ephemeral_public_key_hash: str | None = None,
) -> bool:
    ...

async def has_replay_guard(self, recipient_aid: str, sender_aid: str, message_id: str) -> bool:
    ...

async def cleanup_replay_guard(self, older_than_ms: int, batch_size: int = 1000) -> int:
    ...
```

#### B3. `claim_one_prekey()` 的事务要求

实现要求：

1. 只领取 `available`
2. 跳过已过期记录
3. 原子化返回唯一一条
4. 返回后不能再被其他请求领取

推荐流程：

1. `SELECT ... FOR UPDATE`
2. 按 `created_at_ms ASC LIMIT 1`
3. 更新为 `reserved` 或直接 `used`
4. 提交事务

如果第一版不做 `reserved`，可以直接从 `available -> used`，但要在文档里明确“领取即消费”。

#### B4. `record_replay_guard()` 的语义

建议语义：

- 成功插入返回 `True`
- 唯一键冲突返回 `False`

这样 SDK 或服务端流程中可以直接把 `False` 视为重放。

### Stage C：Message 模块 RPC 改造

主文件：[extensions/services/message/entry.py](/D:/modelunion/kite/extensions/services/message/entry.py)

#### C1. 新增 handler

建议新增：

1. `_rpc_e2ee_upload_prekeys(params: dict) -> dict`
2. `_rpc_e2ee_get_prekey(params: dict) -> dict`
3. `_rpc_e2ee_prekey_status(params: dict) -> dict`

可选新增：

4. `_rpc_e2ee_mark_prekey_used(params: dict) -> dict`

一般不建议对外暴露第 4 个；如果服务端采用“claim 即消费”，就不需要。

#### C2. `_rpc_e2ee_upload_prekeys()`

必须做：

1. 从 `_auth.aid` 取当前身份
2. 校验 `prekeys` 数组存在且不为空
3. 限制批量大小
4. 校验每个 prekey 的：
   - `prekey_id`
   - `public_key`
   - `signature`
   - `created_at`
   - `curve`
   - `suite`
5. 调 `db.insert_prekeys()`
6. 返回 `accepted/rejected/total`

第一版这里可以只做格式校验，不做密码学签名校验；签名有效性放到发送方使用 prekey 时校验。

建议 RPC 请求体：

```json
{
  "jsonrpc": "2.0",
  "id": "rpc-id",
  "method": "message.e2ee.upload_prekeys",
  "params": {
    "prekeys": [
      {
        "prekey_id": "uuid-v4",
        "public_key": "base64",
        "signature": "base64",
        "created_at": 1710504000000,
        "expires_at": 1710590400000,
        "curve": "P-256",
        "suite": "P256_HKDF_SHA256_AES_256_GCM"
      }
    ]
  }
}
```

建议成功返回：

```json
{
  "accepted": 10,
  "rejected": 0,
  "total": 10
}
```

#### C3. `_rpc_e2ee_get_prekey()`

必须做：

1. 读取目标 `aid`
2. 调 `db.claim_one_prekey()`
3. 如果没有可用 prekey，返回 `{"found": false}`
4. 如果有，返回：
   - `found: true`
   - `prekey_id`
   - `public_key`
   - `signature`
   - `created_at`
   - `expires_at`
   - `curve`
   - `suite`

不要在这里拼接证书内容。证书继续走 `/pki/cert/{aid}`。

建议 RPC 请求体：

```json
{
  "jsonrpc": "2.0",
  "id": "rpc-id",
  "method": "message.e2ee.get_prekey",
  "params": {
    "aid": "bob.aid.pub"
  }
}
```

建议成功返回：

```json
{
  "found": true,
  "prekey": {
    "prekey_id": "uuid-v4",
    "public_key": "base64",
    "signature": "base64",
    "created_at": 1710504000000,
    "expires_at": 1710590400000,
    "curve": "P-256",
    "suite": "P256_HKDF_SHA256_AES_256_GCM"
  }
}
```

#### C4. `_rpc_e2ee_prekey_status()`

必须做：

1. 默认查询 `_auth.aid`
2. 调 `db.get_prekey_status()`
3. 返回：
   - `total`
   - `available`
   - `reserved`
   - `used`
   - `expired`
   - `threshold`

建议成功返回：

```json
{
  "total": 20,
  "available": 12,
  "reserved": 1,
  "used": 5,
  "expired": 2,
  "threshold": 5
}
```

#### C5. 注册 handler map

在现有 `handlers = { "send": ..., "pull": ... }` 中扩展：

- `"e2ee.upload_prekeys": _rpc_e2ee_upload_prekeys`
- `"e2ee.get_prekey": _rpc_e2ee_get_prekey`
- `"e2ee.prekey_status": _rpc_e2ee_prekey_status`

如果决定正式名称是 `message.e2ee.*`，则要同步确认模块 RPC 路由如何映射。如果 message 模块内部只收子方法名，则这里保留 `e2ee.*` 子域即可。

建议在文档里定死一个规则：

- registry 对外展示用 `message.e2ee.*`
- message 模块内部 handler key 用 `e2ee.upload_prekeys` / `e2ee.get_prekey` / `e2ee.prekey_status`
- gateway/Kernel 路由进入 message 模块后，剥离 `message.` 前缀

#### C6. 模块状态输出

建议在 `_rpc_status()` 里追加：

- `e2ee_prekey_total`
- `e2ee_prekey_available`
- `e2ee_replay_guard_size`
- `e2ee_replay_reject_total`

#### C7. 后台清理

在现有后台 cleanup loop 中追加：

1. `cleanup_expired_prekeys`
2. `cleanup_replay_guard`

并把统计输出到日志。

### Stage D：Gateway 暴露层

主文件：[extensions/services/gateway/ws_server.py](/D:/modelunion/kite/extensions/services/gateway/ws_server.py)

#### D1. 认证后 RPC 透传检查

确认 gateway 不会拦截或拒绝以下方法：

- `message.e2ee.upload_prekeys`
- `message.e2ee.get_prekey`
- `message.e2ee.prekey_status`

如果内部实际是 `message` 域 + 子方法，那么只需要保证 message 域透传逻辑不做额外限制。

#### D2. 不需要做的改动

明确不做：

1. 不在 gateway 做 prekey 缓存
2. 不在 gateway 做 replay guard
3. 不在 gateway 解析 E2EE payload

### Stage E：SDK 公开接口层

主文件：

- [aun-sdk-core/python/src/aun_core/e2ee.py](/D:/modelunion/kite/aun-sdk-core/python/src/aun_core/e2ee.py)
- 以及对应 client/namespace 暴露层

#### E1. `E2EEManager` 需要新增的公开方法

建议新增：

1. `async def upload_prekeys(self, count: int = 10, *, expires_in_hours: int | None = None) -> dict`
2. `async def get_prekey_status(self) -> dict`
3. `async def replenish_prekeys(self, target: int = 15) -> dict`

建议新增只读属性：

4. `last_error`
5. 可选 `last_encryption_mode`

建议签名：

```python
async def upload_prekeys(self, count: int = 10, *, expires_in_hours: int | None = None) -> dict[str, object]:
    ...

async def get_prekey_status(self) -> dict[str, object]:
    ...

async def replenish_prekeys(self, target: int = 15) -> dict[str, object]:
    ...
```

#### E2. 本地辅助方法

建议新增：

1. `_generate_prekey() -> tuple[dict, private_key]`
2. `_store_local_prekey_private(prekey_id, private_key)`
3. `_load_local_prekey_private(prekey_id)`
4. `_delete_local_prekey_private(prekey_id)`
5. `_fetch_peer_prekey(peer_aid)`
6. `_verify_prekey_signature(peer_aid, prekey)`
7. `_record_seen_message_id(peer_aid, message_id, mode, timestamp, *, eph_hash=None)`
8. `_seen_message_id(peer_aid, message_id) -> bool`
9. `_validate_timestamp_window(timestamp: int)`
10. `_ephemeral_public_key_hash(value: str) -> str`

建议签名：

```python
def _generate_prekey(self, *, expires_in_hours: int | None = None) -> tuple[dict[str, object], object]:
    ...

def _store_local_prekey_private(self, prekey_id: str, private_key: object, *, created_at: int, expires_at: int | None) -> None:
    ...

def _load_local_prekey_private(self, prekey_id: str) -> object | None:
    ...

def _delete_local_prekey_private(self, prekey_id: str) -> None:
    ...

async def _fetch_peer_prekey(self, peer_aid: str) -> dict[str, object] | None:
    ...

def _verify_prekey_signature(self, peer_aid: str, prekey: dict[str, object]) -> None:
    ...

def _record_seen_message_id(
    self,
    peer_aid: str,
    message_id: str,
    mode: str,
    timestamp: int,
    *,
    eph_hash: str | None = None,
) -> None:
    ...

def _seen_message_id(self, peer_aid: str, message_id: str) -> bool:
    ...

def _validate_timestamp_window(self, timestamp: int) -> None:
    ...
```

#### E3. 重构 `encrypt_outbound()`

当前 `encrypt_outbound()` 需要拆成：

1. `_encrypt_with_session(...)`
2. `_try_negotiate_session(...)`
3. `_encrypt_with_prekey(...)`
4. `_encrypt_with_long_term_key(...)`

推荐最终流程：

1. 查现有 session
2. session 可用则模式 1
3. 无 session，则短超时协商
4. 协商超时或失败，则 `_fetch_peer_prekey()`
5. 有 prekey 则模式 2
6. 无 prekey 则模式 3

#### E4. 模式 2 加密函数

`_encrypt_with_prekey(...)` 需要负责：

1. 获取并验证 peer prekey
2. 生成会话密钥
3. 生成发送方临时密钥
4. 使用 peer prekey 加密会话密钥
5. 组装 AAD
6. 组装 envelope

AAD 至少包含：

- `from`
- `to`
- `message_id`
- `timestamp`
- `encryption_mode`
- `suite`
- `prekey_id`

#### E5. 模式 2 解密函数

新增 `_decrypt_message_prekey(...)`

步骤：

1. 读取 `prekey_id`
2. 校验外层字段与 AAD 一致
3. 校验 `message_id` 未处理
4. 校验时间窗
5. 取本地 prekey 私钥
6. 解密会话密钥
7. 解密业务载荷
8. 删除 prekey 私钥
9. 写入 seen-message 状态

#### E6. 模式 3 加密函数

现有 `_encrypt_with_long_term_key(...)` 需要改造：

1. AAD 不能只含 `from/to/message_id/timestamp`
2. 必须加上：
   - `encryption_mode`
   - `suite`
   - `ephemeral_public_key`
   - `recipient_cert_fingerprint`

3. 发出前要构造接收方证书指纹

#### E7. 模式 3 解密函数

现有 `_decrypt_message_mode2()` 的长期公钥分支需要重命名和拆清。

建议新增：

1. `_decrypt_message_mode1(...)`
2. `_decrypt_message_prekey(...)`
3. `_decrypt_message_long_term_key(...)`

模式 3 解密步骤：

1. 校验外层字段与 AAD 一致
2. 校验 `message_id` 未处理
3. 校验时间窗
4. 校验 `recipient_cert_fingerprint`
5. 解密会话密钥
6. 解密 payload
7. 写入 seen-message 状态

#### E8. AAD 工具函数重构

现有 `_aad_bytes()` 只支持一套固定字段，必须改。

建议改成：

1. `_aad_bytes_mode1(aad)`
2. `_aad_bytes_prekey(aad)`
3. `_aad_bytes_long_term(aad)`
4. `_aad_matches_mode1(expected, actual)`
5. `_aad_matches_prekey(expected, actual)`
6. `_aad_matches_long_term(expected, actual)`

否则模式 2 / 模式 3 会继续共用错误字段集合。

建议固定字段集：

```python
AAD_FIELDS_MODE1 = ("from", "to", "message_id", "timestamp", "session_id", "counter")
AAD_FIELDS_PREKEY = ("from", "to", "message_id", "timestamp", "encryption_mode", "suite", "prekey_id")
AAD_FIELDS_LONG_TERM = (
    "from",
    "to",
    "message_id",
    "timestamp",
    "encryption_mode",
    "suite",
    "ephemeral_public_key",
    "recipient_cert_fingerprint",
)
```

#### E9. 本地持久化结构

在现有 keystore metadata 中新增：

- `e2ee_prekeys_private`
- `e2ee_seen_messages`
- 可选 `e2ee_seen_mode3_ephemeral_hashes`

建议结构：

`e2ee_prekeys_private`
- `{ prekey_id: { private_key_pem, created_at, expires_at } }`

`e2ee_seen_messages`
- `[{ peer_aid, message_id, mode, timestamp, seen_at, eph_hash? }]`

建议进一步定成：

```json
{
  "e2ee_prekeys_private": {
    "uuid-v4": {
      "private_key_pem": "-----BEGIN PRIVATE KEY-----...",
      "created_at": 1710504000000,
      "expires_at": 1710590400000
    }
  },
  "e2ee_seen_messages": [
    {
      "peer_aid": "alice.aid.pub",
      "message_id": "msg-123",
      "mode": "prekey",
      "timestamp": 1710504000000,
      "seen_at": 1710504001234,
      "eph_hash": null
    }
  ]
}
```

建议给 `e2ee_seen_messages` 做本地裁剪：

- 只保留最近 N 条，默认 5000
- 或按时间窗 + 离线 TTL 裁剪

### Stage H：需要 review 时重点拍板的决策项

1. 正式 RPC 名是否采用 `message.e2ee.*`
2. prekey 是否“领取即消费”，还是需要 `reserved -> used`
3. `e2ee_replay_guard` 是否单独建表
4. 模式 3 的 `recipient_cert_fingerprint` 是否进入 AAD
5. 模式 3 的 `ephemeral_public_key` 是否原文进入 AAD
6. `message_id` 唯一性是否按“发送方维度”
7. 时间窗是否固定 300 秒
8. seen-message 本地缓存上限和裁剪策略

### Stage F：测试拆分

#### F1. DB 单测

建议新增文件：

- [tests/unit/test_message_prekey_db.py](/D:/modelunion/kite/tests/unit/test_message_prekey_db.py)

建议测试名：

1. `test_insert_prekeys_accepts_valid_batch`
2. `test_insert_prekeys_rejects_duplicate_prekey_id`
3. `test_claim_one_prekey_returns_oldest_available`
4. `test_claim_one_prekey_is_atomic_under_concurrency`
5. `test_get_prekey_status_counts_by_state`
6. `test_record_replay_guard_rejects_duplicate_message_id`
7. `test_cleanup_expired_prekeys_removes_expired_rows`
8. `test_cleanup_replay_guard_removes_old_rows`

#### F2. Message 模块单测

扩展 [tests/unit/test_message_module.py](/D:/modelunion/kite/tests/unit/test_message_module.py)

建议新增测试名：

1. `test_rpc_e2ee_upload_prekeys_requires_auth_aid`
2. `test_rpc_e2ee_upload_prekeys_validates_shape`
3. `test_rpc_e2ee_get_prekey_returns_found_false_when_empty`
4. `test_rpc_e2ee_get_prekey_claims_exactly_one`
5. `test_rpc_e2ee_prekey_status_returns_counts`
6. `test_message_status_includes_e2ee_metrics`

#### F3. SDK 单测

建议新增文件：

- [aun-sdk-core/python/tests/unit/test_e2ee.py](/D:/modelunion/kite/aun-sdk-core/python/tests/unit/test_e2ee.py)

建议测试名：

1. `test_encrypt_outbound_prefers_existing_session`
2. `test_encrypt_outbound_falls_back_to_prekey_after_negotiation_timeout`
3. `test_encrypt_outbound_falls_back_to_long_term_key_when_no_prekey`
4. `test_encrypt_with_prekey_envelope_contains_required_aad_fields`
5. `test_decrypt_prekey_message_consumes_local_prekey`
6. `test_decrypt_prekey_message_rejects_replay_message_id`
7. `test_decrypt_long_term_message_rejects_replay_message_id`
8. `test_decrypt_long_term_message_rejects_wrong_recipient_fingerprint`
9. `test_decrypt_mode2_or_mode3_rejects_timestamp_outside_window`
10. `test_upload_prekeys_calls_message_e2ee_upload_prekeys`
11. `test_replenish_prekeys_uploads_missing_count_only`

#### F4. E2E 测试

建议新增：

- [tests/e2e/test_message_e2ee_prekey_sdk.py](/D:/modelunion/kite/tests/e2e/test_message_e2ee_prekey_sdk.py)

建议测试名：

1. `test_online_first_message_uses_mode1`
2. `test_offline_recipient_with_prekey_uses_mode2`
3. `test_offline_recipient_without_prekey_uses_mode3`
4. `test_prekey_message_cannot_be_replayed`
5. `test_long_term_mode_message_cannot_be_replayed`
6. `test_mode2_tampered_prekey_id_is_rejected`
7. `test_mode2_tampered_suite_is_rejected`
8. `test_mode3_tampered_ephemeral_public_key_is_rejected`
9. `test_mode3_tampered_recipient_binding_is_rejected`

### Stage G：建议的实际编码顺序

真正开始写代码时，推荐按下面顺序提交，避免一个 PR 太大：

#### PR 1：协议和计划文档收敛

包含：

1. `08-AUN-E2EE.md`
2. `E2EE完善计划.md`

目标：冻结字段、AAD、重放规则、错误语义。

#### PR 2：Message DB + RPC 骨架

包含：

1. `message/db.py`
2. `message/entry.py`
3. `message/module.md`
4. `message/message_config.json`
5. DB / 模块单测

目标：服务端具备真实 prekey 生命周期管理和 replay guard 基础能力。

#### PR 3：SDK prekey 能力接入

包含：

1. `aun_core/e2ee.py`
2. 公开 API 暴露层
3. SDK 单测

目标：`encrypt_outbound()` 变成真实 1 -> 2 -> 3。

#### PR 4：重放与篡改防护补齐

包含：

1. seen-message 持久化
2. timestamp window
3. recipient binding
4. 模式 2 / 3 AAD 重构
5. 相关单测

目标：不是“能跑”，而是“防重放、防篡改规则成立”。

#### PR 5：E2E + 文档回写

包含：

1. E2E 测试
2. Python SDK 文档
3. aun-skill 文档

目标：文档只描述已落地能力。
