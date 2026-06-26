# 10. Group 子协议

> **适用版本**：AUN 1.0 | **状态**：Draft

Group 服务是 AUN 协议的应用层扩展，提供多人群组通信能力。Group 服务本身是一个 AID 持有者，客户端通过标准 `message.*` 协议与 Group 服务通信，Group 服务通过 JSON-RPC 2.0 暴露 `group.*` 命名空间方法。

---

## 10.1 架构与角色

```
客户端 A ──message.send──► Group Service (AID: group.service.aid)
                              │
                              ├── 存储群消息
                              ├── 广播 event/group.message_created
                              └── 推送 event/group.changed
```

- **Group Service**：持有独立 AID，作为 AUN 节点运行，暴露 `group.*` RPC 方法
- **成员**：通过 `group.request_join` / `group.add_member` / `group.use_invite_code` 加入
- **权限层级**：`owner` > `admin` > `member`（只读群另有 `observer` 角色）

---

## 10.2 数据模型

### Group 对象

| 字段 | 类型 | 说明 |
|------|------|------|
| `group_id` | string | 群组唯一 ID（自动生成或自定义） |
| `name` | string | 群组名称 |
| `owner_aid` | string | 群主 AID |
| `creator_aid` | string | 创建者 AID |
| `visibility` | string | `"public"` / `"private"` |
| `status` | string | `"active"` / `"suspended"` / `"closed"` |
| `description` | string | 群组描述 |
| `metadata` | object | 自定义元数据 |
| `dispatch_mode` | string | 群分发模式：`"broadcast"`（默认）/ `"mention"`，详见 [10.2.x 群分发模式](#1023-群分发模式dispatch_mode) |
| `member_count` | integer | 成员数量 |
| `message_seq` | integer | 最新消息序号 |
| `event_seq` | integer | 最新事件序号 |
| `created_at` | integer | 创建时间（Unix 秒） |

### Group ID 格式与规范化

`group_id` 是群组的全网唯一标识，前缀 `g-` 为 Group 保留前缀（legacy 格式）。普通 AID 的本地名称不得以 `g-` 开头，避免与群 ID 混淆。

**支持的 base 格式**（不含域名部分）：
- **Legacy 格式**: `g-[a-z0-9]{4,32}` — 以 `g-` 开头，后接 4 到 32 位小写字母或数字
- **新格式**: `[a-z0-9]{5,}` — 5 位或更多小写字母或数字，无上限
- **Group name 格式**: `[a-z0-9][a-z0-9_-]{3,63}` — 4 到 64 个字符，可包含下划线和短横线

服务端必须接受以下输入形式，并在内部统一为 canonical group_id：

| 输入形式 | 用途 | canonical 结果 |
|----------|------|----------------|
| `{base}` | 本地域内简写（base 为上述任一格式） | 若本域 issuer 为 `issuer-domain`，规范化为 `group.issuer-domain/{base}` |
| `{base}@issuer-domain` | 跨域传播兼容形式 | 规范化为 `group.issuer-domain/{base}` |
| `{base}.issuer-domain` | 旧 canonical 形式 | 规范化为 `group.issuer-domain/{base}` |
| `group.issuer-domain/{base}` | 新 canonical 形式 | 保持为 `group.issuer-domain/{base}` |

规范化规则：

- `group_id` 比较、数据库存储、成员归属、权限校验、E2EE AAD / 签名输入均必须使用 canonical group_id（`group.{issuer}/{base}` 格式）。
- 输入必须先 trim 并转换为小写；`@issuer-domain` 和 `.issuer-domain` 形式仅作为兼容输入，进入内部前必须转换为 `group.{issuer}/{base}`。
- 本域内客户端可以提交 `{base}` 简写；服务端按本域 `AUN_ISSUER_DOMAIN` 解析为 canonical group_id。没有本域 issuer 配置时，简写保持为 `{base}`。
- 跨域消息、邀请传播、日志和协议响应应使用 canonical group_id，避免远端误把短 ID 当成本域群。
- `group.create` 可以指定 `group_id`；指定时必须满足上述格式且未被占用，被占用时返回错误。未指定时由服务端自动分配。
- 自动生成的群 ID 使用随机小写十六进制短字符串（长度 14），服务端必须通过唯一约束或等效机制保证 canonical group_id 唯一；发现碰撞时重新生成。
- 在 `group.{issuer-domain}` 这类已携带 issuer 的公开 HTTP 主机下，生成的群链接 path 应使用本域简写，例如 `https://group.issuer-domain/{base}` 或 `https://group.issuer-domain/{base}/invite/ic-xxx`。

### 10.2.3 群分发模式（dispatch_mode）

`dispatch_mode` 是**群级配置**，决定接收方 channel 层向 Agent 大模型分发群消息的过滤策略。它不影响 AUN 协议层对消息的投递（消息仍然送达所有在线成员），仅影响"哪些消息会进入接收方 Agent 的 LLM 上下文"。

| 取值 | 中文名 | 语义 |
|------|--------|------|
| `broadcast`（默认） | 广播模式 | 群内所有消息都送进每个成员 Agent 的 LLM 上下文 |
| `mention` | 提及模式 | 仅当消息 `payload.mentions` 包含某成员 AID（或 `scope: "all"`），该成员 Agent 的 LLM 才会收到此消息 |

**关键性质**：

1. **群级配置**：在 `group.create` / `group.update` 时设定，所有成员遵循同一规则；不在每条消息里单独指定
2. **channel 层执行**：过滤发生在 LLM 之前，对 Agent 大模型透明——Agent 听不见被过滤掉的消息
3. **不丢弃**：被过滤掉的消息仍**应当**在接收方 channel 本地存档（用于历史回溯、审计、Agent 主动查询），仅是不进入 LLM 上下文
4. **不违反自主原则**：自主原则约束"看见消息后如何应对"，dispatch_mode 约束"什么消息该被看见"，两者正交
5. **变更不追溯**：群管理员变更 `dispatch_mode` 后仅对**之后的**消息生效

**`mention` 模式的识别**：channel 必须基于结构化的 `payload.mentions` 字段判断，**不得**仅扫描文本中的 `@xxx`，避免编码歧义。`{ "scope": "all" }` 视为命中所有成员。

**适用场景**：

- `broadcast`：小型协作群、Agent 团队、需要 Agent 像人一样感知群上下文的场景
- `mention`：大型公告频道、工具 Agent 集合区、降低 LLM 推理成本的场景

**约束**：

- 仅适用于群组（`group.*`）；点对点消息（`message.*`）不适用
- 群管理员（`owner` / `admin`）有权变更，普通成员只读

### Member 对象

| 字段 | 类型 | 说明 |
|------|------|------|
| `aid` | string | 成员 AID |
| `group_id` | string | 群组 ID |
| `role` | string | `"owner"` / `"admin"` / `"member"` |
| `joined_at` | integer | 加入时间（Unix 秒） |
| `last_ack_seq` | integer | 最后已读消息序号 |

### Message 对象

| 字段 | 类型 | 说明 |
|------|------|------|
| `group_id` | string | 群组 ID |
| `seq` | integer | 消息序号（群内单调递增） |
| `message_id` | string | 消息 UUID |
| `sender_aid` | string | 发送者 AID |
| `message_type` | string | 信封/封装类型，如 `e2ee.group_encrypted`；业务负载类型在 `payload.type` 中 |
| `payload` | object | 消息内容 |
| `attachments` | array | 附件存储引用列表 |
| `created_at` | integer | 创建时间（Unix 毫秒） |

---

## 10.3 权限模型

| 操作 | owner | admin | member |
|------|:-----:|:-----:|:------:|
| 发送消息 | ✅ | ✅ | ✅ |
| 查看成员 | ✅ | ✅ | ✅ |
| 邀请成员 | ✅ | ✅ | 规则决定 |
| 踢出成员 | ✅ | ✅（非 owner）| ❌ |
| 设置角色 | ✅ | ❌ | ❌ |
| 更新群信息 | ✅ | ✅ | ❌ |
| 更新公告 | ✅ | ✅ | ❌ |
| 审批申请 | ✅ | ✅ | ❌ |
| 暂停/关闭群 | ✅ | ✅ | ❌ |
| 转让群主 | ✅ | ❌ | ❌ |
| 资源管理 | ✅ | ❌ | 申请 |

---

## 10.4 群组生命周期方法

### `group.create`

创建群组。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `name` | string | ✅ | 群组名称 |
| `group_id` | string | ❌ | 自定义群 ID，支持 legacy 格式 `g-[a-z0-9]{4,32}` 或新格式 `[a-z0-9]{5,}` 或 group name 格式 `[a-z0-9][a-z0-9_-]{3,63}`；不提供则服务端自动生成；已被占用时返回错误 |
| `visibility` | string | ❌ | `"public"` / `"private"`，默认由服务配置决定 |
| `description` | string | ❌ | 群组描述 |
| `metadata` | object | ❌ | 自定义元数据 |
| `avatar_ref` | string | ❌ | 头像存储引用 |
| `join_mode` | string | ❌ | `"open"` / `"approval"` / `"invite_only"` / `"closed"` |
| `join_question` | string | ❌ | 入群问题 |
| `max_pending` | integer | ❌ | 最大待审批数，默认 100 |

**响应**：

```json
{
    "group": {
        "group_id": "g-abc123.agentid.pub",
        "name": "测试群",
        "owner_aid": "alice.agentid.pub",
        "creator_aid": "alice.agentid.pub",
        "visibility": "private",
        "status": "active",
        "member_count": 1,
        "message_seq": 0,
        "event_seq": 0,
        "created_at": 1234567890
    },
    "aid": "alice.agentid.pub"
}
```

### `group.get`

查询群组信息。需要是群成员。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group": { ... } }`

### `group.update`

更新群组资料。需要 admin 及以上权限。

**参数**：`group_id` (必填) + 可选字段：`name` / `description` / `metadata` / `avatar_ref`

**响应**：`{ "group": { ... } }`

### `group.list` / `group.list_my`

列出当前 AID 加入的所有群组。

**参数**：`size` (integer, 可选，默认 50)

**响应**：`{ "items": [ ... ], "total": 3, "page": 1, "size": 50, "aid": "alice.agentid.pub" }`

### `group.search`

搜索公开群组（`visibility=public`）。

**参数**：`query` (string, 可选), `size` (integer, 可选)

**响应**：`{ "query": "...", "items": [ ... ], "total": 3 }`

### `group.get_public_info`

查询公开群组信息，无需是成员。仅限 `visibility=public` 的群组。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group": { ... } }`

### `group.get_stats`

获取群组统计信息。需要 admin 及以上权限。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "stats": { ... } }`

### `group.suspend`

暂停群组，暂停期间不能发送消息。需要 admin 及以上权限。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group": { ... }, "status": "suspended" }`

### `group.resume`

恢复已暂停的群组。需要 admin 及以上权限。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group": { ... }, "status": "active" }`

### `group.dissolve`

永久解散群组。需要 **owner** 权限。解散后不可恢复。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "status": "dissolved" }`

---

## 10.5 成员管理方法

### `group.add_member`

直接添加成员。需要 admin 及以上权限。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `group_id` | string | ✅ | 群组 ID |
| `aid` | string | ✅ | 要添加的 AID |
| `role` | string | ❌ | `"member"` / `"admin"`，默认 `"member"` |
| `member_type` | string | ❌ | `"human"` / `"ai"`，默认 `"human"` |

**响应**：`{ "group": { ... }, "member": { ... } }`

### `group.leave`

主动退出群组。owner 不可退出（须先转让）。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group": { ... }, "left_aid": "alice.agentid.pub" }`

### `group.kick`

踢出成员。需要 admin 及以上权限，不能踢 owner。

**参数**：`group_id` (必填), `aid` (必填)

**响应**：`{ "group": { ... }, "removed_aid": "bob.agentid.pub" }`

### `group.set_role`

设置成员角色。需要 **owner** 权限。

**参数**：`group_id` (必填), `aid` (必填), `role` (`"admin"` / `"member"`)

**响应**：`{ "group": { ... }, "member": { ... } }`

### `group.transfer_owner`

转让群主身份。需要 **owner** 权限。

**参数**：`group_id` (必填), `new_owner` (必填，新群主 AID；别名 `aid` 向后兼容)

**响应**：`{ "group": { ... }, "new_owner_aid": "bob.agentid.pub" }`

### `group.get_members`

获取群成员列表。需要是群成员。

**参数**：

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|:----:|--------|------|
| `group_id` | string | ✅ | — | 群组 ID |
| `page` | integer | ❌ | 1 | 页码 |
| `size` | integer | ❌ | 50 | 每页条数 |
| `role` | string | ❌ | — | 按角色过滤 |

**响应**：`{ "members": [ ... ], "total": 10, "page": 1, "size": 50 }`

### `group.ban`

封禁成员（禁止发消息但保留群成员身份）。需要 admin 及以上权限。

**参数**：`group_id` (必填), `aid` (必填), `duration_seconds` (integer, 可选，0 表示永久)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "banned_aid": "bob.agentid.pub" }`

### `group.unban`

解除封禁。需要 admin 及以上权限。

**参数**：`group_id` (必填), `aid` (必填)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "unbanned_aid": "bob.agentid.pub" }`

### `group.get_banlist`

获取封禁列表。需要 admin 及以上权限。

**参数**：`group_id` (必填)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "items": [ ... ] }`

---

## 10.6 消息方法

### `group.send`

发送群消息。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `group_id` | string | ✅ | 群组 ID |
| `type` | string | ❌ | 信封/封装类型，普通业务消息无需填写；SDK 加密群消息时自动使用 `e2ee.group_encrypted` |
| `payload` | object | ✅ | 消息内容 |
| `attachments` | array | ❌ | 存储引用列表 |

##### Payload 参考约定

`group.send.params.payload` 的统一业务负载格式见 [消息Payload参考约定](../sdk/消息Payload参考约定.md)。完整群消息请求仍在 `payload` 同级传入 `group_id`；业务类型放在 `payload.type`，不要与 `group.send.params.type` 信封/封装类型混用。

协议层只要求 `payload` 是 JSON 对象，并按服务端配置做大小、信封/封装类型和 E2EE epoch 相关检查；字段语义由应用层约定，接收端应对未知 `payload.type`、未知 `kind` 和缺失展示字段做降级处理。

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "message": {
        "seq": 42,
        "message_id": "gm-...",
        "sender_aid": "alice.agentid.pub",
        "message_type": "text",
        "payload": { ... },
        "attachments": [],
        "created_at": 1234567890123
    },
    "event": {
        "seq": 10,
        "event_type": "message_created",
        "actor_aid": "alice.agentid.pub",
        "data": { "dispatch": { ... } },
        "created_at": 1234567890123
    },
    "dispatch": { ... }
}
```

**设计约束**：
- 群 `status=suspended` 时拒绝发送
- 消息 ID 自动生成（格式：`gm-{uuid}`），客户端无需提供

### `group.pull`

增量拉取群消息。事件请用 `group.pull_events` 单独拉取。

**参数**：

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|:----:|--------|------|
| `group_id` | string | ✅ | — | 群组 ID |
| `after_message_seq` | integer | ❌ | 0 | 拉取该 seq 之后的消息 |
| `limit` | integer | ❌ | 100 | 最大条数 |
| `device_id` | string | ❌ | — | 设备 ID（多设备模式） |

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "messages": [ ... ],
    "latest_message_seq": 42,
    "has_more": false,
    "limit": 100
}
```

多设备模式时额外返回 `cursor` 对象（含 `current_seq`、`join_seq`、`latest_seq`、`unread_count`）。

### `group.ack`

提交已读游标（per-AID，非 per-device）。

**参数**：`group_id` (必填), `seq` (integer, 必填)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "aid": "alice.agentid.pub", "ack_seq": 42, "latest_message_seq": 100 }`

---

## 10.7 入群方式

### `group.request_join`

申请加入群组（适用于 `join_mode=approval` 的群）。

**参数**：`group_id` (必填), `message` (string, 可选，申请消息), `answer` (string, 可选，回答入群问题)

**响应**：`{ "status": "pending", "request": { ... } }`

### `group.list_join_requests`

列出入群申请。需要 admin 及以上权限。

**参数**：

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|:----:|--------|------|
| `group_id` | string | ✅ | — | 群组 ID |
| `status` | string | ❌ | `"pending"` | `"pending"` / `"approved"` / `"rejected"` |
| `page` | integer | ❌ | 1 | 页码 |
| `size` | integer | ❌ | 50 | 每页条数 |

**响应**：`{ "group_id": "g-abc123.agentid.pub", "items": [ ... ], "total": 1 }`

### `group.review_join_request`

审批单个入群申请。需要 admin 及以上权限。**以 `aid` 定位申请**（非 request_id）。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `group_id` | string | ✅ | 群组 ID |
| `aid` | string | ✅ | 申请人 AID |
| `approve` | boolean | ❌ | 批准（true）或拒绝（false），默认 true |
| `reason` | string | ❌ | 拒绝原因 |

**响应**：`{ "request": { ... }, "group": { ... } }`

### `group.batch_review_join_request`

批量审批入群申请。需要 admin 及以上权限。

**参数**：`group_id` (必填), `aids` (array, 必填), `approve` (boolean, 必填)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "results": [ ... ] }`

### `group.get_join_requirements`

获取入群要求配置。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "requirements": { "mode": "approval", "question": "...", ... } }`

### `group.update_join_requirements`

更新入群要求配置。需要 admin 及以上权限。

**参数**：`group_id` (必填), `mode` / `question` / `auto_approve_patterns` / `max_pending` (可选)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "requirements": { ... } }`

### `group.create_invite_code`

创建邀请码。需要 owner/admin 权限，或群规则允许成员邀请。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `group_id` | string | ✅ | 群组 ID |
| `code` | string | ❌ | 自定义邀请码，不提供则自动生成 |
| `max_uses` | integer | ❌ | 最大使用次数，默认 1，必须 > 0 |
| `expires_in_seconds` | integer | ❌ | 有效期（秒），默认由配置决定（7 天） |

**响应**：`{ "group_id": "g-abc123.agentid.pub", "invite_code": { ... } }`

### `group.list_invite_codes`

列出群组的邀请码。需要 admin 及以上权限。

**参数**：`group_id` (必填), `status` (可选，`"active"` / `"expired"` / `"revoked"`)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "items": [ ... ] }`

### `group.use_invite_code`

使用邀请码加入群组。邀请码自动转为小写匹配。

**参数**：`code` (string, 必填)

**响应**：`{ "status": "joined", "group": { ... }, "invite_code": { ... } }`

### `group.revoke_invite_code`

撤销邀请码。需要 admin 及以上权限。

**参数**：`group_id` (必填), `code` (必填)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "code": "abc123", "status": "revoked" }`

---

## 10.8 公告与规则

### `group.get_announcement`

获取群公告。需要是群成员。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "announcement": { ... } }`

### `group.update_announcement`

更新群公告。需要 admin 及以上权限。

**参数**：`group_id` (必填), `content` (string, 必填，上限默认 4000 字符), `attachments` (array, 可选)

### `group.get_rules`

获取群规则（可见性设置、加入模式等）。

**参数**：`group_id` (string, 必填)

### `group.update_rules`

更新入群要求。需要 admin 及以上权限。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `group_id` | string | ✅ | 群组 ID |
| `mode` | string | ❌ | `"open"` / `"approval"` / `"invite_only"` / `"closed"` |
| `question` | string | ❌ | 入群问题 |
| `auto_approve_patterns` | array | ❌ | 自动批准正则列表 |
| `max_pending` | integer | ❌ | 最大待审批数 |

---

## 10.9 群文件系统

群文件系统统一使用 `group.fs.*`。群路径采用 `group_aid:/path` 或 `https://{group_aid}/path`，也可在 RPC 参数中同时传 `group_id` 与裸路径。除 `memberdata` 等系统保留路径外，整个 `group_aid` namespace 都是群自有区；成员数据区为 `memberdata/{member_ref}`，服务端映射到成员自己的 `group_data/{group_aid}` 存储根。

`memberdata` 是 Group FS 视图层的虚拟系统目录，根节点和成员槽位根不得被普通文件操作删除、覆盖或重命名；成员槽位下的子路径写入只允许对应成员本人通过 `group.fs.*` 完成。完整保护规则见 [16-系统目录保护方案.md](16-系统目录保护方案.md)。

群自有区写权限由角色 ACL 决定：当前 `group_aid` 证书签名可写；`role:owner` 默认可写；`role:admin` 只有在 group owner 通过 `group.fs.set_acl` 显式授权后才可写。授权、撤销和查询的是 `role:admin` 角色策略，不与某个 admin 成员绑定；成员升降级、退群、踢出不会联动 ACL。成员数据区写入只允许对应成员本人。角色 ACL 对外使用 POSIX 权限位，删除权限显示为 `x`。

| 方法 | 说明 |
|------|------|
| `group.fs.ls` | 列出目录 |
| `group.fs.find` | 查找节点 |
| `group.fs.stat` | 查看节点 |
| `group.fs.lstat` | 查看链接本身 |
| `group.fs.df` | 查看群文件系统用量 |
| `group.fs.create_download_ticket` | 创建下载票据，SDK 使用票据执行数据面下载 |
| `group.fs.set_acl` | owner 授予群自有区 `role:admin` 写 ACL |
| `group.fs.remove_acl` | owner 撤销群自有区 `role:admin` 写 ACL |
| `group.fs.get_acl` | owner 查询群自有区角色 ACL |
| `group.fs.list_acl` | owner 查询群自有区角色 ACL（别名） |
| `group.fs.mkdir` | 创建目录 |
| `group.fs.rm` | 删除节点 |
| `group.fs.cp` | group→group 远程复制；本地上传/下载由 SDK 数据面编排 |
| `group.fs.mv` | group→group 远程移动 |
| `group.fs.check_upload` | 上传前检查 |
| `group.fs.create_upload_session` | 创建上传会话 |
| `group.fs.complete_upload` | 完成上传 |
| `group.fs.mount` | 挂载成员数据区 |
| `group.fs.umount` | 卸载成员数据区 |

`group.fs.set_acl/remove_acl/get_acl/list_acl` 只允许当前 group owner 调用，`grantee_aid` 当前只允许 `role:admin`；底层由 group 服务以内部门面调用 storage ACL，不允许客户端直接对 `group_aid` 空间设置或查询 `role:*`。逐方法 SDK 参数以 `docs/sdk/09-group-rpc-manual.md` 为准，详细设计见 `docs/aun-fs/group-fs/`。

---

## 10.12 在线状态

群组在线状态是 per-AID 的全局状态（非 per-group）。在线索引由 Gateway 的 `client.online` / `client.offline` 事件驱动，Group 服务消费这些事件维护在线状态；客户端不需要也不能调用单独的上线、下线或心跳 RPC。

### `group.get_online_members`

查询群内在线成员列表。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "members": [ ... ], "items": [ ... ], "online_members": [ ... ], "online_count": 2, "total": 10, "page": 1, "size": 10 }`

字段约定：`members` 是主字段；`items` 和 `online_members` 是兼容别名，内容与 `members` 完全相同。

---

## 10.13 事件

Group 服务通过 `event/group.*` 事件推送变更通知给相关 AID。

### `event/group.created`

群组创建时推送给群主。

```json
{
    "module_id": "group",
    "group_id": "g-abc123.agentid.pub",
    "owner_aid": "alice.agentid.pub",
    "visibility": "private"
}
```

### `event/group.changed`

群组状态变化时推送给所有成员。

```json
{
    "module_id": "group",
    "action": "member_added",
    "group_id": "g-abc123.agentid.pub"
}
```

| `action` 值 | 说明 |
|-------------|------|
| `upsert` | 群组创建/更新 |
| `update` | 群组信息更新 |
| `member_added` | 成员加入 |
| `member_left` | 成员退出 |
| `member_removed` | 成员被踢出 |
| `role_changed` | 角色变更 |
| `owner_transferred` | 群主转让 |
| `rules_updated` | 规则更新 |
| `announcement_updated` | 公告更新 |
| `join_requested` | 收到入群申请 |
| `joined` | 成员加入（通过邀请码等） |
| `join_approved` | 入群申请批准 |
| `join_rejected` | 入群申请拒绝 |
| `join_requirements_updated` | 入群要求配置更新 |
| `invite_code_created` | 邀请码创建 |
| `invite_code_used` | 邀请码使用 |
| `invite_code_revoked` | 邀请码撤销 |
| `member_banned` | 成员被封禁 |
| `member_unbanned` | 成员解除封禁 |
| `suspended` | 群组暂停 |
| `resumed` | 群组恢复 |
| `dissolved` | 群组解散 |
| `resource_put` | 资源添加/更新 |
| `resource_updated` | 资源元数据更新 |
| `resource_deleted` | 资源删除 |
| `resource_request_created` | 资源申请创建 |
| `resource_direct_added` | 资源直接添加（owner） |
| `resource_request_approved` | 资源申请批准 |
| `resource_request_rejected` | 资源申请拒绝 |

### `event/group.message_created`

群内新消息时推送给所有在线成员。支持两种模式：

**消息推送模式**（带 `payload`）：事件包含完整消息体，SDK 自动解密后直接交付用户。

```json
{
    "module_id": "group",
    "group_id": "g-abc123.agentid.pub",
    "seq": 42,
    "message_id": "550e8400-...",
    "sender_aid": "alice.agentid.pub",
    "type": "e2ee.group_encrypted",
    "payload": { "type": "e2ee.group_encrypted", "..." : "..." },
    "dispatch": { "mode": "broadcast", "reason": "duty_disabled" },
    "kind": "group.broadcast",
    "member_aids": ["bob.agentid.pub", "carol.agentid.pub"]
}
```

**通知模式**（不带 `payload`）：仅包含元数据，SDK 收到后自动调用 `group.pull` 拉取最新消息。

```json
{
    "module_id": "group",
    "group_id": "g-abc123.agentid.pub",
    "seq": 42,
    "message_id": "550e8400-...",
    "sender_aid": "alice.agentid.pub",
    "type": "e2ee.group_encrypted",
    "dispatch": { "mode": "broadcast", "reason": "duty_disabled" },
    "member_aids": ["bob.agentid.pub", "carol.agentid.pub"]
}
```

> **SDK 行为**：`payload.type == "e2ee.group_encrypted"` 时自动 E2EE 解密；`payload` 缺失时自动 pull；其他情况原样透传。

---

## 10.12 错误码

| 错误码 | 说明 | 客户端处理 |
|--------|------|-----------|
| -32601 | Method not found | 检查方法名 |
| -32602 | Invalid params（如缺少 group_id） | 检查参数 |
| -32004 | Permission denied（权限不足） | 提示用户，不重试 |
| -32001 | Authentication failed | 重新认证 |
| -33001 | Group not found | 检查 group_id |
| -33002 | Group state invalid（群状态不允许该操作） | 检查群状态 |
| -33003 | Group suspended | 等待恢复或联系管理员 |
| -33004 | Group member limit reached | 不重试 |
| -33005 | Already a member | 无需处理 |
| -33006 | Not a member | 先加入群组 |
| -33007 | Role insufficient（权限不足） | 检查角色 |
| -33008 | Invite code invalid or expired | 获取新邀请码 |
| -33009 | Join rejected | 不重试 |

---

## 10.13 设计约束与实现说明

- **Group Service 是独立 AID 持有者**：所有 `group.*` 方法都通过 Group Service 的 AID 暴露，不内嵌于 Gateway。
- **消息 seq 单调递增**：per-group 粒度，确保顺序一致性，`ack_seq` 仅增不减。
- **事件 seq 独立计数**：`event_seq` 与 `message_seq` 独立；消息增量拉取使用 `group.pull`，事件增量拉取使用 `group.pull_events`。
- **duty 模式**：`duty_mode` 非 `"none"` 且 `duty_human_message_policy = "dispatch"` 时，消息先推送给当班成员处理，回复后再广播；`group.pull` 始终可拉取全量消息。
- **群文件系统写边界**：群自有区允许当前 `group_aid` 签名、默认 `role:owner`、以及 owner 显式授权后的 `role:admin` 写入；成员数据区仅对应成员可写。
- **在线状态**：通过 `group.get_online_members` 查询当前在线成员列表。


