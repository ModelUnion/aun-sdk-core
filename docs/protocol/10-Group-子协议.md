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
| `member_count` | integer | 成员数量 |
| `message_seq` | integer | 最新消息序号 |
| `event_seq` | integer | 最新事件序号 |
| `created_at` | integer | 创建时间（Unix 秒） |

### Group ID 格式与规范化

`group_id` 是群组的全网唯一标识，前缀 `g-` 为 Group 保留前缀。普通 AID 的本地名称不得以 `g-` 开头，避免与群 ID 混淆。短形式必须以 `g-` 开头，总长度 6 到 16 字符；`g-` 后面的 slug 为 4 到 14 位，只能使用小写字母和数字。

服务端必须接受以下三种输入形式，并在内部统一为 canonical group_id：

| 输入形式 | 用途 | canonical 结果 |
|----------|------|----------------|
| `g-{slug}` | 本地域内简写别名 | 若本域 issuer 为 `issuer-domain`，规范化为 `g-{slug}.issuer-domain` |
| `g-{slug}@issuer-domain` | 跨域传播兼容形式 | 规范化为 `g-{slug}.issuer-domain` |
| `g-{slug}.issuer-domain` | canonical 形式 | 保持为 `g-{slug}.issuer-domain` |

规范化规则：

- `group_id` 比较、数据库存储、成员归属、权限校验、E2EE AAD / 签名输入均必须使用 canonical group_id。
- 输入必须先 trim 并转换为小写；`@issuer-domain` 形式仅作为兼容输入，进入内部前必须转换为 `.issuer-domain`。
- 本域内客户端可以提交 `g-{slug}` 简写；服务端按本域 `AUN_ISSUER_DOMAIN` 解析为 canonical group_id。没有本域 issuer 配置时，简写保持为 `g-{slug}`。
- 跨域消息、邀请传播、日志和协议响应应使用 canonical group_id，避免远端误把短 ID 当成本域群。
- `group.create` 可以指定 `group_id`；指定时必须满足上述格式且未被占用，被占用时返回错误。未指定时由服务端自动分配。
- 自动生成的群 ID 使用 `g-` 加随机小写十六进制短 slug，服务端必须通过唯一约束或等效机制保证 canonical group_id 唯一；发现碰撞时重新生成。
- 在 `group.{issuer-domain}` 这类已携带 issuer 的公开 HTTP 主机下，生成的群链接 path 应使用本域简写，例如 `https://group.issuer-domain/g-abc123` 或 `https://group.issuer-domain/g-abc123/invite/ic-xxx`。

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
| `group_id` | string | ❌ | 自定义群 ID，短形式必须以 `g-` 开头且总长度 6 到 16 字符；不提供则服务端自动生成；已被占用时返回错误 |
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

`payload` 是群消息的应用层内容，Group 服务只做 JSON 可序列化、大小、信封/封装类型和 E2EE epoch 相关检查，其他字段由客户端约定。本节参考 wxauto `Message` 类的常见消息形态（文本、引用、语音、图片、视频、文件、位置、链接、表情、合并转发、名片、笔记等），并补充 AUN Agent 场景常用的状态、结构化数据、投票和工具调用类型。

示例展示的是 `group.send.params.payload` 片段；完整群请求仍需要在同级传入 `group_id`。文本、图片、文件等业务消息类型只能放在 `payload.type`；`group.send.params.type` 是信封/封装类型，例如 SDK 加密群消息时自动填充的 `e2ee.group_encrypted`，不表示业务负载类型。

###### 信封字段不进入 payload

`payload` 只描述业务内容，不重复群消息信封已经提供的字段。

| 字段 | 所在位置 | 说明 |
|------|----------|------|
| `group_id` | `group.send.params` 和群消息信封 | 群组 ID |
| `sender_aid` | 服务端生成的群消息信封 | 发送方 AID |
| `message_id` / `seq` / `created_at` | 服务端生成的群消息信封 | 当前群消息 ID、群内序号、创建时间 |
| `message_type` / `type` | 发送参数或消息信封 | 信封/封装类型，如 `e2ee.group_encrypted`；业务负载类型使用 `payload.type` |
| `dispatch` / `duty_state` | `group.send` 响应 | 群消息分发状态 |

###### 公共辅助字段

以下字段可出现在多数 payload 中；如无需要，不必携带。

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `type` | string | 是 | 业务负载类型，如 `text` / `image` / `status` / `event` / `tool_call` |
| `text` | string | 否 | 面向用户展示的正文或摘要 |
| `format` | string | 否 | 文本格式，建议值：`plain` / `markdown` |
| `chat_id` | string | 否 | 应用层会话或场景标识；群组本身仍由外层 `group_id` 标识 |
| `thread_id` | string | 否 | 群内话题、子线程或任务线程 |
| `reply_to` | object | 否 | 回复目标，推荐含 `message_id`、`seq`、`sender_aid` |
| `mentions` | array | 否 | 提及对象数组；单人提及推荐项为 `{aid, display, offset, length}`；全体提及使用 `{scope: "all"}` |
| `entities` | array | 否 | 文本实体，如链接、代码片段、时间范围 |
| `attachments` | array | 否 | 附件引用列表，结构见“附件引用” |
| `client_context` | object | 否 | 客户端自定义上下文，如窗口、任务、草稿来源 |

字段名建议使用 snake_case，如 `chat_id`、`thread_id`；已有应用若使用 `chatId` 等命名，可在自己的应用层约定中保持一致。

`chat_id`、`thread_id`、`reply_to`、`mentions`、`entities`、`client_context` 这类字段无法可靠放入群消息信封：它们属于应用上下文，不参与群路由或权限判断，但又常常需要端到端加密保护。因此这些字段应保留在 `payload` 内，由 SDK 随群消息内容一起加密。

###### `mentions`：提及语义

`payload.mentions` 是应用层提及列表，只用于展示、高亮或通知提示，不参与群路由、权限判断或 E2EE 收件人集合计算。提及必须放在 `payload` 内并随业务内容一起加密；不要放在 `group.send` 外层信封。

- 单人成员提及使用 `{ "aid": "bob.agentid.pub", "display": "Bob", "offset": 0, "length": 3 }`。`offset` / `length` 描述 `payload.text` 中对应展示文本的字符范围；没有可靠范围时可省略。
- 全体提及使用规范形式 `{ "scope": "all" }`，含义为 `@所有人`。需要 UI 高亮时可带 `display` / `offset` / `length`，例如 `{ "scope": "all", "display": "@所有人", "offset": 0, "length": 4 }`。
- `all` 不是 AID，不要写成 `{ "aid": "all" }`。它只覆盖当前群成员，不扩大到非成员或历史成员，也不改变服务端分发模式。
- 若同时出现 `{ "scope": "all" }` 和具体 `{ "aid": ... }`，客户端应按全体提及处理；具体成员项可继续用于局部高亮。
- 不理解 `mentions` 的客户端必须忽略该字段，不影响消息展示。

###### `text`：文本消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `text` | string | 是 | 文本内容 |
| `format` | string | 否 | `plain` / `markdown`，默认 `plain` |
| `lang` | string | 否 | BCP 47 语言标签，如 `zh-CN` |
| `mentions` | array | 否 | 群成员或全体提及列表；全体提及使用 `{scope: "all"}` |
| `entities` | array | 否 | 文本实体范围 |

```json
{
  "payload": {
    "type": "e2ee.group_encrypted",
    "text": "@所有人 明天 10:00 开会",
    "format": "plain",
    "mentions": [{"scope": "all", "display": "@所有人", "offset": 0, "length": 4}]
  }
}
```

###### `quote`：引用消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `text` | string | 是 | 本次回复内容 |
| `quote` | object | 是 | 被引用消息摘要，避免复制完整敏感原文 |
| `quote.message_id` | string | 否 | 被引用群消息 ID |
| `quote.seq` | integer | 否 | 被引用群消息序号 |
| `quote.text` | string | 否 | 被引用内容摘要 |
| `quote.sender_display` | string | 否 | 展示用发送者名称 |

```json
{
  "payload": {
    "type": "quote",
    "text": "我同意这个方案",
    "quote": {
      "message_id": "gm-prev",
      "seq": 12,
      "text": "是否采用方案 A？",
      "sender_display": "Bob"
    }
  }
}
```

###### `voice`：语音消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `attachments` | array | 是 | 语音文件引用，通常为单项 |
| `duration_ms` | integer | 否 | 语音时长 |
| `transcript` | string | 否 | 语音转文字结果 |
| `codec` | string | 否 | 编码格式，如 `opus` / `aac` |

```json
{
  "payload": {
    "type": "voice",
    "duration_ms": 8200,
    "transcript": "我稍后处理这个问题",
    "attachments": [{
      "url": "aun://storage/default/groups/g-abc123.agentid.pub/voice/gm-1.opus",
      "filename": "gm-1.opus",
      "content_type": "audio/ogg"
    }]
  }
}
```

###### `image`：图片消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `attachments` | array | 是 | 图片对象引用，可多张 |
| `alt` | string | 否 | 无障碍或降级展示文本 |
| `width` | integer | 否 | 图片宽度，像素 |
| `height` | integer | 否 | 图片高度，像素 |
| `text` | string | 否 | 图片说明 |

```json
{
  "payload": {
    "type": "image",
    "text": "新版流程图",
    "alt": "AUN 群消息投递流程图",
    "width": 1280,
    "height": 720,
    "attachments": [{
      "url": "aun://storage/default/groups/g-abc123.agentid.pub/images/flow.png",
      "filename": "flow.png",
      "content_type": "image/png"
    }]
  }
}
```

###### `video`：视频消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `attachments` | array | 是 | 视频对象引用，通常为单项 |
| `duration_ms` | integer | 否 | 视频时长 |
| `thumbnail` | object | 否 | 封面图引用，结构同附件引用 |
| `width` / `height` | integer | 否 | 视频尺寸，像素 |
| `text` | string | 否 | 视频说明 |

```json
{
  "payload": {
    "type": "video",
    "text": "演示录屏",
    "duration_ms": 30500,
    "thumbnail": {
      "url": "aun://storage/default/groups/g-abc123.agentid.pub/videos/demo-cover.jpg",
      "content_type": "image/jpeg"
    },
    "attachments": [{
      "url": "aun://storage/default/groups/g-abc123.agentid.pub/videos/demo.mp4",
      "filename": "demo.mp4",
      "content_type": "video/mp4"
    }]
  }
}
```

###### `file`：文件消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `attachments` | array | 是 | 文件引用，可多项 |
| `text` | string | 否 | 文件说明 |
| `expires_at` | integer | 否 | 应用层建议过期时间，毫秒时间戳 |

```json
{
  "payload": {
    "type": "file",
    "text": "请查收附件",
    "attachments": [{
      "url": "aun://storage/default/groups/g-abc123.agentid.pub/docs/report.pdf",
      "filename": "report.pdf",
      "content_type": "application/pdf",
      "size_bytes": 245678,
      "sha256": "3d8e577b..."
    }]
  }
}
```

###### `location`：位置消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `name` | string | 否 | 地点名称 |
| `address` | string | 否 | 地址文本 |
| `latitude` | number | 是 | 纬度，WGS84 |
| `longitude` | number | 是 | 经度，WGS84 |
| `precision_m` | number | 否 | 精度，单位米 |
| `map_url` | string | 否 | 地图链接 |

```json
{
  "payload": {
    "type": "location",
    "name": "上海虹桥站",
    "address": "上海市闵行区申贵路 1500 号",
    "latitude": 31.1944,
    "longitude": 121.3189,
    "precision_m": 30,
    "map_url": "https://maps.example.com/?q=31.1944,121.3189"
  }
}
```

###### `link`：链接消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `url` | string | 是 | 目标链接 |
| `title` | string | 否 | 卡片标题 |
| `description` | string | 否 | 卡片摘要 |
| `thumbnail` | object | 否 | 预览图引用 |

```json
{
  "payload": {
    "type": "link",
    "url": "https://example.com/aun/design",
    "title": "AUN 设计说明",
    "description": "消息、群组和 E2EE 的设计摘要",
    "thumbnail": {
      "url": "aun://storage/default/previews/aun-design.png",
      "content_type": "image/png"
    }
  }
}
```

###### `emotion`：表情消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `emoji_id` | string | 否 | 表情或贴纸 ID |
| `package_id` | string | 否 | 表情包 ID |
| `alt` | string | 否 | 降级展示文本 |
| `attachments` | array | 否 | 自定义表情文件引用 |

```json
{
  "payload": {
    "type": "emotion",
    "emoji_id": "thumbs_up",
    "alt": "[点赞]"
  }
}
```

###### `merge`：合并转发消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `title` | string | 是 | 合并转发标题 |
| `summary` | string | 否 | 摘要文本 |
| `items` | array | 否 | 少量内联消息摘要；大量内容应走附件 |
| `attachments` | array | 否 | 完整合并记录的对象引用 |

```json
{
  "payload": {
    "type": "merge",
    "title": "项目讨论记录",
    "summary": "包含 3 条关键消息",
    "items": [
      {"sender_display": "Alice", "text": "先确认接口"},
      {"sender_display": "Bob", "text": "我来补测试"}
    ]
  }
}
```

###### `personal_card`：名片消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `aid` | string | 否 | AUN AID；没有 AID 时可只作为展示卡片 |
| `display_name` | string | 是 | 展示名称 |
| `avatar` | object | 否 | 头像引用 |
| `profile_url` | string | 否 | 资料页链接 |
| `note` | string | 否 | 推荐语或备注 |

```json
{
  "payload": {
    "type": "personal_card",
    "aid": "carol.agentid.pub",
    "display_name": "Carol",
    "profile_url": "https://agentid.pub/carol",
    "note": "负责存储服务"
  }
}
```

###### `note`：笔记消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `title` | string | 否 | 笔记标题 |
| `text` | string | 是 | 笔记正文或摘要 |
| `format` | string | 否 | `plain` / `markdown` |
| `url` | string | 否 | 外部笔记链接 |
| `attachments` | array | 否 | 笔记内附件引用 |

```json
{
  "payload": {
    "type": "note",
    "title": "联调记录",
    "text": "1. 修复重连\n2. 补充 group.send 测试",
    "format": "markdown"
  }
}
```

###### `status`：状态或事件消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `state` | string | 是 | 当前状态，如 `online` / `busy` / `typing` / `processing` / `completed` / `error` |
| `event` | string | 否 | 触发状态变化的事件名 |
| `text` | string | 否 | 展示文案 |
| `data` | object | 否 | 事件或状态的结构化数据 |
| `progress` | number | 否 | 进度，范围 0 到 1 |
| `expires_at` | integer | 否 | 状态过期时间，毫秒时间戳 |

```json
{
  "payload": {
    "type": "status",
    "state": "processing",
    "event": "deployment.started",
    "text": "正在发布新版 SDK",
    "progress": 0.4,
    "data": {"task_id": "deploy-123"}
  }
}
```

###### `event`：事件消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `type` | string | 是 | 固定为 `event` |
| `event` | string | 是 | 应用层事件名，如 `deployment.completed` |
| `data` | object | 否 | 事件数据 |
| `text` | string | 否 | 降级展示文案 |
| `severity` | string | 否 | 级别，如 `info` / `warning` / `error` |
| `occurred_at` | integer | 否 | 事件发生时间，毫秒时间戳 |

```json
{
  "payload": {
    "type": "event",
    "event": "deployment.completed",
    "text": "新版 SDK 已发布",
    "severity": "info",
    "data": {"task_id": "deploy-123", "version": "0.2.7"}
  }
}
```

###### `json`：结构化数据消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `kind` | string | 是 | 业务子类型，建议使用反向域名或产品前缀 |
| `data` | object | 是 | 结构化数据 |
| `schema` | string | 否 | JSON Schema URL 或版本标识 |
| `fallback_text` | string | 否 | 接收方不识别时的降级展示文本 |

```json
{
  "payload": {
    "type": "json",
    "kind": "pub.agentid.workflow.plan",
    "schema": "https://agentid.pub/schemas/workflow-plan-v1.json",
    "fallback_text": "收到一个工作流计划",
    "data": {
      "steps": ["collect", "analyze", "report"]
    }
  }
}
```

###### `reaction`：消息反应

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `target` | object | 是 | 目标群消息，推荐含 `message_id`、`seq`、`sender_aid` |
| `action` | string | 是 | `add` / `remove` |
| `key` | string | 是 | 反应标识，如 `like` / `done` |
| `text` | string | 否 | 展示文本 |

```json
{
  "payload": {
    "type": "reaction",
    "target": {"message_id": "gm-prev", "seq": 41, "sender_aid": "bob.agentid.pub"},
    "action": "add",
    "key": "done",
    "text": "已处理"
  }
}
```

###### `poll`：投票或表单

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `kind` | string | 是 | 固定为 `poll` 或应用自定义表单类型 |
| `title` | string | 是 | 投票或表单标题 |
| `options` | array | 是 | 选项列表 |
| `multiple` | boolean | 否 | 是否允许多选，默认 `false` |
| `expires_at` | integer | 否 | 截止时间，毫秒时间戳 |

```json
{
  "payload": {
    "type": "json",
    "kind": "poll",
    "title": "下次例会时间",
    "options": [
      {"id": "a", "text": "周一 10:00"},
      {"id": "b", "text": "周二 14:00"}
    ],
    "multiple": false
  }
}
```

###### `tool_call`：工具调用请求

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `call_id` | string | 是 | 调用 ID，用于关联结果 |
| `name` | string | 是 | 工具或能力名称 |
| `arguments` | object | 是 | 调用参数 |
| `timeout_ms` | integer | 否 | 期望超时时间 |
| `meta` | object | 否 | 调用方附加元数据 |

```json
{
  "payload": {
    "type": "tool_call",
    "call_id": "call-001",
    "name": "ci.run",
    "arguments": {"workflow": "sdk-tests"},
    "timeout_ms": 120000
  }
}
```

###### `tool_result`：工具调用结果

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `call_id` | string | 是 | 对应 `tool_call.call_id` |
| `ok` | boolean | 是 | 是否成功 |
| `result` | object | 否 | 成功结果 |
| `error` | object | 否 | 失败信息，推荐含 `code`、`message` |

```json
{
  "payload": {
    "type": "tool_result",
    "call_id": "call-001",
    "ok": true,
    "result": {
      "passed": 128,
      "failed": 0
    }
  }
}
```

###### `custom`：自定义消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `kind` | string | 是 | 自定义类型标识 |
| `data` | object | 是 | 自定义数据 |
| `fallback_text` | string | 否 | 降级展示文本 |

```json
{
  "payload": {
    "type": "custom",
    "kind": "com.example.crm.ticket",
    "fallback_text": "收到一个工单卡片",
    "data": {
      "ticket_id": "T-10086",
      "priority": "high"
    }
  }
}
```

##### 附件引用

推荐把附件引用放入 `payload.attachments`。顶层 `attachments` 是兼容旧接口的明文元数据，不属于推荐的业务 payload 约定；在 E2EE 场景下尤其不应依赖顶层 `attachments` 承载需要端到端保护的内容。

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `owner_aid` | string | 否 | 对象所有者 AID，可作为对象标识补充 |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `object_key` | string | 否 | Storage 对象路径 |
| `url` | string | 否 | 对象 URL；AUN Storage 场景下为上传完成后返回的长期对象引用 |
| `filename` | string | 否 | 原始文件名；缺省时可由 `object_key` 推导 |
| `content_type` | string | 否 | MIME 类型 |
| `size_bytes` | integer | 否 | 文件大小（字节） |
| `sha256` | string | 否 | 内容哈希，用于完整性校验 |
| `thumbnail` | object | 否 | 缩略图引用，结构同附件引用 |

AUN Storage 的 `url` 是长期对象引用，不是最终文件下载地址。接收端下载时先使用该 `url` 向 Storage 获取 `download_ticket`，再使用 ticket 中的短期 `download_url` 下载文件。`owner_aid`、`bucket`、`object_key` 可作为可选对象标识补充，便于没有 `url` 解析能力的客户端或服务端工具定位对象。

**附件引用示例**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "payload": {
      "type": "image",
        "text": "这张图是新版流程",
        "thread_id": "release-2026-04",
        "reply_to": {"message_id": "gm-prev", "seq": 12},
        "mentions": [{"aid": "bob.agentid.pub", "display": "Bob", "offset": 0, "length": 3}],
        "attachments": [{
            "owner_aid": "alice.agentid.pub",
            "bucket": "default",
            "object_key": "images/flow.png",
            "url": "https://storage.agentid.pub/objects/default/images/flow.png",
            "filename": "flow.png",
            "content_type": "image/png"
        }]
    }
}
```


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

## 10.9 资源管理

群资源是分享到群组的文件/链接引用。资源内容本身存储在 `storage.*` 服务，群组只持有引用。

### `group.resources.put`

分享资源到群组。需要 member 及以上权限。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `group_id` | string | ✅ | 群组 ID |
| `resource_path` | string | ✅ | 资源路径 |
| `title` | string | ✅ | 资源标题 |
| `resource_type` | string | ❌ | `"file"` / `"folder"` / `"link"`，默认 `"file"` |
| `storage_ref` | object | ❌ | 存储引用对象 |
| `metadata` | object | ❌ | 自定义元数据 |
| `visibility` | string | ❌ | `"members_only"` / `"public"`，默认 `"members_only"` |
| `tags` | array | ❌ | 标签数组 |

**响应**：`{ "group_id": "g-abc123.agentid.pub", "resource": { ... }, "created": true }`（`created=false` 表示更新已有资源）

### `group.resources.get`

查看资源详情。**参数**：`group_id`, `resource_path`

**响应**：`{ "group_id": "g-abc123.agentid.pub", "resource": { ... } }`

### `group.resources.list`

列出群资源。**参数**：`group_id` (必填), `tag` / `resource_type` / `page` / `size` (可选)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "items": [ ... ], "total": 10 }`

### `group.resources.update`

更新资源元数据。需要 admin 及以上权限。

**参数**：`group_id` (必填), `resource_path` (必填), `title` / `metadata` / `tags` / `visibility` (可选)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "resource": { ... } }`

### `group.resources.delete`

删除资源链接。需要 admin 权限。**参数**：`group_id`, `resource_path`

**响应**：`{ "group_id": "g-abc123.agentid.pub", "resource_path": "/path/to/file" }`

### `group.resources.get_access`

获取资源访问令牌（用于下载）。

**参数**：`group_id`, `resource_path`

**响应**：`{ "resource": { ... }, "access_token": "tk_...", "token_type": "Bearer", "download": { ... } }`

### `group.resources.resolve_access_ticket`

使用访问票据换取下载令牌。

**参数**：`ticket` (string, 必填)

**响应**：`{ "resource": { ... }, "download": { ... } }`

### `group.resources.request_add`

成员申请分享资源（需 owner 审批）。**参数**：同 `group.resources.put`（不需要 `storage_ref`）。

### `group.resources.direct_add`

Owner 直接添加资源（无需审批）。需要 **owner** 权限。

### `group.resources.list_pending`

列出待审批的资源申请。需要 **owner** 权限。

### `group.resources.approve_request`

批准资源申请。需要 **owner** 权限。**参数**：`request_id` (必填), `note` (可选)

### `group.resources.reject_request`

拒绝资源申请。需要 **owner** 权限。**参数**：`request_id` (必填), `note` (可选)

---

## 10.12 在线状态

群组在线状态是 per-AID 的全局状态（非 per-group），注册一次对所有群可见。

### `group.register_online`

注册在线状态。无需 `group_id` 参数，基于当前认证 AID。

**参数**：`session_id` (string, 可选)

**响应**：`{ "aid": "alice.agentid.pub", "online": true, "member": { ... } }`

### `group.unregister_online`

注销在线状态。无参数。

**响应**：`{ "aid": "alice.agentid.pub", "online": false, "removed": true }`

### `group.heartbeat`

刷新在线心跳（防止超时过期）。无需 `group_id`。

**参数**：`session_id` (string, 可选)

### `group.get_online_members`

查询群内在线成员列表。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "online_members": [ ... ] }`

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
- **资源审批**：`group.resources.request_add` 提交申请后需 admin 通过 `group.resources.review_add` 审批；直接添加（owner/admin）使用 `group.resources.direct_add`。
- **在线状态**：通过 `group.get_online_members` 查询当前在线成员列表。

