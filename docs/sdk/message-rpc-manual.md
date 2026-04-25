# 消息 — RPC Manual

## 消息存储模型

| `delivery_mode.mode` | 投递方式 | 存储位置 | 生命周期 | 适用场景 |
|----------------------|----------|---------|---------|---------|
| `queue` | 单实例实时消费 | 内存环形缓冲 | 5 分钟 / 200 条每 AID | Agent 间实时交互、有时效性的请求/响应 |
| `fanout` | 广播到在线实例 | 数据库 | TTL 过期前持久保存（默认 24h，可由服务端配置调整） | 离线送达、历史查询、多实例同步接收 |

P2P `message.*` 的最终投递语义由连接阶段声明的 `delivery_mode` 决定。`group.send` 固定为 fanout，不支持 queue。

临时消息超出时间窗口或条数限制后自动淘汰，`message.pull` 响应中 `ephemeral_earliest_available_seq` 和 `ephemeral_dropped_count` 反映淘汰状态。

---

## 方法索引

| 方法 | 说明 |
|------|------|
| [message.send](#messagesend) | 发送消息 |
| [message.pull](#messagepull) | 增量拉取消息 |
| [message.ack](#messageack) | 确认送达 |
| [message.recall](#messagerecall) | 撤回消息 |
| [message.query_online](#messagequery_online) | 批量查询在线状态 |

## 事件索引

| 事件 | 说明 |
|------|------|
| [event/message.received](#eventmessagereceived) | 收到新消息 |
| [event/message.ack](#eventmessageack) | 消息被确认 |
| [event/message.recalled](#eventmessagerecalled) | 消息被撤回 |

---

## message.send

发送一条 P2P 消息。

### 请求

```json
{
    "jsonrpc": "2.0",
    "method": "message.send",
    "params": {
        "to": "bob.agentid.pub",
        "payload": {"type": "text", "text": "Hello!"},
        "encrypted": false,
        "message_id": "550e8400-e29b-41d4-a716-446655440000",
        "timestamp": 1234567890000
    },
    "id": 1
}
```

### 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `to` | string | 是 | — | 接收方 AID |
| `payload` | object | 是 | — | 消息内容（任意 JSON 对象） |
| `type` | string | 否 | — | 信封/封装类型，普通业务消息无需填写；SDK 加密发送时自动使用 `e2ee.encrypted` |
| `encrypted` | boolean | 否 | `false` | 底层 RPC 的 E2EE 标记。Python SDK 便捷层通常使用 `encrypt` 入参并由 SDK 自动填充此字段 |
| `message_id` | string | 否 | — | 幂等键（客户端提供或服务端生成 UUID） |
| `timestamp` | integer | 否 | — | 客户端时间戳（毫秒）。**服务端忽略此字段，始终使用服务端时间** |

> 连接级 `delivery_mode` 在 `auth.connect` 阶段声明。Python SDK 的 P2P 消息发送会沿用当前连接的 `delivery_mode`，应用层发送时无需重复指定。

### Payload 参考约定

`payload` 是应用层 JSON 对象，服务端只做大小限制和透传，不按本节字段做强制校验。本节参考 wxauto `Message` 类的常见消息形态（文本、引用、语音、图片、视频、文件、位置、链接、表情、合并转发、名片、笔记等），并补充 AUN Agent 场景常用的状态、结构化数据和工具调用类型。

示例展示的是 `message.send.params.payload` 片段；完整 P2P 请求仍需要在同级传入 `to`。文本、图片、文件等业务消息类型只能放在 `payload.type`；`message.send.params.type` 是信封/封装类型，例如 SDK 加密发送时自动填充的 `e2ee.encrypted`，不表示业务负载类型。

#### 信封字段不进入 payload

`payload` 只描述业务内容，不重复传输层或投递层已经提供的字段。

| 字段 | 所在位置 | 说明 |
|------|----------|------|
| `to` | `message.send.params` | 接收方 AID |
| `from` / `sender_aid` | 服务端生成的消息信封 | 发送方身份 |
| `message_id` / `seq` / `timestamp` | 服务端生成或发送参数 | 当前消息 ID、序号、服务端时间 |
| `encrypted` / `delivery_mode` | 发送参数或连接上下文 | 加密和投递语义 |
| `type` / `message_type` | 发送参数或消息信封 | 信封/封装类型，如 `e2ee.encrypted`；业务负载类型使用 `payload.type` |

#### 公共辅助字段

以下字段可出现在多数 payload 中；如无需要，不必携带。

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `type` | string | 是 | 业务负载类型，如 `text` / `image` / `status` / `event` / `tool_call` |
| `text` | string | 否 | 面向用户展示的正文或摘要 |
| `format` | string | 否 | 文本格式，建议值：`plain` / `markdown` |
| `chat_id` | string | 否 | 应用层会话标识；AUN P2P 不创建服务端会话生命周期 |
| `thread_id` | string | 否 | 话题、子线程或任务线程标识 |
| `reply_to` | object | 否 | 回复目标，推荐含被回复消息的 `message_id`、`seq` |
| `mentions` | array | 否 | 提及对象，推荐项为 `{aid, display, offset, length}` |
| `entities` | array | 否 | 文本实体，如链接、代码片段、时间范围 |
| `attachments` | array | 否 | 附件引用列表，结构见“附件引用” |
| `client_context` | object | 否 | 客户端自定义上下文，如窗口、任务、草稿来源 |

字段名建议使用 snake_case，如 `chat_id`、`thread_id`；已有应用若使用 `chatId` 等命名，可在自己的应用层约定中保持一致。

`chat_id`、`thread_id`、`reply_to`、`mentions`、`entities`、`client_context` 这类字段无法可靠放入传输信封：它们属于应用上下文，不参与路由，但又常常需要端到端加密保护。因此这些字段应保留在 `payload` 内，由 SDK 随消息内容一起加密。

#### `text`：文本消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `text` | string | 是 | 文本内容 |
| `format` | string | 否 | `plain` / `markdown`，默认 `plain` |
| `lang` | string | 否 | BCP 47 语言标签，如 `zh-CN` |
| `entities` | array | 否 | 文本实体范围 |

```json
{
  "payload": {
    "type": "text",
    "text": "你好，明天 10:00 开会",
    "format": "plain",
    "lang": "zh-CN"
  }
}
```

#### `quote`：引用消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `text` | string | 是 | 本次回复内容 |
| `quote` | object | 是 | 被引用消息摘要，避免复制完整敏感原文 |
| `quote.message_id` | string | 否 | 被引用消息 ID |
| `quote.text` | string | 否 | 被引用内容摘要 |
| `quote.sender_display` | string | 否 | 展示用发送者名称 |

```json
{
  "payload": {
    "type": "quote",
    "text": "我同意这个方案",
    "quote": {
      "message_id": "msg-prev",
      "text": "是否采用方案 A？",
      "sender_display": "Bob"
    }
  }
}
```

#### `voice`：语音消息

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
      "url": "aun://storage/default/voice/msg-1.opus",
      "filename": "msg-1.opus",
      "content_type": "audio/ogg"
    }]
  }
}
```

#### `image`：图片消息

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
    "alt": "AUN 消息投递流程图",
    "width": 1280,
    "height": 720,
    "attachments": [{
      "url": "aun://storage/default/images/flow.png",
      "filename": "flow.png",
      "content_type": "image/png"
    }]
  }
}
```

#### `video`：视频消息

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
      "url": "aun://storage/default/videos/demo-cover.jpg",
      "content_type": "image/jpeg"
    },
    "attachments": [{
      "url": "aun://storage/default/videos/demo.mp4",
      "filename": "demo.mp4",
      "content_type": "video/mp4"
    }]
  }
}
```

#### `file`：文件消息

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
      "url": "aun://storage/default/docs/report.pdf",
      "filename": "report.pdf",
      "content_type": "application/pdf",
      "size_bytes": 245678,
      "sha256": "3d8e577b..."
    }]
  }
}
```

#### `location`：位置消息

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

#### `link`：链接消息

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

#### `emotion`：表情消息

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

#### `merge`：合并转发消息

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

#### `personal_card`：名片消息

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

#### `note`：笔记消息

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

#### `status`：状态或事件消息

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
    "event": "task.started",
    "text": "正在生成报告",
    "progress": 0.15,
    "data": {"task_id": "task-123"}
  }
}
```

#### `event`：事件消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `type` | string | 是 | 固定为 `event` |
| `event` | string | 是 | 应用层事件名，如 `task.completed` |
| `data` | object | 否 | 事件数据 |
| `text` | string | 否 | 降级展示文案 |
| `severity` | string | 否 | 级别，如 `info` / `warning` / `error` |
| `occurred_at` | integer | 否 | 事件发生时间，毫秒时间戳 |

```json
{
  "payload": {
    "type": "event",
    "event": "task.completed",
    "text": "报告已生成",
    "severity": "info",
    "data": {"task_id": "task-123", "artifact": "report.pdf"}
  }
}
```

#### `json`：结构化数据消息

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

#### `reaction`：消息反应

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `target` | object | 是 | 目标消息，推荐含 `message_id`、`seq` |
| `action` | string | 是 | `add` / `remove` |
| `key` | string | 是 | 反应标识，如 `like` / `done` |
| `text` | string | 否 | 展示文本 |

```json
{
  "payload": {
    "type": "reaction",
    "target": {"message_id": "msg-prev", "seq": 41},
    "action": "add",
    "key": "done",
    "text": "已处理"
  }
}
```

#### `tool_call`：工具调用请求

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
    "name": "weather.query",
    "arguments": {"city": "Shanghai"},
    "timeout_ms": 30000
  }
}
```

#### `tool_result`：工具调用结果

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
      "city": "Shanghai",
      "weather": "cloudy"
    }
  }
}
```

#### `custom`：自定义消息

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

### 附件引用

大文件、二进制附件不应直接嵌入 `payload`，应先通过 `storage.*` 上传，再在 `payload.attachments` 中携带对象引用：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `owner_aid` | string | 否 | 对象所有者 AID，可作为对象标识补充 |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `object_key` | string | 否 | Storage 对象路径 |
| `url` | string | 否 | 对象 URL；AUN Storage 场景下为上传完成后返回的长期对象引用 |
| `filename` | string | 否 | 原始文件名 |
| `size_bytes` | integer | 否 | 文件大小（字节） |
| `sha256` | string | 否 | 内容哈希，用于完整性校验 |
| `content_type` | string | 否 | MIME 类型 |
| `thumbnail` | object | 否 | 缩略图引用，结构同附件引用 |

AUN Storage 的 `url` 是长期对象引用，不是最终文件下载地址。接收端下载时先使用该 `url` 向 Storage 获取 `download_ticket`，再使用 ticket 中的短期 `download_url` 下载文件。`owner_aid`、`bucket`、`object_key` 可作为可选对象标识补充，便于没有 `url` 解析能力的客户端或服务端工具定位对象。

**附件引用示例**：

```json
{
  "payload": {
    "type": "file",
    "text": "请查收附件",
    "attachments": [{
      "owner_aid": "alice.agentid.pub",
      "bucket": "default",
      "object_key": "docs/report.pdf",
      "url": "https://storage.agentid.pub/objects/default/docs/report.pdf",
      "filename": "report.pdf",
      "content_type": "application/pdf",
      "size_bytes": 245678,
      "sha256": "3d8e577b..."
    }]
  }
}
```

> 服务端对 `payload` 内容透传，不校验上述结构。接收端应对未知 `type`、未知 `kind` 和缺失展示字段做降级处理。

### 响应

```json
{
    "jsonrpc": "2.0",
    "result": {
        "message_id": "550e8400-e29b-41d4-a716-446655440000",
        "seq": 42,
        "timestamp": 1234567890000,
        "status": "delivered",
        "delivery_mode": "fanout"
    },
    "id": 1
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `message_id` | string | 消息 ID |
| `seq` | integer | 接收方收件箱序号 |
| `timestamp` | integer | 服务端时间戳（毫秒） |
| `status` | string | `"sent"` / `"delivered"` / `"duplicate"` |
| `delivery_mode` | string | 最终生效的连接级投递语义：`fanout` 或 `queue` |
| `cross_domain` | boolean | 仅跨域投递时出现，当前值为 `true` |
| `target_issuer` | string | 仅跨域投递时出现，表示目标 issuer |

> **duplicate 响应**：当 `message_id` 重复时，若服务端仍缓存首次结果，返回完整首次响应并附加 `"status": "duplicate"`；若缓存已过期，仅返回 `message_id`、`timestamp`、`status`，**不含** `seq` 和 `delivery_mode`。客户端收到 `"duplicate"` 状态时应视为幂等成功，无需重试。

### 错误

| code | 说明 |
|------|------|
| -32002 | 服务暂不可用（如数据库未连接、服务证书未加载） |
| -32603 | 参数缺失（to 或 payload） |
| -32603 | payload 超过大小限制（默认 1 MB） |
| -32603 | 目标 AID 不存在 |
| -32603 | 频率限制超限 |

### 示例

```python
result = await client.call("message.send", {
    "to": "bob.agentid.pub",
    "payload": {"type": "text", "text": "Hello!"},
})
# result: {"message_id": "...", "seq": 42, "status": "delivered", ...}
```

---

## message.pull

按游标增量拉取消息。合并持久化消息和临时消息，按 seq 升序返回。

### 请求

```json
{
    "jsonrpc": "2.0",
    "method": "message.pull",
    "params": {
        "after_seq": 100,
        "limit": 50
    },
    "id": 2
}
```

### 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `after_seq` | integer | 否 | 0 | 拉取 seq > after_seq 的消息 |
| `limit` | integer | 否 | 100 | 单次返回上限（最大 200） |

### 响应

```json
{
    "jsonrpc": "2.0",
    "result": {
        "messages": [
            {
                "message_id": "uuid-1",
                "seq": 101,
                "from": "alice.agentid.pub",
                "to": "bob.agentid.pub",
                "timestamp": 1234567890000,
                "payload": {"type": "text", "text": "Hello!"},
                "delivery_mode": "fanout",
                "encrypted": false
            }
        ],
        "count": 1,
        "latest_seq": 101,
        "ephemeral_earliest_available_seq": null,
        "ephemeral_dropped_count": 0
    },
    "id": 2
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `messages` | array | 消息列表（按 seq 升序）。消息对象含 `encrypted` 字段（仅 `encrypted=true` 时出现） |
| `count` | integer | 本次返回的消息数 |
| `latest_seq` | integer | 返回的最大 seq |
| `ephemeral_earliest_available_seq` | integer\|null | 临时缓冲中可用的最小 seq |
| `ephemeral_dropped_count` | integer | 已被淘汰的临时消息数 |

### 示例

```python
result = await client.call("message.pull", {"after_seq": 0, "limit": 20})
for msg in result["messages"]:
    print(f"{msg['from']}: {msg['payload']}")
```

---

## message.ack

确认已收到消息。推进接收方的 ack_seq 游标。

### 请求

```json
{
    "jsonrpc": "2.0",
    "method": "message.ack",
    "params": {
        "seq": 150
    },
    "id": 3
}
```

### 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `seq` | integer | 是 | — | 确认 seq ≤ 此值的所有消息 |

### 响应

```json
{
    "jsonrpc": "2.0",
    "result": {
        "success": true,
        "ack_seq": 150,
        "event_published": true
    },
    "id": 3
}
```

其中 `event_published` / `event_error` 为可选字段：当 ack 游标已成功写入数据库，但事件发布失败时，当前实现会返回 `{"success": true, "ack_seq": ..., "event_published": false, "event_error": "..."}`，提示调用方不要因重试而重复推进状态。

### 副作用

确认成功后，服务端向**发送方**推送 `event/message.ack` 事件。

### 示例

```python
result = await client.call("message.ack", {"seq": 150})
# result: {"success": true, "ack_seq": 150}
```

---

## message.recall

撤回消息。仅发送方可撤回，受时间窗口限制（默认 2 分钟）。

### 请求

```json
{
    "jsonrpc": "2.0",
    "method": "message.recall",
    "params": {
        "message_ids": ["uuid-1", "uuid-2"]
    },
    "id": 6
}
```

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `message_ids` | array | 是 | 要撤回的消息 ID 列表（最多 100 个） |

### 响应

```json
{
    "jsonrpc": "2.0",
    "result": {
        "success": true,
        "accepted": 2,
        "recalled": 1,
        "errors": [
            {"message_id": "uuid-2", "error": "expired"}
        ]
    },
    "id": 6
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | 操作是否执行 |
| `accepted` | integer | 接收的 message_id 数 |
| `recalled` | integer | 实际撤回的数 |
| `errors` | array\|null | 失败项（`not_found` / `not_sender` / `already_recalled` / `expired`） |

### 副作用

撤回成功后，服务端向**接收方**推送 `event/message.recalled` 事件。

---

## message.query_online

批量查询 AID 在线状态。

### 请求

```json
{
    "jsonrpc": "2.0",
    "method": "message.query_online",
    "params": {
        "aids": ["alice.agentid.pub", "bob.example.com"]
    },
    "id": 7
}
```

### 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `aids` | array | 是 | — | 要查询的 AID 列表，最多 100 个 |

### 响应

```json
{
    "jsonrpc": "2.0",
    "result": {
        "online": {
            "alice.agentid.pub": true,
            "bob.example.com": false
        }
    },
    "id": 7
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `online` | object | `AID -> boolean` 的映射 |

### 当前实现说明

- 本域 AID 直接由 message 服务的在线跟踪器返回状态
- 外域 AID 当前通过 `gateway.forward_federation` 转发到目标域查询
- 若某个外域查询失败，当前实现会把该域内 AID 回落为 `false`，而不是让整个 RPC 失败

---

## event/message.received

收到新消息时推送。

### Payload

```json
{
    "message_id": "uuid-1",
    "from": "alice.agentid.pub",
    "to": "bob.agentid.pub",
    "seq": 42,
    "timestamp": 1234567890000,
    "payload": {"type": "text", "text": "Hello!"},
    "delivery_mode": "queue",
    "encrypted": false
}
```

### 订阅

```python
client.on("message.received", lambda msg: print(msg["payload"]))
```

---

## event/message.ack

消息被接收方确认时推送给**发送方**。

### Payload

```json
{
    "to": "bob.agentid.pub",
    "ack_seq": 150,
    "device_id": "dev-001",
    "slot_id": "slot-a",
    "timestamp": 1234567890000
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `to` | string | **确认方（接收方）AID** — 即执行 ack 操作的一方 |
| `ack_seq` | integer | 已确认的最大 seq |
| `device_id` | string | 当前确认所归属的设备 ID |
| `slot_id` | string | 当前确认所归属的实例槽位；未使用多实例时可为空字符串 |
| `timestamp` | integer | 服务端时间戳（毫秒） |

### 订阅

```python
client.on("message.ack", lambda ev: print(f"{ev['to']}[{ev['device_id']}/{ev['slot_id']}] 已确认到 seq {ev['ack_seq']}"))
```

---

## event/message.recalled

消息被发送方撤回时推送给**接收方**。

### Payload

```json
{
    "from": "alice.agentid.pub",
    "to": "bob.agentid.pub",
    "message_ids": ["uuid-1", "uuid-2"],
    "timestamp": 1234567890000
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `from` | string | 发送方（撤回者）AID |
| `to` | string | 接收方 AID |
| `message_ids` | array | 被撤回的消息 ID 列表 |
| `timestamp` | integer | 服务端时间戳（毫秒） |

### 订阅

```python
client.on("message.recalled", lambda ev: print(f"{ev['from']} 撤回了 {len(ev['message_ids'])} 条消息"))
```
