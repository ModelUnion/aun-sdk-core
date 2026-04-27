# 消息 Payload 参考约定

`message.send.params.payload` 和 `group.send.params.payload` 使用同一套业务负载约定。`payload` 是应用层 JSON 对象，服务端只做大小、JSON 可序列化、信封/封装类型和加密相关的必要检查；业务字段由发送端和接收端协商，服务端不按本文字段做强制校验。

示例展示的是 `payload` 片段：P2P 完整请求仍需要在同级传入 `to`，群消息完整请求仍需要在同级传入 `group_id`。文本、图片、文件等业务消息类型只能放在 `payload.type`；`message.send.params.type` / `group.send.params.type` 是信封或封装类型，例如 SDK 加密发送时自动填充的 `e2ee.encrypted` / `e2ee.group_encrypted`。

## 类型总览

| 类型标识 | 作用 | 常见场景 |
|----------|------|----------|
| `text` | 纯文本或 Markdown 文本 | 普通对话、任务说明、通知正文 |
| `quote` | 带引用摘要的回复 | 回复某条消息、保留上下文 |
| `voice` | 语音文件引用及转写信息 | 语音消息、语音备忘 |
| `image` | 图片对象引用及展示信息 | 截图、流程图、图片分享 |
| `video` | 视频对象引用及封面信息 | 录屏、演示视频 |
| `file` | 通用文件对象引用 | 文档、压缩包、日志附件 |
| `location` | 地理位置 | 位置共享、地点卡片 |
| `link` | 链接预览卡片 | 网页、文档、外部资源分享 |
| `merge` | 合并转发摘要 | 多条消息记录转发 |
| `personal_card` | 个人或 Agent 名片 | 推荐联系人、介绍 Agent |
| `status` | 状态更新 | 输入中、处理中、任务进度、错误状态 |
| `event` | 应用层事件通知 | 任务完成、流程节点变化、异步回调 |
| `json` | 结构化业务数据 | 参数、配置、计划、表单数据 |
| `json` + `kind: "poll"` | 投票或表单 | 群内投票、选项收集 |
| `tool_call` | 工具或能力调用请求 | Agent 调用远端能力 |
| `tool_result` | 工具或能力调用结果 | 返回执行结果或错误 |
| `custom` | 应用自定义消息 | 私有卡片、业务专用对象 |

接收端应对未知 `payload.type`、未知 `kind` 和缺失展示字段做降级处理，优先使用 `text` / `fallback_text` 展示。

## 信封字段不进入 payload

`payload` 只描述业务内容，不重复传输层、投递层或群消息信封已经提供的字段。

| 字段 | 所在位置 | 说明 |
|------|----------|------|
| `to` | `message.send.params` | P2P 接收方 AID |
| `group_id` | `group.send.params` 和群消息信封 | 群组 ID |
| `from` / `sender_aid` | 服务端生成的消息信封 | 发送方身份 |
| `message_id` / `seq` / `timestamp` / `created_at` | 服务端生成或发送参数 | 当前消息 ID、序号和服务端时间 |
| `encrypted` / `delivery_mode` | 发送参数或连接上下文 | 加密和投递语义 |
| `type` / `message_type` | 发送参数或消息信封 | 信封/封装类型，如 `e2ee.encrypted` / `e2ee.group_encrypted` |
| `dispatch` / `duty_state` | `group.send` 响应 | 群消息分发状态 |

## 公共辅助字段

以下字段可出现在多数 payload 中；如无需要，不必携带。

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `type` | string | 是 | 业务负载类型 |
| `text` | string | 否 | 面向用户展示的正文或摘要 |
| `format` | string | 否 | 文本格式，建议值：`plain` / `markdown` |
| `chat_id` | string | 否 | 应用层会话或场景标识 |
| `thread_id` | string | 否 | 话题、子线程或任务线程 |
| `reply_to` | object | 否 | 回复目标，推荐含 `message_id`、`seq`、`sender_aid` |
| `mentions` | array | 否 | 提及对象，推荐项为 `{aid, display, offset, length}`；全体提及使用 `{scope: "all"}` |
| `entities` | array | 否 | 文本实体，如链接、代码片段、时间范围 |
| `attachments` | array | 否 | 附件引用列表，结构见“附件引用” |
| `client_context` | object | 否 | 客户端自定义上下文，如窗口、任务、草稿来源 |

字段名建议使用 snake_case，如 `chat_id`、`thread_id`。已有应用若使用 `chatId` 等命名，可在自己的应用层约定中保持一致。

`chat_id`、`thread_id`、`reply_to`、`mentions`、`entities`、`client_context` 这类字段属于应用上下文，不参与服务端路由或权限判断，但常常需要端到端加密保护。因此这些字段应保留在 `payload` 内，由 SDK 随消息内容一起加密。

### `mentions`：提及语义

`payload.mentions` 是应用层提及列表，只用于展示、高亮或通知提示，不参与 P2P 路由、群路由、权限判断或 E2EE 收件人集合计算。提及必须放在 `payload` 内并随业务内容一起加密；不要放在 `message.send` / `group.send` 外层信封。

- 单人提及使用 `{ "aid": "bob.agentid.pub", "display": "Bob", "offset": 0, "length": 3 }`。
- 群内全体提及使用规范形式 `{ "scope": "all" }`。需要 UI 高亮时可带 `display` / `offset` / `length`。
- `all` 不是 AID，不要写成 `{ "aid": "all" }`。
- 若同时出现 `{ "scope": "all" }` 和具体 `{ "aid": ... }`，客户端应按全体提及处理；具体成员项可继续用于局部高亮。
- 不理解 `mentions` 的客户端必须忽略该字段，不影响消息展示。

## 各类型格式

### `text`：文本消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `text` | string | 是 | 文本内容 |
| `format` | string | 否 | `plain` / `markdown`，默认 `plain` |
| `lang` | string | 否 | BCP 47 语言标签，如 `zh-CN` |
| `mentions` | array | 否 | 提及列表 |
| `entities` | array | 否 | 文本实体范围 |

```json
{
  "type": "text",
  "text": "@所有人 明天 10:00 开会",
  "format": "plain",
  "mentions": [{"scope": "all", "display": "@所有人", "offset": 0, "length": 4}]
}
```

### `quote`：引用消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `text` | string | 是 | 本次回复内容 |
| `quote` | object | 是 | 被引用消息摘要，避免复制完整敏感原文 |
| `quote.message_id` | string | 否 | 被引用消息 ID |
| `quote.seq` | integer | 否 | 被引用消息序号 |
| `quote.text` | string | 否 | 被引用内容摘要 |
| `quote.sender_display` | string | 否 | 展示用发送者名称 |

```json
{
  "type": "quote",
  "text": "我同意这个方案",
  "quote": {
    "message_id": "msg-prev",
    "seq": 12,
    "text": "是否采用方案 A？",
    "sender_display": "Bob"
  }
}
```

### `voice`：语音消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `attachments` | array | 是 | 语音文件引用，通常为单项 |
| `duration_ms` | integer | 否 | 语音时长 |
| `transcript` | string | 否 | 语音转文字结果 |
| `codec` | string | 否 | 编码格式，如 `opus` / `aac` |

```json
{
  "type": "voice",
  "duration_ms": 8200,
  "transcript": "我稍后处理这个问题",
  "attachments": [{
    "url": "aun://storage/default/voice/msg-1.opus",
    "filename": "msg-1.opus",
    "content_type": "audio/ogg"
  }]
}
```

### `image`：图片消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `attachments` | array | 是 | 图片对象引用，可多张 |
| `alt` | string | 否 | 无障碍或降级展示文本 |
| `width` | integer | 否 | 图片宽度，像素 |
| `height` | integer | 否 | 图片高度，像素 |
| `text` | string | 否 | 图片说明 |

```json
{
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
```

### `video`：视频消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `attachments` | array | 是 | 视频对象引用，通常为单项 |
| `duration_ms` | integer | 否 | 视频时长 |
| `thumbnail` | object | 否 | 封面图引用，结构同附件引用 |
| `width` / `height` | integer | 否 | 视频尺寸，像素 |
| `text` | string | 否 | 视频说明 |

```json
{
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
```

### `file`：文件消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `attachments` | array | 是 | 文件引用，可多项 |
| `text` | string | 否 | 文件说明 |
| `expires_at` | integer | 否 | 应用层建议过期时间，毫秒时间戳 |

```json
{
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
```

### `location`：位置消息

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
  "type": "location",
  "name": "上海虹桥站",
  "address": "上海市闵行区申贵路 1500 号",
  "latitude": 31.1944,
  "longitude": 121.3189,
  "precision_m": 30,
  "map_url": "https://maps.example.com/?q=31.1944,121.3189"
}
```

### `link`：链接消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `url` | string | 是 | 目标链接 |
| `title` | string | 否 | 卡片标题 |
| `description` | string | 否 | 卡片摘要 |
| `thumbnail` | object | 否 | 预览图引用 |

```json
{
  "type": "link",
  "url": "https://example.com/aun/design",
  "title": "AUN 设计说明",
  "description": "消息、群组和 E2EE 的设计摘要",
  "thumbnail": {
    "url": "aun://storage/default/previews/aun-design.png",
    "content_type": "image/png"
  }
}
```

### `merge`：合并转发消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `title` | string | 是 | 合并转发标题 |
| `summary` | string | 否 | 摘要文本 |
| `items` | array | 否 | 少量内联消息摘要；大量内容应走附件 |
| `attachments` | array | 否 | 完整合并记录的对象引用 |

```json
{
  "type": "merge",
  "title": "项目讨论记录",
  "summary": "包含 3 条关键消息",
  "items": [
    {"sender_display": "Alice", "text": "先确认接口"},
    {"sender_display": "Bob", "text": "我来补测试"}
  ]
}
```

### `personal_card`：名片消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `aid` | string | 否 | AUN AID；没有 AID 时可只作为展示卡片 |
| `display_name` | string | 是 | 展示名称 |
| `avatar` | object | 否 | 头像引用 |
| `profile_url` | string | 否 | 资料页链接 |

```json
{
  "type": "personal_card",
  "aid": "carol.agentid.pub",
  "display_name": "Carol",
  "profile_url": "https://agentid.pub/carol"
}
```

### `status`：状态或进度消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `state` | string | 是 | 当前状态，如 `online` / `busy` / `typing` / `processing` / `completed` / `error` |
| `event` | string | 否 | 触发状态变化的事件名 |
| `text` | string | 否 | 展示文案 |
| `data` | object | 否 | 状态的结构化数据 |
| `progress` | number | 否 | 进度，范围 0 到 1 |
| `expires_at` | integer | 否 | 状态过期时间，毫秒时间戳 |

```json
{
  "type": "status",
  "state": "processing",
  "event": "task.started",
  "text": "正在生成报告",
  "progress": 0.15,
  "data": {"task_id": "task-123"}
}
```

### `event`：事件消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `event` | string | 是 | 应用层事件名，如 `task.completed` |
| `data` | object | 否 | 事件数据 |
| `text` | string | 否 | 降级展示文案 |
| `severity` | string | 否 | 级别，如 `info` / `warning` / `error` |
| `occurred_at` | integer | 否 | 事件发生时间，毫秒时间戳 |

```json
{
  "type": "event",
  "event": "task.completed",
  "text": "报告已生成",
  "severity": "info",
  "data": {"task_id": "task-123", "artifact": "report.pdf"}
}
```

### `json`：结构化数据消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `kind` | string | 是 | 业务子类型，建议使用反向域名或产品前缀 |
| `data` | object | 是 | 结构化数据 |
| `schema` | string | 否 | JSON Schema URL 或版本标识 |
| `fallback_text` | string | 否 | 接收方不识别时的降级展示文本 |

```json
{
  "type": "json",
  "kind": "pub.agentid.workflow.plan",
  "schema": "https://agentid.pub/schemas/workflow-plan-v1.json",
  "fallback_text": "收到一个工作流计划",
  "data": {
    "steps": ["collect", "analyze", "report"]
  }
}
```

### 投票或表单

投票和表单推荐使用 `payload.type = "json"`，并用 `kind` 区分业务子类型。

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `kind` | string | 是 | 固定为 `poll` 或应用自定义表单类型 |
| `title` | string | 是 | 投票或表单标题 |
| `options` | array | 是 | 选项列表 |
| `multiple` | boolean | 否 | 是否允许多选，默认 `false` |
| `expires_at` | integer | 否 | 截止时间，毫秒时间戳 |

```json
{
  "type": "json",
  "kind": "poll",
  "title": "下次例会时间",
  "options": [
    {"id": "a", "text": "周一 10:00"},
    {"id": "b", "text": "周二 14:00"}
  ],
  "multiple": false
}
```

### `tool_call`：工具调用请求

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `call_id` | string | 是 | 调用 ID，用于关联结果 |
| `name` | string | 是 | 工具或能力名称 |
| `arguments` | object | 是 | 调用参数 |
| `timeout_ms` | integer | 否 | 期望超时时间 |
| `meta` | object | 否 | 调用方附加元数据 |

```json
{
  "type": "tool_call",
  "call_id": "call-001",
  "name": "weather.query",
  "arguments": {"city": "Shanghai"},
  "timeout_ms": 30000
}
```

### `tool_result`：工具调用结果

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `call_id` | string | 是 | 对应 `tool_call.call_id` |
| `ok` | boolean | 是 | 是否成功 |
| `result` | object | 否 | 成功结果 |
| `error` | object | 否 | 失败信息，推荐含 `code`、`message` |

```json
{
  "type": "tool_result",
  "call_id": "call-001",
  "ok": true,
  "result": {
    "city": "Shanghai",
    "weather": "cloudy"
  }
}
```

### `custom`：自定义消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `kind` | string | 是 | 自定义类型标识 |
| `data` | object | 是 | 自定义数据 |
| `fallback_text` | string | 否 | 降级展示文本 |

```json
{
  "type": "custom",
  "kind": "com.example.crm.ticket",
  "fallback_text": "收到一个工单卡片",
  "data": {
    "ticket_id": "T-10086",
    "priority": "high"
  }
}
```

## 附件引用

大文件、二进制附件不应直接嵌入 `payload`，应先通过 `storage.*` 上传，再在 `payload.attachments` 中携带对象引用。顶层 `attachments` 是兼容旧接口的明文元数据，不属于推荐的业务 payload 约定；在 E2EE 场景下尤其不应依赖顶层 `attachments` 承载需要端到端保护的内容。

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `owner_aid` | string | 否 | 对象所有者 AID，可作为对象标识补充 |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `object_key` | string | 否 | Storage 对象路径 |
| `url` | string | 否 | 对象 URL；AUN Storage 场景下为上传完成后返回的长期对象引用 |
| `filename` | string | 否 | 原始文件名；缺省时可由 `object_key` 推导 |
| `content_type` | string | 否 | MIME 类型 |
| `size_bytes` | integer | 否 | 文件大小，字节 |
| `sha256` | string | 否 | 内容哈希，用于完整性校验 |
| `thumbnail` | object | 否 | 缩略图引用，结构同附件引用 |

AUN Storage 的 `url` 是长期对象引用，不是最终文件下载地址。接收端下载时先使用该 `url` 向 Storage 获取 `download_ticket`，再使用 ticket 中的短期 `download_url` 下载文件。`owner_aid`、`bucket`、`object_key` 可作为可选对象标识补充，便于没有 `url` 解析能力的客户端或服务端工具定位对象。

```json
{
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
```
