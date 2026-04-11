# 实时流 — RPC Manual

## 方法索引

### 控制面方法（通过 Gateway JSON-RPC）

| 方法 | 说明 |
|------|------|
| [stream.create](#streamcreate) | 创建流，返回推流/拉流 URL |
| [stream.close](#streamclose) | 关闭流（仅创建者） |
| [stream.get_info](#streamget_info) | 获取流状态和统计 |
| [stream.list_active](#streamlist_active) | 列出当前 AID 的活跃流 |

### 数据面端点（独立端口，默认 9490）

| 端点 | 协议 | 说明 |
|------|------|------|
| `/push/{stream_id}?token=xxx` | WebSocket | 推流（当前实现为 `push_token` 能力鉴权） |
| `/pull/{stream_id}?token=xxx` | HTTP SSE | 拉流（当前实现为 `pull_token` 能力鉴权，可跨域使用） |
| `/health` | HTTP GET | 健康检查 |

---

## stream.create

创建一条新的流，返回推流和拉流地址。推流方通过 WebSocket 连接 push_url 发送数据帧，拉流方通过 HTTP SSE 连接 pull_url 接收数据。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `content_type` | string | 否 | 内容类型，默认 `"text/plain"`。常用值：`text/plain`（文本流）、`application/json-stream`（JSON 对象流）、`text/event-stream`（SSE 风格事件流） |
| `metadata` | object | 否 | 自定义元数据，如 `{"model": "gpt-4", "task_id": "xxx"}` |
| `target_aid` | string | 否 | 绑定拉流方 AID。设置后仅该 AID 可拉流，用于一对一场景 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `stream_id` | string | 流唯一 ID（16 位 hex） |
| `push_url` | string | 推流 WebSocket URL（含 push_token） |
| `pull_url` | string | 拉流 HTTP SSE URL（含 pull_token） |
| `pull_token` | string | 拉流凭证，便于通过 message.send 单独传递 |

### 调用示例

```python
result = await client.call("stream.create", {
    "content_type": "text/plain",
    "metadata": {"model": "gpt-4"},
})
# result = {
#   "stream_id": "4d5067f203cf42ba",
#   "push_url": "wss://stream.aid.com:9490/push/4d5067f203cf42ba?token=ec80...",
#   "pull_url": "https://stream.aid.com:9490/pull/4d5067f203cf42ba?token=c438...",
#   "pull_token": "c438953be0ca887b..."
# }
```

### 错误

| code | message | 原因 |
|------|---------|------|
| -32000 | 达到最大流数限制 (`达到最大流数限制 (N)`) | 活跃流数超过服务配置上限 |

---

## stream.close

关闭流。仅流的创建者可调用。关闭后所有拉流端收到 SSE `event: done`。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `stream_id` | string | 是 | 要关闭的流 ID |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | `true` |

### 调用示例

```python
await client.call("stream.close", {"stream_id": "4d5067f203cf42ba"})
```

### 错误

| code | message | 原因 |
|------|---------|------|
| -32000 | `流不存在: {stream_id}` | stream_id 无效或已被清理 |
| -32000 | `只有流创建者可以关闭流` | 非创建者调用 |

---

## stream.get_info

获取流的状态和统计信息。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `stream_id` | string | 是 | 流 ID |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `stream_id` | string | 流 ID |
| `creator_aid` | string | 创建者 AID |
| `content_type` | string | 内容类型 |
| `metadata` | object | 自定义元数据 |
| `status` | string | `"waiting"` / `"active"` / `"done"` |
| `is_online` | boolean | 推流端是否在线 |
| `seq` | integer | 当前最大序列号 |
| `frames_pushed` | integer | 已推送帧数 |
| `bytes_pushed` | integer | 已推送字节数 |
| `puller_count` | integer | 当前拉流端数量 |
| `age_seconds` | float | 流存活时间（秒） |
| `idle_seconds` | float | 距最近活动的秒数 |

### 调用示例

```python
info = await client.call("stream.get_info", {"stream_id": "4d5067f203cf42ba"})
# info["status"] == "active"
# info["frames_pushed"] == 42
```

---

## stream.list_active

列出当前 AID 创建的所有活跃流。

### 参数

无。

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `streams` | array | StreamInfo 对象数组（同 get_info 响应格式） |

### 调用示例

```python
result = await client.call("stream.list_active", {})
for s in result["streams"]:
    print(f"{s['stream_id']}: {s['status']}, {s['frames_pushed']} frames")
```

---

## 数据面：推流 WebSocket

连接 `stream.create` 返回的 `push_url`，通过 WebSocket 发送 JSON 帧。

### 帧格式

**数据帧**：
```json
{"cmd": "data", "data": "chunk内容", "seq": 1}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `cmd` | string | 是 | 固定 `"data"` |
| `data` | string | 是 | 数据内容，无大小限制（WS 帧上限 64MB） |
| `seq` | integer | 否 | 序列号，不提供则服务端自增 |

**关闭帧**：
```json
{"cmd": "close"}
```

### 完整示例

```python
import websockets, json

async with websockets.connect(push_url, ssl=ssl_ctx) as ws:
    for i, token in enumerate(llm_tokens, 1):
        await ws.send(json.dumps({"cmd": "data", "data": token, "seq": i}))
    await ws.send(json.dumps({"cmd": "close"}))
```

### 断线重连

WebSocket 断开后，服务端保留流状态最多 120 秒。重连后继续从断点 seq 推送即可。

---

## 数据面：拉流 HTTP SSE

连接 `stream.create` 返回的 `pull_url`，接收标准 SSE 流。

### SSE 格式

```
data: Hello 

data: World

event: done
data: {}
```

- `data:` — 原始数据内容
- `event: done` — 流结束信号
- `: keep-alive` — 心跳注释（每 10 秒）

### 断线续拉

当前实现支持标准 SSE 的 `Last-Event-ID` 续拉：

- 服务端在每个 SSE 数据块中写入 `id: {seq}`
- 客户端重连时可携带 `Last-Event-ID`
- 服务端会跳过 `seq <= Last-Event-ID` 的缓冲数据，再继续实时推送

注意：这只覆盖仍保留在当前流内存缓冲中的历史数据，不是持久化重放。

### 完整示例

```python
import aiohttp

async with aiohttp.ClientSession() as session:
    async with session.get(pull_url, headers={"Accept": "text/event-stream"}) as resp:
        buffer = ""
        async for chunk in resp.content.iter_any():
            buffer += chunk.decode()
            # 解析 SSE 帧...
```

### HTTP 错误码

| 状态码 | 说明 |
|--------|------|
| 403 | pull_token 无效 或 target_aid 不匹配 |
| 404 | 流不存在 |
| 410 | 流已关闭 |
| 429 | 拉流端数量已达上限 |
