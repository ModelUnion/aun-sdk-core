# 附录 N — 分布式 Trace 协议

## 设计目标

为 AUN RPC 调用链路（SDK → Gateway → Service → Gateway → SDK）提供轻量级的分布式追踪能力，
支持两种使用场景：

1. **日志关联（log 模式）** — 全链路日志通过 `trace_id` 串联，零开销，可在生产环境常开
2. **诊断回传（diag 模式）** — 各环节追加 span，response 携带完整链路返回调用者，
   仅用于疑难问题诊断，需通过开关启用

不依赖 OpenTelemetry / Jaeger 等外部体系，自定义 `_trace` 字段即可，跨语言实现成本极低。

---

## 一、协议层

### 1.1 字段位置

`_trace` 字段位于 JSON-RPC `params` 内，沿用 AUN 现有框架字段约定（与 `_caller_id`、`_auth` 同级）：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "message.send",
  "params": {
    "to": "bob.aid.com",
    "body": "hello",
    "_trace": {
      "trace_id": "a1b2c3d4e5f6...",
      "mode": "log"
    }
  }
}
```

### 1.2 字段定义

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `trace_id` | string | 是 | 32 hex chars（16 bytes 随机），由 SDK 生成，全链路唯一 |
| `mode` | string | 是 | `"log"` 或 `"diag"`，缺失视为 `"log"` |
| `spans` | array | 否 | 仅 `diag` 模式存在，各环节追加 |

**说明**：`mode: "off"` 不需要显式表示——不带 `_trace` 字段即为 off 状态。

### 1.3 Span 结构

```json
{
  "node": "gateway",
  "ts": 1716300000156,
  "action": "relay_in",
  "ms": 0,
  "detail": "route→message"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `node` | string | 环节标识：`sdk-{aid}`、`gateway`、`{service_name}` |
| `ts` | number | Unix 毫秒时间戳（入站时刻） |
| `action` | string | 动作：`send` / `relay_in` / `process` / `relay_out` / `deliver` |
| `ms` | number | 本环节处理耗时（出站时填写，入站初始为 0） |
| `detail` | string | 可选，关键上下文（路由目标、错误码等），最多 256 字符 |

---

## 二、链路传播流程

```
SDK-A                Gateway              Service             Gateway              SDK-B
  │                    │                    │                    │                    │
  │─── params._trace ─▶│                    │                    │                    │
  │  {trace_id, mode,  │                    │                    │                    │
  │   spans:[sdk-send]}│                    │                    │                    │
  │                    │── 追加 gateway ───▶│                    │                    │
  │                    │   转发到 service   │                    │                    │
  │                    │                    │── 追加 svc span ──▶│                    │
  │                    │                    │   返回 response    │                    │
  │                    │◀── response ───────│                    │                    │
  │                    │   追加 gateway-out │                    │                    │
  │◀── response._trace─│                    │                    │                    │
  │                    │                    │                    │                    │
  │                    │─── event._trace ──────────────────────▶│── deliver ────────▶│
```

### 2.1 各环节职责

| 环节 | 入站行为 | 出站行为 |
|------|----------|----------|
| SDK 发起 | 生成 trace_id；mode≠off 时构造 `_trace` 注入 params | — |
| Gateway 入站 | 读取 _trace，应用降级；diag 模式追加 `relay_in` span | — |
| Service 处理 | 读取 _trace 写入日志（log）或追加 span（diag） | response 透传 _trace |
| Gateway 出站 | diag 模式追加 `relay_out` span | log 模式剥离 _trace；diag 模式注入 response 顶层 |
| SDK 接收 | 提取 response._trace 回调 trace observer | — |

---

## 三、Response 回传（仅 diag 模式）

Gateway 在 `deliver_response_to_client` 中将 `_trace` 注入 response 顶层（与 `_meta` 平级）：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {"status": "ok", "message_id": "..."},
  "_meta": {"agent_md_etag": "..."},
  "_trace": {
    "trace_id": "a1b2c3...",
    "mode": "diag",
    "spans": [
      {"node": "sdk-alice.aid.com", "ts": 1716300000100, "action": "send"},
      {"node": "gateway", "ts": 1716300000123, "action": "relay_in", "ms": 2, "detail": "→message"},
      {"node": "message", "ts": 1716300000125, "action": "process", "ms": 15},
      {"node": "gateway", "ts": 1716300000142, "action": "relay_out", "ms": 1}
    ]
  }
}
```

**注意**：log 模式下 response 不带 `_trace`（保持 envelope 干净，零开销）。

---

## 四、开关层级

### 4.1 三态定义

| 值 | 行为 |
|---|---|
| `off` | 不生成 `_trace`，零开销（默认） |
| `log` | 生成 trace_id + 各环节写本地日志，response 不回传 |
| `diag` | 同 log + spans 追加 + response 回传完整链路 |

### 4.2 控制点

| 层级 | 配置位置 | 默认值 | 作用 |
|------|----------|--------|------|
| 服务端上限 | Gateway 环境变量 `AUN_TRACE_MAX_MODE` | `"log"` | 超过此级别自动降级 |
| SDK 会话级 | `client.set_trace_mode("log")` | `"off"` | 连接内所有请求默认 mode |
| SDK 调用级 | `client.rpc("method", params, trace="diag")` | 继承会话级 | 单次覆盖，优先级最高 |

### 4.3 优先级规则

```
最终 mode = min(SDK 调用级 || SDK 会话级, 服务端上限)
其中 off < log < diag
```

### 4.4 服务端降级逻辑（Gateway 入站时）

```python
client_mode = trace.get("mode", "off")
server_max = config.trace_max_mode  # "off" | "log" | "diag"
effective = min(client_mode, server_max)
if effective != client_mode:
    trace["mode"] = effective
    if effective != "diag":
        trace.pop("spans", None)  # 降级到 log/off 时丢弃已有 spans
```

**生产环境推荐配置**：`AUN_TRACE_MAX_MODE=log`，diag 需运维手动开启。

---

## 五、各组件改动点

### 5.1 SDK 侧

**`transport.py`**：
- `call()` 方法：会话/调用级 mode 非 off 时，构造 `_trace` 注入 params
- response 处理：提取 `_trace` 回调 trace observer（与现有 `_meta_observer` 模式一致）

**`client.py`**：
- 新增 `set_trace_mode(mode: str)`：设置会话级默认 mode
- `rpc()` 方法新增 `trace` 参数：单次覆盖 mode
- 暴露 `set_trace_observer(callback)`：接收 diag 模式回传的 spans

### 5.2 Gateway 侧

**`ws_server.py`**：
- `_resolve_ws_message_trace()` 改造：读取 mode，应用服务端降级
- 入站时追加 `relay_in` span（diag 模式）
- `_strip_internal_route()` 保持现状：log 模式仍剥离 `_trace`，diag 模式由 response 路径专门处理

**`relay.py`**：
- `deliver_response_to_client()`：diag 模式追加 `relay_out` span，将 `_trace` 注入 response 顶层

### 5.3 Service 侧

通用 pattern（适用于 message / group / storage / stream / mail 等所有服务）：
1. RPC 入口提取 `params._trace`
2. 处理过程中通过 trace_id 写入日志
3. diag 模式追加自身 span
4. response 透传 `_trace` 字段

---

## 六、日志格式（log 模式）

各环节按现有日志规范输出，前缀加 trace_id：

```
[2026-05-21 10:00:00.123][INFO][gateway] [trace=a1b2c3d4] relay_in method=message.send conn=42
[2026-05-21 10:00:00.125][INFO][message] [trace=a1b2c3d4] process persist=true target=bob.aid.com
[2026-05-21 10:00:00.140][INFO][gateway] [trace=a1b2c3d4] relay_out duration_ms=17
```

排查时 `grep trace=a1b2c3d4` 即可串联全链路。

---

## 七、安全约束

| 约束 | 限制 |
|------|------|
| spans 数组最大长度 | 32 条，超出由 Gateway 截断尾部 |
| 单个 detail 最大长度 | 256 字符 |
| trace_id 长度 | 严格 32 hex chars，不合规由 Gateway 重新生成 |
| 敏感信息 | spans 禁止包含消息体、密钥、Token 等，只记录路由/耗时/错误码等元数据 |
| 生产环境默认 | `AUN_TRACE_MAX_MODE=log`，diag 需运维手动开启 |
| 跨域传播 | 跨 federation 边界时保留 trace_id，spans 在边界节点视为新链路起点 |

---

## 八、跨语言实现要点

所有 SDK（Python / Go / TypeScript / JavaScript / C++）需保持一致：

1. **trace_id 生成**：16 字节加密随机数，hex 编码
2. **时间戳**：Unix 毫秒（不使用秒/纳秒），统一单位
3. **字段顺序**：JSON 字段顺序不影响语义，但建议按 `trace_id, mode, spans` 顺序输出便于阅读
4. **observer 接口**：各 SDK 提供 `set_trace_observer(callback)` 接口，签名一致
5. **会话/调用级 API 命名**：
   - 设置：`set_trace_mode(mode)` / `setTraceMode(mode)`
   - 单次覆盖：`rpc(method, params, trace=mode)` / `rpc(method, params, {trace: mode})`

---

## 九、未实现 / 后续扩展

以下能力本附录暂不覆盖，留作后续扩展：

- **采样率控制**：当前 SDK 完全控制 mode，未引入概率采样（如 1% diag）
- **OpenTelemetry 适配**：未来如需对接 Jaeger / Zipkin，可在 Gateway 端增加导出适配层，
  将 spans 转为 OTLP 格式
- **跨域链路连续性**：当前跨 federation 边界视为新链路，未实现端到端 trace_id 透传
- **span 父子关系**：当前 spans 数组仅按时间排序，未引入 parent_span_id（保持极简）

---

## 文档版本

- v1.0 — 2026-05-21 初稿，定义协议字段、链路传播、开关层级、安全约束
