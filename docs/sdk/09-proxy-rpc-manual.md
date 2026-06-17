# Service Proxy — RPC Manual

## 方法索引

### Gateway 控制面方法

| 方法 | 说明 |
|------|------|
| [proxy.register_services](#proxyregister_services) | 注册当前 Gateway 长连接可提供的 Service Proxy 服务列表 |
| [proxy.unregister_services](#proxyunregister_services) | 注销当前 Gateway 长连接上的部分或全部服务列表 |
| [proxy.list_services](#proxylist_services) | 查询当前 Gateway 长连接已注册的服务列表 |

### proxy-server 数据面隧道消息

| 消息 | 方向 | 说明 |
|------|------|------|
| [register_services](#register_services-隧道消息) | proxy-client → proxy-server | proxy-server 隧道认证后注册本连接的数据面服务列表 |
| `register_services_ack` | proxy-server → proxy-client | 数据面服务注册成功确认 |

---

## 控制面与数据面

Service Proxy 有两层注册，二者都必须存在：

- **Gateway 控制面**：provider 的 AUN 长连接调用 `proxy.register_services`，Gateway 记录该 provider 在线且声明了哪些服务。proxy-server 用它判断 provider 是否在线、目标服务是否声明、是否应该 wakeup。
- **proxy-server 数据面**：proxy-client 连接 proxy-server 的 `/ws/client` 并完成认证后，必须再发送 `register_services` 隧道消息。proxy-server 只会向本地已注册目标服务的数据面连接转发请求。

服务列表与连接绑定。Gateway 长连接断开后，Gateway 上的服务列表立即失效；proxy-server 隧道断开后，proxy-server 上的服务列表立即失效。

同一个 provider AID 可以有多个实例连接，但所有实例注册的服务摘要必须一致。若同一 provider AID 的第二条连接注册了不同服务列表，服务端应拒绝该次注册并返回 `proxy_services_inconsistent`。

---

## 服务摘要

服务摘要只描述可公开发现的服务能力，不包含本地 endpoint。

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `service_name` | string | 是 | 服务名，建议使用 `[a-z0-9_-]+` |
| `service_type` | string | 否 | 服务类型，默认 `http`；常见值为 `http` / `websocket` / `sse` / `mcp` |
| `visibility` | string | 否 | 可见性，默认 `private` |
| `metadata` | object | 否 | 非敏感描述信息。服务端会移除 token、secret、endpoint、url、cookie、key、cert 等敏感字段 |

Python `ServiceProxyClient.register_service()` 会保存本地 endpoint，但 `list_service_summaries()`、Gateway 注册和 proxy-server 注册只发送摘要。

---

## proxy.register_services

注册当前 Gateway 长连接提供的 Service Proxy 服务列表。服务端必须以连接认证得到的 AID 作为 provider AID，不能信任客户端传入的 `provider_aid` 覆盖认证身份。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `provider_aid` | string | 否 | 兼容字段或诊断字段；服务端以认证身份为准 |
| `services` | array | 是 | 服务摘要列表 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `ok` | boolean | 固定为 `true` |
| `provider_aid` | string | 认证后的 provider AID |
| `connection_id` | string | Gateway 连接 ID |
| `count` | integer | 已注册服务数量 |
| `services` | array | 服务端清洗后的服务摘要列表 |

### 示例

```python
result = await client.call("proxy.register_services", {
    "services": [
        {
            "service_name": "fileshare",
            "service_type": "http",
            "visibility": "public",
            "metadata": {"label": "Files"},
        }
    ],
})
```

### 错误

| JSON-RPC code | message | 原因 |
|---------------|---------|------|
| -32602 | `proxy service registration requires a long connection` | 短连接不能注册 Service Proxy 服务 |
| -32020 | `proxy_services_inconsistent` | 同一 provider AID 的已有连接注册了不一致的服务列表 |

---

## proxy.unregister_services

注销当前 Gateway 长连接上的部分或全部服务。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `service_names` | array | 否 | 要注销的服务名列表；省略时注销当前连接上的全部服务 |
| `service_name` | string | 否 | 单服务兼容字段 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `ok` | boolean | 固定为 `true` |
| `provider_aid` | string | 认证后的 provider AID |
| `connection_id` | string | Gateway 连接 ID |
| `removed` | array | 实际移除的服务名 |
| `count` | integer | 剩余服务数量；全部注销时可省略 |

### 示例

```python
await client.call("proxy.unregister_services", {
    "service_names": ["fileshare"],
})
```

---

## proxy.list_services

查询当前 Gateway 长连接已注册的 Service Proxy 服务列表。

### 参数

无有效参数。`provider_aid` 若存在，也只能作为兼容字段；服务端以当前连接身份为准。

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `provider_aid` | string | 当前连接认证后的 AID |
| `connection_id` | string | Gateway 连接 ID |
| `services` | array | 当前连接已注册的服务摘要列表 |

### 示例

```python
current = await client.call("proxy.list_services", {})
```

---

## register_services 隧道消息

proxy-client 连接 proxy-server `/ws/client` 并收到 `service_proxy_auth_response.ok=true` 后，必须立即发送 `register_services` 隧道消息。proxy-server 只根据这个数据面注册表选择实际转发连接。

### 请求

```json
{
  "type": "register_services",
  "request_id": "register-services",
  "services": [
    {
      "service_name": "fileshare",
      "service_type": "http",
      "visibility": "public",
      "metadata": {"label": "Files"}
    }
  ]
}
```

### 成功响应

```json
{"type": "register_services_ack", "request_id": "register-services", "ok": true, "count": 1}
```

### 失败响应

```json
{
  "type": "service_proxy_error",
  "request_id": "register-services",
  "error": {
    "code": "proxy_services_inconsistent",
    "message": "provider service list is inconsistent with existing connections"
  }
}
```

---

## Python ServiceProxyClient

Python SDK 的 `ServiceProxyClient` 已封装双注册流程：

1. `connect_once()` / `serve_once()` / `serve_forever()` 建立 proxy-server 隧道前，会在存在 `aun_client.call()` 时自动调用 `proxy.register_services`。
2. proxy-server 连接地址必须通过 `/.well-known/aun-proxy` 发现：先读 provider AID SQLite metadata 中 1 小时 TTL 的 `service_proxy_discovery` 缓存；缓存缺失或过期时查询 `https://{provider_aid}/.well-known/aun-proxy`，失败后回退 `https://proxy.{issuer}/.well-known/aun-proxy`。应用不得传入、配置或硬拼 proxy-server URL。
3. proxy-server 隧道使用 AUN auth token 鉴权：优先复用 cached access token；缓存缺失或过期时，必须通过 `aun_client.authenticate()` 经 Gateway 两步登录刷新 token。
4. proxy-server 隧道认证成功后，会自动发送 `register_services` 隧道消息。
5. persistent 和 on-demand 重连时，每条新连接都会重新执行以上流程。

常用入口：

| 方法 | 说明 |
|------|------|
| `register_service(name, endpoint, service_type="http", visibility="private", metadata=None)` | 注册本地 embedded endpoint |
| `unregister_service(name)` | 移除本地 endpoint |
| `list_service_summaries()` | 返回可上报的服务摘要 |
| `register_services_with_gateway()` | 显式向 Gateway 注册控制面服务列表 |
| `unregister_services_from_gateway(names=None)` | 显式从 Gateway 注销控制面服务 |
| `list_gateway_services()` | 查询 Gateway 当前连接服务列表 |
| `register_services_with_proxy_server(ws)` | 通过已认证 proxy-server 隧道注册数据面服务列表 |
| `discover_proxy_server(force_refresh=False)` | 通过缓存 / well-known 发现 proxy-server |
| `serve_once()` / `serve_forever()` | 连接 proxy-server 并处理转发请求 |

---

## 路由与 wakeup 语义

proxy-server 收到 `https://proxy.{issuer}/{user_name}/{svc_name}` 或对应 WebSocket 请求时，应按以下顺序处理：

1. 本 proxy-server 已有 `(provider_aid, service_name)` 数据面连接：直接转发，并按 visitor/provider/service 维持稳定粘性。
2. provider 已连接本 proxy-server 且已注册服务列表，但没有目标服务：返回 `service_not_registered`，不 wakeup。
3. provider 未连接本 proxy-server：查询 Gateway 控制面。
4. Gateway 检查 provider AID 证书不存在：返回 `provider_aid_not_found`；证书查询失败：返回 `provider_aid_check_failed`。
5. Gateway 显示 provider 没有在线长连接：返回 `provider_offline`。
6. Gateway 显示 provider 在线但未声明目标服务：返回 `service_not_registered`，不 wakeup。
7. Gateway 显示 provider 在线且声明目标服务：仅向注册了该服务的 provider 连接发送 wakeup。
8. wakeup 已投递但本 proxy-server 等不到目标数据面隧道注册时，返回 `provider_wakeup_timeout`。

因此，只向 Gateway 注册不足以承载请求；只有 proxy-server 数据面也注册了目标服务，访问才会真正转发。


