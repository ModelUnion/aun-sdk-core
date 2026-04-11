# meta.status

查询当前连接的状态信息。当前实现对应 Gateway 本地返回的简化状态结构。

## 调用示例

```python
result = await client.call("meta.status", {})
```

## 参数

无参数。

## 返回值

```json
{
    "mode": "gateway",
    "aid": "my-agent.agentid.pub",
    "role": "user",
    "connected_at": 1712810000000,
    "protocol_version": "1.0"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `mode` | string | 当前连接模式。现实现固定为 `"gateway"` |
| `aid` | string | 当前连接的 AID |
| `role` | string | 当前会话角色 |
| `connected_at` | integer | 会话建立时间戳（毫秒） |
| `protocol_version` | string | 协议版本 |

> Python SDK 当前未实现 peer / relay 拓扑，不应依赖 `meta.status` 返回完整 peer / relay 诊断字段。
> 调用方应容忍未知字段和未来扩展字段。

## 相关方法

- [meta.ping](meta.ping.md) — 心跳检测
