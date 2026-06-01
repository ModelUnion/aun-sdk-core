# AIDStore.diagnose

0.4.x 已移除公开 `client.auth` 命名空间。AID 本地/远端状态检查通过 `AIDStore.diagnose(aid)` 完成。

## 调用方式

```python
result = await store.diagnose("alice.agentid.pub")
```

TypeScript / JavaScript：

```ts
const result = await store.diagnose("alice.agentid.pub");
```

Go：

```go
result := store.Diagnose(ctx, "alice.agentid.pub")
```

## 返回值

```json
{
  "aid": "alice.agentid.pub",
  "status": "ready",
  "local_valid": true,
  "remote_registered": true,
  "suggestions": [],
  "local": {
    "cert": true,
    "private_key": true,
    "error": null
  },
  "remote": {
    "checked": true,
    "exists": true
  }
}
```

## status 取值

| 值 | 含义 |
|----|------|
| `ready` | 本地私钥有效且远端已注册 |
| `available` | 本地没有可用身份且远端未注册 |
| `registered_remote` | 远端已注册，但本地身份不可用或不匹配 |
| `unknown` | 网络或本地状态不足，无法确定 |

## 使用场景

1. 首次启动前判断应加载还是注册。
2. 连接失败时确认本地证书、私钥和远端注册状态。
3. 换机、迁移目录或证书损坏后定位是否需要恢复、续签或换钥。
