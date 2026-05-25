# auth.check_aid

检查 AID 的本地密钥/证书完整性和远程注册状态。

## 调用方式

```python
result = await client.auth.check_aid({"aid": "alice.agentid.pub"})
```

## 参数

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| aid | string | 是 | 要检查的 AID |

## 返回值

```json
{
  "aid": "alice.agentid.pub",
  "status": "local_ready",
  "can_register": false,
  "local": {
    "exists": true,
    "complete": true,
    "private_key": true,
    "public_key": true,
    "certificate": {
      "present": true,
      "valid": true,
      "expired": false,
      "not_before": "2025-01-01T00:00:00+00:00",
      "not_after": "2026-01-01T00:00:00+00:00",
      "expires_at": 1767225600,
      "seconds_until_expiry": 31536000,
      "fingerprint": "sha256:abcdef...",
      "subject_cn": "alice.agentid.pub",
      "aid_matches": true
    },
    "issues": []
  },
  "remote": {
    "status": "not_checked"
  }
}
```

## status 取值

| 值 | 含义 |
|----|------|
| `local_ready` | 本地密钥和证书完整，可直接连接 |
| `local_incomplete` | 本地缺少私钥/公钥/证书，需要检查远程 |
| `available` | 本地不完整且远程未注册，可以注册 |
| `registered_remote` | 本地不完整但远程已注册（需要恢复或重新导入） |
| `unknown` | 无法确定状态（网络错误等） |

## can_register 取值

| 值 | 含义 |
|----|------|
| `true` | AID 可注册（远程未占用） |
| `false` | AID 不可注册（本地已就绪或远程已占用） |
| `null` | 无法确定（本地已就绪时不检查远程） |

## 使用场景

1. **首次启动**：检查 AID 是否已存在，决定是创建还是恢复
2. **连接前检查**：确认本地密钥完整性，避免连接失败
3. **证书续期提醒**：检查 `seconds_until_expiry` 判断是否需要续期
4. **多设备同步**：检查远程注册状态，判断是否需要导入密钥

## 跨语言调用

```typescript
// TypeScript / JavaScript
const result = await client.auth.checkAid({ aid: 'alice.agentid.pub' });

// Go
result, err := client.Auth.CheckAID(ctx, map[string]any{"aid": "alice.agentid.pub"})

// C++
client->Auth()->CheckAID("alice.agentid.pub", [](Result r, json result) { ... });
```
