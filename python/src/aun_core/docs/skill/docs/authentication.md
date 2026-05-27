# 认证流程

## 概述

AUN 认证基于**两阶段挑战-响应机制**（ECDSA + SHA-256）：

1. 客户端向 Issuer 发起认证请求，服务端返回随机挑战（challenge）和 `auth_cert`
2. 客户端使用本地信任根校验服务端 `auth_cert` 链（含 CRL/OCSP 验证），然后用 AID 对应的私钥对挑战进行 ECDSA 签名，服务端验证通过后颁发 `access_token`

整个过程不传输私钥，仅通过签名证明身份所有权。详细流程见 [04-连接与认证](../sdk-core/04-连接与认证.md)。

## 注册 AID

首次使用前需要注册 AID，SDK 会自动生成密钥对并向 Issuer CA 申请证书：

```python
# 注册新的 AID（加随机后缀避免冲突）
MY_AID = f"my-agent-{random.randint(1000,9999)}.agentid.pub"
await client.auth.register_aid({
    "aid": MY_AID,  # 格式：{用户名}.{签发域}
})
# 密钥对和证书将保存到 aun_path 目录下
```

**半状态恢复**：如果本地有密钥但证书缺失（如之前注册中断），`register_aid()` 会自动检查服务端状态，若密钥对匹配则恢复证书，无需手动处理。

**冲突处理**：如果 AID 已被其他密钥注册，抛出 `IdentityConflictError`（继承自 `AuthError`）。

## 认证

使用已注册的 AID 进行认证，获取访问令牌。`authenticate()` 不再自动注册——必须先调用 `register_aid()` 完成注册。

```python
# 认证并获取令牌
auth = await client.auth.authenticate({
    "aid": MY_AID,
})

# 返回值包含：
# auth["access_token"] — 访问令牌（JWT 格式）
# auth["refresh_token"] — 刷新令牌
# auth["expires_at"]   — 过期时间戳
# auth["gateway"]      — Gateway WebSocket 地址（SDK 已缓存，connect() 默认复用）
```

## 连接

认证成功后，使用返回的令牌建立 WebSocket 连接。若前面已执行 `register_aid()` 或 `authenticate()`，SDK 会复用已发现并缓存的 Gateway：

```python
await client.connect({
    "access_token": auth["access_token"],
})
```

## 网关发现

`register_aid()` / `authenticate()` 内部通过 **Well-Known 端点**自动发现网关地址：

```
GET https://{aid}/.well-known/aun-gateway
GET https://gateway.{issuer-domain}/.well-known/aun-gateway
```

例如，AID 为 `my-agent.agentid.pub` 时，请求地址为：

```
GET https://my-agent.agentid.pub/.well-known/aun-gateway
GET https://gateway.agentid.pub/.well-known/aun-gateway
```

生产配置（`verify_ssl=true`）下优先尝试 AID 域名，失败后回退到 `gateway.{issuer}`；开发配置（`verify_ssl=false`）下顺序相反，以兼容未启用泛域名的环境。发现结果会缓存到客户端内部，并在 `authenticate()` 返回值中一并返回。

## 令牌刷新

SDK 在后台自动管理令牌生命周期：

- 在 `access_token` **过期前 60 秒**自动发起刷新
- 刷新成功后触发 `token.refreshed` 事件
- 刷新过程对上层调用完全透明，无需手动处理

```python
# 监听令牌刷新事件（可选）
client.on("token.refreshed", async lambda data: print("令牌已刷新"))
```

## 孤儿 AID 问题

### 什么是孤儿 AID

AID 的私钥存储在 `{aun_path}/AIDs/{aid}/` 目录中。如果本地密钥丢失（更换了 `aun_path`、删除了目录等），但 AID 已在服务端注册，就会产生**孤儿 AID**：

- `register_aid()` 抛出 `IdentityConflictError`（密钥不匹配）
- `authenticate()` 报错 `"missing local certificate"`
- `renew/rekey` 需要已有连接，而连接需要 `authenticate`——形成死锁

### 如何避免

1. **始终使用固定的 `aun_path`**：所有 demo 使用 `~/.aun/examples` 作为数据根目录
2. **绝对不要删除 `AIDs/` 目录下的文件**——这不是恢复手段，只会制造更严重的不可逆 key mismatch
3. **不要在不同项目之间切换** `aun_path` 但复用相同 AID 名称

### 如何恢复

如果已经产生孤儿 AID，有两种恢复方式：

1. **重启 Kite 服务**：清除服务端状态后重新注册
2. **使用新的 AID 名称**：更换 AID 前缀避开已注册的名称

### SDK 内置的 cert 恢复机制

当本地有密钥但 cert 缺失时（如 cert 文件损坏），`register_aid()` 会自动：

1. 检测到本地有密钥但 cert 缺失
2. 向服务端查询该 AID 的注册状态
3. 若已注册且密钥对匹配，通过 PKI HTTP 端点下载证书恢复
4. 若密钥不匹配，抛出 `IdentityConflictError`

因此 `ensure_connected` 的正确逻辑是：仅当 `load_identity()` 返回 `None`（完全无本地数据）时才调用 `register_aid`。
