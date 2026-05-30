# AUN SDK - API 手册

---

## 目录

- [AIDStore](#aidstore)
- [AID](#aid)
- [AUNClient](#aunclient)
- [事件](#事件)
- [E2EE 高级 API](#e2ee-高级-api)
- [RPC 方法参考](#rpc-方法参考)
- [Stream 使用指南](#stream-使用指南)

> **多语言命名约定**：Python 使用 `snake_case`（如 `aun_path`、`fetch_agent_md`），TS/JS 使用 `camelCase`（如 `aunPath`、`fetchAgentMd`），Go 使用 `PascalCase` 公开方法（如 `Load`、`Register`）。本手册表格中各列对应各语言的实际命名。

---

## AIDStore

Python：

```python
store = AIDStore(
    aun_path: str,
    encryption_seed: str,
    *,
    device_id=None,
    slot_id="default",
    verify_ssl=None,      # None=自动（由 AUN_ENV/KITE_ENV 决定），True/False=强制
    root_ca_path=None,    # 私有部署时指定自定义根证书路径
    debug=False,
)
```

TypeScript / JavaScript：

```ts
const store = new AIDStore({
  aunPath, encryptionSeed,
  deviceId, slotId,
  verifySsl,    // 同 Python verify_ssl
  rootCaPath,   // 同 Python root_ca_path
  debug,
});
```

Go：

```go
store := aun.NewAIDStore(aunPath, encryptionSeed)
// 可选配置通过 AIDStoreOptions 传入
store := aun.NewAIDStore(aunPath, encryptionSeed, aun.AIDStoreOptions{
    VerifySSL:  &[]bool{true}[0],
    RootCaPath: "/path/to/ca.crt",
    Debug:      true,
})
```

### 方法

| Python | TS/JS | Go | 说明 |
|--------|-------|----|------|
| `load(aid)` | `load(aid)` | `Load(aid)` | 从本地加载 AID |
| `register(aid)` | `register(aid)` | `Register(ctx, aid)` | 注册并落盘证书和私钥 |
| `list()` | `list()` | `List()` | 列出本地 AID |
| `exists(aid)` | `exists(aid)` | `Exists(ctx, aid)` | 远端存在性检查 |
| `resolve(aid, opts=None)` | `resolve(aid, opts?)` | `Resolve(ctx, aid, opts...)` | 拉证书、缓存、拉 agent.md 并验签；`opts.timeout` / `context.WithTimeout` 控制超时 |
| `fetch_agent_md(aid, timeout_ms=30000)` | `fetchAgentMd(aid, timeoutMs=30000)` | `FetchAgentMd(ctx, aid)` | 下载 agent.md，返回 `FetchAgentMdResult` / `AgentMDInfo` |
| `head_agent_md(aid)` | `headAgentMd(aid)` | `HeadAgentMd(ctx, aid)` | HEAD agent.md |
| `check_agent_md(aid, ttl_days=1)` | `checkAgentMd(aid, ttlDays?)` | `CheckAgentMd(ctx, aid, maxUnsyncedDays...)` | 缓存一致性检查 |
| `diagnose(aid)` | `diagnose(aid)` | `Diagnose(ctx, aid)` | 本地 + 远端诊断 |
| `renew_cert(aid)` / `rekey(aid)` | `renewCert(aid)` / `rekey(aid)` | `RenewCert(ctx, aid)` / `Rekey(ctx, aid)` | 证书运维 |
| `change_seed(old, new)` | `changeSeed(old, new)` | `ChangeSeed(old, new)` | 本地密钥保护种子迁移 |

Python / TS / JS 返回 Result 对象；Go 使用惯用 `(value, error)`。

### Result 类型

```python
# ok=True 时
{"ok": True, "data": {...}}

# ok=False 时
{"ok": False, "error": {"code": "ERROR_CODE", "message": "..."}}
```

### FetchAgentMdResult

| 字段 | 类型 | 说明 |
|------|------|------|
| `aid` | str | AID 字符串 |
| `content` | str | agent.md 原始内容 |
| `verification` | `{status, reason?}` | 验签结果；`status` 为 `"ok"` / `"no_cert"` / `"invalid"` 等 |
| `cert_pem` | str | 签名所用证书 PEM |
| `etag` | str | HTTP ETag |
| `last_modified` | str | HTTP Last-Modified |

> **v0.4.2 变更**：`discoveryPort` 配置项已移除，Gateway 地址完全由 SDK 根据 AID issuer 自动发现，无需手动指定端口。

---

## AID

AID 由 `AIDStore.load()` 返回，应用层不直接构造。

### 只读属性

| Python | TS/JS | Go | 说明 |
|--------|-------|----|------|
| `aid` | `aid` | `AID()` | AID 字符串 |
| `cert_pem` | `certPem` | `CertPEM()` | 证书 PEM |
| `public_key` | `publicKey` | `PublicKey()` | 公钥 |
| `cert_fingerprint` | `certFingerprint` | `CertFingerprint()` | 证书指纹 |
| `aun_path` | `aunPath` | `AUNPath()` | 所属数据目录 |
| `device_id` | `deviceId` | `DeviceID` | 设备 ID |
| `slot_id` | `slotId` | `SlotID` | 密钥槽 ID |
| `verify_ssl` | `verifySsl` | `VerifySSL` | 是否校验 TLS 证书 |
| `root_ca_path` | `rootCaPath` | `RootCaPath` | 自定义根证书路径 |
| `debug` | `debug` | `Debug` | 是否开启调试日志 |

### 方法

| Python | TS/JS | Go | 说明 |
|--------|-------|----|------|
| `is_cert_valid()` | `isCertValid()` | `IsCertValid()` | 证书是否有效 |
| `is_private_key_valid()` | `isPrivateKeyValid()` | `IsPrivateKeyValid()` | 私钥是否可用 |
| `sign(data)` | `sign(data)` | `Sign(data)` | 签名 bytes |
| `verify(data, signature)` | `verify(data, signature)` | `Verify(data, signature)` | 验签 |
| `sign_agent_md(content)` | `signAgentMd(content)` | `SignAgentMd(content)` | agent.md 签名 |
| `verify_agent_md(content)` | `verifyAgentMd(content)` | `VerifyAgentMd(content)` | agent.md 验签 |

---

## AUNClient

### 构造

Python：

```python
client = AUNClient()
client = AUNClient(aid)
```

TS/JS：

```ts
const client = new AUNClient();
const client = new AUNClient(aid);
```

Go：

```go
client := aun.NewAUNClientEmpty()
client := aun.NewAUNClient(aid)
```

构造约束：

- `aid` 必须是 AID 对象（由 `AIDStore.load()` 返回）。
- 不接受字符串 AID。
- 不接受把 aid 放进 options。
- 不接受旧的 `(config, debug)` 或 `(config, true)` 形态。

### 身份与状态

| Python | TS/JS | Go | 说明 |
|--------|-------|----|------|
| `load_identity(aid)` | `loadIdentity(aid)` | `LoadIdentityFromAID(aid)` | 在 `no_identity` / `closed` 状态加载身份 |
| `state` | `state` | `ConnectionState()` | 九态公开状态 |
| `gateway_url` | `gatewayUrl` | `GetGatewayURL()` | 当前连接的 Gateway URL（只读，自动发现，连接前为空） |
| `current_aid` | `currentAid` | `CurrentAID()` | 当前 AID 对象 |
| `aid` | `aid` | `AID()` | 当前 AID 字符串 |
| `has_identity` | `hasIdentity` | `HasIdentity()` | 是否已加载身份 |
| `can_sign` | `canSign` | `CanSign()` | 是否可签名 |
| `can_connect` | `canConnect` | `CanConnect()` | 是否可连接 |
| `can_send` / `is_ready` | `canSend` / `isReady` | `CanSend()` / `IsReady()` | 是否可发送 |
| `is_online` | `isOnline` | `IsOnline()` | 是否处于在线或重连相关状态 |
| `is_closed` | `isClosed` | `IsClosed()` | 是否已关闭 |

状态值：

```text
no_identity / standby / authenticated / connecting / ready /
retry_backoff / reconnecting / connection_failed / closed
```

### 生命周期

Python：

```python
auth = await client.authenticate()
await client.connect({"slot_id": "main", "auto_reconnect": True})
await client.disconnect()
await client.close()
```

说明：

- `authenticate()` 只取 token，不建立业务会话。
- `connect()` 可从 `standby` 自动认证并进入 `ready`。
- `disconnect()` 断开当前传输连接，对象仍可重新连接。
- `close()` 关闭连接和后台任务；之后只能重新加载身份再复用。

TS/JS/Go 目前保留底层双参数连接形态以兼容现有调用链，但构造入口、AID 值对象、状态机和 capability getter 已与 Python 对齐。

### RPC

```python
result = await client.call("message.send", {
    "to": "bob.agentid.pub",
    "payload": {"type": "text", "text": "hello"},
})
```

常用 meta RPC 直接透传：

```python
await client.call("meta.ping", {})
await client.call("meta.status", {})
await client.call("meta.trust_roots", {})
```

### protected_headers

```python
client = AUNClient(aid, protected_headers={"sdk": "python"})
client.set_protected_headers({"sdk": "python", "trace": "abc"})
headers = client.get_protected_headers()
```

只合并到以下 RPC：

- `message.send`
- `group.send`
- `message.thought.put`
- `group.thought.put`

### agent.md

| Python | TS/JS | Go | 说明 |
|--------|-------|----|------|
| `publish_agent_md(content=None)` | `publishAgentMd(content?)` | `PublishAgentMD(ctx)` | 发布当前 AID 的 agent.md |
| 推荐 `AIDStore.fetch_agent_md(aid)` | 推荐 `store.fetchAgentMd(aid)` | 当前用 RPC/HTTP 组合实现 | 下载并验签 |
| 推荐 `AIDStore.check_agent_md(aid)` | 推荐 `store.checkAgentMd(aid)` | 当前用 RPC/HTTP 组合实现 | 检查一致性 |

---

## 事件

```python
sub = client.on("message.received", handler)
client.off("message.received", handler)
sub.unsubscribe()
```

常用内置事件：

| 事件 | 说明 |
|------|------|
| `state_change` | 状态变化，`state` 为九态公开值 |
| `connection.error` | 连接或重连错误 |
| `token.refreshed` | token 刷新完成 |
| `message.received` | 收到 P2P 消息 |
| `message.ack` | 消息 ack |
| `message.undecryptable` | P2P E2EE 解密失败 |
| `group.changed` | 群组事件 |
| `group.message_undecryptable` | 群 E2EE 解密失败 |

---

## E2EE 高级 API

普通业务无需直接操作 E2EE manager；`message.send` / `group.send` 默认加密并自动解密收到的消息。

高级场景可使用：

| API | 说明 |
|-----|------|
| `client.e2ee.encrypt_message(...)` | 裸 WebSocket 或特殊集成中的 P2P 加密 |
| `client.e2ee.decrypt_message(...)` | 裸消息解密 |
| `client.e2ee.generate_prekey()` | 生成 prekey |
| `client.e2ee.invalidate_prekey_cache(peer_aid)` | 清理对端 prekey 缓存 |
| `client.group_e2ee.encrypt(...)` | 群消息加密 |
| `client.group_e2ee.decrypt(...)` | 群消息解密 |
| `client.group_e2ee.current_epoch(group_id)` | 查询当前群 epoch |

---

## RPC 方法参考

| 领域 | 手册 | 关键方法 |
|------|------|----------|
| 消息 | [09-message-rpc-manual.md](09-message-rpc-manual.md) | `message.send` / `message.pull` / `message.ack` / `message.thought.*` |
| 群组 | [09-group-rpc-manual.md](09-group-rpc-manual.md) | `group.create` / `group.invite` / `group.send` / `group.v2.*` |
| 存储 | [09-storage-rpc-manual.md](09-storage-rpc-manual.md) | `storage.upload` / `storage.download` / `storage.share` |
| 元信息 | [09-meta-rpc-manual.md](09-meta-rpc-manual.md) | `meta.ping` / `meta.status` / `meta.trust_roots` |
| Stream | [09-stream-rpc-manual.md](09-stream-rpc-manual.md) | `stream.create` / `stream.close` / `stream.list_active` |

---

## Stream 使用指南

创建流：

```python
stream = await client.call("stream.create", {
    "kind": "audio",
    "metadata": {"sample_rate": 16000},
})
```

查询流：

```python
info = await client.call("stream.get_info", {"stream_id": stream["stream_id"]})
```

关闭流：

```python
await client.call("stream.close", {"stream_id": stream["stream_id"]})
```
