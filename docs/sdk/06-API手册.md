# AUN SDK - API 手册

---

## 目录

- [AIDStore](#aidstore)
- [AID](#aid)
- [AUNClient](#aunclient)
- [事件](#事件)
- [ServiceProxyClient](#serviceproxyclient)
- [E2EE 高级 API](#e2ee-高级-api)
- [RPC 方法参考](#rpc-方法参考)
- [Stream 使用指南](#stream-使用指南)

> **多语言命名约定**：Python 使用 `snake_case`（如 `aun_path`、`download_agent_md`），TS/JS 使用 `camelCase`（如 `aunPath`、`downloadAgentMd`），Go 使用 `PascalCase` 公开方法（如 `Load`、`Register`）。本手册表格中各列对应各语言的实际命名。

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
| `resolve(aid, opts=None)` | `resolve(aid, opts?)` | `Resolve(ctx, aid, opts...)` | 拉证书并缓存；默认下载 agent.md，可用 `skip_agent_md` / `skipAgentMd` 跳过 |
| `upload_agent_md(aid, content=None)` | `uploadAgentMd(aid, content?)` | `UploadAgentMD(ctx, aid, content...)` | 发布本地 AID 的 agent.md；签名后使用该 AID 的 access_token 上传 |
| `download_agent_md(aid, timeout_s=None)` | `downloadAgentMd(aid, timeoutMs=30000)` | `DownloadAgentMD(ctx, aid)` | 下载 agent.md，返回 `DownloadAgentMdResult` / `AgentMDInfo` |
| `check_agent_md(aid, ttl_days=1)` | `checkAgentMd(aid, ttlDays=1)` | `CheckAgentMD(ctx, aid, maxUnsyncedDays...)` | 通过 HEAD 和本地记录检查一致性 |
| `diagnose(aid)` | `diagnose(aid)` | `Diagnose(ctx, aid)` | 本地 + 远端诊断 |
| `renew_cert(aid)` / `rekey(aid)` | `renewCert(aid)` / `rekey(aid)` | `RenewCert(ctx, aid)` / `Rekey(ctx, aid)` | 证书运维 |
| `change_seed(old, new)` | `changeSeed(old, new)` | `ChangeSeed(old, new)` | 本地密钥保护种子迁移 |

Python、TS/Node 与 Go 的 `AIDStore` 本地方法返回 Result 包装；浏览器 JS 因 IndexedDB / WebCrypto 约束返回 `Promise<Result>`。联网方法在 TS/JS 中均返回 `Promise<Result>`；Go 形态为 `Result[T]`，字段为 `Ok` / `Data` / `Error`。

### Result 类型

```python
# ok=True 时
{"ok": True, "data": {...}}

# ok=False 时
{"ok": False, "error": {"code": "ERROR_CODE", "message": "..."}}
```

### DownloadAgentMdResult

| 字段 | 类型 | 说明 |
|------|------|------|
| `aid` | str | AID 字符串 |
| `content` | str | agent.md 原始内容 |
| `verification` | `{status, reason?}` | 验签结果；`status` 为 `"ok"` / `"no_cert"` / `"invalid"` 等 |
| `signature` | dict | 低层签名解析和验签结果 |
| `cert_pem` | str | 签名所用证书 PEM |
| `etag` | str | HTTP ETag |
| `last_modified` | str | HTTP Last-Modified |
| `status` | int | HTTP 状态码；异常 304 且本地有内容时可返回 304 |
| `in_sync` | bool\|null | 目标是当前 AID 时表示本地内容 ETag 是否等于远端 ETag；对端 AID 通常为 null |
| `saved_to` | str | SDK 管理的本地 agent.md 位置或浏览器 logical key |

### CheckAgentMdResult

| 字段 | 类型 | 说明 |
|------|------|------|
| `aid` | str | AID 字符串 |
| `local_found` | bool | 本地是否有 agent.md 内容或本地 ETag |
| `remote_found` | bool | 远端 HEAD 是否发现 agent.md |
| `local_etag` | str | 本地内容 SHA-256 ETag |
| `remote_etag` | str | 远端 HTTP ETag |
| `in_sync` / `needs_update` | bool | 是否同步 / 是否需要下载 |
| `last_modified` | str | 远端 Last-Modified |
| `status` | int | HEAD 状态码 |
| `cached` | bool | 是否命中 TTL 窗口内的本地检查记录 |
| `verify_status` / `verify_error` | str | 最近一次下载验签状态 |

agent.md 本地记录不写入 SQLite。Python / TypeScript / Go 使用 `{aun_path}/AIDs/{aid}/agent.md` 与 `agentmd.json`；浏览器 JavaScript 使用 IndexedDB 等价 key，存储不可用时退化为内存缓存。

`remote_etag` / `last_modified` 除了来自 `check_agent_md()` 的 HEAD，也会由连接后的内部观察器更新：SDK 会读取 RPC response / event push `_meta.agent_md_etags` 的 `requester`、`peer`、`group` 及兼容别名，并读取 V2 envelope 的 `agent_md.sender` / `agent_md.group`。`group` 记录使用群自身 `group_aid` / `group_id` 作为 AID key。

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
| `slot_id` | `slotId` | `SlotID` | 实例槽位 ID；允许 `/`、`:`、空格作为共享隔离键分隔符 |
| `verify_ssl` | `verifySsl` | `VerifySSL` | 是否校验 TLS 证书 |
| `root_ca_path` | `rootCaPath` | `RootCaPath` | 自定义根证书路径 |
| `debug` | `debug` | `Debug` | 是否开启调试日志 |
| `private_key_pem` | `privateKeyPem` | `PrivateKeyPem` | 明文私钥 PEM（由 `AIDStore.load()` 注入，空字符串表示无私钥）|

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
| `load_identity(aid)` | `loadIdentity(aid)` | `LoadIdentity(aid)` | 在 `no_identity` / `closed` 状态加载身份 |
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

四个 SDK 的公开构造入口均已对齐为“无参或 AID 对象”。调试、TLS、根证书、device_id、slot_id 等配置由 `AIDStore` 传递到 AID，再由 `AUNClient` 继承；连接级选项只传给 `connect()`。

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

### Notify

`notify()` 发送轻量在线通知，底层是 JSON-RPC Notification，无 `id`，不进入离线存储、seq、pull 或 ack。

| Python | TS/JS | Go | 说明 |
|--------|-------|----|------|
| `notify(method, params=None, *, to=None, group_id=None, device_id=None, slot_id=None, ttl_ms=None)` | `notify(method, params?, options?)` | `Notify(ctx, method, params, NotifyOptions{...})` | 发送在线轻量通知 |

常见用法：

```python
await client.notify("notification/client.activity", {"state": "idle"})
await client.notify("event/app.typing", {"thread_id": "t1"}, to="bob.agentid.pub", ttl_ms=5000)
await client.notify("event/app.presence", {"state": "active"}, group_id="g-abc123.agentid.pub")
```

路由选项：

| 选项 | 说明 |
|------|------|
| `to` / `To` | 目标 AID；可同域或跨域 |
| `group_id` / `groupId` / `GroupID` | 目标群；兼容参数名，值使用目标态 `group_aid`，与 `to` 互斥 |
| `device_id` / `deviceId` / `DeviceID` | 限定目标 AID 的在线设备；必须配合 `to` |
| `slot_id` / `slotId` / `SlotID` | 限定目标设备的在线 slot；必须配合 `device_id` |
| `ttl_ms` / `ttlMs` / `TTLMS` | `0..60000`，只控制在线投递过期，不表示离线缓存 |

约束：

- 未指定 `to` / `group_id` 时，`method` 必须以 `notification/` 开头，表示直发 Gateway 的协议级通知。
- 指定 `to` 或 `group_id` 时，`method` 必须是 `event/app.*`，接收端通过 `client.on("app.xxx", handler)` 订阅。
- 跨域 AID notify 已支持 federation 在线转发，但仍是 best-effort；目标离线或 federation 不可用时丢弃。
- 可靠、敏感或需要审计的业务事件应继续使用 `message.send` / `group.send`。

详细语义见 [Notify通知方案.md](Notify通知方案.md)。

### protected_headers

```python
client = AUNClient(aid)
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
| `AIDStore.upload_agent_md(aid, content=None)` | `store.uploadAgentMd(aid, content?)` | `store.UploadAgentMD(ctx, aid, content...)` | 发布指定本地 AID 的 agent.md |
| `AIDStore.download_agent_md(aid)` | `store.downloadAgentMd(aid)` | `store.DownloadAgentMD(ctx, aid)` | 下载并验签 |
| `AIDStore.check_agent_md(aid)` | `store.checkAgentMd(aid)` | `store.CheckAgentMD(ctx, aid, maxUnsyncedDays...)` | 检查一致性 |

说明：

- agent.md 上传、下载和检查入口都在 `AIDStore`；`AUNClient` 不再暴露上传入口。
- 上传要求目标 AID 已在本地加载且私钥有效；SDK 会对正文签名，并通过 `AuthFlow` 获取或复用该 AID 的 access_token。
- SDK 发起 GET 时只发送 `Accept: text/markdown`，不主动发送 `If-None-Match` / `If-Modified-Since`。如果服务端异常返回 304，本地有内容则复用；无内容时再发一次无条件 GET。
- SDK 会自动从 Gateway `_meta.agent_md_etags` 和信封 `agent_md` 观察远端版本；`requester`、`peer`、`group` 是标准角色键，`receiver`、`target`、`to`、`sender`、`from` 是兼容别名。
- `Accept: text/markdown` 与 agent.md 的 YAML frontmatter + Markdown 格式兼容；agent.md 仍是 Markdown 媒体类型上的结构化约定。

---

## 业务门面

除 `client.call(method, params)` 外，四语言 SDK 提供高层门面（Facade），封装常用操作并简化参数。普通应用优先用门面，只有需要精确控制底层参数时再直调 RPC。

### 文件与存储门面

| 能力 | Python | TS/JS | Go | 说明 |
|------|--------|-------|----|------|
| Storage VFS | `client.storage` | `client.storage` | `client.Storage()` | 类 POSIX 文件操作；上传自动选择 inline / session / 秒传，下载自动选择 inline / ticket；支持 `touch`、`find`、`du`、`df`、ACL/token/软链/挂载门面 |
| Collab | `client.collab` | `client.collab` | `client.Collab()` | 版本化文档、标签、`gc` / `reflog` / `revert` |
| Group FS | `client.group.fs` | `client.group.fs` | `client.Group().FS()` | POSIX 风格群文件系统；`ls/find/stat/lstat/mkdir/rm/cp/mv/df/mount/umount`，以及 `set_acl/remove_acl/get_acl/list_acl` 角色 ACL 门面，上传下载数据面由 SDK 编排 |

群文件系统路径统一使用 `group_aid:/...`，成员数据区使用 `group_aid:/memberdata/{member_ref}/...`。SDK 不拼接真实 storage 路径，`memberdata` 到成员 `group_data/{group_aid}` 的映射只在服务端完成。群自有区写入允许当前 `group_aid` 证书签名；成员角色中 `owner/admin` 默认可写群自有区，`member` 默认不可写。`owner/admin` 可通过 `group.fs.set_acl` 对特定业务目录授予 `role:member` 的 `rw` 权限，用于后续群协作场景；`rw` 只允许创建/写入，不授予删除、移动、重命名权限。`rwd` 是 storage 内部权限位，SDK/RPC 对外按 POSIX 视图显示为 `rwx`，不给删除/移动/重命名权限时只使用 `rw`。`.group/` 是系统控制目录，默认给 `owner/admin` 写权限，用于群公告、群规则、入群要求附件，不能向 `role:member` 授权。老群如果缺少 `.group/` 默认 ACL，group 服务会在该群首次被 RPC 访问时 best-effort 触发 namespace/ACL lazy repair；ACL 同步全部成功后才记录本进程已检查，失败会在后续访问继续重试。JS 浏览器版上传中 `string` 默认表示文本内容，Node 本地路径需显式 `sourceType: "path"`、`localPath: true` 或 `local:` 前缀；Python/TS/Go 默认把 `string` 当本地路径。

### 消息与群组门面

| 能力 | Python | TS/JS | Go | 说明 |
|------|--------|-------|----|------|
| Message | `client.message` | `client.message` | `client.Message()` | 消息便利方法：`send()`、`pull()`、`ack()`、`recall()`、`queryOnline()` |
| Message Thought | `client.message.thought` | `client.message.thought` | `client.Message().Thought()` | P2P 思考内容：`put()`、`get()`（不持久化、不分配 seq、强制 E2EE） |
| Group | `client.group` | `client.group` | `client.Group()` | 群组便利方法：`create()`、`send()`、`pull()`、`ack()`、群管理方法、群查询方法、群设置便利方法 |
| Group Thought | `client.group.thought` | `client.group.thought` | `client.Group().Thought()` | 群思考内容：`put()`、`get()`（不持久化、不分配 seq、强制 E2EE） |
| Stream | `client.stream` | `client.stream` | — | 流式数据：`createStream()`、`sendChunk()`、`endStream()`、`subscribeStream()` |

**群查询方法**：`GroupFacade` 提供三个查询方法，适用不同场景：

- `getBasic()` — 查询群组基础信息（嵌套格式 `{found, group_id, group: {...}}`），**SDK 内部逻辑使用**
- `getInfo()` — 查询群组信息（扁平化格式，提升常用字段到顶层），**推荐外部使用**
- `info()` — 查询群组详细信息（带权限控制，非成员只能看公开群，成员能看 seq/epoch 等运行时状态）

**群设置便利方法**：`GroupFacade` 提供向后兼容的便利方法：

- `getAnnouncement()` / `updateAnnouncement()` — 群公告
- `getRules()` / `updateRules()` — 群规则
- `getJoinRequirements()` / `updateJoinRequirements()` — 入群要求
- `getSettingWithIndex()` / `updateSettingWithIndex()` — 通用文档型 indexed setting（Python 为 `get_setting_with_index()` / `update_setting_with_index()`，Go 为 `GetSettingWithIndex()` / `UpdateSettingWithIndex()`）

读取方法优先返回 SDK 本地缓存；本地没有对应值时才读取相应 settings 做初始化。便利读取从服务端拿到 canonical `group_aid` 后，会同时以 canonical `group_aid` 和本次入参 `group_id` 写入 settings cache，避免 legacy/base `group_id` 下一次读取直接 cache miss。即使 `checkGroupIndex` 观察到远端 etag 与本地 etag 不一致，`getAnnouncement()` / `getRules()` / `getJoinRequirements()` / `getSettingWithIndex()` 也不会自动拉取远端版本覆盖本地缓存。`updateAnnouncement()` / `updateRules()` / `updateJoinRequirements()` / `updateSettingWithIndex()` 属于 indexed 写入，内部会调用 `updateGroupIndex` 生成签名 `group.index` 并带 `expected_index_etag` CAS 提交。

`getSettingWithIndex()` / `updateSettingWithIndex()` 比三对预定义方法多一个 `keyName`（Python 可传 `key_name`，Go 同时接受 `keyName` / `key_name`）。SDK 会生成 `{keyName}.content` 和 `{keyName}.attachments` 两个 settings key；`keyName` 只能是受控文档名（`^[A-Za-z][A-Za-z0-9_-]{0,63}$`，且不能使用 `join` 等保留前缀）。`getRules()` / `updateRules()` 与 `getAnnouncement()` / `updateAnnouncement()` 是该通用方法在 `rules`、`announcement` 上的薄封装；`getJoinRequirements()` / `updateJoinRequirements()` 保持结构化 schema，不改成 `join.content`。

这些 `update*` 便利方法只更新群设置元数据：`updateRules()` / `updateAnnouncement()` / `updateSettingWithIndex()` 写入 `*.content` 与 `*.attachments`，`updateJoinRequirements()` 写入 `join.mode` / `join.question` / `join.auto_approve_patterns` / `join.max_pending` / `join.attachments`。`attachments` 只保存稳定引用，附件实体应先上传到 group.fs 群自有区，推荐路径为 `group_aid:/.group/attachments/{rules|announcement|join|<keyName>}/...`。

**Group Index 高级同步方法**：`group.index` 是 SDK 内部签名 manifest，用于记录群公告、群规则、入群要求及附件稳定引用的版本。SDK 观察 `_meta.group_indexes` 后只记录远端 etag；etag 不一致只表示本地与观察到的远端版本不同，可能是远端更新，也可能是本地有未提交修改。应用层需要显式选择 pull 远端或 push 本地。

| 语义 | Python | TS/JS | Go | 说明 |
|------|--------|-------|----|------|
| 检查 index 是否不同步 | `client.group.check_group_index({...})` | `client.group.checkGroupIndex({...})` | `client.Group().CheckGroupIndex(ctx, params)` | 本地判断，不发网络请求；返回 `local_found/remote_found/local_etag/remote_etag/in_sync/needs_update/last_modified/status/cached` |
| 显式 pull 远端 index | `client.group.get_group_index({...})` | `client.group.getGroupIndex({...})` | `client.Group().GetGroupIndex(ctx, params)` | 调用 `group.get_settings(keys=["group.index"])` 摘取 manifest，并按 entry etag 只拉取变化的 db settings 写入本地缓存 |
| 显式 push 本地 indexed settings + index | `client.group.update_group_index({...})` | `client.group.updateGroupIndex({...})` | `client.Group().UpdateGroupIndex(ctx, params)` | 先读取当前 index 得到 `expected_index_etag`，在远端基线上合并本地变更，生成签名 `group.index` 后 CAS push |

`getGroupIndex` pull 验签成功后会持久化本地视图。Python / TypeScript(Node) / Go 使用 `{aun_path}/AIDs/{local_aid}/groups/{group_aid}/index.jsonl` 保存签名 `group.index.body` 原文，并用同目录 `group-index-cache.json` 保存 `local_etag`、`remote_meta`、`settings`、`entry_etags` 等 cache envelope。浏览器 JavaScript 使用 IndexedDB `group_index_cache` store 的等价记录，按 `local_aid + group_aid` 隔离。普通便利读取可额外写入本次请求 `group_id` 的 settings cache alias；签名正文和 `getGroupIndex` 视图仍以 canonical `group_aid` 为准。不要使用 `{aun_path}/AIDs/{group_aid}/`，也不要使用旧单文件 `group-index.json`。

#### checkGroupIndex — 检查 index 同步状态

**本地判断**，不发网络请求。基于 SDK 观察到的 `_meta.group_indexes` 远端 etag 与本地缓存 etag 对比，返回同步状态。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `group_id` | string | ✅ | 群组标识（支持 `group_aid` 格式） |

**返回值**：

```python
{
  "group_id": "g-team.agentid.pub",
  "group_aid": "g-team.agentid.pub",
  "local_found": true,          # 本地是否有缓存 etag
  "remote_found": true,         # 是否观察到远端 _meta.group_indexes
  "local_etag": "\"sha256:...\"",  # 本地缓存 etag（带引号）
  "remote_etag": "\"sha256:...\"", # 远端 etag（带引号）
  "in_sync": false,             # local_etag == remote_etag
  "needs_update": true,         # remote_found && !in_sync（建议 pull）
  "last_modified": 1780000000000, # 远端 last_modified（若有）
  "schema": "aun.group.index.v1", # 远端 schema（若有）
  "status": "stale"             # "fresh" / "stale" / "unknown"
}
```

**使用场景**：

- 群列表展示同步状态图标（如"本地有未同步修改"或"远端有更新"）
- 判断是否需要调用 `getGroupIndex` pull 远端

**示例**：

```python
# Python
status = await client.group.check_group_index(group_id="g-team.agentid.pub")
if status["needs_update"]:
    print("远端有更新，建议 pull")
```

```typescript
// TypeScript/JavaScript
const status = await client.group.checkGroupIndex({ group_id: 'g-team.agentid.pub' });
if (status.needs_update) {
  console.log('远端有更新，建议 pull');
}
```

```go
// Go
status, err := client.Group().CheckGroupIndex(ctx, map[string]any{
    "group_id": "g-team.agentid.pub",
})
if status["needs_update"].(bool) {
    fmt.Println("远端有更新，建议 pull")
}
```

---

#### getGroupIndex — 拉取远端 index 并更新本地缓存

调用 `group.get_settings(keys=["group.index"])` 摘取远端签名 manifest，验签后按 entry etag 只拉取变化的 indexed settings，更新本地缓存。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `group_id` | string | ✅ | 群组标识（支持 `group_aid` 格式） |

**返回值**：

```python
{
  "group_id": "g-team.agentid.pub",
  "group_aid": "g-team.agentid.pub",
  "group_index": {              # 完整的 group.index 值
    "body": "...",              # 签名 JSONL 原文
    "meta": {...},              # 解析出的 meta 行
    "entries": [...]            # 解析出的 entries 行数组
  },
  "meta": {                     # 从 meta 行提取的关键字段
    "etag": "\"sha256:...\"",
    "last_modified": 1780000000000,
    "schema": "aun.group.index.v1"
  },
  "entries": [...],             # 同 group_index.entries
  "settings": {                 # 水合后的 indexed settings 值
    "rules.content": "...",
    "announcement.content": "...",
    ...
  }
}
```

**行为**：

1. 调用 `group.get_settings(keys=["group.index"])` 获取远端 manifest
2. 解析 JSONL，验证 `signed_by` / `body_hash` / `etag` / 签名（当前仅支持 **ECDSA-P256-SHA256**）
3. 按 entry etag 对比本地缓存，只拉取变化的 settings（如 `rules.content`、`announcement.content` 等）
4. 持久化 `index.jsonl` 和 `group-index-cache.json`（或 IndexedDB）
5. 调用 `client.mark_group_index_fresh(group_aid, etag)` 标记本地与远端同步

**错误处理**：

- **签名验证失败**：抛异常，不更新本地缓存
- **不支持的 `sig_alg`**：当前四语言 SDK 仅支持 `ECDSA-P256-SHA256`，其他算法（Ed25519/RSA）会被拒绝
- **网络错误**：透传底层 RPC 错误

**使用场景**：

- 群成员首次进群后拉取群公告、群规则
- `checkGroupIndex` 发现远端有更新时主动 pull
- 冲突解决：放弃本地修改，以远端为准

**示例**：

```python
# Python
result = await client.group.get_group_index(group_id="g-team.agentid.pub")
print(f"拉取成功，etag: {result['meta']['etag']}")
print(f"群公告: {result['settings'].get('announcement.content')}")
```

```typescript
// TypeScript/JavaScript
const result = await client.group.getGroupIndex({ group_id: 'g-team.agentid.pub' });
console.log(`拉取成功，etag: ${result.meta.etag}`);
console.log(`群公告: ${result.settings['announcement.content']}`);
```

```go
// Go
result, err := client.Group().GetGroupIndex(ctx, map[string]any{
    "group_id": "g-team.agentid.pub",
})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("拉取成功，etag: %s\n", result["meta"].(map[string]any)["etag"])
```

---

#### updateGroupIndex — 推送本地 indexed settings 修改

在远端基线上合并本地 indexed settings 修改，生成签名 `group.index` 后通过 CAS（Compare-And-Swap）机制提交。支持自动重试 etag 冲突。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `group_id` | string | ✅ | 群组标识（支持 `group_aid` 格式） |
| `settings` | object | ✅ | 要更新的 indexed settings（key-value 对象） |
| `signer` | AID | ❌ | 签名者身份（默认 `client.current_aid`） |
| `last_modified` | int | ❌ | 时间戳毫秒（默认 `Date.now()` / `time.time()*1000`） |
| `max_attempts` | int | ❌ | CAS 冲突最大重试次数（默认 2） |

**支持的 indexed settings keys**：

- `rules.content` / `rules.attachments` — 群规则及附件
- `announcement.content` / `announcement.attachments` — 群公告及附件
- `join.mode` / `join.question` / `join.auto_approve_patterns` / `join.max_pending` / `join.attachments` — 入群要求及附件
- `{keyName}.content` / `{keyName}.attachments` — 通用文档型 indexed setting；`keyName` 需满足 `^[A-Za-z][A-Za-z0-9_-]{0,63}$`，且不能使用 `join` 等保留前缀

**返回值**：

```python
{
  "group_id": "g-team.agentid.pub",
  "group_aid": "g-team.agentid.pub",
  "updated_keys": ["announcement.content", "group.index"],
  "_meta": {
    "group_indexes": {
      "g-team.agentid.pub": {
        "etag": "\"sha256:...\"",     # 推送成功后的新 etag
        "last_modified": 1780000000000,
        "schema": "aun.group.index.v1"
      }
    }
  }
}
```

**行为**：

1. 调用 `group.get_settings(keys=["group.index"])` 获取当前远端 etag（作为 CAS 基线）
2. 解析远端 `group.index` 的 entries，保留不在 `settings` 中的条目
3. 为 `settings` 中每个 key 计算新的 entry（包含 `etag: "sha256:<value的sha256>"`）
4. 合并远端保留条目和新 entries，生成新的 canonical JSONL
5. 用 `signer` 签名生成完整的 `group.index`（包含 meta 行的 `signature` 字段）
6. 调用 `group.set_settings(settings={...修改的key..., "group.index": {...}}, expected_index_etag=<远端etag>)`
7. **CAS 冲突自动重试**：若返回 "etag conflict" 错误，回到步骤 1 重新拉取基线（最多 `max_attempts` 次）
8. 推送成功后调用 `client.mark_group_index_fresh()` 和 `client.cache_group_index_settings()` 更新本地缓存

**错误处理**：

- **CAS 冲突重试耗尽**：抛出最后一次的 "etag conflict" 异常
- **非 CAS 错误**：立即抛出（如权限不足、签名失败）
- **`signer` 与 RPC `actor` 不一致**：服务端会拒绝（`signed_by` 必须等于 `actor_aid`）

**使用场景**：

- 群主/管理员修改群公告、群规则后推送
- 冲突解决：本地修改优先，覆盖远端（若冲突次数超限需人工介入）

**示例**：

```python
# Python - 更新群公告
result = await client.group.update_group_index(
    group_id="g-team.agentid.pub",
    settings={
        "announcement.content": "新公告内容",
        "announcement.attachments": []
    }
)
print(f"推送成功，新 etag: {result['_meta']['group_indexes']['g-team.agentid.pub']['etag']}")
```

```typescript
// TypeScript/JavaScript - 更新群规则
const result = await client.group.updateGroupIndex({
  group_id: 'g-team.agentid.pub',
  settings: {
    'rules.content': '1. 禁止广告\n2. 尊重他人',
    'rules.attachments': []
  }
});
console.log(`推送成功，新 etag: ${result._meta.group_indexes['g-team.agentid.pub'].etag}`);
```

```go
// Go - 更新入群要求
result, err := client.Group().UpdateGroupIndex(ctx, map[string]any{
    "group_id": "g-team.agentid.pub",
    "settings": map[string]any{
        "join.mode": "approval",
        "join.question": "你是如何知道本群的？",
        "join.attachments": []any{
            map[string]any{"type": "group.fs", "path": "/.group/attachments/join/guide.pdf"},
        },
    },
})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("推送成功\n")
```

**注意事项**：

1. **权限要求**：写入 indexed settings 需要 admin 及以上权限
2. **签名算法限制**：当前版本仅支持 ECDSA-P256-SHA256，使用其他算法的 AID 无法签名
3. **CAS 冲突策略**：默认重试 2 次，高并发场景建议增加 `max_attempts`
4. **`signer` 必须是当前连接身份**：服务端强制校验 `signed_by == actor_aid`，传入其他 AID 会被拒绝
5. **附件字段只存引用**：`updateRules` / `updateAnnouncement` / `updateSettingWithIndex` 传入 `content` 和 `attachments` 元数据引用；`updateJoinRequirements` 传入结构化入群字段和 `attachments` 元数据引用。附件实体先上传到群自有区，推荐路径为 `group_aid:/.group/attachments/{rules|announcement|join|<keyName>}/...`。群自有区默认允许 `owner/admin` 写入，`member` 默认不可写；`.group/` 不允许授予 `role:member` 写权限。

---

## ServiceProxyClient

Service Proxy 用于 provider 通过 AUN 身份暴露本地 HTTP / WebSocket 服务。当前公开封装在 Python SDK 的 `ServiceProxyClient` 中；其它语言可以按 [09-proxy-rpc-manual.md](09-proxy-rpc-manual.md) 直接实现同等控制面和隧道消息。

```python
from aun_core.service_proxy import ServiceProxyClient

proxy_client = ServiceProxyClient(
    provider_aid="alice.agentid.pub",
    aun_client=client,
)
proxy_client.register_service(
    "fileshare",
    "http://127.0.0.1:8080",
    visibility="public",
)
await proxy_client.serve_forever()
```

proxy-server 连接地址不能由应用外部传入或配置。`ServiceProxyClient` 会先读取 provider AID 本地 SQLite metadata 中 1 小时 TTL 的 `service_proxy_discovery` 缓存；缓存缺失或过期时，按协议查询 `https://{provider_aid}/.well-known/aun-proxy`，失败后回退 `https://proxy.{issuer}/.well-known/aun-proxy`，并使用返回的 `ws_url` 建立隧道。

关键 API：

| Python | 说明 |
|--------|------|
| `register_service(service_name, endpoint, service_type="http", visibility="private", metadata=None)` | 注册本地 embedded endpoint |
| `unregister_service(service_name)` | 注销本地服务 |
| `list_service_summaries()` | 获取可上报到 Gateway 和 proxy-server 的服务摘要 |
| `register_services_with_gateway()` | 显式调用 Gateway `proxy.register_services` |
| `unregister_services_from_gateway(service_names=None)` | 显式调用 Gateway `proxy.unregister_services` |
| `list_gateway_services()` | 显式调用 Gateway `proxy.list_services` |
| `register_services_with_proxy_server(ws)` | 通过已认证 proxy-server 隧道发送 `register_services` |
| `discover_proxy_server(force_refresh=False)` | 通过缓存 / well-known 发现 proxy-server |
| `connect_once()` | 建立一次 proxy-server 隧道并完成认证、数据面注册和可选心跳 |
| `serve_once()` | 处理有限数量的 proxy-server 转发请求 |
| `serve_forever(connection_mode="persistent")` | 持续提供 Service Proxy 服务；支持 persistent / on_demand |

自动注册顺序：

- `connect_once()`、`serve_once()`、`serve_forever()` 在存在 `aun_client.call()` 时，会先向 Gateway 调用 `proxy.register_services`。
- 建立 proxy-server 隧道前，SDK 必须通过缓存 / `/.well-known/aun-proxy` 发现得到 `ws_url`；不得由应用传入或配置 proxy-server 地址。
- proxy-server 隧道使用 `Authorization: Bearer <access_token>` 鉴权；SDK 优先复用 cached token，缺失或过期时通过 `aun_client.authenticate()` 向 Gateway 完成登录刷新。
- 每次 proxy-server 隧道认证成功后，都会立即向 proxy-server 发送 `register_services` 隧道消息。
- 服务列表与连接绑定；断开 Gateway 长连接或 proxy-server 隧道后，相应注册立即失效。

详细控制面 RPC、隧道消息和路由语义见 [09-proxy-rpc-manual.md](09-proxy-rpc-manual.md)。

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
| `token.refresh_exhausted` | refresh_token 缺失、过期或刷新链耗尽，SDK 已清理本地 token 并等待重新登录 |
| `message.received` | 收到 P2P 消息 |
| `message.ack` | 消息 ack |
| `message.undecryptable` | P2P E2EE 解密失败 |
| `group.changed` | 群组事件 |
| `group.message_undecryptable` | 群 E2EE 解密失败 |
| `storage.object_changed` | Storage 对象变更事件透传 |

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
| 群组 | [09-group-rpc-manual.md](09-group-rpc-manual.md) | `group.create` / `group.send` / `group.v2.*` / `group.fs.*` |
| 存储 | [09-storage-rpc-manual.md](09-storage-rpc-manual.md) | `storage.put_object` / `storage.fs.*` / `storage.volume.*` / ACL / token / share link |
| 协作 | [09-collab-rpc-manual.md](09-collab-rpc-manual.md) | `collab.ls-files` / `collab.show` / `collab.commit` / `collab.merge` / `collab.log` / `collab.diff` / `collab.clone` / `collab.prune` / `collab.gc` / `collab.reflog` / `collab.revert` / `collab.tag.*` / `collab.ls-remote` / `collab.unregister` |
| 元信息 | [09-meta-rpc-manual.md](09-meta-rpc-manual.md) | `meta.ping` / `meta.status` / `meta.trust_roots` |
| Stream | [09-stream-rpc-manual.md](09-stream-rpc-manual.md) | `stream.create` / `stream.close` / `stream.list_active` |
| Service Proxy | [09-proxy-rpc-manual.md](09-proxy-rpc-manual.md) | `proxy.register_services` / `proxy.unregister_services` / `proxy.list_services` |

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

