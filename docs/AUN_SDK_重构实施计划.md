# AUN SDK 重构实施计划

基于《AUN SDK 重构设计方案 v4.0》，本文档细化各阶段具体改动。

**目标版本**：0.4.0
**旧 API 策略**：不保留兼容层，直接替换

---

## 决策记录

| # | 决策 | 结论 |
|---|------|------|
| 1 | Python 错误处理风格 | AIDStore/AID 可失败方法返回 Result 字典；AUNClient 的 connect/call 保留异常 |
| 2 | CustodyNamespace | 保留 HTTP 直连方式，从 AUNClient 上移除，独立为 CustodyClient |
| 3 | sendV2 等方法 | SDK 内部方法，不对外暴露 |
| 4 | protected_headers 附加范围 | 只附加到消息类（message.send/group.send）和 thought 类（message.thought.put/group.thought.put） |
| 5 | 旧 API 保留 | 不保留，直接替换 |
| 6 | exists() PKI 端点 | URL 不变（与 GET 证书同一端点），服务端增加 HEAD 方法支持 |

---

## 阶段 0：冻结基线

**目标**：确保重构有回归基准，明确改动影响面

| 步骤 | 动作 | 产出 |
|------|------|------|
| 0.1 | 跑 `python -X utf8 -m pytest tests/unit/ -v --tb=short`，记录通过数 | 基线通过率 |
| 0.2 | 导出 `__init__.py` 的 `__all__` + AUNClient 所有 public 方法签名 | API 快照 |
| 0.3 | grep 调用点：`client.auth.`、`client.meta.`、`client.custody.`、`connect(auth`、`list_identities`、`set_agent_md_path`、`FileKeyStore` | 影响面清单 |
| 0.4 | 盘点 CLI (`aun_cli/__init__.py`) 对旧 API 的依赖 | CLI 改动范围 |
| 0.5 | 确认 PKI 证书下载端点 URL 格式（从 `AuthFlow.fetch_peer_cert` 提取） | exists() 实现依据 |

---

## 阶段 1：基础类型层（零破坏）

**目标**：新增 Result / AID / AIDStore 骨架，可独立使用，现有代码不动

### 1.1 新增 `result.py`

| 项 | 内容 |
|----|------|
| `Result` | 泛型 dataclass：`ok: bool`、`data: T | None`、`error: ErrorInfo | None` |
| `ErrorInfo` | dataclass：`code: str`、`message: str`、`cause: Exception | None` |
| `result_ok(data)` | 工厂函数 |
| `result_err(code, message, cause=None)` | 工厂函数 |

### 1.2 新增 `error_codes.py`

按设计方案 2.10 定义字符串常量：

- 加载阶段：`CERT_NOT_FOUND` / `CERT_PARSE_ERROR` / `CERT_EXPIRED` / `CERT_NOT_YET_VALID` / `CERT_CHAIN_BROKEN` / `KEYPAIR_MISMATCH` / `PRIVATE_KEY_PARSE_ERROR`
- 注册阶段：`IDENTITY_CONFLICT` / `INVALID_AID_FORMAT` / `NETWORK_ERROR` / `SERVER_ERROR`
- agent.md 阶段：`AGENTMD_NOT_FOUND` / `AGENTMD_PARSE_ERROR` / `SIGNATURE_NOT_FOUND` / `SIGNATURE_INVALID` / `CERT_FINGERPRINT_MISMATCH`
- 证书运维：`CERT_RENEWAL_FAILED` / `REKEY_FAILED` / `PRIVATE_KEY_REQUIRED`
- 密码学操作：`SIGNATURE_OPERATION_ERROR` / `VERIFICATION_OPERATION_ERROR` / `CERT_NOT_VALID` / `PRIVATE_KEY_NOT_VALID`

### 1.3 新增 `aid.py` — AID 值对象

**构造（内部）**：`_AID(aid, aun_path, cert_pem, cert_obj, private_key_obj?, cert_valid, pk_valid)` — 外部不可直接 new

**只读属性**：

| 属性 | 来源 |
|------|------|
| `aid: str` | 传入 |
| `aun_path: str` | 传入 |
| `cert_pem: str` | 传入 |
| `public_key: str` | `cert_obj.public_key()` → DER → base64 |
| `cert_subject: str` | `cert_obj.subject` CN |
| `cert_not_before: datetime` | `cert_obj.not_valid_before_utc` |
| `cert_not_after: datetime` | `cert_obj.not_valid_after_utc` |
| `cert_issuer: str` | `cert_obj.issuer` CN |
| `cert_fingerprint: str` | `sha256:` + hex |

**方法**：

| 方法 | 前置条件 | 返回 | 实现来源 |
|------|---------|------|---------|
| `is_cert_valid()` | — | `bool` | 构造时计算并缓存 |
| `is_private_key_valid()` | — | `bool` | 构造时计算并缓存 |
| `sign(payload: bytes)` | `is_private_key_valid()` | `Result[{signature: str}]` | ECDSA P-256 SHA-256，base64 输出 |
| `verify(payload: bytes, signature: str)` | `is_cert_valid()` | `Result[{valid: bool}]` | ECDSA verify |
| `sign_agent_md(content: str)` | `is_private_key_valid()` | `Result[{signed: str}]` | 从 `auth_namespace.py` 提取签名块拼接 |
| `verify_agent_md(content: str)` | `is_cert_valid()` | `Result[VerifyResult]` | 从 `_parse_agent_md_tail_signature` + ECDSA 提取 |

**需从现有代码提取的纯函数**（放 `_cert_utils.py`）：
- `_parse_agent_md_tail_signature()` — 来自 `auth_namespace.py:40`
- `_verify_signature()` — 来自 `auth.py`
- `_build_signature_block()` — 来自 `auth_namespace.py` 签名拼接逻辑
- `_validate_cert_chain()` — 从 `AuthFlow` 提取链验证为独立函数

### 1.4 新增 `aid_store.py` — AIDStore 骨架（仅离线方法）

**构造**：`AIDStore(aun_path, encryption_seed, device_id=None, slot_id='default')`

内部创建：`FileKeyStore`、`GatewayDiscovery`、`DnsResilientNet`

**阶段 1 实现的方法**：

| 方法 | 联网 | 实现要点 |
|------|:----:|---------|
| `load(aid) → Result[{aid: AID}]` | 否 | 读 cert + 读 private key + 链验证 + 签名自检 → 构造 AID |
| `list() → Result[{identities: list[AIDInfo]}]` | 否 | 扫描 `{aun_path}/AIDs/`，过滤有私钥的 |
| `change_seed(old_seed, new_seed) → Result[{changed, count}]` | 否 | 复用 FileKeyStore seed migration |

**`load()` 内部流程**（对应设计方案 2.11）：

```
1. 读 {aun_path}/AIDs/{aid}/public/certs/ → 无文件 → CERT_NOT_FOUND
2. 解析 PEM → 失败 → CERT_PARSE_ERROR
3. 有效期检查 → 过期 → CERT_EXPIRED / 未生效 → CERT_NOT_YET_VALID
4. 链验证（需根证书）→ 失败 → CERT_CHAIN_BROKEN
5. 读 {aun_path}/AIDs/{aid}/private/key.pem → 无文件 → 返回 PeerOnly AID
6. 解析私钥 → 失败 → PRIVATE_KEY_PARSE_ERROR
7. 签名自检（sign + verify）→ 失败 → KEYPAIR_MISMATCH
8. 返回完整 AID（is_private_key_valid()=True）
```

### 1.5 导出

`__init__.py` 新增导出：`AIDStore`、`AID`、`Result`、`ErrorInfo`、`result_ok`、`result_err`

### 1.6 单测

| 文件 | 覆盖 |
|------|------|
| `tests/unit/test_result.py` | Result 构造、ok/err 判断 |
| `tests/unit/test_aid.py` | sign/verify/sign_agent_md/verify_agent_md、is_cert_valid/is_private_key_valid |
| `tests/unit/test_aid_store_offline.py` | load 成功/各种失败、list、change_seed |

---

## 阶段 2：AIDStore 联网方法

**目标**：AIDStore 完整可用，覆盖注册、存在性检查、对端解析、agent.md、证书运维

### 2.1 gateway 发现提取

从 `AuthNamespace._resolve_gateway()` (`auth_namespace.py:120-175`) 提取到 `AIDStore._resolve_gateway(aid)`：
- 内部持有 `GatewayDiscovery` 实例
- 缓存逻辑（keystore metadata）保留
- 不再依赖 `self._client`

### 2.2 联网方法

| 方法 | 内部复用 | 关键改动 |
|------|---------|---------|
| `register(aid) → Result[{registered: True}]` | `AuthFlow.register_aid(gateway_url, aid)` | AIDStore 内部持有 AuthFlow 实例 |
| `exists(aid) → Result[{exists: bool}]` | **新实现** | HEAD PKI 证书端点（URL 与 GET 相同），200→存在，404→不存在 |
| `resolve(aid, opts?) → Result[ResolveData]` | `AuthFlow.fetch_peer_cert()` + agent.md 下载 + `AID.verify_agent_md()` | 组合调用 |
| `fetch_agent_md(aid) → Result[AgentMdFetchData]` | 从 `auth_namespace.py:428` 提取 HTTP GET + 验签 | 下载 + 拉证书 + 验签 |
| `head_agent_md(aid) → Result[{etag, last_modified, content_length}]` | 新实现 HEAD 请求 | 判断名片是否发布 |
| `check_agent_md(aid, ttl_days?) → Result[{needs_update, ...}]` | 从 `client.py:862` 提取 etag 比对 | 本地 vs 远端 |
| `renew_cert(aid) → Result[{renewed, new_cert_not_after}]` | AuthFlow 续签逻辑 | 需 gateway + 私钥签名 |
| `rekey(aid) → Result[{rekeyed, new_fingerprint}]` | AuthFlow 换钥逻辑 | 生成新 keypair → 服务端换证书 |
| `diagnose(aid) → Result[DiagnoseData]` | `load()` + `exists()` 组合 | 本地+远端对比 |

### 2.3 `exists()` 实现

```python
async def exists(self, aid: str) -> Result:
    url = self._pki_cert_url(aid)  # 与 fetch_peer_cert 用同一个 URL
    try:
        async with aiohttp.ClientSession() as session:
            async with session.head(url, ssl=self._ssl_context, timeout=10) as resp:
                if resp.status == 200:
                    return result_ok({"exists": True})
                elif resp.status == 404:
                    return result_ok({"exists": False})
                else:
                    return result_err("NETWORK_ERROR", f"unexpected status {resp.status}")
    except Exception as e:
        return result_err("NETWORK_ERROR", str(e), cause=e)
```

### 2.4 `resolve()` 流程

```
1. 检查本地证书缓存（load(aid)）
2. 缓存未命中或 force_refresh → 下载证书（GET PKI 端点）
3. 验证证书 + 落盘缓存
4. 若 skip_agent_md=True → 返回（仅证书）
5. 下载 agent.md（GET https://{aid}/agent.md）
6. 验证 agent.md 签名（用证书公钥）
7. 返回 ResolveData
```

### 2.5 服务端配合

`exists()` 需要服务端 PKI 端点支持 HEAD 方法。URL 不变，只加 HEAD 路由。

### 2.6 测试

| 文件 | 覆盖 |
|------|------|
| `tests/unit/test_aid_store_network.py` | mock HTTP 测试 register/exists/resolve/fetch_agent_md |
| `tests/integration_test_aid_store.py` | Docker 单域：register → load → exists → resolve |

---

## 阶段 3：AUNClient 状态机重构

**目标**：新构造方式 + 9 态状态机，不保留旧 API

### 3.1 状态枚举替换

`types.py` 中 `ConnectionState` 改为：

```python
class ConnectionState(str, Enum):
    NO_IDENTITY = "no_identity"
    STANDBY = "standby"
    AUTHENTICATED = "authenticated"
    CONNECTING = "connecting"
    READY = "ready"
    RETRY_BACKOFF = "retry_backoff"
    RECONNECTING = "reconnecting"
    CONNECTION_FAILED = "connection_failed"
    CLOSED = "closed"
```

**旧 → 新映射**：
- `idle` → `no_identity`（无身份）/ `standby`（有身份）
- `connecting` / `authenticating` → `connecting`（authenticating 不再对外暴露）
- `connected` → `ready`
- `disconnected` → `standby`
- `reconnecting` → `reconnecting` / `retry_backoff`
- `terminal_failed` → `connection_failed`
- `closed` → `closed`

### 3.2 构造函数

```python
class AUNClient:
    def __init__(
        self,
        aid: AID | None = None,
        *,
        debug: bool = False,
        protected_headers: dict[str, str] | None = None,
    ):
```

- 传入有效本地 AID（`is_private_key_valid() == True`）→ 进入 `standby`
- 不传 → 进入 `no_identity`
- 内部从 `aid.aun_path` 获取路径，创建 `RPCTransport`、`EventDispatcher`
- 内部持有 `AuthFlow` 实例（用于 authenticate/connect）
- 不再创建 `AuthNamespace` / `MetaNamespace` / `CustodyNamespace`

### 3.3 状态推进方法

| 方法 | 前置状态 | 目标状态 | 实现要点 |
|------|---------|---------|---------|
| `load_identity(aid: AID)` | no_identity / closed | standby | 校验 `aid.is_private_key_valid()`，设置 `_current_aid`，重建 AuthFlow |
| `authenticate()` | standby | authenticated | 调 `AuthFlow.authenticate()`，存 token |
| `connect(opts?)` | standby / authenticated / retry_backoff / connection_failed | connecting → ready | standby 时内部先 authenticate |
| `disconnect()` | authenticated 及以上 | standby | 关 WS，取消重连 task，清 token |
| `close()` | 任意 | closed | 关 WS，取消所有 task，清身份 |

### 3.4 Capability getters

| getter | 实现 |
|--------|------|
| `has_identity` | `state not in (NO_IDENTITY, CLOSED)` |
| `can_sign` | `has_identity and _current_aid.is_private_key_valid()` |
| `can_connect` | `has_identity and state != CLOSED` |
| `can_send` | `state == READY` |
| `is_ready` | `state == READY` |
| `is_online` | `state in (READY, RETRY_BACKOFF, RECONNECTING)` |
| `is_closed` | `state == CLOSED` |
| `current_aid` | `_current_aid if has_identity else None` |
| `aun_path` | `_current_aid.aun_path if has_identity else None` |
| `next_retry_at` | `_next_retry_at if state == RETRY_BACKOFF else None` |
| `next_retry_in_seconds` | `max(0, _next_retry_at - time.time()) if ... else None` |
| `retry_attempt` | `_retry_attempt` |
| `retry_max_attempts` | `_retry_max_attempts` |
| `last_error` | `_last_error` |
| `last_error_code` | `_last_error_code` |
| `gateway_health` | `_gateway_health` |

### 3.5 重连逻辑改造

当前 `_reconnect_loop` 改为：

```
网络断开 → state = RETRY_BACKOFF, 记录 _next_retry_at
    ↓ 退避到期
state = RECONNECTING, 尝试连接
    ↓ 成功 → state = READY
    ↓ 失败且有次数 → state = RETRY_BACKOFF（递增退避）
    ↓ 失败且耗尽 → state = CONNECTION_FAILED, 记录 _last_error/_last_error_code
```

- 用户在 `RETRY_BACKOFF` 调 `connect()` → 跳过退避，立即 `RECONNECTING`
- 用户在 `CONNECTION_FAILED` 调 `connect()` → 重置计数器，进入 `CONNECTING`

### 3.6 `call()` 方法

```python
async def call(self, method: str, params: dict | None = None, *, trace: str | None = None) -> Any:
    if self._state != ConnectionState.READY:
        raise StateError(f"call not allowed in state {self._state}")
    if method in _INTERNAL_ONLY_METHODS:
        raise PermissionError(f"method is internal_only: {method}")

    merged = dict(params or {})
    # 只在消息类和 thought 类附加 protected_headers
    if self._instance_protected_headers and method in _PROTECTED_HEADERS_METHODS:
        existing = merged.get("protected_headers") or {}
        merged["protected_headers"] = {**self._instance_protected_headers, **existing}

    return await self._transport.call(method, merged, timeout=..., trace=trace)
```

```python
_PROTECTED_HEADERS_METHODS = frozenset({
    "message.send", "group.send",
    "message.thought.put", "group.thought.put",
})
```

### 3.7 `set_protected_headers` / `get_protected_headers`

```python
def set_protected_headers(self, headers: dict[str, str] | None) -> None:
    self._instance_protected_headers = dict(headers) if headers else None

def get_protected_headers(self) -> dict[str, str] | None:
    return dict(self._instance_protected_headers) if self._instance_protected_headers else None
```

### 3.8 对端管理

| 方法 | 实现 |
|------|------|
| `lookup_peer(aid)` | 查内存缓存 → 无则调 `self._aid_store.resolve(aid)` → 缓存 → 返回 AID |
| `get_peer(aid)` | 仅查内存缓存，无则返回 None |
| `cache_peer(aid: AID)` | 加入内存缓存 |
| `peers()` | 返回缓存中所有 AID 列表 |

### 3.9 V2 E2EE 内部化

- 加密/解密逻辑保留为 AUNClient 内部方法
- `call('message.send', ...)` 时 SDK 内部自动处理 V2 加密
- 收到消息时内部自动解密，通过 `message.received` 事件交付明文
- 不再对外暴露 `sendV2()` / `pullV2()` / `ackV2()` 等方法名

### 3.10 事件

| 事件 | 数据 |
|------|------|
| `state-change` | `{"from": str, "to": str}` |
| `message.received` | `{"from", "payload", "protected_headers?", "context?", ...}` |
| `group.message_created` | `{"from", "group_id", "payload", "protected_headers?", ...}` |
| `message.recalled` | `{"message_id", "from", ...}` |
| `message.undecryptable` | `{"from", "seq", "_decrypt_error", "protected_headers?", ...}` |
| `group.message_undecryptable` | `{"from", "group_id", "seq", "_decrypt_error", "protected_headers?", ...}` |
| `token.refreshed` | `{"expires_at"}` |
| `gateway.disconnect` | `{"reason", "code"}` |
| `connection.error` | `{"error", "code"}` |

### 3.11 测试

| 文件 | 覆盖 |
|------|------|
| `tests/unit/test_client_state_machine.py` | 所有状态转换路径 |
| `tests/unit/test_client_capability.py` | 各状态下 getter 返回值 |
| `tests/unit/test_client_protected_headers.py` | 实例级 headers 合并逻辑 |

---

## 阶段 4：调用方全量迁移

**目标**：CLI、tests、docs 全部迁移到新 API

### 4.1 CLI 迁移 (`aun_cli/__init__.py`)

所有命令改为新模式：

```python
store = AIDStore(aun_path=..., encryption_seed=...)
result = await store.register(aid)
if not result.ok:
    print(f"注册失败: {result.error.code}")
    return
load_result = await store.load(aid)
me = load_result.data["aid"]
client = AUNClient(me, debug=debug)
await client.connect()
```

### 4.2 单元测试迁移

| 旧调用 | 新调用 |
|--------|--------|
| `client.auth.register_aid({"aid": aid})` | `store.register(aid)` |
| `client.auth.load_identity({"aid": aid})` | `store.load(aid)` |
| `client.auth.authenticate({"aid": aid})` | `client.authenticate()` |
| `client.connect(auth, opts)` | `client.connect(opts)` |
| `client.list_identities()` | `store.list()` |
| `client.auth.sign_agent_md(content)` | `aid.sign_agent_md(content)` |
| `client.auth.verify_agent_md(content)` | `peer.verify_agent_md(content)` |
| `client.meta.ping()` | `client.call('meta.ping')` |
| `client.meta.status()` | `client.call('meta.status')` |
| `client.fetch_agent_md(aid)` | `store.fetch_agent_md(aid)` |
| `client.check_agent_md(aid, ttl)` | `store.check_agent_md(aid, ttl_days)` |
| 状态断言 `ConnectionState.CONNECTED` | `ConnectionState.READY` |
| 状态断言 `ConnectionState.IDLE` | `ConnectionState.NO_IDENTITY` / `STANDBY` |

### 4.3 集成测试 / E2E 测试

`tests/integration_test_*.py` 和 `tests/e2e_test_*.py`：
- 开头创建 `AIDStore`
- `store.load(aid)` 获取 AID
- `AUNClient(aid)` 构造
- `client.connect()` 连接
- 业务操作用 `client.call('message.send', ...)`

### 4.4 双域测试

`docker-deploy/federation-test/tests/` 下的脚本同步改。

### 4.5 CustodyNamespace 处理

从 AUNClient 上移除，独立为 `CustodyClient` 类：

```python
from aun_core.custody import CustodyClient

custody = CustodyClient(aid="alice.aid.pub", verify_ssl=False)
await custody.bind_phone(params)
```

保留 HTTP 直连方式，不走 gateway RPC。

### 4.6 MetaNamespace 方法迁移

| 旧 | 新 |
|----|-----|
| `client.meta.ping()` | `client.call('meta.ping')` |
| `client.meta.status()` | `client.call('meta.status')` |
| `client.meta.trust_roots()` | `client.call('meta.trust_roots')` |
| `client.meta.download_trust_roots(...)` | AIDStore 内部自动处理 |
| `client.meta.verify_trust_roots(...)` | AIDStore.load() 内部链验证 |
| `client.meta.import_trust_roots(...)` | AIDStore 构造时自动导入 |
| `client.meta.refresh_trust_roots(...)` | AIDStore 内部按需刷新 |

---

## 阶段 5：清理 + 跨语言同步

**目标**：删除旧代码，跨语言对齐，发布 0.4.0

### 5.1 删除文件

| 文件 | 说明 |
|------|------|
| `namespaces/auth_namespace.py` | 全部功能已迁移到 AIDStore/AID/AUNClient |
| `namespaces/meta_namespace.py` | ping/status/trust_roots 改 call()；信任根管理内化 |
| `namespaces/custody_namespace.py` | 独立为 `custody.py` |
| `namespaces/__init__.py` | 目录可删 |

### 5.2 AUNClient 内部清理

| 删除项 | 原位置 |
|--------|--------|
| `self.auth = AuthNamespace(self)` | 构造函数 |
| `self.meta = MetaNamespace(self)` | 构造函数 |
| `self.custody = CustodyNamespace(self)` | 构造函数 |
| `set_agent_md_path()` / `SetAgentMDPath()` | `client.py:562-572` |
| `list_identities()` | `client.py:1133` |
| `check_gateway_health()` | `client.py:1067` |
| `ping()` / `status()` / `trust_roots()` | `client.py:1661-1667` |
| `fetch_agent_md()` / `check_agent_md()` | `client.py:862-972` |
| 旧 `connect(auth, opts)` 签名 | `client.py:1071` |

### 5.3 `__init__.py` 最终导出

```python
__all__ = [
    "AIDStore", "AID", "AUNClient",
    "CustodyClient",
    "Result", "ErrorInfo", "result_ok", "result_err",
    "ProtectedHeaders", "ConnectionState", "get_device_id",
    # 异常类（AUNClient connect/call 仍抛异常）
    "AUNError", "AuthError", "ConnectionError", "TimeoutError",
    "StateError", "E2EEError", "GroupError", ...
]
```

### 5.4 跨语言同步

| SDK | 改动范围 | 优先级 |
|-----|---------|--------|
| TS (`ts/`) | 新增 `AIDStore`/`AID` 类，重构 `AUNClient` 构造和状态机 | 高 |
| JS (`js/`) | 同 TS，但 `AIDStore.load` 从 IndexedDB/内存加载，无文件 I/O | 中 |
| Go (`go/`) | `AIDStore`/`AID` 用 struct + method，Result 用 `(T, error)` 惯用法 | 中 |

### 5.5 文档 + 版本

- 版本号：`0.4.0`
- 更新 `docs/sdk/06-API手册.md`
- 运行 `python/sync_docs.py` 同步到 skill 目录
- CHANGELOG 记录所有破坏性变更

---

## 接口迁移对照表

| 旧 API | 新 API | 归属 |
|--------|--------|------|
| `AUNClient(config, debug)` | `AUNClient(aid, debug=, protected_headers=)` | AUNClient |
| `client.auth.register_aid({"aid": x})` | `store.register(x)` | AIDStore |
| `client.auth.load_identity({"aid": x})` | `store.load(x)` | AIDStore |
| `client.auth.authenticate({"aid": x})` | `client.authenticate()` | AUNClient |
| `client.connect(auth, opts)` | `client.connect(opts)` | AUNClient |
| `client.disconnect()` | `client.disconnect()` | AUNClient（不变） |
| `client.close()` | `client.close()` | AUNClient（不变） |
| `client.call(method, params)` | `client.call(method, params)` | AUNClient（不变） |
| `client.on(event, handler)` | `client.on(event, handler)` | AUNClient（不变） |
| `client.list_identities()` | `store.list()` | AIDStore |
| `client.fetch_agent_md(aid)` | `store.fetch_agent_md(aid)` | AIDStore |
| `client.check_agent_md(aid, ttl)` | `store.check_agent_md(aid, ttl_days)` | AIDStore |
| `client.publish_agent_md()` | `client.publish_agent_md(content?)` | AUNClient |
| `client.auth.upload_agent_md(content)` | `client.upload_agent_md(content)` | AUNClient |
| `client.auth.sign_agent_md(content)` | `aid.sign_agent_md(content)` | AID |
| `client.auth.verify_agent_md(content)` | `peer.verify_agent_md(content)` | AID |
| `client.auth.fetch_peer_cert({"aid": x})` | `store.resolve(x)` | AIDStore |
| `client.auth.check_aid({"aid": x})` | `store.diagnose(x)` | AIDStore |
| `client.auth.renew_cert()` | `store.renew_cert(aid)` | AIDStore |
| `client.auth.rekey()` | `store.rekey(aid)` | AIDStore |
| `client.meta.ping()` | `client.call('meta.ping')` | RPC 透传 |
| `client.meta.status()` | `client.call('meta.status')` | RPC 透传 |
| `client.meta.trust_roots()` | `client.call('meta.trust_roots')` | RPC 透传 |
| `client.custody.bind_phone(p)` | `CustodyClient(aid).bind_phone(p)` | CustodyClient |
| `FileKeyStore.change_seed(...)` | `store.change_seed(old, new)` | AIDStore |
| `client.set_agent_md_path(path)` | 删除（构造参数或 AIDStore 配置） | — |
| `client.check_gateway_health(url)` | `client.gateway_health` getter | AUNClient |
| `client.state` | `client.state` | AUNClient（值变更） |
| `client.aid` | `client.current_aid` | AUNClient |

---

## 文件变更汇总

### 新增文件

| 文件 | 说明 |
|------|------|
| `python/src/aun_core/result.py` | Result / ErrorInfo / result_ok / result_err |
| `python/src/aun_core/error_codes.py` | 错误码字符串常量 |
| `python/src/aun_core/aid.py` | AID 值对象 |
| `python/src/aun_core/aid_store.py` | AIDStore 管理器 |
| `python/src/aun_core/_cert_utils.py` | 从现有代码提取的证书/签名纯函数 |
| `python/src/aun_core/custody.py` | CustodyClient 独立类 |
| `tests/unit/test_result.py` | Result 单测 |
| `tests/unit/test_aid.py` | AID 单测 |
| `tests/unit/test_aid_store_offline.py` | AIDStore 离线单测 |
| `tests/unit/test_aid_store_network.py` | AIDStore 联网单测 |
| `tests/unit/test_client_state_machine.py` | 状态机单测 |
| `tests/unit/test_client_capability.py` | Capability getter 单测 |
| `tests/unit/test_client_protected_headers.py` | protected_headers 单测 |
| `tests/integration_test_aid_store.py` | AIDStore 集成测试 |

### 修改文件

| 文件 | 改动 |
|------|------|
| `python/src/aun_core/__init__.py` | 新增导出，移除旧 namespace 导出 |
| `python/src/aun_core/types.py` | ConnectionState 枚举值替换 |
| `python/src/aun_core/client.py` | 重构构造函数、状态机、connect、删除 namespace 引用 |
| `python/src/aun_core/auth.py` | 提取纯函数到 `_cert_utils.py`，AuthFlow 保留供 AIDStore/AUNClient 内部使用 |
| `python/src/aun_core/keystore/file.py` | 无大改，被 AIDStore 内部调用 |
| `python/src/aun_cli/__init__.py` | CLI 全量迁移到新 API |
| `tests/unit/test_auth.py` | 改为测试 AIDStore |
| `tests/unit/test_client.py` | 改为新构造 + 新状态 |
| `tests/unit/test_connection_kind.py` | 状态枚举值更新 |
| `tests/integration_test_*.py` | 全量迁移 |
| `tests/e2e_test_*.py` | 全量迁移 |

### 删除文件

| 文件 | 说明 |
|------|------|
| `python/src/aun_core/namespaces/auth_namespace.py` | 功能迁移到 AIDStore/AID/AUNClient |
| `python/src/aun_core/namespaces/meta_namespace.py` | 功能迁移到 call() + AIDStore 内部 |
| `python/src/aun_core/namespaces/custody_namespace.py` | 独立为 custody.py |
| `python/src/aun_core/namespaces/__init__.py` | 目录删除 |

---

**文档版本**：v1.0
**最后更新**：2026-05-28
