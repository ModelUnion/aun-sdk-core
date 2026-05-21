# AUN RPC Trace 增强设计

**日期**: 2026-05-22  
**范围**: Gateway + Message + Auth + CA + Group + Python SDK  
**目标**: 补全 RPC trace 诊断信息，从"只有路径和耗时"到"能定位业务失败原因"

---

## 问题现状

当前 trace 输出示例：

```
[TRACE][message.v2.put_peer_pk][error] total=54ms trace_id=93643d8d922d3d49a86345b8c267c178
  ├─ sdk.send  dur=0ms @00:24:29.197
  ├─ gateway.relay_in  dur=0ms @00:24:29.378
  ├─ ca.process  dur=2ms @00:24:29.382
  ├─ message.process  dur=7ms @00:24:29.380
  ├─ gateway.relay_out  dur=10ms @00:24:29.378
  └─ sdk.recv  dur=54ms
```

**缺陷：**
1. 只能看到"经过了哪些模块"，看不到"每个模块做了什么"
2. `ca.process dur=2ms` 无法知道查的是哪个 AID、什么条件、结果是否找到
3. `message.process dur=7ms` 无法知道调用了哪个嵌套 RPC、为什么失败
4. 单行 `process` span 无法区分"进入"和"退出"，嵌套关系不清晰

**根本原因：**
- 服务端 span 只有 `node`、`ts`、`action=process`、`ms` 四个字段
- 没有业务诊断字段（aid、method、found、error_code 等）
- SDK 展示逻辑按"平铺列表"而非"调用树"

---

## 设计方案

### 1. Span 结构改造

#### 1.1 Enter/Exit 语义

每个服务产生 **两个 span**：

**Enter span（承载所有诊断信息）：**
```python
{
    "node": "message",           # 模块名
    "ts": 1234567890123,         # 毫秒时间戳
    "action": "enter",           # 固定 "enter"
    "method": "v2.put_peer_pk",  # RPC 方法短名
    # 业务诊断字段（按模块定制，尽可能详细）
    "caller_aid": "yayi2000.agentid.pub",
    "peer_aid": "yayi2000.agentid.pub",
    "key_source": "peer_device_prekey",
    "spk_id": "sha256:abc123ab",
    "device_id": "device-xyz",
}
```

**Exit span：**
```python
{
    "node": "message",
    "ts": 1234567890130,
    "action": "exit",
    "ms": 7,                     # 耗时（必需）
    "status": "error",           # ok / error（必需）
    # 失败时补充错误信息 + 上下文
    "error_code": -32603,
    "error_msg": "AID cert not found",
    "peer_aid": "yayi2000.agentid.pub",  # 失败相关的关键上下文
    "method": "v2.put_peer_pk",
    # 成功时补充关键结果（可选）
    "found": false,              # CA 查询结果
    "delivered_count": 2,        # Message 发送结果
}
```

**设计原则：**
- **Enter span 承载完整上下文**，方便定位问题根因
- **Exit span 关注结果和性能**：
  - 成功时：`ms`、`status=ok`、关键结果字段（found/delivered_count）
  - 失败时：`ms`、`status=error`、`error_code`、`error_msg`、**失败相关的上下文字段**（aid/method/peer_aid 等）
- SDK 展示时，enter 行显示完整诊断信息，exit 行显示结果和耗时

#### 1.2 嵌套调用处理

当 Message 调用 CA 时：
- Message 的 `_current_trace.child_spans` 自动收集 CA 的 enter/exit span
- Message exit 时，将 child_spans 合并到响应的 `_trace.spans` 列表
- SDK 收到后按 ts 排序，自动识别嵌套关系

#### 1.3 安全字段白名单

**允许放入 span：**
- ✅ aid、method、curve、lifecycle_state、found、error_code
- ✅ cert_sn 前缀（前 8 位）、route、namespace、instance_id
- ✅ group_id、member_count、delivered_count

**严格禁止：**
- ❌ token、私钥、证书 PEM、签名原文
- ❌ challenge nonce、密码、refresh_token

---

### 2. 各模块补充字段

#### 2.1 Gateway (relay.py)

**Enter span (`relay_in`)：**
```python
{
    "node": "gateway",
    "action": "enter",
    "ts": <timestamp>,
    # 详细诊断信息
    "route": "service_plane",  # direct / service_plane / kernel / fallback
    "namespace": "message",
    "method": "v2.put_peer_pk",
    "aid": "yayi2000.agentid.pub",
    "instance_id": "message#1",  # service_plane 时有值
    "connection_id": "conn-abc123",
    "device_id": "device-xyz",
}
```

**Exit span：**
```python
{
    "node": "gateway",
    "action": "exit",
    "ts": <timestamp>,
    "ms": 10,              # 耗时（必需）
    "status": "error",     # ok / error（必需）
    # 失败时补充错误信息 + 上下文
    "error_code": -32603,
    "error_msg": "AID cert not found",
    "method": "v2.put_peer_pk",
    "aid": "yayi2000.agentid.pub",
}
```

**修改位置：**
- `relay.py:844` — relay_in span 补字段
- `relay.py:962` — relay_out span 补字段

#### 2.2 Message (entry.py)

**Enter span：**
```python
{
    "node": "message",
    "action": "enter",
    "ts": <timestamp>,
    # 详细诊断信息
    "method": "v2.put_peer_pk",
    "caller_aid": "yayi2000.agentid.pub",
    "peer_aid": "yayi2000.agentid.pub",
    "key_source": "peer_device_prekey",
    "spk_id": "sha256:abc123ab",
    "device_id": "device-xyz",
    # 或按方法不同：
    # "to_aid" / "from_aid" / "group_id" / "message_id"
}
```

**Exit span：**
```python
{
    "node": "message",
    "action": "exit",
    "ts": <timestamp>,
    "ms": 7,               # 耗时（必需）
    "status": "error",     # ok / error（必需）
    # 失败时补充错误信息 + 上下文
    "error_code": -32603,
    "error_msg": "AID cert not found",
    "method": "v2.put_peer_pk",
    "peer_aid": "yayi2000.agentid.pub",
    # 成功时补充关键结果
    "found": true,         # bootstrap 方法
    "delivered_count": 2,  # send 方法
    "message_id": "msg-xyz",
}
```

**修改位置：**
- `entry.py:199-268` — `_TracingWS` 类改造
  - `__init__` 记录 enter 时间
  - `_inject_trace` 改成生成 enter + exit 两个 span
  - enter span 从 `params` 提取业务字段
  - exit span 从 `payload` 提取 status/error

#### 2.3 Auth (entry.py)

**Enter span：**
```python
{
    "node": "auth",
    "action": "enter",
    "ts": <timestamp>,
    # 详细诊断信息
    "method": "verify",  # 或 login_phase1 / login_phase2 / create_aid
    "aid": "yayi2000.agentid.pub",
    "auth_method": "aid",  # pairing_code / kite_token / aid
    "device_id": "device-xyz",
    "client_nonce": "nonce-abc...",  # 前 16 位
}
```

**Exit span：**
```python
{
    "node": "auth",
    "action": "exit",
    "ts": <timestamp>,
    "ms": 15,              # 耗时（必需）
    "status": "ok",        # ok / error（必需）
    # 成功时补充
    "success": true,       # verify 方法
    "created": false,      # create_aid 方法（幂等标识）
    # 失败时补充
    "error_code": -32001,
    "error_msg": "invalid signature",
}
```

**修改位置：**
- Auth 模块当前没有 `_TracingWS` 封装，需要新增或复用 Message 的模式

#### 2.4 CA (entry.py)

**Enter span：**
```python
{
    "node": "ca",
    "action": "enter",
    "ts": <timestamp>,
    # 详细诊断信息
    "method": "get_cert",
    "aid": "yayi2000.agentid.pub",
    "curve": "P-256",
    "lifecycle_state": "active_signing",
    "cert_sn": "abc123...",  # 按序列号查询时
    "cert_fingerprint": "sha256:abc123ab...",  # 按指纹查询时（前 16 位）
}
```

**Exit span：**
```python
{
    "node": "ca",
    "action": "exit",
    "ts": <timestamp>,
    "ms": 2,               # 耗时（必需）
    "status": "ok",        # ok / error（必需）
    # 成功时补充
    "found": true,
    "cert_sn_prefix": "abc123ab",  # 找到时返回前 8 位
    "lifecycle_state": "active_signing",
    # 失败时补充错误信息 + 上下文
    "found": false,
    "error_code": -32002,
    "error_msg": "certificate not found",
    "method": "get_cert",
    "aid": "yayi2000.agentid.pub",
    "curve": "P-256",
}
```

**修改位置：**
- CA 模块当前没有 `_TracingWS` 封装，需要新增

#### 2.5 Group (entry.py)

**Enter span：**
```python
{
    "node": "group",
    "action": "enter",
    "ts": <timestamp>,
    # 详细诊断信息
    "method": "create",
    "group_id": "group-abc123",
    "caller_aid": "alice.aid.com",
    "member_aids": ["alice.aid.com", "bob.aid.com", "carol.aid.com"],  # 或 member_count
    "group_name": "Project Team",
}
```

**Exit span：**
```python
{
    "node": "group",
    "action": "exit",
    "ts": <timestamp>,
    "ms": 12,              # 耗时（必需）
    "status": "ok",        # ok / error（必需）
    # 成功时补充
    "group_id": "group-abc123",
    "member_count": 3,
    # 失败时补充错误信息 + 上下文
    "error_code": -32603,
    "error_msg": "member not found",
    "method": "create",
    "caller_aid": "alice.aid.com",
}
```

**修改位置：**
- Group 模块当前没有 `_TracingWS` 封装，需要新增

---

### 3. SDK 展示改造（Python）

#### 3.1 目标效果

```
[TRACE][message.v2.put_peer_pk][error] total=54ms trace_id=93643d8d922d3d49a86345b8c267c178
  ├─ sdk.send @00:24:29.197
  ├─ gateway.enter route=service_plane namespace=message @00:24:29.378
  ├─ message.enter method=v2.put_peer_pk peer_aid=yayi2000.agentid.pub @00:24:29.380
  │  ├─ ca.enter method=get_cert aid=yayi2000.agentid.pub curve=P-256 lifecycle=active_signing @00:24:29.382
  │  └─ ca.exit status=not_found found=false dur=2ms @00:24:29.384
  ├─ message.exit status=error error_code=-32603 error="AID cert not found" dur=7ms @00:24:29.387
  ├─ gateway.exit status=error dur=10ms @00:24:29.388
  └─ sdk.recv dur=54ms
```

#### 3.2 实现要点

**树状结构识别：**
1. 按 `ts` 排序所有 span
2. 维护栈：遇到 `action=enter` 入栈，遇到 `action=exit` 出栈
3. 栈深度决定缩进层级
4. exit span 展示 duration（从对应 enter span 计算）

**字段展示规则：**
- enter span：展示关键业务字段（aid、method、route 等）
- exit span：展示结果字段（status、found、error_code、dur）
- 单行最多展示 3-4 个关键字段，避免过长

**向后兼容：**
- 旧格式 `action=process`：按单行展示，dur 直接取 `ms` 字段
- 新格式 enter/exit：按树状展示
- 混合格式：分别处理

**修改位置：**
- `python/src/aun_core/transport.py:268-281` — `_trace_observer` 回调
- 新增 `_format_trace_tree(spans)` 函数，返回多行字符串

---

### 4. 实现计划

#### Phase 1: 服务端 span 结构改造

**Task 1.1: Message 模块 enter/exit span**
- 修改 `_TracingWS` 类，改造 `_inject_trace` 方法
- enter span 从 `params` 提取 `method`、`caller_aid`、`peer_aid`/`to_aid`/`group_id`
- exit span 从 `payload` 提取 `status`、`error_code`、`found`/`delivered_count`
- 测试：`message.v2.put_peer_pk` 失败时 trace 包含 `peer_aid` 和 `error_code`

**Task 1.2: CA 模块 enter/exit span**
- 新增 `_TracingWS` 封装（复用 Message 模式）
- enter span 提取 `aid`、`cert_sn`、`curve`、`lifecycle_state`
- exit span 提取 `found`、`cert_sn_prefix`（前 8 位）
- 测试：`ca.get_cert` 查询失败时 trace 包含 `aid` 和 `found=false`

**Task 1.3: Auth 模块 enter/exit span**
- 新增 `_TracingWS` 封装
- enter span 提取 `method`、`aid`、`auth_method`
- exit span 提取 `success`、`created`
- 测试：`auth.verify` 失败时 trace 包含 `aid` 和 `auth_method`

**Task 1.4: Group 模块 enter/exit span**
- 新增 `_TracingWS` 封装
- enter span 提取 `method`、`group_id`、`caller_aid`、`member_count`
- exit span 提取 `group_id`、`member_count`
- 测试：`group.create` 成功时 trace 包含 `group_id` 和 `member_count`

**Task 1.5: Gateway relay span 补字段**
- `relay_in` span 补充 `route`、`namespace`、`method`、`aid`、`instance_id`
- `relay_out` span 补充 `status`、`error_code`
- 测试：service_plane 路由时 trace 包含 `route=service_plane` 和 `instance_id`

#### Phase 2: SDK 展示改造

**Task 2.1: 树状展示逻辑**
- 新增 `_format_trace_tree(spans)` 函数
- 按 `ts` 排序，维护栈识别嵌套
- enter/exit 配对，exit 时计算 duration
- 返回多行字符串（带缩进）

**Task 2.2: 字段展示规则**
- enter span：展示 `method`、`aid`、`route` 等关键字段
- exit span：展示 `status`、`found`、`error_code`、`dur`
- 单行最多 3-4 个字段

**Task 2.3: 向后兼容**
- 识别旧格式 `action=process`，按单行展示
- 混合格式分别处理

**Task 2.4: 集成到 transport.py**
- 修改 `_trace_observer` 回调，调用 `_format_trace_tree`
- 输出到日志（`self._log.info`）

#### Phase 3: 测试验证

**Task 3.1: 单元测试**
- `test_trace_span_enter_exit.py` — 验证 enter/exit span 生成
- `test_trace_tree_format.py` — 验证 SDK 树状展示

**Task 3.2: 集成测试**
- 运行 `python -X utf8 tests/integration_test_e2ee.py`
- 验证 `message.v2.put_peer_pk` 失败时 trace 包含完整诊断信息
- 验证嵌套调用（message → ca）的 span 正确合并

**Task 3.3: 手动测试**
- `aun login yayi2000.agentid.pub` 触发 `put_peer_pk` 失败
- 检查日志输出是否包含 `peer_aid`、`ca.enter`、`found=false`、`error_code`

---

### 5. 向后兼容

**旧 SDK 收到新 span：**
- 忽略不认识的字段（`action=enter/exit`、业务字段）
- 仍能展示基本路径和耗时

**新 SDK 收到旧 span：**
- 识别 `action=process`，按单行展示
- 不影响现有功能

**trace mode 不变：**
- 仍为 `off/log/diag` 三档
- 不引入新模式

---

### 6. 安全审查

**禁止字段清单：**
- token、refresh_token、access_token
- 私钥（private_key、priv、secret）
- 证书 PEM（cert_pem、cert、certificate）
- 签名原文（signature、sig_raw）
- challenge nonce、密码（password、pwd）

**允许字段清单：**
- aid、method、curve、lifecycle_state
- found、error_code、error_msg（不含敏感信息）
- cert_sn 前缀（前 8 位）
- route、namespace、instance_id
- group_id、member_count、delivered_count

**审查机制：**
- 代码审查时检查所有 span 字段来源
- 禁止直接 `span.update(params)` 全量复制
- 必须显式白名单提取

---

### 7. 性能影响

**额外开销：**
- 每个 RPC 多生成 1 个 span（enter + exit 共 2 个，原来 1 个）
- 每个 span 增加 3-5 个业务字段（约 50-100 字节）
- SDK 展示增加树状格式化（O(n log n) 排序 + O(n) 遍历）

**预估影响：**
- diag 模式下单次 RPC 增加 ~200 字节网络传输
- SDK 格式化耗时 <1ms（100 个 span 以内）
- 对 off/log 模式无影响（不生成 span）

**优化措施：**
- span 数量上限保持 32 个（已有限制）
- 字段值截断（error_msg 最多 200 字符）
- 仅 diag 模式生成详细字段

---

## 实施顺序

1. **Phase 1.1-1.2**：Message + CA（最高优先级，覆盖 80% 失败场景）
2. **Phase 2**：SDK 展示改造（让 Phase 1 的字段可见）
3. **Phase 3.2-3.3**：集成测试 + 手动验证
4. **Phase 1.3-1.5**：Auth + Group + Gateway（补全剩余模块）
5. **Phase 3.1**：单元测试（回归保护）

---

## 成功标准

**功能完整性：**
- ✅ `message.v2.put_peer_pk` 失败时，trace 包含 `peer_aid` 和 `ca.get_cert` 的 `found=false`
- ✅ `ca.get_cert` 查询失败时，trace 包含 `aid`、`curve`、`lifecycle_state`
- ✅ SDK 展示为树状结构，嵌套调用正确缩进
- ✅ enter/exit span 配对，exit 展示 duration

**向后兼容：**
- ✅ 旧 SDK 收到新 span 不报错
- ✅ 新 SDK 收到旧 span 降级展示

**安全合规：**
- ✅ 所有 span 字段通过白名单审查
- ✅ 不包含 token、私钥、证书 PEM、签名原文

**性能可接受：**
- ✅ diag 模式下单次 RPC 增加传输 <500 字节
- ✅ SDK 格式化耗时 <5ms

---

## 风险与缓解

**风险 1：span 数量爆炸**
- 缓解：保持 32 个上限，超出时截断最早的 span

**风险 2：敏感信息泄露**
- 缓解：代码审查 + 白名单机制 + 单元测试覆盖

**风险 3：向后兼容性破坏**
- 缓解：旧 SDK 忽略新字段，新 SDK 识别旧格式

**风险 4：性能回退**
- 缓解：仅 diag 模式生成详细字段，off/log 模式不变

---

## 后续扩展

**Phase 4（可选）：**
- 其他语言 SDK（Go/TS/JS/C++）展示改造
- 其他服务模块（Storage/Stream/Mail）span 补全
- Trace 聚合分析工具（按 trace_id 查询完整链路）

**Phase 5（可选）：**
- Trace 持久化（写入 ClickHouse/Elasticsearch）
- Trace 可视化（Web UI 展示调用树）
- Trace 告警（失败率/耗时异常自动通知）
