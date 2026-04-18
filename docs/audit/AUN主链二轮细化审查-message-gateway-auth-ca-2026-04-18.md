# AUN 主链二轮细化审查：message / gateway / auth / ca

日期：2026-04-18
范围：
- `extensions/services/message`
- `extensions/services/gateway`
- `extensions/services/auth`
- `extensions/services/ca`

目标：继续压实认证、消息发送、断连清理这条主链上的时序边界问题。

## 一、主链结构

### 1. 认证接入主链
`SDK -> gateway._handle_auth_connect -> auth.verify / aid_login1 / aid_login2 -> ca.get_cert / renew / rekey`

### 2. 单聊消息主链
`SDK -> gateway relay -> message.send -> ca.get_cert -> seq allocator -> deliver/persist`

### 3. 断开与清理主链
`connection close -> gateway pending cleanup -> auth/kernel pending cleanup -> SDK reconnect`

真正危险的不是单个函数，而是几个边界：
1. `gateway` 握手与 session 建立边界
2. `auth` pending challenge 与 CA DB 校验边界
3. `ca` 旧证书 / 新证书状态切换边界
4. `message` 目标 AID 校验、seq 分配、跨域 relay 边界
5. 断开时 pending request 清理边界

---

## 二、二轮重点问题

### A. `auth.aid_login1` 里 pending 先写，再做 CA 校验
- 证据：`extensions/services/auth/entry.py:580-604`
- 关键顺序：
  1. `_aid_verifier.login_phase1(...)`
  2. 将 `request_id` 写入 pending
  3. `await ca.get_cert(aid)`
  4. 若不匹配再 `pop pending`
- 问题本质：
  - 这是典型“先进入待验证状态，再异步做 server-of-record 校验”的窗口
- 风险：
  - 设计上存在 pending 生命周期早于服务端 DB / public key 校验完成的问题
- 建议方向：
  - 更安全的顺序应是：完成 DB/public key 核验后，再正式注册 pending

### B. `auth` 的 `_ws_global_clear()` 与在途 RPC future 存在清理竞态
- 证据：`extensions/services/auth/entry.py:1089-1096`
- 问题：
  - 连接断开时直接把所有 pending future 设异常并清空
  - 若某个 RPC 响应已在路上或正准备投递，会发生竞态
- 风险：
  - 调用方看到“连接丢失”
  - 但服务端可能实际上已处理成功
- 后果：
  - 客户端重试
  - 服务端重复执行
- 后续需要重点核查：
  - auth -> ca / auth -> kernel RPC 中哪些是幂等的，哪些不是

### C. `gateway` 断连时 `_fail_pending_for_connection()` 直接删 pending，响应可能被静默丢弃
- 证据：`extensions/services/gateway/ws_server.py:480-485`
- 问题：
  - 客户端连接断开就把该连接所有 pending 删除
- 风险：
  - 如果 kernel / 下游模块响应刚好晚一点回来，这个响应只能被丢弃
- 业务后果：
  - 客户端看到超时 / 断开
  - 但服务端动作可能已经成功执行
- 对消息链尤其危险：
  - send 这类操作如果客户端重试，很容易形成重复动作，必须强依赖 dedup 才安全

### D. `gateway` 认证成功后再做连接约束检查，时序较脆
- 证据：`extensions/services/gateway/ws_server.py:1766-1775`
- 问题：
  - `_ensure_connection_constraints()` 在 session 建立前做，但多个并发连接时仍可能形成竞态窗口
- 风险：
  - 同一 aid/device/slot 的并发连接在极端情况下都通过约束检查
- 影响：
  - delivery_mode
  - device/session 唯一性
  - 多设备 fanout 语义

### E. `ca.issue_cert` 是典型 check-then-act
- 证据：`extensions/services/ca/entry.py:449-476`
- 顺序：
  1. `get_active_signing_cert`
  2. 若不存在，生成 cert
  3. `get_next_version`
  4. `insert_cert`
- 问题：
  - 两个并发请求可能同时看到“不存在”
- 风险：
  - 同一 AID / curve 下并发发出两张 active_signing 证书
- 主链影响：
  - auth / gateway / SDK 都隐含假设“当前 active_signing 唯一”

### F. `ca.renew_cert` / `ca.rekey` 的状态转换不是一个原子事务
- 证据：
  - `extensions/services/ca/entry.py:558-563`
  - `extensions/services/ca/entry.py:618-629`
- 问题：
  - 旧证书降级 / 新证书插入 / replaces_serial 更新 / old revoke 是多步分离
- 风险：
  - 一旦中间失败，会留下：
    - 旧证书仍有效
    - 新旧同时有效
    - replaces 链不完整
- 主链影响：
  - auth 登录时 cert 归属判断、public key 匹配、active cert 获取都可能被污染

### G. `message._check_aid_exists()` 是 fail-close，但缓存窗口很长
- 证据：`extensions/services/message/entry.py:1145-1181`
- 优点：
  - 已经不是超时就静默放行
- 问题：
  - `_AID_CACHE_TTL = 600`
- 风险：
  - 证书被撤销/删除后，10 分钟内 message 仍可能继续认为目标 AID 可投递
- 性质：
  - 这是“安全性 vs 可用性”上的典型时间窗口问题

### H. `message` 的 seq allocator 使用块缓存，空洞语义要特别小心
- 证据：`extensions/services/message/entry.py:1184-1207`
- 问题：
  - 预分配一段 seq block
  - 进程崩溃时，这段后半未使用 seq 会永久形成空洞
- 影响：
  - 如果上层或 SDK 假设 seq 近似连续，这些洞会影响 pull / ack / 补洞逻辑
- 结论：
  - 这不一定是 bug，但要求客户端和服务端都接受“合法空洞”
  - 不能简单把“有空洞”推导成“消息丢了”

### I. `message` 跨域 send 是“先给 sender 分配本地 seq，再去 federation relay”
- 证据：`extensions/services/message/entry.py:1257-1300`
- 问题：
  - `sender_seq = await _alloc_seq_cached(from_aid)` 先发生
  - 然后才 `gateway.forward_federation`
- 风险：
  - 如果 relay 失败，发送方这边可能已经消耗了 seq
- 需要确认：
  - 返回给 SDK 的 `seq` 是“本地发送确认号”，还是“真正交付序号”
- 若语义不清：
  - 客户端可能把失败消息当成功推进本地状态

### J. `message` 对 federation inbound 的 issuer 绑定校验是好的，但要继续看旁路
- 证据：`extensions/services/message/entry.py:1343-1359`
- 结论：
  - 这里有明确的 `from_aid issuer` 与 `_federation.from_issuer` 一致性检查
- 这是主链里一处做得比较对的安全边界
- 但后续仍需继续核查：
  - 其它链路是否能绕过这层绑定直接进入 send / relay

---

## 三、这条主链上最像“隐蔽炸点”的问题

如果只挑最隐蔽、最可能在线上爆炸的：

1. `auth.aid_login1` 的 pending 注册早于 CA 校验完成
2. `ca.issue_cert` 并发下可能双 `active_signing`
3. `ca.rekey / renew` 非原子状态切换
4. `gateway` 断连直接删 pending，响应静默丢弃
5. `message` 跨域 send 先分配本地 seq 再 relay
6. `message` AID existence cache 10 分钟窗口
7. `auth / gateway / SDK` 对“请求已处理但响应丢了”的幂等策略还不够统一

---

## 四、建议继续压实的顺序

### 第一组：认证状态机
1. `gateway._handle_auth_connect`
2. `auth._rpc_aid_login1 / _rpc_aid_login2`
3. `auth._rpc_verify`
4. `auth._rpc_call_await`
5. `ca.issue_cert / renew_cert / rekey`

目标：
- 看是否存在“一边成功、一边以为失败”的重复执行风险
- 看是否存在旧 cert / 新 cert 状态混用

### 第二组：消息发送状态机
1. `message._rpc_send`
2. `_check_aid_exists`
3. `_alloc_seq_cached`
4. `_send_cross_domain`
5. send 成功 / 失败返回语义

目标：
- 明确 `seq`、`message_id`、delivery status 的真实语义
- 明确失败重试是否会导致重复或跳 seq

### 第三组：断开与重试状态机
1. `gateway._fail_pending_for_connection`
2. `gateway._prune_expired_pending`
3. `auth._ws_global_clear`
4. SDK reconnect 之后如何处理 in-flight call

目标：
- 看超时 / 断开后是否形成“服务端已处理，客户端重试”的重复副作用

---

## 五、结论

这一条主链当前最大的风险，不是“某个 RPC 少了校验”，而是：

- 请求是否已真正完成
- 响应是否真的送达客户端
- 连接断开时 pending 如何收尾
- 证书状态切换是否原子
- send 返回里的 `seq` 到底代表什么

这些问题一旦不统一，最终就会落成两类线上故障：
1. 客户端以为失败而重试，服务端其实已成功
2. 客户端以为成功而推进本地状态，服务端其实没有真正交付

这也是这条主链后续最值得继续深挖的方向。