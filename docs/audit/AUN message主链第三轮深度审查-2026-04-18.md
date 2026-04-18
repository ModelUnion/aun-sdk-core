# AUN message 主链第三轮深度审查

日期：2026-04-18
范围：
- `extensions/services/message`
- 关联链路：`gateway`、`ca`、SDK 重连/重试语义

目标：把 `message` 这条主链按 **send / pull / ack / reconnect / 多设备** 五段重新掰开，继续追“状态真实落点”和“客户端看到的结果”之间是否一致，重点找那些**平时不报错、但在线上会积累成炸点**的时序问题。

## 一、第三轮关注的不是“有没有校验”，而是“什么时候算成功”

第二轮已经确认，`message` 模块最大的问题不是单点权限判断缺失，而是：

1. 服务端什么时候认为消息已经 authoritative 成功
2. SDK 什么时候会把某条消息当作已成功或已处理
3. event / push / relay / ack 失败时，状态是否还能收敛
4. 多设备与重连交错时，seq 空洞与重复是否被正确定义

也就是说，这一轮真正要追的是：

- **send 返回的成功到底代表什么**
- **pull / ack 推进的是什么 cursor**
- **push 与 DB 提交的先后有没有倒挂**
- **多设备回填与正常拉取是否会互相踩 seq**
- **重连后重复提交是否会造成重复副作用**

---

## 二、主链拆解

### 1. 发送主链
`SDK -> gateway relay -> message.send -> aid existence check -> seq allocator -> persist/push -> return`

### 2. 拉取主链
`SDK pull -> message.pull -> device cursor / ack floor / legacy backfill -> DB query -> return messages`

### 3. ack 主链
`SDK ack -> message.ack -> update ack/cursor -> publish event -> return`

### 4. 重连主链
`disconnect -> SDK reconnect -> re-auth -> resume send/pull/ack -> gap fill`

### 5. 多设备主链
`same aid / multiple devices -> per-device cursor -> legacy backfill -> push fanout / pull coexist`

这五段链路单看都还能工作，但一旦互相交错，问题就会集中暴露在：

- seq 先分配还是先成功
- cursor 先推进还是先通知
- push 先发还是先 commit
- dedup 是持久还是内存
- backfill 是否与常规 pull 并发安全

---

## 三、第三轮确认的关键问题

### A. `send` 返回时，DB 主记录已落地，但 `message.received` 只是 fire-and-forget
- 结论：当前 send 成功返回，最多只能说明**服务端 authoritative 接受并记录了这条消息**；并不能说明接收方设备已收到、已展示、已解密。
- 问题在于：
  - push / event 发布不是事务内强保证
  - 发送成功与“接收方已可见”之间还有明显距离
- 风险：
  - 如果接口继续返回接近 `delivered` 的语义，SDK 和上层业务会过度乐观
- 正确语义应是：
  - `accepted` / `persisted` 才是当前最接近真实的成功层级
  - `delivered` 需要额外确认链路支持，当前并没有

### B. 跨域 send 先分配本地 `sender_seq`，relay 失败会留下永久空洞
- 证据链：第三轮重新核对 `message._send_cross_domain` 路径
- 问题：
  - 本地先消耗 `sender_seq`
  - 然后才走 federation relay
  - relay 一旦失败，本地 seq 已经无法回收
- 风险：
  - 发送方可能看见 seq 前进，但实际上远端根本未接受
  - 若 SDK 把 seq 当作真正发送成功号，会提前推进本地状态
- 定性：
  - 这不是普通 seq 空洞，而是**失败路径制造出来的语义性空洞**

### C. `_backfill_legacy_messages_for_device` 在 pull / ack 并发下可能制造 device seq 空洞
- 问题：
  - 该回填逻辑不只在一个单一入口发生
  - pull 与 ack 路径都会触发相关补齐
  - 多设备、重连、老设备首次上线交错时，会对同一 device cursor 周边做并发操作
- 风险：
  - 某设备还未真正接收的旧消息被标记进更高 cursor 区间
  - 合法未读消息被“逻辑跳过”
- 性质：
  - 这是典型“补偿逻辑与正式推进逻辑未隔离”的问题

### D. dedup 只在内存里，进程重启后完全失效
- 问题：
  - 对 send / push / federation inbound 来说，很多重复保护只依赖进程内 map 或短期内存结构
- 风险：
  - 进程重启后，相同 `message_id` 或同一重试请求无法被认出
  - 客户端在“响应丢了、重试一次”场景下，最容易重复执行
- 主链影响：
  - 这会把 gateway 断线清理问题直接放大成真实重复消息风险

### E. ack 中 `_publish_event` 失败时，DB 已更新但接口返回失败
- 问题：
  - ack 的 authoritative 状态已经写入 DB
  - 但后续发布事件失败，会让整个 RPC 看起来像失败
- 风险：
  - 客户端重试 ack
  - 调用方误以为“服务端没收下”
- 结果：
  - 状态其实已推进，但外部看到错误
  - 这是一类非常典型的“主状态成功、派生动作失败、接口整体报错”的坏语义

### F. 某些 push 可能已发出，但 DB 事务随后回滚
- 问题：
  - 如果消息在事务提交前就被投递给在线设备，后续 DB commit 一旦失败，接收方可能已经先看见消息
- 风险：
  - 接收端展示过的消息，之后 pull 再也拉不到
  - 上层会把这种情况理解成“消息幽灵”或“已读后消失”
- 这是主链里非常危险的倒挂：
  - **可见性早于 authoritative 持久化**

### G. 多设备语义里，`ack`、`cursor`、`legacy backfill` 的边界还不够统一
- 问题：
  - 当前有 sender 视角、recipient inbox 视角、device 视角几套 seq/cursor
  - 回填逻辑试图兼容老设备与新设备，但边界比较脆
- 风险：
  - 一个设备的补偿推进影响另一个设备对“未读/已读/需补洞”的判断
- 这类问题单测往往不容易暴露，但在线上多设备并发会持续积累。

---

## 四、问题分级

### P0：最容易在线上造成错误业务语义

#### P0-T1. 跨域 send 先分配本地 seq，再 relay
- 影响：失败路径产生语义性空洞
- 结果：客户端可能把失败消息当成功推进本地状态

#### P0-T2. dedup 纯内存，重启后失效
- 影响：断线重试 / 进程重启后重复执行副作用
- 结果：重复消息、重复 relay、重复状态推进

#### P0-T3. send 返回语义过于乐观
- 影响：接口成功被理解成“已送达”
- 结果：业务层误判交付状态

#### P0-T4. `legacy backfill` 并发导致 device seq 空洞
- 影响：合法消息可能被跳过
- 结果：设备视角出现长期未补的历史洞

### P1：会造成“服务端已变更、客户端却看到失败”

#### P1-T5. ack 的 DB 已成功但 `_publish_event` 失败导致接口报错
- 影响：调用方误重试
- 结果：语义混乱，虽然 DB 往往还能收敛

#### P1-T6. push 先发、事务后回滚
- 影响：接收端可见性先于 authoritative state
- 结果：消息幽灵 / pull 不一致

#### P1-T7. 多设备 cursor / ack / backfill 边界不清
- 影响：不同设备对未读范围理解不一致
- 结果：长尾错乱、偶发丢感知

### P2：当前可接受但必须明文化的点

#### P2-T8. seq block cache 天生允许合法空洞
- 影响：崩溃后会留未消费尾段
- 结论：不是 bug，但必须明确“空洞 != 丢消息”。

#### P2-T9. AID existence cache 是安全性与可用性折中
- 影响：短窗口内可能仍认为目标可达
- 结论：可通过缩短 TTL 缓解，但本质是缓存策略问题。

---

## 五、最核心的状态机误区

### 1. 把“已接收”误写成“已送达”
当前 send 最多能证明：
- 服务端收到了请求
- 基本校验通过
- DB 或发送记录已写入

但它还不能证明：
- 接收方在线设备已收到
- 接收方 pull 一定能马上拉到
- 接收方已经展示/解密

### 2. 把“断线后未收到响应”误写成“操作失败”
在 `gateway` 和 `message` 主链配合下，最危险的不是一次明确失败，而是：
- 其实已成功写入
- 但响应回不去
- SDK 重试后再执行一次

### 3. 把“补偿逻辑”与“正式推进逻辑”混在一起
`legacy backfill` 本来是兼容路径，但它会参与 device seq 推进，这意味着：
- 兼容性补偿不再只是补偿
- 它开始影响 authoritative cursor
- 一旦并发，就容易污染正式状态

---

## 六、建议修复顺序

### 第一批：先修 send 成功语义
1. 降级 send 对外语义：从接近 `delivered` 改为 `accepted/persisted`
2. 跨域 send 调整顺序：先 relay，后本地 sender seq / 或至少明确失败不推进成功语义
3. 把 `message_id` 作为严格幂等键贯穿 send / relay / retry

### 第二批：修重复执行与重启失忆
1. dedup 从纯内存提升为 durable 去重记录或最少可恢复状态
2. gateway 断线后的 pending 不再立即删除
3. SDK 重试统一要求携带稳定 `message_id`

### 第三批：修多设备与 backfill
1. `legacy backfill` 与正式 cursor 推进解耦
2. 同一 device 的 backfill / pull / ack 串行化或加版本保护
3. 明确“哪个字段是 authoritative device cursor”

### 第四批：修派生动作失败语义
1. ack 的 DB 更新成功后，event publish 失败不得把整个 ack 伪装成失败
2. push 发送必须晚于事务提交，避免消息幽灵

---

## 七、最该补的测试

### A. send / retry 测试
- 跨域 relay 失败时，不得返回误导性成功
- 同一 `message_id` 重试，不得重复发出
- 断线后响应丢失，重试不得重复落库

### B. push / commit 顺序测试
- 人为让 push 成功、DB commit 失败
- 断言接收端不会看到最终不可拉取的幽灵消息

### C. ack / event 测试
- DB ack 成功、event publish 失败
- 断言接口语义与 DB 状态一致，不误导调用方

### D. 多设备 / backfill 测试
- 两个设备同时 pull/ack/backfill
- 断言 device cursor 不跳过合法未读消息

### E. 重启恢复测试
- 重启后对同一 `message_id` 重试
- 断言不会重复执行 send / relay / push

---

## 八、结论

`message` 主链第三轮最值得强调的结论是：

1. **当前 send 成功不等于 delivered**
2. **跨域 send 的 seq 先分配后 relay，会在失败路径制造语义性空洞**
3. **dedup 只在内存里，意味着“重启一次，幂等就丢”**
4. **`legacy backfill` 已经不只是兼容逻辑，而是在影响 authoritative device cursor**
5. **ack / push / event 这些派生动作与主状态写入的先后顺序，还存在倒挂**

如果只挑这条链最像线上炸点的四个问题，就是：

- 跨域 send 成功语义错误
- durable dedup 缺失
- backfill 并发污染 device cursor
- push 与 commit 顺序未彻底收敛

它们共同指向同一个根问题：

> `message` 现在最需要统一的，不是“能不能发消息”，而是“消息在什么时刻才算 authoritative 成功，以及失败后如何保证不会重复、不会伪成功、不会伪丢失”。
