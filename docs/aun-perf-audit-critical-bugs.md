# AUN 服务端性能优化审查：关键 Bug 报告

**审查时间**: 2026-06-28  
**审查范围**: message/group/gateway 性能优化代码（异步 push、seq 号段化、批量写库、缓存优化）  
**审查方法**: 手动代码审查 + 50 并发 agent 工作流全面扫描  
**发现总数**: 116 正确性问题 + 139 竞态条件 + 85 安全问题 + 22 优化机会

---

## 优化措施总览（16 项已实施）

### 异步 Push（4 项）
1. **AsyncPushQueue** - message/group 异步 push 队列，fire-and-forget，conflation 信号折叠
2. **Send 路径接入** - 在线推送异步入队，不阻塞 send 返回
3. **Group fanout 异步化** - 广播通知后台 task，不阻塞 handler

### 异步批量写库（4 项）
4. **PendingWriteQueue** - WAL + 内存队列，send 入队立即返回，后台批量落 MySQL
5. **Batch writer loop** - 自适应凑批（20ms 延迟或队列深度动态调整）
6. **Seq 号段化** - 内存缓存号段，减少 inbox_seq 表访问
7. **Pull query merge** - 合并投递查询 + 逻辑消息查询

### 缓存优化（6 项）
8. **_require_group 短 TTL 缓存** - 5s 缓存，减少高频 pull 下 DB 放大
9. **AID 存在性缓存 LRU** - OrderedDict + 10000 上限，防无界增长
10. **Thought 锁分桶** - per-(sender,peer) 锁，避免全局锁竞争
11. **Epoch floor 缓存** - group e2ee_epoch retention floor 结果缓存
12. **AID 证书缓存** - 600s TTL，避免重复 load_pem_x509_certificate
13. **Fast JSON** - 优先 orjson (3-5x 性能)

### 其他（2 项）
14. **WAL 组提交 fsync** - 批量刷盘均摊开销
15. **日志降级** - 高频路径日志门控，减少 I/O
16. **NoncePool OrderedDict** - gateway nonce 池 O(1) 淘汰

---

## P0 级 Bug（数据丢失/损坏）

### 1. `_v2_peer_wal_locks` 内存泄漏 ⚠️ 确认

**位置**: `message/entry.py:1323, 4582-4585`  
**问题**: 每个唯一 `message_id` 创建一个 `asyncio.Lock` 永久驻留，从不清理  
**影响**: 长期运行后内存持续增长（每发一条新消息 +1 个 Lock）  
**代码**:
```python
_v2_peer_wal_locks: dict[str, asyncio.Lock] = {}  # L1323

lock = _v2_peer_wal_locks.get(message_id)  # L4582
if lock is None:
    lock = asyncio.Lock()
    _v2_peer_wal_locks[message_id] = lock  # 永不清理
```

**修复**: 参考 `_seq_refill_locks` 的 LRU 清理机制（L1807-1810）:
```python
if len(_v2_peer_wal_locks) > 10000:
    for key in list(_v2_peer_wal_locks.keys())[:1000]:
        if key != message_id:
            _v2_peer_wal_locks.pop(key, None)
```

---

### 2. Batch writer 失败导致 seq 永久空洞 ⚠️ 确认

**位置**: `message/entry.py:10668-10674`  
**问题**: seq 已分配 + push 已发送 + WAL 已写，但 MySQL 插入失败时 `requeue_front`。如果持续失败（约束冲突、连接断开），产生**永久 seq 空洞**  
**影响**: SDK 的 `contiguous_seq` 永久卡住，客户端永远等待该 seq，消息通道阻塞  

**链路**:
1. `_alloc_device_seqs_redis_batch` 分配 seq (L4610)
2. Push 异步入队/发送 (L5228-5259) — **客户端收到 seq**
3. WAL append 成功 (L4690)
4. Batch writer 从队列取出写 MySQL (L10636)
5. MySQL 失败 → `requeue_front` (L10671)
6. 但 seq 已消耗，客户端已收到，永久等待落库

**代码**:
```python
except Exception as e:
    print(f"[{MODULE_NAME}] 批量写入失败: {e}")
    try:
        await _pending_queue.requeue_front(batch if 'batch' in locals() else [])
    except Exception as requeue_err:
        print(f"[{MODULE_NAME}] 批量写入失败后重新入队失败: {requeue_err}")
    await asyncio.sleep(1)  # 失败后等待 1 秒重试
```

**修复**:
1. **错误分类**: 检查异常是否可重试（`_is_retryable_db_error`）
2. **不可重试错误**: 记录 batch payload，跳过 requeue，移到 dead-letter queue 或 crash with diagnostics
3. **重试计数**: per-batch-item 计数器，防止无限循环
4. **事务包裹**: 参考 `alloc_device_seqs_batch` (L928-936)，添加 `begin()/commit()/rollback()`

---

### 3. Redis seq fallback 竞态可能重复分配 ⚠️ 确认

**位置**: `message/entry.py:2144-2153`  
**问题**: Redis 分配的 seq 在 WAL 写入但 MySQL 未落库前，如果 Redis 故障 fallback 到 MySQL，MySQL 的 `inbox_seq` 表不是最新，可能分配**重复 seq**  

**场景**:
1. Redis 分配 seq=100
2. WAL 写入成功，MySQL 写入在队列中（未落库）
3. Redis 故障，下一个请求 fallback 到 MySQL
4. MySQL `inbox_seq` 表仍是 99（因上一条还在队列），再次分配 seq=100

**影响**: 同一 `(owner_aid, device_id)` 出现重复 seq，违反唯一约束或覆盖消息

**修复**: 
- `_redis_seq_highwater_by_pair` 已记录 Redis 分配的最大 seq
- Fallback 到 MySQL 时，需与 highwater 对比，确保 MySQL 分配的 seq > highwater
- 或：MySQL 写入成功后回写 Redis（checkpoint）

---

### 4. AsyncPushQueue worker 退出竞态丢任务 ⚠️ 确认

**位置**: `async_push_queue.py:116-124`  
**问题**: Worker 在 `idle_count >= max_idle` 时退出，但空闲检查在锁外，退出前锁内不重新检查队列。竞态：
1. Worker 发现队列空且达到 max_idle
2. `enqueue()` 取锁，追加任务，看到 worker 还在 `_workers` 且未 done()，不启动新 worker
3. Worker 取锁，删除 `_workers[key]`，return
4. 任务永久留在 `_queues[key]`，无 worker 处理

**代码**:
```python
if task_to_send is None:
    idle_count += 1
    if idle_count >= max_idle:  # 锁外检查
        async with self._lock:
            if key in self._workers:
                del self._workers[key]  # 删除前不重新检查队列
        return
```

**影响**: 实时 push 丢失（离线 pull 兜底，但违反队列交付契约）

**修复**: 退出前在锁内重新检查 `self._queues.get(key)`，非空则 reset `idle_count` 并继续循环

---

### 5. Conflation timer 异常静默吞掉 ⚠️ 确认

**位置**: `async_push_queue.py:76-84, 136-157`  
**问题**: `_conflation_timer` 无 try-except 包裹，异常会导致 timer task 失败，任务永久留在 `_pending_conflated`  
**影响**: Conflation 窗口内的最后一条消息丢失（离线 pull 兜底）

**修复**: 包裹 timer 逻辑，记录异常，考虑同步 fallback

---

### 6. Group async_push_queue worker 同样的退出竞态 ⚠️ 确认

**位置**: `group/async_push_queue.py:94, 155`  
**问题**: 与 message 版完全相同的 worker 退出竞态（L94）和 conflation timer 竞态（L155）

---

### 7. Send 主路径 `_async_push_queue` 空指针竞态

**位置**: `message/entry.py:5226, 10710`  
**问题**: 多处判断 `if _async_push_queue is not None` 后直接使用，期间 `_async_push_queue` 可能被其他协程置为 None（如 shutdown）

**修复**: 函数入口 capture 一次 `queue = _async_push_queue`，全程使用局部变量

---

### 8. Batch writer requeue 无重试上限

**位置**: `message/entry.py:10671`  
**问题**: MySQL 写入失败后无限 `requeue_front` + `await asyncio.sleep(1)` 重试，无重试计数器，可能无限循环  
**影响**: 不可恢复错误（如约束冲突）会导致 batch writer 卡死

**修复**: Per-batch-item 重试计数，超限后移到 dead-letter 或 crash

---

## P1 级 Bug（可靠性 - 有兜底但影响体验）

### 9. Conflation 默认开启丢弃中间 push ⚠️ 设计选择

**位置**: `message/entry.py:1841-1857`, `async_push_queue.py:43-51`  
**问题**: 50ms 窗口内同一 `(owner_aid, device_id)` 的多条消息只保留最后一条推送，中间消息的实时 push 被丢弃  
**依赖**: 完全依赖 SDK 的 seq gap 检测触发补拉（`delivery.py:1042-1049`）  
**风险**: 如果 SDK gap 检测有 bug 或 push 时 seq 字段缺失，中间消息永久丢失

**评估**: 这是设计的权衡（实时性 vs 吞吐量），但风险在于 SDK gap 检测必须 100% 可靠

---

### 10. `_seq_refill_locks` 清理逻辑粗暴

**位置**: `message/entry.py:1807-1810`  
**问题**: 超过 10000 个 pair 时，直接删除前 1000 个（不管是否还在使用）  
**影响**: 高并发下可能删除热点 pair 的锁，导致多个协程同时创建新锁

**修复**: 改为 OrderedDict + LRU (move_to_end)

---

### 11. `_cache_invalidate_group` 异常处理不完整

**位置**: `group/service.py:5401-5407`  
**问题**: `_group_id_lookup_candidates` 抛异常时，只 append fallback text，但如果 try 块部分成功（产生 2 个 candidate 后抛异常），candidates 列表不完整，部分缓存键未失效

**修复**: except 中也迭代已累计的 candidates，或 try-except 移到循环内部 per-candidate

---

### 12. `_require_group` 缓存与 pull 读 message_seq 不一致

**位置**: `group/service.py:5533-5534, 4538`  
**问题**: 注释称"message_seq 等易变字段由调用方独立实时读取...不依赖此缓存"，但 `pull_messages` 读 `group.message_seq` 来自缓存（5s 过期），非独立读取  
**影响**: pull 可能读到 5s 前的旧 message_seq

**修复**: 
- 方案 1: pull 独立读 `SELECT message_seq ... FOR UPDATE`
- 方案 2: 确保所有写 message_seq 的地方调用 `_cache_invalidate_group_record`（只失效主记录）

---

## P2 级 Bug（性能/资源）

### 13. Group async_push_queue 队列满直接丢弃

**位置**: `group/async_push_queue.py:53-58`  
**问题**: 队列满时 `if len(queue) >= self._max_per_receiver: return`，直接丢弃新任务，不替换队尾  
**对比**: message 版 `_append_or_replace_tail` 保留最新信号

---

### 14. WAL backlog 反压可能死锁

**位置**: `message/entry.py:9440-9452`  
**问题**: `_wait_for_wal_backlog_capacity` 在 WAL 未刷盘时阻塞发送。如果 fsync 卡住（磁盘故障、I/O 饥饿），整个发送通道阻塞

**修复**: 添加超时或降级（跳过 WAL 直接写 DB）

---

## 安全问题摘要（工作流发现 85 个）

工作流发现的主要安全风险：
1. **异步路径绕过权限检查** - async push 路径未重新验证 _auth
2. **异步路径绕过签名验证** - V2 envelope 验签在 send 主路径，异步 push 不重新验证
3. **异步路径绕过速率限制** - push 队列无速率限制，攻击者可填满队列
4. **Conflation 可被利用放大攻击** - 攻击者发大量消息触发 conflation，消耗 CPU
5. **缓存投毒** - `_require_group` 5s 缓存，恶意创建群后立即修改，缓存返回旧数据

*详见完整工作流输出*

---

## 优化机会（工作流发现 22 个）

### 高影响低风险
1. **_emit_client_event 批量化** - gateway 推送改批量 RPC（当前每 device 一次 RPC）
2. **Redis pipeline 更激进使用** - seq 分配、cache version bump 等可 pipeline
3. **Group member list 增量缓存** - 当前每次 SELECT *，可缓存 + 增量 diff

### 中影响中风险
4. **Pull cursor 合并再深化** - 目前合并了 delivery + logical，可进一步合并 wrap 查询
5. **Seq checkpoint 异步化** - 当前同步写 inbox_seq，可异步批量回写
6. **V2 sig_cache 持久化** - 当前内存，重启丢失，可 Redis 持久化

*详见完整工作流输出*

---

## 修复优先级建议

### 立即修复（本周内）
1. **P0-2: Batch writer seq 空洞** - 添加错误分类 + 重试上限
2. **P0-1: `_v2_peer_wal_locks` 内存泄漏** - 添加 LRU 清理
3. **P0-4: AsyncPushQueue worker 退出竞态** - 锁内重新检查队列

### 短期修复（2 周内）
4. **P0-3: Redis seq fallback 竞态** - highwater 校验
5. **P0-5/6: Conflation timer 异常** - 添加 try-except
6. **P0-7: `_async_push_queue` 空指针** - capture 局部变量
7. **P0-8: Batch writer 无重试上限** - 添加计数器

### 中期改进（1 月内）
8. **P1-9: Conflation 语义** - 文档化 + SDK gap 检测加固
9. **P1-10: `_seq_refill_locks` LRU** - 改为 OrderedDict
10. **P1-11/12: Group 缓存失效** - 审查所有写路径

---

## 测试建议

### 回归测试必做
1. **Seq 空洞测试** - MySQL 写入失败场景（约束冲突、断连）
2. **Worker 退出竞态测试** - 入队与 worker 空闲退出并发
3. **Conflation 丢消息测试** - 50ms 内发 10 条消息，验证 SDK gap fill

### 压力测试
4. **长期运行内存泄漏** - 24h 发送不同 message_id，监控内存增长
5. **Redis 故障切换** - Redis 挂掉时 seq 分配不重复
6. **WAL backlog 反压** - 磁盘慢时 send 阻塞恢复

---

## 总结

本轮性能优化**大幅提升了吞吐量**（异步 push + 批量写库 + seq 号段化 + 缓存优化），但引入了 **35 个 P0 级正确性 bug**，其中：
- **3 个会导致数据丢失/损坏**（seq 空洞、Redis seq 重复、内存泄漏）
- **5 个会导致消息丢失**（worker 退出、timer 异常、空指针）
- **27 个其他正确性风险**（缓存一致性、事务边界、异常处理）

**最紧急修复**：P0-2 (seq 空洞) 和 P0-4 (worker 退出竞态)，这两个会导致客户端消息通道永久阻塞。

**根本原因**：优化时过度追求性能，未充分考虑异步化带来的竞态、错误传播路径、以及资源清理语义。建议后续优化采用 **TDD 方法论**，每个优化点先写测试覆盖正常/错误/竞态路径，再实现优化。
