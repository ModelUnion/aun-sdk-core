# AUN 服务端性能优化清单

**审查时间**: 2026-06-23  
**审查方法**: 16 个独立 finder agent 深度读取代码 + 对抗复核 + 架构师综合  
**审查范围**: gateway, auth, ca, message, group, storage, nameservice, aid_custody, stream, service_proxy  
**确认问题**: 101 条（P0×1 + P1×22 + P2×64 + P3×14）  

---

## 执行摘要

### 统计汇总

- **按严重级别**: P0(1) / P1(22) / P2(64) / P3(14)
- **按类别**: DB(44) / Network(23) / CPU(19) / Concurrency(12) / Memory(3)
- **按模块**: group(26) / gateway(18) / message(14) / storage(14) / nameservice(9) / 其他(20)

### 吞吐瓶颈最重的模块

1. **auth** — P0 全局锁验签（致命）
2. **storage** — 4 个 P1（配额 COUNT/aid_type 每次 RPC/复制文件夹 N×RPC/删除文件夹串行）
3. **group** — 3 个 P1（v2_send 串行查询/pull 串行装饰附件/get_next_group_no 全表扫）
4. **message** — 2 个 P1（V2 Merkle 阻塞/query_online N+1）

### 系统性横切模式（跨模块反复出现）

1. **事件循环阻塞** — ECDSA/Merkle/sha256/YAML/ZIP 未走 executor
2. **串行扇出** — 群发/广播/元数据查询串行 await，缺 gather
3. **N+1 查询** — 循环内逐个 DB acquire / Redis 逐键 / 逐个 RPC
4. **全表聚合** — COUNT(*)/OFFSET 分页/REGEXP 扫描，缺独立计数表
5. **autocommit + 多次 acquire** — 单逻辑请求跨多事务，竞态 + 放大池占用
6. **重复序列化/深拷贝** — 同一 AID 多设备各自 dumps/深拷贝 event

---

## P0（立即修复，阻塞并发能力）

### 1. auth/entry.py:814-827 — AID 登录全局锁串行化所有验签

**问题**: 所有 AID 登录排队等一把全局锁，锁内执行 ECDSA 验签（数 ms）。高并发登录时吞吐崩塌。

**证据**:
- Line 814: `async with self._global_lock` 全局锁保护整个验签逻辑
- Line 816-821: 锁内调用 `self._verifier.verify_challenge_response` 同步 ECDSA 验签
- 所有并发登录请求串行化，无法利用多核

**优化**: asyncio.Lock 仅保护 verifier 引用读取（极短临界区），验签移到锁外 `await asyncio.to_thread`；AIDVerifier._pending 加细粒度锁。

**风险**: 🔴 **高** — _pending 竞态需细化锁粒度，reload 引用切换需 RCU 模式，需完整并发测试。

---

## P1（显著影响吞吐，22 条）

### 低风险快赢（优先）

#### 2. message/entry.py:3048-3052 — V2 P2P 校验路径事件循环内同步重算 Merkle 树 🚀

**问题**: `compute_merkle_root(recipients)` 在事件循环同步执行，大量 recipients（100+ 设备）时阻塞数十 ms。

**优化**: 改为 `await asyncio.to_thread(compute_merkle_root, recipients)`，或复用 line 3461 已构建的 merkle_layers。

**风险**: 🟢 **低** — 纯计算卸载，不改变验签逻辑。

---

#### 3. message/entry.py:6128-6129 — query_online 逐 AID 串行 Redis EXISTS（N+1）🚀

**问题**: 循环内逐个 `await self._online_tracker.is_online_async(aid)`，N 个 AID = N 次 Redis 往返。

**优化**: `asyncio.gather` 并发 N 个查询，或在 OnlineTracker 增加批量方法用 Redis pipeline。

**风险**: 🟢 **低** — gather 语义等价，pipeline 需验证 decode_responses=False 下结果解析。

---

#### 10. storage/entry.py:2451-2470 — aid_type_resolver 每次 RPC 无跨请求缓存 🚀

**问题**: 每次权限校验都 `await group.get_aid_type(aid)`，高频热路径重复 RPC。

**优化**: 进程级 TTL 缓存 `{aid: (timestamp, aid_type)}`，TTL=300s，LRU 10000 条。

**风险**: 🟢 **低** — AID 类型变更后最多 5 分钟 stale，可通过 invalidate API 主动清理。

---

#### 15. group/repository.py:3640-3668 — cursor 更新内联子查询查 groups 🚀

**问题**: `UPDATE device_cursors SET ... WHERE group_id IN (SELECT id FROM groups WHERE ...)`，子查询每次执行。

**优化**: 全面推广 `_fast` 路径，调用方传入 `group_msg_max/group_event_max`，废弃内联子查询版本。

**风险**: 🟢 **低** — 调用方在 pull 时已查过 groups 拿到 message_seq/event_seq，传入即可。

---

#### 17. storage/repository.py:753-817 — update_folder_subtree_paths 两次 acquire 非原子 🚀

**问题**: 先 SELECT 查子路径，再第二次 acquire 执行 UPDATE，两次 acquire 非原子。

**优化**: 删除第一次 SELECT，直接执行 `UPDATE WHERE path LIKE`（SQL 中 LIKE 条件已足够），单连接单事务完成。

**风险**: 🟢 **低** — UPDATE WHERE path LIKE 与 SELECT WHERE path LIKE 语义相同，去 SELECT 无副作用。

---

#### 20. nameservice/server.py:2868-2879 — 快照下载同步阻塞读取整个 ZIP 🚀

**问题**: `open(zip_path,'rb').read()` 同步读取整个 ZIP（可能数十 MB）到内存，阻塞事件循环。

**优化**: 改用 `starlette.responses.FileResponse(path)` 让框架流式传输，无需全量内存。

**风险**: 🟢 **低** — FileResponse 自动处理流式与 Content-Length，需测试与 Content-Disposition 头兼容。

---

### 需谨慎验证（事务/竞态/架构变更）

#### 12. storage/service.py:485-495 — 每次写操作都 COUNT(*) 全表聚合 ⚠️

**问题**: 每个对象写入前调 `_check_quota`，执行 `SELECT COUNT(*), SUM(size_bytes)` 全表聚合。

**优化**: 独立 quota 表维护 `{owner_aid: used_bytes, object_count}`，写操作 `UPDATE quota`；进程级缓存 TTL=5s。

**风险**: 🔴 **高** — 独立 quota 表需保证与 object 表一致性（触发器或应用层事务），不是纯性能优化。

---

#### 18. storage/repository.py:2381-2409 — blob 引用计数读写竞态 ⚠️

**问题**: `blob_ref_increment/decrement` 先 `SELECT ref_count` 再 `UPDATE SET ref_count=...`，两次 acquire，autocommit=True 下非原子。

**优化**: 写+读放入单连接显式事务（`await conn.begin()`）并 `SELECT...FOR UPDATE`，确保读到自身写入结果。

**风险**: 🟡 **中** — 需确保 blob 去重路径有行为影响，需补并发测试。

---

### 其他 P1（14 条）

详见完整清单第 4-9、11、13-14、16、19、21-22 条。

---

## P2（中等影响，64 条）

### 低风险快赢（部分列举）

- **gateway/ws_server.py:2588** — dispatch_event 全量去重缓存清理，删除循环内调用 🚀
- **gateway/ws_server.py:3554** — 消息调试记录增加 enable 开关（默认 false）🚀
- **gateway/ws_server.py:9709** — JWT 验签改 `to_thread` 🚀
- **gateway/online_state.py:74** — Redis pipeline 4 命令合并 Lua 🚀
- **gateway/federation_client.py:636** — well-known 查询连接池复用 🚀
- **gateway/relay.py:164** — agent.md 缓存 miss 自旋改 Event 通知 🚀
- **message/entry.py:4895** — V1+V2 sender 查询改 gather 🚀
- **group/service.py:3412** — send_message 删除冗余游标缓存失效 🚀
- **group/service.py:3377** — send_message 附件验证改 gather 🚀
- **group/entry.py:7249** — RPC handler dict 改模块级常量 🚀

详见完整清单第 23-79 条（57 条，其中 30+ 条标 🚀 低风险快赢）。

---

## P3（轻微影响，14 条）

代码质量/可维护性改进，对吞吐影响有限。详见完整清单第 80-93 条（已省略，可按需查阅）。

---

## 完整问题清单（101 条）

**文件位置**: 
- 原始 JSON: `C:\Users\ready\AppData\Local\Temp\claude\...\confirmed_items.json`
- 架构师综合: `C:\Users\ready\AppData\Local\Temp\claude\...\synthesis.txt`

每条包含：
- 文件路径与行号/函数名
- 问题描述 + 代码证据
- 优化建议 + 风险评估 + 正确性安全标志
- 复核者确认的证据

**查询方式**: 
```bash
# 按模块过滤
jq '.[] | select(.file | contains("gateway"))' confirmed_items.json

# 按严重级别过滤
jq '.[] | select(.severity == "P1")' confirmed_items.json

# 按类别过滤
jq '.[] | select(.category == "db")' confirmed_items.json
```

---

## 下一步建议

### 立即行动（高优先级）

1. **修复 P0**（auth 全局锁），否则登录高峰雪崩
2. **快赢 P1**（上面标 🚀 的 6 条）：改动 < 20 行，收益显著
3. **并行推进 P2 快赢**（30+ 条标 🚀）：积少成多，单条 1-2 小时

### 谨慎处理（需验证）

- 标 ⚠️ 的问题（事务一致性/竞态/架构变更）需完整并发测试
- 独立 quota 表、blob 引用计数、cursor 同步等涉及数据正确性，建议 TDD

### 长期优化

- Redis 批量接口（OnlineTracker、CA、group）
- 流式 ZIP（nameservice snapshot）
- CT log 内存副本（ca/aid_custody）

---

## 审查元数据

- **Agent 数量**: 123（16 finder + 大量 verifier + 1 synthesize）
- **Token 消耗**: 844 万（subagent 总计）
- **耗时**: 22 分钟
- **工具调用**: 1714 次（Read/Grep/Bash）
- **否决率**: 5/145 = 3.4%（对抗复核有效拦截误报）

---

**附录**: 详细的 101 条问题清单见原始 JSON 文件，每条包含完整的代码证据、优化方案、风险评估、复核结论。
