# AUN 服务端性能优化 - 低风险快赢清单

**优先级**: P1/P2 低风险快赢（标 🚀）  
**原则**: 改动小（< 50 行）+ 风险低 + correctness_safe + 收益显著  
**总数**: 36 条（P1×6 + P2×30）

---

## P1 低风险快赢（6 条）

### #2 message/entry.py:3048-3052 — V2 P2P 校验同步重算 Merkle 树

**问题**: `compute_merkle_root(recipients)` 在事件循环同步执行，100+ recipients 时阻塞数十 ms。

**修复**: 
```python
# 改前
expected_root = compute_merkle_root(recipients)

# 改后
expected_root = await asyncio.to_thread(compute_merkle_root, recipients)
```

**文件**: `D:/modelunion/kite/extensions/services/message/entry.py:3048-3052`  
**风险**: 🟢 低 — 纯计算卸载  
**改动**: 1 行

---

### #3 message/entry.py:6128-6129 — query_online 逐 AID 串行 Redis EXISTS

**问题**: 循环内 `await is_online_async(aid)`，N 个 AID = N 次 Redis 往返。

**修复**:
```python
# 改前
for aid in aids:
    if await self._online_tracker.is_online_async(aid):
        result.append(aid)

# 改后（方案 A：gather）
results = await asyncio.gather(
    *[self._online_tracker.is_online_async(aid) for aid in aids]
)
result = [aid for aid, online in zip(aids, results) if online]
```

**文件**: `message/entry.py:6128`  
**风险**: 🟢 低  
**改动**: 5 行

---

### #10 storage/entry.py:2451-2470 — aid_type_resolver 每次 RPC 无缓存

**问题**: 每次权限校验都 `await group.get_aid_type(aid)`。

**修复**: 新增进程级 LRU 缓存（TTL 300s，最多 10000 条）：
```python
from functools import lru_cache
import time

_aid_type_cache = {}  # {aid: (timestamp, aid_type)}
_CACHE_TTL = 300.0

async def _resolve_aid_type_cached(aid):
    now = time.time()
    if aid in _aid_type_cache:
        ts, aid_type = _aid_type_cache[aid]
        if now - ts < _CACHE_TTL:
            return aid_type
    
    aid_type = await group_rpc_call("get_aid_type", {"aid": aid})
    _aid_type_cache[aid] = (now, aid_type)
    
    # LRU 清理（简单实现：超过 10000 条时清理过期）
    if len(_aid_type_cache) > 10000:
        expired = [k for k, (ts, _) in _aid_type_cache.items() if now - ts >= _CACHE_TTL]
        for k in expired:
            _aid_type_cache.pop(k, None)
    
    return aid_type
```

**文件**: `storage/entry.py:2451`  
**风险**: 🟢 低  
**改动**: ~20 行

---

### #15 group/repository.py:3640-3668 — cursor 更新内联子查询

**问题**: `UPDATE device_cursors ... WHERE group_id IN (SELECT id FROM groups WHERE ...)`

**修复**: 全面推广 `_fast` 路径，调用方传入 `group_msg_max/group_event_max`。

**文件**: `group/repository.py:3640`  
**风险**: 🟢 低 — 调用方在 pull 时已查过 groups  
**改动**: 删除旧路径 + 调用方传参，~30 行

---

### #17 storage/repository.py:753-817 — update_folder_subtree_paths 两次 acquire

**问题**: 先 SELECT 查子路径，再 UPDATE。

**修复**: 删除 SELECT，直接 UPDATE：
```python
# 改前
async with self._pool.acquire() as conn:
    cur = await conn.cursor(DictCursor)
    await cur.execute("SELECT path FROM ... WHERE path LIKE %s", (...,))
    rows = await cur.fetchall()
# 再 acquire 一次执行 UPDATE

# 改后
async with self._pool.acquire() as conn:
    cur = await conn.cursor()
    await cur.execute("UPDATE ... SET path = ... WHERE path LIKE %s", (...,))
```

**文件**: `storage/repository.py:753`  
**风险**: 🟢 低  
**改动**: 删除第一个 acquire 块，~10 行

---

### #20 nameservice/server.py:2868-2879 — 快照下载同步读整个 ZIP

**问题**: `open(zip_path,'rb').read()` 阻塞事件循环。

**修复**:
```python
# 改前
return Response(
    content=open(zip_path, 'rb').read(),
    media_type='application/zip',
    headers={'Content-Disposition': f'attachment; filename="{filename}"'}
)

# 改后
from starlette.responses import FileResponse
return FileResponse(
    path=zip_path,
    media_type='application/zip',
    filename=filename
)
```

**文件**: `nameservice/server.py:2868`  
**风险**: 🟢 低  
**改动**: 3 行

---

## P2 低风险快赢（30 条，列举前 15）

### #23 gateway/ws_server.py:2588-2595 — dispatch_event 全量去重缓存清理

**修复**: 删除 `_event_dedup_mark` 内的 `_cleanup_event_dedup_cache` 调用（line 2595）。  
**改动**: 删除 1 行

---

### #26 gateway/ws_server.py:3554-3663 — 消息调试记录无 enable 开关

**修复**: 增加全局标志 `_MESSAGE_DEBUG_ENABLED = os.getenv('AUN_MESSAGE_DEBUG') == '1'`，热路径入口早退。  
**改动**: ~5 行

---

### #27 gateway/ws_server.py:9709-9797 — JWT 验签同步 ECDSA

**修复**: 
```python
# 改前
verified = self._identity_public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))

# 改后
verified = await asyncio.to_thread(
    lambda: self._identity_public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
)
```
**改动**: 2 行

---

### #29 gateway/online_state.py:74-86 — Redis pipeline 4 命令合并 Lua

**修复**: 编写 Lua 脚本 `EVAL "redis.call('SADD',...); redis.call('EXPIRE',...); ..." 0 ...`  
**改动**: ~15 行

---

### #31 gateway/federation_client.py:636-663 — well-known 缺连接池复用

**修复**: `FederationClient.__init__` 创建 `self._session = aiohttp.ClientSession()`，`stop` 时关闭。  
**改动**: ~10 行

---

### #32 gateway/relay.py:164-189 — agent.md 缓存 miss 自旋轮询

**修复**: 
```python
# 改前
_inflight = set()
while key in _inflight:
    await asyncio.sleep(0.02)

# 改后
_inflight_events = {}  # {key: asyncio.Event}
if key in _inflight_events:
    await _inflight_events[key].wait()
else:
    event = asyncio.Event()
    _inflight_events[key] = event
    try:
        # ... fetch ...
    finally:
        event.set()
        _inflight_events.pop(key, None)
```
**改动**: ~15 行

---

### #33 gateway/relay.py:1560-1598 — 响应投递路径 await agent.md fetch

**修复**: 用 `_agent_md_meta_get_nowait`，miss 时启动后台 prewarm 而非阻塞。  
**改动**: ~5 行

---

### #34 gateway/entry.py:1233-1256 — CA 就绪事件同步 await ca.get_issuer_info

**修复**: 
```python
# 改前
result = await self._rpc_call("ca.get_issuer_info", ...)

# 改后
asyncio.create_task(self._init_federation_async())

async def _init_federation_async(self):
    result = await self._rpc_call("ca.get_issuer_info", ...)
    # ... federation init ...
```
**改动**: ~10 行

---

### #37 gateway/service_plane.py:430-441 — 心跳超时串行处理

**修复**: 
```python
# 改前
for sid in expired:
    await self._on_service_lost(sid)

# 改后
for sid in expired:
    asyncio.create_task(self._on_service_lost(sid))
```
**改动**: 1 行

---

### #38 message/entry.py:4895-4904 — V1+V2 sender 查询串行

**修复**: 
```python
# 改前
v1_senders = await self._db.list_sender_aids_for_device_seq(...)
v2_senders = await self._db.list_v2_sender_aids_for_device_seq(...)

# 改后
v1_senders, v2_senders = await asyncio.gather(
    self._db.list_sender_aids_for_device_seq(...),
    self._db.list_v2_sender_aids_for_device_seq(...)
)
```
**改动**: 3 行

---

### #42 message/online_tracker.py — 新增批量接口

**修复**: 新增 `are_online(aids)` 与 `get_connections_batch(aids)`，Redis 路径用 pipeline。  
**改动**: ~30 行

---

### #43 group/service.py:3412 — send_message 冗余游标缓存失效

**修复**: 删除 `_invalidate_device_cursor_cache_for_group` 调用。  
**改动**: 删除 1 行

---

### #44 group/service.py:3856-3862 — 设备游标缓存失效全表扫描

**修复**: 改用二级字典 `{group_id: {(aid,device,slot): cursor}}`。  
**改动**: ~20 行

---

### #45 group/service.py:3411 — send_message 失效成员缓存后立即重查

**修复**: 删除 `_cache_invalidate_group` 调用（只在真正改变成员的操作保留）。  
**改动**: 删除 1 行

---

### #46 group/service.py:3377-3382 — send_message 串行验证附件

**修复**: 
```python
# 改前
for ref in attachment_refs:
    await storage_rpc_call("verify_ref", ...)

# 改后
await asyncio.gather(*[
    storage_rpc_call("verify_ref", {"ref": ref}) for ref in attachment_refs
])
```
**改动**: 3 行

---

## 其余 P2 快赢（15 条）

详见原始清单 #47-#61：
- group/entry.py RPC handler dict 改模块级常量
- group/entry.py v2_send device lookup gather
- group/entry.py v2_bootstrap state signature 合并查询
- group/repository.py list_members COUNT(*) 默认改可选
- nameservice/db.py OFFSET 分页改 cursor
- aid_custody/repository.py 写后回读优化
- storage/service.py batch_delete/batch_head_object gather
- service_proxy/entry.py 隧道 base64 编解码优化
- 等等

---

## 实施建议

### 优先顺序（按收益/改动比）

1. **一行改动**（#23, #37, #43, #45）— 立即修
2. **message/storage 缓存**（#3, #10）— 高频路径，收益大
3. **CPU 卸载**（#2, #27）— 解除事件循环阻塞
4. **gather 并行化**（#38, #46）— 串行改并发，简单直接
5. **文件流式传输**（#20）— 内存占用显著降低

### TDD 方法

每条修复前：
1. 读取当前代码确认位置
2. 编写/补充单元测试覆盖该路径
3. 修改代码
4. 运行测试确认通过 + 性能对比

### 并行推进

可按模块分派：
- gateway 快赢（10 条）→ Agent A
- message 快赢（5 条）→ Agent B
- group/storage 快赢（15 条）→ Agent C

---

**完整 101 条清单**: `docs/aun-server-perf-audit-2026-06-23.md`
