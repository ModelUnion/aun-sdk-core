# AUN SDK + 服务模块业务逻辑 Bug 审查清单（复审综合版）

- 审查日期：2026-04-17
- 审查方式：静态源码审查，未启动 Kite、未跑单域/双域联邦 e2e
- 审查范围：
  - SDK 四语言：`aun-sdk-core/{python,ts,js,go}/` 的 client、transport、auth、e2ee、e2ee-group、keystore、seq_tracker
  - 服务模块（aun_console 纳管）：gateway、auth、ca、message、group、storage、mail、stream、leaderboard、aid_custody、nameservice、aun_console

说明：本清单仅作分析，未做任何源码改动；所有"修复方向"仅作建议。

---

## 严重（明确导致数据/身份/消息静默丢失，或直接绕过安全边界）

### S1. SDK 补洞 dedup 键仅在异常路径清理，成功返空仍永久污染

四语言 SDK 的群消息/P2P 补洞逻辑都使用 `{ns}:{after_seq}` 作为 `_gap_fill_done` 去重键，且仅在抓到异常时移除。第一次补洞请求若"成功但返回 0 条"，该键永远留在集合内，真实空洞后续再出现时不会再触发补洞，表现为"消息永远拉不到"。

- 位置：`python/src/aun_core/client.py:1073`、`ts/src/client.ts:1268`、`js/src/client.ts:927`、`go/client.go:1417`。
- 修复方向：成功路径也必须 `discard` 键；或改为"首次补洞完成后"基于 `max_seen_seq/contiguous_seq` 是否前进来决定是否保留标记。

### S2. SDK SeqTracker 首条消息即作为 baseline + 3-probe-resolve

客户端上线后第一条消息若是 `seq=N`，`lastSeq` 直接设为 N，[1..N-1] 不建 gap；即便建了 gap，probe 3 次拉不到就标记 `resolved=true` 跳过，再叠加 `force_contiguous_seq(server_ack)` 服务端 ack 位置被无条件接受。离线期间历史消息静默丢失。四语言行为一致。

- 位置：`python/src/aun_core/seq_tracker.py:82-86/143-145`、`ts/src/seq-tracker.ts:180-189`、`go/seq_tracker.go:92-97`。
- 修复方向：baseline 改为从持久化 `(aid,device,slot,ns)` 最近 ack seq 读；首次消息应构造 `[persisted+1, seq-1]` gap；`resolved` 应基于服务端 tombstone 明确回答，而非 probe 次数。

### S3. SQLCipher HMAC 校验失败被当作文件损坏自动删除身份库

`_is_recoverable_db_error` 命中 "hmac check failed" 即走 `_cleanup_broken_files()`，`.db`、`-wal`、`-shm`、`-journal` 全部 unlink。密码不一致（多进程/不同 runtime 使用不同 `_key`）时会静默销毁私钥、证书、群密钥、token。

- 位置：`python/src/aun_core/keystore/sqlcipher_db.py:164-199`。
- 修复方向：从可恢复列表移除 `hmac check failed`；对密码错误抛明确异常并要求用户显式确认。

### S4. refresh token JSONL 追加失败被吞，仍返回新 token

`_append_refresh_record` 异常仅 print；`consume_refresh_token` 把"吊销写入"与"返回成功"解耦，吊销写失败 → 旧 token 仍有效、但上游继续签发新 token；进程崩溃/盘满时链上产生两条并发合法 refresh。

- 位置：`extensions/services/auth/token_store.py:224/256/301`、`extensions/services/auth/entry.py:878`。
- 修复方向：`_append_refresh_record` 须将 IO 错误向上冒泡；`consume` 之后若写吊销失败必须回滚新 token 签发。

### S5. aid_custody 短信验证码消费非原子

`get_valid_sms_code` 查 `status='pending'` 与 `consume_sms_code` UPDATE 分离；UPDATE 无 `status='pending'` 条件、不检查 `rowcount`。并发两个 `verify_code` 都能通过校验，一个验证码可被重复使用。

- 位置：`extensions/services/aid_custody/auth_service.py:87/119`、`extensions/services/aid_custody/repository.py:231/250`。
- 修复方向：`UPDATE ... SET status='consumed', consumed_at=? WHERE id=? AND status='pending'`；检查 `rowcount=1` 才视为消费成功，否则视为并发失败。

### S6. `_alloc_seq_cached` DB 故障伪造 2^40 高位 seq，破坏 per-recipient 单调性

DB 异常时 fallback 生成 `int(t*1000)%(2**40) + 2**40 + counter%1000`，此临时 seq 从不写回 `inbox_seq` 表。DB 恢复后继续从原低位分配；客户端 ack 到 fallback_seq 后 `update_ack_seq` 推到 2^40 以上，之后所有正常低位 seq 都小于 ack_seq，永远不会被 pull 返回。

- 位置：`extensions/services/message/entry.py:1195-1204`。
- 修复方向：DB 不可用应直接 503，不得伪造 seq；或用独立持久化的 fallback 发号器，故障恢复后要求 inbox_seq 最大值 ≥ 已用过的 fallback_seq。

### S7. Storage cleanup 路径 blob 删除失败仍删元数据

与 `service.py:327` 自己的注释完全矛盾（注释明确"先删 blob 再删元数据，否则产生无法识别和回收的 orphan blob"）。`batch_delete`、过期 cleanup、配额 cleanup、磁盘阈值 cleanup 四条路径全部违反。

- 位置：`extensions/services/storage/service.py:722`、`extensions/services/storage/cleanup.py:82-191`。
- 修复方向：blob 删除失败必须跳过元数据删除，或写入 `pending_delete` 表等待后续重试；绝不可留下孤儿 blob。

### S8. Federation relay 未剥离远端注入的 `_` 前缀字段

本地客户端 relay 剥离了 `_` 前缀字段，但 federation relay 只重写了 `_auth` 和 `_federation`。远端 Gateway 被劫持时可在 `rpc_params` 中塞任意 `_xxx` 字段（除 Kernel 已重写的 `_caller_id`），污染下游模块的权限上下文。

- 位置：`extensions/services/gateway/ws_server.py:2157-2193`。
- 修复方向：federation relay 入口统一剥离所有 `_` 前缀字段，再注入 `_federation`/`_auth`。

### S9. Bare AID 绕过域校验

所有 `_check_aid_domain` 形态都是 `if aid and "." in aid`，不含 `.` 的 AID 直接放行。后续流程按 `_issuer_ca_agentid` 补全，造成跨域误操作。

- 位置：`extensions/services/gateway/ws_server.py:1486/1580`、`extensions/services/auth/entry.py:285`。
- 修复方向：bare AID 显式拒绝或先补全为本域 AID 再校验。

### S10. AID login_phase2 aid/nonce 不匹配时不删除 pending

仅在"证书过期""签名失败""超时"三种情况下 `del _pending[request_id]`，aid/nonce 不匹配不消费。攻击者拿到 `request_id` 后可在 `challenge_ttl` 内反复尝试不同组合。

- 位置：`extensions/services/auth/verifiers/aid.py:365-377`。
- 修复方向：任何 phase2 校验失败都立即 `del pending`；超过失败阈值锁定 aid/IP。

### S11. aid_custody 指纹计算来源不一致

`validate_cert_only` 使用未 strip 的 `cert_pem_original` 计算 sha256；`validate_aid_materials` 使用 strip 后的 `cert_pem`。同一证书经 `import_aid` 与 `backup_aid` 两条链路落库的 `cert_sha256` 可能不同，CT log 与 DB 视图错位，后续去重/排查失效。

- 位置：`extensions/services/aid_custody/validators.py`。
- 修复方向：统一用规范化 PEM 或 DER 字节计算指纹（推荐 base64 解码后 DER 哈希）。

### S12. aid_custody 下载私钥审批可在 TTL 内无限复用

`_key_download_approvals` 是进程内 dict；`verify_key_download` 通过后只看 `expires_at>=now` 不消费。`download_key_verify_ttl_seconds`（默认 300s）内可无限次下载主私钥及所有 extra_cert 私钥；多 worker 部署审批状态完全失效。

- 位置：`extensions/services/aid_custody/service.py:46/321-337/631-657/1200-1211`。
- 修复方向：审批持久化到 DB/Redis；一次性消费，仅对申请的 aid+cert_sn 生效。

### S13. aun_console 管理 API 缺统一鉴权

FastAPI 路由定义了 `/api/aun/modules/{id}/{start,stop,enable,disable}`、`/config`、`/logs`；未见统一 admin token 中间件。相较 leaderboard/aid_custody 的 admin_api_key 校验，aun_console 是权限放大入口，任何能访问 console HTTP 端口的人都能启停模块/改 config。

- 位置：`extensions/services/aun_console/server.py:155-281`。
- 修复方向：统一 admin token / mTLS 中间件；跨模块 RPC 代理增加调用方鉴权。

### S14. 群密钥分发消息解密失败后被当作普通业务消息投递

`_try_handle_group_key_message` 在 P2P 解密失败时返回 `False`，主处理流程继续 `_decrypt_single_message` 并 publish `message.received`。群密钥分发信封（控制面消息）会被当作普通聊天消息（数据面消息）发布给业务 handler，造成控制/数据面混淆，应用层会看到"乱码聊天消息"。

- 位置：`python/src/aun_core/client.py:1312-1318/842-872`。
- 修复方向：对无法识别/解密的密钥分发消息必须拦截（标记 `_key_message_failed=True` 或直接吞），不再进入业务消息分发。

---

## 高（明确存在，业务后果显著）

### H1. 跨域 `e2ee.get_prekey` 失败伪装为 `{"found": false}`

SDK 据此降级到 `long_term_key` 路径。联邦/远端故障期间所有跨域消息静默失去前向保密。这是"失败被伪装成正常业务态"而非单纯失败。

- 位置：`extensions/services/message/entry.py:2284`、`python/src/aun_core/client.py:743`。
- 修复方向：真实联邦失败应抛 `ServiceUnavailable`，让 SDK 选择重试或显式报错，而非静默降级。

### H2. `e2ee.put_prekey` DB 持久化失败仍返回 `{"ok": true}`

仅保证缓存有 prekey；服务重启后 DB 里没有记录，对端拉不到 prekey 降级到长期密钥，调用方却以为上传成功。

- 位置：`extensions/services/message/entry.py:2255`。
- 修复方向：DB 写失败必须透传错误；缓存和 DB 要么都成功要么都失败。

### H3. `group.changed` 持久化失败降级为"仅 WS 推送"

在线客户端可能看到，离线客户端之后无法通过 `group_events` 补洞。成员增删、权限变更、公告等视图永久分叉。

- 位置：`extensions/services/group/entry.py:1040`、`extensions/services/group/message_store.py:184`。
- 修复方向：持久化失败应拒绝返回 success；或降级模式下标记事件为"需补偿"，后续重连时重放。

### H4. Mail `messages.size_bytes` 默认不含附件

发送前配额预检算附件，但真正写入 `messages.size_bytes` 时不包含附件大小；`SUM(size_bytes)` 用作配额/展示/统计长期低估。

- 位置：`extensions/services/mail/internal/core/handler.go:266/407`、`extensions/services/mail/internal/store/messages.go:129`、`extensions/services/mail/internal/store/quota.go:14`。
- 修复方向：`size_bytes` 应等于 MIME Body 实际大小，或加独立 `attachment_size_bytes` 列。

### H5. aid_custody 发短信先写 DB 再调 provider，不查 accepted

provider 发送失败或返回 accepted=false 时 DB 已留 pending 记录并触发 cooldown；用户没收到验证码却被"冷却中"挡住。

- 位置：`extensions/services/aid_custody/auth_service.py:51/59`、`extensions/services/aid_custody/repository.py:215`、`extensions/services/aid_custody/sms_provider.py:11`。
- 修复方向：先调 provider，accepted 后再落库；或落库后事务性回滚失败记录。

### H6. Message `_check_aid_exists` 超时/异常静默放行

CA 不可达、网络抖动、Redis 故障等任何非 ValueError 异常都被降级为 print 后继续投递。攻击者/错误客户端可向不存在 AID 灌消息，inbox 无界增长。

- 位置：`extensions/services/message/entry.py:1171-1176`。
- 修复方向：区分"确认不存在"与"无法判定"；无法判定应拒绝发送或临时排队。

### H7. `cert_fingerprint` 协议语义系统内不一致

CA 侧把 `cert_fingerprint` 兼容成"证书 DER 指纹或公钥 SPKI 指纹"并允许按 AID 回退；Python SDK 取证书路径未校验"请求的指纹/公钥 与 返回证书公钥一致"；`message.e2ee.put_prekey` 又当作严格 DER 指纹比对。同一字段在不同链路里语义分裂：有的静默接受回退，有的直接拒绝。

- 位置：`extensions/services/ca/db.py:104`、`extensions/services/ca/entry.py:662`、`python/src/aun_core/client.py:1371`、`python/src/aun_core/auth.py:620`、`extensions/services/message/entry.py:2209`。
- 修复方向：统一定义 `cert_fingerprint` 为 DER SHA256；SDK 在请求侧必须做"返回证书公钥与请求指纹一致"的强校验，服务端对不同链路的 fingerprint 语义要对齐。

### H8. Gateway JWT 本地验签不查吊销

JWT 快速路径仅验签 + exp + iat；未查询 token/refresh 吊销、AID/证书撤销。证书吊销或 refresh_token 吊销后 JWT 仍可用至 exp（最长 1 小时）。

- 位置：`extensions/services/gateway/ws_server.py:1596-1614`、`extensions/services/auth/jwt_provider.py:200-241`。
- 修复方向：对应 refresh_token 撤销或证书吊销时同步剔除 JWT；或定期拉取 CRL/jti 吊销表。

### H9. auth `chain_cache` 与 CRL 刷新不同步

`_sync_crl_loop` 每 5 分钟刷新 `_revoked_serials`，但 `_chain_cache` 在 cert 命中缓存后不再检查 CRL；且 cert_sn 规范化（hex 前导 0、大小写）两边不一定一致。证书吊销可能长期不生效。

- 位置：`extensions/services/auth/verifiers/aid.py:482-519`、`extensions/services/auth/entry.py:1224`。
- 修复方向：`update_revoked_serials` 后清理 `_chain_cache` 对应条目；统一 cert_sn 归一化规则。

### H10. CA `renew_cert` / `rekey` 不比对新公钥与现绑定

auth 侧 `verify_renew_cert` 只验签名不比对 DB 公钥；CA 也不比对。上游 bug 或被攻破时可传入别人 AID 的公钥，CA 以"续期"名义替换活跃签名证书，等于静默密钥劫持。

- 位置：`extensions/services/ca/entry.py:504-626`、`extensions/services/auth/entry.py:780`。
- 修复方向：`_rpc_renew_cert` 必须比对 `existing.public_key == params.public_key`，不一致拒绝。

### H11. Group `add_member` 与 `group_membership_index` 非同一事务

`add_member` 事务内只写 `group_members`；`upsert_membership_index` 独立提交。崩溃/抖动窗口下会出现"成员在 group_members 里、membership_index 里没有"，用户 `list_my_groups` 查不到自己的群。

- 位置：`extensions/services/group/repository.py:662-696`。
- 修复方向：两表同事务写；或应用层 idempotent 重建任务。

### H12. Group `ack_messages` 用缓存 `group.message_seq` 做 min 上界截断

`_require_group` 返回的快照可能落后于 DB；客户端合法 ack 到最新 seq 被截到旧值，`update_ack_seq` 不前进 → 产生重复推送。

- 位置：`extensions/services/group/service.py:1661-1668`。
- 修复方向：不用缓存群 message_seq 做上界；直接信任客户端数值由 DB 侧 `GREATEST` 兜底。

### H13. Group `dissolve_group` 清 Redis 失败被 pass 静默

DB 删除已成功，但 `grp:msgs:*`/`grp:evts:*` 缓存残留（TTL 24h）。解散群仍能被成员 pull 到历史。

- 位置：`extensions/services/group/service.py:1736-1741`。
- 修复方向：至少写入异步重试队列，不应单纯 pass。

### H14. Stream pusher chunks 无界 + 持锁做网络写

- `session.chunks.append((seq, data))` 无裁剪，长流 OOM；
- Pull SSE 回放阶段持 `session._lock` 时 `await response.write`，慢 puller 把 pusher 与其他 puller 一起卡死。

- 位置：`extensions/services/stream/entry.py:566/598/672-682`。
- 修复方向：chunks 设上限（环形缓冲）；回放阶段快照 chunks 后释放锁再写网络。

### H15. Stream push/pull token 明文出现在 URL query

token 会进入访问日志、Referer、浏览器历史，SSE 场景尤甚。

- 位置：`extensions/services/stream/entry.py:434/439`。
- 修复方向：改用 `Authorization` 头或 POST 握手换取一次性 session token。

### H16. Mail `CheckQuota` 错误被当作通过

`if ok, err := h.db.CheckQuota(...); err == nil && !ok` —— DB 查询报错时直接继续投递，配额绕过；且 `handleSend` 未改用原子 `InsertMessageWithQuota`，TOCTOU 竞争。

- 位置：`extensions/services/mail/internal/core/handler.go:375-382`、`extensions/services/mail/internal/store/quota.go:57-102`。
- 修复方向：fail-close；改调原子版本。

### H17. Mail `handleDeliver` 联邦入站缺签名二道防线

仅校验 `_caller_id=="gateway"` 和 `from.Domain != localIssuer`；本地 gateway 被攻破后没有二次校验；入参 `deliverParams` 不包含 `BccAddrs`、`Priority`、`ReplyTo`、`InReplyTo`、`References`，字段丢失。

- 位置：`extensions/services/mail/internal/core/handler.go:587-665`。
- 修复方向：联邦层携带签名，mail 再次校验 signer = from.Domain；扩展 deliverParams。

### H18. Leaderboard `recover_pending_events` 重放不幂等 + 空 event_id 被吃掉

- 恢复批次失败即被 `mark_ingest_events_failed` 永久标 failed，指标永久缺失；
- `str(event.get("event_id") or "")` 缺失时映射到空主键，`INSERT IGNORE` 把所有空 id 事件当作重复吃掉不报错。

- 位置：`extensions/services/leaderboard/service.py:235-272/100-147`。
- 修复方向：恢复流幂等重放 + DB 状态机；缺失 event_id 应返回 failed 而非 duplicate。

### H19. aid_custody `_check_aid_access(auth_type='aid')` 仅比对 AID 名

不校验该 AID 是否在托管表内属于当前 user；若 jwt_provider issuer 限定不够严，存在跨账户访问风险。

- 位置：`extensions/services/aid_custody/service.py:899-912`。
- 修复方向：`auth_type='aid'` 时再查托管表要求 AID 属于 ctx user_id 且未冻结。

### H20. TS SDK `_verifyEventSignatureSync` 三态布尔

返回 `true | false | 'pending'`；`d._verified = 'pending'` 是 truthy，业务若写 `if (event._verified)` 会把"尚未拿到证书"当作"已验证"。

- 位置：`ts/src/client.ts:1466-1505/1434-1437`。
- 修复方向：异步 await `_fetchPeerCert` 再做同步判定；或发 `signature_pending` 事件后回填，不用 truthy string 混淆。

### H21. TS SDK 群 epoch 轮换风暴

所有剩余 admin 同时收到 `member_left` 都本地触发 `_rotateGroupEpoch`，CAS 冲突且无 leader 选举/抖动退让。

- 位置：`ts/src/client.ts:1455-1462`。
- 修复方向：判断本地 AID 是否按排序最小 admin；或基于 `initiator_aid` 字段抢锁；加 jitter + 失败重试退让。

### H22. JS SDK IndexedDB `openDB` 缺 `onblocked` 回调

其它 tab 持有旧版本连接时 `onupgradeneeded` 永久挂起，所有 keystore/登录/E2EE 流程卡死，前端无任何反馈。

- 位置：`js/src/keystore/indexeddb.ts:184-218`。
- 修复方向：补 `onblocked` 回调；在 `unload` 时主动关闭连接。

### H23. JS SDK RPC 超时不 `clearTimeout`，慢响应被静默丢弃

`Promise.race` 成功路径不清定时器，定时器泄漏；服务端慢响应到达后 `_routeMessage` 找不到 pending 直接丢，调用方当作失败可能重复下发。

- 位置：`js/src/transport.ts:175-213`。
- 修复方向：成功/失败路径统一 `clearTimeout`；未知 id 打 warn 并上报。

### H24. Go SDK `persistIdentity` 与 `keystore/aid_db.go` 大量写路径忽略 err

`_ = a.persistIdentity(identity)`；keystore SetToken/SavePrekey/SaveGroupCurrent/SetGroupReplayState 等方法签名为 void，错误仅 log。access_token / refresh_token / active_cert / prekey / group epoch 持久化失败全部无感知。

- 位置：`go/auth.go:424/1374/1431`、`go/keystore/aid_db.go`。
- 修复方向：方法签名统一返回 error 或提供 GetLastPersistError 机制；关键路径失败必须向上冒泡。

### H25. Go SDK `transport.t.ws` 字段读写 data race

`readerLoop` goroutine 无锁读；`Connect` 写赋值、`Close` 写 nil；`-race` 下必崩，重连瞬间可能读到旧连接。

- 位置：`go/transport.go:82-276`。
- 修复方向：全程用 mutex 或 `atomic.Pointer[websocket.Conn]` 保护。

### H26. SDK 未解密密文 payload 被原样投递给应用层事件

P2P 与群消息两条路径在 `_decryptMessage` 返回 null 时都把原 `message`（含 `e2ee.encrypted` 或 `e2ee.group_encrypted` 信封）publish 给 `message.received` / `group.message_created`。应用层会看到 base64 密文 / 元数据（prekey_id、cert 指纹、长度），存在元数据泄漏 + 语义混淆。

- 位置：`python/client.py:884-889`、`ts/client.ts:1805-1830/1886-1913`。
- 修复方向：改为 publish `message.undecryptable` / `group.message_undecryptable` 事件，只携带 message_id、from、seq、`_decrypt_error`，不带原密文 payload。
- 注意：这与"是否 auto-ack"无关。auto-ack 必须照常进行以保证 cursor 推进。

### H27. TS SDK `_seenMessages` 先写后解密

`seenKey` 在 `_decryptMessage` 与 `_verifySenderSignature` 之前即被 `set`；解密或验签失败时合法重传也被当作重复丢弃。

- 位置：`ts/src/e2ee.ts:576-602`。
- 修复方向：`seen.set` 放在 `_decryptMessage` 成功且签名验证通过之后；或改"tentative→confirm"两步提交。

---

## 中（语义错误或可观测性丢失，大多在故障态才显现）

### M1. `message.ack` 事件发布失败仍返回成功

ack 游标已推进，但发送方收不到"已读"通知。`_publish_event` 失败链路不计数、不重试。

- 位置：`extensions/services/message/entry.py:1859`。

### M2. `stream.close` 结束信号被满队列吞掉 + 拉流循环不看 `session.is_done`

部分 puller 在流关闭后仍挂在 keep-alive 上，收不到 done。

- 位置：`extensions/services/stream/entry.py:331/627`。

### M3. aid_custody 审计/CT 事件发布失败被吞

DB 记录已写，但订阅方永远收不到 `aid_custody.audit_written / ct_logged`；审计流下游分析丢数据。

- 位置：`extensions/services/aid_custody/audit.py:39`、`extensions/services/aid_custody/ct_log.py:63`、`extensions/services/aid_custody/server.py:719`。

### M4. `group.changed` 持久化 `created_at=int(time.time())` 用秒

系统大多数事件用毫秒；消费者按毫秒做排序/窗口过滤会单位错位，前端时间显示偏差。

- 位置：`extensions/services/group/entry.py:1052`。

### M5. Storage `append_object` 非 CAS + 锁 dict race

`_append_lock` 是进程内 asyncio.Lock 多进程失效；`_release_append_lock` pop 与 acquire 间隙有 race，会并行多把锁。

- 位置：`extensions/services/storage/service.py:635-702`。

### M6. Storage `complete_upload` 配额检查在 blob 已上传后

超配额拒绝时 blob 残留磁盘，cleanup 基于元数据无法识别/回收。

- 位置：`extensions/services/storage/service.py:454-494`。

### M7. Group `_dispatch_message_runtime` 失败不重试不建 pending 窗口

失败后 duty fallback 机制不触发，消息已入库但"分发丢失"。

- 位置：`extensions/services/group/service.py:2956-2962`。

### M8. Python SDK replay guard 命中后仍返回原 message 继续分发

业务层无法区分"正常消息"和"被判为重放的消息"。

- 位置：`python/client.py:1609-1610`。

### M9. JS/TS SDK 关键编排错误压成 `console.debug`

`_safeAsync` / `.catch(() => {})` 把群 key 分发、epoch 轮换、prekey 补充、auto-ack、seq tracker 持久化等失败全部打成 debug 或完全吞掉。

- 位置：`js/client.ts:2677-2681/2600/2615/2650/2659`、`ts/client.ts:2114/2167`。

### M10. Mail DMARC/SPF/DKIM 仅加分不按策略强拒

`p=reject` 邮件若 spam 分数未破阈值仍入库。

- 位置：`extensions/services/mail/internal/smtp/session.go`（DATA 阶段）。

### M11. Mail `handleSend` 附件上传失败时 sent 邮箱已落库但附件残缺

无事务、无回滚；且 `InsertAttachment` 错误返回值被丢弃。

- 位置：`extensions/services/mail/internal/core/handler.go:286-318/310/433`。

### M12. Mail SMTP 出站 BCC 副本 Message-Id 不一致

对每个收件人重复生成 MIME；`BuildMIME` 每次新 boundary、新 Date，同一封邮件多个副本 Message-Id 不同，追踪链断裂。

- 位置：`extensions/services/mail/internal/core/handler.go:504-560`。

### M13. Mail `handleDeliver` 配额检查缺失

联邦入站不检查收件人配额；与 `deliverLocal` 路径不对称，配额可被联邦投递绕过。

- 位置：`extensions/services/mail/internal/core/handler.go:616-643`。

### M14. Mail `ca.get_cert` 返回反序列化失败被当作"证书存在"

`if json.Unmarshal(result, &certResult) == nil && !certResult.Found` —— 失败时条件不成立，fail-open 继续投递。

- 位置：`extensions/services/mail/internal/core/handler.go:393-396`。

### M15. Mail `DeleteAttachmentsByMessage` 未清 storage blob

仅删 DB 记录，注释说"附件文件需由调用方清理"，但无显式调用点 → 附件 blob 孤儿泄漏。

- 位置：`extensions/services/mail/internal/store/messages.go:399-404`。

### M16. Mail `handleGet` 可能泄漏 BCC 名单给收件人

`deliverLocal` 对 BCC 收件人保留了 bcc 列表；`mail.get` 返回 `bcc_addrs` 无区分 —— BCC 收件人能看到所有 BCC 名单，隐私合规问题。

- 位置：`extensions/services/mail/internal/core/handler.go:400-403/706`。

### M17. Gateway `dispatch_event` 异常静默 + 私网豁免可伪造

- `send notification` 抛异常仅 pass，连接半死时事件持续失送无指标；
- `_client_rate_check` 在反向代理后 `remote_address` 恒为 127.0.0.1/172.x，全部请求豁免限流；
- Pre-auth 方法对 `auth.refresh_token` / `auth.download_cert` 只有 IP 限流，无 per-target 限流。

- 位置：`extensions/services/gateway/ws_server.py:276-279/220-238/56-77`。

### M18. Auth `token_store._load_latest` 失败返回空字典

文件损坏时 cache 不填充，后续 `touch/revoke` 默默失败；生产环境无告警。

- 位置：`extensions/services/auth/token_store.py:151-176`。

### M19. Auth `consume_refresh_token` 事务缺失

两个并发消费同一 refresh_token 可能都通过校验并各自写 revoke 记录，但都返回合法结果 → 同一 token 被消费两次。

- 位置：`extensions/services/auth/token_store.py:227-263`、`extensions/services/auth/entry.py`（`_refresh_lock` 未在 `consume` 处使用）。

### M20. CA `_rpc_revoke_cert` 无审计日志且 state 变更无并发保护

吊销只 print + `rows > 0`；无事务、无 `WHERE lifecycle_state IN ('active_signing','verify_only')` 条件。

- 位置：`extensions/services/ca/entry.py:629-649`。

### M21. CA `get_cert_by_fingerprint` 全量扫描 + PEM 解析

无 fingerprint 列索引，证书频繁轮换时 O(N×PEM解析)。

- 位置：`extensions/services/ca/db.py:104-148`。

### M22. Leaderboard `apply_aggregated_batch` 捕 `BaseException` 仅 rollback

`_flush_pending` 只捕 `Exception`，`SystemExit/CancelledError` 路径下 snapshot 不恢复。

- 位置：`extensions/services/leaderboard/repository.py:285-307`、`extensions/services/leaderboard/service.py:444-451`。

### M23. aid_custody 业务设计杂项

- `bind_aid` 不复用 `bind_external_account` 的冲突检查；
- `backup_aid` 不校验 key 与 cert 匹配；
- `renew_cert`/`rotate_key` 对加密私钥直接拒绝，强迫用户明文上传。

- 位置：`extensions/services/aid_custody/service.py:495-554/661-831`。

### M24. nameservice `_normalize_gateway_url` 仅检查 loopback

未限制 scheme/port；写入端点签名校验需确认。恶意写入可把某 issuer 的 gateway 指向攻击者 ws。

- 位置：`extensions/services/nameservice/server.py:38-60`。

### M25. SDK 重连/心跳跨语言行为不一致

- JS 无 `max_attempts`、Go 有上限；
- TS 心跳三次失败才判断断连，期间 RPC 全超时；
- TS `transport.close()` 3 秒超时 resolve 可能留下老 ws 继续接收消息注入到 `_routeMessage`。

- 位置：`js/client.ts:2510-2559`、`ts/client.ts:2435-2684`、`ts/transport.ts:138-151`、`go/client.go:3130-3229`。

### M26. SDK keystore/prekey 降级静默

- Python prekey 加密失败自动降级到 long_term_key，虽有 `require_forward_secrecy` 配置但默认关；
- TS `_buildRotationSignature` 签名失败返回空对象 → 调用方把 `{}` spread 到 RPC，服务端 409/403；
- TS `_saveSeqTrackerState`/`_restoreSeqTrackerState` 持久化异常全部 `catch { }` 吞，跨进程重启后 cursor 回退可能重复投递历史。

- 位置：`python/e2ee.py:406-422`、`ts/client.ts:2068-2089/2114/2167`。

---

## 低（性能、细节、合规性）

### L1. Message `_fallback_seq_counter` 是模块级全局 + 模 1000
碰撞空间极小；并发与回退合流时可能产生 seq 倒挂。位置：`extensions/services/message/entry.py`。

### L2. Group `get_dispatch_log` 读整个日志文件到内存
日志过百 MB 时 OOM。位置：`extensions/services/group/service.py:1827`。

### L3. Storage 其它细节
- `list_prefixes` 无 LIMIT，大 bucket OOM；
- `list_objects` LIMIT+OFFSET 分页大偏移退化；
- `_check_quota_before_write` 并发竞态；
- `expire_in_seconds` 无上限校验；
- `copy_object` 不检查配额；
- cleanup 磁盘告急时 `get_oldest` 不按 owner 公平。

位置：`extensions/services/storage/`（对应文件）。

### L4. Stream 其它细节
- 日志/崩溃写入异常 `except Exception: pass`；
- `_rpc_close` 检查 creator_aid 大小写不归一化；
- `Last-Event-ID` 无范围校验；
- `_try_load_stream_cert` 只看文件存在不校验有效性；
- `int(client_seq)` 无 try/except，异常会崩 ws 协程。

位置：`extensions/services/stream/entry.py`。

### L5. Auth/CA 其它细节
- `login_phase1` 公钥比对异常仅 print；
- `_rpc_create_aid` 全局 10/min 限流易被单点 DoS；
- CA MySQL pool `maxsize=5` 生产偏低；
- CA `get_crl` 无缓存/ETag。

位置：`extensions/services/auth/entry.py`、`extensions/services/ca/db.py`。

### L6. Gateway/Leaderboard/Console 其它细节
- Gateway `_strip_internal_route` 白名单极小，新增内部字段易泄漏；
- Gateway `close_session` `except Exception` 吞过宽；
- Leaderboard HTTP 接口 `/api/leaderboard/*` 无鉴权；
- Leaderboard `_db_reconnect_loop` 错误码 400 应为 503；
- Console `_atomic_write_text` fd 泄漏路径；
- Console `AUN_MODULES` 硬编码模块列表与"零共享"理念冲突。

位置：各模块 entry/server。

### L7. aid_custody 其它细节
- `restore_by_phone` 不检查用户冻结状态；
- `bind_phone_verify` 可能把 phone 绑到新创建的 user 而 AID 仍在原 user 名下；
- `_publish_event` 静默吞异常；
- `_db_reconnect_loop` 起始 `sleep(30)` 导致 503 窗口过长。

位置：`extensions/services/aid_custody/service.py`、`server.py`。

### L8. SDK 其它细节
- Python `_seen_messages` 数量裁剪按插入顺序，可能误删仍在防重放窗口内的条目；
- Python `EventDispatcher` 非线程/异步安全；
- Python `_open_and_init_once` 连接失败路径 `conn.close()` 可能 UnboundLocalError；
- Python CRL 缓存最大 TTL 24h，紧急吊销可能延迟；
- TS `publicKeyToUncompressedPoint` 不校验 crv，P-384 密钥场景错误延后到解密才 fail；
- JS `console.debug` 默认浏览器不可见（等同吞错）；
- Go `canonicalJSONMarshal` 忽略 marshal error，AAD 异常值可静默产生空字节；
- Go `gapKey` 使用 `string(rune(start))` 易踩 Unicode 替换字符坑；
- Go `writeCtx` 5 秒硬编码超时。

位置：各 SDK 对应文件。

---

## 共性模式（跨模块反复出现）

| 模式 | 代表位置 |
|---|---|
| `except Exception: pass` / `catch {}` / `_ = fn()` 吞业务异常 | 全模块 |
| 进程内 dict 保存状态（审批/限流/缓存） | `aid_custody.service:46`、`nameservice` 缓存 |
| "业务 check + 实际写" 两步非事务/非 CAS | aid_custody sms、auth refresh、group add_member、storage append |
| 缓存写失败 print 不失效 | message/entry.py Redis 写失败多处 |
| 解密/签名失败被原样返回或空对象 | SDK e2ee/e2ee-group 多处 |
| 后台 loop `while True: ... except: print` 无熔断/告警 | 四模块 `_ws_client_loop` |
| 证书/OCSP/CRL 失败静默降级 | auth/ca 多条路径 |
| fail-open 语义（`err == nil && !ok` 模式） | Mail handler.go CheckQuota |

---

## 开放问题 / 假设

- **联邦重定向循环**：Gateway/Mail 都缺跳数头，靠 `from.Domain` 判定；真实是否能造成无限环取决于对端 gateway 路由实现。
- **prekey `last_active_at` 刷新竞争**：写路径未见锁，取决于 MySQL upsert 行为。
- **nameservice `.well-known` 远程 fetch**：未看到完整实现，SSRF 风险依赖实际 HTTP client 配置。
- **SMS provider 真实失败语义**：仓库内只看到 MockSMSProvider；真实 provider 返回 `accepted=false` 的分支是确定 bug，但线上触发频率取决于 provider。
- **CA fingerprint fallback**：允许 `aid+cert_fingerprint` 未命中后按 AID 回退本身不算 bug；当前问题是"同公钥一致性"未被各链路一致实现，属于契约和校验不统一。

---

## 覆盖范围

- 静态源码审查，未启动 Kite、未跑单域/双域联邦 e2e。
- 已覆盖：
  - SDK 四语言（python/ts/js/go）：client、transport、auth、e2ee、e2ee-group、keystore、seq_tracker。
  - 服务模块：gateway、auth、ca、message、group、storage、mail、stream、leaderboard、aid_custody、nameservice、aun_console。
- 残余风险主要集中在：联邦链路真实抖动时的行为、多 worker 部署下的状态一致性、重连 + in-flight RPC 的时序、E2EE 在 epoch 切换瞬间的可用性窗口。

---

## 设计澄清（已排除的"伪 bug"）

- **"解密失败仍 auto-ack"不是 bug**：auto-ack 的本质是推进服务端 cursor，让 seq tracker 单向前进；若因 prekey 缺失 / epoch 未同步 / 证书未验证不 ack，客户端 cursor 永久卡死，所有后续消息堆积在服务端无法恢复。解密失败的业务处理（占位符展示、触发密钥恢复请求）是应用层责任，不应阻塞协议层游标。
- 与之真正相关的 bug 是：
  - **S14**：群密钥分发控制面消息解密失败后被当作业务消息投递；
  - **H26**：解密失败时未解密密文 payload 被原样 publish 给应用层事件；
  - **H27**：TS SDK seenMessages 先于解密/验签记录，合法重传被误判为重复。
- auto-ack 本身保留不改。

---

## 建议优先修复顺序

1. **数据丢失类**：S1（dedup 永久污染）、S2（baseline/probe）、S3（HMAC 自删）、S6（seq 伪造）、S7（孤儿 blob）、H18（leaderboard 永久 failed）。
2. **安全绕过类**：S4（refresh token 双发）、S5（短信复用）、S8（federation `_` 前缀）、S9（bare AID）、S10（phase2 不消费）、S12（审批复用）、S13（console 鉴权）、H8-H10（JWT/CRL/renew）。
3. **E2EE 语义错误类**：S11（指纹计算分裂）、S14（控制面混入数据面）、H1/H2/H7（prekey 协议）、H26/H27（密文泄漏 / seen 污染）。
4. **服务可用性类**：H3（group.changed 持久化）、H4（mail size_bytes）、H5（sms 先写后发）、H6（AID 存在性）、H11/H12/H13（group 一致性）、H14/H15（stream）、H16/H17（mail）。
5. **SDK 跨语言稳定性**：H20-H25（TS/JS/Go 各自特有问题）、M25/M26（重连/静默降级）。
6. **可观测性与细节**：中/低档全部。

---

## 尾部补记（2026-04-17，本轮继续修复时复核确认但尚未落补丁）

以下问题是在按本清单继续落修过程中再次确认的剩余项，先补记在清单尾部，避免遗漏：

1. **Leaderboard HTTP 接口仍缺鉴权**
   - `/api/leaderboard/*` 目前仍是裸露 HTTP 路由，未做 bearer/admin 鉴权。
   - 位置：`extensions/services/leaderboard/server.py:100-138`。

2. **Leaderboard 数据库未就绪的 HTTP 语义仍不合理**
   - `LeaderboardService._require_db_ready()` 仍抛 `ValueError("leaderboard database not ready")`，HTTP 层会映射成 `400`，更合理应为 `503 Service Unavailable`。
   - 位置：`extensions/services/leaderboard/service.py:620-622`、`extensions/services/leaderboard/server.py:75-81`。

3. **aid_custody `bind_phone_verify` 仍存在归属分裂风险**
   - 当前流程会先 `get_or_create_user(phone)`，再把 phone 绑定到这个 `phone_user.id`；但该 AID 的托管 owner 可能仍是另一 user，存在“手机号用户”和“AID 托管 owner”不一致的风险。
   - 位置：`extensions/services/aid_custody/service.py:726-786`。

4. **aid_custody `restore_by_phone` 仍未检查绑定用户冻结状态**
   - 当前只校验“手机号是否绑定到该 AID”与“备份记录是否存在”，未继续校验绑定 user 是否处于 `frozen/suspended/deleted` 等不可恢复状态。
   - 位置：`extensions/services/aid_custody/service.py:878-916`。

5. **aid_custody `_publish_event` 发送异常仍被静默吞掉**
   - 事件发布失败当前仍是 `except Exception: pass`，订阅侧丢事件且无诊断线索。
   - 位置：`extensions/services/aid_custody/server.py:719-734`。

6. **aid_custody `_db_reconnect_loop` 首轮仍先 `sleep(30)`**
   - 数据库初始化失败后，后台重连循环第一轮就先等待 30 秒，放大启动期 `503` 窗口。
   - 位置：`extensions/services/aid_custody/server.py:736-748`。

7. **补充复核结论：L6 中 console `_atomic_write_text` 的 fd 泄漏项需重新判定**
   - 本轮复查当前代码时，`extensions/services/aun_console/server.py` 里的 `_atomic_write_text()` 已看到 `dir_fd` 在 `finally` 中关闭；该条更像“旧审计结论可能已过时”，后续需要把此项从“待修复”与“待确认/可能已修复”中区分开，不宜直接按现状继续算作未修复。
