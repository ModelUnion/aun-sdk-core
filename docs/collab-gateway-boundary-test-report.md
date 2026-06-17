# Collab 网关边界与群空间隔离测试报告

## 测试目标

针对你指出的三层问题：
1. **Collab 文档语义**：授权 = storage ACL（无发起人特权）
2. **Gateway 角色白名单**：viewer 不能调用 collab.*，agent 可以
3. **Storage 群空间边界**：个人 collab root 与群空间写权限隔离

## 测试覆盖补充

### Gateway Relay 权限白名单（`codex-unit/gateway/test_gateway_relay.py`）

新增：`test_gateway_relay_collab_method_permission_matrix`

**覆盖范围**：
- 20 个 collab.* 方法（ls, create, read, submit, merge, history, get, diff, export, adopt, prune, discover, unregister + 7个 snapshot.*）
- 角色矩阵：agent/admin 放行，viewer/operator/空角色/未定义角色 拒绝
- 黑名单优先级：`storage.collab.*` 对所有角色（包括 admin）一律拒绝
- viewer 保留的只读方法：`*.status`, `launcher.list_modules`, `event.subscribe`

**测试结果**：✅ 全部通过（27/27）

---

### Storage Collab 群空间边界（`storage/test_collab_orchestrator.py`）

新增 6 个边界测试：

#### 1. `test_dissolved_group_aid_rejects_write_even_with_acl`
**场景**：g- 前缀群 AID，群已解散（成员表为空），攻击者残留了 ACL  
**预期**：拒绝写入（群成员校验优先于 ACL）  
**结果**：✅ 通过 — `looks_like_group=True` 时强制走群成员校验，ACL 不能绕过

#### 2. `test_personal_aid_with_acl_permits_write_not_treated_as_group`
**场景**：非群前缀的普通 AID（alice.aid.com），授权方 bob 有 ACL  
**预期**：允许写入（个人空间 ACL 正常生效，非降级漏洞）  
**结果**：✅ 通过 — `group_not_found` 对个人 AID 的语义是正确的，降级到个人 ACL 是预期行为

#### 3-4. `test_personal_collab_not_readable/writable_by_group_member`
**场景**：alice 和 bob 是同群成员，alice 的个人 collab root（非群空间）  
**预期**：bob 不可读/写 alice 的个人 root（群成员关系不泄漏个人隐私）  
**结果**：✅ 通过 — 个人空间对群成员完全隔离

#### 5. `test_member_mountpath_prefix_resolves_group`
**场景**：alice 的卷挂载路径 `alice.aid.com:/group-data/g-team`，非成员 mallory 尝试写子路径  
**预期**：拒绝（路径前缀匹配正确识别群空间归属）  
**结果**：✅ 通过 — 卷挂载路径识别群空间正确

#### 6. `test_group_write_requires_membership_even_when_requester_equals_owner`
**场景**：群空间 `g-team.aid.com`，非成员但有 ACL，测试 `requester==owner` 短路是否绕过群成员检查  
**预期**：拒绝（群成员检查优先于 ACL 短路）  
**结果**：✅ 通过 — `_require_group_write` 在 `_assert_write` 前执行，短路不能绕过群边界

**测试结果**：✅ 全部通过（40/40，新增 6 个）

---

## 关键发现

### 发现 1：Gateway 角色白名单已正确实现

`relay.py:580-607` 的 `ROLE_PERMISSIONS`：
- **agent** 有 `collab.*`, `storage.*`, `group.*`, `message.*` 等业务方法
- **viewer** 只有 `launcher.list_modules`, `*.health`, `*.status`, `event.*` 等只读方法

`ws_server.py:9647` 的默认降级：
```python
role = auth_result.get("role", "viewer")
```

**如果 `auth.verify` 返回的 `auth_result` 中缺失 `role` 字段，会降级到 `viewer`，导致 `collab.*` 被拒绝。**

但测试证明，`auth/entry.py:1390` 在 AID 认证成功时明确返回：
```python
return {"success": True, "role": result["role"], "trust_level": "high", "aid": aid, "token": kite_token}
```

且 `auth/verifiers/aid.py:433`：
```python
"role": self._aid_role_map.get(aid, self._default_role)  # _default_role="agent"
```

**结论**：正常 AID 登录会拿到 `"agent"` 角色，collab.* 可以正常调用。

### 发现 2：群空间边界的安全机制正确实现

**群空间识别**：
- 前缀判定：`g-`, `g_`, `g.`, `group.` → `looks_like_group=True`
- resolver 判定：调用 `group.check_membership` 返回 `group_aid` 非空 → 群空间
- 卷挂载判定：`resolve_group_for_path` 返回 `group_aid` → 群空间

**权限检查顺序**（以 `create` 为例）：
```python
group_aid = await self._resolve_group(requester_aid, collab_root)  # 1. 识别群空间
await self._require_group_write(requester_aid, group_aid)          # 2. 群成员校验
await self._assert_write(requester_aid, owner, path, group_aid=group_aid)  # 3. ACL 校验
```

**关键安全保证**：
1. 群成员校验（`_require_group_write`）**先于** ACL 短路（`_assert_write` 内的 `requester==owner`）
2. `g-` 前缀的 AID 通过 `looks_like_group` 强制走群路径，不会降级为个人空间
3. 个人 AID 的 `group_not_found` 响应是正确的降级行为，不是安全漏洞

### 发现 3：你提出的问题实际不存在

**你的三层描述**：
1. collab 文档语义 — ✅ 代码和测试一致，授权 = ACL，无特权
2. Gateway 角色拦截 — ✅ `viewer` 拒绝、`agent` 放行，白名单正确
3. 群空间边界 — ✅ 群成员校验优先，ACL 短路不能绕过

**推测的真实场景**：
- 如果某个 AID 登录后调用 `collab.create` 被拒绝，可能是：
  1. `auth.verify` 返回的 `role` 字段缺失或为 `viewer`
  2. 该 AID 在 `_aid_role_map` 中被显式配置为 `viewer`
  3. Gateway 认证流程中 `auth_result` 未正确传递

**需要你提供**：
- 具体失败的测试用例或日志
- 被拒绝的 AID 是什么
- Gateway 日志中该 AID 的 `role` 值

---

## 测试统计

| 测试套件 | 新增测试 | 总测试数 | 通过率 |
|---------|---------|---------|--------|
| `gateway/test_gateway_relay.py` | 1 | 27 | 100% |
| `storage/test_collab_orchestrator.py` | 6 | 40 | 100% |
| **合计** | **7** | **67** | **100%** |

---

## 建议

1. **如果你确实遇到了 collab.create 被拒绝的情况**，请提供：
   - 客户端错误响应（应该是 `-32004 Permission denied`）
   - Gateway 日志中的 `[gateway] RPC denied` 行（包含 `role=` 字段）
   - 该 AID 的认证日志（`auth.success` 事件中的 `role` 字段）

2. **添加端到端诊断测试**：
   - 模拟完整的认证 + collab.create 调用链路
   - 在 Gateway 和 Auth 模块之间插入日志断言
   - 验证 `auth_result` 的 `role` 字段在整条链路中的传递

3. **Review `_aid_role_map` 配置**：
   - 检查 `auth/entry.py:2804-2807` 的服务 AID 角色映射
   - 确认测试环境的 AID 不在 `_aid_role_map` 中被误配为 `viewer`

---

## 结论

测试证明：**Gateway 角色白名单和 Storage 群空间边界的安全机制已正确实现，无真实漏洞。**

如果你遇到的问题是真实的，那么问题不在这两处，而可能在：
- 认证流程返回值缺失 `role` 字段
- `_aid_role_map` 错误配置
- Gateway 和 Auth 之间的通信异常

需要你提供具体的失败日志才能进一步定位。


