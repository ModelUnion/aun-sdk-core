# Group 服务角色/权限验证矩阵

## 角色层级

`owner` > `admin` > `member` > 非成员（任何已认证 AID）

### 管理层级规则（`_check_can_manage_member`）

- owner 可管理 admin 和 member
- admin 只能管理 member，不能管理 owner 或其他 admin
- owner 角色不可通过 `set_role` 修改，必须通过 `transfer_owner` 转让

### 被 ban 的 admin

- 被 ban 的 admin 管理权限自动失效（`_require_admin` 中检查）
- owner 不受 ban 影响

---

## 权限矩阵

### 群组生命周期

| RPC 方法         | 非成员 | member | admin | owner | 备注                                     |
| ---------------- | :----: | :----: | :---: | :---: | ---------------------------------------- |
| `group.create`   |   ✅   |   ✅   |  ✅   |  ✅   | 任何已认证 AID，创建者自动成为 owner     |
| `group.get`      |   ✅   |   ✅   |  ✅   |  ✅   | 公开信息所有人可查；私有字段按身份过滤   |
| `group.update`   |   ❌   |   ❌   |  ✅   |  ✅   | 修改名称/描述/可见性等                   |
| `group.suspend`  |   ❌   |   ❌   |  ❌   |  ✅   | 仅 owner                                |
| `group.resume`   |   ❌   |   ❌   |  ❌   |  ✅   | 仅 owner                                |
| `group.dissolve` |   ❌   |   ❌   |  ❌   |  ✅   | 仅 owner，级联删除所有数据               |

### 成员管理

| RPC 方法               | 非成员 | member | admin | owner | 备注                                            |
| ---------------------- | :----: | :----: | :---: | :---: | ----------------------------------------------- |
| `group.add_member`     |   ❌   |   ❌   |  ✅   |  ✅   | 添加 admin 角色仅 owner 可操作                  |
| `group.kick`           |   ❌   |   ❌   | ✅\*  |  ✅   | admin 只能踢 member                             |
| `group.leave`          |   ❌   |   ✅   |  ✅   | ❌\*\*| owner 必须先 transfer_owner                     |
| `group.set_role`       |   ❌   |   ❌   |  ❌   |  ✅   | 不能直接改 owner 角色                           |
| `group.transfer_owner` |   ❌   |   ❌   |  ❌   |  ✅   | 目标必须是现有成员                              |
| `group.get_members`    |   ❌   |   ✅   |  ✅   |  ✅   |                                                 |
| `group.ban_member`     |   ❌   |   ❌   | ✅\*  |  ✅   | admin 不能 ban owner/admin                      |
| `group.unban_member`   |   ❌   |   ❌   | ✅\*  |  ✅   | admin 不能 unban admin                      |
| `group.get_banlist`    |   ❌   |   ❌   |  ✅   |  ✅   |                                                 |

### 入群流程

| RPC 方法                         | 非成员 | member   | admin    | owner    | 备注                           |
| -------------------------------- | :----: | :------: | :------: | :------: | ------------------------------ |
| `group.request_join`             |   ✅   | ❌\*\*\* | ❌\*\*\* | ❌\*\*\* | 受 join_requirements.mode 控制 |
| `group.review_join_request`      |   ❌   |    ❌    |    ✅    |    ✅    |                                |
| `group.list_join_requests`       |   ❌   |    ❌    |    ✅    |    ✅    |                                |
| `group.get_join_requirements`    |   ✅   |    ✅    |    ✅    |    ✅    | 对所有认证用户公开             |
| `group.update_join_requirements` |   ❌   |    ❌    |    ✅    |    ✅    |                                |

### 邀请码

| RPC 方法                   | 非成员 | member   | admin | owner | 备注                                         |
| -------------------------- | :----: | :------: | :---: | :---: | -------------------------------------------- |
| `group.create_invite_code` |   ❌   |    ❌    |  ✅   |  ✅   | member 的 `allow_member_invite=false`         |
| `group.use_invite_code`    |   ✅   | ❌\*\*\* |   —   |   —   | 非成员通过邀请码入群；已是成员报错           |
| `group.list_invite_codes`  |   ❌   |    ❌    |  ✅   |  ✅   |                                              |
| `group.revoke_invite_code` |   ❌   |    ❌    |  ✅   |  ✅   |                                              |

### 消息

| RPC 方法     | 非成员 | member | admin | owner | 备注                         |
| ------------ | :----: | :----: | :---: | :---: | ---------------------------- |
| `group.send` |   ❌   |   ✅   |  ✅   |  ✅   | 被 ban 的成员不能发消息      |
| `group.pull` |   ❌   |   ✅   |  ✅   |  ✅   | 支持多设备游标同步           |

### E2EE

| RPC 方法                  | 非成员 | member | admin | owner | 备注                                              |
| ------------------------- | :----: | :----: | :---: | :---: | ------------------------------------------------- |
| `group.rotate_e2ee_epoch` |   ❌   |   ❌   |  ✅   |  ✅   | 需 rotation_signature + 时间戳新鲜度(5min) + 去重 |

### 公告与规则

| RPC 方法                    | 非成员 | member | admin | owner | 备注                                       |
| --------------------------- | :----: | :----: | :---: | :---: | ------------------------------------------ |
| `group.get_announcement`    |   ❌   |   ✅   |  ✅   |  ✅   | 非成员不可查                               |
| `group.update_announcement` |   ❌   |   ❌   |  ✅   |  ✅   |                                            |
| `group.get_rules`           |   ❌   |   ✅   |  ✅   |  ✅   | 非成员不可查                               |
| `group.update_rules`        |   ❌   |   ❌   |  ✅   |  ✅   |                                            |

### 群资源

| RPC 方法                         | 非成员 |    member    |    admin     | owner | 备注                                                    |
| -------------------------------- | :----: | :----------: | :----------: | :---: | ------------------------------------------------------- |
| `group.put_resource`             |   ❌   | ✅\*\*\*\*\* |      ✅      |  ✅   | 新建：成员可创建；覆盖已有：仅 admin/owner 或原始创建者 |
| `group.update_resource`          |   ❌   | ✅\*\*\*\*\* | ❌\*\*\*\*\* |  ✅   | 仅 owner 或资源创建者/storage_owner                     |
| `group.delete_resource`          |   ❌   | ✅\*\*\*\*\* | ❌\*\*\*\*\* |  ✅   | 仅 owner 或资源创建者/storage_owner                     |
| `group.get_resource`             |   ❌   |      ✅      |      ✅      |  ✅   |                                                         |
| `group.list_resources`           |   ❌   |      ✅      |      ✅      |  ✅   | 支持 prefix/tags/visibility 过滤                        |
| `group.get_resource_access`      |   ❌   |      ✅      |      ✅      |  ✅   | 获取下载凭证（access_ticket）                           |
| `group.resolve_access_ticket`    |   ❌   |      ✅      |      ✅      |  ✅   | 消费 access_ticket 获取下载链接                         |
| `group.request_resource`         |   ❌   |      ✅      |      ✅      |  ✅   | 成员提交资源上传申请                                    |
| `group.list_resource_requests`   |   ❌   |      ❌      |      ❌      |  ✅   | 仅 owner                                               |
| `group.approve_resource_request` |   ❌   |      ❌      |      ❌      |  ✅   | 仅 owner                                               |
| `group.reject_resource_request`  |   ❌   |      ❌      |      ❌      |  ✅   | 仅 owner                                               |
| `group.direct_add_resource`      |   ❌   |      ❌      |      ❌      |  ✅   | 仅 owner，跳过审批直接添加                              |

### 查询与统计

| RPC 方法                      | 非成员 |    member    | admin | owner | 备注                                   |
| ----------------------------- | :----: | :----------: | :---: | :---: | -------------------------------------- |
| `group.list_my_groups`        |   ✅   |      ✅      |  ✅   |  ✅   | 查自己加入的群列表                     |
| `group.search_groups`         |   ✅   |      ✅      |  ✅   |  ✅   | 仅搜索 public 群                      |
| `group.get_public_info`       |   ✅   |      ✅      |  ✅   |  ✅   | 仅 public 群                          |
| `group.get_stats`             |   ❌   |      ❌      |  ✅   |  ✅   |                                        |
| `group.get_online_members`    |   ❌   |      ✅      |  ✅   |  ✅   |                                        |

---

## 标注说明

- \*       admin 受 `_check_can_manage_member` 限制，只能操作 member
- \*\*     owner 不能直接 leave，必须先 transfer_owner
- \*\*\*   已是成员会报 "member already exists" 错误
- \*\*\*\*\* 资源操作特殊权限：`put_resource` 覆盖已有资源时需 admin/owner 或原始创建者；`update_resource` 和 `delete_resource` 需群 owner 或资源创建者/storage_owner，普通 admin 无权操作他人资源

---

## 安全机制

### 身份认证

所有方法至少需要 `_require_auth`（Kite 框架注入的 `_auth` 字段）。

### 客户端签名（client_signature）

以下敏感操作通过 `_require_actor_aid_verified` 强制验证客户端 ECDSA 签名，防篡改防重放：

- `group.add_member`, `group.kick`, `group.leave`
- `group.set_role`, `group.transfer_owner`
- `group.send`, `group.request_join`, `group.review_join_request`
- `group.use_invite_code`
- `group.update`, `group.update_rules`, `group.update_announcement`, `group.update_join_requirements`

### E2EE Epoch 轮换签名

`group.rotate_e2ee_epoch` 有独立的 `rotation_signature` 验证：
- 签名数据：`{group_id}|{current_epoch}|{new_epoch}|{aid}|{rotation_ts}`
- 时间戳新鲜度窗口：5 分钟
- 签名去重：同一签名在窗口内只接受一次

---

## SDK 侧行为

各 SDK（Python / TypeScript / JavaScript / Go）不做客户端侧角色预检，权限校验完全依赖服务端。SDK 的核心附加逻辑在 E2EE 自动编排：

| SDK 操作                       | E2EE 自动编排                                    |
| ------------------------------ | ------------------------------------------------ |
| `group_create`                 | 自动创建 Epoch 1 密钥并同步                      |
| `group_add_member`             | 成功后自动向新成员 P2P 分发密钥                  |
| `group_kick` / `group_leave`   | 触发 Epoch 轮换（存活的 admin/owner 竞争发起）   |
| `group_send`                   | 自动加密                                         |
| `group_pull`                   | 自动解密 + 零信任签名校验                        |
| `review_join_request`（通过）  | 自动向新成员分发密钥                             |
