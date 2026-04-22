# 10. Group 子协议

> **适用版本**：AUN 1.0 | **状态**：Draft

Group 服务是 AUN 协议的应用层扩展，提供多人群组通信能力。Group 服务本身是一个 AID 持有者，客户端通过标准 `message.*` 协议与 Group 服务通信，Group 服务通过 JSON-RPC 2.0 暴露 `group.*` 命名空间方法。

---

## 10.1 架构与角色

```
客户端 A ──message.send──► Group Service (AID: group.service.aid)
                              │
                              ├── 存储群消息
                              ├── 广播 event/group.message_created
                              └── 推送 event/group.changed
```

- **Group Service**：持有独立 AID，作为 AUN 节点运行，暴露 `group.*` RPC 方法
- **成员**：通过 `group.request_join` / `group.add_member` / `group.use_invite_code` 加入
- **权限层级**：`owner` > `admin` > `member`（只读群另有 `observer` 角色）

---

## 10.2 数据模型

### Group 对象

| 字段 | 类型 | 说明 |
|------|------|------|
| `group_id` | string | 群组唯一 ID（自动生成或自定义） |
| `name` | string | 群组名称 |
| `owner_aid` | string | 群主 AID |
| `creator_aid` | string | 创建者 AID |
| `visibility` | string | `"public"` / `"private"` |
| `status` | string | `"active"` / `"suspended"` / `"closed"` |
| `description` | string | 群组描述 |
| `metadata` | object | 自定义元数据 |
| `member_count` | integer | 成员数量 |
| `message_seq` | integer | 最新消息序号 |
| `event_seq` | integer | 最新事件序号 |
| `created_at` | integer | 创建时间（Unix 秒） |

### Member 对象

| 字段 | 类型 | 说明 |
|------|------|------|
| `aid` | string | 成员 AID |
| `group_id` | string | 群组 ID |
| `role` | string | `"owner"` / `"admin"` / `"member"` |
| `joined_at` | integer | 加入时间（Unix 秒） |
| `last_ack_seq` | integer | 最后已读消息序号 |

### Message 对象

| 字段 | 类型 | 说明 |
|------|------|------|
| `group_id` | string | 群组 ID |
| `seq` | integer | 消息序号（群内单调递增） |
| `message_id` | string | 消息 UUID |
| `sender_aid` | string | 发送者 AID |
| `message_type` | string | 消息类型（`"text"` 等） |
| `payload` | object | 消息内容 |
| `attachments` | array | 附件存储引用列表 |
| `created_at` | integer | 创建时间（Unix 毫秒） |

---

## 10.3 权限模型

| 操作 | owner | admin | member |
|------|:-----:|:-----:|:------:|
| 发送消息 | ✅ | ✅ | ✅ |
| 查看成员 | ✅ | ✅ | ✅ |
| 邀请成员 | ✅ | ✅ | 规则决定 |
| 踢出成员 | ✅ | ✅（非 owner）| ❌ |
| 设置角色 | ✅ | ❌ | ❌ |
| 更新群信息 | ✅ | ✅ | ❌ |
| 更新公告 | ✅ | ✅ | ❌ |
| 审批申请 | ✅ | ✅ | ❌ |
| 暂停/关闭群 | ✅ | ✅ | ❌ |
| 转让群主 | ✅ | ❌ | ❌ |
| 资源管理 | ✅ | ❌ | 申请 |

---

## 10.4 群组生命周期方法

### `group.create`

创建群组。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `name` | string | ✅ | 群组名称 |
| `group_id` | string | ❌ | 自定义群 ID，不提供则自动生成 |
| `visibility` | string | ❌ | `"public"` / `"private"`，默认由服务配置决定 |
| `description` | string | ❌ | 群组描述 |
| `metadata` | object | ❌ | 自定义元数据 |
| `avatar_ref` | string | ❌ | 头像存储引用 |
| `join_mode` | string | ❌ | `"open"` / `"approval"` / `"invite_only"` / `"closed"` |
| `join_question` | string | ❌ | 入群问题 |
| `max_pending` | integer | ❌ | 最大待审批数，默认 100 |

**响应**：

```json
{
    "group": {
        "group_id": "grp_abc123",
        "name": "测试群",
        "owner_aid": "alice.agentid.pub",
        "creator_aid": "alice.agentid.pub",
        "visibility": "private",
        "status": "active",
        "member_count": 1,
        "message_seq": 0,
        "event_seq": 0,
        "created_at": 1234567890
    },
    "aid": "alice.agentid.pub"
}
```

### `group.get`

查询群组信息。需要是群成员。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group": { ... } }`

### `group.update`

更新群组资料。需要 admin 及以上权限。

**参数**：`group_id` (必填) + 可选字段：`name` / `description` / `metadata` / `avatar_ref`

**响应**：`{ "group": { ... } }`

### `group.list` / `group.list_my`

列出当前 AID 加入的所有群组。

**参数**：`size` (integer, 可选，默认 50)

**响应**：`{ "items": [ ... ], "total": 3, "page": 1, "size": 50, "aid": "alice.agentid.pub" }`

### `group.search`

搜索公开群组（`visibility=public`）。

**参数**：`query` (string, 可选), `size` (integer, 可选)

**响应**：`{ "query": "...", "items": [ ... ], "total": 3 }`

### `group.get_public_info`

查询公开群组信息，无需是成员。仅限 `visibility=public` 的群组。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group": { ... } }`

### `group.get_stats`

获取群组统计信息。需要 admin 及以上权限。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group_id": "grp_abc", "stats": { ... } }`

### `group.suspend`

暂停群组，暂停期间不能发送消息。需要 admin 及以上权限。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group": { ... }, "status": "suspended" }`

### `group.resume`

恢复已暂停的群组。需要 admin 及以上权限。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group": { ... }, "status": "active" }`

### `group.dissolve`

永久解散群组。需要 **owner** 权限。解散后不可恢复。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group_id": "grp_abc", "status": "dissolved" }`

---

## 10.5 成员管理方法

### `group.add_member`

直接添加成员。需要 admin 及以上权限。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `group_id` | string | ✅ | 群组 ID |
| `aid` | string | ✅ | 要添加的 AID |
| `role` | string | ❌ | `"member"` / `"admin"`，默认 `"member"` |
| `member_type` | string | ❌ | `"human"` / `"ai"`，默认 `"human"` |

**响应**：`{ "group": { ... }, "member": { ... } }`

### `group.leave`

主动退出群组。owner 不可退出（须先转让）。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group": { ... }, "left_aid": "alice.agentid.pub" }`

### `group.kick`

踢出成员。需要 admin 及以上权限，不能踢 owner。

**参数**：`group_id` (必填), `aid` (必填)

**响应**：`{ "group": { ... }, "removed_aid": "bob.agentid.pub" }`

### `group.set_role`

设置成员角色。需要 **owner** 权限。

**参数**：`group_id` (必填), `aid` (必填), `role` (`"admin"` / `"member"`)

**响应**：`{ "group": { ... }, "member": { ... } }`

### `group.transfer_owner`

转让群主身份。需要 **owner** 权限。

**参数**：`group_id` (必填), `new_owner` (必填，新群主 AID；别名 `aid` 向后兼容)

**响应**：`{ "group": { ... }, "new_owner_aid": "bob.agentid.pub" }`

### `group.get_members`

获取群成员列表。需要是群成员。

**参数**：

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|:----:|--------|------|
| `group_id` | string | ✅ | — | 群组 ID |
| `page` | integer | ❌ | 1 | 页码 |
| `size` | integer | ❌ | 50 | 每页条数 |
| `role` | string | ❌ | — | 按角色过滤 |

**响应**：`{ "members": [ ... ], "total": 10, "page": 1, "size": 50 }`

### `group.ban`

封禁成员（禁止发消息但保留群成员身份）。需要 admin 及以上权限。

**参数**：`group_id` (必填), `aid` (必填), `duration_seconds` (integer, 可选，0 表示永久)

**响应**：`{ "group_id": "grp_abc", "banned_aid": "bob.agentid.pub" }`

### `group.unban`

解除封禁。需要 admin 及以上权限。

**参数**：`group_id` (必填), `aid` (必填)

**响应**：`{ "group_id": "grp_abc", "unbanned_aid": "bob.agentid.pub" }`

### `group.get_banlist`

获取封禁列表。需要 admin 及以上权限。

**参数**：`group_id` (必填)

**响应**：`{ "group_id": "grp_abc", "items": [ ... ] }`

---

## 10.6 消息方法

### `group.send`

发送群消息。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `group_id` | string | ✅ | 群组 ID |
| `type` | string | ❌ | 消息类型，如 `"text"` / `"json"` / `"notice"`，默认 `"text"` |
| `payload` | object | ✅ | 消息内容 |
| `attachments` | array | ❌ | 存储引用列表 |

**响应**：

```json
{
    "group_id": "grp_abc",
    "message": {
        "seq": 42,
        "message_id": "gm-...",
        "sender_aid": "alice.agentid.pub",
        "message_type": "text",
        "payload": { ... },
        "attachments": [],
        "created_at": 1234567890123
    },
    "event": {
        "seq": 10,
        "event_type": "message_created",
        "actor_aid": "alice.agentid.pub",
        "data": { "dispatch": { ... } },
        "created_at": 1234567890123
    },
    "dispatch": { ... }
}
```

**设计约束**：
- 群 `status=suspended` 时拒绝发送
- 消息 ID 自动生成（格式：`gm-{uuid}`），客户端无需提供

### `group.pull`

增量拉取群消息。事件请用 `group.pull_events` 单独拉取。

**参数**：

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|:----:|--------|------|
| `group_id` | string | ✅ | — | 群组 ID |
| `after_message_seq` | integer | ❌ | 0 | 拉取该 seq 之后的消息 |
| `limit` | integer | ❌ | 100 | 最大条数 |
| `device_id` | string | ❌ | — | 设备 ID（多设备模式） |

**响应**：

```json
{
    "group_id": "grp_abc",
    "messages": [ ... ],
    "latest_message_seq": 42,
    "has_more": false,
    "limit": 100
}
```

多设备模式时额外返回 `cursor` 对象（含 `current_seq`、`join_seq`、`latest_seq`、`unread_count`）。

### `group.ack`

提交已读游标（per-AID，非 per-device）。

**参数**：`group_id` (必填), `seq` (integer, 必填)

**响应**：`{ "group_id": "grp_abc", "aid": "alice.agentid.pub", "ack_seq": 42, "latest_message_seq": 100 }`

---

## 10.7 入群方式

### `group.request_join`

申请加入群组（适用于 `join_mode=approval` 的群）。

**参数**：`group_id` (必填), `message` (string, 可选，申请消息), `answer` (string, 可选，回答入群问题)

**响应**：`{ "status": "pending", "request": { ... } }`

### `group.list_join_requests`

列出入群申请。需要 admin 及以上权限。

**参数**：

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|:----:|--------|------|
| `group_id` | string | ✅ | — | 群组 ID |
| `status` | string | ❌ | `"pending"` | `"pending"` / `"approved"` / `"rejected"` |
| `page` | integer | ❌ | 1 | 页码 |
| `size` | integer | ❌ | 50 | 每页条数 |

**响应**：`{ "group_id": "grp_abc", "items": [ ... ], "total": 1 }`

### `group.review_join_request`

审批单个入群申请。需要 admin 及以上权限。**以 `aid` 定位申请**（非 request_id）。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `group_id` | string | ✅ | 群组 ID |
| `aid` | string | ✅ | 申请人 AID |
| `approve` | boolean | ❌ | 批准（true）或拒绝（false），默认 true |
| `reason` | string | ❌ | 拒绝原因 |

**响应**：`{ "request": { ... }, "group": { ... } }`

### `group.batch_review_join_request`

批量审批入群申请。需要 admin 及以上权限。

**参数**：`group_id` (必填), `aids` (array, 必填), `approve` (boolean, 必填)

**响应**：`{ "group_id": "grp_abc", "results": [ ... ] }`

### `group.get_join_requirements`

获取入群要求配置。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group_id": "grp_abc", "requirements": { "mode": "approval", "question": "...", ... } }`

### `group.update_join_requirements`

更新入群要求配置。需要 admin 及以上权限。

**参数**：`group_id` (必填), `mode` / `question` / `auto_approve_patterns` / `max_pending` (可选)

**响应**：`{ "group_id": "grp_abc", "requirements": { ... } }`

### `group.create_invite_code`

创建邀请码。需要 owner/admin 权限，或群规则允许成员邀请。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `group_id` | string | ✅ | 群组 ID |
| `code` | string | ❌ | 自定义邀请码，不提供则自动生成 |
| `max_uses` | integer | ❌ | 最大使用次数，默认 1，必须 > 0 |
| `expires_in_seconds` | integer | ❌ | 有效期（秒），默认由配置决定（7 天） |

**响应**：`{ "group_id": "grp_abc", "invite_code": { ... } }`

### `group.list_invite_codes`

列出群组的邀请码。需要 admin 及以上权限。

**参数**：`group_id` (必填), `status` (可选，`"active"` / `"expired"` / `"revoked"`)

**响应**：`{ "group_id": "grp_abc", "items": [ ... ] }`

### `group.use_invite_code`

使用邀请码加入群组。邀请码自动转为小写匹配。

**参数**：`code` (string, 必填)

**响应**：`{ "status": "joined", "group": { ... }, "invite_code": { ... } }`

### `group.revoke_invite_code`

撤销邀请码。需要 admin 及以上权限。

**参数**：`group_id` (必填), `code` (必填)

**响应**：`{ "group_id": "grp_abc", "code": "abc123", "status": "revoked" }`

---

## 10.8 公告与规则

### `group.get_announcement`

获取群公告。需要是群成员。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group_id": "grp_abc", "announcement": { ... } }`

### `group.update_announcement`

更新群公告。需要 admin 及以上权限。

**参数**：`group_id` (必填), `content` (string, 必填，上限默认 4000 字符), `attachments` (array, 可选)

### `group.get_rules`

获取群规则（可见性设置、加入模式等）。

**参数**：`group_id` (string, 必填)

### `group.update_rules`

更新入群要求。需要 admin 及以上权限。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `group_id` | string | ✅ | 群组 ID |
| `mode` | string | ❌ | `"open"` / `"approval"` / `"invite_only"` / `"closed"` |
| `question` | string | ❌ | 入群问题 |
| `auto_approve_patterns` | array | ❌ | 自动批准正则列表 |
| `max_pending` | integer | ❌ | 最大待审批数 |

---

## 10.9 资源管理

群资源是分享到群组的文件/链接引用。资源内容本身存储在 `storage.*` 服务，群组只持有引用。

### `group.resources.put`

分享资源到群组。需要 member 及以上权限。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `group_id` | string | ✅ | 群组 ID |
| `resource_path` | string | ✅ | 资源路径 |
| `title` | string | ✅ | 资源标题 |
| `resource_type` | string | ❌ | `"file"` / `"folder"` / `"link"`，默认 `"file"` |
| `storage_ref` | object | ❌ | 存储引用对象 |
| `metadata` | object | ❌ | 自定义元数据 |
| `visibility` | string | ❌ | `"members_only"` / `"public"`，默认 `"members_only"` |
| `tags` | array | ❌ | 标签数组 |

**响应**：`{ "group_id": "grp_abc", "resource": { ... }, "created": true }`（`created=false` 表示更新已有资源）

### `group.resources.get`

查看资源详情。**参数**：`group_id`, `resource_path`

**响应**：`{ "group_id": "grp_abc", "resource": { ... } }`

### `group.resources.list`

列出群资源。**参数**：`group_id` (必填), `tag` / `resource_type` / `page` / `size` (可选)

**响应**：`{ "group_id": "grp_abc", "items": [ ... ], "total": 10 }`

### `group.resources.update`

更新资源元数据。需要 admin 及以上权限。

**参数**：`group_id` (必填), `resource_path` (必填), `title` / `metadata` / `tags` / `visibility` (可选)

**响应**：`{ "group_id": "grp_abc", "resource": { ... } }`

### `group.resources.delete`

删除资源链接。需要 admin 权限。**参数**：`group_id`, `resource_path`

**响应**：`{ "group_id": "grp_abc", "resource_path": "/path/to/file" }`

### `group.resources.get_access`

获取资源访问令牌（用于下载）。

**参数**：`group_id`, `resource_path`

**响应**：`{ "resource": { ... }, "access_token": "tk_...", "token_type": "Bearer", "download": { ... } }`

### `group.resources.resolve_access_ticket`

使用访问票据换取下载令牌。

**参数**：`ticket` (string, 必填)

**响应**：`{ "resource": { ... }, "download": { ... } }`

### `group.resources.request_add`

成员申请分享资源（需 owner 审批）。**参数**：同 `group.resources.put`（不需要 `storage_ref`）。

### `group.resources.direct_add`

Owner 直接添加资源（无需审批）。需要 **owner** 权限。

### `group.resources.list_pending`

列出待审批的资源申请。需要 **owner** 权限。

### `group.resources.approve_request`

批准资源申请。需要 **owner** 权限。**参数**：`request_id` (必填), `note` (可选)

### `group.resources.reject_request`

拒绝资源申请。需要 **owner** 权限。**参数**：`request_id` (必填), `note` (可选)

---

## 10.12 在线状态

群组在线状态是 per-AID 的全局状态（非 per-group），注册一次对所有群可见。

### `group.register_online`

注册在线状态。无需 `group_id` 参数，基于当前认证 AID。

**参数**：`session_id` (string, 可选)

**响应**：`{ "aid": "alice.agentid.pub", "online": true, "member": { ... } }`

### `group.unregister_online`

注销在线状态。无参数。

**响应**：`{ "aid": "alice.agentid.pub", "online": false, "removed": true }`

### `group.heartbeat`

刷新在线心跳（防止超时过期）。无需 `group_id`。

**参数**：`session_id` (string, 可选)

### `group.get_online_members`

查询群内在线成员列表。

**参数**：`group_id` (string, 必填)

**响应**：`{ "group_id": "grp_abc", "online_members": [ ... ] }`

---

## 10.13 事件

Group 服务通过 `event/group.*` 事件推送变更通知给相关 AID。

### `event/group.created`

群组创建时推送给群主。

```json
{
    "module_id": "group",
    "group_id": "grp_abc",
    "owner_aid": "alice.agentid.pub",
    "visibility": "private"
}
```

### `event/group.changed`

群组状态变化时推送给所有成员。

```json
{
    "module_id": "group",
    "action": "member_added",
    "group_id": "grp_abc"
}
```

| `action` 值 | 说明 |
|-------------|------|
| `upsert` | 群组创建/更新 |
| `update` | 群组信息更新 |
| `member_added` | 成员加入 |
| `member_left` | 成员退出 |
| `member_removed` | 成员被踢出 |
| `role_changed` | 角色变更 |
| `owner_transferred` | 群主转让 |
| `rules_updated` | 规则更新 |
| `announcement_updated` | 公告更新 |
| `join_requested` | 收到入群申请 |
| `joined` | 成员加入（通过邀请码等） |
| `join_approved` | 入群申请批准 |
| `join_rejected` | 入群申请拒绝 |
| `join_requirements_updated` | 入群要求配置更新 |
| `invite_code_created` | 邀请码创建 |
| `invite_code_used` | 邀请码使用 |
| `invite_code_revoked` | 邀请码撤销 |
| `member_banned` | 成员被封禁 |
| `member_unbanned` | 成员解除封禁 |
| `suspended` | 群组暂停 |
| `resumed` | 群组恢复 |
| `dissolved` | 群组解散 |
| `resource_put` | 资源添加/更新 |
| `resource_updated` | 资源元数据更新 |
| `resource_deleted` | 资源删除 |
| `resource_request_created` | 资源申请创建 |
| `resource_direct_added` | 资源直接添加（owner） |
| `resource_request_approved` | 资源申请批准 |
| `resource_request_rejected` | 资源申请拒绝 |

### `event/group.message_created`

群内新消息时推送给所有在线成员。支持两种模式：

**消息推送模式**（带 `payload`）：事件包含完整消息体，SDK 自动解密后直接交付用户。

```json
{
    "module_id": "group",
    "group_id": "grp_abc",
    "seq": 42,
    "message_id": "550e8400-...",
    "sender_aid": "alice.agentid.pub",
    "type": "text",
    "payload": { "type": "e2ee.group_encrypted", "..." : "..." },
    "dispatch": { "mode": "broadcast", "reason": "duty_disabled" },
    "kind": "group.broadcast",
    "member_aids": ["bob.agentid.pub", "carol.agentid.pub"]
}
```

**通知模式**（不带 `payload`）：仅包含元数据，SDK 收到后自动调用 `group.pull` 拉取最新消息。

```json
{
    "module_id": "group",
    "group_id": "grp_abc",
    "seq": 42,
    "message_id": "550e8400-...",
    "sender_aid": "alice.agentid.pub",
    "type": "text",
    "dispatch": { "mode": "broadcast", "reason": "duty_disabled" },
    "member_aids": ["bob.agentid.pub", "carol.agentid.pub"]
}
```

> **SDK 行为**：`payload.type == "e2ee.group_encrypted"` 时自动 E2EE 解密；`payload` 缺失时自动 pull；其他情况原样透传。

---

## 10.12 错误码

| 错误码 | 说明 | 客户端处理 |
|--------|------|-----------|
| -32601 | Method not found | 检查方法名 |
| -32602 | Invalid params（如缺少 group_id） | 检查参数 |
| -32004 | Permission denied（权限不足） | 提示用户，不重试 |
| -32001 | Authentication failed | 重新认证 |
| -33001 | Group not found | 检查 group_id |
| -33002 | Group state invalid（群状态不允许该操作） | 检查群状态 |
| -33003 | Group suspended | 等待恢复或联系管理员 |
| -33004 | Group member limit reached | 不重试 |
| -33005 | Already a member | 无需处理 |
| -33006 | Not a member | 先加入群组 |
| -33007 | Role insufficient（权限不足） | 检查角色 |
| -33008 | Invite code invalid or expired | 获取新邀请码 |
| -33009 | Join rejected | 不重试 |

---

## 10.13 设计约束与实现说明

- **Group Service 是独立 AID 持有者**：所有 `group.*` 方法都通过 Group Service 的 AID 暴露，不内嵌于 Gateway。
- **消息 seq 单调递增**：per-group 粒度，确保顺序一致性，`ack_seq` 仅增不减。
- **事件 seq 独立计数**：`event_seq` 与 `message_seq` 独立；消息增量拉取使用 `group.pull`，事件增量拉取使用 `group.pull_events`。
- **duty 模式**：`duty_mode` 非 `"none"` 且 `duty_human_message_policy = "dispatch"` 时，消息先推送给当班成员处理，回复后再广播；`group.pull` 始终可拉取全量消息。
- **资源审批**：`group.resources.request_add` 提交申请后需 admin 通过 `group.resources.review_add` 审批；直接添加（owner/admin）使用 `group.resources.direct_add`。
- **在线状态**：通过 `group.get_online_members` 查询当前在线成员列表。
