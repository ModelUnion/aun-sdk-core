# 群组 — RPC Manual

## 权限层级

| 角色 | 说明 |
|------|------|
| `owner` | 群主，最高权限，可转让 |
| `admin` | 管理员，可管理成员和群设置 |
| `member` | 普通成员，可收发消息 |
| `observer` | 只读成员，仅可接收消息（预留，当前未实现） |

## 方法索引

### 群组生命周期

| 方法 | 说明 |
|------|------|
| [group.create](#groupcreate) | 创建群组 |
| [group.get](#groupget) | 查询群组信息 |
| [group.update](#groupupdate) | 更新群组资料 |
| [group.list_my](#grouplist_my) | 列出我的群组 |
| [group.search](#groupsearch) | 搜索公开群 |
| [group.get_public_info](#groupget_public_info) | 查询公开群信息 |
| [group.suspend](#groupsuspend) | 暂停群组 |
| [group.resume](#groupresume) | 恢复群组 |
| [group.dissolve](#groupdissolve) | 解散群组 |
| [group.get_stats](#groupget_stats) | 获取统计信息 |

### 成员管理

| 方法 | 说明 |
|------|------|
| [group.add_member](#groupadd_member) | 添加成员 |
| [group.get_members](#groupget_members) | 获取成员列表 |
| [group.kick](#groupkick) | 踢出成员 |
| [group.leave](#groupleave) | 主动退群 |
| [group.set_role](#groupset_role) | 设置角色 |
| [group.transfer_owner](#grouptransfer_owner) | 转让群主 |
| [group.ban](#groupban) | 封禁成员 |
| [group.unban](#groupunban) | 解封成员 |
| [group.get_banlist](#groupget_banlist) | 获取封禁列表 |

### 入群流程

| 方法 | 说明 |
|------|------|
| [group.request_join](#grouprequest_join) | 申请加入 |
| [group.list_join_requests](#grouplist_join_requests) | 列出待审批申请 |
| [group.review_join_request](#groupreview_join_request) | 审批申请 |
| [group.batch_review_join_request](#groupbatch_review_join_request) | 批量审批 |
| [group.create_invite_code](#groupcreate_invite_code) | 创建邀请码 |
| [group.list_invite_codes](#grouplist_invite_codes) | 列出邀请码 |
| [group.use_invite_code](#groupuse_invite_code) | 使用邀请码 |
| [group.revoke_invite_code](#grouprevoke_invite_code) | 撤销邀请码 |

### 消息

| 方法 | 说明 |
|------|------|
| [group.send](#groupsend) | 发送群消息 |
| [group.pull](#grouppull) | 增量拉取消息 |
| [group.pull_events](#grouppull_events) | 增量拉取事件 |
| [group.ack](#groupack) | 确认已读（旧接口，等同 ack_messages） |
| [group.ack_messages](#groupack_messages) | 确认消息游标 |
| [group.ack_events](#groupack_events) | 确认事件游标 |

### 多设备管理

| 方法 | 说明 |
|------|------|
| [group.list_devices](#grouplist_devices) | 列出设备列表 |
| [group.unregister_device](#groupunregister_device) | 注销设备 |

### 管理员与成员类型

| 方法 | 说明 |
|------|------|
| [group.get_admins](#groupget_admins) | 获取管理员列表 |
| [group.get_master](#groupget_master) | 获取群主信息 |
| [group.refresh_member_types](#grouprefresh_member_types) | 刷新成员类型统计 |

### 统计与指标

| 方法 | 说明 |
|------|------|
| [group.get_summary](#groupget_summary) | 获取群组摘要 |
| [group.get_metrics](#groupget_metrics) | 获取性能指标 |

### E2EE

| 方法 | 说明 |
|------|------|
| [group.e2ee.rotate_epoch](#groupe2eerotate_epoch) | 轮换 E2EE 纪元 |
| [group.e2ee.get_epoch](#groupe2eeget_epoch) | 获取当前 E2EE 纪元 |

### 公告与规则

| 方法 | 说明 |
|------|------|
| [group.get_announcement](#groupget_announcement) | 获取公告 |
| [group.update_announcement](#groupupdate_announcement) | 更新公告 |
| [group.get_rules](#groupget_rules) | 获取群规则 |
| [group.update_rules](#groupupdate_rules) | 更新群规则 |
| [group.get_join_requirements](#groupget_join_requirements) | 获取入群要求 |
| [group.update_join_requirements](#groupupdate_join_requirements) | 更新入群要求 |

### 资源管理

| 方法 | 说明 |
|------|------|
| [group.resources.put](#groupresourcesput) | 分享资源 |
| [group.resources.get](#groupresourcesget) | 查看资源 |
| [group.resources.list](#groupresourceslist) | 列出资源 |
| [group.resources.update](#groupresourcesupdate) | 更新资源元数据 |
| [group.resources.get_access](#groupresourcesget_access) | 获取下载票据 |
| [group.resources.resolve_access_ticket](#groupresourcesresolve_access_ticket) | 解析访问票据 |
| [group.resources.delete](#groupresourcesdelete) | 删除资源 |
| [group.resources.request_add](#groupresourcesrequest_add) | 申请分享 |
| [group.resources.direct_add](#groupresourcesdirect_add) | 直接添加 |
| [group.resources.list_pending](#groupresourceslist_pending) | 待审批列表 |
| [group.resources.approve_request](#groupresourcesapprove_request) | 批准申请 |
| [group.resources.reject_request](#groupresourcesreject_request) | 拒绝申请 |

### 在线状态

| 方法 | 说明 |
|------|------|
| [group.get_online_members](#groupget_online_members) | 在线成员 |

---

## Group ID 规范

`group_id` 支持三种输入形式：`g-{slug}`、`g-{slug}@issuer-domain`、`g-{slug}.issuer-domain`。服务端接受输入后会统一规范化为 canonical group_id；本域内 `g-{slug}` 只是简写别名，响应、签名、E2EE AAD 和内部存储使用 canonical 形式。

短形式必须以 `g-` 开头，总长度 6 到 16 字符；`slug` 为 4 到 14 位，只能包含小写字母和数字。`group.create` 可以指定 `group_id`，但必须满足该规则且未被占用；如果已被占用会返回错误。不指定 `group_id` 时由服务端自动分配，服务端通过唯一约束兜底，发现碰撞会重新生成。

在 `https://group.issuer-domain/...` 这类群链接中，host 已携带 issuer，path 中的 `group_id` 使用本域简写形式，例如 `https://group.agentid.pub/g-abc123/invite/ic-xxx`。

---

## 群组生命周期

### group.create

创建群组。调用者自动成为 owner。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | 是 | 群组名称 |
| `group_id` | string | 否 | 自定义群 ID，短形式必须以 `g-` 开头且总长度 6 到 16 字符；不提供则服务端自动生成；已被占用时返回错误 |
| `visibility` | string | 否 | `"public"` / `"private"`，默认由配置决定 |
| `description` | string | 否 | 群组描述 |
| `metadata` | object | 否 | 自定义元数据 |
| `avatar_ref` | string | 否 | 头像存储引用 |
| `join_mode` | string | 否 | `"open"` / `"approval"` / `"invite_only"` / `"closed"`，回退到 visibility 映射 |
| `join_question` | string | 否 | 入群问题 |
| `auto_approve_patterns` | array | 否 | 自动批准正则列表 |
| `max_pending` | integer | 否 | 最大待审批数，默认 100 |

**响应**：

```json
{
    "group": {
        "group_id": "g-abc123.agentid.pub",
        "name": "测试群",
        "owner_aid": "alice.agentid.pub",
        "creator_aid": "alice.agentid.pub",
        "visibility": "private",
        "status": "active",
        "description": "",
        "metadata": {},
        "member_count": 1,
        "message_seq": 0,
        "event_seq": 0,
        "created_at": 1234567890,
        "updated_at": 1234567890
    }
}
```

### group.get

查询群组信息。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |

**响应**：

```json
{
    "found": true,
    "group_id": "g-abc123.agentid.pub",
    "group": { ... }
}
```

> 若群组不存在，`found` 为 `false`，`group` 为 `null`。

### group.update

更新群组资料。需要 admin 及以上权限。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `name` | string | 否 | 新名称 |
| `visibility` | string | 否 | 新可见性 |
| `description` | string | 否 | 新描述 |
| `metadata` | object | 否 | 新元数据 |
| `avatar_ref` | string | 否 | 新头像存储引用 |

### group.list_my

列出当前用户加入的群组。`group.list` 是此方法的别名，两者等价。

**参数**：

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `size` | integer | 否 | 50 | 返回数量上限（最大 200，受 max_limit 配置限制） |

> 也接受 `limit` 作为 `size` 的别名。

**响应**：

```json
{
    "items": [
        {
            "group_id": "g-abc123.agentid.pub",
            "name": "项目讨论",
            "visibility": "private",
            "member_count": 5,
            "updated_at": 1234567890,
            "role": "owner"
        }
    ],
    "total": 1,
    "page": 1,
    "size": 200,
    "aid": "alice.agentid.pub"
}
```

> **注意**：当前 `page` 固定为 1，不支持翻页。

### group.search

搜索公开群组。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `query` | string | 否 | 搜索关键词（也接受 `q`） |
| `size` | integer | 否 | 返回数量上限（也接受 `limit`） |

**响应**：

```json
{
    "query": "项目",
    "page": 1,
    "size": 50,
    "items": [ ... ],
    "total": 3
}
```

> **注意**：当前 `page` 固定为 1，不支持翻页。仅返回公开群组。

### group.get_public_info

查询公开群组信息。仅限 `visibility=public` 的群组可查询。

**参数**：`group_id` (string, 必填)

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "group": { ... }
}
```

### group.suspend

暂停群组。暂停期间不能发送消息。需要 **admin 及以上**权限。

**参数**：`group_id` (string, 必填)

**响应**：

```json
{
    "group": { ... },
    "status": "suspended"
}
```

> 若群组已处于暂停状态，`status` 为 `"unchanged"`。

### group.resume

恢复暂停的群组。需要 **admin 及以上**权限。

**参数**：`group_id` (string, 必填)

**响应**：

```json
{
    "group": { ... },
    "status": "active"
}
```

> 若群组已处于活跃状态，`status` 为 `"unchanged"`。

### group.dissolve

永久解散群组。不可恢复。需要 **owner** 权限。

**参数**：`group_id` (string, 必填)

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "status": "dissolved"
}
```

### group.get_stats

获取群组统计信息。需要 **admin 及以上**权限。

**参数**：`group_id` (string, 必填)

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "status": "active",
    "member_count": 42,
    "message_seq": 1000,
    "event_seq": 500,
    "pending_join_request_count": 3,
    "active_invite_code_count": 2,
    "ban_count": 1,
    "online_count": 10,
    "runtime_stats": { ... },
    "cleanup": { ... }
}
```

---

## 成员管理

### group.add_member

添加成员。需要 admin 及以上权限。若设置 `role=admin`，需要 owner 权限。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `aid` | string | 是 | 要添加的 AID |
| `role` | string | 否 | `"admin"` / `"member"`，默认 `"member"` |
| `member_type` | string | 否 | `"human"` / `"ai"`，默认 `"human"` |

**响应**：

```json
{
    "group": { ... },
    "member": {
        "aid": "bob.agentid.pub",
        "role": "member",
        "member_type": "human",
        "joined_at": 1234567890
    }
}
```

### group.get_members

获取成员列表。支持分页和角色过滤。

**参数**：

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `group_id` | string | 是 | — | 群组 ID |
| `page` | integer | 否 | 1 | 页码 |
| `size` | integer | 否 | 50 | 每页条数（最大 200） |
| `role` | string | 否 | — | 按角色过滤（owner/admin/member） |

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "members": [
        {
            "group_id": "g-abc123.agentid.pub",
            "aid": "alice.agentid.pub",
            "role": "owner",
            "member_type": "human",
            "joined_at": 1234567890,
            "last_ack_seq": 100,
            "last_pull_at": 1234567890
        }
    ],
    "total": 1,
    "count": 1,
    "page": 1,
    "size": 50
}
```

### group.kick

踢出成员。需要 admin 及以上权限，不能踢 owner。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `aid` | string | 是 | 要踢出的 AID |

**响应**：

```json
{
    "group": { ... },
    "removed_aid": "bob.agentid.pub"
}
```

### group.leave

主动退出群组。owner 不能直接退群，需先转让群主。

**参数**：`group_id` (string, 必填)

**响应**：

```json
{
    "group": { ... },
    "left_aid": "bob.agentid.pub"
}
```

### group.set_role

设置成员角色。需要 **owner** 权限。不能改变 owner 角色。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `aid` | string | 是 | 目标 AID |
| `role` | string | 是 | `"admin"` / `"member"` |

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "member": {
        "group_id": "g-abc123.agentid.pub",
        "aid": "bob.agentid.pub",
        "role": "admin",
        "member_type": "human",
        "joined_at": 1234567890,
        "last_ack_seq": 0,
        "last_pull_at": 0
    }
}
```

### group.transfer_owner

转让群主。需要 owner 权限。原 owner 转为 admin。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `new_owner` | string | 是 | 新群主 AID（也接受 `aid`） |

**响应**：

```json
{
    "group": { ... },
    "old_owner": "alice.agentid.pub",
    "new_owner": "bob.agentid.pub"
}
```

### group.ban

封禁成员。被封禁者禁止发消息但保留成员身份，且不能重新加入（如先被移除再封禁）。需要 **admin 及以上**权限。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `subject` | string | 是 | 要封禁的 AID（也接受 `aid`） |
| `reason` | string | 否 | 封禁原因 |
| `expires_at` | integer | 否 | 过期时间戳（0 = 永久） |
| `expires_in_seconds` | integer | 否 | 相对过期秒数（0 = 永久） |

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "ban": {
        "group_id": "g-abc123.agentid.pub",
        "subject": "spammer.agentid.pub",
        "banned_by": "alice.agentid.pub",
        "reason": "垃圾消息",
        "expires_at": 0,
        "created_at": 1234567890
    }
}
```

### group.unban

解除封禁。需要 **admin 及以上**权限。

**参数**：`group_id` (string), `subject` 或 `aid` (string)

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "subject": "spammer.agentid.pub",
    "status": "removed"
}
```

### group.get_banlist

获取封禁列表。需要 **admin 及以上**权限。

**参数**：`group_id` (string, 必填)

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "items": [
        {
            "group_id": "g-abc123.agentid.pub",
            "subject": "spammer.agentid.pub",
            "banned_by": "alice.agentid.pub",
            "reason": "垃圾消息",
            "expires_at": 0,
            "created_at": 1234567890
        }
    ],
    "total": 1,
    "page": 1,
    "size": 200
}
```

---

## 入群流程

### group.request_join

申请加入群组。根据群组 join_mode 设置，有三种结果分支。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `message` | string | 否 | 申请留言 |
| `answer` | string | 否 | 入群问题的答案 |

**响应**（三种分支）：

**1. 自动加入**（open 模式或匹配自动批准规则）：

```json
{
    "status": "joined",
    "group": { ... },
    "member": { ... }
}
```

**2. 需要回答问题**（approval 模式但未提供答案）：

```json
{
    "status": "question_required",
    "question": "请描述你的用途"
}
```

**3. 待审批**（approval 模式且已提供答案）：

```json
{
    "status": "pending",
    "request": {
        "group_id": "g-abc123.agentid.pub",
        "aid": "carol.agentid.pub",
        "message": "请加我",
        "answer": "...",
        "status": "pending",
        "created_at": 1234567890,
        "updated_at": 1234567890,
        "expires_at": 1234654290,
        "reviewed_by": null,
        "rejection_reason": null
    }
}
```

### group.list_join_requests

列出待审批申请。需要 admin 权限。

**参数**：

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `group_id` | string | 是 | — | 群组 ID |
| `status` | string | 否 | `"pending"` | `"pending"` / `"approved"` / `"rejected"` |
| `page` | integer | 否 | 1 | 页码 |
| `size` | integer | 否 | — | 每页数量 |

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "items": [
        {
            "group_id": "g-abc123.agentid.pub",
            "aid": "carol.agentid.pub",
            "message": "请加我",
            "status": "pending",
            "created_at": 1234567890,
            "updated_at": 1234567890
        }
    ],
    "total": 1,
    "page": 1,
    "size": 50
}
```

### group.review_join_request

审批单个申请。需要 admin 权限。**使用 `aid` 定位申请**（非 request_id）。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `aid` | string | 是 | 申请人 AID |
| `approve` | boolean | 否 | 批准或拒绝，默认 `true` |
| `reason` | string | 否 | 拒绝原因 |

**响应**（批准时）：

```json
{
    "status": "approved",
    "request": { ... },
    "group": { ... }
}
```

**响应**（拒绝时）：

```json
{
    "status": "rejected",
    "request": {
        "group_id": "g-abc123.agentid.pub",
        "aid": "carol.agentid.pub",
        "status": "rejected",
        "reviewed_by": "alice.agentid.pub",
        "rejection_reason": "不符合条件"
    }
}
```

### group.batch_review_join_request

批量审批入群申请。需要 admin 权限。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `requests` | array | 是 | 审批列表 |

`requests` 数组每项：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `aid` | string | 是 | 申请人 AID |
| `approve` | boolean | 是 | 批准或拒绝 |
| `reason` | string | 否 | 拒绝原因 |

**响应**：

```json
{
    "results": [
        {"aid": "carol.agentid.pub", "ok": true, "status": "approved", "request": { ... }},
        {"aid": "dave.agentid.pub", "ok": false, "error": "not found"}
    ],
    "success_count": 1,
    "fail_count": 1
}
```

### group.create_invite_code

创建邀请码。需要 owner/admin 权限，或群规则允许成员邀请。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `code` | string | 否 | 自定义邀请码（不提供则自动生成） |
| `max_uses` | integer | 否 | 最大使用次数，默认 1，必须 > 0 |
| `expires_in_seconds` | integer | 否 | 有效期（秒），默认由 invite_code_ttl_days 配置（7 天） |

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "invite_code": {
        "group_id": "g-abc123.agentid.pub",
        "code": "ic-a1b2c3d4e5",
        "created_by": "alice.agentid.pub",
        "expires_at": 1235172690,
        "max_uses": 10,
        "used_count": 0,
        "status": "active",
        "created_at": 1234567890
    }
}
```

### group.use_invite_code

使用邀请码加入群组。

**参数**：`code` (string, 必填，自动转为小写)

**响应**：

```json
{
    "status": "joined",
    "group": { ... },
    "invite_code": { ... }
}
```

### group.list_invite_codes

列出群组的邀请码。需要 admin 权限。

**参数**：`group_id` (string, 必填)

### group.revoke_invite_code

撤销邀请码。需要 admin 权限。

**参数**：`group_id` (string), `code` (string)

---

## 消息

### group.send

发送群消息。需要 member 权限。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `payload` | object | 否 | 消息内容 |
| `type` | string | 否 | 信封/封装类型，普通业务消息无需填写；SDK 加密群消息时自动使用 `e2ee.group_encrypted` |
| `attachments` | array | 否 | 兼容旧接口的顶层附件元数据；推荐把业务附件放入 `payload.attachments` |

### Payload 参考约定

`payload` 是群消息的应用层内容，Group 服务只做 JSON 可序列化、大小、信封/封装类型和 E2EE epoch 相关检查，其他字段由客户端约定。本节参考 wxauto `Message` 类的常见消息形态（文本、引用、语音、图片、视频、文件、位置、链接、表情、合并转发、名片、笔记等），并补充 AUN Agent 场景常用的状态、结构化数据、投票和工具调用类型。

示例展示的是 `group.send.params.payload` 片段；完整群请求仍需要在同级传入 `group_id`。文本、图片、文件等业务消息类型只能放在 `payload.type`；`group.send.params.type` 是信封/封装类型，例如 SDK 加密群消息时自动填充的 `e2ee.group_encrypted`，不表示业务负载类型。

#### 信封字段不进入 payload

`payload` 只描述业务内容，不重复群消息信封已经提供的字段。

| 字段 | 所在位置 | 说明 |
|------|----------|------|
| `group_id` | `group.send.params` 和群消息信封 | 群组 ID |
| `sender_aid` | 服务端生成的群消息信封 | 发送方 AID |
| `message_id` / `seq` / `created_at` | 服务端生成的群消息信封 | 当前群消息 ID、群内序号、创建时间 |
| `message_type` / `type` | 发送参数或消息信封 | 信封/封装类型，如 `e2ee.group_encrypted`；业务负载类型使用 `payload.type` |
| `dispatch` / `duty_state` | `group.send` 响应 | 群消息分发状态 |

#### 公共辅助字段

以下字段可出现在多数 payload 中；如无需要，不必携带。

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `type` | string | 是 | 业务负载类型，如 `text` / `image` / `status` / `event` / `tool_call` |
| `text` | string | 否 | 面向用户展示的正文或摘要 |
| `format` | string | 否 | 文本格式，建议值：`plain` / `markdown` |
| `chat_id` | string | 否 | 应用层会话或场景标识；群组本身仍由外层 `group_id` 标识 |
| `thread_id` | string | 否 | 群内话题、子线程或任务线程 |
| `reply_to` | object | 否 | 回复目标，推荐含 `message_id`、`seq`、`sender_aid` |
| `mentions` | array | 否 | 提及对象数组；单人提及推荐项为 `{aid, display, offset, length}`；全体提及使用 `{scope: "all"}` |
| `entities` | array | 否 | 文本实体，如链接、代码片段、时间范围 |
| `attachments` | array | 否 | 附件引用列表，结构见“附件引用” |
| `client_context` | object | 否 | 客户端自定义上下文，如窗口、任务、草稿来源 |

字段名建议使用 snake_case，如 `chat_id`、`thread_id`；已有应用若使用 `chatId` 等命名，可在自己的应用层约定中保持一致。

`chat_id`、`thread_id`、`reply_to`、`mentions`、`entities`、`client_context` 这类字段无法可靠放入群消息信封：它们属于应用上下文，不参与群路由或权限判断，但又常常需要端到端加密保护。因此这些字段应保留在 `payload` 内，由 SDK 随群消息内容一起加密。

#### `mentions`：提及语义

`payload.mentions` 是应用层提及列表，只用于展示、高亮或通知提示，不参与群路由、权限判断或 E2EE 收件人集合计算。提及必须放在 `payload` 内并随业务内容一起加密；不要放在 `group.send` 外层信封。

- 单人成员提及使用 `{ "aid": "bob.agentid.pub", "display": "Bob", "offset": 0, "length": 3 }`。`offset` / `length` 描述 `payload.text` 中对应展示文本的字符范围；没有可靠范围时可省略。
- 全体提及使用规范形式 `{ "scope": "all" }`，含义为 `@所有人`。需要 UI 高亮时可带 `display` / `offset` / `length`，例如 `{ "scope": "all", "display": "@所有人", "offset": 0, "length": 4 }`。
- `all` 不是 AID，不要写成 `{ "aid": "all" }`。它只覆盖当前群成员，不扩大到非成员或历史成员，也不改变服务端分发模式。
- 若同时出现 `{ "scope": "all" }` 和具体 `{ "aid": ... }`，客户端应按全体提及处理；具体成员项可继续用于局部高亮。
- 不理解 `mentions` 的客户端必须忽略该字段，不影响消息展示。

#### `text`：文本消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `text` | string | 是 | 文本内容 |
| `format` | string | 否 | `plain` / `markdown`，默认 `plain` |
| `lang` | string | 否 | BCP 47 语言标签，如 `zh-CN` |
| `mentions` | array | 否 | 群成员或全体提及列表；全体提及使用 `{scope: "all"}` |
| `entities` | array | 否 | 文本实体范围 |

```json
{
  "payload": {
    "type": "text",
    "text": "@所有人 明天 10:00 开会",
    "format": "plain",
    "mentions": [{"scope": "all", "display": "@所有人", "offset": 0, "length": 4}]
  }
}
```

#### `quote`：引用消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `text` | string | 是 | 本次回复内容 |
| `quote` | object | 是 | 被引用消息摘要，避免复制完整敏感原文 |
| `quote.message_id` | string | 否 | 被引用群消息 ID |
| `quote.seq` | integer | 否 | 被引用群消息序号 |
| `quote.text` | string | 否 | 被引用内容摘要 |
| `quote.sender_display` | string | 否 | 展示用发送者名称 |

```json
{
  "payload": {
    "type": "quote",
    "text": "我同意这个方案",
    "quote": {
      "message_id": "gm-prev",
      "seq": 12,
      "text": "是否采用方案 A？",
      "sender_display": "Bob"
    }
  }
}
```

#### `voice`：语音消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `attachments` | array | 是 | 语音文件引用，通常为单项 |
| `duration_ms` | integer | 否 | 语音时长 |
| `transcript` | string | 否 | 语音转文字结果 |
| `codec` | string | 否 | 编码格式，如 `opus` / `aac` |

```json
{
  "payload": {
    "type": "voice",
    "duration_ms": 8200,
    "transcript": "我稍后处理这个问题",
    "attachments": [{
      "url": "aun://storage/default/groups/g-abc123.agentid.pub/voice/gm-1.opus",
      "filename": "gm-1.opus",
      "content_type": "audio/ogg"
    }]
  }
}
```

#### `image`：图片消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `attachments` | array | 是 | 图片对象引用，可多张 |
| `alt` | string | 否 | 无障碍或降级展示文本 |
| `width` | integer | 否 | 图片宽度，像素 |
| `height` | integer | 否 | 图片高度，像素 |
| `text` | string | 否 | 图片说明 |

```json
{
  "payload": {
    "type": "image",
    "text": "新版流程图",
    "alt": "AUN 群消息投递流程图",
    "width": 1280,
    "height": 720,
    "attachments": [{
      "url": "aun://storage/default/groups/g-abc123.agentid.pub/images/flow.png",
      "filename": "flow.png",
      "content_type": "image/png"
    }]
  }
}
```

#### `video`：视频消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `attachments` | array | 是 | 视频对象引用，通常为单项 |
| `duration_ms` | integer | 否 | 视频时长 |
| `thumbnail` | object | 否 | 封面图引用，结构同附件引用 |
| `width` / `height` | integer | 否 | 视频尺寸，像素 |
| `text` | string | 否 | 视频说明 |

```json
{
  "payload": {
    "type": "video",
    "text": "演示录屏",
    "duration_ms": 30500,
    "thumbnail": {
      "url": "aun://storage/default/groups/g-abc123.agentid.pub/videos/demo-cover.jpg",
      "content_type": "image/jpeg"
    },
    "attachments": [{
      "url": "aun://storage/default/groups/g-abc123.agentid.pub/videos/demo.mp4",
      "filename": "demo.mp4",
      "content_type": "video/mp4"
    }]
  }
}
```

#### `file`：文件消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `attachments` | array | 是 | 文件引用，可多项 |
| `text` | string | 否 | 文件说明 |
| `expires_at` | integer | 否 | 应用层建议过期时间，毫秒时间戳 |

```json
{
  "payload": {
    "type": "file",
    "text": "请查收附件",
    "attachments": [{
      "url": "aun://storage/default/groups/g-abc123.agentid.pub/docs/report.pdf",
      "filename": "report.pdf",
      "content_type": "application/pdf",
      "size_bytes": 245678,
      "sha256": "3d8e577b..."
    }]
  }
}
```

#### `location`：位置消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `name` | string | 否 | 地点名称 |
| `address` | string | 否 | 地址文本 |
| `latitude` | number | 是 | 纬度，WGS84 |
| `longitude` | number | 是 | 经度，WGS84 |
| `precision_m` | number | 否 | 精度，单位米 |
| `map_url` | string | 否 | 地图链接 |

```json
{
  "payload": {
    "type": "location",
    "name": "上海虹桥站",
    "address": "上海市闵行区申贵路 1500 号",
    "latitude": 31.1944,
    "longitude": 121.3189,
    "precision_m": 30,
    "map_url": "https://maps.example.com/?q=31.1944,121.3189"
  }
}
```

#### `link`：链接消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `url` | string | 是 | 目标链接 |
| `title` | string | 否 | 卡片标题 |
| `description` | string | 否 | 卡片摘要 |
| `thumbnail` | object | 否 | 预览图引用 |

```json
{
  "payload": {
    "type": "link",
    "url": "https://example.com/aun/design",
    "title": "AUN 设计说明",
    "description": "消息、群组和 E2EE 的设计摘要",
    "thumbnail": {
      "url": "aun://storage/default/previews/aun-design.png",
      "content_type": "image/png"
    }
  }
}
```

#### `emotion`：表情消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `emoji_id` | string | 否 | 表情或贴纸 ID |
| `package_id` | string | 否 | 表情包 ID |
| `alt` | string | 否 | 降级展示文本 |
| `attachments` | array | 否 | 自定义表情文件引用 |

```json
{
  "payload": {
    "type": "emotion",
    "emoji_id": "thumbs_up",
    "alt": "[点赞]"
  }
}
```

#### `merge`：合并转发消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `title` | string | 是 | 合并转发标题 |
| `summary` | string | 否 | 摘要文本 |
| `items` | array | 否 | 少量内联消息摘要；大量内容应走附件 |
| `attachments` | array | 否 | 完整合并记录的对象引用 |

```json
{
  "payload": {
    "type": "merge",
    "title": "项目讨论记录",
    "summary": "包含 3 条关键消息",
    "items": [
      {"sender_display": "Alice", "text": "先确认接口"},
      {"sender_display": "Bob", "text": "我来补测试"}
    ]
  }
}
```

#### `personal_card`：名片消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `aid` | string | 否 | AUN AID；没有 AID 时可只作为展示卡片 |
| `display_name` | string | 是 | 展示名称 |
| `avatar` | object | 否 | 头像引用 |
| `profile_url` | string | 否 | 资料页链接 |
| `note` | string | 否 | 推荐语或备注 |

```json
{
  "payload": {
    "type": "personal_card",
    "aid": "carol.agentid.pub",
    "display_name": "Carol",
    "profile_url": "https://agentid.pub/carol",
    "note": "负责存储服务"
  }
}
```

#### `note`：笔记消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `title` | string | 否 | 笔记标题 |
| `text` | string | 是 | 笔记正文或摘要 |
| `format` | string | 否 | `plain` / `markdown` |
| `url` | string | 否 | 外部笔记链接 |
| `attachments` | array | 否 | 笔记内附件引用 |

```json
{
  "payload": {
    "type": "note",
    "title": "联调记录",
    "text": "1. 修复重连\n2. 补充 group.send 测试",
    "format": "markdown"
  }
}
```

#### `status`：状态或事件消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `state` | string | 是 | 当前状态，如 `online` / `busy` / `typing` / `processing` / `completed` / `error` |
| `event` | string | 否 | 触发状态变化的事件名 |
| `text` | string | 否 | 展示文案 |
| `data` | object | 否 | 事件或状态的结构化数据 |
| `progress` | number | 否 | 进度，范围 0 到 1 |
| `expires_at` | integer | 否 | 状态过期时间，毫秒时间戳 |

```json
{
  "payload": {
    "type": "status",
    "state": "processing",
    "event": "deployment.started",
    "text": "正在发布新版 SDK",
    "progress": 0.4,
    "data": {"task_id": "deploy-123"}
  }
}
```

#### `event`：事件消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `type` | string | 是 | 固定为 `event` |
| `event` | string | 是 | 应用层事件名，如 `deployment.completed` |
| `data` | object | 否 | 事件数据 |
| `text` | string | 否 | 降级展示文案 |
| `severity` | string | 否 | 级别，如 `info` / `warning` / `error` |
| `occurred_at` | integer | 否 | 事件发生时间，毫秒时间戳 |

```json
{
  "payload": {
    "type": "event",
    "event": "deployment.completed",
    "text": "新版 SDK 已发布",
    "severity": "info",
    "data": {"task_id": "deploy-123", "version": "0.2.7"}
  }
}
```

#### `json`：结构化数据消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `kind` | string | 是 | 业务子类型，建议使用反向域名或产品前缀 |
| `data` | object | 是 | 结构化数据 |
| `schema` | string | 否 | JSON Schema URL 或版本标识 |
| `fallback_text` | string | 否 | 接收方不识别时的降级展示文本 |

```json
{
  "payload": {
    "type": "json",
    "kind": "pub.agentid.workflow.plan",
    "schema": "https://agentid.pub/schemas/workflow-plan-v1.json",
    "fallback_text": "收到一个工作流计划",
    "data": {
      "steps": ["collect", "analyze", "report"]
    }
  }
}
```

#### `reaction`：消息反应

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `target` | object | 是 | 目标群消息，推荐含 `message_id`、`seq`、`sender_aid` |
| `action` | string | 是 | `add` / `remove` |
| `key` | string | 是 | 反应标识，如 `like` / `done` |
| `text` | string | 否 | 展示文本 |

```json
{
  "payload": {
    "type": "reaction",
    "target": {"message_id": "gm-prev", "seq": 41, "sender_aid": "bob.agentid.pub"},
    "action": "add",
    "key": "done",
    "text": "已处理"
  }
}
```

#### `poll`：投票或表单

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `kind` | string | 是 | 固定为 `poll` 或应用自定义表单类型 |
| `title` | string | 是 | 投票或表单标题 |
| `options` | array | 是 | 选项列表 |
| `multiple` | boolean | 否 | 是否允许多选，默认 `false` |
| `expires_at` | integer | 否 | 截止时间，毫秒时间戳 |

```json
{
  "payload": {
    "type": "json",
    "kind": "poll",
    "title": "下次例会时间",
    "options": [
      {"id": "a", "text": "周一 10:00"},
      {"id": "b", "text": "周二 14:00"}
    ],
    "multiple": false
  }
}
```

#### `tool_call`：工具调用请求

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `call_id` | string | 是 | 调用 ID，用于关联结果 |
| `name` | string | 是 | 工具或能力名称 |
| `arguments` | object | 是 | 调用参数 |
| `timeout_ms` | integer | 否 | 期望超时时间 |
| `meta` | object | 否 | 调用方附加元数据 |

```json
{
  "payload": {
    "type": "tool_call",
    "call_id": "call-001",
    "name": "ci.run",
    "arguments": {"workflow": "sdk-tests"},
    "timeout_ms": 120000
  }
}
```

#### `tool_result`：工具调用结果

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `call_id` | string | 是 | 对应 `tool_call.call_id` |
| `ok` | boolean | 是 | 是否成功 |
| `result` | object | 否 | 成功结果 |
| `error` | object | 否 | 失败信息，推荐含 `code`、`message` |

```json
{
  "payload": {
    "type": "tool_result",
    "call_id": "call-001",
    "ok": true,
    "result": {
      "passed": 128,
      "failed": 0
    }
  }
}
```

#### `custom`：自定义消息

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `kind` | string | 是 | 自定义类型标识 |
| `data` | object | 是 | 自定义数据 |
| `fallback_text` | string | 否 | 降级展示文本 |

```json
{
  "payload": {
    "type": "custom",
    "kind": "com.example.crm.ticket",
    "fallback_text": "收到一个工单卡片",
    "data": {
      "ticket_id": "T-10086",
      "priority": "high"
    }
  }
}
```

### 附件引用

推荐把附件引用放入 `payload.attachments`。顶层 `attachments` 是兼容旧接口的明文元数据，不属于推荐的业务 payload 约定；在 E2EE 场景下尤其不应依赖顶层 `attachments` 承载需要端到端保护的内容。

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `owner_aid` | string | 否 | 对象所有者 AID，可作为对象标识补充 |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `object_key` | string | 否 | Storage 对象路径 |
| `url` | string | 否 | 对象 URL；AUN Storage 场景下为上传完成后返回的长期对象引用 |
| `filename` | string | 否 | 原始文件名；缺省时可由 `object_key` 推导 |
| `content_type` | string | 否 | MIME 类型 |
| `size_bytes` | integer | 否 | 文件大小（字节） |
| `sha256` | string | 否 | 内容哈希，用于完整性校验 |
| `thumbnail` | object | 否 | 缩略图引用，结构同附件引用 |

AUN Storage 的 `url` 是长期对象引用，不是最终文件下载地址。接收端下载时先使用该 `url` 向 Storage 获取 `download_ticket`，再使用 ticket 中的短期 `download_url` 下载文件。`owner_aid`、`bucket`、`object_key` 可作为可选对象标识补充，便于没有 `url` 解析能力的客户端或服务端工具定位对象。

**附件引用示例**：

```json
{
  "group_id": "g-abc123.agentid.pub",
  "payload": {
    "type": "image",
    "text": "这张图是新版流程",
    "thread_id": "release-2026-04",
    "reply_to": {"message_id": "gm-prev", "seq": 12},
    "mentions": [{"aid": "bob.agentid.pub", "display": "Bob", "offset": 0, "length": 3}],
    "attachments": [{
      "owner_aid": "alice.agentid.pub",
      "bucket": "default",
      "object_key": "images/flow.png",
      "url": "https://storage.agentid.pub/objects/default/images/flow.png",
      "filename": "flow.png",
      "content_type": "image/png"
    }]
  }
}
```

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "message": {
        "group_id": "g-abc123.agentid.pub",
        "seq": 42,
        "message_id": "uuid",
        "sender_aid": "alice.agentid.pub",
        "message_type": "e2ee.group_encrypted",
        "payload": {"type": "e2ee.group_encrypted", "...": "..."},
        "attachments": [],
        "created_at": 1234567890000
    },
    "event": { ... },
    "dispatch": {"mode": "broadcast", "reason": "duty_disabled"},
    "message_dispatch": { ... }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `group_id` | string | 群组 ID |
| `message` | object | 消息对象（含 seq、message_id、sender_aid 等） |
| `event` | object | 关联的群事件对象 |
| `dispatch` | object | 分发策略：`mode` 为 `"broadcast"`（广播全员）或 `"duty"`（值班分发）；`reason` 说明原因（如 `"duty_disabled"` / `"active_duty"` / `"no_duty_candidate"` 等） |
| `duty_state` | object | 可选，值班模式下的当前状态 |
| `message_dispatch` | object | 运行时分发结果（广播目标等结构化信息） |

### group.pull

增量拉取群消息。事件请用 `group.pull_events` 单独拉取。

**参数**：

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `group_id` | string | 是 | — | 群组 ID |
| `after_message_seq` | integer | 否 | 0 | 从该消息 seq 之后拉取 |
| `limit` | integer | 否 | 100 | 最大条数 |
| `device_id` | string | 否 | — | 设备 ID（多设备模式） |

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "messages": [ ... ],
    "latest_message_seq": 42,
    "has_more": false,
    "limit": 100
}
```

多设备模式时额外返回 `cursor` 对象（含 `current_seq`、`join_seq`、`latest_seq`、`unread_count`）。

### group.ack

提交群消息已读游标。等同于 `group.ack_messages`，需要 `device_id`。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `device_id` | string | 是 | 设备 ID |
| `msg_seq` | integer | 是 | 确认到的消息序号 |

**响应**：

```json
{"cursor": 42}
```

---

## 公告与规则

### group.get_announcement

获取群公告。

**参数**：`group_id` (string, 必填)

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "announcement": { ... }
}
```

### group.update_announcement

更新群公告。需要 **admin 及以上**权限。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `content` | string | 是 | 公告内容（上限由 announcement_max_length 配置，默认 4000） |
| `attachments` | array | 否 | 存储引用数组 |

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "announcement": { ... }
}
```

### group.get_rules

获取群规则。

**参数**：`group_id` (string, 必填)

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "rules": { ... }
}
```

### group.update_rules

更新群规则。需要 **admin 及以上**权限。

**参数**：`group_id` (string) + 规则字段（max_members, allow_member_invite 等，均可选）

### group.get_join_requirements

获取入群要求。

**参数**：`group_id` (string, 必填)

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "join_requirements": {
        "group_id": "g-abc123.agentid.pub",
        "mode": "approval",
        "question": "请描述你的用途",
        "auto_approve_patterns": [],
        "max_pending": 100,
        "updated_by": "alice.agentid.pub",
        "updated_at": 1234567890
    }
}
```

### group.update_join_requirements

更新入群要求。需要 **admin 及以上**权限。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `mode` | string | 否 | `"open"` / `"approval"` / `"invite_only"` / `"closed"` |
| `question` | string | 否 | 入群问题 |
| `auto_approve_patterns` | array | 否 | 自动批准正则列表 |
| `max_pending` | integer | 否 | 最大待审批数 |

---

## 资源管理

### group.resources.put

分享资源链接到群组。需要 **member 及以上**权限。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `resource_path` | string | 是 | 资源路径 |
| `resource_type` | string | 否 | `"file"` / `"folder"` / `"link"`，默认 `"file"` |
| `title` | string | 是 | 资源标题 |
| `storage_ref` | object | 否 | 存储引用对象 |
| `metadata` | object | 否 | 自定义元数据 |
| `visibility` | string | 否 | `"members_only"` / `"public"`，默认 `"members_only"` |
| `tags` | array | 否 | 标签数组 |

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "resource": { ... },
    "created": true
}
```

> `created` 为 `true` 表示新建，`false` 表示更新已有资源。

### group.resources.get

查看资源详情。

**参数**：`group_id` (string), `resource_path` (string)

### group.resources.list

列出群资源。

**参数**：

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `group_id` | string | 是 | — | 群组 ID |
| `prefix` | string | 否 | — | 资源路径前缀 |
| `owner_aid` | string | 否 | — | 筛选创建者 |
| `visibility` | string | 否 | — | 筛选可见性 |
| `tags` | array | 否 | — | 筛选标签 |
| `sort_by` | string | 否 | `"resource_path"` | 排序字段 |
| `order` | string | 否 | `"asc"` | `"asc"` / `"desc"` |
| `size` | integer | 否 | 50 | 每页数量（也接受 `limit`） |
| `page` | integer | 否 | 1 | 页码（也接受 `offset`） |

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "prefix": "",
    "owner_aid": null,
    "visibility": null,
    "tags": [],
    "limit": 50,
    "size": 50,
    "offset": 0,
    "page": 1,
    "items": [ ... ],
    "count": 3,
    "total": 3
}
```

### group.resources.get_access

获取资源下载票据。

**参数**：`group_id` (string), `resource_path` (string)

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "resource_path": "/docs/guide.pdf",
    "resource_link": "storage://...",
    "resource": { ... },
    "access_ticket": {
        "ticket": "tk_...",
        "ticket_type": "group-resource-access",
        "issued_to": "alice.agentid.pub",
        "resource_link": "storage://...",
        "issued_at": 1234567890,
        "expire_at": 1234571490
    },
    "access_token": "tk_...",
    "token_type": "Bearer",
    "download": { ... }
}
```

### group.resources.delete

删除群资源链接。需要 admin 权限。

**参数**：`group_id` (string), `resource_path` (string)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "resource_path": "/path/to/file" }`

### group.resources.update

更新资源元数据。需要 admin 及以上权限。

**参数**：`group_id` (必填), `resource_path` (必填), `title` / `metadata` / `tags` / `visibility` (可选)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "resource": { ... } }`

### group.resources.resolve_access_ticket

使用访问票据换取下载令牌。

**参数**：`ticket` (string, 必填)

**响应**：`{ "resource": { ... }, "download": { ... } }`

### group.resources.request_add

成员申请分享资源（需审批）。

**参数**：同 `group.resources.put`（不需要 `storage_ref`）。

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "request": {
        "request_id": "req_...",
        "group_id": "g-abc123.agentid.pub",
        "requester_aid": "bob.agentid.pub",
        "resource_path": "/docs/my-file.pdf",
        "resource_type": "file",
        "title": "我的文件",
        "status": "pending",
        "created_at": 1234567890,
        "updated_at": 1234567890,
        "visibility": "members_only",
        "tags": [],
        "reviewed_by": null,
        "review_note": null,
        "resource_created": false
    }
}
```

### group.resources.direct_add

Owner 直接添加资源（无需审批）。需要 **owner** 权限。

**参数**：同 `group.resources.put`（`resource_type` 不能是 `"folder"`）。

**响应**：同 `group.resources.put`。

### group.resources.list_pending

列出待审批的资源申请。需要 **owner** 权限。

**参数**：`group_id` (string)

### group.resources.approve_request

批准资源申请。需要 **owner** 权限。

**参数**：`request_id` (string, 必填), `note` (string, 可选)

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "request": { ... },
    "resource": { ... }
}
```

### group.resources.reject_request

拒绝资源申请。需要 **owner** 权限。

**参数**：`request_id` (string, 必填), `note` (string, 可选)

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "request": { ... }
}
```

---

## 在线状态

### group.get_online_members

获取当前在线成员列表。

**参数**：`group_id` (string, 必填)

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "total": 2,
    "page": 1,
    "size": 200,
    "online_count": 2,
    "items": [
        {
            "aid": "alice.agentid.pub",
            "role": "owner",
            "joined_at": 1234567890,
            "online": true,
            "session_id": "sess_123",
            "last_active_at": 1234567890,
            "expire_at": 1234571490
        }
    ]
}
```

---

## 多设备游标

### group.pull_events

增量拉取群事件，支持多设备独立游标。

**参数**：

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `group_id` | string | 是 | — | 群组 ID |
| `device_id` | string | 否 | — | 设备 ID，多设备模式必填 |
| `device_name` | string | 否 | — | 设备名称（首次注册时使用） |
| `device_type` | string | 否 | — | 设备类型 |
| `after_event_seq` | integer | 否 | 游标位置 | 从该事件 seq 之后拉取；多设备模式下默认使用设备游标 |
| `limit` | integer | 否 | 100 | 最大条数（受 `pull_max_limit` 配置限制） |

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "events": [ ... ],
    "latest_event_seq": 100,
    "has_more": false,
    "limit": 100,
    "cursor": {
        "current_seq": 50,
        "join_seq": 0,
        "latest_seq": 100,
        "unread_count": 50
    }
}
```

> `cursor` 仅多设备模式（提供 `device_id`）时返回。响应大小受 `pull_max_response_bytes` 配置限制。包含 E2EE epoch 范围检查，不返回成员加入前的加密事件。

### group.ack_messages

确认消息游标（多设备模式）。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `device_id` | string | 是 | 设备 ID |
| `msg_seq` | integer | 是 | 确认到的消息序号 |

**响应**：`{ "cursor": 123 }`

> 不能确认加入位置之前的消息；序号自动截断到群组当前最大消息序号。

### group.ack_events

确认事件游标（多设备模式）。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `device_id` | string | 是 | 设备 ID |
| `event_seq` | integer | 是 | 确认到的事件序号 |

**响应**：`{ "cursor": 456 }`

### group.list_devices

列出当前用户在指定群组的所有设备及游标状态。

**参数**：`group_id` (必填)

**响应**：

```json
{
    "devices": [
        {
            "device_id": "device-123",
            "device_name": "My Phone",
            "device_type": "mobile",
            "last_pull_at": 1234567890000,
            "msg_unread": 10,
            "event_unread": 5
        }
    ]
}
```

### group.unregister_device

注销设备游标（清理不再使用的设备记录）。

**参数**：`group_id` (必填), `device_id` (必填)

**响应**：`{ "success": true }`

---

## 管理辅助

### group.get_admins

获取管理员列表（owner + admin 角色）。

**参数**：`group_id` (必填)

**响应**：

```json
{
    "admins": [
        {
            "aid": "alice.agentid.pub",
            "role": "owner",
            "member_type": "human",
            "joined_at": 1234567890
        }
    ]
}
```

### group.get_master

获取群主 AID。

**参数**：`group_id` (必填)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "owner_aid": "alice.agentid.pub" }`

### group.get_summary

获取群组综合统计摘要。

**参数**：`group_id` (必填)

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "name": "My Group",
    "owner_aid": "alice.agentid.pub",
    "status": "active",
    "visibility": "private",
    "member_count": 10,
    "human_count": 7,
    "ai_count": 3,
    "admin_count": 2,
    "online_count": 5,
    "message_seq": 1000,
    "event_seq": 2000,
    "e2ee_epoch": 3,
    "created_at": 1234567890,
    "updated_at": 1234567890
}
```

### group.get_metrics

获取群组性能指标，包含 E2EE epoch 范围记录。需要 **admin 及以上**权限。

**参数**：`group_id` (必填)

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "message_seq": 1000,
    "event_seq": 2000,
    "member_count": 10,
    "online_count": 5,
    "e2ee_epoch": 3,
    "epoch_count": 4,
    "epoch_ranges": [
        {
            "epoch": 0,
            "start_msg_seq": 0,
            "start_event_seq": 0,
            "end_msg_seq": 100,
            "end_event_seq": 200,
            "rotated_by": "alice.agentid.pub",
            "rotated_at": 1234567890
        }
    ]
}
```

### group.refresh_member_types

刷新成员类型分类统计。

**参数**：`group_id` (必填)

**响应**：

```json
{
    "group_id": "g-abc123.agentid.pub",
    "total": 10,
    "human_count": 7,
    "ai_count": 3,
    "members": [
        { "aid": "alice.agentid.pub", "role": "owner", "member_type": "human" }
    ]
}
```

---

## E2EE

### group.e2ee.rotate_epoch

CAS 轮换群组 E2EE Epoch。需要 **admin 及以上**权限。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群组 ID |
| `current_epoch` | integer | 是 | 当前 epoch 值（CAS 校验） |
| `rotation_signature` | string | 是 | 轮换签名（Base64，ECDSA SHA-256） |
| `rotation_timestamp` | string | 是 | 轮换时间戳（秒） |

**响应**：`{ "group_id": "g-abc123.agentid.pub", "success": true, "epoch": 4 }`

> 签名格式：`{group_id}|{current_epoch}|{new_epoch}|{aid}|{rotation_timestamp}`。时间戳必须在 5 分钟窗口内。签名去重防止重放攻击（10 分钟窗口）。

### group.e2ee.get_epoch

获取当前 E2EE Epoch 值。

**参数**：`group_id` (必填)

**响应**：`{ "group_id": "g-abc123.agentid.pub", "epoch": 3 }`

---

---

## 事件

### event/group.created

群组创建时推送。

**Payload**：

```json
{
    "module_id": "group",
    "group_id": "g-abc123.agentid.pub",
    "owner_aid": "alice.agentid.pub",
    "visibility": "private"
}
```

### event/group.changed

群组状态变化时推送。

**Payload**：

```json
{
    "module_id": "group",
    "action": "member_added",
    "group_id": "g-abc123.agentid.pub"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `module_id` | string | 固定 `"group"` |
| `action` | string | 变更类型（见下表） |
| `group_id` | string | 群组 ID |
| `request_id` | string | 可选，仅资源审批相关 action |
| `resource_path` | string | 可选，仅资源相关 action |

**action 取值**：

| action | 说明 |
|--------|------|
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
| `join_requirements_updated` | 入群要求更新 |
| `invite_code_created` | 邀请码创建 |
| `invite_code_used` | 邀请码使用 |
| `invite_code_revoked` | 邀请码撤销 |
| `member_banned` | 成员封禁 |
| `member_unbanned` | 成员解封 |
| `resource_put` | 资源上传 |
| `resource_updated` | 资源更新 |
| `resource_deleted` | 资源删除 |
| `resource_request_created` | 资源申请创建 |
| `resource_direct_added` | 资源直接添加 |
| `resource_request_approved` | 资源申请批准 |
| `resource_request_rejected` | 资源申请拒绝 |
| `suspended` | 群组暂停 |
| `resumed` | 群组恢复 |
| `dissolved` | 群组解散 |

**订阅**：

```python
client.on("group.changed", lambda ev: print(ev["action"]))
```

### event/group.message_created

群消息创建时推送给所有在线成员。支持两种模式：

**消息推送模式**（带 `payload`）：

```json
{
    "module_id": "group",
    "group_id": "g-abc123.agentid.pub",
    "seq": 42,
    "message_id": "uuid",
    "sender_aid": "alice.agentid.pub",
    "type": "e2ee.group_encrypted",
    "payload": { "type": "e2ee.group_encrypted", "..." : "..." },
    "dispatch": {"mode": "broadcast", "reason": "duty_disabled"},
    "kind": "group.broadcast",
    "member_aids": ["bob.agentid.pub"]
}
```

SDK 收到后自动解密 `payload`，解密后的明文消息直接交付用户回调。

**通知模式**（不带 `payload`）：

```json
{
    "module_id": "group",
    "group_id": "g-abc123.agentid.pub",
    "seq": 42,
    "message_id": "uuid",
    "sender_aid": "alice.agentid.pub",
    "type": "e2ee.group_encrypted",
    "dispatch": {"mode": "broadcast", "reason": "duty_disabled"}
}
```

SDK 收到后自动调用 `group.pull` 拉取最新消息并逐条解密后交付用户回调。

---

## 错误码

Group 服务定义了以下专用错误码（-33xxx 段）：

| 错误码 | 含义 | 客户端处理建议 |
|--------|------|---------------|
| -33001 | Group not found | 检查 group_id 是否正确 |
| -33002 | Group suspended | 等待恢复或联系管理员 |
| -33003 | Group closed | 不重试，群已解散 |
| -33004 | Already a member | 无需处理 |
| -33005 | Not a member | 需先加入群组 |
| -33006 | Invite code invalid or expired | 获取新邀请码 |
| -33007 | Join request pending | 等待审批，勿重复提交 |
| -33008 | Resource not found | 检查 resource_path |
| -33009 | Resource request not found | 检查 request_id |

> SDK 客户端将 -33001 映射为 `GroupNotFoundError`，-33002~-33003 映射为 `GroupStateError`，其余映射为 `GroupError`。未识别的错误码 fallback 到 `AUNError`。

