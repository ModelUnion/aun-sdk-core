# Group State Hash 设计方案

> 日期：2026-05-11
> 范围：将群组状态（成员角色、E2EE 策略等）纳入可验证的签名 commitment 体系

## 1. 问题

当前 `key_commitment` 只绑定成员 AID 列表，不包含角色、策略等关键群状态。
服务端可以在同一 epoch 内静默修改角色（admin → member），客户端无法检测。

同时，角色变更不需要轮换密钥（谁能读消息没变），但需要更新 commitment。
当前 epoch 推进 = 密钥轮换 = commitment 更新 三者耦合，无法满足这个需求。

## 2. 核心设计：双轨 commitment

### 2.1 两个独立维度

| 维度 | 推进条件 | 绑定内容 |
|------|---------|---------|
| `key_epoch` | 成员加入/离开/定时轮换 | group_secret + 成员列表 |
| `state_version` | 任何关键群状态变更 | 成员 + 角色 + 策略 + prev_state_hash |

### 2.2 key_commitment（现有，不改）

```
key_commitment = SHA-256(sorted_aids | key_epoch | group_id | SHA-256(secret))
```

用途：密钥分发时验证"这个密钥属于这批成员"。
推进时机：仅在 key_epoch 变更（密钥轮换）时。

### 2.3 state_hash（新增）

```
state_hash = SHA-256(
    group_id          | 0x00 |
    state_version     | 0x00 |    # uint64 big-endian 8 bytes
    key_epoch         | 0x00 |    # 绑定当前密钥代
    membership_block  | 0x00 |    # 成员+角色（见下）
    policy_block      | 0x00 |    # E2EE 策略配置
    prev_state_hash             # 32 bytes，链式
)
```

#### membership_block 构造

```
对每个成员按 AID 字典序排列：
    "{aid}:{role}"

用 "|" 拼接：
    "alice.aid.com:owner|bob.aid.com:admin|carol.aid.com:member"
```

#### policy_block 构造

```
JSON 规范化（key 字典序，无空格）：
    {"require_signature":true,"rotation_policy":"on_member_change"}
```

初始版本只包含以下策略字段：
- `require_signature`: bool — 是否要求消息签名
- `rotation_policy`: string — 轮换策略（"on_member_change" | "manual" | "scheduled"）

后续可扩展，新字段追加不影响旧 state_hash 的验证（各版本独立）。

## 3. 推进规则

| 操作 | key_epoch | state_version | 是否轮换密钥 | 流程 |
|------|-----------|---------------|-------------|------|
| add_member | +1 | +1 | 是 | rotation 两阶段 |
| kick_member | +1 | +1 | 是 | rotation 两阶段 |
| leave | +1 | +1 | 是 | rotation 两阶段 |
| change_role | 不变 | +1 | 否 | 轻量提交 |
| change_e2ee_policy | 不变 | +1 | 否 | 轻量提交 |
| 定时轮换 | +1 | +1 | 是 | rotation 两阶段 |

**关键约束**：`key_epoch` 变更时 `state_version` 必须同步 +1（密钥轮换隐含状态变更）。
反过来不成立：`state_version` 可以独立于 `key_epoch` 推进。

## 4. 轻量提交流程（无密钥轮换）

用于 change_role、change_e2ee_policy 等不需要轮换密钥的操作。

```
1. 发起方（admin/owner）执行操作（如 group.change_role）
2. 服务端校验权限 → 更新 group_members / group_settings
3. 服务端原子推进 state_version
4. 发起方计算新 state_hash（基于新状态 + prev_state_hash）
5. 发起方签名 state_commit：
   {
     "group_id": "grp_xxx",
     "state_version": 5,
     "key_epoch": 3,          // 当前 key_epoch，不变
     "state_hash": "...",
     "prev_state_hash": "...",
     "actor_aid": "alice",
     "reason": "change_role",
     "timestamp": 1234567890,
     "signature": "..."       // ECDSA
   }
6. 发起方调用 group.commit_state（新 RPC）提交签名
7. 服务端持久化 state_commit → 广播 event/group.state_committed 事件
8. 所有客户端收到事件 → 验证签名 + prev_state_hash 连续性 → 本地更新
```

### 与 rotation 两阶段的区别

| | rotation（密钥轮换） | 轻量提交（无密钥轮换） |
|---|---|---|
| 密钥分发 | 需要 P2P E2EE 分发 group_secret | 不需要 |
| ack 机制 | 需要 required_acks | 不需要 |
| lease 机制 | 需要（防卡住） | 不需要 |
| 服务端状态 | group_e2ee_rotations 表 | group_state_commits 表 |
| 客户端验证 | commitment + epoch_chain + manifest | state_hash + prev_state_hash + signature |
| 延迟 | 高（等 ack） | 低（单次 RPC + 广播） |

## 5. 服务端变更

### 5.1 groups 表新增字段

```sql
ALTER TABLE `groups` ADD COLUMN `state_version` BIGINT NOT NULL DEFAULT 0;
ALTER TABLE `groups` ADD COLUMN `state_hash` VARCHAR(128) NOT NULL DEFAULT '';
```

### 5.2 新增 group_state_commits 表

```sql
CREATE TABLE IF NOT EXISTS `group_state_commits` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `group_id` VARCHAR(128) NOT NULL,
    `state_version` BIGINT NOT NULL,
    `key_epoch` BIGINT NOT NULL COMMENT '提交时对应的 key_epoch',
    `state_hash` VARCHAR(128) NOT NULL,
    `prev_state_hash` VARCHAR(128) NOT NULL DEFAULT '',
    `actor_aid` VARCHAR(255) NOT NULL,
    `reason` VARCHAR(64) NOT NULL DEFAULT '',
    `membership_snapshot` TEXT NOT NULL COMMENT 'JSON: [{aid, role}, ...]',
    `policy_snapshot` TEXT NOT NULL DEFAULT '' COMMENT 'JSON: 策略快照',
    `signature` TEXT NOT NULL DEFAULT '',
    `committed_at` BIGINT NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_group_state_version` (`group_id`, `state_version`),
    KEY `idx_group_latest` (`group_id`, `state_version` DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### 5.3 新增 RPC

```
group.commit_state
  params: { group_id, state_version, key_epoch, state_hash, prev_state_hash, actor_aid, reason, signature }
  校验：
    - actor 是 admin/owner
    - state_version == groups.state_version + 1
    - key_epoch == groups.e2ee_epoch（防止 stale 提交）
    - prev_state_hash == groups.state_hash（链连续性）
  行为：
    - 原子推进 groups.state_version 和 groups.state_hash
    - 插入 group_state_commits 记录
    - 广播 event/group.state_committed

group.get_state
  params: { group_id }
  返回：{ state_version, state_hash, key_epoch, latest_commit }
```

### 5.4 rotation 两阶段的联动

`commit_e2ee_rotation` 时自动推进 state_version：

```
commit_e2ee_rotation 内部追加：
  1. state_version = groups.state_version + 1
  2. 计算新 state_hash（使用 rotation 后的成员+角色）
  3. 插入 group_state_commits（reason = rotation.reason）
  4. 更新 groups.state_version 和 groups.state_hash
```

这样密钥轮换自动生成 state_commit，不需要客户端额外调用。

## 6. 客户端存储变更

### 6.1 当前存储结构

```sql
-- group_current / group_old_epochs 的 data JSON
{
  "commitment": "...",
  "member_aids": [...],
  "epoch_chain": "...",
  "pending_rotation_id": "...",
  "epoch_chain_unverified": false,
  "epoch_chain_unverified_reason": null
}
```

### 6.2 新增存储

**不改现有 group_current / group_old_epochs 表。** 新增一张本地表：

```sql
CREATE TABLE IF NOT EXISTS group_state (
    group_id TEXT PRIMARY KEY,
    state_version INTEGER NOT NULL DEFAULT 0,
    state_hash TEXT NOT NULL DEFAULT '',
    key_epoch INTEGER NOT NULL DEFAULT 0,
    membership_json TEXT NOT NULL DEFAULT '',   -- [{aid, role}, ...]
    policy_json TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL DEFAULT 0
);
```

理由：
- state_version 与 key_epoch 生命周期不同，不应塞进 epoch 存储
- state 是 per-group 的（不是 per-epoch 的），一个群只有一个当前 state
- 历史 state 不需要客户端保留（服务端 group_state_commits 表有完整历史）
- 新表不影响现有密钥存储和加解密流程

### 6.3 客户端处理流程

**收到 event/group.state_committed 时：**

```python
def handle_state_committed(event):
    commit = event["data"]

    # 1. 验证签名
    if not verify_state_commit_signature(commit, actor_cert):
        log.warning("state_commit 签名无效")
        return

    # 2. 验证 prev_state_hash 连续性
    local_state = load_group_state(group_id)
    if local_state and local_state.state_hash != commit["prev_state_hash"]:
        log.warning("state_hash 链不连续，可能错过了中间变更")
        # 回源查询服务端最新状态
        sync_group_state_from_server(group_id)
        return

    # 3. 本地重算 state_hash 验证
    computed = compute_state_hash(
        group_id, commit["state_version"], commit["key_epoch"],
        commit["membership_snapshot"], commit["policy_snapshot"],
        commit["prev_state_hash"],
    )
    if computed != commit["state_hash"]:
        log.warning("state_hash 重算不匹配")
        return

    # 4. 更新本地 group_state 表
    save_group_state(group_id, commit)
```

**发送群消息前（可选增强）：**

```python
# AAD 可选绑定 state_version
aad = f"{group_id}|{from_aid}|{msg_id}|{key_epoch}|{state_version}|{suite}"
```

绑定 state_version 到 AAD 后，接收方可检测"发送时的群状态"是否与本地一致。
不一致不阻塞解密，但可提示用户"此消息发送时群状态可能已变更"。

**首次 lazy sync 时追加查询：**

```python
# 现有: group.e2ee.get_epoch
# 新增: group.get_state
state = await call("group.get_state", {"group_id": group_id})
save_group_state(group_id, state)
```

## 7. 迁移策略

### 7.1 服务端

1. `groups` 表加 `state_version`、`state_hash` 字段（通过 _ensure_column，默认值 0/""）
2. 创建 `group_state_commits` 表
3. 新增 `group.commit_state` 和 `group.get_state` RPC
4. `commit_e2ee_rotation` 内部自动推进 state_version
5. 存量群组 state_version=0, state_hash="" — 首次操作时初始化

### 7.2 客户端

1. keystore 新增 `group_state` 表（通过 _ensure_table 自动创建）
2. 新增 `compute_state_hash`、`verify_state_commit_signature` 函数
3. 订阅 `event/group.state_committed` 事件
4. lazy sync 时追加 `group.get_state` 查询
5. 发送时 AAD 可选绑定 state_version（后续版本）

### 7.3 兼容性

- 旧客户端不理解 state_version → 忽略 event/group.state_committed 事件，不影响消息收发
- 旧客户端发送的消息不绑定 state_version → 新客户端正常解密
- 服务端 state_version=0 表示未初始化 → 客户端跳过 state_hash 校验

## 8. 安全分析

| 攻击场景 | 当前（无 state_hash） | 有 state_hash 后 |
|---------|---------------------|-----------------|
| 服务端偷改角色 | 不可检测 | state_hash 链断裂，客户端告警 |
| 服务端偷改策略 | 不可检测 | 同上 |
| 服务端回滚 state | 不可检测 | prev_state_hash 链校验失败 |
| 幽灵 state_version | 不可检测 | 签名校验失败（需要 admin 私钥） |
| 跳过中间变更 | 不可检测 | 客户端发现 state_version 不连续 → 回源 |

## 9. 不做什么

- **不改 key_commitment** — 现有密钥分发流程不受影响
- **不改消息加解密** — state_version 不参与密钥派生
- **不要求所有成员 ack state_commit** — 轻量提交，不等 ack
- **不在客户端保留 state 历史** — 服务端有完整记录，客户端只保留最新
- **不阻塞解密** — state_version 不匹配时只告警，不拒绝解密
