# 协作 — RPC Manual

> collab 层是「锚定在某块存储上的自包含版本化目录」。每个协作文档有独立版本线（`<doc>@current` 软链 + 台账），整目录有标签线（公开 API 为 `collab.tag.*`；内部仍使用 `@snapshot` 软链和 `.collab-snapshots/` manifest）。
>
> **服务端编排**：collab 编排已并入 storage 服务进程，`collab.*` RPC handler 与 `storage.*` 并列注册。collab handler 以调用者身份（Gateway 注入的 `_auth.aid`）直调 storage 原语，无特权通道。
>
> **授权 = 协作根写 ACL**：谁能 `commit` = 谁对 `collab_root` 有写权限。普通 AID storage 可继续用 `storage.set_acl/remove_acl` 管理写授权；群 `memberdata` 协作根必须用 `collab.set_acl/remove_acl` 按 `collab_root` 授权，SDK/CLI 不得拼接真实 `group_data` 路径。
>
> SDK 侧通过 `client.collab` 访问（`CollabClient`），每个命令 1:1 映射一条 `collab.*` RPC。

## 方法索引

### 文档版本线

| 方法 | 说明 |
|------|------|
| [collab.ls-files](#collabls-files) | 列出协作根下所有文档 |
| [collab.create](#collabcreate) | 创建协作文档（首版本） |
| [collab.show](#collabshow) | 读当前或指定版本内容 |
| [collab.commit](#collabcommit) | 提交新版本（乐观锁 CAS） |
| [collab.merge](#collabmerge) | 三方合并（服务端 diff3） |
| [collab.log](#collablog) | 查版本台账 |
| [collab.diff](#collabdiff) | 比较两版本 |
| [collab.revert](#collabrevert) | 以历史版本内容提交一个新版本 |
| [collab.prune](#collabprune) | 清理某文档的历史版本文件 |

### 运维、备份与迁移

| 方法 | 说明 |
|------|------|
| [collab.gc](#collabgc) | 扫描不可达版本文件并可选删除 |
| [collab.reflog](#collabreflog) | 查看协作审计日志 |
| [collab.clone](#collabclone) | 深拷贝整个协作到新位置（可选 reroot） |

### 目录级标签（Tag）

| 方法 | 说明 |
|------|------|
| [collab.tag.create](#collabtag.create) | 打目录标签（语义化版本） |
| [collab.tag.list](#collabtag.list) | 列出标签 |
| [collab.tag.show](#collabtag.show) | 查看标签详情 |
| [collab.tag.diff](#collabtag.diff) | 比较两标签 |
| [collab.tag.restore](#collabtag.restore) | 回滚到某标签（forward-only） |
| [collab.tag.rm](#collabtag.rm) | 删除单个标签 |
| [collab.tag.prune](#collabtag.prune) | 批量清理旧标签 |

### 群内发现

| 方法 | 说明 |
|------|------|
| [collab.ls-remote](#collabls-remote) | 列出群内已登记的协作根 |
| [collab.unregister](#collabunregister) | 注销注册表中的协作根条目 |
| [collab.set_acl](#collabset_acl) | owner 授予具体 AID 对协作根的写权限 |
| [collab.remove_acl](#collabremove_acl) | owner 撤销具体 AID 对协作根的写权限 |

---

## 核心概念

### 协作根目录结构

```
<aid>:<collab_root>/
├── .collab                    ← 发现锚点（YAML frontmatter: name/authority/root）
├── <doc>@current              ← 软链 → .collab-versions/<doc>/<author>/vN
├── <doc>@ledger               ← 版本台账
├── @snapshot                  ← 标签头软链 → .collab-snapshots/<semver>.json
├── .collab-versions/<doc>/<author>/v1…vN   ← 不可变版本文件（write-once）
└── .collab-snapshots/<semver>.json         ← 不可变标签 manifest
```

- **`collab_root` 参数格式**：`<aid>:<path>`（如 `alice.aid.pub:/projects/myapp`），来自 `.collab` 文件的 `root` 字段或上层响应。
- **响应一律回吐相对 `collab_root` 的内部 target 拼成的绝对 `<aid>:<path>`**——agent 原样用于下一条命令，无需拼接。

### 乐观锁（commit）

1. `put_object`（写新版本文件，永不失败，数据先存下）。
2. 同一事务：`atomic_repoint(<doc>@current, new_target, expected_version=onto)` + 台账追加。
3. CAS 成功 → version+1；CAS 失败 → 整事务回滚，返回 `{ok:false, current_version, hint}`。

`onto` 来源：`collab.show` 响应的 `version` 字段；merge 后用 commit 失败响应的 `current_version`。

### 数据不变量

- 版本文件写一次永不覆盖；删指针不删数据。
- 回滚是 **forward-only**：restore 不回退 version 计数器，而是以旧内容写新版本，保证 version 单调递增。

---

## collab.ls-files

列出协作根下所有协作文档（含当前 version）。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |

### 响应

返回文档数组，每项：

| 字段 | 类型 | 说明 |
|------|------|------|
| `doc` | string | 文档当前显示名 |
| `version` | integer | 当前版本号 |
| `author` | string | 最新版本作者 AID |
| `current_target` | string | 当前版本文件绝对路径 `<aid>:<path>` |

### 示例

```python
docs = await client.collab.ls_files("alice.aid.pub:/projects/myapp")
```

---

## collab.create

创建协作文档，写入首版本（version=1）。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `doc` | string | 是 | 文档名 |
| `source` | string | 是 | 初始内容：本地文件路径或 `<aid>:<path>` |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `version` | integer | 固定为 `1` |
| `current_target` | string | 版本文件绝对路径 |

---

## collab.show

读取文档当前内容或指定历史版本内容。`rev` 为空时返回当前版本；`rev` 有值时返回该历史版本。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `doc` | string | 是 | 文档名 |
| `rev` | integer | 否 | 指定历史版本号；不传则读取当前版本 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `content` | string | base64 编码的当前内容 |
| `version` | integer | 当前或指定版本号（**commit 的 onto 来源**） |
| `author` | string | 当前版本作者 AID |
| `anchor` | string | 台账锚点（读取历史版本时返回） |
| `current_target` | string | 当前版本文件绝对路径（读取当前版本时返回） |

---

## collab.commit

提交新版本，乐观锁 CAS 切换 `@current`。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `doc` | string | 是 | 文档名 |
| `source` | string | 是 | 新内容：本地路径或 `<aid>:<path>` |
| `onto` | integer | 是 | 基线版本号（来自 `collab.show` 的 `version`） |

### 响应

**成功**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `ok` | boolean | `true` |
| `version` | integer | 新版本号（onto+1） |
| `current_target` | string | 新版本文件绝对路径 |

**撞版本失败**（数据已安全保存，需 merge 后重提）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `ok` | boolean | `false` |
| `current_version` | integer | 当前权威版本号（**merge 后 commit 用此作新 onto**） |
| `current_target` | string | 当前权威版本文件绝对路径 |
| `hint` | string | 后端格式化好的下一步命令行字符串 |

### 示例

```python
cur = await client.collab.show(root, "design.md")
res = await client.collab.commit(root, "design.md", "./design.md", cur["version"])
if not res["ok"]:
    await client.collab.merge(root, "design.md", "./design.md", cur["version"])
    res = await client.collab.commit(root, "design.md", "./design.md", res["current_version"])
```

---

## collab.merge

三方合并（服务端 diff3，四语言 SDK 不实现 diff3）。合并 base 版本、本地 source、当前 `@current` 三方内容。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `doc` | string | 是 | 文档名 |
| `source` | string | 是 | 本地草稿内容（ours）：本地路径或 `<aid>:<path>` |
| `onto` | integer | 是 | 共同祖先版本号 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `content` | string | base64 编码的合并结果 |
| `conflicts` | boolean | 是否含冲突标记（`<<<<<<<` / `=======` / `>>>>>>>`） |

`conflicts=true` 时需人工编辑消解冲突后再 commit。

---

## collab.log

查文档版本台账。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `doc` | string | 是 | 文档名（按物理目录名索引，改显示名后仍按原名查） |

### 响应

返回版本数组，每项 `{version, author, target, time}`，`target` 为完整 `<aid>:<path>`。

---

## collab.diff

比较同一文档的两个版本，返回 unified diff 文本。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `doc` | string | 是 | 文档名 |
| `from` | integer | 是 | 起始版本号（SDK 形参 `v_from`） |
| `to` | integer | 是 | 目标版本号（SDK 形参 `v_to`） |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `diff` | string | unified diff 文本 |

---

## collab.revert

以指定历史版本的内容提交一个新版本。revert 不回退版本号，也不直接改写历史文件；它读取目标版本内容，以当前版本为 `onto` 再走普通 `commit` 流程，因此仍保持 forward-only 不变量。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `collab_root` | string | 是 | — | 协作根 `<aid>:<path>` |
| `doc` | string | 是 | — | 文档名 |
| `rev` | integer | 是 | — | 要恢复内容的历史版本号 |
| `message` | string | 否 | `""` | 记录到台账/审计日志的说明 |

### 响应

返回普通 `collab.commit` 的响应字段；如果当前版本已经等于目标版本，返回包含 `no_change: true` 的结果。

---

## collab.prune

清理某文档的历史版本文件（保留台账与当前版本，回收旧 blob）。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `doc` | string | 是 | 文档名 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `pruned` | integer | 清理的版本文件数 |

---

## collab.gc

目录级垃圾扫描。服务端会扫描 `.collab-versions`，从台账、当前指针和标签 manifest 标记可达版本文件；未被引用的版本文件计为 garbage。默认 `dry_run=true` 只返回统计，不删除。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `collab_root` | string | 是 | — | 协作根 `<aid>:<path>` |
| `dry_run` | boolean | 否 | `true` | 只扫描不删除 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `scanned` | integer | 扫描到的版本文件数 |
| `reachable` | integer | 可达版本文件数 |
| `garbage` | integer | 不可达版本文件数 |
| `deleted` | integer | 实际删除数量；`dry_run=true` 时为 0 |
| `freed_bytes` | integer | 实际释放字节数 |

---

## collab.reflog

读取协作审计日志，用于排查 commit/merge/revert/tag 等操作历史。可按文档过滤并限制条数。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `collab_root` | string | 是 | — | 协作根 `<aid>:<path>` |
| `doc` | string | 否 | — | 仅查看某个文档的日志 |
| `limit` | integer | 否 | `100` | 返回条数上限 |

### 响应

返回日志数组，每项包含 `seq`、`action`、`requester`、`doc`、`version`、`onto`、`target`、`status`、`error_code`、`error_msg`、`metadata`、`timestamp` 等字段。

---

## collab.clone

克隆整个协作到新位置。默认 `reroot=false` 时做纯子树拷贝（用于备份）；`reroot=true` 时在目标根重建并让目标 owner 成为新授权方（用于迁移 / 换主理人）。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `src` | string | 是 | 源协作根 `<aid>:<path>` |
| `dest` | string | 是 | 目标路径 `<aid>:<path>` |
| `reroot` | boolean | 否 | 默认 `false`；`true` 表示重建 root 和授权方 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `ok` | boolean | `true` |
| `dest` | string | 目标路径 |
| `copied_objects` | integer | 拷贝的对象数 |
| `new_root` | string | `reroot=true` 时的新协作根 |
| `new_authority_aid` | string | `reroot=true` 时的新授权方 AID（= dest 存储 owner） |

> collabRoot 整体改名/迁移用 `collab.clone(..., reroot=true)`，不要用 `storage.fs.rename`：后者在对象存储上可能是 O(n) copy+delete，且会让 `.collab` 的 `root` 字段失效。

---

## collab.tag.create

打目录级标签。语义化版本自动判定：doc 集合变化 → minor；仅内容变化 → patch；`major=true` 强制 major；无变化 → 报错。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `collab_root` | string | 是 | — | 协作根 `<aid>:<path>` |
| `message` | string | 否 | `""` | 标签说明 |
| `major` | boolean | 否 | `false` | 强制 major bump |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `version` | string | 新标签语义化版本（如 `2.3.1`） |
| `bump` | string | 本次 bump 级别（`major`/`minor`/`patch`） |
| `changed` | array | 变化的文档名列表 |

---

## collab.tag.list

列出所有标签。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |

### 响应

返回标签数组，每项 `{version, message, created_at, ...}`，按语义化版本升序。

---

## collab.tag.show

查看单个标签详情（含文档清单 entries）。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `version` | string | 是 | 标签版本（如 `2.3.1`） |

### 响应

标签 manifest，含 `collab_root`、`version` 与 `entries`（每项含 `doc`/`version`/`current_target` 绝对路径）。

---

## collab.tag.diff

比较两标签的文档版本差异。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `version_a` | string | 是 | 标签 A 版本 |
| `version_b` | string | 是 | 标签 B 版本 |

### 响应

返回新增/删除/版本变化的文档清单。

---

## collab.tag.restore

回滚到某标签。**forward-only**：不回退 version 计数器，而是对每个文档以标签中的旧内容写一个新版本（vN+1），最后以回滚后状态自动创建新标签。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `collab_root` | string | 是 | — | 协作根 `<aid>:<path>` |
| `version` | string | 是 | — | 要回滚到的标签版本 |
| `message` | string | 否 | `""` | 回滚说明 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `restored_from` | string | 回滚来源标签版本 |
| `new_snapshot_version` | string | 回滚后自动创建的新标签版本（历史字段名保留为 `new_snapshot_version`） |
| `warnings` | array | 回滚过程中的告警（如某文档被他人并发提交而跳过） |

---

## collab.tag.rm

删除单个标签。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `version` | string | 是 | 要删除的标签版本 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `ok` | boolean | `true` |

---

## collab.tag.prune

批量清理旧标签。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `before` | integer\|string | 否 | 清理此时间点之前的标签 |
| `keep_last` | integer | 否 | 保留最近 N 个标签 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `pruned` | integer | 清理的标签数 |

---

## collab.ls-remote

列出群内已登记的协作根（群 owner 优先查 `collab_registry`，免 O(n) 全树扇出）。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_aid` | string | 是 | 群 AID |

### 响应

返回协作根数组，每项含 `collab_root` 等登记信息。

---

## collab.unregister

注销注册表中的协作根条目（不删数据，仅去登记）。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_aid` | string | 是 | 群 AID |
| `collab_root` | string | 是 | 要注销的协作根 `<aid>:<path>` |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `ok` | boolean | `true` |

---

## collab.set_acl

授予具体 AID 对协作根的写权限。调用者必须是协作根真实 storage owner。对 `group_aid:/memberdata/{aid}/...` 根，服务端内部映射到成员 storage 的 `group_data/{group_aid}`，但调用参数仍只使用 `collab_root`。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `grantee_aid` | string | 是 | 被授权 AID；不支持 `role:*` |
| `perms` | string | 否 | 权限位，默认 `w` |
| `expires_at` | integer | 否 | 过期时间戳 |
| `max_uses` | integer | 否 | 最大使用次数 |

---

## collab.remove_acl

撤销具体 AID 对协作根的写权限。调用者必须是协作根真实 storage owner。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `grantee_aid` | string | 是 | 被撤销 AID |

---

## 错误码

| code | 说明 |
|------|------|
| -32002 | 服务暂不可用（数据库未连接） |
| -32004 | 权限拒绝（requester 对 collab_root 无写权限） |
| -32008 | 协作文档 / 版本 / 标签不存在 |
| -32009 | 版本冲突（commit 撞版本，见 `ok:false` 响应；tag create 时标签头已移动） |
| -32000 | 通用错误（参数校验失败、源内容读取失败、无变更可打标签等） |
