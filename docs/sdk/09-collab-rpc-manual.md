# 协作 — RPC Manual

> collab 层是「锚定在某块存储上的自包含版本化目录」。每个协作文档有独立版本线（`<doc>@current` 软链 + 台账），整目录有快照线（`@snapshot` 软链）。
>
> **服务端编排**：collab 编排已并入 storage 服务进程，`collab.*` RPC handler 与 `storage.*` 并列注册。collab handler 以调用者身份（Gateway 注入的 `_auth.aid`）直调 storage 原语，无特权通道。
>
> **授权 = 存储 ACL**：谁能 `submit` = 谁对 `collab_root` 有写权限（`storage.set_acl`）。无独立发起人特权。
>
> SDK 侧通过 `client.collab` 访问（`CollabClient`），每个命令 1:1 映射一条 `collab.*` RPC。

## 方法索引

### 文档版本线

| 方法 | 说明 |
|------|------|
| [collab.ls](#collabls) | 列出协作根下所有文档 |
| [collab.create](#collabcreate) | 创建协作文档（首版本） |
| [collab.read](#collabread) | 读当前内容 + version |
| [collab.submit](#collabsubmit) | 提交新版本（乐观锁 CAS） |
| [collab.merge](#collabmerge) | 三方合并（服务端 diff3） |
| [collab.history](#collabhistory) | 查版本台账 |
| [collab.get](#collabget) | 读指定历史版本 |
| [collab.diff](#collabdiff) | 比较两版本 |
| [collab.prune](#collabprune) | 清理某文档的历史版本文件 |

### 备份与迁移

| 方法 | 说明 |
|------|------|
| [collab.export](#collabexport) | 深拷贝整个协作到新位置 |
| [collab.adopt](#collabadopt) | 换 host 重建协作（迁移） |

### 目录级快照

| 方法 | 说明 |
|------|------|
| [collab.snapshot.create](#collabsnapshotcreate) | 打目录快照（语义化版本） |
| [collab.snapshot.list](#collabsnapshotlist) | 列出快照 |
| [collab.snapshot.show](#collabsnapshotshow) | 查看快照详情 |
| [collab.snapshot.diff](#collabsnapshotdiff) | 比较两快照 |
| [collab.snapshot.restore](#collabsnapshotrestore) | 回滚到某快照（forward-only） |
| [collab.snapshot.rm](#collabsnapshotrm) | 删除单个快照 |
| [collab.snapshot.prune](#collabsnapshotprune) | 批量清理旧快照 |

### 群内发现

| 方法 | 说明 |
|------|------|
| [collab.discover](#collabdiscover) | 列出群内已登记的协作根 |
| [collab.unregister](#collabunregister) | 注销注册表中的协作根条目 |

---

## 核心概念

### 协作根目录结构

```
<aid>:<collab_root>/
├── .collab                    ← 发现锚点（YAML frontmatter: name/authority/root）
├── <doc>@current              ← 软链 → .collab-versions/<doc>/<author>/vN
├── <doc>@ledger               ← 版本台账
├── @snapshot                  ← 软链 → .collab-snapshots/<semver>.json
├── .collab-versions/<doc>/<author>/v1…vN   ← 不可变版本文件（write-once）
└── .collab-snapshots/<semver>.json         ← 不可变快照 manifest
```

- **`collab_root` 参数格式**：`<aid>:<path>`（如 `alice.aid.pub:/projects/myapp`），来自 `.collab` 文件的 `root` 字段或上层响应。
- **响应一律回吐相对 `collab_root` 的内部 target 拼成的绝对 `<aid>:<path>`**——agent 原样用于下一条命令，无需拼接。

### 乐观锁（submit）

1. `put_object`（写新版本文件，永不失败，数据先存下）。
2. 同一事务：`atomic_repoint(<doc>@current, new_target, expected_version=base_version)` + 台账追加。
3. CAS 成功 → version+1；CAS 失败 → 整事务回滚，返回 `{ok:false, current_version, hint}`。

`base_version` 来源：`collab.read` 响应的 `version` 字段；merge 后用 submit 失败响应的 `current_version`。

### 数据不变量

- 版本文件写一次永不覆盖；删指针不删数据。
- 回滚是 **forward-only**：restore 不回退 version 计数器，而是以旧内容写新版本，保证 version 单调递增。

---

## collab.ls

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
docs = await client.collab.ls("alice.aid.pub:/projects/myapp")
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

## collab.read

读取文档当前内容 + version 号。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `doc` | string | 是 | 文档名 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `content` | string | base64 编码的当前内容 |
| `version` | integer | 当前版本号（**submit 的 base_version 来源**） |
| `author` | string | 当前版本作者 AID |
| `current_target` | string | 当前版本文件绝对路径 |

---

## collab.submit

提交新版本，乐观锁 CAS 切换 `@current`。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `doc` | string | 是 | 文档名 |
| `source` | string | 是 | 新内容：本地路径或 `<aid>:<path>` |
| `base_version` | integer | 是 | 基线版本号（来自 `collab.read` 的 `version`） |

### 响应

**成功**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `ok` | boolean | `true` |
| `version` | integer | 新版本号（base_version+1） |
| `current_target` | string | 新版本文件绝对路径 |

**撞版本失败**（数据已安全保存，需 merge 后重提）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `ok` | boolean | `false` |
| `current_version` | integer | 当前权威版本号（**merge 后 submit 用此作新 base_version**） |
| `current_target` | string | 当前权威版本文件绝对路径 |
| `hint` | string | 后端格式化好的下一步命令行字符串 |

### 示例

```python
cur = await client.collab.read(root, "design.md")
res = await client.collab.submit(root, "design.md", "./design.md", cur["version"])
if not res["ok"]:
    await client.collab.merge(root, "design.md", "./design.md", cur["version"])
    res = await client.collab.submit(root, "design.md", "./design.md", res["current_version"])
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
| `base_version` | integer | 是 | 共同祖先版本号 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `content` | string | base64 编码的合并结果 |
| `conflicts` | boolean | 是否含冲突标记（`<<<<<<<` / `=======` / `>>>>>>>`） |

`conflicts=true` 时需人工编辑消解冲突后再 submit。

---

## collab.history

查文档版本台账。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `doc` | string | 是 | 文档名（按物理目录名索引，改显示名后仍按原名查） |

### 响应

返回版本数组，每项 `{version, author, target, time}`，`target` 为完整 `<aid>:<path>`。

---

## collab.get

读指定历史版本内容。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `doc` | string | 是 | 文档名 |
| `version` | integer | 是 | 版本号（来自 `collab.history`） |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `content` | string | base64 编码内容 |
| `version` | integer | 版本号 |
| `author` | string | 该版本作者 AID |
| `anchor` | string | 台账锚点（物理目录名） |

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

## collab.export

深拷贝整个协作（所有版本文件 + 台账 + 快照）到新位置，用于备份。因内部 target 相对化，export 是纯子树拷贝。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 源协作根 `<aid>:<path>` |
| `dest` | string | 是 | 目标路径 `<aid>:<path>` |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `ok` | boolean | `true` |
| `dest` | string | 目标路径 |
| `copied_objects` | integer | 拷贝的对象数 |

---

## collab.adopt

换 host 重建协作：在 `new_root` 重建，`new_root` 所在存储 owner 成为新授权方（authority）。用于迁移整个协作（换位置 / 换主理人）。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `src` | string | 是 | 源（通常是 export 产物）`<aid>:<path>` |
| `new_root` | string | 是 | 新协作根 `<aid>:<path>` |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `ok` | boolean | `true` |
| `new_root` | string | 新协作根 |
| `new_authority_aid` | string | 新授权方 AID（= new_root 存储 owner） |

> collabRoot 整体改名/迁移用 `adopt`，**不要用 `storage.fs.rename`**——后者在对象存储上是 O(n) copy+delete，且会让 `.collab` 的 `root` 绝对字段失效。

---

## collab.snapshot.create

打目录级快照。语义化版本自动判定：doc 集合变化 → minor；仅内容变化 → patch；`major=true` 强制 major；无变化 → 报错。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `collab_root` | string | 是 | — | 协作根 `<aid>:<path>` |
| `message` | string | 否 | `""` | 快照说明 |
| `major` | boolean | 否 | `false` | 强制 major bump |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `version` | string | 新快照语义化版本（如 `2.3.1`） |
| `bump` | string | 本次 bump 级别（`major`/`minor`/`patch`） |
| `changed` | array | 变化的文档名列表 |

---

## collab.snapshot.list

列出所有快照。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |

### 响应

返回快照数组，每项 `{version, message, created_at, ...}`，按语义化版本升序。

---

## collab.snapshot.show

查看单个快照详情（含文档清单 entries）。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `version` | string | 是 | 快照版本（如 `2.3.1`） |

### 响应

快照 manifest，含 `collab_root`、`version` 与 `entries`（每项含 `doc`/`version`/`current_target` 绝对路径）。

---

## collab.snapshot.diff

比较两快照的文档版本差异。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `version_a` | string | 是 | 快照 A 版本 |
| `version_b` | string | 是 | 快照 B 版本 |

### 响应

返回新增/删除/版本变化的文档清单。

---

## collab.snapshot.restore

回滚到某快照。**forward-only**：不回退 version 计数器，而是对每个文档以快照中的旧内容写一个新版本（vN+1），最后以回滚后状态自动创建新快照。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `collab_root` | string | 是 | — | 协作根 `<aid>:<path>` |
| `version` | string | 是 | — | 要回滚到的快照版本 |
| `message` | string | 否 | `""` | 回滚说明 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `restored_from` | string | 回滚来源快照版本 |
| `new_snapshot_version` | string | 回滚后自动创建的新快照版本 |
| `warnings` | array | 回滚过程中的告警（如某文档被他人并发提交而跳过） |

---

## collab.snapshot.rm

删除单个快照。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `version` | string | 是 | 要删除的快照版本 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `ok` | boolean | `true` |

---

## collab.snapshot.prune

批量清理旧快照。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `collab_root` | string | 是 | 协作根 `<aid>:<path>` |
| `before` | integer\|string | 否 | 清理此时间点之前的快照 |
| `keep_last` | integer | 否 | 保留最近 N 个快照 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `pruned` | integer | 清理的快照数 |

---

## collab.discover

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

## 错误码

| code | 说明 |
|------|------|
| -32002 | 服务暂不可用（数据库未连接） |
| -32004 | 权限拒绝（requester 对 collab_root 无写权限） |
| -32008 | 协作文档 / 版本 / 快照不存在 |
| -32009 | 版本冲突（submit 撞版本，见 `ok:false` 响应；snapshot create 时快照头已移动） |
| -32000 | 通用错误（参数校验失败、源内容读取失败、无变更可快照等） |
