# AID 和 Group ID 格式校验实现 (2026-06-18)

## 背景

发现测试环境中 SDK 发送的目标对象（AID 和 Group ID）存在完全不合法的格式（如 `__system__`），这些非法格式应该在客户端早期拦截，避免发送到服务端。

## 问题

1. SDK 没有在关键发送接口进行格式校验
2. 文档中的 Group ID 格式描述与实际代码不一致

## 解决方案

### 1. 修正文档

**原文档错误**（`docs/protocol/10-Group-子协议.md`）：
- 声称 Group ID slug 为 4-14 位小写字母数字
- 声称总长度 6-16 字符

**实际格式**（基于服务端代码 `extensions/services/group/service.py`）：
- **Legacy 格式**: `g-[a-z0-9]{4,32}` — 4 到 32 位
- **新格式**: `[a-z0-9]{5,}` — 5 位或更多，无上限
- **Group name 格式**: `[a-z0-9][a-z0-9_-]{3,63}` — 4 到 64 个字符

已更新文档以反映实际实现。

### 2. Python SDK 实现

#### 新增模块
- `python/src/aun_core/validators.py`
  - `validate_aid_format(aid, *, param_name="aid") -> str`
  - `validate_group_id_format(group_id, *, param_name="group_id") -> str`

#### 集成位置
- `python/src/aun_core/_client/rpc_pipeline.py` (`validate_outbound_call` 方法)
  - `message.send` → 校验 `to` (AID)
  - `group.send` → 校验 `group_id`
  - `message.thought.put` → 校验 `to` (AID)
  - `message.thought.get` → 校验 `sender_aid` (AID)
  - `group.thought.put` → 校验 `group_id`
  - `group.thought.get` → 校验 `sender_aid` (AID) 和 `group_id`

- `python/src/aun_core/client.py` (`notify` 方法)
  - 校验 `to` (AID)
  - 校验 `group_id`

#### 测试
- `python/tests/unit/test_validators.py` — 26 个测试用例
- 所有单元测试通过（1058 个）

### 3. Go/TypeScript/JavaScript SDK 实现

四个 SDK 全部在 **pipeline 层**（`validateOutboundCall` / `validate_outbound_call`）集成校验，确保 `client.call(...)` 直接调用也无法绕过：

| SDK | 校验器文件 | 集成点 | 测试结果 |
|-----|-----------|--------|---------|
| Python | `python/src/aun_core/validators.py` | `_client/rpc_pipeline.py` + `client.py` notify | 1058 单测通过 |
| Go | `go/validators.go` | `client_rpc_pipeline.go` + `client.go` Notify | 全部通过 |
| TypeScript | `ts/src/validators.ts` | `client/rpc-pipeline.ts` + `client.ts` notify | 582 单测通过 |
| JavaScript | `js/src/validators.ts` | `client/rpc-pipeline.ts` + `client.ts` notify | 599 单测通过 |

**注意**：TS SDK 最初由 workflow 放在 facade 层（`facades.ts`），存在被 `client.call()` 绕过的风险，已修正为 pipeline 层（与其他三个 SDK 对齐）。facade 层保留了冗余的早期校验。

**测试夹具修正**：四个 SDK 的测试中存在不合法的占位标识符（如 `bob.*` name 仅 3 字符、`g1`/`g-1` group base 过短），已统一改为合法形式（`bob1.*`、`grp01`、`g-test1`），并同步更新对应的 seq-tracker namespace（`group:g1` → `group:grp01`）。

## AID 格式规范

```
{name}.{issuer}
```

- **name**: 4-64 字节，仅 `[a-z0-9_-]`，首字符不能是 `-`，不能以 `guest` 开头
- **issuer**: 合法的可注册域名

**示例**:
- ✅ `alice.aid.pub`
- ✅ `test_user.example.com`
- ✅ `user-123.aid.pub`
- ❌ `bob.aid.pub` (name 只有 3 个字符)
- ❌ `__system__` (无 issuer，包含非法字符)
- ❌ `guest.aid.pub` (以 guest 开头)

## Group ID 格式规范

### Base 格式（不含域名部分）

支持三种格式：

1. **Legacy 格式**: `g-[a-z0-9]{4,32}`
   - 以 `g-` 开头
   - 后接 4 到 32 位小写字母或数字
   - 示例: `g-abc123`, `g-test`

2. **新格式**: `[a-z0-9]{5,}`
   - 5 位或更多小写字母或数字
   - 无上限
   - 示例: `12345`, `abcdef`

3. **Group name 格式**: `[a-z0-9][a-z0-9_-]{3,63}`
   - 4 到 64 个字符
   - 首字符为 `[a-z0-9]`
   - 可包含下划线和短横线
   - 示例: `team_alpha`, `my-group`

### 完整格式

- `group.{issuer}/{base}` — canonical 格式
- `{base}.{issuer}` — 旧格式（会被规范化）
- `{base}@{issuer}` — 兼容格式（会被规范化）
- `{base}` — 本域简写（需要服务端补全）

**示例**:
- ✅ `g-abc123.aid.pub`
- ✅ `group.aid.pub/g-test1`
- ✅ `team_alpha`
- ✅ `12345678`
- ❌ `g-1` (只有 3 个字符)
- ❌ `abc` (只有 3 个字符，不满足任何格式)

## 服务端已有校验

服务端在 `group.create` 中已经有以下校验：

```python
# extensions/services/group/service.py:1036-1037
if requested_group_id and self._is_numeric_group_id(requested_group_id):
    raise ValueError("custom group_id cannot be numeric; numeric group_id is reserved for generated group_no")
```

**规则**: 创建命名群时，群 ID 不能为纯数字。纯数字的 ID 只能由系统自动分配，以免冲突。

## 验证效果

客户端校验成功拦截以下非法格式：
- `__system__` → `ValidationError: Invalid aid '__system__': must be in format '{name}.{issuer}'`
- `bob.aid.pub` → `ValidationError: Invalid aid 'bob.aid.pub': name 'bob' must be 4-64 characters`
- `g-1` → `ValidationError: Invalid group_id 'g-1': base 'g-1' must be one of: ...`

## 参考

- Python SDK 实现: `python/src/aun_core/validators.py`
- 服务端格式定义: `extensions/services/group/service.py:53-58`
- 协议文档: `docs/protocol/10-Group-子协议.md`
- SDK 文档: `docs/sdk/03-核心概念.md`
