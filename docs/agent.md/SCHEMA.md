# Agent.md 规格定义

版本: 1.0.0

## 限制

- **文件大小**: 最大 4KB

## 文件格式

agent.md 文件采用 **YAML frontmatter + Markdown 内容 + 签名块（可选，位于文件尾部）** 的格式：

```markdown
---
# YAML 元数据 (核心字段)
aid: "agent-name.aid.pub"
name: "Agent Name"
type: "assistant"
version: "1.0.0"
description: "一句话描述"
tags:
  - tag1
  - tag2
---

# Markdown 正文内容
详细说明、Skills、使用示例等...

<!-- AUN-SIGNATURE
cert_fingerprint: sha256:abc123...
timestamp: 1715300000
signature: MEUCIQDx...
-->
```

无签名的文件仍然合法，第一行直接以 `---` 开头。

## 签名块规范

### 位置

文件尾部，位于 Markdown 正文之后。

### 格式

```
<!-- AUN-SIGNATURE
cert_fingerprint: sha256:<hex>
timestamp: <unix_seconds>
signature: <base64_der>
-->
```

- **cert_fingerprint**: 签名证书的 SHA-256 指纹，格式 `sha256:<64位hex>`
- **timestamp**: 签名时刻的 Unix 时间戳（秒）
- **signature**: ECDSA P-256 签名的 DER 编码，Base64 表示

### 签名计算

1. **被签内容（payload）**：签名块开始标记 `<!-- AUN-SIGNATURE` 之前的全部字节
2. **哈希**：对 payload 计算 SHA-256
3. **签名**：使用 NIST P-256 私钥对哈希值进行 ECDSA 签名

### 验签流程

1. 检测文件尾部是否存在 `<!-- AUN-SIGNATURE` 签名块
2. 提取签名块中的 `cert_fingerprint`、`timestamp`、`signature`
3. 剥离签名块，取剩余内容为 payload
4. 对 payload 计算 SHA-256
5. 通过 `cert_fingerprint` 查找对应证书，获取公钥
6. 使用公钥验证 ECDSA 签名

### 约束

- 签名块必须是文件的最后一个可见块（后面只允许可忽略的空白）
- 签名块与正文之间应至少保留一个换行
- 签名块不计入 4KB 文件大小限制

## YAML Schema (核心字段)

```yaml
# ===== 身份标识 (必填) =====
aid:
  type: string
  required: true
  pattern: "^[a-zA-Z0-9_-]+\\.aid\\.pub$"
  description: "Agent 的唯一身份标识 (AID 格式)"
  example: "lobster.aid.pub"

# ===== 基本信息 =====
name:
  type: string
  required: true
  description: "Agent 显示名称"
  example: "Code Reviewer"

type:
  type: string
  required: true
  enum:
    - human          # 真人用户
    - assistant      # 通用助手
    - avatar         # 用户化身/分身
    - openclaw       # OpenClaw AI 助手
    - codeagent      # 代码编程 Agent
  description: "Agent 类型"

version:
  type: string
  required: true
  pattern: "^\\d+\\.\\d+\\.\\d+$"
  example: "1.0.0"

# ===== 描述信息 =====
description:
  type: string
  required: true
  max_length: 100
  description: "一句话简介，用于列表展示"

# ===== 标签 =====
tags:
  type: array
  required: false
  items:
    type: string
  description: "用于分类和检索"
```

## Agent Type 说明

| Type | 用途 | 示例 |
|------|------|------|
| `human` | 真人用户 | 开发者、管理员、终端用户 |
| `assistant` | 通用对话助手 | 聊天机器人、客服 |
| `avatar` | 用户分身 | 代表用户行动的 agent |
| `openclaw` | OpenClaw AI 助手 | 本地个人助手、ACP 桥接 |
| `codeagent` | 代码编程 Agent | Claude Code、Cursor Agent |

## 示例文件

| 文件 | Type | AID | 说明 |
|------|------|-----|------|
| [human-developer.md](examples/human-developer.md) | `human` | `zhangsan.aid.pub` | 全栈开发者 |
| [openclaw-lobster.md](examples/openclaw-lobster.md) | `openclaw` | `lobster.aid.pub` | OpenClaw AI 助手（无签名） |
| [signed-openclaw-lobster.md](examples/signed-openclaw-lobster.md) | `openclaw` | `lobster.aid.pub` | OpenClaw AI 助手（带签名） |
| [codeagent-claudecode.md](examples/codeagent-claudecode.md) | `codeagent` | `claudecode.aid.pub` | Claude Code 编程助手 |

## Markdown 部分建议内容

YAML 只保留核心元数据，详细信息放在 Markdown 部分：

- **Skills** - 技能/命令列表及说明
- **功能说明** - 详细的功能描述
- **使用示例** - 具体的使用方法
- **配置说明** - 运行时配置（如需要）
- **限制/注意事项** - 使用限制

## 解析方式

解析时需先检测并跳过尾部签名块：

```go
// 1. 检测尾部签名块
if idx := strings.LastIndex(content, "<!-- AUN-SIGNATURE"); idx >= 0 {
    content = content[:idx] // 跳过尾部签名块，取 payload
}
// 2. 按原规则解析 frontmatter
parts := strings.SplitN(content, "---", 3)
// parts[0] = "" (空)
// parts[1] = YAML 内容
// parts[2] = Markdown 内容
```
