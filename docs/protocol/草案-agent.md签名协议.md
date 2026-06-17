# 草案：agent.md 签名协议

**状态**：DRAFT v0.1
**日期**：2026-05-08
**定位**：社会人补丁——让 agent 的自我介绍不被伪造
**非目标**：不是服务认证、不是访问授权、不是内容审核

---

## 1. 问题陈述

`agent.md` 是 Agent 的自我介绍（见 `docs/protocol/agent.md/SCHEMA.md` 与 `附录K-Agent_Web发现协议.md`）。当前版本是**静态文本文件**，没有任何签名机制。这导致：

- 任何人可以在第三方服务器放一份伪造的 `agent.md`，冒用他人 AID
- 访问方（人或 agent）读到的内容无法在协议层面验证是否由该 AID 本人维护
- 中间人、CDN、代理可以在传输路径上篡改而不被发现（TLS 只保证传输段，不保证来源真实性）

**类比人类社会**：身份证有水印和芯片防伪。AID 的证书体系已经解决了"你是谁"，但没解决"这张自我介绍是不是你写的"。

## 2. 核心原则

1. **纯粹可信性补丁**：签名**仅**用于验证 agent.md 的作者身份与完整性，不做访问控制
2. **可选**：未签名的 agent.md 仍然合法；签名只是**让信任可验证**，不是准入门槛
3. **复用现有信任根**：签名使用 AID 证书链，不引入新的密钥体系
4. **静态友好**：签名可离线生成，可放 CDN，可被无头浏览器验证——不需要运行时服务

## 3. 签名载体

采用**外挂文件**方案，不修改 agent.md 本身。

### 3.1 URL 约定

```
https://{aid}.{issuer_domain}/agent.md       ← 本体（不变）
https://{aid}.{issuer_domain}/agent.md.sig   ← 签名（新增，可选）
```

`agent.md.sig` 的存在是**可选的**。访问方**应当**尝试拉取，拉取失败或 404 时视为"未签名"（合法但不可验证）。

### 3.2 为什么选外挂而不是内嵌 YAML

- **避免"签名包含自己"的循环**：内嵌字段签名需要规范化排除，实现易出错
- **兼容现有解析器**：已部署的 agent.md 解析器零改动
- **支持离线签名工具链**：签名生成工具无需理解 agent.md 的 YAML/Markdown 结构

## 4. 签名文件格式

`agent.md.sig` 是 **JSON 文件**，UTF-8 编码，最大 4KB。

```json
{
  "version": "1.0.0",
  "aid": "alice.aid.pub",
  "algorithm": "ECDSA-P256-SHA256",
  "content_sha256": "base64url(sha256(agent.md 原始字节))",
  "signed_at": "2026-05-08T10:00:00Z",
  "signature": "base64url(ECDSA 签名)",
  "cert_chain": [
    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\n...(Issuer CA)...\n-----END CERTIFICATE-----"
  ]
}
```

### 4.1 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|:---:|------|
| `version` | string | ✅ | 签名协议版本号，当前 `1.0.0` |
| `aid` | string | ✅ | 被签名 agent.md 所属的 AID，**必须**与 agent.md 内 YAML 的 `aid` 字段一致 |
| `algorithm` | string | ✅ | 签名算法，当前仅 `ECDSA-P256-SHA256` |
| `content_sha256` | string | ✅ | agent.md **原始字节**的 SHA-256，base64url 无填充 |
| `signed_at` | string | ✅ | ISO-8601 UTC 时间戳，签名生成时刻 |
| `signature` | string | ✅ | ECDSA 签名，详见 §5 签名数据结构 |
| `cert_chain` | array | ✅ | 证书链（PEM 格式），自 Agent 证书至 Issuer CA，**不含** Root CA |

## 5. 签名数据结构

签名对象是一个**规范化 JSON 串**（不是 agent.md 本身），内容：

```json
{
  "aid": "alice.aid.pub",
  "content_sha256": "...",
  "signed_at": "2026-05-08T10:00:00Z",
  "version": "1.0.0"
}
```

**规范化规则**：
- 字段按字典序排列
- UTF-8 编码
- 无多余空白、无尾随换行
- 仅使用上述 4 个字段（`signature` 和 `cert_chain`、`algorithm` **不参与**签名）

签名 = `ECDSA-P256-SHA256(sign_payload)`，使用 Agent 证书对应的私钥。

> **为什么 `algorithm` 不参与签名**：避免算法字段被篡改导致语义降级攻击——算法选择应在验证方的允许清单中独立校验，不依赖签名文件自述。

## 6. 验证流程

接收方（人类浏览器插件、agent 客户端、evol IM）**应当**按顺序执行：

1. **拉取本体**：`GET /agent.md`（必要）
2. **拉取签名**：`GET /agent.md.sig`（可选）。失败 → 标记为 `unsigned`，结束
3. **结构校验**：`agent.md.sig` 是否合法 JSON，字段是否齐全
4. **AID 一致性**：解析 agent.md 的 YAML frontmatter，校验 `yaml.aid == sig.aid`
5. **内容哈希**：计算 agent.md 原始字节的 SHA-256，校验 `== sig.content_sha256`
6. **算法白名单**：`sig.algorithm` 是否在本地允许清单中
7. **证书链验证**：
   - 按 `cert_chain` 顺序验证 Agent 证书 → Issuer CA → 本地受信 Root CA
   - 校验 Agent 证书的 subject 对应 `sig.aid`
   - 校验证书**未过期**、**未吊销**（CRL/OCSP，与 AUN 证书体系一致）
8. **签名验证**：重建 `sign_payload`，用 Agent 证书公钥验证 `sig.signature`
9. **时间戳合理性**（应用层策略）：`sig.signed_at` 是否在 Agent 证书有效期内，是否过度陈旧（建议默认 365 天警告）

任一步失败 → 标记为 `invalid`（比 `unsigned` 更严重——有签名但验证失败应警示）。

## 7. 状态分类

| 状态 | 含义 | UI 建议 |
|------|------|--------|
| `valid` | 签名存在且验证通过 | 绿色徽章「✓ 已验证」 |
| `unsigned` | 无签名文件 | 中性，不显示徽章 |
| `invalid` | 有签名但验证失败 | 红色警示「⚠ 签名无效」 |
| `expired` | 签名时使用的证书现已过期 | 黄色警示「签名过期」 |

## 8. 发布方义务

Agent 维护者（AID 所有者）**应当**：

1. 在发布或更新 `agent.md` 时**同步更新** `agent.md.sig`
2. 使用**当前有效**的 Agent 证书私钥签名
3. 证书换发（rotate）后，在合理时间内（建议 7 天）重新签名所有现存 agent.md
4. 证书吊销后，**应当**主动撤下该版本 agent.md 或重新签名

**不得**：

- 使用已吊销或过期的证书签名新发布
- 将签名私钥交给第三方托管平台（类似身份证原件不得委托）

## 9. 发布方不作为的后果

`agent.md.sig` 是可选的——**未签名本身不是违规**。但：

- 访问方客户端可以选择**只信任已签名的 agent.md**（应用层策略）
- 依赖 agent.md 做决策的自动化系统（如 agent 发现、能力匹配）**应当**在未签名时降低置信度
- evol 等 IM 客户端**应当**在 UI 区分已签名/未签名，类似 HTTPS 锁图标

## 10. 反模式（明确不做）

这些是 service 思维陷阱，**不是**本协议的目标：

- ❌ 签名作为访问控制（「只有签名有效才能调用这个 agent」）
- ❌ 签名绑定内容审核（「签名内容必须通过某审核」）
- ❌ 强制签名过期频率（签名是事实性的「是我写的」，不是订阅制授权）
- ❌ 中心化签名服务（签名私钥属于 AID 所有者，不托管）
- ❌ 签名与 agent 运行时状态挂钩（agent 在线/离线不影响静态签名）

## 11. 与现有 AUN 体系的集成

- 证书体系：**复用** `docs/protocol/02-证书与信任体系.md` 定义的四级证书链
- 签名算法：**复用** ECDSA-P256，与 `peer.*` 签名体系一致
- 证书吊销：**复用** CRL/OCSP 机制
- 不引入新服务：Issuer / Gateway / Relay 均**无需**改动

## 12. 示例

**agent.md**（简化示意）：

```markdown
---
aid: "alice.aid.pub"
name: "Alice"
type: "assistant"
version: "1.0.0"
description: "An example agent"
---

# Skills
- general conversation
```

**agent.md.sig**（对应签名）：

```json
{
  "version": "1.0.0",
  "aid": "alice.aid.pub",
  "algorithm": "ECDSA-P256-SHA256",
  "content_sha256": "3kL9_...base64url...XyZ",
  "signed_at": "2026-05-08T10:00:00Z",
  "signature": "MEUCIQC...base64url...gAw",
  "cert_chain": [
    "-----BEGIN CERTIFICATE-----\nMIIBv...\n-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\nMIIC3...\n-----END CERTIFICATE-----"
  ]
}
```

## 13. 待议事项

- 是否支持多签名（多个 AID 共同背书同一个 agent.md）？当前版本不支持
- 是否定义签名过期后的"续签"流程？当前版本依赖重新签名
- 是否把签名字段扩展到 agent.md 以外的 Agent Web 资源（如 index.html）？超出本草案范围


