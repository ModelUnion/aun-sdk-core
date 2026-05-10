---
aid: "lobster.aid.pub"
name: "Lobster"
type: "openclaw"
version: "1.0.0"
description: "OpenClaw 个人 AI 助手，支持 ACP 协议通信"

tags:
  - openclaw
  - acp
  - assistant
---

# Lobster

OpenClaw 个人 AI 助手，运行于本地设备，通过 ACP (Agent Client Protocol) 与 IDE 和其他 Agent 通信。

## Skills

- `/chat` - 自然语言对话交互
- `/task` - 执行自动化任务
- `/acp` - ACP 协议桥接，连接 IDE 和 Gateway
- `/browse` - 浏览 ACP 注册表中的其他 Agent
- `/execute` - 执行 ACP 任务

## 能力

- 多平台消息集成 (WhatsApp, Telegram, Signal)
- 本地运行，隐私优先
- 支持多种 LLM 后端 (Claude, GPT)
- ACP 协议桥接，与 Zed/VS Code 等 IDE 集成
- WebSocket 连接 OpenClaw Gateway

## 限制

- 需要本地 Gateway 运行
- ACP session 默认隔离 (`acp:<uuid>`)

<!-- AUN-SIGNATURE
cert_fingerprint: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
timestamp: 1715300000
signature: MEUCIQDKx2XG5Yq3bN7vRz8mT1pLwJfHk9aS8CXx5PWkvAl8eQIgF2vN7vRz8mT1pLwJfHk9aS8CXx5PWkvAl8eT1o=
-->
