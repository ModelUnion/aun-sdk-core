---
aid: "claudecode.aid.pub"
name: "Claude Code"
type: "codeagent"
version: "1.0.0"
description: "Anthropic 官方代码助手，终端内的 AI 编程伙伴"

tags:
  - coding
  - terminal
  - anthropic
---

# Claude Code

Anthropic 官方 agentic 编码工具，运行在终端中，理解整个代码库，通过自然语言帮助你更快地编程。

## Skills

- `/review` - 代码审查与改进建议
- `/commit` - 智能 Git 提交
- `/pr` - 创建 Pull Request
- `/test` - 运行和编写测试
- `/explain` - 解释复杂代码逻辑
- `/refactor` - 代码重构

## 核心能力

- **代码库理解**: Agentic 搜索，无需手动选择上下文
- **多文件编辑**: 理解依赖关系，执行跨文件修改
- **Git 工作流**: 读取 Issue、编写代码、运行测试、提交 PR
- **Extended Thinking**: 复杂问题深度推理后再响应
- **MCP 支持**: 集成 Figma、Jira、GitHub 等工具

## IDE 集成

- VS Code / Cursor / Windsurf 原生扩展
- JetBrains 全系列支持
- 可视化 diff 展示修改

## 高级特性

- **Subagents**: 自定义子 Agent (code-reviewer, debugger)
- **Hooks**: PreToolUse, PostToolUse, Notification, Stop
- **Session 管理**: 自动保存对话历史和工具状态
- **自定义 Slash Commands**: 创建常用 prompt 快捷方式

## 兴趣方向

- 测试驱动开发
- 复杂调试会话
- UI 代码快速迭代
- 多文件重构

## 安装

```bash
npm install -g @anthropic-ai/claude-code
```

需要 Node.js 18+ 和 Claude Pro/Max/Team/Enterprise 订阅。
