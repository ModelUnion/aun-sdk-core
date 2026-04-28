# AUN Protocol — Node.js SDK

## Overview

AUN (Agent Union Network) defines a standard interface for secure communication between Agents — based on WebSocket + JSON-RPC 2.0, covering identity, authentication, messaging, and capability invocation, without being tied to a single communication topology.

---

## Core Concepts

**Problem**: AI Agents are trapped in their respective platforms, unable to communicate across domains and invoke each other's capabilities.

**AUN's Answer**:

- **AID Identity**: Globally unique identifier in `{name}.{issuer}` format (e.g., `alice.agentid.pub`), based on X.509 certificate chain
- **Three Connection Modes**: Gateway (standard access), Peer (point-to-point direct), Relay (relay forwarding), with consistent application-layer API
- **Capability Invocation**: Native `tool_call` / `tool_result` message types, allowing cross-domain discovery and invocation of Agent capabilities

```
                  ┌─ Gateway ──→ Standard access (browser/mobile/server)
Agent A ← WSS → ─┤─ Peer ─────→ Point-to-point direct (same network/low latency)
                  └─ Relay ────→ Relay forwarding (NAT traversal/lightweight deployment)
```

**This SDK** is the Node.js/TypeScript client implementation of the AUN protocol. Install with `npm install @agentunion/core.node`.

---

## Installation

```bash
npm install @agentunion/core.node
```

## Quick Start

```typescript
import { AunClient } from '@agentunion/core.node';

// Create client
const client = new AunClient({
  aid: 'alice.agentid.pub',
  gatewayUrl: 'wss://gateway.agentid.pub',
  dataDir: './data'
});

// Connect
await client.connect();

// Send message
await client.sendMessage({
  to: 'bob.agentid.pub',
  content: 'Hello from Alice!'
});

// Receive messages
client.on('message', (msg) => {
  console.log('Received:', msg);
});
```

## Features

- ✅ AID-based identity authentication
- ✅ End-to-end encrypted messaging
- ✅ Group chat with E2EE
- ✅ Cross-domain communication
- ✅ Tool call/result support
- ✅ Storage service integration
- ✅ TypeScript support with full type definitions

## Documentation

For detailed documentation, visit: https://github.com/agentunion/aun-sdk-core

## License

Apache-2.0
