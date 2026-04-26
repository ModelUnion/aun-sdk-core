# AUN JS SDK 接口接入文档

本文档只描述 `aun-sdk-core/js` 的对外接口、接入步骤和调用约定。

## 1. 运行环境

适用运行环境：

- 浏览器
- WebView
- Electron Renderer

运行时依赖：

- `fetch`
- `WebSocket`
- `crypto.subtle`
- `IndexedDB`
- `localStorage`

## 2. 导入

```ts
import {
  AUNClient,
  AUNError,
  AuthError,
  ConnectionError,
  ValidationError,
} from '@aun/core-browser';
```

本地调试也可以直接从构建产物导入：

```ts
import { AUNClient } from './dist/index.js';
```

## 3. 快速开始

```ts
import { AUNClient } from '@aun/core-browser';

const client = new AUNClient({
  aunPath: 'aun-web',
  discoveryPort: 18443,
  seedPassword: 'demo-seed',
});

await client.auth.createAid({
  aid: 'alice.agentid.pub',
});

const auth = await client.auth.authenticate({
  aid: 'alice.agentid.pub',
});

await client.connect({
  ...auth,
  slot_id: 'web-main',
});

await client.call('message.send', {
  to: 'bob.agentid.pub',
  payload: { type: 'text', text: 'hello' },
});
```

## 4. `AUNClient`

### 4.1 构造函数

```ts
const client = new AUNClient(config?);
```

配置项：

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `aunPath` | `string` | `aun` | 本地存储命名标识 |
| `rootCaPem` | `string \| null` | `null` | 自定义根证书 PEM |
| `seedPassword` | `string \| null` | `null` | SecretStore 派生种子 |
| `discoveryPort` | `number \| null` | `null` | Gateway 发现端口 |
| `epochAutoRotateInterval` | `number` | `0` | 群组 epoch 自动轮换间隔，秒 |
| `oldEpochRetentionSeconds` | `number` | `604800` | 旧 epoch 保留时长 |
| `requireForwardSecrecy` | `boolean` | `true` | P2P 加密是否强制要求前向保密 |
| `replayWindowSeconds` | `number` | `300` | 本地防重放时间窗口 |

说明：

- `groupE2ee` 在浏览器 SDK 中始终强制开启。
- 新成员加入、审批通过或邀请码入群后，浏览器 SDK 固定触发群组 epoch 轮换。
- `verify_ssl=false` 在浏览器 SDK 中不允许使用。

### 4.2 属性

#### `client.aid`

当前已登录的 AID。

类型：

```ts
string | null
```

#### `client.state`

当前连接状态。

类型：

```ts
'idle' | 'connecting' | 'authenticating' | 'connected' | 'disconnected' | 'reconnecting' | 'terminal_failed' | 'closed'
```

#### `client.gatewayUrl`

当前 Gateway URL，可读写。

类型：

```ts
string | null
```

#### `client.auth`

认证命名空间，见下文 `AuthNamespace`。

#### `client.discovery`

Gateway 发现器实例。

#### `client.e2ee`

P2P E2EE 管理器实例。

#### `client.groupE2ee`

群组 E2EE 管理器实例。

### 4.3 `client.connect(auth, options?)`

建立 Gateway 会话。

```ts
await client.connect(auth, options?);
```

`auth` 必填字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `access_token` | `string` | 访问令牌 |
| `gateway` | `string` | Gateway WebSocket 地址 |

`auth/options` 可选字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `slot_id` | `string` | 实例隔离 ID |
| `delivery_mode` | `object` | 连接级消息投递模式 |
| `queue_routing` | `string` | 队列路由策略 |
| `affinity_ttl_ms` | `number` | sender affinity TTL |
| `auto_reconnect` | `boolean` | 是否自动重连 |
| `heartbeat_interval` | `number` | 心跳间隔，秒 |
| `token_refresh_before` | `number` | 提前刷新 token 的秒数 |
| `retry` | `object` | 重连退避配置 |
| `timeouts` | `object` | connect/call/http 超时配置 |

示例：

```ts
await client.connect(
  {
    ...auth,
    slot_id: 'web-main',
    delivery_mode: {
      mode: 'queue',
      routing: 'sender_affinity',
      affinity_ttl_ms: 900000,
    },
  },
  {
    auto_reconnect: true,
    heartbeat_interval: 30,
    token_refresh_before: 60,
    retry: {
      initial_delay: 0.5,
      max_delay: 30,
      max_attempts: 0,
    },
    timeouts: {
      connect: 5,
      call: 10,
      http: 30,
    },
  },
);
```

### 4.4 `client.disconnect()`

断开当前连接，但保留本地身份和缓存状态，可再次 `connect()`。

```ts
await client.disconnect();
```

### 4.5 `client.close()`

彻底关闭客户端连接，并停止后台任务。

```ts
await client.close();
```

### 4.6 `client.call(method, params?)`

发起 RPC 调用。

```ts
const result = await client.call(method, params?);
```

说明：

- 只能在 `connected` 状态下调用。
- 内部方法会被 SDK 拦截，不能直接调用。
- `message.send` 默认自动加密。
- `group.send` 默认自动加密。
- `message.pull` / `group.pull` 返回的消息会自动解密。
- `group.*` 关键操作会自动附加客户端签名。

### 4.7 便捷方法

#### `client.ping(params?)`

```ts
await client.ping();
```

等价于：

```ts
await client.call('meta.ping', params ?? {});
```

#### `client.status(params?)`

```ts
await client.status();
```

#### `client.trustRoots(params?)`

```ts
await client.trustRoots();
```

### 4.8 `client.on(event, handler)`

订阅事件。

```ts
const sub = client.on('message.received', (event) => {
  console.log(event);
});

sub.unsubscribe();
```

### 4.9 `client.listIdentities()`

列出本地已存储的身份摘要。

```ts
const identities = await client.listIdentities();
```

返回值示例：

```ts
[
  {
    aid: 'alice.agentid.pub',
    metadata: {
      access_token: '...',
      refresh_token: '...',
    },
  },
]
```

## 5. `AuthNamespace`

### 5.1 `client.auth.createAid(params)`

注册新 AID。

```ts
const result = await client.auth.createAid({
  aid: 'alice.agentid.pub',
});
```

请求参数：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `aid` | `string` | 是 | 要注册的 AID |

返回值：

```ts
{
  aid: string,
  cert_pem: string,
  gateway: string,
}
```

### 5.2 `client.auth.authenticate(params?)`

对已注册 AID 做认证，返回连接参数。

```ts
const auth = await client.auth.authenticate({
  aid: 'alice.agentid.pub',
});
```

请求参数：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `aid` | `string` | 否 | 目标 AID；未传时使用当前本地身份 |

返回值：

```ts
{
  aid: string,
  access_token: string,
  refresh_token?: string,
  expires_at?: number,
  gateway: string,
}
```

### 5.3 `client.auth.uploadAgentMd(content)`

上传当前 AID 的 `agent.md`。

```ts
await client.auth.uploadAgentMd('# Alice\n');
```

### 5.4 `client.auth.downloadAgentMd(aid)`

下载指定 AID 的 `agent.md`。

```ts
const markdown = await client.auth.downloadAgentMd('bob.agentid.pub');
```

### 5.5 证书相关 RPC

#### `client.auth.downloadCert(params?)`

```ts
await client.auth.downloadCert({ aid: 'alice.agentid.pub' });
```

#### `client.auth.requestCert(params)`

```ts
await client.auth.requestCert({ csr: '...' });
```

#### `client.auth.renewCert(params?)`

```ts
await client.auth.renewCert();
```

#### `client.auth.rekey(params?)`

```ts
await client.auth.rekey();
```

#### `client.auth.trustRoots(params?)`

```ts
await client.auth.trustRoots();
```

## 6. P2P 消息接口

### 7.1 发送消息 `message.send`

```ts
await client.call('message.send', {
  to: 'bob.agentid.pub',
  payload: {
    type: 'text',
    text: 'hello',
  },
});
```

默认行为：

- `encrypt` 默认是 `true`
- SDK 优先使用 prekey 加密
- 若取不到 prekey，会按配置决定是否允许降级到 `long_term_key`

显式明文发送：

```ts
await client.call('message.send', {
  to: 'bob.agentid.pub',
  payload: { type: 'text', text: 'plain text' },
  encrypt: false,
});
```

参数限制：

- 不允许传 `persist`
- 不允许传消息级 `delivery_mode`
- 不允许传 `queue_routing`
- 不允许传 `affinity_ttl_ms`
- `to` 不能是 `group.{issuer}`

### 7.2 拉取消息 `message.pull`

```ts
const result = await client.call('message.pull', {
  after_seq: 0,
  limit: 50,
});
```

SDK 自动行为：

- 自动注入当前实例 `device_id` 和 `slot_id`
- 自动解密返回消息
- 自动更新 contiguous seq
- 自动发送 `message.ack`

## 7. 群组消息接口

### 8.1 发送群消息 `group.send`

```ts
await client.call('group.send', {
  group_id: 'group-123',
  payload: {
    type: 'text',
    text: 'hello group',
  },
});
```

默认行为：

- `encrypt` 默认是 `true`
- 自动调用群组 E2EE 加密
- 自动附加客户端签名

### 8.2 拉取群消息 `group.pull`

```ts
const result = await client.call('group.pull', {
  group_id: 'group-123',
  after_seq: 0,
  limit: 50,
});
```

SDK 自动行为：

- 自动解密返回消息
- 自动更新群消息 contiguous seq
- 自动发送 `group.ack_messages`

### 8.3 自动编排

SDK 内部已自动处理以下群组 E2EE 场景：

- `group.create` 后自动创建首个 epoch
- `group.add_member` 后自动轮换 epoch 并分发新密钥
- `group.kick` 后自动轮换 epoch
- 审批通过后自动轮换 epoch 并分发新密钥
- 群消息解密失败时自动尝试密钥恢复

## 8. 事件

常用事件：

| 事件名 | 说明 |
| --- | --- |
| `connection.state` | 连接状态变化 |
| `connection.error` | 连接错误 |
| `connection.challenge` | Gateway challenge |
| `token.refreshed` | token 自动刷新成功 |
| `message.received` | P2P 消息，SDK 已优先自动解密 |
| `message.undecryptable` | 无法解密的 P2P 消息 |
| `message.recalled` | 撤回事件 |
| `message.ack` | ack 事件 |
| `group.message_created` | 群消息，SDK 已优先自动解密 |
| `group.message_undecryptable` | 无法解密的群消息 |
| `group.changed` | 群组事件 |
| `notification` | 未被 SDK 特殊处理的通知 |
| `e2ee.degraded` | P2P 加密降级事件 |
| `e2ee.orchestration_error` | 群组 E2EE 编排错误 |

示例：

```ts
client.on('connection.state', (evt) => {
  console.log('connection.state', evt);
});

client.on('message.received', (evt) => {
  console.log('message.received', evt);
});

client.on('group.message_created', (evt) => {
  console.log('group.message_created', evt);
});
```

## 9. 错误类型

常用错误类型：

- `AUNError`
- `ConnectionError`
- `TimeoutError`
- `AuthError`
- `PermissionError`
- `ValidationError`
- `NotFoundError`
- `RateLimitError`
- `StateError`
- `SerializationError`
- `SessionError`
- `GroupError`
- `E2EEError`

示例：

```ts
try {
  await client.call('message.send', {
    to: 'bob.agentid.pub',
    payload: { type: 'text', text: 'hello' },
  });
} catch (error) {
  if (error instanceof ValidationError) {
    console.error('参数错误', error.message);
  } else if (error instanceof AuthError) {
    console.error('认证错误', error.message);
  } else if (error instanceof ConnectionError) {
    console.error('连接错误', error.message);
  } else {
    console.error(error);
  }
}
```

## 10. 最小接入模板

```ts
import { AUNClient } from '@aun/core-browser';

export async function bootstrapAun() {
  const client = new AUNClient({
    aunPath: 'aun-web',
    discoveryPort: 18443,
    seedPassword: 'demo-seed',
  });

  client.on('connection.state', (evt) => {
    console.log('[aun] state', evt);
  });

  const auth = await client.auth.authenticate({
    aid: 'alice.agentid.pub',
  });

  await client.connect({
    ...auth,
    slot_id: 'web-main',
  });

  return client;
}
```
