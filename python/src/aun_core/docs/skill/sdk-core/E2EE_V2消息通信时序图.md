# E2EE V2 消息通信时序图

本文只描述当前 V2-only 链路下的主要时序：P2P/GROUP 明文消息、P2P/GROUP 加密消息，以及 V2 设备密钥注册前置流程。不包含 V1 E2EE、旧 group epoch secret 分发、thought 内容读写。

## 范围约定

- SDK 默认 `message.send` / `group.send` 为 `encrypt=true`，由 SDK 本地构造 V2 加密 envelope。
- 显式 `encrypt=false` 时走明文发送；V2 SDK 接收端仍通过 `message.v2.pull` / `group.v2.pull` 合并拉取明文历史行。
- P2P 加密 envelope 类型为 `e2ee.p2p_encrypted`，通过 `message.send` 提交，服务端按 V2 分流处理。
- GROUP 加密 envelope 类型为 `e2ee.group_encrypted`，通过 `group.v2.send` 提交。
- 服务端只做认证、路由、结构校验、密文存储和事件通知，不持有明文 payload，也不执行端到端解密。

## V2 设备密钥注册

```mermaid
sequenceDiagram
    participant SDK as 接收方 SDK
    participant Message as message 服务
    participant Group as group 服务
    participant CA as CA/Auth

    SDK->>SDK: 初始化 V2Session<br/>IK=AID 长期密钥，生成或加载 P2P SPK
    SDK->>Message: message.v2.put_peer_pk<br/>peer_device_prekey + SPK 签名
    Message->>CA: ca.get_cert / 校验 AID 公钥
    Message-->>SDK: ok

    opt 已加入某个群
        SDK->>SDK: ensure_group_spk(group_id)
        SDK->>Group: group.v2.put_group_pk<br/>group_device_prekey + SPK 签名
        Group->>CA: ca.get_cert / 校验 AID 公钥
        Group-->>SDK: ok
    end
```

## P2P 明文消息

```mermaid
sequenceDiagram
    participant A as Sender SDK
    participant M as message 服务
    participant G as gateway
    participant B as Receiver SDK

    A->>M: message.send<br/>encrypt=false, payload=明文
    alt 目标跨域
        M->>G: gateway.forward_federation<br/>namespace=message, method=send
        G->>M: 转发到目标域 message 服务
    end
    M->>M: 按接收方 device 分配 seq<br/>写普通消息存储
    M->>G: dispatch_event(message.received)
    G-->>B: event/message.received 或通知

    B->>M: message.v2.pull(after_seq, limit)
    M-->>B: messages[]<br/>明文行 version=v1 / legacy_v1
    B->>B: 直接发布 message.received<br/>不做 E2EE 解密
    B->>M: message.v2.ack(up_to_seq)
```

## P2P 加密消息

```mermaid
sequenceDiagram
    participant A as Sender SDK
    participant M as message 服务
    participant G as gateway
    participant B as Receiver SDK

    A->>M: message.v2.bootstrap(peer_aid=B)
    M-->>A: B active devices<br/>IK + peer_device_prekey SPK<br/>self_devices + audit_recipients

    A->>A: 构造 recipients<br/>peer + self_sync + audit
    A->>A: 生成 master_key / msg_nonce / sender_session_key
    A->>A: 3DH/1DH wrap master_key<br/>AES-GCM 加密 payload<br/>ECDSA 签名 ct+tag+AAD+recipients_digest
    A->>M: message.send<br/>payload.type=e2ee.p2p_encrypted, version=v2, encrypt=false

    alt 目标跨域
        M->>G: gateway.forward_federation<br/>namespace=message, method=send
        G->>M: 转发到目标域 message 服务
    end

    M->>M: 校验 AAD/from/to/device、t_send、recipients_digest、audit wrap
    M->>M: 写 v2_peer_messages 共享密文体
    M->>M: 按 device 写 v2_peer_wraps<br/>seq per owner_aid + device_id
    M->>G: dispatch_event(peer.v2.message_received)<br/>只含 seq/message_id/device_id
    G-->>B: peer.v2.message_received

    B->>M: message.v2.pull(after_seq, limit)
    M-->>B: per-device envelope_json<br/>recipient wrap + merkle_proof
    B->>B: 验 sender_signature / recipients proof
    B->>B: 用本地 IK/SPK 解 wrap_key -> master_key
    B->>B: AES-GCM 解密 payload
    B-->>B: 发布 message.received
    B->>M: message.v2.ack(up_to_seq)
    B->>B: 若消费当前 SPK，异步 rotate_spk()
```

## GROUP 明文消息

```mermaid
sequenceDiagram
    participant A as Sender SDK
    participant Group as group 服务
    participant G as gateway
    participant B as Member SDK

    A->>Group: group.send<br/>encrypt=false, payload=明文
    Group->>Group: 校验成员/禁言/消息类型/epoch 边界
    Group->>Group: 写 group_messages + group_events<br/>递增 group.message_seq / event_seq
    Group->>G: dispatch_event(group.message_created)<br/>member_aids / dispatch 信息
    G-->>B: group.message_created 通知

    B->>Group: group.v2.pull(group_id, after_seq, limit)
    Group->>Group: 合并普通明文 group_messages
    Group-->>B: messages[]<br/>明文行 version=v1 + payload
    B->>B: 直接发布 group.message_created
    B->>Group: group.v2.ack(group_id, up_to_seq)
```

## GROUP 加密消息

```mermaid
sequenceDiagram
    participant A as Sender SDK
    participant Group as group 服务
    participant Msg as message 服务
    participant G as gateway
    participant B as Member SDK

    A->>Group: group.v2.bootstrap(group_id)
    Group->>Group: 校验成员资格，读取 epoch/state_chain
    Group->>Group: 读取 v2_group_devices<br/>group_device_prekey
    Group->>Msg: message.v2.group_bootstrap(member_aids)
    Msg-->>Group: fallback P2P device prekeys + audit_recipients
    Group-->>A: devices + epoch + state_commitment<br/>pending/committed members + audit_recipients

    A->>A: 校验 group state 签名 / 分叉
    A->>A: 构造 targets<br/>member + self_sync + audit
    A->>A: 生成 e2ee.group_encrypted envelope<br/>AAD 含 group_id/epoch/state_commitment
    A->>Group: group.v2.send(group_id, envelope)

    alt 群在异域
        Group->>G: gateway.forward_federation<br/>namespace=group, method=v2.send
        G->>Group: 转发到群归属域 group 服务
    end

    Group->>Group: 校验成员、e2ee_version=v2、epoch 匹配
    Group->>Group: 校验 AAD/from/group_id/from_device/message_id
    Group->>Group: 校验 recipients 排序、digest、audit wrap
    Group->>Group: 写 v2_group_messages 共享密文体
    Group->>Group: 按 recipient 写 v2_group_wraps
    Group->>G: dispatch_event(group.v2.message_created)<br/>seq/message_id/sender/member_aids
    G-->>B: group.v2.message_created 通知

    B->>Group: group.v2.pull(group_id, after_seq, limit)
    Group-->>B: per-device envelope_json<br/>recipient wrap + merkle_proof
    B->>B: 选择 group_id 对应 group SPK<br/>fallback 到 P2P SPK 仅兼容旧 wrap
    B->>B: 验签 / 验 proof / 解 wrap / 解密 payload
    B-->>B: 发布 group.message_created
    B->>Group: group.v2.ack(group_id, up_to_seq)
    B->>B: 若消费 group_device_prekey，异步 rotate_group_spk()
```

## 核心差异

| 场景 | 发送入口 | 服务端存储 | 接收入口 | 解密位置 |
|------|----------|------------|----------|----------|
| P2P 明文 | `message.send(encrypt=false)` | 普通 device message | `message.v2.pull` 合并明文行 | 不解密 |
| P2P 加密 | `message.send` 承载 `e2ee.p2p_encrypted` | `v2_peer_messages` + `v2_peer_wraps` | `message.v2.pull` | 接收方 SDK |
| GROUP 明文 | `group.send(encrypt=false)` | `group_messages` + `group_events` | `group.v2.pull` 合并明文行 | 不解密 |
| GROUP 加密 | `group.v2.send` 承载 `e2ee.group_encrypted` | `v2_group_messages` + `v2_group_wraps` | `group.v2.pull` | 接收方 SDK |

