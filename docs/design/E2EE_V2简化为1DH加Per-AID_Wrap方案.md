# E2EE V2 简化为 1DH + Per-AID Wrap 方案

> 状态：执行方案
> 目标：新消息优先使用服务端控制的 `1DH + per-AID wrap`，同时兼容旧 SDK、旧服务端和历史消息。

## 1. 最终协议边界

- `e2ee_wrap_policy` 只出现在 `message.v2.bootstrap` / `group.v2.bootstrap` 返回值中。
- policy 不写入 envelope，不新增 AAD 字段，不新增 `wrap_scope` / `wrap_policy_version`。
- 现有 AAD 里的 `wrap_protocol` 仍由实际 recipient rows 推导；1DH/per-AID 时自然为 `1DH`。
- recipient row schema 不变，仍是 8 字段：
  `[aid, device_id, role, key_source, ik_fp, spk_id, wrap_nonce, wrapped_key]`
- per-AID row 通过 `device_id == ""` 区分：
  `[aid, "", role, "aid_master", ik_fp, "", wrap_nonce, wrapped_key]`
- per-device 旧 row 格式不变，历史消息继续按原逻辑解密。

## 2. Bootstrap Policy

新 SDK 在 bootstrap 请求中声明能力，旧 SDK 不传该参数：

```json
{
  "e2ee_wrap_capabilities": {
    "version": "v2.1",
    "protocols": ["1DH", "3DH"],
    "scopes": ["aid", "device"],
    "per_aid_wrap": true,
    "per_device_wrap": true
  }
}
```

服务端返回实际生效 policy：

```json
{
  "e2ee_wrap_policy": {
    "version": "v2.1",
    "protocol": "1DH",
    "scope": "aid",
    "per_aid_wrap": true,
    "per_device_wrap": false,
    "source": "server_default"
  }
}
```

SDK 行为：

- SDK 只能声明能力，不能强制选择 policy；实际 `1DH/3DH`、`aid/device` 由服务端返回的 `e2ee_wrap_policy` 决定。
- 旧 SDK / 未声明能力的 bootstrap：服务端返回 legacy `3DH + per-device`，并保留 SPK 字段，避免新发送端生成老解密端不支持的 `device_id=""` row。
- policy 缺失：保持旧行为，继续按 bootstrap devices 生成 per-device wrap。
- `protocol=1DH`：忽略 SPK，清空 `spk_id`，使用 AID IK 做 1DH。
- `scope=aid`：按 `(aid, role)` 折叠 target，生成 `device_id=""` 的 row。
- `scope=aid` 强制 `protocol=1DH`；不支持 `3DH + per-AID`。

服务端只在调用方显式声明支持 per-AID wrap 后才可能返回 `scope=aid`。在 1DH 策略下服务端也会从 bootstrap 返回中剥掉 SPK 字段，让新 SDK 即使只按设备条目本身判断，也会自然退到 1DH。

## 3. 服务端投递语义

服务端能区分 per-device / per-AID：

- `row[1] != ""`：per-device wrap，直接投递给该 device。
- `row[1] == ""`：per-AID wrap，服务端查当前应投递的实际 device 列表并 fanout。

投递账本不变：

- P2P 仍写 `v2_peer_wraps(owner_aid, owner_device_id, seq, ...)`。
- Group 仍写 `v2_group_wraps(group_id, owner_aid, owner_device_id, seq, ...)`。
- push、pull、ack、seq tracker、GC 仍按真实 device 执行。

关键兼容点：

- DB 新增 `recipient_row_json` 保存 sender 原始 row。
- aid-wide row fanout 时，`owner_device_id` 写真实 device，但 `recipient_row_json` 保留 `device_id=""`。
- pull 重建 envelope 时优先使用 `recipient_row_json` 生成 `envelope.recipient`。
- Merkle proof 和 `recipients_digest` 始终基于 sender 原始 recipients 数组，不能把 `recipient.device_id` 改成真实 device，否则 proof 会失败。

## 4. SDK 修改范围

只改发送端 target 构造和解密 row 匹配：

- Python：`python/src/aun_core/client.py`
- TypeScript：`ts/src/client.ts`
- JavaScript：`js/src/client.ts`
- Go：`go/v2_p2p.go`、`go/v2_group.go`、`go/v2_thought.go`
- C++：`D:/modelunion/ACP-APP/aun-so/core/src/client/aun_client.cpp`

不改各语言 e2ee `EncryptOptions`，不把 policy 传入纯加密层，不改 AAD。

解密端仅补 full-envelope/thought 场景的匹配：

```text
row[0] == self_aid AND (row[1] == self_device_id OR row[1] == "")
```

per-device pull envelope 中，`recipient.device_id=""` 直接按 1DH 解密。

## 5. 执行计划

1. 服务端 P2P
   - `message.v2.bootstrap` 读取 `e2ee_wrap_capabilities`，未声明时返回 legacy `3DH/device`。
   - 显式支持 per-AID 时返回服务端配置决定的 `e2ee_wrap_policy`。
   - 1DH policy 下剥离 `peer_devices/self_devices/audit_recipients` 的 SPK 字段。
   - `_rpc_send_v2_p2p` 接受 `device_id=""` row，并 fanout 到当前 active devices。
   - `v2_peer_wraps` 增加 `recipient_row_json`，pull 时用原始 row 重建 recipient。

2. 服务端 Group
   - `group.v2.bootstrap` 读取 `e2ee_wrap_capabilities`，未声明时返回 legacy `3DH/device`。
   - 显式支持 per-AID 时返回服务端配置决定的 `e2ee_wrap_policy`，不再由 join_mode 隐式决定。
   - `_rpc_v2_send` 接受 per-AID row，按 AID fanout 到群成员实际 devices。
   - `v2_group_wraps` 增加 `recipient_row_json`，pull 时用原始 row 重建 recipient。

3. SDK
   - 五个 SDK 调 `message.v2.bootstrap` / `group.v2.bootstrap` 时声明 `e2ee_wrap_capabilities`。
   - 五个 SDK 缓存 bootstrap 时同时缓存 policy。
   - envelope 构造前按 policy 转换 targets。
   - 解密端补 `device_id=""` 匹配。

4. 验证
   - Python/服务端文件做语法检查。
   - Go 跑相关 package 测试。
   - TS/JS 跑类型检查或最小编译检查。
   - 用 1DH/per-AID 构造 P2P 和 Group envelope，验证 row 格式、AAD 无新增字段、解密成功。


