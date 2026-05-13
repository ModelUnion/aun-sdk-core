# 议题 — E2EE 移动端性能与可用性分析

> 状态：问题记录（未立项）
> 日期：2026-05-13
> 相关规范：`08-AUN-E2EE.md`、`08-AUN-E2EE-Group.md`、`10-Group-子协议.md`
> 相关实现：`aun-sdk-core/python/src/aun_core/client.py`、`aun-sdk-core/python/src/aun_core/e2ee.py`

---

## 1. 问题现象

移动端群聊场景下实测：

- `group.send` / 群消息接收经常失败
- 失败集中在 **epoch 轮换 / 密钥交换** 环节
- 移动端 App 切到后台即断 WebSocket → 群内「在线成员」长期接近 0
- 密钥恢复需要多次 RPC 往返，且强依赖对端此刻在线

---

## 2. 性能评估：明文 vs 当前 E2EE

| 场景 | 明文 | 当前 E2EE | 差距 |
|---|---|---|:---:|
| P2P 发送（缓存命中） | 1 RPC | 1 RPC + ~5 ms CPU | 持平 |
| P2P 发送（首次给某对端） | 1 RPC | 3 RPC + PKI 链/CRL/OCSP 验证 | **3×** |
| 群聊发送（热路径、一切正常） | 1 RPC | **5 RPC** + 客户端签名 | **5×** |
| 群聊发送（epoch 不对齐） | 1 RPC | **6 ~ N RPC** + 最多 5 s 阻塞等待 | 失败率激增 |
| 群聊密钥恢复（对端离线） | — | 多次 `get_epoch` + key_request + 5 s 超时 → 整体失败 | 阻断 |

---

## 3. 代码证据

### 3.1 P2P 发送热路径

`client.py:772-829`（`_send_encrypted`）：

- `_fetch_peer_prekeys`（`client.py:2734`）：缓存 5 min，未命中时 1× `message.e2ee.get_prekey`
- `_fetch_peer_cert`（`client.py:2654`）：缓存 10 min，未命中时 1× HTTPS + PKI 链 + CRL + OCSP + AID 绑定校验（`client.py:2708-2711`）
- 最终 1× `message.send`

冷启动首条 = 3 次网络往返 + PKI 全链验证。

### 3.2 群聊发送热路径

`client.py:1055-1106`（`_send_group_encrypted`）。**每次发送都重复调用 `group.e2ee.get_epoch` 三次**：

1. `_ensure_group_epoch_ready` → `get_epoch`
2. `_wait_for_group_membership_epoch_floor` → `get_epoch` + `group.get_members`
3. `_committed_group_epoch_state` → `get_epoch`（第 3 次，同一次发送内）
4. 最终 `group.send`

= **5 RPC / 条消息**，热路径。

### 3.3 群聊密钥恢复路径

`client.py:1285-1317`（`_do_recover_group_epoch_key`）、`client.py:1395-1428`（`_ensure_group_epoch_ready` 恢复分支）：

- `_KEY_WAIT_TIMEOUT_S = 5.0`、`_KEY_WAIT_POLL_INTERVAL_S = 0.15`（`client.py:67-68`）
- 候选成员列表遍历发 P2P 加密 `e2ee.group_key_request`（每条自身 3 RPC）
- 每 150 ms 轮询本地 secret 是否到位；对部分分支还会每轮询一次就再打 `get_epoch`
- 无任何成员响应 → 5 s 后超时，`group.send` 抛 `StateError`

---

## 4. 密码学计算开销（非瓶颈）

- **P2P `prekey_ecdh_v2`** 加密（`e2ee.py:486-594`）：4× ECDH P-256 + 1× HKDF + 1× AES-GCM + 1× ECDSA + prekey 签名验证
  - 桌面 ~3–5 ms，移动端 ~5–10 ms
- **群消息** 加密：1× HKDF + 1× AES-GCM + 1× ECDSA ≈ 1 ms

CPU 不是瓶颈。瓶颈是 **RPC 往返次数** + **在线成员硬依赖**。

---

## 5. 放大因素拆解

| # | 层次 | 描述 |
|---|---|---|
| 1 | 协议层 | `get_epoch` 预检 + 成员 floor 检查 + CAS 轮换——强一致性把一次发送拆成多次 RPC |
| 2 | 实现层 | `_send_group_encrypted` 三条代码路径重复调用 `get_epoch`，无 snapshot 合并 |
| 3 | 协议层 | 密钥恢复是阻塞同步（最多 5 s），超时即整体失败 |
| 4 | 协议层 | `group_secret` 分发硬绑定 P2P E2EE 通道 → 对端**此刻必须在线**才能响应 key_request |

---

## 6. 移动端后台断连放大链路

```
1. Alice 踢了 Bob → 触发 epoch 轮换
2. 其他成员手机全部切后台 → 无人在线接收 Alice 的 P2P 分发
3. Alice 也切后台 → Carol 上线收到新 epoch 消息 → 解密失败
4. Carol 发 e2ee.group_key_request → 群内无人在线响应
5. 5 s 超时 → Carol 永远无法解密后续群消息
```

根源：**协议禁止服务端持有 group_secret**（`08-AUN-E2EE-Group.md` §1.2），而 P2P 分发通道在移动端场景下"在线重合窗口"接近 0。

---

## 7. 修复方向（待评估，未立项）

### 短期止血（纯实现，不动协议）

- `_send_group_encrypted` 合并 `get_epoch` 重复调用：**5 RPC → 2 RPC**
- 密钥恢复轮询期间不再重复打 `get_epoch`

### 根治（协议层变更，需讨论）

- **Group Prekey / Epoch Mailbox**：轮换后把 `group_secret` 用每成员身份公钥（或 prekey）加密，存服务端「离线邮箱」，成员上线自取
  - 打破"必须在线成员响应 key_request"的硬依赖
  - 保持服务端零信任（存的是每成员独立加密的副本，服务端看不到明文）
  - 类比 P2P 的 prekey 思路，自然外推到群密钥分发
- **推送唤醒兜底**：轮换事件通过 push 唤醒目标成员客户端完成密钥同步（依赖前端/Channel 支持）

---

## 8. 相关代码位置索引

| 路径 | 作用 |
|---|---|
| `aun-sdk-core/python/src/aun_core/client.py:772-829` | P2P 加密发送 |
| `aun-sdk-core/python/src/aun_core/client.py:1055-1106` | 群组加密发送 |
| `aun-sdk-core/python/src/aun_core/client.py:1285-1428` | 群密钥恢复 + epoch 预检 |
| `aun-sdk-core/python/src/aun_core/client.py:2654-2732` | `_fetch_peer_cert`（PKI 全链） |
| `aun-sdk-core/python/src/aun_core/client.py:2734-2795` | `_fetch_peer_prekeys` |
| `aun-sdk-core/python/src/aun_core/e2ee.py:434-594` | P2P 加密实现（四路 ECDH） |
| `aun-sdk-core/python/src/aun_core/e2ee.py:2355-2722` | 群组 E2EE 实现 |
| `aun-sdk-core/docs/protocol/08-AUN-E2EE.md` | P2P E2EE 规范 |
| `aun-sdk-core/docs/protocol/08-AUN-E2EE-Group.md` | 群组 E2EE 规范 |
