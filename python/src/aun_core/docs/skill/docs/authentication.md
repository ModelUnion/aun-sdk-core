# 认证流程

0.4.x 将身份管理从 `AUNClient` 拆到 `AIDStore`。注册、加载、认证、连接的边界如下：

1. `AIDStore.register(aid)` 生成本地密钥、申请证书并落盘。
2. `AIDStore.load(aid)` 从本地加载 AID 值对象。
3. `AUNClient(aid)` 或 `client.load_identity(aid)` 注入身份。
4. `client.authenticate()` 获取 token；通常可省略，由 `connect()` 自动完成。
5. `client.connect(options)` 建立 Gateway WebSocket 会话。

## 注册与加载

```python
store = AIDStore(aun_path="~/.aun/myapp", encryption_seed="")

loaded = store.load("alice.agentid.pub")
if not loaded["ok"]:
    registered = await store.register("alice.agentid.pub")
    if not registered["ok"]:
        raise RuntimeError(registered["error"]["message"])
    loaded = store.load("alice.agentid.pub")

me = loaded["data"]["aid"]
```

本地数据保存在 `{aun_path}/AIDs/{aid}/`。不要手工删除单个密钥或证书文件；需要诊断时使用 `store.diagnose(aid)`。

## 认证与连接

```python
client = AUNClient(me)

auth = await client.authenticate()  # 可选；connect() 会按需自动认证
print(auth["access_token"], auth["gateway"])

await client.connect({
    "slot_id": "main",
    "connection_kind": "long",
    "auto_reconnect": True,
})
```

认证使用两阶段挑战响应：客户端验证服务端证书链，再用本地 AID 私钥签名挑战。私钥不会离开本机。

## 网关发现

注册、解析和认证都会按 AID issuer 自动发现 Gateway：

```text
GET https://{aid}/.well-known/aun-gateway
GET https://gateway.{issuer-domain}/.well-known/aun-gateway
```

`verify_ssl` 在 `AIDStore` 构造时配置；自动模式下由 `AUN_ENV` 优先、其次 `KITE_ENV` 决定。值为 `development` / `dev` / `local` 时关闭校验，其余情况开启。

## 常见恢复

- 本地无身份：调用 `store.register(aid)` 后重新 `store.load(aid)`。
- 本地有密钥但证书缺失：`store.register(aid)` 会尝试恢复匹配的证书。
- 本地证书与远端不匹配：`store.diagnose(aid)` 会返回 `registered_remote` 或修复建议；确认后再考虑 `rekey`。

更多连接状态、slot 和 agent.md 入口见 [sdk-core/04-连接与认证.md](../sdk-core/04-连接与认证.md)。
