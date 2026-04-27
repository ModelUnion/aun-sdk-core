# 元信息 — RPC Manual

## 方法索引

| 方法 | 说明 |
|------|------|
| [meta.ping](#metaping) | 心跳检测 |
| [meta.status](#metastatus) | 查询连接状态 |
| [meta.trust_roots](#metatrust_roots) | 获取信任根证书 |

---

## meta.ping

心跳检测。SDK Core 自动调用以保持连接活性，也可手动调用验证连接是否正常。

### 参数

无。

> **注意**：`timestamp` 参数**不会被回显**，服务端始终返回自身当前时间戳。

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `pong` | boolean | 固定为 `true` |
| `timestamp` | integer | 服务端当前 Unix 时间戳（秒） |

### 示例

```python
result = await client.call("meta.ping", {})
print(result)  # {"pong": true, "timestamp": ...}
```

---

## meta.status

查询当前连接的状态信息。

### 参数

无。

### 响应

当前服务实现由 Gateway 本地处理 `meta.status`，返回的是**简化 Gateway 连接状态**，不是完整的 peer/relay 诊断结构。

| 字段 | 类型 | 说明 |
|------|------|------|
| `mode` | string | 当前连接模式。现实现固定返回 `"gateway"` |
| `aid` | string | 当前会话认证后的 AID |
| `role` | string | 当前会话角色 |
| `connected_at` | integer | 会话建立时间戳（毫秒） |
| `protocol_version` | string | 协议版本，当前为 `"1.0"` |

> **实现事实**：Python SDK 当前也只实现 Gateway 拓扑；`peer` / `relay` 拓扑在 Python SDK 中尚未实现，不应把 `meta.status` 当作可稳定返回完整 peer/relay 诊断结构的接口。
> 客户端仍应容忍未知字段和未来扩展字段。

### 示例

```python
status = await client.call("meta.status", {})
print(f"模式: {status['mode']}")
```

---

## meta.trust_roots

获取当前服务端缓存的受信根证书列表。Gateway 内部转发给 `ca.get_trust_roots`。

该 RPC 适合已连接客户端查询。首次信任根更新应优先使用公开 HTTP 端点 `GET https://trust.aun.network/.well-known/aun/trust-roots.json`，不可达时可使用 Issuer PKI 泛域名端点 `GET https://pki.{issuer}/trust-root.json` 或 Gateway 镜像 `GET https://gateway.{issuer}/pki/trust-roots.json`。无论来源是 RPC 还是 HTTP，客户端导入前都必须验证 `authority_signature`。

Issuer PKI 泛域名服务还必须公开 `GET https://pki.{issuer}/root.crt`，用于下载该 issuer 证书链锚定的 Root CA PEM。客户端通过 `client.meta.update_issuer_root_cert(issuer)` 更新指定 issuer 的根证书时，必须先确认该证书指纹存在于已验签的受信根列表中。

### 参数

无参数。

### 响应

```json
{
  "version": 2,
  "issued_at": "2026-03-15T10:00:00Z",
  "next_update": "2026-03-16T10:00:00Z",
  "authority_signature": "MEUCIQDx...",
  "root_cas": [
    {
      "id": "root-ca-001",
      "name": "AUN Root CA A",
      "organization": "Organization A",
      "certificate": "-----BEGIN CERTIFICATE-----\n...",
      "fingerprint_sha256": "a1b2c3d4...",
      "status": "active",
      "crl_url": "http://crl.rootca-a.example/root.crl",
      "ocsp_url": "http://ocsp.rootca-a.example"
    }
  ]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `version` | integer | 受信根列表版本，单调递增 |
| `issued_at` | string | 列表签发时间 |
| `next_update` | string | 建议下次更新时间 |
| `authority_signature` | string | 管理局对规范化列表内容的签名 |
| `root_cas` | array | Root CA 列表 |
| `root_cas[].certificate` | string | PEM 格式 Root CA 证书 |
| `root_cas[].fingerprint_sha256` | string | Root CA 证书 DER SHA-256 指纹 |
| `root_cas[].status` | string | `active` / `retired` / `revoked` 等状态 |

> 兼容说明：早期服务可能仍返回 `roots/count` 简化结构。SDK 可以查询该结构，但默认不得将未签名列表导入本地信任根。
> 导入签名列表时，SDK 还会校验 `version`、`issued_at`、`next_update`、Root CA 证书 CA 约束、有效期和 SHA-256 指纹，并拒绝低于本地已导入版本的回滚列表。

### 示例

```python
trust_list = await client.meta.trust_roots()
client.meta.import_trust_roots(trust_list, authority_cert_pem=authority_cert_pem)
```

---

## Python SDK `MetaNamespace` 辅助方法

以下方法属于 SDK 本地辅助能力，不是新的服务端 RPC；底层只在需要时调用 `meta.trust_roots` 或公开 HTTP 端点。

| 方法 | 说明 |
|------|------|
| `await client.meta.download_trust_roots(...)` | 从管理局权威端点、`pki.{issuer}` 或 Gateway 镜像下载受信根列表 |
| `client.meta.verify_trust_roots(...)` | 验证受信根列表结构、签名、证书 CA 约束、有效期和 SHA-256 指纹 |
| `client.meta.import_trust_roots(...)` | 验证后写入本地 `trust-roots.json` / `trust-roots.pem` 并刷新信任根缓存 |
| `await client.meta.refresh_trust_roots(...)` | 下载、验证并导入受信根列表 |
| `await client.meta.download_issuer_root_cert(issuer, ...)` | 从 `https://pki.{issuer}/root.crt` 下载指定 issuer 的 Root CA PEM |
| `await client.meta.update_issuer_root_cert(issuer, ...)` | 校验证书为自签 Root CA，且指纹存在于已验签受信根列表后导入本地 |

`update_issuer_root_cert()` 不信任下载来源本身；它必须以已验签的受信根列表为准，确认 `root.crt` 的 SHA-256 指纹已列入 `root_cas` 后才能写入本地信任锚。
