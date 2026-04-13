# AID 托管（Custody）— HTTP API Manual

AID Custody 是 AUN AP 提供的**可选增值服务**，不属于 AUN 协议本身。它为用户提供基于手机号的 AID 密钥托管、备份与恢复能力。

**服务地址：** `https://aid_custody.{issuer_domain}:{port}`

**核心流程：** AID 登录 → 绑定手机号 + 备份加密私钥 → 凭手机号+验证码恢复

> 私钥由客户端自行加密后上传，custody 服务只存储密文，不知道加密算法和密码。

---

## 端点索引

| 端点 | 方法 | 认证 | 说明 |
|------|------|------|------|
| [/custody/accounts/send-code](#send-code) | POST | aun_token | 发送手机验证码 |
| [/custody/accounts/bind-phone](#bind-phone) | POST | aun_token | 验证码 + 绑定手机号 + 备份 |
| [/custody/accounts/restore-phone](#restore-phone) | POST | 无 | 手机号 + 验证码 + AID → 恢复 |

---

## send-code

发送手机号验证码（用于绑定场景）。

### 请求

```
POST /custody/accounts/send-code
Authorization: Bearer <aun_token>
Content-Type: application/json
```

```json
{
    "phone": "+8613800138000"
}
```

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `phone` | string | 是 | E.164 格式手机号（如 `+8613800138000`） |

### 响应

```json
{
    "request_id": "bind-phone-a1b2c3d4e5f6",
    "phone": "+8613800138000",
    "provider": "mock",
    "expires_in_seconds": 300,
    "purpose": "bind-phone",
    "debug_code": "123456"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `request_id` | string | 本次验证码请求 ID |
| `phone` | string | 规范化后的手机号 |
| `expires_in_seconds` | integer | 验证码有效期（秒） |
| `debug_code` | string | 开发环境返回验证码明文，生产环境为空 |

### 错误

| HTTP 状态 | 错误码 | 说明 |
|-----------|--------|------|
| 400 | `invalid_phone` | 手机号格式无效 |
| 429 | `code_rate_limited` | 发送冷却时间未到 |
| 429 | `rate_limited` | 请求频率超限 |

---

## bind-phone

验证手机验证码，绑定手机号到当前 AID，同时备份证书和加密私钥。

### 请求

```
POST /custody/accounts/bind-phone
Authorization: Bearer <aun_token>
Content-Type: application/json
```

```json
{
    "phone": "+8613800138000",
    "code": "123456",
    "cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "key": "<客户端加密后的私钥密文>",
    "metadata": {
        "encryption": "aes-256-gcm",
        "kdf": "argon2id",
        "kdf_params": {"m": 65536, "t": 3, "p": 4},
        "device": "iPhone 15",
        "note": "主密钥备份"
    }
}
```

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `phone` | string | 是 | E.164 格式手机号 |
| `code` | string | 是 | 6 位数字验证码 |
| `cert` | string | 是 | AID 证书 PEM |
| `key` | string | 是 | **客户端加密后的私钥密文** |
| `metadata` | object | 否 | 加密参数和备注（custody 不解读，原样存储） |

> **私钥加密：** custody 不知道加密算法和密码。客户端应使用自选算法（如 AES-256-GCM + Argon2id KDF）加密私钥后上传。`metadata` 中记录加密参数供恢复时使用。

### 响应

```json
{
    "binding": {
        "provider": "phone",
        "external_subject": "+8613800138000",
        "aid": "alice.aid.com",
        "status": "active",
        "created_at": 1713000000000,
        "updated_at": 1713000000000
    },
    "backup_result": {
        "aid": "alice.aid.com",
        "status": "active",
        "source": "backup",
        "cert_sn": "1a2b3c4d",
        "curve": "P-256",
        "key_encrypted": true,
        "metadata": {"encryption": "aes-256-gcm", "backup": true}
    }
}
```

### 错误

| HTTP 状态 | 错误码 | 说明 |
|-----------|--------|------|
| 400 | `invalid_code` | 验证码无效或已过期 |
| 400 | `invalid_crt` | 证书 PEM 格式无效 |
| 403 | `wrong_auth_type` | 需要 AID 登录（aun_token） |

---

## restore-phone

凭手机号 + 验证码 + AID 恢复备份的证书和加密私钥。**不需要登录。**

### 请求

```
POST /custody/accounts/restore-phone
Content-Type: application/json
```

```json
{
    "phone": "+8613800138000",
    "code": "123456",
    "aid": "alice.aid.com"
}
```

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `phone` | string | 是 | E.164 格式手机号 |
| `code` | string | 是 | 6 位数字验证码 |
| `aid` | string | 是 | 要恢复的 AID |

### 响应

```json
{
    "aid": "alice.aid.com",
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "key_pem": "<加密后的私钥密文>",
    "key_encrypted": true,
    "cert_sn": "1a2b3c4d",
    "curve": "P-256",
    "metadata": {
        "encryption": "aes-256-gcm",
        "kdf": "argon2id",
        "kdf_params": {"m": 65536, "t": 3, "p": 4},
        "device": "iPhone 15",
        "backup": true
    }
}
```

> 客户端收到后，使用自己的密码 + metadata 中记录的 KDF 参数解密 `key_pem`。

### 错误

| HTTP 状态 | 错误码 | 说明 |
|-----------|--------|------|
| 400 | `invalid_code` | 验证码无效或已过期 |
| 403 | `phone_not_bound` | 该手机号未绑定到此 AID |
| 404 | `backup_not_found` | 未找到此 AID 的备份数据 |

---

## 认证说明

### aun_token

AID 通过 auth 模块登录后获得的 ES256 JWT，通过 `Authorization: Bearer <token>` 头携带。

- **签发方：** auth 模块（`iss=kite-identity`）
- **验证方：** custody 服务用 auth 公钥本地 ES256 验签
- **用途：** `send-code` 和 `bind-phone` 端点需要 aun_token 证明 AID 身份

### restore-phone 无需认证

恢复场景中，用户可能已丢失私钥，无法做 AID 登录。因此 `restore-phone` 端点仅凭手机号+验证码+绑定关系来验证身份，不需要任何 token。

---

## SDK 封装

Python SDK 通过 `AUNClient.custody` namespace 提供便捷方法：

```python
# 发送绑定验证码（需先 AID 登录）
result = await client.custody.send_code(phone="+8613800138000")

# 绑定手机号 + 备份（需 AID 登录 + 验证码）
result = await client.custody.bind_phone(
    phone="+8613800138000",
    code="123456",
    cert=cert_pem,
    key=encrypted_key,
    metadata={"encryption": "aes-256-gcm"}
)

# 手机号恢复（无需登录）
result = await client.custody.restore_phone(
    phone="+8613800138000",
    code="123456",
    aid="alice.aid.com"
)
```
