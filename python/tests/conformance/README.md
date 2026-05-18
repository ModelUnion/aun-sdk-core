# AUN E2EE V2 Conformance 测试

> 本目录是 V2 协议跨语言一致性的**唯一权威来源**。
> Python 是参考实现，golden/ 是其它 SDK 的对齐目标。

## 目录结构

```
conformance/
├── README.md                      # 本文件
├── test_canonical.py              # canonical_json 测试
├── test_ecdh.py                   # ECDH 共享秘密
├── test_hkdf.py                   # HKDF-SHA256
├── test_aead.py                   # AES-256-GCM
├── test_ecdsa.py                  # ECDSA-SHA256 RAW (RFC 6979)
├── test_recipients_digest.py      # recipients_digest 计算
├── test_state_commitment.py       # state_commitment 计算
├── test_3dh.py                    # 3DH 完整路径
├── test_1dh.py                    # 1DH 完整路径
├── generate_golden_outputs.py     # 跑通后导出 golden 文件
└── golden/                        # 固化向量（commit 到仓库）
    ├── canonical/
    ├── ecdh/
    ├── hkdf/
    ├── aead/
    ├── ecdsa/
    ├── recipients_digest/
    ├─ state_commitment/
    ├── 3dh/
    └── 1dh/
```

## 使用方法

### 运行 conformance 测试（Python 参考实现）

```bash
cd aun-sdk-core/python
python -X utf8 -m pytest tests/conformance/ -v --tb=short
```

### 生成 golden 输出

```bash
cd aun-sdk-core/python
python -X utf8 tests/conformance/generate_golden_outputs.py
```

### 其它 SDK 加载 golden 自检

各 SDK 在自己的 `tests/conformance/` 下实现 loader，加载 `../python/tests/conformance/golden/` 中的 JSON 文件，断言本 SDK 输出与 golden 字节级一致。

## 测试用例设计原则

1. **固定输入**：所有测试用例使用硬编码的密钥 / 明文 / nonce，不使用随机数
2. **确定性输出**：ECDSA 使用 RFC 6979 deterministic 签名，保证同输入同输出
3. **字节级一致**：golden 文件中的 expected output 是 base64 编码的精确字节
4. **覆盖边界**：每个 category 至少覆盖正常路径 + 边界情况
5. **自描述**：每个 golden JSON 文件含 description 字段说明测试意图

## 协议规范引用

- canonical_json: 规范 §10.2
- ECDH / HKDF / AEAD / ECDSA: 规范 §3
- recipients_digest: 规范 §10.3
- state_commitment: 规范 §6.2
- 3DH / 1DH: 规范 §3.2
