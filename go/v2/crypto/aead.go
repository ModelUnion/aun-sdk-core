package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const (
	// AESGCMKeyLen AES-256-GCM 密钥长度（32 字节）
	AESGCMKeyLen = 32
	// AESGCMNonceLen GCM nonce 长度（12 字节）
	AESGCMNonceLen = 12
	// AESGCMTagLen GCM tag 长度（16 字节）
	AESGCMTagLen = 16
)

// AESGCMEncrypt 使用 AES-256-GCM 加密 plaintext。
//
// 返回 (ciphertext, tag)；tag 始终为 16 字节。Go 的 cipher.AEAD.Seal 输出
// `ciphertext || tag`，本函数将其拆分以方便上层组装 wrapped_key 等结构。
func AESGCMEncrypt(key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	if len(key) != AESGCMKeyLen {
		return nil, nil, fmt.Errorf("AEAD: 密钥长度无效，期望 %d 字节，实际 %d", AESGCMKeyLen, len(key))
	}
	if len(nonce) != AESGCMNonceLen {
		return nil, nil, fmt.Errorf("AEAD: nonce 长度无效，期望 %d 字节，实际 %d", AESGCMNonceLen, len(nonce))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("AEAD: 创建 AES cipher 失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("AEAD: 创建 GCM 失败: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	if len(sealed) < AESGCMTagLen {
		return nil, nil, fmt.Errorf("AEAD: 输出长度异常 %d < tag(%d)", len(sealed), AESGCMTagLen)
	}
	n := len(sealed) - AESGCMTagLen
	// 复制为独立切片，避免上层共享底层数组引发不可见修改
	ct := make([]byte, n)
	copy(ct, sealed[:n])
	tg := make([]byte, AESGCMTagLen)
	copy(tg, sealed[n:])
	return ct, tg, nil
}

// AESGCMDecrypt 使用 AES-256-GCM 解密并校验 tag。
//
// ciphertext 与 tag 必须分别传入；tag 校验失败返回错误。
func AESGCMDecrypt(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	if len(key) != AESGCMKeyLen {
		return nil, fmt.Errorf("AEAD: 密钥长度无效，期望 %d 字节，实际 %d", AESGCMKeyLen, len(key))
	}
	if len(nonce) != AESGCMNonceLen {
		return nil, fmt.Errorf("AEAD: nonce 长度无效，期望 %d 字节，实际 %d", AESGCMNonceLen, len(nonce))
	}
	if len(tag) != AESGCMTagLen {
		return nil, fmt.Errorf("AEAD: tag 长度无效，期望 %d 字节，实际 %d", AESGCMTagLen, len(tag))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AEAD: 创建 AES cipher 失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("AEAD: 创建 GCM 失败: %w", err)
	}
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)
	plaintext, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("AEAD: 解密/校验失败: %w", err)
	}
	return plaintext, nil
}
