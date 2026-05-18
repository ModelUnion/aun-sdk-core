package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDFDerive 计算 HKDF-SHA256(IKM, salt, info, length)。
//
// 当 salt 为空时，按 RFC 5869 §2.2 默认填充为 HashLen 个零字节（SHA-256 即 32 字节）。
// 这与 Python `cryptography` HKDF 在 salt=None 时的行为一致。
func HKDFDerive(ikm, salt, info []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("HKDF: length 必须为正，实际 %d", length)
	}
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("HKDF: 读取派生输出失败: %w", err)
	}
	return out, nil
}
