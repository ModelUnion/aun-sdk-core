package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type goldenECDSAVector struct {
	Description       string `json:"description"`
	PrivateKeyB64     string `json:"private_key_b64"`
	PublicKeyDERB64   string `json:"public_key_der_b64"`
	MessageB64        string `json:"message_b64"`
	ExpectedSignature string `json:"expected_signature_b64"`
}

func TestECDSAGoldenVectors(t *testing.T) {
	dir := filepath.Join("testdata", "golden", "ecdsa")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取 golden 目录失败: %v", err)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("读取失败: %v", err)
			}
			var g goldenECDSAVector
			if err := json.Unmarshal(data, &g); err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			priv, _ := base64.StdEncoding.DecodeString(g.PrivateKeyB64)
			pubDER, _ := base64.StdEncoding.DecodeString(g.PublicKeyDERB64)
			msg, _ := base64.StdEncoding.DecodeString(g.MessageB64)
			expected, _ := base64.StdEncoding.DecodeString(g.ExpectedSignature)

			sig, err := ECDSASignRaw(priv, msg)
			if err != nil {
				t.Fatalf("ECDSASignRaw: %v", err)
			}
			if !bytes.Equal(sig, expected) {
				t.Fatalf("签名字节不匹配（RFC 6979 deterministic 必须复现）\n期望: %x\n实际: %x", expected, sig)
			}

			if !ECDSAVerifyRaw(pubDER, sig, msg) {
				t.Fatal("ECDSAVerifyRaw 应返回 true")
			}

			// 篡改消息：验签必须 false
			tampered := append([]byte{}, msg...)
			if len(tampered) > 0 {
				tampered[0] ^= 0x01
			} else {
				tampered = []byte{0x00}
			}
			if ECDSAVerifyRaw(pubDER, sig, tampered) {
				t.Fatal("篡改消息后验签应返回 false")
			}
		})
		count++
	}
	if count == 0 {
		t.Fatal("未找到任何 ECDSA golden 向量")
	}
}

// TestECDSADeterministic 同一私钥+消息两次签名结果应字节一致（RFC 6979）。
func TestECDSADeterministic(t *testing.T) {
	priv := bytes.Repeat([]byte{0x42}, 32)
	msg := []byte("AUN V2 deterministic")
	a, err := ECDSASignRaw(priv, msg)
	if err != nil {
		t.Fatalf("sign a: %v", err)
	}
	b, err := ECDSASignRaw(priv, msg)
	if err != nil {
		t.Fatalf("sign b: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("RFC 6979 应输出确定性签名\na: %x\nb: %x", a, b)
	}
}

// TestECDSAInvalidSigLen 验证签名长度校验。
func TestECDSAInvalidSigLen(t *testing.T) {
	if ECDSAVerifyRaw([]byte{0x00}, make([]byte, 32), []byte("msg")) {
		t.Fatal("非法长度应直接返回 false")
	}
}
