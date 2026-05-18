package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// goldenHKDFVector 兼容两种字段格式：
//   - rfc5869_case1.json 用 *_hex
//   - aun_v2_*.json 用 ikm_b64/salt_b64 + info（明文字符串）
type goldenHKDFVector struct {
	Description string `json:"description"`

	IKMHex   string `json:"ikm_hex,omitempty"`
	SaltHex  string `json:"salt_hex,omitempty"`
	InfoHex  string `json:"info_hex,omitempty"`
	IKMB64   string `json:"ikm_b64,omitempty"`
	SaltB64  string `json:"salt_b64,omitempty"`
	InfoText string `json:"info,omitempty"`

	Length          int    `json:"length"`
	ExpectedOKMB64  string `json:"expected_okm_b64"`
}

func (g *goldenHKDFVector) decode(t *testing.T) (ikm, salt, info []byte) {
	t.Helper()
	switch {
	case g.IKMHex != "":
		var err error
		if ikm, err = hex.DecodeString(g.IKMHex); err != nil {
			t.Fatalf("decode ikm_hex: %v", err)
		}
		if salt, err = hex.DecodeString(g.SaltHex); err != nil {
			t.Fatalf("decode salt_hex: %v", err)
		}
		if info, err = hex.DecodeString(g.InfoHex); err != nil {
			t.Fatalf("decode info_hex: %v", err)
		}
	case g.IKMB64 != "":
		var err error
		if ikm, err = base64.StdEncoding.DecodeString(g.IKMB64); err != nil {
			t.Fatalf("decode ikm_b64: %v", err)
		}
		if g.SaltB64 != "" {
			if salt, err = base64.StdEncoding.DecodeString(g.SaltB64); err != nil {
				t.Fatalf("decode salt_b64: %v", err)
			}
		}
		info = []byte(g.InfoText)
	default:
		t.Fatalf("golden 向量缺少 IKM 字段：%+v", g)
	}
	return
}

func TestHKDFGoldenVectors(t *testing.T) {
	dir := filepath.Join("testdata", "golden", "hkdf")
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
				t.Fatalf("读取 %s 失败: %v", name, err)
			}
			var g goldenHKDFVector
			if err := json.Unmarshal(data, &g); err != nil {
				t.Fatalf("解析 %s 失败: %v", name, err)
			}

			ikm, salt, info := g.decode(t)
			expected, err := base64.StdEncoding.DecodeString(g.ExpectedOKMB64)
			if err != nil {
				t.Fatalf("解码 expected_okm_b64 失败: %v", err)
			}

			got, err := HKDFDerive(ikm, salt, info, g.Length)
			if err != nil {
				t.Fatalf("HKDFDerive 失败: %v", err)
			}
			if !bytes.Equal(got, expected) {
				t.Fatalf("HKDF 输出不匹配\n期望: %x\n实际: %x", expected, got)
			}
		})
		count++
	}
	if count == 0 {
		t.Fatal("未找到任何 HKDF golden 向量")
	}
}

// TestHKDFEmptySalt 验证 salt 为空时填充 32 字节零值（与显式传入相同）。
func TestHKDFEmptySalt(t *testing.T) {
	ikm := []byte("test-ikm")
	info := []byte("AUN-V2")
	a, err := HKDFDerive(ikm, nil, info, 32)
	if err != nil {
		t.Fatalf("HKDFDerive(nil salt) 失败: %v", err)
	}
	b, err := HKDFDerive(ikm, make([]byte, 32), info, 32)
	if err != nil {
		t.Fatalf("HKDFDerive(zero salt) 失败: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("空 salt 与全零 salt 输出不一致\n空: %x\n零: %x", a, b)
	}
}
