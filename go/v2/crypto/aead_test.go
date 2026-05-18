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

type goldenAEADBasic struct {
	Description string `json:"description"`
	KeyHex      string `json:"key_hex"`
	NonceHex    string `json:"nonce_hex"`
	PlaintextB64 string `json:"plaintext_b64"`
	AADB64       string `json:"aad_b64"`
	ExpectedCiphertextB64 string `json:"expected_ciphertext_b64"`
	ExpectedTagB64        string `json:"expected_tag_b64"`
}

type goldenAEADWrap struct {
	Description string `json:"description"`
	WrapKeyB64  string `json:"wrap_key_b64"`
	WrapNonceB64 string `json:"wrap_nonce_b64"`
	MasterKeyB64 string `json:"master_key_b64"`
	ExpectedWrappedKeyB64 string `json:"expected_wrapped_key_b64"`
}

func TestAEADBasicEncrypt(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "golden", "aead", "basic_encrypt.json"))
	if err != nil {
		t.Fatalf("读取 golden 失败: %v", err)
	}
	var g goldenAEADBasic
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatalf("解析 golden 失败: %v", err)
	}

	key, err := hex.DecodeString(g.KeyHex)
	if err != nil {
		t.Fatalf("解码 key_hex: %v", err)
	}
	nonce, err := hex.DecodeString(g.NonceHex)
	if err != nil {
		t.Fatalf("解码 nonce_hex: %v", err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(g.PlaintextB64)
	if err != nil {
		t.Fatalf("解码 plaintext: %v", err)
	}
	aad, err := base64.StdEncoding.DecodeString(g.AADB64)
	if err != nil {
		t.Fatalf("解码 aad: %v", err)
	}
	expectedCT, err := base64.StdEncoding.DecodeString(g.ExpectedCiphertextB64)
	if err != nil {
		t.Fatalf("解码 expected_ciphertext: %v", err)
	}
	expectedTag, err := base64.StdEncoding.DecodeString(g.ExpectedTagB64)
	if err != nil {
		t.Fatalf("解码 expected_tag: %v", err)
	}

	ct, tag, err := AESGCMEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("AESGCMEncrypt: %v", err)
	}
	if !bytes.Equal(ct, expectedCT) {
		t.Fatalf("ciphertext 不匹配\n期望: %x\n实际: %x", expectedCT, ct)
	}
	if !bytes.Equal(tag, expectedTag) {
		t.Fatalf("tag 不匹配\n期望: %x\n实际: %x", expectedTag, tag)
	}

	// 解密回环
	pt, err := AESGCMDecrypt(key, nonce, ct, tag, aad)
	if err != nil {
		t.Fatalf("AESGCMDecrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("解密结果不匹配\n期望: %x\n实际: %x", plaintext, pt)
	}
}

func TestAEADWrapMasterKey(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "golden", "aead", "wrap_master_key.json"))
	if err != nil {
		t.Fatalf("读取 golden 失败: %v", err)
	}
	var g goldenAEADWrap
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatalf("解析 golden 失败: %v", err)
	}

	wrapKey, _ := base64.StdEncoding.DecodeString(g.WrapKeyB64)
	wrapNonce, _ := base64.StdEncoding.DecodeString(g.WrapNonceB64)
	masterKey, _ := base64.StdEncoding.DecodeString(g.MasterKeyB64)
	expectedWrapped, _ := base64.StdEncoding.DecodeString(g.ExpectedWrappedKeyB64)

	// V2 wrapped_key = ciphertext || tag，aad 为空
	ct, tag, err := AESGCMEncrypt(wrapKey, wrapNonce, masterKey, nil)
	if err != nil {
		t.Fatalf("AESGCMEncrypt: %v", err)
	}
	got := append(append([]byte{}, ct...), tag...)
	if !bytes.Equal(got, expectedWrapped) {
		t.Fatalf("wrapped_key 不匹配\n期望: %x\n实际: %x", expectedWrapped, got)
	}

	// 解密回环
	if len(got) < AESGCMTagLen {
		t.Fatal("wrapped_key 长度异常")
	}
	n := len(got) - AESGCMTagLen
	pt, err := AESGCMDecrypt(wrapKey, wrapNonce, got[:n], got[n:], nil)
	if err != nil {
		t.Fatalf("AESGCMDecrypt: %v", err)
	}
	if !bytes.Equal(pt, masterKey) {
		t.Fatalf("解密 master_key 不匹配")
	}
}

// TestAEADTamper 验证篡改 ciphertext / tag / aad 会触发解密失败。
func TestAEADTamper(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	nonce := bytes.Repeat([]byte{0x22}, 12)
	pt := []byte("AUN V2 message")
	aad := []byte("aad-bytes")

	ct, tag, err := AESGCMEncrypt(key, nonce, pt, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// 篡改 ct
	bad := append([]byte{}, ct...)
	bad[0] ^= 0x01
	if _, err := AESGCMDecrypt(key, nonce, bad, tag, aad); err == nil {
		t.Fatal("篡改 ct 应解密失败")
	}
	// 篡改 tag
	badTag := append([]byte{}, tag...)
	badTag[0] ^= 0x01
	if _, err := AESGCMDecrypt(key, nonce, ct, badTag, aad); err == nil {
		t.Fatal("篡改 tag 应解密失败")
	}
	// 篡改 aad
	if _, err := AESGCMDecrypt(key, nonce, ct, tag, []byte("other-aad")); err == nil {
		t.Fatal("篡改 aad 应解密失败")
	}
}
