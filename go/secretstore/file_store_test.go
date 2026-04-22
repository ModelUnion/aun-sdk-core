package secretstore

import (
	"encoding/base64"
	"testing"
)

type stubSeedBackup struct{}

func (*stubSeedBackup) BackupSeed(seed []byte) {}

func (*stubSeedBackup) RestoreSeed() []byte { return nil }

func TestNewFileSecretStoreIgnoresTypedNilSeedBackup(t *testing.T) {
	dir := t.TempDir()
	var backup *stubSeedBackup

	store, err := NewFileSecretStore(dir, "", backup)
	if err != nil {
		t.Fatalf("NewFileSecretStore 不应因 typed-nil backup 失败: %v", err)
	}
	if store == nil {
		t.Fatal("NewFileSecretStore 不应返回 nil")
	}
}

func TestRevealReturnsErrorOnDecryptionFailure(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileSecretStore(dir, "test-seed", nil)
	if err != nil {
		t.Fatalf("创建 store 失败: %v", err)
	}

	// 先正常 Protect 一个值
	record, err := store.Protect("scope1", "key1", []byte("hello"))
	if err != nil {
		t.Fatalf("Protect 失败: %v", err)
	}

	// 篡改 ciphertext 使解密失败
	record["ciphertext"] = base64.StdEncoding.EncodeToString([]byte("corrupted-data"))

	// Reveal 应返回 error（不是 nil, nil）
	plaintext, revealErr := store.Reveal("scope1", "key1", record)
	if plaintext != nil {
		t.Error("解密失败时 plaintext 应为 nil")
	}
	if revealErr == nil {
		t.Error("解密失败时应返回 error，而非 nil（GO-006）")
	}
}

func TestRevealReturnsErrorOnInvalidBase64(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileSecretStore(dir, "test-seed", nil)
	if err != nil {
		t.Fatalf("创建 store 失败: %v", err)
	}

	record := map[string]any{
		"scheme":     "file_aes",
		"name":       "key1",
		"nonce":      "not-valid-base64!!!",
		"ciphertext": base64.StdEncoding.EncodeToString([]byte("x")),
		"tag":        base64.StdEncoding.EncodeToString([]byte("y")),
	}

	plaintext, revealErr := store.Reveal("scope1", "key1", record)
	if plaintext != nil {
		t.Error("无效 base64 时 plaintext 应为 nil")
	}
	if revealErr == nil {
		t.Error("无效 base64 时应返回 error（GO-006）")
	}
}

func TestRevealReturnsNilNilOnSchemeMismatch(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileSecretStore(dir, "test-seed", nil)
	if err != nil {
		t.Fatalf("创建 store 失败: %v", err)
	}

	// scheme 不匹配 → 正常返回 nil, nil（表示"不是我的 record"）
	record := map[string]any{
		"scheme": "other_scheme",
		"name":   "key1",
	}
	plaintext, revealErr := store.Reveal("scope1", "key1", record)
	if plaintext != nil || revealErr != nil {
		t.Error("scheme 不匹配时应返回 nil, nil")
	}
}
