package secretstore

import "testing"

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
