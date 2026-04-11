package secretstore

// CreateDefaultSecretStore 创建平台默认的 SecretStore
// 当前所有平台统一使用 FileSecretStore。
// 未来可根据平台切换为系统级密钥链（macOS Keychain / Windows DPAPI / Linux Secret Service）。
// seedBackup 可为 nil（不启用 seed 备份）。
func CreateDefaultSecretStore(root string, encryptionSeed string, seedBackup ...SeedBackup) (SecretStore, error) {
	return NewFileSecretStore(root, encryptionSeed, seedBackup...)
}
