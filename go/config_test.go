package aun

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDefaultConfig 验证默认配置值
func TestDefaultConfig(t *testing.T) {
	t.Setenv("AUN_ENV", "production")
	cfg := DefaultConfig()
	home, _ := os.UserHomeDir()

	if cfg.AUNPath != filepath.Join(home, ".aun") {
		t.Errorf("默认 AUNPath 不正确: %s", cfg.AUNPath)
	}
	if !cfg.GroupE2EE {
		t.Error("默认 GroupE2EE 应为 true")
	}
	if cfg.RotateOnJoin {
		t.Error("默认 RotateOnJoin 应为 false")
	}
	if cfg.EpochAutoRotateInterval != 0 {
		t.Error("默认 EpochAutoRotateInterval 应为 0")
	}
	if cfg.OldEpochRetentionSeconds != 604800 {
		t.Errorf("默认 OldEpochRetentionSeconds 应为 604800, 实际: %d", cfg.OldEpochRetentionSeconds)
	}
	if !cfg.VerifySSL {
		t.Error("默认 VerifySSL 应为 true")
	}
	if !cfg.RequireForwardSecrecy {
		t.Error("默认 RequireForwardSecrecy 应为 true")
	}
	if cfg.ReplayWindowSeconds != 300 {
		t.Errorf("默认 ReplayWindowSeconds 应为 300, 实际: %d", cfg.ReplayWindowSeconds)
	}
}

// TestConfigFromMap 验证从字典构建配置
func TestConfigFromMap(t *testing.T) {
	t.Setenv("AUN_ENV", "development")
	raw := map[string]any{
		"aun_path":                    "/custom/path",
		"root_ca_path":                "/ca/root.pem",
		"encryption_seed":             "test-seed",
		"discovery_port":              20001,
		"group_e2ee":                  false,
		"rotate_on_join":              true,
		"epoch_auto_rotate_interval":  3600,
		"old_epoch_retention_seconds": 86400,
		"verify_ssl":                  false,
		"require_forward_secrecy":     false,
		"replay_window_seconds":       600,
	}
	cfg := ConfigFromMap(raw)

	if cfg.AUNPath != "/custom/path" {
		t.Errorf("AUNPath 不正确: %s", cfg.AUNPath)
	}
	if cfg.RootCAPath != "/ca/root.pem" {
		t.Errorf("RootCAPath 不正确: %s", cfg.RootCAPath)
	}
	if cfg.SeedPassword != "test-seed" {
		t.Errorf("SeedPassword 不正确: %s", cfg.SeedPassword)
	}
	if cfg.DiscoveryPort != 20001 {
		t.Errorf("DiscoveryPort 不正确: %d", cfg.DiscoveryPort)
	}
	if !cfg.GroupE2EE {
		t.Error("GroupE2EE 是必备能力，应始终为 true")
	}
	if !cfg.RotateOnJoin {
		t.Error("RotateOnJoin 应为 true")
	}
	if cfg.EpochAutoRotateInterval != 3600 {
		t.Errorf("EpochAutoRotateInterval 不正确: %d", cfg.EpochAutoRotateInterval)
	}
	if cfg.OldEpochRetentionSeconds != 86400 {
		t.Errorf("OldEpochRetentionSeconds 不正确: %d", cfg.OldEpochRetentionSeconds)
	}
	if cfg.VerifySSL {
		t.Error("VerifySSL 应为 false")
	}
	if cfg.RequireForwardSecrecy {
		t.Error("RequireForwardSecrecy 应为 false")
	}
	if cfg.ReplayWindowSeconds != 600 {
		t.Errorf("ReplayWindowSeconds 不正确: %d", cfg.ReplayWindowSeconds)
	}
}

func TestConfigFromMapSupportsCamelCaseAliases(t *testing.T) {
	raw := map[string]any{
		"aunPath":                  "/camel/path",
		"rootCaPath":               "/ca/camel.pem",
		"encryptionSeed":           "camel-seed",
		"discoveryPort":            21001,
		"groupE2EE":                false,
		"rotateOnJoin":             true,
		"epochAutoRotateInterval":  120,
		"oldEpochRetentionSeconds": 30,
		"verifySSL":                false,
		"requireForwardSecrecy":    false,
		"replayWindowSeconds":      42,
	}
	cfg := ConfigFromMap(raw)

	if cfg.AUNPath != "/camel/path" {
		t.Fatalf("AUNPath 不正确: %s", cfg.AUNPath)
	}
	if cfg.RootCAPath != "/ca/camel.pem" {
		t.Fatalf("RootCAPath 不正确: %s", cfg.RootCAPath)
	}
	if cfg.SeedPassword != "camel-seed" {
		t.Fatalf("SeedPassword 不正确: %s", cfg.SeedPassword)
	}
	if cfg.DiscoveryPort != 21001 {
		t.Fatalf("DiscoveryPort 不正确: %d", cfg.DiscoveryPort)
	}
	if !cfg.GroupE2EE {
		t.Fatal("GroupE2EE 应始终为 true（必备能力）")
	}
	if !cfg.RotateOnJoin {
		t.Fatal("RotateOnJoin 应为 true")
	}
	if cfg.EpochAutoRotateInterval != 120 {
		t.Fatalf("EpochAutoRotateInterval 不正确: %d", cfg.EpochAutoRotateInterval)
	}
	if cfg.OldEpochRetentionSeconds != 30 {
		t.Fatalf("OldEpochRetentionSeconds 不正确: %d", cfg.OldEpochRetentionSeconds)
	}
	if cfg.VerifySSL {
		t.Fatal("VerifySSL 应为 false")
	}
	if cfg.RequireForwardSecrecy {
		t.Fatal("RequireForwardSecrecy 应为 false")
	}
	if cfg.ReplayWindowSeconds != 42 {
		t.Fatalf("ReplayWindowSeconds 不正确: %d", cfg.ReplayWindowSeconds)
	}
}

// TestConfigIgnoresUnknownKeys 验证未知键被忽略，不影响默认值
func TestConfigIgnoresUnknownKeys(t *testing.T) {
	t.Setenv("AUN_ENV", "production")
	raw := map[string]any{
		"unknown_key_1":   "value",
		"unknown_key_2":   42,
		"foo_bar":         true,
		"delivery_mode":   "queue",
		"queue_routing":   "sender_affinity",
		"affinity_ttl_ms": 120000,
	}
	cfg := ConfigFromMap(raw)
	defaults := DefaultConfig()

	if cfg.GroupE2EE != defaults.GroupE2EE {
		t.Error("未知键不应影响 GroupE2EE 默认值")
	}
	if cfg.VerifySSL != defaults.VerifySSL {
		t.Error("未知键不应影响 VerifySSL 默认值")
	}
	if cfg.ReplayWindowSeconds != defaults.ReplayWindowSeconds {
		t.Error("未知键不应影响 ReplayWindowSeconds 默认值")
	}
}

func TestDefaultConfigVerifySSLFollowsDevelopmentEnv(t *testing.T) {
	t.Setenv("AUN_ENV", "development")
	if DefaultConfig().VerifySSL {
		t.Fatal("开发环境默认 VerifySSL 应为 false")
	}
}

func TestDefaultConfigVerifySSLFollowsKITEEnv(t *testing.T) {
	t.Setenv("AUN_ENV", "")
	t.Setenv("KITE_ENV", "development")
	if DefaultConfig().VerifySSL {
		t.Fatal("KITE_ENV=development 时 VerifySSL 应为 false")
	}
}

func TestNormalizeInstanceID(t *testing.T) {
	value, err := NormalizeInstanceID("slot-a_01", "slot_id", false)
	if err != nil {
		t.Fatalf("合法 slot_id 不应报错: %v", err)
	}
	if value != "slot-a_01" {
		t.Fatalf("slot_id 规范化结果不正确: %s", value)
	}

	empty, err := NormalizeInstanceID("", "slot_id", true)
	if err != nil {
		t.Fatalf("允许空 slot_id 时不应报错: %v", err)
	}
	if empty != "" {
		t.Fatalf("空 slot_id 规范化结果应为空字符串: %q", empty)
	}

	if _, err := NormalizeInstanceID("slot with space", "slot_id", false); err == nil {
		t.Fatal("非法 slot_id 应报错")
	}
	if _, err := NormalizeInstanceID("", "device_id", false); err == nil {
		t.Fatal("空 device_id 应报错")
	}
}

func TestGetDeviceIDPersistsStableValue(t *testing.T) {
	root := t.TempDir()

	first := GetDeviceID(root)
	if first == "" {
		t.Fatal("首次获取 device_id 不应为空")
	}
	if _, err := NormalizeInstanceID(first, "device_id", false); err != nil {
		t.Fatalf("首次生成的 device_id 非法: %v", err)
	}

	second := GetDeviceID(root)
	if second != first {
		t.Fatalf("同一目录的 device_id 应保持稳定: first=%s second=%s", first, second)
	}

	data, err := os.ReadFile(filepath.Join(root, ".device_id"))
	if err != nil {
		t.Fatalf("读取 .device_id 失败: %v", err)
	}
	if string(data) != first {
		t.Fatalf(".device_id 文件内容不正确: %q", string(data))
	}
}

func TestGetDeviceIDRepairsInvalidStoredValue(t *testing.T) {
	root := t.TempDir()
	deviceIDPath := filepath.Join(root, ".device_id")
	if err := os.WriteFile(deviceIDPath, []byte("bad id with spaces"), 0o600); err != nil {
		t.Fatalf("写入非法 .device_id 失败: %v", err)
	}

	repaired := GetDeviceID(root)
	if repaired == "" {
		t.Fatal("修复后的 device_id 不应为空")
	}
	if repaired == "bad id with spaces" {
		t.Fatal("非法 .device_id 应被替换")
	}
	if _, err := NormalizeInstanceID(repaired, "device_id", false); err != nil {
		t.Fatalf("修复后的 device_id 非法: %v", err)
	}

	stored, err := os.ReadFile(deviceIDPath)
	if err != nil {
		t.Fatalf("读取修复后的 .device_id 失败: %v", err)
	}
	if string(stored) != repaired {
		t.Fatalf("修复后的 .device_id 文件未更新: %q", string(stored))
	}
}
