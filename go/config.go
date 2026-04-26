package aun

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/google/uuid"
)

var instanceIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
var devEnvValues = map[string]bool{
	"development": true,
	"dev":         true,
	"local":       true,
}

func NormalizeInstanceID(value any, field string, allowEmpty bool) (string, error) {
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "" {
		if allowEmpty {
			return "", nil
		}
		return "", fmt.Errorf("%s must be a non-empty string", field)
	}
	if !instanceIDPattern.MatchString(text) {
		return "", fmt.Errorf("%s contains unsupported characters", field)
	}
	return text, nil
}

// GetDeviceID 获取或生成本设备的稳定 ID。
// 存储在 {aunRoot}/.device_id（默认 ~/.aun/.device_id）。
// 首次调用时自动生成 UUID 并持久化，后续调用返回同一值。
// 同一台机器上所有 SDK 实例共享同一个 device_id。
func GetDeviceID(aunRoot string) string {
	if aunRoot == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			aunRoot = ".aun"
		} else {
			aunRoot = filepath.Join(home, ".aun")
		}
	}

	// 确保目录存在
	_ = os.MkdirAll(aunRoot, 0o700)

	deviceIDPath := filepath.Join(aunRoot, ".device_id")

	// 尝试读取已有 ID
	data, err := os.ReadFile(deviceIDPath)
	if err == nil {
		stored := strings.TrimSpace(string(data))
		if stored != "" {
			if normalized, normErr := NormalizeInstanceID(stored, "device_id", false); normErr == nil {
				return normalized
			}
		}
	}

	// 生成新 UUID v4
	newID, _ := NormalizeInstanceID(generateUUID4(), "device_id", false)

	// 写入文件
	if err := os.WriteFile(deviceIDPath, []byte(newID), 0o600); err == nil {
		// 非 Windows 平台设置文件权限
		if runtime.GOOS != "windows" {
			_ = os.Chmod(deviceIDPath, 0o600)
		}
	}

	return newID
}

func resolveVerifySSLFromEnv() bool {
	for _, key := range []string{"AUN_ENV", "KITE_ENV"} {
		value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
		if value == "" {
			continue
		}
		return !devEnvValues[value]
	}
	return true
}

// AUNConfig SDK 配置
type AUNConfig struct {
	AUNPath                  string // AUN 数据根目录，默认 ~/.aun
	RootCAPath               string // 自定义根证书路径
	SeedPassword             string // 私钥加密口令（用于本地密钥派生）
	DiscoveryPort            int    // Gateway 发现端口
	GroupE2EE                bool   // 启用群组 E2EE，默认 true
	EpochAutoRotateInterval  int    // epoch 自动轮换间隔（秒），0 表示不自动轮换
	OldEpochRetentionSeconds int    // 旧 epoch 保留时间（秒），默认 604800（7 天）
	VerifySSL                bool   // 是否验证 TLS 证书，默认 true
	RequireForwardSecrecy    bool   // 是否要求前向保密，默认 true
	ReplayWindowSeconds      int    // 防重放时间窗口（秒），默认 300
}

// DefaultConfig 返回默认配置
func DefaultConfig() *AUNConfig {
	home, _ := os.UserHomeDir()
	aunPath := filepath.Join(home, ".aun")
	return &AUNConfig{
		AUNPath:                  aunPath,
		GroupE2EE:                true,
		EpochAutoRotateInterval:  0,
		OldEpochRetentionSeconds: 604800, // 7 天
		VerifySSL:                resolveVerifySSLFromEnv(),
		RequireForwardSecrecy:    true,
		ReplayWindowSeconds:      300,
	}
}

// ConfigFromMap 从字典构建配置（与 Python SDK AUNConfig.from_dict 对应）
func ConfigFromMap(raw map[string]any) *AUNConfig {
	cfg := DefaultConfig()
	if raw == nil {
		return cfg
	}

	if v, ok := raw["aun_path"].(string); ok && v != "" {
		cfg.AUNPath = v
	}
	if v, ok := raw["aunPath"].(string); ok && v != "" {
		cfg.AUNPath = v
	}
	if v, ok := raw["root_ca_path"].(string); ok {
		cfg.RootCAPath = v
	}
	if v, ok := raw["rootCaPath"].(string); ok {
		cfg.RootCAPath = v
	}
	if v, ok := raw["seed_password"].(string); ok {
		cfg.SeedPassword = v
	}
	if v, ok := raw["seedPassword"].(string); ok {
		cfg.SeedPassword = v
	}
	if v, ok := raw["encryption_seed"].(string); ok {
		cfg.SeedPassword = v
	}
	if v, ok := raw["encryptionSeed"].(string); ok {
		cfg.SeedPassword = v
	}
	if v, ok := numberFromMap(raw, "discovery_port", "discoveryPort"); ok {
		cfg.DiscoveryPort = int(v)
	}
	// GroupE2EE 是必备能力，不再从用户配置中读取
	if v, ok := numberFromMap(raw, "epoch_auto_rotate_interval", "epochAutoRotateInterval"); ok {
		cfg.EpochAutoRotateInterval = int(v)
	}
	if v, ok := numberFromMap(raw, "old_epoch_retention_seconds", "oldEpochRetentionSeconds"); ok {
		cfg.OldEpochRetentionSeconds = int(v)
	}
	if v, ok := boolFromMap(raw, "verify_ssl", "verifySSL", "verifySsl"); ok {
		cfg.VerifySSL = v
	}
	if v, ok := boolFromMap(raw, "require_forward_secrecy", "requireForwardSecrecy"); ok {
		cfg.RequireForwardSecrecy = v
	}
	if v, ok := numberFromMap(raw, "replay_window_seconds", "replayWindowSeconds"); ok {
		cfg.ReplayWindowSeconds = int(v)
	}
	return cfg
}

// DeviceID 返回当前设备的稳定 ID
func (c *AUNConfig) DeviceID() string {
	return GetDeviceID(c.AUNPath)
}

// generateUUID4 生成 UUID v4，使用 google/uuid 库（项目已引入）
func generateUUID4() string {
	return uuid.New().String()
}

func boolFromMap(raw map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		if value, ok := raw[key].(bool); ok {
			return value, true
		}
	}
	return false, false
}

func numberFromMap(raw map[string]any, keys ...string) (float64, bool) {
	for _, key := range keys {
		switch value := raw[key].(type) {
		case int:
			return float64(value), true
		case int32:
			return float64(value), true
		case int64:
			return float64(value), true
		case float32:
			return float64(value), true
		case float64:
			return value, true
		}
	}
	return 0, false
}
