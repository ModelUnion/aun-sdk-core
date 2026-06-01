package keystore

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// metaLocksLimit 限制 per-AID 锁表大小，防止无界增长。
const metaLocksLimit = 256

// secureFilePermissions 在非 Windows 平台收紧文件权限至 0600。
func secureFilePermissions(path string) {
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, 0o600)
	}
}

// safeRename 原子重命名，Windows 上 os.Rename 目标已存在时可能失败，
// 失败后 fallback 为先删除再重命名（ISSUE-GO-003）。
func safeRename(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		// Windows fallback: 先删除目标再重命名
		if removeErr := os.Remove(dst); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("删除目标文件失败: %w (原始 rename 错误: %v)", removeErr, err)
		}
		return os.Rename(src, dst)
	}
	return nil
}

// safeAID 将 AID 中的路径分隔符替换为下划线，避免目录穿越。
func safeAID(aid string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_")
	return r.Replace(aid)
}

// normalizeCertFingerprint 校验并归一化 sha256: 指纹，非法时返回空字符串。
func normalizeCertFingerprint(fp string) string {
	v := strings.TrimSpace(strings.ToLower(fp))
	if !strings.HasPrefix(v, "sha256:") || len(v) != 71 {
		return ""
	}
	for _, c := range v[7:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return v
}

// copyMap 浅拷贝 map。
func copyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// deepCopyMap 深拷贝 map（含嵌套 map/slice）。
func deepCopyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = cloneAny(v)
	}
	return dst
}

func cloneAny(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return deepCopyMap(val)
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = cloneAny(item)
		}
		return out
	default:
		return v
	}
}
