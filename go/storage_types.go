package aun

import (
	"path"
	"strconv"
	"strings"
)

type NodeView struct {
	Type        string         `json:"type"`
	Path        string         `json:"path"`
	Name        string         `json:"name"`
	Owner       string         `json:"owner"`
	Bucket      string         `json:"bucket"`
	Size        int64          `json:"size"`
	MTime       int64          `json:"mtime"`
	ContentType string         `json:"content_type"`
	Version     int64          `json:"version"`
	Mode        string         `json:"mode"`
	IsPublic    bool           `json:"is_public"`
	ObjectID    string         `json:"object_id"`
	FolderID    string         `json:"folder_id"`
	Target      string         `json:"target"`
	MountSource string         `json:"mount_source"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	SHA256      string         `json:"sha256,omitempty"`
	ETag        string         `json:"etag,omitempty"`
}

type RemoveResult struct {
	Path         string `json:"path"`
	RemovedCount int64  `json:"removed_count"`
}

type UnmountResult struct {
	Unmounted bool   `json:"unmounted"`
	Owner     string `json:"owner_aid"`
	Bucket    string `json:"bucket"`
	Path      string `json:"path"`
	MountPath string `json:"mount_path"`
}

type DownloadResult struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Verified bool   `json:"verified"`
	Data     []byte `json:"-"`
}

type UsageView struct {
	Owner       string `json:"owner"`
	QuotaBytes  int64  `json:"quota_bytes"`
	UsedBytes   int64  `json:"used_bytes"`
	AvailBytes  int64  `json:"avail_bytes"`
	ObjectCount int64  `json:"object_count"`
}

func NormalizeStoragePath(value string) string {
	raw := strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if raw == "" {
		raw = "/"
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	normalized := path.Clean(raw)
	if normalized == "." {
		return "/"
	}
	return normalized
}

func StoragePathToKey(value string) string {
	normalized := NormalizeStoragePath(value)
	if normalized == "/" {
		return ""
	}
	return strings.TrimPrefix(normalized, "/")
}

func storageKeyToPath(value any) string {
	return NormalizeStoragePath(storageString(value, ""))
}

func storageNameFromPath(value string) string {
	cleaned := strings.TrimRight(NormalizeStoragePath(value), "/")
	if cleaned == "" || cleaned == "/" {
		return "/"
	}
	parts := strings.Split(cleaned, "/")
	return parts[len(parts)-1]
}

func storageString(value any, fallback string) string {
	if value == nil {
		return fallback
	}
	switch v := value.(type) {
	case string:
		if v == "" {
			return fallback
		}
		return v
	case []byte:
		if len(v) == 0 {
			return fallback
		}
		return string(v)
	default:
		return strings.TrimSpace(strings.Trim(strings.ReplaceAll(strings.ReplaceAll(strconv.Quote(storageAnyToString(v)), `\"`, `"`), `"`, ""), "\n"))
	}
}

func storageAnyToString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		return ""
	}
}

func storageInt64(value any) int64 {
	switch v := value.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case int32:
		return int64(v)
	case float64:
		return int64(v)
	case float32:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	default:
		return 0
	}
}

func storageBool(value any, fallback bool) bool {
	if value == nil {
		return fallback
	}
	if v, ok := value.(bool); ok {
		return v
	}
	return fallback
}

func storageMap(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if m, ok := value.(map[string]any); ok {
		return m
	}
	if m, ok := value.(map[string]interface{}); ok {
		return map[string]any(m)
	}
	return map[string]any{}
}

func NodeViewFromAny(value any) NodeView {
	raw := storageMap(value)
	nodeType := strings.ToLower(storageString(firstNonNil(raw["type"], raw["node_type"]), ""))
	switch nodeType {
	case "folder", "dir", "directory":
		return baseNodeView(raw, "dir", storageKeyToPath(raw["path"]))
	case "symlink", "link":
		return baseNodeView(raw, "symlink", storageKeyToPath(raw["path"]))
	case "mount":
		return baseNodeView(raw, "mount", storageKeyToPath(raw["path"]))
	default:
		node := baseNodeView(raw, "file", storageKeyToPath(firstNonNil(raw["path"], raw["object_key"])))
		node.SHA256 = storageString(raw["sha256"], "")
		node.ETag = storageString(raw["etag"], "")
		return node
	}
}

func baseNodeView(raw map[string]any, nodeType string, nodePath string) NodeView {
	metadata := storageMap(raw["metadata"])
	return NodeView{
		Type:        nodeType,
		Path:        nodePath,
		Name:        firstNonEmpty(storageString(raw["name"], ""), storageNameFromPath(nodePath)),
		Owner:       storageString(firstNonNil(raw["owner"], raw["owner_aid"]), ""),
		Bucket:      firstNonEmpty(storageString(raw["bucket"], ""), "default"),
		Size:        storageInt64(firstNonNil(raw["size"], raw["size_bytes"])),
		MTime:       storageInt64(firstNonNil(raw["mtime"], raw["updated_at"])),
		ContentType: storageString(raw["content_type"], ""),
		Version:     storageInt64(raw["version"]),
		Mode:        storageString(raw["mode"], ""),
		IsPublic:    !storageBool(raw["is_private"], true),
		ObjectID:    storageString(raw["object_id"], ""),
		FolderID:    storageString(raw["folder_id"], ""),
		Target:      storageString(raw["target"], ""),
		MountSource: storageString(raw["mount_source"], ""),
		Metadata:    metadata,
	}
}

func UsageViewFromAny(value any, ownerFallback string) UsageView {
	raw := storageMap(value)
	quota := storageInt64(firstNonNil(raw["quota_bytes"], raw["quota_total_bytes"]))
	used := storageInt64(firstNonNil(raw["used_bytes"], raw["quota_used_bytes"]))
	avail := int64(0)
	if quota > 0 && quota > used {
		avail = quota - used
	}
	return UsageView{
		Owner:       firstNonEmpty(storageString(firstNonNil(raw["owner"], raw["owner_aid"]), ""), ownerFallback),
		QuotaBytes:  quota,
		UsedBytes:   used,
		AvailBytes:  avail,
		ObjectCount: storageInt64(raw["object_count"]),
	}
}

func firstNonNil(values ...any) any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
