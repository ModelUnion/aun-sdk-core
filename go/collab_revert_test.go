package aun

import (
	"context"
	"testing"
)

// TestCollabTagRestoreResult_FieldMapping 测试 restore 返回字段映射
func TestCollabTagRestoreResult_FieldMapping(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		serverResp map[string]any
		wantFields map[string]any
	}{
		{
			name: "完整恢复",
			serverResp: map[string]any{
				"restored_from":        "1.0.0",
				"new_snapshot_version": "1.1.0",
				"warnings":             []any{"doc1 在恢复期间被他人修改，已跳过"},
				"restored_docs":        []any{"doc2", "doc3"},
			},
			wantFields: map[string]any{
				"restored_from":        "1.0.0",
				"new_snapshot_version": "1.1.0",
				"warnings_count":       1,
				"restored_docs_count":  2,
			},
		},
		{
			name: "部分恢复",
			serverResp: map[string]any{
				"restored_from":        "2.0.0",
				"new_snapshot_version": nil,
				"warnings":             []any{"网络超时", "doc5 恢复失败: DB超时"},
				"restored_docs":        []any{"doc1", "doc2"},
			},
			wantFields: map[string]any{
				"restored_from":        "2.0.0",
				"new_snapshot_version": "",
				"warnings_count":       2,
				"restored_docs_count":  2,
			},
		},
		{
			name: "无 restored_docs 字段（向后兼容）",
			serverResp: map[string]any{
				"restored_from":        "3.0.0",
				"new_snapshot_version": "3.1.0",
				"warnings":             []any{},
			},
			wantFields: map[string]any{
				"restored_from":        "3.0.0",
				"new_snapshot_version": "3.1.0",
				"warnings_count":       0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &scriptedCollabClient{
				results: map[string]any{
					"collab.tag.restore": tt.serverResp,
				},
			}

			collab := newCollabFacade(client)
			result, err := collab.Tag().Restore(ctx, "alice.aid.com:/proj", "1.0.0", "test")
			if err != nil {
				t.Fatalf("Restore 失败: %v", err)
			}

			// 比较结果
			if result.RestoredFrom != tt.wantFields["restored_from"].(string) {
				t.Errorf("RestoredFrom = %q, want %q", result.RestoredFrom, tt.wantFields["restored_from"])
			}
			wantNewVer := tt.wantFields["new_snapshot_version"].(string)
			if result.NewSnapshotVersion != wantNewVer {
				t.Errorf("NewSnapshotVersion = %q, want %q", result.NewSnapshotVersion, wantNewVer)
			}
			if len(result.Warnings) != tt.wantFields["warnings_count"].(int) {
				t.Errorf("Warnings count = %d, want %d", len(result.Warnings), tt.wantFields["warnings_count"])
			}
			if wantRestoredCount, ok := tt.wantFields["restored_docs_count"]; ok {
				if len(result.RestoredDocs) != wantRestoredCount.(int) {
					t.Errorf("RestoredDocs count = %d, want %d", len(result.RestoredDocs), wantRestoredCount)
				}
			}
		})
	}
}
