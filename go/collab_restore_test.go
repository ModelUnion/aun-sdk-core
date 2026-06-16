package aun

import (
	"context"
	"encoding/json"
	"testing"
)

// TestCollabSnapshotRestoreResult_PartialFields 测试 restore 返回 partial 和 restored_docs 字段
func TestCollabSnapshotRestoreResult_PartialFields(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		serverResp map[string]any
		wantResult CollabSnapshotRestoreResult
	}{
		{
			name: "完整恢复",
			serverResp: map[string]any{
				"restored_from":        "1.0.0",
				"new_snapshot_version": "1.1.0",
				"warnings":             []any{"doc1 在恢复期间被他人修改，已跳过"},
				"partial":              false,
				"restored_docs":        []any{"doc2", "doc3"},
			},
			wantResult: CollabSnapshotRestoreResult{
				RestoredFrom:       "1.0.0",
				NewSnapshotVersion: "1.1.0",
				Warnings:           []string{"doc1 在恢复期间被他人修改，已跳过"},
				Partial:            false,
				RestoredDocs:       []string{"doc2", "doc3"},
			},
		},
		{
			name: "部分恢复",
			serverResp: map[string]any{
				"restored_from":        "2.0.0",
				"new_snapshot_version": nil,
				"warnings":             []any{"网络超时", "doc5 恢复失败: DB超时"},
				"partial":              true,
				"restored_docs":        []any{"doc1", "doc2"},
			},
			wantResult: CollabSnapshotRestoreResult{
				RestoredFrom:       "2.0.0",
				NewSnapshotVersion: "",
				Warnings:           []string{"网络超时", "doc5 恢复失败: DB超时"},
				Partial:            true,
				RestoredDocs:       []string{"doc1", "doc2"},
			},
		},
		{
			name: "无 partial/restored_docs 字段（向后兼容）",
			serverResp: map[string]any{
				"restored_from":        "3.0.0",
				"new_snapshot_version": "3.1.0",
				"warnings":             []any{},
			},
			wantResult: CollabSnapshotRestoreResult{
				RestoredFrom:       "3.0.0",
				NewSnapshotVersion: "3.1.0",
				Warnings:           []string{},
				Partial:            false,
				RestoredDocs:       nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &scriptedCollabClient{
				results: map[string]any{
					"collab.snapshot.restore": tt.serverResp,
				},
			}

			collab := newCollabFacade(client)
			result, err := collab.Snapshot().Restore(ctx, "alice.aid.com:/proj", "1.0.0", "test")
			if err != nil {
				t.Fatalf("Restore 失败: %v", err)
			}

			// 比较结果
			if result.RestoredFrom != tt.wantResult.RestoredFrom {
				t.Errorf("RestoredFrom = %q, want %q", result.RestoredFrom, tt.wantResult.RestoredFrom)
			}
			if result.NewSnapshotVersion != tt.wantResult.NewSnapshotVersion {
				t.Errorf("NewSnapshotVersion = %q, want %q", result.NewSnapshotVersion, tt.wantResult.NewSnapshotVersion)
			}
			if result.Partial != tt.wantResult.Partial {
				t.Errorf("Partial = %v, want %v", result.Partial, tt.wantResult.Partial)
			}
			if !equalStringSlice(result.Warnings, tt.wantResult.Warnings) {
				t.Errorf("Warnings = %v, want %v", result.Warnings, tt.wantResult.Warnings)
			}
			if !equalStringSlice(result.RestoredDocs, tt.wantResult.RestoredDocs) {
				t.Errorf("RestoredDocs = %v, want %v", result.RestoredDocs, tt.wantResult.RestoredDocs)
			}
		})
	}
}

// TestCollabSnapshotRestoreResult_JSONRoundtrip 测试 JSON 序列化往返
func TestCollabSnapshotRestoreResult_JSONRoundtrip(t *testing.T) {
	original := CollabSnapshotRestoreResult{
		RestoredFrom:       "1.0.0",
		NewSnapshotVersion: "1.1.0",
		Warnings:           []string{"warning1", "warning2"},
		Partial:            true,
		RestoredDocs:       []string{"doc1", "doc2"},
	}

	// 序列化
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("JSON Marshal 失败: %v", err)
	}

	// 反序列化
	var result CollabSnapshotRestoreResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("JSON Unmarshal 失败: %v", err)
	}

	// 验证
	if result.Partial != original.Partial {
		t.Errorf("Partial = %v, want %v", result.Partial, original.Partial)
	}
	if !equalStringSlice(result.RestoredDocs, original.RestoredDocs) {
		t.Errorf("RestoredDocs = %v, want %v", result.RestoredDocs, original.RestoredDocs)
	}
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
