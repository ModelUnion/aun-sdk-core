package aun

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type scriptedCollabClient struct {
	calls   []storageCallRecord
	results map[string]any
}

func (f *scriptedCollabClient) Call(ctx context.Context, method string, params map[string]any) (any, error) {
	f.calls = append(f.calls, storageCallRecord{method: method, params: params})
	if f.results != nil {
		if result, ok := f.results[method]; ok {
			return result, nil
		}
	}
	return map[string]any{"ok": true}, nil
}

func TestClientCollabGetterIsCached(t *testing.T) {
	client := NewAUNClientEmpty()
	defer func() { _ = client.Close() }()

	if first, second := client.Collab(), client.Collab(); first == nil || first != second {
		t.Fatal("Collab getter 应惰性缓存同一实例")
	}
	if first, second := client.Collab().Snapshot(), client.Collab().Snapshot(); first == nil || first != second {
		t.Fatal("Collab().Snapshot getter 应惰性缓存同一实例")
	}
}

func TestCollabFacadeRPCMappings(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	collab := newCollabFacade(client)
	before := 123
	keepLast := 2

	calls := []struct {
		name string
		call func() error
		want string
	}{
		{"ls", func() error { _, err := collab.LS(ctx, "alice.aid.com:/proj"); return err }, "collab.ls"},
		{"create", func() error { _, err := collab.Create(ctx, "alice.aid.com:/proj", "d.md", "S"); return err }, "collab.create"},
		{"read", func() error { _, err := collab.Read(ctx, "alice.aid.com:/proj", "d.md"); return err }, "collab.read"},
		{"submit", func() error { _, err := collab.Submit(ctx, "alice.aid.com:/proj", "d.md", "S", 1, ""); return err }, "collab.submit"},
		{"merge", func() error { _, err := collab.Merge(ctx, "alice.aid.com:/proj", "d.md", "S", 1); return err }, "collab.merge"},
		{"history", func() error { _, err := collab.History(ctx, "alice.aid.com:/proj", "d.md"); return err }, "collab.history"},
		{"get", func() error { _, err := collab.Get(ctx, "alice.aid.com:/proj", "d.md", 1); return err }, "collab.get"},
		{"diff", func() error { _, err := collab.Diff(ctx, "alice.aid.com:/proj", "d.md", 1, 2); return err }, "collab.diff"},
		{"export", func() error { _, err := collab.Export(ctx, "alice.aid.com:/proj", "alice.aid.com:/copy"); return err }, "collab.export"},
		{"adopt", func() error { _, err := collab.Adopt(ctx, "alice.aid.com:/proj", "alice.aid.com:/new"); return err }, "collab.adopt"},
		{"prune", func() error { _, err := collab.Prune(ctx, "alice.aid.com:/proj", "d.md"); return err }, "collab.prune"},
		{"discover", func() error { _, err := collab.Discover(ctx, "g-team.aid.com"); return err }, "collab.discover"},
		{"unregister", func() error { _, err := collab.Unregister(ctx, "g-team.aid.com", "g-team.aid.com:/proj"); return err }, "collab.unregister"},
		{"snapshot_create", func() error { _, err := collab.Snapshot().Create(ctx, "alice.aid.com:/proj", "m", true); return err }, "collab.snapshot.create"},
		{"snapshot_list", func() error { _, err := collab.Snapshot().List(ctx, "alice.aid.com:/proj"); return err }, "collab.snapshot.list"},
		{"snapshot_show", func() error { _, err := collab.Snapshot().Show(ctx, "alice.aid.com:/proj", "1.0.0"); return err }, "collab.snapshot.show"},
		{"snapshot_diff", func() error {
			_, err := collab.Snapshot().Diff(ctx, "alice.aid.com:/proj", "1.0.0", "1.0.1")
			return err
		}, "collab.snapshot.diff"},
		{"snapshot_restore", func() error {
			_, err := collab.Snapshot().Restore(ctx, "alice.aid.com:/proj", "1.0.0", "r")
			return err
		}, "collab.snapshot.restore"},
		{"snapshot_rm", func() error { _, err := collab.Snapshot().Remove(ctx, "alice.aid.com:/proj", "1.0.0"); return err }, "collab.snapshot.rm"},
		{"snapshot_prune", func() error {
			_, err := collab.Snapshot().Prune(ctx, "alice.aid.com:/proj", &before, &keepLast)
			return err
		}, "collab.snapshot.prune"},
	}

	for _, tc := range calls {
		if err := tc.call(); err != nil {
			t.Fatalf("%s 调用失败: %v", tc.name, err)
		}
	}
	if len(client.calls) != len(calls) {
		t.Fatalf("调用次数不正确: got=%d want=%d calls=%#v", len(client.calls), len(calls), client.calls)
	}
	for i, tc := range calls {
		if client.calls[i].method != tc.want {
			t.Fatalf("第 %d 次调用方法不正确: got=%s want=%s", i, client.calls[i].method, tc.want)
		}
		if strings.HasPrefix(client.calls[i].method, "storage.") {
			t.Fatalf("collab facade 不应调用 storage 前缀 RPC: %#v", client.calls[i])
		}
	}
	if !reflect.DeepEqual(client.calls[3].params, map[string]any{
		"collab_root":  "alice.aid.com:/proj",
		"doc":          "d.md",
		"source":       "S",
		"base_version": 1,
	}) {
		t.Fatalf("submit 参数不正确: %#v", client.calls[3].params)
	}
	if !reflect.DeepEqual(client.calls[7].params, map[string]any{
		"collab_root": "alice.aid.com:/proj",
		"doc":         "d.md",
		"from":        1,
		"to":          2,
	}) {
		t.Fatalf("diff 参数不正确: %#v", client.calls[7].params)
	}
	if !reflect.DeepEqual(client.calls[19].params, map[string]any{
		"collab_root": "alice.aid.com:/proj",
		"before":      123,
		"keep_last":   2,
	}) {
		t.Fatalf("snapshot.prune 参数不正确: %#v", client.calls[19].params)
	}
	if !reflect.DeepEqual(client.calls[9].params, map[string]any{
		"src":      "alice.aid.com:/proj",
		"new_root": "alice.aid.com:/new",
	}) {
		t.Fatalf("adopt 参数不正确: %#v", client.calls[9].params)
	}
}

func TestCollabFacadeTypedResults(t *testing.T) {
	ctx := context.Background()
	client := &scriptedCollabClient{results: map[string]any{
		"collab.ls": []any{map[string]any{"doc": "a.md", "anchor": "a.md", "version": 2, "author": "alice", "current_target": "alice:/proj/v2"}},
		"collab.read": map[string]any{
			"collab_root":    "alice:/proj",
			"doc":            "a.md",
			"anchor":         "a.md",
			"content":        "YQ==",
			"version":        2,
			"author":         "alice",
			"current_target": "alice:/proj/v2",
		},
		"collab.history":         []any{map[string]any{"version": 1, "author": "alice", "target": "alice:/proj/v1", "time": int64(10)}},
		"collab.diff":            map[string]any{"from": 1, "to": 2, "diff": "+b\n"},
		"collab.export":          map[string]any{"ok": true, "dest": "alice:/copy", "copied_objects": 3},
		"collab.discover":        []any{map[string]any{"group_aid": "g.aid.com", "authority_aid": "g.aid.com", "collab_root": "g.aid.com:/proj"}},
		"collab.snapshot.create": map[string]any{"version": "1.0.0", "bump": "major", "changed": []any{"a.md"}},
		"collab.snapshot.list":   []any{map[string]any{"version": "1.0.0", "created_at": int64(20), "message": "m"}},
		"collab.snapshot.show": map[string]any{
			"version":    "1.0.0",
			"created_at": int64(20),
			"message":    "m",
			"collab_root": "alice:/proj",
			"entries":    []any{map[string]any{"doc": "a.md", "anchor": "a.md", "version": 2, "author": "alice", "current_target": "alice:/proj/.collab-versions/a.md/v2", "target": "alice:/proj/.collab-versions/a.md/v2"}},
		},
		"collab.snapshot.diff":    map[string]any{"added": []any{"b.md"}, "removed": []any{"old.md"}, "changed": []any{"a.md"}},
		"collab.snapshot.restore": map[string]any{"restored_from": "1.0.0", "new_snapshot_version": "1.0.1", "warnings": []any{"skip deleted.md"}},
		"collab.snapshot.prune":   map[string]any{"pruned": 2},
	}}
	collab := newCollabFacade(client)

	list, err := collab.Ls(ctx, "alice:/proj")
	if err != nil || len(list) != 1 || list[0].Doc != "a.md" || list[0].Anchor != "a.md" || list[0].Version != 2 {
		t.Fatalf("Ls 类型结果不正确: %#v err=%v", list, err)
	}
	read, err := collab.Read(ctx, "alice:/proj", "a.md")
	if err != nil || read.Content != "YQ==" || read.Anchor != "a.md" || read.CurrentTarget != "alice:/proj/v2" {
		t.Fatalf("Read 类型结果不正确: %#v err=%v", read, err)
	}
	history, err := collab.History(ctx, "alice:/proj", "a.md")
	if err != nil || len(history) != 1 || history[0].Time != 10 {
		t.Fatalf("History 类型结果不正确: %#v err=%v", history, err)
	}
	diff, err := collab.Diff(ctx, "alice:/proj", "a.md", 1, 2)
	if err != nil || diff.Diff != "+b\n" || diff.From != 1 || diff.To != 2 {
		t.Fatalf("Diff 类型结果不正确: %#v err=%v", diff, err)
	}
	exported, err := collab.Export(ctx, "alice:/proj", "alice:/copy")
	if err != nil || !exported.OK || exported.CopiedObjects != 3 {
		t.Fatalf("Export 类型结果不正确: %#v err=%v", exported, err)
	}
	discovered, err := collab.Discover(ctx, "g.aid.com")
	if err != nil || len(discovered) != 1 || discovered[0].CollabRoot != "g.aid.com:/proj" {
		t.Fatalf("Discover 类型结果不正确: %#v err=%v", discovered, err)
	}
	snapshot, err := collab.Snapshot().Create(ctx, "alice:/proj", "m", true)
	if err != nil || snapshot.Version != "1.0.0" || len(snapshot.Changed) != 1 {
		t.Fatalf("Snapshot.Create 类型结果不正确: %#v err=%v", snapshot, err)
	}
	snapshots, err := collab.Snapshot().List(ctx, "alice:/proj")
	if err != nil || len(snapshots) != 1 || snapshots[0].CreatedAt != 20 {
		t.Fatalf("Snapshot.List 类型结果不正确: %#v err=%v", snapshots, err)
	}
	shown, err := collab.Snapshot().Show(ctx, "alice:/proj", "1.0.0")
	if err != nil || len(shown.Entries) != 1 || shown.Entries[0].Anchor != "a.md" || !strings.HasPrefix(shown.Entries[0].CurrentTarget, "alice:/proj/") || !strings.HasPrefix(shown.Entries[0].Target, "alice:/proj/") {
		t.Fatalf("Snapshot.Show 类型结果不正确: %#v err=%v", shown, err)
	}
	snapDiff, err := collab.Snapshot().Diff(ctx, "alice:/proj", "1.0.0", "1.0.1")
	if err != nil || len(snapDiff.Added) != 1 || len(snapDiff.Removed) != 1 || len(snapDiff.Changed) != 1 {
		t.Fatalf("Snapshot.Diff 类型结果不正确: %#v err=%v", snapDiff, err)
	}
	restored, err := collab.Snapshot().Restore(ctx, "alice:/proj", "1.0.0", "restore")
	if err != nil || restored.NewSnapshotVersion != "1.0.1" || len(restored.Warnings) != 1 {
		t.Fatalf("Snapshot.Restore 类型结果不正确: %#v err=%v", restored, err)
	}
	pruned, err := collab.Snapshot().Prune(ctx, "alice:/proj", "2026-06-01", nil)
	if err != nil || pruned.Pruned != 2 {
		t.Fatalf("Snapshot.Prune 类型结果不正确: %#v err=%v", pruned, err)
	}
	lastParams := client.calls[len(client.calls)-1].params
	if lastParams["before"] != "2026-06-01" {
		t.Fatalf("Snapshot.Prune 应透传日期字符串 before: %#v", lastParams)
	}
}

func TestCollabConflictErrorPreservesServerFields(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{
		aid: "alice.agentid.pub",
		failMethods: map[string]error{
			"collab.submit": NewVersionConflictError(
				"提交失败",
				WithCode(-32009),
				WithData(map[string]any{
					"current_version": 4,
					"current_target":  "alice.aid.com:/proj/v4",
					"hint":            "merge first",
				}),
			),
		},
	}
	collab := newCollabFacade(client)

	_, err := collab.Submit(ctx, "alice.aid.com:/proj", "d.md", "S", 3, "")
	if err == nil {
		t.Fatal("expected CollabConflictError, got nil")
	}
	var conflict *CollabConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("expected *CollabConflictError, got %T: %v", err, err)
	}
	if conflict.CurrentVersion == nil || *conflict.CurrentVersion != 4 {
		t.Fatalf("CurrentVersion 未保留: %#v", conflict.CurrentVersion)
	}
	if conflict.CurrentTarget != "alice.aid.com:/proj/v4" || conflict.Hint != "merge first" {
		t.Fatalf("冲突字段未保留: target=%q hint=%q", conflict.CurrentTarget, conflict.Hint)
	}
	if conflict.Code != -32009 {
		t.Fatalf("冲突错误码不正确: %d", conflict.Code)
	}
}

func TestCollabSnapshotPruneOmitsNilOptionalParams(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	collab := newCollabFacade(client)

	if _, err := collab.Snapshot().Prune(ctx, "alice.aid.com:/proj", nil, nil); err != nil {
		t.Fatalf("Snapshot().Prune 失败: %v", err)
	}
	params := client.calls[0].params
	if !reflect.DeepEqual(params, map[string]any{"collab_root": "alice.aid.com:/proj"}) {
		t.Fatalf("nil 可选参数应被过滤: %#v", params)
	}
}
