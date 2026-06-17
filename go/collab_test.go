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
	if first, second := client.Collab().Tag(), client.Collab().Tag(); first == nil || first != second {
		t.Fatal("Collab().Tag getter 应惰性缓存同一实例")
	}
}

func TestCollabFacadeRPCMappings(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	collab := newCollabFacade(client)
	before := 123
	keepLast := 2
	rev1 := 1

	calls := []struct {
		name string
		call func() error
		want string
	}{
		{"ls_files", func() error { _, err := collab.LsFiles(ctx, "alice.aid.com:/proj"); return err }, "collab.ls-files"},
		{"create", func() error { _, err := collab.Create(ctx, "alice.aid.com:/proj", "d.md", "S"); return err }, "collab.create"},
		{"show", func() error { _, err := collab.Show(ctx, "alice.aid.com:/proj", "d.md", nil); return err }, "collab.show"},
		{"show_rev", func() error { _, err := collab.Show(ctx, "alice.aid.com:/proj", "d.md", &rev1); return err }, "collab.show"},
		{"commit", func() error { _, err := collab.Commit(ctx, "alice.aid.com:/proj", "d.md", "S", 1, ""); return err }, "collab.commit"},
		{"merge", func() error { _, err := collab.Merge(ctx, "alice.aid.com:/proj", "d.md", "S", 1); return err }, "collab.merge"},
		{"log", func() error { _, err := collab.Log(ctx, "alice.aid.com:/proj", "d.md"); return err }, "collab.log"},
		{"diff", func() error { _, err := collab.Diff(ctx, "alice.aid.com:/proj", "d.md", 1, 2); return err }, "collab.diff"},
		{"clone", func() error {
			_, err := collab.Clone(ctx, "alice.aid.com:/proj", "alice.aid.com:/copy", false)
			return err
		}, "collab.clone"},
		{"clone_reroot", func() error {
			_, err := collab.Clone(ctx, "alice.aid.com:/proj", "alice.aid.com:/new", true)
			return err
		}, "collab.clone"},
		{"prune", func() error { _, err := collab.Prune(ctx, "alice.aid.com:/proj", "d.md"); return err }, "collab.prune"},
		{"ls_remote", func() error { _, err := collab.LsRemote(ctx, "g-team.aid.com"); return err }, "collab.ls-remote"},
		{"unregister", func() error { _, err := collab.Unregister(ctx, "g-team.aid.com", "g-team.aid.com:/proj"); return err }, "collab.unregister"},
		{"tag_create", func() error { _, err := collab.Tag().Create(ctx, "alice.aid.com:/proj", "m", true); return err }, "collab.tag.create"},
		{"tag_list", func() error { _, err := collab.Tag().List(ctx, "alice.aid.com:/proj"); return err }, "collab.tag.list"},
		{"tag_show", func() error { _, err := collab.Tag().Show(ctx, "alice.aid.com:/proj", "1.0.0"); return err }, "collab.tag.show"},
		{"tag_diff", func() error {
			_, err := collab.Tag().Diff(ctx, "alice.aid.com:/proj", "1.0.0", "1.0.1")
			return err
		}, "collab.tag.diff"},
		{"tag_restore", func() error {
			_, err := collab.Tag().Restore(ctx, "alice.aid.com:/proj", "1.0.0", "r")
			return err
		}, "collab.tag.restore"},
		{"tag_rm", func() error { _, err := collab.Tag().Rm(ctx, "alice.aid.com:/proj", "1.0.0"); return err }, "collab.tag.rm"},
		{"tag_prune", func() error {
			_, err := collab.Tag().Prune(ctx, "alice.aid.com:/proj", &before, &keepLast)
			return err
		}, "collab.tag.prune"},
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
	// commit params (index 4)
	if !reflect.DeepEqual(client.calls[4].params, map[string]any{
		"collab_root": "alice.aid.com:/proj",
		"doc":         "d.md",
		"source":      "S",
		"onto":        1,
		"message":     "",
	}) {
		t.Fatalf("commit 参数不正确: %#v", client.calls[4].params)
	}
	// diff params (index 7)
	if !reflect.DeepEqual(client.calls[7].params, map[string]any{
		"collab_root": "alice.aid.com:/proj",
		"doc":         "d.md",
		"from":        1,
		"to":          2,
	}) {
		t.Fatalf("diff 参数不正确: %#v", client.calls[7].params)
	}
	// tag.prune params (last)
	if !reflect.DeepEqual(client.calls[19].params, map[string]any{
		"collab_root": "alice.aid.com:/proj",
		"before":      123,
		"keep_last":   2,
	}) {
		t.Fatalf("tag.prune 参数不正确: %#v", client.calls[19].params)
	}
	// clone reroot params (index 9)
	if !reflect.DeepEqual(client.calls[9].params, map[string]any{
		"src":    "alice.aid.com:/proj",
		"dest":   "alice.aid.com:/new",
		"reroot": true,
	}) {
		t.Fatalf("clone reroot 参数不正确: %#v", client.calls[9].params)
	}
	// show with rev params (index 3)
	if !reflect.DeepEqual(client.calls[3].params, map[string]any{
		"collab_root": "alice.aid.com:/proj",
		"doc":         "d.md",
		"rev":         1,
	}) {
		t.Fatalf("show rev 参数不正确: %#v", client.calls[3].params)
	}
}

func TestCollabFacadeTypedResults(t *testing.T) {
	ctx := context.Background()
	client := &scriptedCollabClient{results: map[string]any{
		"collab.ls-files": []map[string]any{{"doc": "a.md", "anchor": "a.md", "version": 2, "author": "alice", "current_target": "alice:/proj/v2"}},
		"collab.show": map[string]any{
			"collab_root":    "alice:/proj",
			"doc":            "a.md",
			"anchor":         "a.md",
			"content":        "YQ==",
			"version":        2,
			"author":         "alice",
			"current_target": "alice:/proj/v2",
		},
		"collab.log":        []map[string]any{{"version": 1, "author": "alice", "target": "alice:/proj/v1", "time": int64(10)}},
		"collab.diff":       map[string]any{"from": 1, "to": 2, "diff": "+b\n"},
		"collab.clone":      map[string]any{"ok": true, "dest": "alice:/copy", "copied_objects": 3},
		"collab.ls-remote":  []map[string]any{{"group_aid": "g.aid.com", "authority_aid": "g.aid.com", "collab_root": "g.aid.com:/proj"}},
		"collab.tag.create": map[string]any{"version": "1.0.0", "message": "m"},
		"collab.tag.list":   []map[string]any{{"version": "1.0.0", "created_at": int64(20), "message": "m"}},
		"collab.tag.show": map[string]any{
			"version":    "1.0.0",
			"created_at": int64(20),
			"message":    "m",
			"entries":    []map[string]any{{"doc": "a.md", "anchor": "a.md", "version": 2, "current_target": "alice:/proj/.collab-versions/a.md/v2", "target": "alice:/proj/.collab-versions/a.md/v2"}},
		},
		"collab.tag.diff":    map[string]any{"added": []map[string]any{{"doc": "b.md"}}, "removed": []map[string]any{{"doc": "old.md"}}, "modified": []map[string]any{{"doc": "a.md"}}},
		"collab.tag.restore": map[string]any{"restored_from": "1.0.0", "new_snapshot_version": "1.0.1", "warnings": []string{"skip deleted.md"}},
		"collab.tag.prune":   map[string]any{"pruned": 2},
	}}
	collab := newCollabFacade(client)

	list, err := collab.LsFiles(ctx, "alice:/proj")
	if err != nil {
		t.Fatalf("LsFiles 调用失败: %v (mock返回: %#v)", err, client.results["collab.ls-files"])
	}
	if len(list) != 1 || list[0].Doc != "a.md" || list[0].Anchor != "a.md" || list[0].Version != 2 {
		t.Fatalf("LsFiles 类型结果不正确: %#v err=%v", list, err)
	}
	show, err := collab.Show(ctx, "alice:/proj", "a.md", nil)
	if err != nil || show.Content != "YQ==" || show.Anchor != "a.md" || show.CurrentTarget != "alice:/proj/v2" {
		t.Fatalf("Show 类型结果不正确: %#v err=%v", show, err)
	}
	log, err := collab.Log(ctx, "alice:/proj", "a.md")
	if err != nil || len(log) != 1 || log[0].Time != 10 {
		t.Fatalf("Log 类型结果不正确: %#v err=%v", log, err)
	}
	diff, err := collab.Diff(ctx, "alice:/proj", "a.md", 1, 2)
	if err != nil || diff.Diff != "+b\n" || diff.From != 1 || diff.To != 2 {
		t.Fatalf("Diff 类型结果不正确: %#v err=%v", diff, err)
	}
	cloned, err := collab.Clone(ctx, "alice:/proj", "alice:/copy", false)
	if err != nil || !cloned.OK || cloned.CopiedObjects != 3 {
		t.Fatalf("Clone 类型结果不正确: %#v err=%v", cloned, err)
	}
	remotes, err := collab.LsRemote(ctx, "g.aid.com")
	if err != nil || len(remotes) != 1 || remotes[0].CollabRoot != "g.aid.com:/proj" {
		t.Fatalf("LsRemote 类型结果不正确: %#v err=%v", remotes, err)
	}
	tag, err := collab.Tag().Create(ctx, "alice:/proj", "m", true)
	if err != nil || tag.Version != "1.0.0" {
		t.Fatalf("Tag.Create 类型结果不正确: %#v err=%v", tag, err)
	}
	tags, err := collab.Tag().List(ctx, "alice:/proj")
	if err != nil || len(tags) != 1 || tags[0].CreatedAt != 20 {
		t.Fatalf("Tag.List 类型结果不正确: %#v err=%v", tags, err)
	}
	shown, err := collab.Tag().Show(ctx, "alice:/proj", "1.0.0")
	if err != nil || len(shown.Entries) != 1 || shown.Entries[0].Anchor != "a.md" || !strings.HasPrefix(shown.Entries[0].CurrentTarget, "alice:/proj/") || !strings.HasPrefix(shown.Entries[0].Target, "alice:/proj/") {
		t.Fatalf("Tag.Show 类型结果不正确: %#v err=%v", shown, err)
	}
	tagDiff, err := collab.Tag().Diff(ctx, "alice:/proj", "1.0.0", "1.0.1")
	if err != nil || len(tagDiff.Added) != 1 || len(tagDiff.Removed) != 1 || len(tagDiff.Modified) != 1 {
		t.Fatalf("Tag.Diff 类型结果不正确: %#v err=%v", tagDiff, err)
	}
	restored, err := collab.Tag().Restore(ctx, "alice:/proj", "1.0.0", "restore")
	if err != nil || restored.NewSnapshotVersion != "1.0.1" || len(restored.Warnings) != 1 {
		t.Fatalf("Tag.Restore 类型结果不正确: %#v err=%v", restored, err)
	}
	pruned, err := collab.Tag().Prune(ctx, "alice:/proj", "2026-06-01", nil)
	if err != nil || pruned.Pruned != 2 {
		t.Fatalf("Tag.Prune 类型结果不正确: %#v err=%v", pruned, err)
	}
	lastParams := client.calls[len(client.calls)-1].params
	if lastParams["before"] != "2026-06-01" {
		t.Fatalf("Tag.Prune 应透传日期字符串 before: %#v", lastParams)
	}
}

func TestCollabConflictErrorPreservesServerFields(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{
		aid: "alice.agentid.pub",
		failMethods: map[string]error{
			"collab.commit": NewVersionConflictError(
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

	_, err := collab.Commit(ctx, "alice.aid.com:/proj", "d.md", "S", 3, "")
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

func TestCollabTagPruneOmitsNilOptionalParams(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	collab := newCollabFacade(client)

	if _, err := collab.Tag().Prune(ctx, "alice.aid.com:/proj", nil, nil); err != nil {
		t.Fatalf("Tag().Prune 失败: %v", err)
	}
	params := client.calls[0].params
	if !reflect.DeepEqual(params, map[string]any{"collab_root": "alice.aid.com:/proj"}) {
		t.Fatalf("nil 可选参数应被过滤: %#v", params)
	}
}
