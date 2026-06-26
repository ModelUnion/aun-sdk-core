//go:build integration

package aun

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestIntegration_CollabCreateShowCommitDiff(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	defer alice.Close()

	aliceAID := fmt.Sprintf("gocol%s.%s", rid, testIssuer())
	ensureConnected(t, alice, aliceAID)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	root := fmt.Sprintf("%s:/collab-go/%s/proj", aliceAID, rid)
	doc := "spec.md"
	defer cleanupCollabIntegrationRoot(t, alice, aliceAID, root)

	created, err := alice.Collab().Create(ctx, root, doc, collabB64("a\n"))
	if err != nil {
		t.Fatalf("collab.create 调用失败: %v", err)
	}
	if created.Version != 1 {
		t.Fatalf("collab.create version 异常: %#v", created)
	}
	if target := created.CurrentTarget; !strings.HasPrefix(target, aliceAID+":/") {
		t.Fatalf("collab.create current_target 应为完整 AID path: %#v", created)
	}

	shown, err := alice.Collab().Show(ctx, root, doc, nil)
	if err != nil {
		t.Fatalf("collab.show 调用失败: %v", err)
	}
	if shown.Version != 1 || collabText(t, shown.Content) != "a\n" {
		t.Fatalf("collab.show 返回异常: %#v", shown)
	}

	committed, err := alice.Collab().Commit(ctx, root, doc, collabB64("a\nb\n"), 1, "Update content")
	if err != nil {
		t.Fatalf("collab.commit 调用失败: %v", err)
	}
	if committed.Version != 2 {
		t.Fatalf("collab.commit version 异常: %#v", committed)
	}

	diff, err := alice.Collab().Diff(ctx, root, doc, 1, 2)
	if err != nil {
		t.Fatalf("collab.diff 调用失败: %v", err)
	}
	if !strings.Contains(diff.Diff, "+b") {
		t.Fatalf("collab.diff 未返回新增行: %#v", diff)
	}

	_, err = alice.Call(ctx, "storage.collab.show", map[string]any{
		"collab_root": root,
		"doc":         doc,
	})
	if err == nil {
		t.Fatalf("storage.collab.* 不应可用")
	}
}

func TestIntegration_CollabAdvancedMergeTagClone(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	defer alice.Close()

	aliceAID := fmt.Sprintf("gocoladv%s.%s", rid, testIssuer())
	ensureConnected(t, alice, aliceAID)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	root := fmt.Sprintf("%s:/collab-go/%s/advanced", aliceAID, rid)
	cloneRoot := fmt.Sprintf("%s:/collab-go/%s/clone", aliceAID, rid)
	adoptRoot := fmt.Sprintf("%s:/collab-go/%s/adopt", aliceAID, rid)
	doc := "guide.md"
	defer cleanupCollabIntegrationRoot(t, alice, aliceAID, root)
	defer cleanupCollabIntegrationRoot(t, alice, aliceAID, cloneRoot)
	defer cleanupCollabIntegrationRoot(t, alice, aliceAID, adoptRoot)

	if _, err := alice.Collab().Create(ctx, root, doc, collabB64("line1\nline2\nline3\n")); err != nil {
		t.Fatalf("collab.create 调用失败: %v", err)
	}
	if _, err := alice.Collab().Commit(ctx, root, doc, collabB64("line1\nLINE2\nline3\n"), 1, "theirs"); err != nil {
		t.Fatalf("collab.commit 调用失败: %v", err)
	}

	merged, err := alice.Collab().Merge(ctx, root, doc, collabB64("line1\nline2\nLINE3\n"), 1)
	if err != nil {
		t.Fatalf("collab.merge 无冲突失败: %v", err)
	}
	if merged.Conflicts || collabText(t, merged.Content) != "line1\nLINE2\nLINE3\n" {
		t.Fatalf("collab.merge 无冲突返回异常: %#v", merged)
	}

	if _, err := alice.Collab().Commit(ctx, root, doc, collabB64("stale\n"), 1, "stale"); err == nil {
		t.Fatalf("collab.commit stale onto 应触发冲突")
	} else {
		var conflict *CollabConflictError
		if !errors.As(err, &conflict) {
			t.Fatalf("collab.commit stale 应映射为 CollabConflictError，got %T: %v", err, err)
		}
		if conflict.CurrentVersion == nil || *conflict.CurrentVersion != 2 || conflict.CurrentTarget == "" || !strings.Contains(strings.ToLower(conflict.Hint), "merge") {
			t.Fatalf("collab.commit stale 冲突字段异常: version=%v target=%q hint=%q err=%v", conflict.CurrentVersion, conflict.CurrentTarget, conflict.Hint, err)
		}
	}

	conflictRoot := fmt.Sprintf("%s:/collab-go/%s/conflict", aliceAID, rid)
	defer cleanupCollabIntegrationRoot(t, alice, aliceAID, conflictRoot)
	if _, err := alice.Collab().Create(ctx, conflictRoot, doc, collabB64("X\n")); err != nil {
		t.Fatalf("conflict create 失败: %v", err)
	}
	if _, err := alice.Collab().Commit(ctx, conflictRoot, doc, collabB64("THEIRS\n"), 1, "theirs"); err != nil {
		t.Fatalf("conflict commit 失败: %v", err)
	}
	conflict, err := alice.Collab().Merge(ctx, conflictRoot, doc, collabB64("OURS\n"), 1)
	if err != nil {
		t.Fatalf("collab.merge 冲突模式失败: %v", err)
	}
	if !conflict.Conflicts || !strings.Contains(collabText(t, conflict.Content), "<<<<<<< ours") {
		t.Fatalf("collab.merge 冲突返回异常: %#v", conflict)
	}

	tag1, err := alice.Collab().Tag().Create(ctx, root, "init", false)
	if err != nil {
		t.Fatalf("collab.tag.create init 失败: %v", err)
	}
	if tag1.Version != "1.0.0" {
		t.Fatalf("tag1 version 异常: %#v", tag1)
	}
	if _, err := alice.Collab().Commit(ctx, root, doc, collabB64("line1\nLINE2\nLINE3\nv4\n"), 2, "patch"); err != nil {
		t.Fatalf("patch commit 失败: %v", err)
	}
	tag2, err := alice.Collab().Tag().Create(ctx, root, "patch", false)
	if err != nil {
		t.Fatalf("collab.tag.create patch 失败: %v", err)
	}
	if tag2.Version != "1.0.1" {
		t.Fatalf("tag2 version 异常: %#v", tag2)
	}
	tags, err := alice.Collab().Tag().List(ctx, root)
	if err != nil {
		t.Fatalf("collab.tag.list 失败: %v", err)
	}
	if len(tags) < 2 || tags[0].Version != "1.0.0" || tags[1].Version != "1.0.1" {
		t.Fatalf("tag list 返回异常: %#v", tags)
	}
	shownTag, err := alice.Collab().Tag().Show(ctx, root, "1.0.0")
	if err != nil {
		t.Fatalf("collab.tag.show 失败: %v", err)
	}
	if !collabTagHasDoc(shownTag, doc) {
		t.Fatalf("tag show 未包含文档: %#v", shownTag)
	}
	tagDiff, err := alice.Collab().Tag().Diff(ctx, root, "1.0.0", "1.0.1")
	if err != nil {
		t.Fatalf("collab.tag.diff 失败: %v", err)
	}
	if len(tagDiff.Changed) == 0 && len(tagDiff.Modified) == 0 {
		t.Fatalf("tag diff 未报告变化: %#v", tagDiff)
	}
	restored, err := alice.Collab().Tag().Restore(ctx, root, "1.0.0", "restore")
	if err != nil {
		t.Fatalf("collab.tag.restore 失败: %v", err)
	}
	if restored.RestoredFrom != "1.0.0" {
		t.Fatalf("tag restore 返回异常: %#v", restored)
	}
	afterRestore, err := alice.Collab().Show(ctx, root, doc, nil)
	if err != nil {
		t.Fatalf("restore 后 show 失败: %v", err)
	}
	if collabText(t, afterRestore.Content) != "line1\nLINE2\nline3\n" {
		t.Fatalf("restore 后内容异常: %#v", afterRestore)
	}

	cloned, err := alice.Collab().Clone(ctx, root, cloneRoot, false)
	if err != nil {
		t.Fatalf("collab.clone reroot=false 失败: %v", err)
	}
	if !cloned.OK || cloned.Dest != cloneRoot {
		t.Fatalf("clone reroot=false 返回异常: %#v", cloned)
	}
	clonedLog, err := alice.Collab().Log(ctx, cloneRoot, doc)
	if err != nil {
		t.Fatalf("clone 后 log 失败: %v", err)
	}
	if len(clonedLog) < 3 {
		t.Fatalf("clone 未复制版本台账: %#v", clonedLog)
	}

	adopted, err := alice.Collab().Clone(ctx, root, adoptRoot, true)
	if err != nil {
		t.Fatalf("collab.clone reroot=true 失败: %v", err)
	}
	if adopted.NewRoot != adoptRoot || adopted.NewAuthorityAID != aliceAID {
		t.Fatalf("clone reroot=true 返回异常: %#v", adopted)
	}

	reflog, err := alice.Collab().Reflog(ctx, root, doc, 20)
	if err != nil {
		t.Fatalf("collab.reflog 失败: %v", err)
	}
	if len(reflog) == 0 {
		t.Fatalf("collab.reflog 应返回审计记录")
	}
	pruned, err := alice.Collab().Prune(ctx, conflictRoot, doc)
	if err != nil {
		t.Fatalf("collab.prune 失败: %v", err)
	}
	if pruned.Pruned < 0 {
		t.Fatalf("collab.prune 返回异常: %#v", pruned)
	}
}

func collabB64(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}

func collabText(t *testing.T, content string) string {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		t.Fatalf("collab content base64 解码失败: %v, content=%q", err, content)
	}
	return string(decoded)
}

func collabTagHasDoc(tag CollabTag, doc string) bool {
	for _, entry := range tag.Entries {
		if entry.Doc == doc {
			return true
		}
	}
	return false
}

func cleanupCollabIntegrationRoot(t *testing.T, client *AUNClient, ownerAID, collabRoot string) {
	t.Helper()
	parts := strings.SplitN(collabRoot, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = client.Storage().Remove(ctx, parts[1], &RemoveOptions{Owner: ownerAID, Recursive: true})
}
