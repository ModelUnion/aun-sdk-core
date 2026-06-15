//go:build integration

package aun

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestIntegration_CollabCreateReadSubmitDiff(t *testing.T) {
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

	read, err := alice.Collab().Read(ctx, root, doc)
	if err != nil {
		t.Fatalf("collab.read 调用失败: %v", err)
	}
	if read.Version != 1 || collabText(t, read.Content) != "a\n" {
		t.Fatalf("collab.read 返回异常: %#v", read)
	}

	submitted, err := alice.Collab().Submit(ctx, root, doc, collabB64("a\nb\n"), 1)
	if err != nil {
		t.Fatalf("collab.submit 调用失败: %v", err)
	}
	if submitted.Version != 2 {
		t.Fatalf("collab.submit version 异常: %#v", submitted)
	}

	diff, err := alice.Collab().Diff(ctx, root, doc, 1, 2)
	if err != nil {
		t.Fatalf("collab.diff 调用失败: %v", err)
	}
	if !strings.Contains(diff.Diff, "+b") {
		t.Fatalf("collab.diff 未返回新增行: %#v", diff)
	}

	_, err = alice.Call(ctx, "storage.collab.read", map[string]any{
		"collab_root": root,
		"doc":         doc,
	})
	if err == nil {
		t.Fatalf("storage.collab.* 不应可用")
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
