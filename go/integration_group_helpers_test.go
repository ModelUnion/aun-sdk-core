//go:build integration

package aun

import (
	"context"
	"testing"
	"time"
)

func createGroup(t *testing.T, client *AUNClient, name string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := client.Call(ctx, "group.create", map[string]any{"name": name})
	if err != nil {
		t.Fatalf("创建群组失败: %v", err)
	}
	resultMap, _ := result.(map[string]any)
	if resultMap == nil {
		t.Fatalf("创建群组返回 nil")
	}
	group, _ := resultMap["group"].(map[string]any)
	if group == nil {
		t.Fatalf("创建群组返回 group 为 nil")
	}
	gid, _ := group["group_id"].(string)
	if gid == "" {
		t.Fatalf("创建群组返回 group_id 为空")
	}
	return gid
}

func addMember(t *testing.T, client *AUNClient, groupID, memberAID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := client.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      memberAID,
	})
	if err != nil {
		t.Fatalf("添加成员失败: %v", err)
	}
}

func groupPull(t *testing.T, client *AUNClient, groupID string, afterSeq int) []map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := client.Call(ctx, "group.pull", map[string]any{
		"group_id":  groupID,
		"after_seq": afterSeq,
		"limit":     50,
	})
	if err != nil {
		t.Fatalf("group.pull 失败: %v", err)
	}
	resultMap, _ := result.(map[string]any)
	if resultMap == nil {
		return nil
	}
	msgs, _ := resultMap["messages"].([]any)
	out := make([]map[string]any, 0, len(msgs))
	for _, raw := range msgs {
		if msg, ok := raw.(map[string]any); ok {
			out = append(out, msg)
		}
	}
	return out
}

func getPayloadText(msg map[string]any) string {
	payload, _ := msg["payload"].(map[string]any)
	if payload == nil {
		return ""
	}
	text, _ := payload["text"].(string)
	return text
}
