//go:build integration

package aun

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func makeFederationClient(t *testing.T) *AUNClient {
	t.Helper()
	t.Setenv("AUN_ENV", "development")
	client := newClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	client.configModel.RequireForwardSecrecy = false
	return client
}

func ensureFederationConnected(t *testing.T, client *AUNClient, aid string) string {
	t.Helper()
	integrationRegisterOrLoadAID(t, client.configModel.AUNPath, aid)
	integrationConnectLoadedAID(t, client, aid, nil)
	return aid
}

func federationRunID() string {
	return generateUUID4()[:12]
}

func federationWaitForMessages(
	t *testing.T,
	client *AUNClient,
	puller func() []map[string]any,
	timeout time.Duration,
	check func([]map[string]any) bool,
	label string,
) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last []map[string]any
	for time.Now().Before(deadline) {
		last = puller()
		if check(last) {
			return last
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("%s 超时: %+v", label, last)
	return nil
}

func TestFederationSDKToSDKPrekey(t *testing.T) {
	rid := federationRunID()
	alice := makeFederationClient(t)
	bob := makeFederationClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := ensureFederationConnected(t, alice, fmt.Sprintf("go-fed-a-%s.aid.com", rid))
	bobAID := ensureFederationConnected(t, bob, fmt.Sprintf("go-fed-b-%s.aid.net", rid))

	text := fmt.Sprintf("go federation hello %s", rid)

	// 用事件订阅捕获 push（auto-ack 会推进 cursor，pull 可能拿不到）
	waitBob := collectSDKPushMessages(bob, aliceAID, 1, func(msg map[string]any) bool {
		return getPayloadText(msg) == text
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	result, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": text},
		"encrypt": true,
	})
	if err != nil {
		t.Fatalf("跨域发送失败: %v", err)
	}
	if resultMap, _ := result.(map[string]any); resultMap == nil {
		t.Fatalf("跨域发送返回 nil")
	}

	msgs := waitBob(20 * time.Second)
	if len(msgs) < 1 {
		t.Fatalf("等待 Bob 收到跨域 E2EE 消息 超时")
	}

	target := msgs[0]

	encrypted, _ := target["encrypted"].(bool)
	if !encrypted {
		t.Fatalf("目标消息应为加密消息: %+v", target)
	}
	e2ee, _ := target["e2ee"].(map[string]any)
	if e2ee == nil {
		t.Fatalf("目标消息缺少 e2ee 字段: %+v", target)
	}
	if ver, _ := e2ee["version"].(string); ver != "v2" {
		t.Fatalf("跨域消息 E2EE version 错误: %+v", e2ee)
	}
	if mode, _ := e2ee["encryption_mode"].(string); !strings.HasPrefix(mode, "v2_") {
		t.Fatalf("跨域消息加密模式错误: %v", e2ee["encryption_mode"])
	}
	if fs, _ := e2ee["forward_secrecy"].(bool); !fs {
		t.Fatalf("跨域消息应标记 forward_secrecy=true: %+v", e2ee)
	}
}

func TestFederationGroupBasicFlow(t *testing.T) {
	rid := federationRunID()
	alice := makeFederationClient(t)
	bob := makeFederationClient(t)
	eve := makeFederationClient(t)
	defer alice.Close()
	defer bob.Close()
	defer eve.Close()

	_ = ensureFederationConnected(t, alice, fmt.Sprintf("go-grp-a-%s.aid.com", rid))
	bobAID := ensureFederationConnected(t, bob, fmt.Sprintf("go-grp-b-%s.aid.net", rid))
	eveAID := ensureFederationConnected(t, eve, fmt.Sprintf("go-grp-e-%s.aid.net", rid))
	_ = eveAID

	groupID := createGroup(t, alice, fmt.Sprintf("go-fed-group-%s", rid))
	addMember(t, alice, groupID, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	send1, err := alice.Call(ctx, "group.send", map[string]any{
		"group_id": groupID,
		"payload":  map[string]any{"type": "text", "text": fmt.Sprintf("go-group-msg-1-%s", rid)},
		"encrypt":  false,
	})
	if err != nil {
		t.Fatalf("群消息发送失败: %v", err)
	}
	if send1Map, _ := send1.(map[string]any); send1Map == nil {
		t.Fatalf("群消息发送返回 nil")
	}

	want1 := fmt.Sprintf("go-group-msg-1-%s", rid)
	deadline := time.Now().Add(20 * time.Second)
	var bobMsgs []map[string]any
	for time.Now().Before(deadline) {
		bobMsgs = groupPull(t, bob, groupID, 0)
		found := false
		for _, msg := range bobMsgs {
			if getPayloadText(msg) == want1 {
				found = true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	found1 := false
	for _, msg := range bobMsgs {
		if getPayloadText(msg) == want1 {
			found1 = true
			break
		}
	}
	if !found1 {
		t.Fatalf("Bob 未收到跨域群消息: %+v", bobMsgs)
	}

	inviteResult, err := alice.Call(ctx, "group.create_invite_code", map[string]any{
		"group_id": groupID,
		"max_uses": 1,
	})
	if err != nil {
		t.Fatalf("创建邀请码失败: %v", err)
	}
	inviteMap, _ := inviteResult.(map[string]any)
	if inviteMap == nil {
		t.Fatalf("创建邀请码返回 nil")
	}
	inviteObj, _ := inviteMap["invite_code"].(map[string]any)
	code, _ := inviteObj["code_with_domain"].(string)
	if code == "" {
		code, _ = inviteObj["code"].(string)
	}
	if code == "" {
		t.Fatalf("邀请码为空: %+v", inviteMap)
	}

	joined, err := eve.Call(ctx, "group.use_invite_code", map[string]any{"code": code})
	if err != nil {
		t.Fatalf("Eve 跨域邀请码入群失败: %v", err)
	}
	joinedMap, _ := joined.(map[string]any)
	if joinedMap == nil {
		t.Fatalf("邀请码入群返回 nil")
	}
	groupObj, _ := joinedMap["group"].(map[string]any)
	gotGroupID, _ := groupObj["group_id"].(string)
	if gotGroupID != groupID {
		t.Fatalf("邀请码入群 group_id 异常: got=%s want=%s", gotGroupID, groupID)
	}

	want2 := fmt.Sprintf("go-group-msg-2-%s", rid)
	if _, err := alice.Call(ctx, "group.send", map[string]any{
		"group_id": groupID,
		"payload":  map[string]any{"type": "text", "text": want2},
		"encrypt":  false,
	}); err != nil {
		t.Fatalf("第二条群消息发送失败: %v", err)
	}

	deadline = time.Now().Add(20 * time.Second)
	var eveMsgs []map[string]any
	for time.Now().Before(deadline) {
		eveMsgs = groupPull(t, eve, groupID, 0)
		found := false
		for _, msg := range eveMsgs {
			if getPayloadText(msg) == want2 {
				found = true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	found2 := false
	for _, msg := range eveMsgs {
		if getPayloadText(msg) == want2 {
			found2 = true
			break
		}
	}
	if !found2 {
		t.Fatalf("Eve 邀码入群后未收到群消息: %+v", eveMsgs)
	}
}
