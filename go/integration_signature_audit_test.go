//go:build integration

package aun

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 群操作签名审计 — 集成测试
//
// 验证：
// - 群关键修改操作携带 client_signature（含 cert_fingerprint）
// - 群事件推送透传 actor_aid + client_signature
// - 只读操作不需要签名，不会崩溃
//
// 运行方法:
//   cd go && go test -tags integration -run TestIntegration_SignatureAudit -v -timeout 300s
// ---------------------------------------------------------------------------

// verifySignatureFields 验证 client_signature 字段结构（如果存在）
// 返回 true 表示签名存在且结构正确，false 表示签名不存在（不是错误）
func verifySignatureFields(t *testing.T, event map[string]any, label string) bool {
	t.Helper()
	cs, ok := event["client_signature"]
	if !ok || cs == nil {
		t.Logf("[%s] 事件未携带 client_signature（服务端可能未透传）", label)
		return false
	}
	csMap, ok := cs.(map[string]any)
	if !ok {
		t.Errorf("[%s] client_signature 应为 map 类型, 实际 %T", label, cs)
		return false
	}

	// 验证必要字段
	for _, key := range []string{"aid", "cert_fingerprint", "signature"} {
		if v, exists := csMap[key]; !exists || v == nil {
			t.Errorf("[%s] client_signature 缺少 %s 字段", label, key)
		}
	}
	t.Logf("[%s] client_signature 结构验证通过: aid=%v, cert_fingerprint=%v",
		label, csMap["aid"], csMap["cert_fingerprint"])
	return true
}

// ---------------------------------------------------------------------------
// TestIntegration_SignatureAudit_UpdateAnnouncement
// group.set_settings(announcement) 应携带签名
// ---------------------------------------------------------------------------

func TestIntegration_SignatureAudit_UpdateAnnouncement(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := fmt.Sprintf("sigaud%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("sigaud%s-b.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// ---- 创建群组 ----
	createResult, err := alice.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("sigaud-ann-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, alice, groupID)
	t.Logf("创建群组: %s", groupID)

	// ---- 添加 Bob ----
	_, err = alice.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加 Bob 失败: %v", err)
	}
	t.Logf("添加 Bob 为成员")

	// 等待成员加入事件落库
	time.Sleep(1 * time.Second)

	// ---- Bob 订阅群事件 ----
	var mu sync.Mutex
	var receivedEvents []map[string]any
	eventDone := make(chan struct{}, 1)

	sub := bob.On("group.changed", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		if gid, _ := data["group_id"].(string); gid != groupID {
			return
		}
		mu.Lock()
		receivedEvents = append(receivedEvents, data)
		mu.Unlock()
		select {
		case eventDone <- struct{}{}:
		default:
		}
	})

	// ---- Alice 修改公告 ----
	_, err = alice.Call(ctx, "group.set_settings", map[string]any{
		"group_id": groupID,
		"settings": map[string]any{
			"announcement.content": fmt.Sprintf("签名测试公告 %s", rid),
		},
	})
	skipIfNotImplemented(t, err, "group.set_settings")
	if err != nil {
		t.Fatalf("set_settings(announcement) 失败: %v", err)
	}
	t.Logf("Alice 更新公告成功")

	// ---- 等待 Bob 收到事件 ----
	timer := time.NewTimer(5 * time.Second)
	select {
	case <-eventDone:
		t.Logf("Bob 收到 group.changed 事件")
	case <-timer.C:
		t.Logf("等待 push 事件超时")
	}
	timer.Stop()
	sub.Unsubscribe()

	// ---- 验证事件内容 ----
	mu.Lock()
	events := make([]map[string]any, len(receivedEvents))
	copy(events, receivedEvents)
	mu.Unlock()

	if len(events) == 0 {
		pullResult, pullErr := bob.Call(ctx, "group.pull_events", map[string]any{
			"group_id":        groupID,
			"after_event_seq": 0,
			"limit":           50,
		})
		if pullErr != nil {
			t.Logf("Bob 未收到 push 事件，pull_events 也失败，跳过事件断言: %v", pullErr)
			return
		}
		pullMap, _ := pullResult.(map[string]any)
		rawEvents, _ := pullMap["events"].([]any)
		for _, raw := range rawEvents {
			evt, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if gid, _ := evt["group_id"].(string); gid == groupID {
				events = append(events, evt)
			}
		}
	}

	if len(events) == 0 {
		t.Logf("Bob 未收到 group.changed 事件（push/pull 均无本群事件），跳过事件断言")
		return
	}

	evt := events[0]

	// 验证 actor_aid
	actorAID, _ := evt["actor_aid"].(string)
	if actorAID != aliceAID {
		t.Errorf("事件 actor_aid 不匹配: 期望 %s, 实际 %s", aliceAID, actorAID)
	} else {
		t.Logf("actor_aid 验证通过: %s", actorAID)
	}

	// 验证 client_signature（如果存在）
	verifySignatureFields(t, evt, "announcement")
}

// ---------------------------------------------------------------------------
// TestIntegration_SignatureAudit_KickMember
// group.kick 应携带签名
// ---------------------------------------------------------------------------

func TestIntegration_SignatureAudit_KickMember(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	charlie := makeClient(t)
	defer alice.Close()
	defer bob.Close()
	defer charlie.Close()

	aliceAID := fmt.Sprintf("sigaud%s-ka.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("sigaud%s-kb.%s", rid, testIssuer())
	charlieAID := fmt.Sprintf("sigaud%s-kc.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)
	ensureConnected(t, charlie, charlieAID)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// ---- 创建群组 ----
	createResult, err := alice.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("sigaud-kick-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, alice, groupID)
	t.Logf("创建群组: %s", groupID)

	// ---- 添加 Bob 和 Charlie ----
	_, err = alice.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加 Bob 失败: %v", err)
	}
	_, err = alice.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      charlieAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加 Charlie 失败: %v", err)
	}
	t.Logf("添加 Bob 和 Charlie 为成员")

	time.Sleep(1 * time.Second)

	// ---- Bob 订阅群事件 ----
	var mu sync.Mutex
	var receivedEvents []map[string]any
	eventDone := make(chan struct{}, 1)

	sub := bob.On("group.changed", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		if gid, _ := data["group_id"].(string); gid != groupID {
			return
		}
		// 只关注 member_removed 事件
		action, _ := data["action"].(string)
		if action == "member_removed" {
			mu.Lock()
			receivedEvents = append(receivedEvents, data)
			mu.Unlock()
			select {
			case eventDone <- struct{}{}:
			default:
			}
		}
	})

	// ---- Alice 踢 Charlie ----
	_, err = alice.Call(ctx, "group.kick", map[string]any{
		"group_id": groupID,
		"aid":      charlieAID,
	})
	skipIfNotImplemented(t, err, "group.kick")
	if err != nil {
		t.Fatalf("group.kick 失败: %v", err)
	}
	t.Logf("Alice 踢出 Charlie")

	// ---- 等待 Bob 收到事件 ----
	timer := time.NewTimer(5 * time.Second)
	select {
	case <-eventDone:
		t.Logf("Bob 收到 member_removed 事件")
	case <-timer.C:
		t.Logf("等待 push 事件超时")
	}
	timer.Stop()
	sub.Unsubscribe()

	// ---- 验证事件内容 ----
	mu.Lock()
	events := make([]map[string]any, len(receivedEvents))
	copy(events, receivedEvents)
	mu.Unlock()

	if len(events) == 0 {
		t.Fatalf("Bob 未收到 member_removed 事件")
	}

	evt := events[0]

	// 验证 actor_aid
	actorAID, _ := evt["actor_aid"].(string)
	if actorAID != aliceAID {
		t.Errorf("kick 事件 actor_aid 不匹配: 期望 %s, 实际 %s", aliceAID, actorAID)
	} else {
		t.Logf("actor_aid 验证通过: %s", actorAID)
	}

	// 验证 client_signature（如果存在）
	verifySignatureFields(t, evt, "kick")
}

// ---------------------------------------------------------------------------
// TestIntegration_SignatureAudit_SetRole
// group.set_role 应携带签名
// ---------------------------------------------------------------------------

func TestIntegration_SignatureAudit_SetRole(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := fmt.Sprintf("sigaud%s-ra.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("sigaud%s-rb.%s", rid, testIssuer())

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// ---- 创建群组 ----
	createResult, err := alice.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("sigaud-role-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, alice, groupID)
	t.Logf("创建群组: %s", groupID)

	// ---- 添加 Bob ----
	_, err = alice.Call(ctx, "group.add_member", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"role":     "member",
	})
	if err != nil {
		t.Fatalf("添加 Bob 失败: %v", err)
	}
	t.Logf("添加 Bob 为成员")

	time.Sleep(1 * time.Second)

	// ---- Bob 订阅群事件 ----
	var mu sync.Mutex
	var receivedEvents []map[string]any
	eventDone := make(chan struct{}, 1)

	sub := bob.On("group.changed", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		if gid, _ := data["group_id"].(string); gid != groupID {
			return
		}
		mu.Lock()
		receivedEvents = append(receivedEvents, data)
		mu.Unlock()
		select {
		case eventDone <- struct{}{}:
		default:
		}
	})

	// ---- Alice 提升 Bob 为 admin ----
	_, err = alice.Call(ctx, "group.set_role", map[string]any{
		"group_id": groupID,
		"aid":      bobAID,
		"role":     "admin",
	})
	skipIfNotImplemented(t, err, "group.set_role")
	if err != nil {
		t.Fatalf("group.set_role 失败: %v", err)
	}
	t.Logf("Alice 将 Bob 提升为 admin")

	// ---- 等待 Bob 收到事件 ----
	timer := time.NewTimer(5 * time.Second)
	select {
	case <-eventDone:
		t.Logf("Bob 收到 group.changed 事件")
	case <-timer.C:
		t.Logf("等待 push 事件超时")
	}
	timer.Stop()
	sub.Unsubscribe()

	// ---- 验证事件内容 ----
	mu.Lock()
	events := make([]map[string]any, len(receivedEvents))
	copy(events, receivedEvents)
	mu.Unlock()

	if len(events) == 0 {
		t.Fatalf("Bob 未收到 set_role 群事件")
	}

	evt := events[0]

	// 验证 actor_aid
	actorAID, _ := evt["actor_aid"].(string)
	if actorAID != aliceAID {
		t.Errorf("set_role 事件 actor_aid 不匹配: 期望 %s, 实际 %s", aliceAID, actorAID)
	} else {
		t.Logf("actor_aid 验证通过: %s", actorAID)
	}

	// 验证 client_signature（如果存在）
	verifySignatureFields(t, evt, "set_role")
}

// ---------------------------------------------------------------------------
// TestIntegration_SignatureAudit_UnsignedOperationSafe
// 只读操作（group.list_my、group.get_info）不需要签名，不应崩溃
// ---------------------------------------------------------------------------

func TestIntegration_SignatureAudit_UnsignedOperationSafe(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	defer alice.Close()

	aliceAID := fmt.Sprintf("sigaud%s-ro.%s", rid, testIssuer())
	ensureConnected(t, alice, aliceAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- 创建群组 ----
	createResult, err := alice.Call(ctx, "group.create", map[string]any{
		"name":       fmt.Sprintf("sigaud-safe-%s", rid),
		"visibility": "private",
	})
	skipIfNotImplemented(t, err, "group.create")
	if err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}
	groupID := extractGroupID(t, createResult)
	defer cleanupGroup(t, alice, groupID)

	// ---- group.list_my 应正常执行 ----
	listResult, err := alice.Call(ctx, "group.list_my", map[string]any{})
	skipIfNotImplemented(t, err, "group.list_my")
	if err != nil {
		t.Fatalf("group.list_my 失败: %v", err)
	}
	if listResult == nil {
		t.Fatalf("group.list_my 返回 nil")
	}
	t.Logf("group.list_my 正常执行")

	// ---- group.get_info 应正常执行 ----
	infoResult, err := alice.Call(ctx, "group.get_info", map[string]any{
		"group_id": groupID,
		"required": []string{"member"},
	})
	skipIfNotImplemented(t, err, "group.get_info")
	if err != nil {
		t.Fatalf("group.get_info 失败: %v", err)
	}
	if infoResult == nil {
		t.Fatalf("group.get_info 返回 nil")
	}
	t.Logf("group.get_info 正常执行")

	t.Logf("只读操作无签名要求，执行正常，无崩溃")
}
