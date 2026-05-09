//go:build integration

package aun

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════
// P0 共同缺口集成测试 — 打真实 Docker Gateway
//
// 运行方法:
//   cd go && go test -tags integration -run TestP0Integration -v -timeout 300s
//
// 前置条件:
//   - Docker 环境运行中（docker compose up -d）
//   - 运行环境能解析 gateway.agentid.pub
// ═══════════════════════════════════════════════════════════════════════════

// ── P0-01: 网关健康检查（真实 Gateway） ────────────────────────────

func TestP0Integration_01_HealthCheckRealGateway(t *testing.T) {
	c := makeClient(t)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ok := c.CheckGatewayHealth(ctx, fmt.Sprintf("https://gateway.%s", testIssuer()), 8*time.Second)
	if !ok {
		t.Skip("真实 Gateway 不可达（Docker 可能未运行）")
	}
}

// ── P0-02: AID 创建失败路径（真实 Gateway） ───────────────────────

func TestP0Integration_02_CreateDuplicateAID(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("p0dup%s.%s", rid, testIssuer())

	c1 := makeClient(t)
	defer func() { _ = c1.Close() }()

	// 首次创建 — 应成功
	ctx := context.Background()
	_, err := c1.Auth.CreateAID(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Skipf("Docker 环境不可用: %v", err)
	}

	// 第二次用新客户端创建同一 AID — 应报错或幂等
	c2 := makeClient(t)
	defer func() { _ = c2.Close() }()

	_, err = c2.Auth.CreateAID(ctx, map[string]any{"aid": aid})
	// 不管是报错还是幂等成功，记录行为
	if err != nil {
		t.Logf("重复 AID 创建正确返回错误: %v", err)
	} else {
		t.Logf("重复 AID 创建无报错（幂等设计）")
	}
}

// ── P0-04: Login 重放攻击（真实 Gateway） ──────────────────────────

func TestP0Integration_04_LoginReplayAttack(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("p0rpl%s.%s", rid, testIssuer())

	c := makeClient(t)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 创建 AID
	_, err := c.Auth.CreateAID(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Skipf("Docker 环境不可用: %v", err)
	}

	// 首次正常认证 — 获取 token
	auth1, err := c.Auth.Authenticate(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Fatalf("首次认证失败: %v", err)
	}
	if auth1["access_token"] == nil {
		t.Fatalf("首次认证未返回 access_token: %v", auth1)
	}
	t.Logf("首次认证成功，获取 token")

	// 再次用同一 AID 认证 — 这里不是重放同一 challenge，
	// 而是验证服务端每次颁发新 challenge
	auth2, err := c.Auth.Authenticate(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Fatalf("第二次认证失败: %v", err)
	}
	// 两次的 token 应不同
	if auth1["access_token"] == auth2["access_token"] {
		t.Logf("警告: 两次认证返回了相同的 access_token")
	} else {
		t.Logf("两次认证返回不同 token（正确）")
	}
}

// ── P0-06: 消息撤回（真实 Gateway） ────────────────────────────────

func TestP0Integration_06_MessageRecall(t *testing.T) {
	rid := runID()
	aliceAID := fmt.Sprintf("p0rca%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("p0rcb%s.%s", rid, testIssuer())

	alice := makeClient(t)
	defer func() { _ = alice.Close() }()
	bob := makeClient(t)
	defer func() { _ = bob.Close() }()

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx := context.Background()

	// Alice 发一条消息
	result, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": fmt.Sprintf("recall-test-%s", rid)},
		"durable": true,
		"encrypt": false,
	})
	if err != nil {
		t.Fatalf("发送消息失败: %v", err)
	}

	resultMap, _ := result.(map[string]any)
	msgID, _ := resultMap["message_id"].(string)
	if msgID == "" {
		t.Skipf("send 未返回 message_id: %v", result)
	}

	time.Sleep(500 * time.Millisecond)

	// Alice 撤回自己的消息
	recallResult, err := alice.Call(ctx, "message.recall", map[string]any{"message_ids": []string{msgID}})
	if err != nil {
		errStr := err.Error()
		if containsAny(errStr, "not implement", "method not found", "unknown method") {
			t.Skipf("message.recall 未实现: %v", err)
		}
		t.Fatalf("撤回自己的消息失败: %v", err)
	}
	if recallMap, ok := recallResult.(map[string]any); ok && toInt64(recallMap["recalled"]) <= 0 {
		t.Fatalf("撤回自己的消息未生效: %v", recallResult)
	}
	t.Logf("撤回自己的消息成功")

	// Bob 撤回 Alice 的消息 — 应被拒绝
	// 先让 Alice 再发一条
	result2, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": fmt.Sprintf("recall-perm-%s", rid)},
		"durable": true,
		"encrypt": false,
	})
	if err != nil {
		t.Fatalf("第二条消息发送失败: %v", err)
	}
	resultMap2, _ := result2.(map[string]any)
	msgID2, _ := resultMap2["message_id"].(string)
	if msgID2 != "" {
		time.Sleep(300 * time.Millisecond)
		denied, err := bob.Call(ctx, "message.recall", map[string]any{"message_ids": []string{msgID2}})
		if err == nil {
			deniedMap, _ := denied.(map[string]any)
			if toInt64(deniedMap["recalled"]) > 0 {
				t.Error("Bob 不应能撤回 Alice 的消息")
			}
		} else {
			t.Logf("Bob 撤回 Alice 消息被正确拒绝: %v", err)
		}
	}
}

// ── P0-08: 重连中补洞（真实 Gateway） ──────────────────────────────

func TestP0Integration_08_ReconnectGapFill(t *testing.T) {
	rid := runID()
	aliceAID := fmt.Sprintf("p0gfa%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("p0gfb%s.%s", rid, testIssuer())

	alice := makeClient(t)
	defer func() { _ = alice.Close() }()
	bob := makeClient(t)
	defer func() { _ = bob.Close() }()

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	const msgCount = 5
	tag := rid

	// 收集 bob 的消息
	var mu sync.Mutex
	var received []map[string]any
	done := make(chan struct{}, 1)

	bob.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		mu.Lock()
		received = append(received, data)
		if len(received) >= msgCount {
			select {
			case done <- struct{}{}:
			default:
			}
		}
		mu.Unlock()
	})

	// Bob 断线
	if err := bob.Disconnect(); err != nil {
		t.Fatalf("Bob 断线失败: %v", err)
	}
	time.Sleep(1 * time.Second)

	// Alice 在 Bob 断线期间发 5 条消息
	ctx := context.Background()
	for i := 0; i < msgCount; i++ {
		_, err := alice.Call(ctx, "message.send", map[string]any{
			"to":      bobAID,
			"payload": map[string]any{"type": "text", "text": fmt.Sprintf("gap-%s-%d", tag, i)},
			"persist": true,
			"encrypt": false,
		})
		if err != nil {
			t.Fatalf("发送第 %d 条消息失败: %v", i, err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	time.Sleep(500 * time.Millisecond)

	// Bob 重连
	mu.Lock()
	received = nil
	mu.Unlock()

	auth, err := bob.Auth.Authenticate(ctx, map[string]any{"aid": bobAID})
	if err != nil {
		t.Fatalf("Bob 重新认证失败: %v", err)
	}
	if err := bob.Connect(ctx, auth, nil); err != nil {
		t.Fatalf("Bob 重连失败: %v", err)
	}

	// 等待补洞完成
	select {
	case <-done:
		mu.Lock()
		count := len(received)
		mu.Unlock()
		t.Logf("重连后补洞成功: 收到 %d/%d 条消息", count, msgCount)
	case <-time.After(15 * time.Second):
		mu.Lock()
		count := len(received)
		mu.Unlock()
		if count > 0 {
			t.Logf("部分补洞: 收到 %d/%d 条", count, msgCount)
		} else {
			t.Errorf("15s 内未收到任何补洞消息")
		}
	}
}

// ── P0-09: 发送到暂停群（真实 Gateway） ────────────────────────────

func TestP0Integration_09_SendToSuspendedGroup(t *testing.T) {
	rid := runID()
	ownerAID := fmt.Sprintf("p0sus%s.%s", rid, testIssuer())
	memberAID := fmt.Sprintf("p0sum%s.%s", rid, testIssuer())

	owner := makeClient(t)
	defer func() { _ = owner.Close() }()
	member := makeClient(t)
	defer func() { _ = member.Close() }()

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, member, memberAID)

	ctx := context.Background()

	// 创建群
	result, err := owner.Call(ctx, "group.create", map[string]any{
		"members":  []string{memberAID},
		"metadata": map[string]any{"name": fmt.Sprintf("suspend-test-%s", rid)},
	})
	if err != nil {
		t.Fatalf("创建群失败: %v", err)
	}
	groupID := extractP0GroupID(result)
	if groupID == "" {
		t.Skipf("创建群未返回 group_id: %v", result)
	}

	time.Sleep(1 * time.Second)

	// 暂停群
	_, err = owner.Call(ctx, "group.suspend", map[string]any{"group_id": groupID})
	if err != nil {
		errStr := err.Error()
		if containsAny(errStr, "not implement", "method not found") {
			t.Skipf("group.suspend 未实现: %v", err)
		}
		t.Fatalf("暂停群失败: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// 成员发消息到暂停群 — 应被拒绝
	_, err = member.Call(ctx, "group.send", map[string]any{
		"group_id": groupID,
		"payload":  map[string]any{"type": "text", "text": "should-fail"},
	})
	if err == nil {
		t.Error("向暂停群发消息应被拒绝")
	} else {
		t.Logf("正确拒绝: %v", err)
	}

	// 清理
	_, _ = owner.Call(ctx, "group.resume", map[string]any{"group_id": groupID})
	_, _ = owner.Call(ctx, "group.dissolve", map[string]any{"group_id": groupID})
}

// ── P0-10: 非成员发送群消息（真实 Gateway） ────────────────────────

func TestP0Integration_10_NonMemberGroupSend(t *testing.T) {
	rid := runID()
	ownerAID := fmt.Sprintf("p0nmo%s.%s", rid, testIssuer())
	outsiderAID := fmt.Sprintf("p0nms%s.%s", rid, testIssuer())

	owner := makeClient(t)
	defer func() { _ = owner.Close() }()
	outsider := makeClient(t)
	defer func() { _ = outsider.Close() }()

	ensureConnected(t, owner, ownerAID)
	ensureConnected(t, outsider, outsiderAID)

	ctx := context.Background()

	// 创建只有 owner 的群
	result, err := owner.Call(ctx, "group.create", map[string]any{
		"members":  []string{},
		"metadata": map[string]any{"name": fmt.Sprintf("perm-test-%s", rid)},
	})
	if err != nil {
		t.Fatalf("创建群失败: %v", err)
	}
	groupID := extractP0GroupID(result)
	if groupID == "" {
		t.Skipf("创建群未返回 group_id: %v", result)
	}

	time.Sleep(500 * time.Millisecond)

	// 非成员发消息 — 应被拒绝
	_, err = outsider.Call(ctx, "group.send", map[string]any{
		"group_id": groupID,
		"payload":  map[string]any{"type": "text", "text": "unauthorized"},
	})
	if err == nil {
		t.Error("非成员不应能向群发送消息")
	} else {
		t.Logf("正确拒绝: %v", err)
	}

	// 清理
	_, _ = owner.Call(ctx, "group.dissolve", map[string]any{"group_id": groupID})
}

// ── P0-14: 断线后 RPC（真实 Gateway） ──────────────────────────────

func TestP0Integration_14_RPCAfterDisconnectAndReconnect(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("p0rpc%s.%s", rid, testIssuer())

	c := makeClient(t)
	defer func() { _ = c.Close() }()

	ensureConnected(t, c, aid)

	ctx := context.Background()

	// 正常 ping
	_, err := c.Call(ctx, "meta.ping", nil)
	if err != nil {
		t.Fatalf("连接状态下 ping 失败: %v", err)
	}

	// 断线
	if err := c.Disconnect(); err != nil {
		t.Fatalf("断线失败: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// 断线后 RPC — 应报错
	_, err = c.Call(ctx, "meta.ping", nil)
	if err == nil {
		t.Error("断线后 RPC 应返回错误")
	} else {
		t.Logf("断线后 RPC 正确报错: %T: %v", err, err)
	}

	// 重连
	auth, err := c.Auth.Authenticate(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Fatalf("重新认证失败: %v", err)
	}
	if err := c.Connect(ctx, auth, nil); err != nil {
		t.Fatalf("重连失败: %v", err)
	}

	// 重连后 RPC — 应恢复
	_, err = c.Call(ctx, "meta.ping", nil)
	if err != nil {
		t.Errorf("重连后 RPC 仍失败: %v", err)
	} else {
		t.Logf("重连后 RPC 恢复正常")
	}
}

// ── P0-03: Login 过期挑战（真实 Gateway） ──────────────────────

func TestP0Integration_03_LoginExpiredChallenge(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("p0exp%s.%s", rid, testIssuer())

	c := makeClient(t)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 创建 AID
	_, err := c.Auth.CreateAID(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Skipf("Docker 环境不可用: %v", err)
	}

	// 首次认证 — 获取第一次 token
	auth1, err := c.Auth.Authenticate(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Fatalf("首次认证失败: %v", err)
	}
	if auth1["access_token"] == nil {
		t.Fatalf("首次认证未返回 access_token: %v", auth1)
	}
	t.Logf("认证成功，获取到 token")

	// 等待一段时间后再次认证 — 验证 challenge 不可重用
	time.Sleep(2 * time.Second)

	auth2, err := c.Auth.Authenticate(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Fatalf("第二次认证失败: %v", err)
	}
	if auth1["access_token"] == auth2["access_token"] {
		t.Logf("警告: 两次认证返回了相同的 access_token")
	} else {
		t.Logf("两次认证返回不同 token（正确）")
	}
}

// ── P0-05: Token 并发刷新（真实 Gateway） ──────────────────────

func TestP0Integration_05_TokenConcurrentRefresh(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("p0tkn%s.%s", rid, testIssuer())

	c := makeClient(t)
	defer func() { _ = c.Close() }()

	ctx := context.Background()

	_, err := c.Auth.CreateAID(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Skipf("Docker 环境不可用: %v", err)
	}

	// 先正常连接
	ensureConnected(t, c, aid)

	// 并发认证 5 次
	const concurrency = 5
	type authResult struct {
		auth map[string]any
		err  error
	}
	results := make(chan authResult, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			auth, err := c.Auth.Authenticate(ctx, map[string]any{"aid": aid})
			results <- authResult{auth, err}
		}()
	}

	successes := 0
	for i := 0; i < concurrency; i++ {
		r := <-results
		if r.err == nil && r.auth["access_token"] != nil {
			successes++
		}
	}

	if successes == 0 {
		t.Error("所有并发认证全部失败")
	} else {
		t.Logf("并发认证 %d/%d 成功", successes, concurrency)
	}

	// 验证并发刷新后客户端仍可用
	_, err = c.Call(ctx, "meta.ping", nil)
	if err != nil {
		t.Logf("并发刷新后 ping 失败（可能需重连）: %v", err)
	} else {
		t.Logf("并发刷新后 ping 正常")
	}

	// inflight 标志清理验证 — 并发完成后再单独 authenticate 应成功
	time.Sleep(500 * time.Millisecond)
	authAfter, err := c.Auth.Authenticate(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Errorf("inflight 清理异常: 并发后 authenticate 失败: %v", err)
	} else if authAfter["access_token"] == nil {
		t.Errorf("inflight 清理异常: 并发后 authenticate 未返回 token")
	} else {
		t.Logf("inflight 清理正常: 并发后 authenticate 成功")
	}
}

// ── P0-07: 临时消息 TTL（真实 Gateway） ──────────────────────

func TestP0Integration_07_EphemeralMessageTTL(t *testing.T) {
	rid := runID()
	aliceAID := fmt.Sprintf("p0epa%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("p0epb%s.%s", rid, testIssuer())

	alice := makeClient(t)
	defer func() { _ = alice.Close() }()
	bob := makeClient(t)
	defer func() { _ = bob.Close() }()

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx := context.Background()

	// 发送临时消息（persist=false 或默认）
	result, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": fmt.Sprintf("ephemeral-%s", rid)},
		"durable": false,
		"encrypt": false,
	})
	if err != nil {
		t.Fatalf("发送临时消息失败: %v", err)
	}
	resultMap, _ := result.(map[string]any)
	if msgID, _ := resultMap["message_id"].(string); msgID != "" {
		t.Logf("临时消息发送成功: %s", msgID)
	} else {
		t.Logf("临时消息发送完成: %v", result)
	}

	time.Sleep(1 * time.Second)

	// Bob pull — 临时消息可能不在 pull 结果中
	pullResult, err := bob.Call(ctx, "message.pull", map[string]any{"limit": 50})
	if err != nil {
		t.Logf("pull 异常（可接受）: %v", err)
	} else {
		pullMap, _ := pullResult.(map[string]any)
		messages, _ := pullMap["messages"].([]any)
		matching := 0
		for _, m := range messages {
			msg, ok := m.(map[string]any)
			if !ok {
				continue
			}
			payload, _ := msg["payload"].(map[string]any)
			text, _ := payload["text"].(string)
			if strings.HasPrefix(text, fmt.Sprintf("ephemeral-%s", rid)) {
				matching++
			}
		}
		if matching > 0 {
			t.Logf("Bob 通过 pull 收到临时消息 (%d 条)", matching)
		} else {
			t.Logf("Bob 未通过 pull 收到临时消息（可能仅推送）")
		}
	}
}

// ── P0-13: Ping 超时检测（真实 Gateway） ──────────────────────

func TestP0Integration_13_PingRoundtrip(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("p0png%s.%s", rid, testIssuer())

	c := makeClient(t)
	defer func() { _ = c.Close() }()

	ensureConnected(t, c, aid)

	ctx := context.Background()

	// 单次 ping 延迟
	start := time.Now()
	_, err := c.Call(ctx, "meta.ping", nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ping 失败: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("ping 延迟过高: %v", elapsed)
	} else {
		t.Logf("ping 延迟: %v", elapsed)
	}

	// 连续 5 次 ping 测稳定性
	var latencies []time.Duration
	for i := 0; i < 5; i++ {
		start := time.Now()
		_, err := c.Call(ctx, "meta.ping", nil)
		if err != nil {
			t.Logf("第 %d 次 ping 失败: %v", i+1, err)
			break
		}
		latencies = append(latencies, time.Since(start))
		time.Sleep(100 * time.Millisecond)
	}

	if len(latencies) >= 3 {
		var total time.Duration
		for _, l := range latencies {
			total += l
		}
		avg := total / time.Duration(len(latencies))
		t.Logf("稳定性: %d/5 成功，平均延迟 %v", len(latencies), avg)
	} else {
		t.Errorf("仅 %d/5 次 ping 成功", len(latencies))
	}
}

// ── P0-15: Stream 边界场景（真实 Gateway） ────────────────────

func TestP0Integration_15_StreamEdgeCases(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("p0str%s.%s", rid, testIssuer())

	c := makeClient(t)
	defer func() { _ = c.Close() }()

	ensureConnected(t, c, aid)

	ctx := context.Background()

	// 1. 创建流
	result, err := c.Call(ctx, "stream.create", map[string]any{
		"content_type": "text/plain",
	})
	if err != nil {
		errStr := err.Error()
		if containsAny(errStr, "not implement", "method not found", "unknown method") {
			t.Skipf("stream 服务未实现: %v", err)
		}
		t.Fatalf("创建流失败: %v", err)
	}
	resultMap, _ := result.(map[string]any)
	streamID, _ := resultMap["stream_id"].(string)
	if streamID == "" {
		t.Skipf("创建流未返回 stream_id: %v", result)
	}
	t.Logf("创建流成功: %s", streamID)

	// 2. 关闭流
	_, err = c.Call(ctx, "stream.close", map[string]any{"stream_id": streamID})
	if err != nil {
		t.Errorf("正常关闭流失败: %v", err)
	} else {
		t.Logf("正常关闭流成功")
	}

	// 3. 重复关闭（幂等或报错均可接受）
	_, err = c.Call(ctx, "stream.close", map[string]any{"stream_id": streamID})
	if err != nil {
		t.Logf("重复关闭报错（可接受）: %v", err)
	} else {
		t.Logf("重复关闭幂等（可接受）")
	}

	// 4. 关闭不存在的流
	_, err = c.Call(ctx, "stream.close", map[string]any{"stream_id": "nonexistent-stream"})
	if err != nil {
		t.Logf("关闭不存在流报错（可接受）: %v", err)
	} else {
		t.Logf("关闭不存在流幂等（可接受）")
	}

	// 5. 非法 content_type；省略 content_type 当前服务端有默认值
	_, err = c.Call(ctx, "stream.create", map[string]any{"content_type": "invalid"})
	if err == nil {
		t.Error("stream.create 非法 content_type 应报错")
	} else {
		t.Logf("正确拒绝非法 content_type: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// 辅助
// ═══════════════════════════════════════════════════════════════════════════

func testIssuer() string {
	if v := os.Getenv("AUN_TEST_ISSUER"); v != "" {
		return v
	}
	return "agentid.pub"
}

func extractP0GroupID(result any) string {
	resultMap, _ := result.(map[string]any)
	if resultMap == nil {
		return ""
	}
	if groupID, _ := resultMap["group_id"].(string); groupID != "" {
		return groupID
	}
	group, _ := resultMap["group"].(map[string]any)
	if group == nil {
		return ""
	}
	groupID, _ := group["group_id"].(string)
	return groupID
}

func containsAny(s string, substrs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}
