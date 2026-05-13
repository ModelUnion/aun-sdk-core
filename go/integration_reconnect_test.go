//go:build integration

package aun

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════
// 断线重连集成测试 — 打真实 Docker Gateway
//
// 运行方法:
//   cd go && go test -tags integration -run TestIntegration_Reconnect -v -timeout 300s
//
// 前置条件:
//   - Docker 环境运行中（docker compose up -d）
//   - 运行环境能解析 gateway.agentid.pub
//
// 注意: 本文件不使用 Docker 命令模拟断线，而是通过 SDK 的 Disconnect() +
//       重新 Authenticate + Connect 模拟断线重连。
// ═══════════════════════════════════════════════════════════════════════════

// ── 基础断线重连 ────────────────────────────────────────────────────────

func TestIntegration_ReconnectBasicDisconnectReconnect(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("rc%s.%s", rid, testIssuer())

	client := makeClient(t)
	defer client.Close()

	// 连接
	ensureConnected(t, client, aid)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 验证 ping 正常
	_, err := client.Call(ctx, "meta.ping", nil)
	if err != nil {
		t.Fatalf("连接后 ping 失败: %v", err)
	}
	t.Logf("状态: 已连接，ping 正常")

	// 断线
	if err := client.Disconnect(); err != nil {
		t.Fatalf("Disconnect 失败: %v", err)
	}
	t.Logf("状态: 已断线")

	time.Sleep(1 * time.Second)

	// 重新认证
	authResult, err := client.Auth.Authenticate(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Fatalf("重新认证失败: %v", err)
	}
	t.Logf("状态: 重新认证成功")

	// 重新连接
	if err := client.Connect(ctx, authResult, nil); err != nil {
		t.Fatalf("重新连接失败: %v", err)
	}
	t.Logf("状态: 重新连接成功")

	// 验证 ping 正常
	_, err = client.Call(ctx, "meta.ping", nil)
	if err != nil {
		t.Fatalf("重连后 ping 失败: %v", err)
	}
	t.Logf("状态: 重连后 ping 正常")
}

// ── 重连后消息收发 ──────────────────────────────────────────────────────

func TestIntegration_ReconnectMessageAfterReconnect(t *testing.T) {
	rid := runID()
	aliceAID := fmt.Sprintf("rca%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("rcb%s.%s", rid, testIssuer())

	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Alice 发送消息 1
	text1 := fmt.Sprintf("rc-msg1-%s", rid)
	_, err := alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": text1},
		"persist": true,
		"encrypt": false,
	})
	if err != nil {
		t.Fatalf("消息 1 发送失败: %v", err)
	}
	t.Logf("Alice 发送消息 1: %s", text1)

	time.Sleep(500 * time.Millisecond)

	// Alice 断线
	if err := alice.Disconnect(); err != nil {
		t.Fatalf("Alice 断线失败: %v", err)
	}
	t.Logf("Alice 已断线")

	time.Sleep(1 * time.Second)

	// Alice 重新认证并连接
	authResult, err := alice.Auth.Authenticate(ctx, map[string]any{"aid": aliceAID})
	if err != nil {
		t.Fatalf("Alice 重新认证失败: %v", err)
	}
	if err := alice.Connect(ctx, authResult, nil); err != nil {
		t.Fatalf("Alice 重新连接失败: %v", err)
	}
	t.Logf("Alice 已重连")

	// Alice 发送消息 2
	text2 := fmt.Sprintf("rc-msg2-%s", rid)
	_, err = alice.Call(ctx, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": text2},
		"persist": true,
		"encrypt": false,
	})
	if err != nil {
		t.Fatalf("消息 2 发送失败: %v", err)
	}
	t.Logf("Alice 发送消息 2: %s", text2)

	time.Sleep(1 * time.Second)

	// Bob 拉取消息 — 应同时收到两条
	pullResult, err := bob.Call(ctx, "message.pull", map[string]any{
		"after_seq": 0,
		"limit":     50,
	})
	if err != nil {
		t.Fatalf("Bob pull 失败: %v", err)
	}

	pullMap, _ := pullResult.(map[string]any)
	msgs, _ := pullMap["messages"].([]any)

	var found1, found2 bool
	var seq1, seq2 float64
	for _, m := range msgs {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		from, _ := msg["from"].(string)
		if from != aliceAID {
			continue
		}
		payload, _ := msg["payload"].(map[string]any)
		if payload == nil {
			continue
		}
		text, _ := payload["text"].(string)
		seq, _ := msg["seq"].(float64)
		if text == text1 {
			found1 = true
			seq1 = seq
		}
		if text == text2 {
			found2 = true
			seq2 = seq
		}
	}

	if !found1 {
		t.Fatalf("Bob 未收到消息 1: %s", text1)
	}
	if !found2 {
		t.Fatalf("Bob 未收到消息 2: %s", text2)
	}

	// 验证 seq 有序
	if seq2 <= seq1 {
		t.Fatalf("消息 seq 顺序异常: msg1_seq=%.0f msg2_seq=%.0f", seq1, seq2)
	}
	t.Logf("两条消息均已收到，seq 有序: msg1_seq=%.0f msg2_seq=%.0f", seq1, seq2)
}

// ── 多次断线重连 ────────────────────────────────────────────────────────

func TestIntegration_ReconnectMultipleDisconnects(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("rcm%s.%s", rid, testIssuer())

	client := makeClient(t)
	defer client.Close()

	ensureConnected(t, client, aid)

	const cycles = 3
	for i := 0; i < cycles; i++ {
		cycleStart := time.Now()

		// 断线
		if err := client.Disconnect(); err != nil {
			t.Fatalf("第 %d 次断线失败: %v", i+1, err)
		}

		time.Sleep(500 * time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		// 重新认证
		authResult, err := client.Auth.Authenticate(ctx, map[string]any{"aid": aid})
		if err != nil {
			cancel()
			t.Fatalf("第 %d 次重新认证失败: %v", i+1, err)
		}

		// 重新连接
		if err := client.Connect(ctx, authResult, nil); err != nil {
			cancel()
			t.Fatalf("第 %d 次重新连接失败: %v", i+1, err)
		}

		// 验证 ping
		_, err = client.Call(ctx, "meta.ping", nil)
		cancel()
		if err != nil {
			t.Fatalf("第 %d 次重连后 ping 失败: %v", i+1, err)
		}

		latency := time.Since(cycleStart)
		t.Logf("第 %d/%d 次重连成功，耗时 %v", i+1, cycles, latency)
	}

	t.Logf("全部 %d 次断线重连均成功", cycles)
}

// ── 断线后 RPC 失败验证 ─────────────────────────────────────────────────

func TestIntegration_ReconnectDisconnectedRPCFails(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("rcf%s.%s", rid, testIssuer())

	client := makeClient(t)
	defer client.Close()

	ensureConnected(t, client, aid)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 连接状态下 ping 正常
	_, err := client.Call(ctx, "meta.ping", nil)
	if err != nil {
		t.Fatalf("连接状态下 ping 失败: %v", err)
	}
	t.Logf("连接状态: ping 正常")

	// 断线
	if err := client.Disconnect(); err != nil {
		t.Fatalf("断线失败: %v", err)
	}
	t.Logf("已断线")

	time.Sleep(500 * time.Millisecond)

	// 断线后 RPC — 应返回错误
	_, err = client.Call(ctx, "meta.ping", nil)
	if err == nil {
		t.Fatal("断线后 RPC 应返回错误，但成功了")
	}
	t.Logf("断线后 RPC 正确报错: %T: %v", err, err)

	// 验证错误信息包含有意义的描述
	errStr := err.Error()
	if errStr == "" {
		t.Error("断线后 RPC 错误信息不应为空")
	}

	// 重连
	authResult, err := client.Auth.Authenticate(ctx, map[string]any{"aid": aid})
	if err != nil {
		t.Fatalf("重新认证失败: %v", err)
	}
	if err := client.Connect(ctx, authResult, nil); err != nil {
		t.Fatalf("重新连接失败: %v", err)
	}
	t.Logf("已重连")

	// 重连后 RPC — 应恢复
	_, err = client.Call(ctx, "meta.ping", nil)
	if err != nil {
		t.Fatalf("重连后 ping 仍失败: %v", err)
	}
	t.Logf("重连后 ping 恢复正常")
}
