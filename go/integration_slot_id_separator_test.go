//go:build integration

package aun

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// SlotID 前缀隔离集成测试
//
// 运行：
//   MSYS_NO_PATHCONV=1 docker exec kite-go-tester sh -lc \
//     "cd /workspace/go && /usr/local/go/bin/go test -tags integration . \
//      -run TestSlotSeparator -count=1 -v"
// ---------------------------------------------------------------------------

// TestSlotSeparator_SamePrefixMutualKick 同前缀 slot 互踢：
// alice c1(evolclaw cli) → c2(evolclaw daemon) 建立 → c1 收到 4009，c2 正常在线
func TestSlotSeparator_SamePrefixMutualKick(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("sep-go-%s.%s", rid, testIssuer())
	sharedPath := t.TempDir()
	createAIDInPath(t, sharedPath, aid)

	c1 := quotaTestClient(t, sharedPath)
	defer closeQuiet(c1)
	c2 := quotaTestClient(t, sharedPath)
	defer closeQuiet(c2)

	c1Disconnect, c1Cancel := captureDisconnect(c1)
	defer c1Cancel()

	// c1 以 "evolclaw cli" 建立长连接
	if err := quotaConnectLong(t, c1, aid, "evolclaw cli", 30*time.Second); err != nil {
		t.Fatalf("c1 连接失败: %v", err)
	}
	t.Log("[OK] c1 已连接 (evolclaw cli)")
	time.Sleep(200 * time.Millisecond)

	// c2 以 "evolclaw daemon" 建立长连接（同前缀 evolclaw → 踢 c1）
	if err := quotaConnectLong(t, c2, aid, "evolclaw daemon", 30*time.Second); err != nil {
		t.Fatalf("c2 连接失败: %v", err)
	}
	t.Log("[OK] c2 已连接 (evolclaw daemon)，应踢掉 c1")

	// 等待 c1 收到 4009
	select {
	case info := <-c1Disconnect:
		t.Logf("c1 收到 disconnect: code=%d reason=%s", info.code, info.reason)
		if info.code != 4009 {
			t.Errorf("期望 code=4009，实际 code=%d", info.code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("超时未收到 c1 的 gateway.disconnect 事件")
	}

	// c2 应仍在线
	if c2.State() != ConnStateReady {
		t.Errorf("c2 应仍在线，实际状态: %s", c2.State())
	}
}

// TestSlotSeparator_DifferentPrefixCoexist 不同前缀 slot 共存：
// alice c1(evolclaw cli) + c2(other daemon) → 两者都正常在线，不互踢
func TestSlotSeparator_DifferentPrefixCoexist(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("sep-go-%s.%s", rid, testIssuer())
	sharedPath := t.TempDir()
	createAIDInPath(t, sharedPath, aid)

	c1 := quotaTestClient(t, sharedPath)
	defer closeQuiet(c1)
	c2 := quotaTestClient(t, sharedPath)
	defer closeQuiet(c2)

	c1Disconnect, c1Cancel := captureDisconnect(c1)
	defer c1Cancel()

	if err := quotaConnectLong(t, c1, aid, "evolclaw cli", 30*time.Second); err != nil {
		t.Fatalf("c1 连接失败: %v", err)
	}
	t.Log("[OK] c1 已连接 (evolclaw cli)")
	time.Sleep(200 * time.Millisecond)

	if err := quotaConnectLong(t, c2, aid, "other daemon", 30*time.Second); err != nil {
		t.Fatalf("c2 连接失败: %v", err)
	}
	t.Log("[OK] c2 已连接 (other daemon)")

	// 等待一段时间，确认 c1 没有被踢
	time.Sleep(2 * time.Second)

	select {
	case info := <-c1Disconnect:
		t.Errorf("c1 不应被踢，但收到 disconnect: code=%d reason=%s", info.code, info.reason)
	default:
	}

	if c1.State() != ConnStateReady {
		t.Errorf("c1 应仍在线，实际状态: %s", c1.State())
	}
	if c2.State() != ConnStateReady {
		t.Errorf("c2 应仍在线，实际状态: %s", c2.State())
	}
}

// TestSlotSeparator_P2PMessageRouting 消息路由到正确实例：
// alice daemon 在线，bob 发 P2P 消息 → alice daemon 收到
func TestSlotSeparator_P2PMessageRouting(t *testing.T) {
	rid := runID()
	aliceAID := fmt.Sprintf("sep-go-a-%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("sep-go-b-%s.%s", rid, testIssuer())

	alicePath := t.TempDir()
	bobPath := t.TempDir()
	createAIDInPath(t, alicePath, aliceAID)
	createAIDInPath(t, bobPath, bobAID)

	aliceDaemon := quotaTestClient(t, alicePath)
	defer closeQuiet(aliceDaemon)
	bobClient := quotaTestClient(t, bobPath)
	defer closeQuiet(bobClient)

	if err := quotaConnectLong(t, aliceDaemon, aliceAID, "evolclaw daemon", 30*time.Second); err != nil {
		t.Fatalf("alice daemon 连接失败: %v", err)
	}
	t.Log("[OK] alice daemon 已连接")

	if err := quotaConnectLong(t, bobClient, bobAID, "main", 30*time.Second); err != nil {
		t.Fatalf("bob 连接失败: %v", err)
	}
	t.Log("[OK] bob 已连接")

	text := fmt.Sprintf("hello-daemon-%s", rid)
	received := make(chan struct{}, 1)
	sub := aliceDaemon.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		p, _ := data["payload"].(map[string]any)
		if p != nil && getStr(p, "text", "") == text {
			select {
			case received <- struct{}{}:
			default:
			}
		}
	})
	defer sub.Unsubscribe()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := bobClient.Call(ctx, "message.send", map[string]any{
		"to":      aliceAID,
		"payload": map[string]any{"text": text},
		"encrypt": false,
	})
	if err != nil {
		t.Fatalf("bob 发送消息失败: %v", err)
	}
	t.Log("[OK] bob 已发送消息")

	select {
	case <-received:
		t.Log("[OK] alice daemon 收到消息")
	case <-time.After(10 * time.Second):
		t.Fatal("超时未收到消息")
	}
}

// TestSlotSeparator_InvalidSlotIdRejected 非法 slot_id 被拒绝：
// slot_id="/invalid" 以 / 开头 → SDK 校验失败，Connect 返回错误
func TestSlotSeparator_InvalidSlotIdRejected(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("sep-go-%s.%s", rid, testIssuer())
	sharedPath := t.TempDir()
	createAIDInPath(t, sharedPath, aid)

	client := quotaTestClient(t, sharedPath)
	defer closeQuiet(client)

	integrationLoadAIDIntoClient(t, client, aid, "/invalid")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Connect(ctx, ConnectionOptions{
		AutoReconnect:  boolPtr(false),
		ConnectionKind: "long",
	})
	if err == nil {
		t.Fatal("期望连接失败（非法 slot_id），但连接成功")
	}
	t.Logf("[OK] 非法 slot_id 被拒绝: %v", err)
}
