//go:build integration

package aun

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// slot_id 分隔符场景 E2E 测试
//
// 对齐 Python e2e_test_slot_id_separator.py 的 4 个测试场景。
//
// 运行：
//   MSYS_NO_PATHCONV=1 docker exec kite-go-tester sh -lc \
//     "cd /workspace/go && /usr/local/go/bin/go test -tags integration . \
//      -run TestSlotSeparatorE2E -count=1 -v -timeout 120s"
// ---------------------------------------------------------------------------

// TestSlotSeparatorE2E_P2PPlaintext P2P 明文消息 — c2(evolclaw daemon) 踢掉 c1(evolclaw cli) 后收到消息
func TestSlotSeparatorE2E_P2PPlaintext(t *testing.T) {
	rid := runID()
	aliceAID := fmt.Sprintf("slot-e2e-a-%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("slot-e2e-b-%s.%s", rid, testIssuer())

	alicePath := t.TempDir()
	bobPath := t.TempDir()
	createAIDInPath(t, alicePath, aliceAID)
	createAIDInPath(t, bobPath, bobAID)

	c1 := quotaTestClient(t, alicePath)
	defer closeQuiet(c1)
	c2 := quotaTestClient(t, alicePath)
	defer closeQuiet(c2)
	bob := quotaTestClient(t, bobPath)
	defer closeQuiet(bob)

	// c1 先连接
	if err := quotaConnectLong(t, c1, aliceAID, "evolclaw cli", 30*time.Second); err != nil {
		t.Fatalf("c1 连接失败: %v", err)
	}
	t.Log("[OK] c1 已连接 (evolclaw cli)")
	time.Sleep(300 * time.Millisecond)

	// c2 连接（同前缀 evolclaw → 踢掉 c1）
	if err := quotaConnectLong(t, c2, aliceAID, "evolclaw daemon", 30*time.Second); err != nil {
		t.Fatalf("c2 连接失败: %v", err)
	}
	t.Log("[OK] c2 已连接 (evolclaw daemon)，应踢掉 c1")
	time.Sleep(300 * time.Millisecond)

	if err := quotaConnectLong(t, bob, bobAID, "main", 30*time.Second); err != nil {
		t.Fatalf("bob 连接失败: %v", err)
	}
	t.Log("[OK] bob 已连接")

	text := fmt.Sprintf("p2p-plain-%s", rid)
	wait := v2SubscribeAndWait(t, c2, bobAID, text)

	v2DrainInbox(t, c2)

	// bob 发 P2P 明文消息
	v2SendWithRetry(t, bob, aliceAID, map[string]any{"text": text})
	t.Logf("[OK] bob 已发送 P2P 明文消息: %s", text)

	msg := wait(15 * time.Second)
	if msg == nil {
		t.Fatal("c2 未收到消息")
	}
	t.Logf("[PASS] c2 收到 P2P 明文消息: %v", msg)
}

// TestSlotSeparatorE2E_P2PEncrypted P2P 加密消息 — c2(evolclaw daemon) 踢掉 c1 后收到并解密
func TestSlotSeparatorE2E_P2PEncrypted(t *testing.T) {
	rid := runID()
	aliceAID := fmt.Sprintf("slot-e2e-a-%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("slot-e2e-b-%s.%s", rid, testIssuer())

	alicePath := t.TempDir()
	bobPath := t.TempDir()
	createAIDInPath(t, alicePath, aliceAID)
	createAIDInPath(t, bobPath, bobAID)

	c1 := quotaTestClient(t, alicePath)
	defer closeQuiet(c1)
	c2 := quotaTestClient(t, alicePath)
	defer closeQuiet(c2)
	bob := quotaTestClient(t, bobPath)
	defer closeQuiet(bob)

	// c1 先连接
	if err := quotaConnectLong(t, c1, aliceAID, "evolclaw cli", 30*time.Second); err != nil {
		t.Fatalf("c1 连接失败: %v", err)
	}
	t.Log("[OK] c1 已连接 (evolclaw cli)")
	time.Sleep(300 * time.Millisecond)

	// c2 连接（踢掉 c1），等待 V2 session 初始化 + prekey 上传
	if err := quotaConnectLong(t, c2, aliceAID, "evolclaw daemon", 30*time.Second); err != nil {
		t.Fatalf("c2 连接失败: %v", err)
	}
	t.Log("[OK] c2 已连接 (evolclaw daemon)")
	time.Sleep(1 * time.Second) // 等 prekey 上传完成

	if err := quotaConnectLong(t, bob, bobAID, "main", 30*time.Second); err != nil {
		t.Fatalf("bob 连接失败: %v", err)
	}
	t.Log("[OK] bob 已连接")
	time.Sleep(1 * time.Second)

	text := fmt.Sprintf("p2p-enc-%s", rid)
	wait := v2SubscribeAndWait(t, c2, bobAID, text)

	v2DrainInbox(t, c2)

	// bob 发 E2EE 加密消息（sendV2 自动走 V2 E2EE）
	v2SendWithRetry(t, bob, aliceAID, map[string]any{"text": text})
	t.Logf("[OK] bob 已发送 P2P 加密消息: %s", text)

	msg := wait(20 * time.Second)
	if msg == nil {
		t.Fatal("c2 未收到消息")
	}
	payload, _ := msg["payload"].(map[string]any)
	if payload == nil || payload["text"] != text {
		t.Fatalf("消息内容不符或未解密: %v", msg)
	}
	t.Logf("[PASS] c2 收到并解密 P2P 加密消息: %v", msg)
}

// TestSlotSeparatorE2E_GroupPlaintext 群明文消息 — alice(evolclaw daemon) 收到 bob 发的群消息
func TestSlotSeparatorE2E_GroupPlaintext(t *testing.T) {
	rid := runID()
	aliceAID := fmt.Sprintf("slot-e2e-a-%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("slot-e2e-b-%s.%s", rid, testIssuer())

	alicePath := t.TempDir()
	bobPath := t.TempDir()
	createAIDInPath(t, alicePath, aliceAID)
	createAIDInPath(t, bobPath, bobAID)

	alice := quotaTestClient(t, alicePath)
	defer closeQuiet(alice)
	bob := quotaTestClient(t, bobPath)
	defer closeQuiet(bob)

	if err := quotaConnectLong(t, alice, aliceAID, "evolclaw daemon", 30*time.Second); err != nil {
		t.Fatalf("alice 连接失败: %v", err)
	}
	t.Log("[OK] alice 已连接 (evolclaw daemon)")

	if err := quotaConnectLong(t, bob, bobAID, "main", 30*time.Second); err != nil {
		t.Fatalf("bob 连接失败: %v", err)
	}
	t.Log("[OK] bob 已连接")

	// bob 建群，加 alice
	groupID := v2CreateGroup(t, bob, fmt.Sprintf("slot-plain-%s", rid))
	v2AddMember(t, bob, groupID, aliceAID)
	t.Logf("[OK] 群组已创建: %s，alice 已加入", groupID)
	time.Sleep(1 * time.Second)

	text := fmt.Sprintf("grp-plain-%s", rid)

	// bob 发群明文消息（直接用 group.send，不走 V2 E2EE）
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := bob.Call(ctx, "group.send", map[string]any{
		"group_id": groupID,
		"payload":  map[string]any{"text": text},
		"encrypt":  false,
	})
	if err != nil {
		t.Fatalf("bob 发送群明文消息失败: %v", err)
	}
	t.Logf("[OK] bob 已发送群明文消息: %s", text)

	msg := v2WaitForGroupMessage(t, alice, groupID, bobAID, text, 15*time.Second)
	if msg == nil {
		t.Fatal("alice 未收到群消息")
	}
	t.Logf("[PASS] alice 收到群明文消息: %v", msg)
}

// TestSlotSeparatorE2E_GroupEncrypted 群加密消息 — alice(evolclaw daemon) 收到并解密 bob 发的群消息
func TestSlotSeparatorE2E_GroupEncrypted(t *testing.T) {
	rid := runID()
	aliceAID := fmt.Sprintf("slot-e2e-a-%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("slot-e2e-b-%s.%s", rid, testIssuer())

	alicePath := t.TempDir()
	bobPath := t.TempDir()
	createAIDInPath(t, alicePath, aliceAID)
	createAIDInPath(t, bobPath, bobAID)

	alice := quotaTestClient(t, alicePath)
	defer closeQuiet(alice)
	bob := quotaTestClient(t, bobPath)
	defer closeQuiet(bob)

	if err := quotaConnectLong(t, alice, aliceAID, "evolclaw daemon", 30*time.Second); err != nil {
		t.Fatalf("alice 连接失败: %v", err)
	}
	t.Log("[OK] alice 已连接 (evolclaw daemon)")
	time.Sleep(1 * time.Second) // 等 prekey 上传

	if err := quotaConnectLong(t, bob, bobAID, "main", 30*time.Second); err != nil {
		t.Fatalf("bob 连接失败: %v", err)
	}
	t.Log("[OK] bob 已连接")
	time.Sleep(1 * time.Second)

	// bob 建群，加 alice，等 V2 密钥就绪
	groupID := v2CreateGroup(t, bob, fmt.Sprintf("slot-enc-%s", rid))
	v2AddMember(t, bob, groupID, aliceAID)
	t.Logf("[OK] 群组已创建: %s，alice 已加入", groupID)

	v2WaitForGroupV2Ready(t, bob, groupID, []string{aliceAID, bobAID}, 30*time.Second)
	t.Log("[OK] 群 V2 密钥就绪")

	text := fmt.Sprintf("grp-enc-%s", rid)

	// bob 发群 V2 加密消息
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := bob.sendGroupV2(ctx, groupID, map[string]any{"text": text})
	if err != nil {
		t.Fatalf("bob 发送群加密消息失败: %v", err)
	}
	t.Logf("[OK] bob 已发送群加密消息: %s", text)

	msg := v2WaitForGroupMessage(t, alice, groupID, bobAID, text, 20*time.Second)
	if msg == nil {
		t.Fatal("alice 未收到群消息")
	}
	payload, _ := msg["payload"].(map[string]any)
	if payload == nil || payload["text"] != text {
		t.Fatalf("消息内容不符或未解密: %v", msg)
	}
	t.Logf("[PASS] alice 收到并解密群加密消息: %v", msg)
}
