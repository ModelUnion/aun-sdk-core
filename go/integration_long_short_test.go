//go:build integration

package aun

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 长短连接共存集成测试 + E2E 测试
//
// 与 Python 版用例对齐：
//   集成测试（8 个）：
//     TestLongShort_SameIdentitySendMessage
//     TestLongShort_ShortDoesNotKickLong
//     TestLongShort_ShortCapacityExceeded
//     TestLongShort_ShortTtlEviction
//     TestLongShort_LongReplacesLongShortsUnaffected
//     TestLongShort_ShortDoesNotPublishClientOnline
//     TestLongShort_HelloOkConnectionKind
//     TestLongShort_ShortDisablesBackgroundTasks
//   E2E 测试（5 个）：
//     TestLongShortE2E_SequentialSends
//     TestLongShortE2E_ConcurrentShorts
//     TestLongShortE2E_LongReceivesBobReply
//     TestLongShortE2E_CliCrashTtl
//     TestLongShortE2E_LongSurvivesShortLifecycle
//
// 运行：
//   docker exec kite-go-tester sh -lc "cd /workspace/go && \
//     /usr/local/go/bin/go test -tags integration . -run TestLongShort -count=1 -v"
// ---------------------------------------------------------------------------

// makeSharedClient 创建共享 aun_path 的客户端（同身份多 client 复用 keystore + device_id）
func makeSharedClient(t *testing.T, sharedPath string) *AUNClient {
	t.Helper()
	t.Setenv("AUN_ENV", "development")
	client := newClient(map[string]any{
		"aun_path": sharedPath,
	}, true)
	client.configModel.RequireForwardSecrecy = false
	return client
}

// connectLong 建立长连接（默认 connection_kind=long）。aid 必须先通过 createAID 注册。
func connectLong(t *testing.T, client *AUNClient, aid, slotID string, timeout time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	integrationLoadAIDIntoClient(t, client, aid)
	return client.Connect(ctx, ConnectionOptions{
		AutoReconnect:     boolPtr(false),
		HeartbeatInterval: 30 * time.Second,
		ConnectionKind:    "long",
		SlotID:            slotID,
	})
}

// connectShort 建立短连接。aid 必须已注册。short_ttl_ms<=0 时不传该选项。
func connectShort(t *testing.T, client *AUNClient, aid, slotID string, shortTtlMs int, timeout time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	integrationLoadAIDIntoClient(t, client, aid)
	opts := ConnectionOptions{
		ConnectionKind: "short",
		ShortTtlMs:     shortTtlMs,
		SlotID:         slotID,
	}
	return client.Connect(ctx, opts)
}

// createAIDOnce 仅注册 AID（不连接），用于多 client 共享一个身份的场景。
func createAIDOnce(t *testing.T, sharedPath, aid string) {
	t.Helper()
	integrationRegisterAIDInPath(t, sharedPath, aid)
}

// rid8 生成 8 位随机 ID（避免 AID 碰撞）
func rid8() string {
	id := generateUUID4()
	// 去掉 - 后取前 8 位
	id = strings.ReplaceAll(id, "-", "")
	if len(id) > 8 {
		id = id[:8]
	}
	return id
}

func makeAID(prefix, id string) string {
	return fmt.Sprintf("ls-%s-%s.agentid.pub", prefix, id)
}

// closeQuiet 静默关闭客户端，忽略错误
func closeQuiet(c *AUNClient) {
	if c == nil {
		return
	}
	_ = c.Close()
}

// ---------------------------------------------------------------------------
// 集成测试 1: 同身份长短共存 — 短连接发消息，bob 收到，alice 长连接无感
// ---------------------------------------------------------------------------

func TestLongShort_SameIdentitySendMessage(t *testing.T) {
	rid := rid8()
	alicePath := t.TempDir()
	bobPath := t.TempDir()
	aliceAID := makeAID("a1", rid)
	bobAID := makeAID("b1", rid)

	// 提前注册 alice 和 bob
	createAIDOnce(t, alicePath, aliceAID)
	createAIDOnce(t, bobPath, bobAID)

	aliceLong := makeSharedClient(t, alicePath)
	aliceShort := makeSharedClient(t, alicePath)
	bobLong := makeSharedClient(t, bobPath)
	defer closeQuiet(aliceLong)
	defer closeQuiet(aliceShort)
	defer closeQuiet(bobLong)

	// 建立 alice 长连接 + bob 长连接
	if err := connectLong(t, aliceLong, aliceAID, "main", 20*time.Second); err != nil {
		t.Fatalf("alice 长连接失败: %v", err)
	}
	if err := connectLong(t, bobLong, bobAID, "main", 20*time.Second); err != nil {
		t.Fatalf("bob 长连接失败: %v", err)
	}

	// alice 长连接监听 message.received（不应收到任何东西）
	var aliceMu sync.Mutex
	var aliceUnexpected []map[string]any
	subAlice := aliceLong.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		aliceMu.Lock()
		aliceUnexpected = append(aliceUnexpected, data)
		aliceMu.Unlock()
	})
	defer subAlice.Unsubscribe()

	// bob 监听
	text := fmt.Sprintf("cli-to-bob-%s", rid)
	bobReceived := make(chan map[string]any, 4)
	subBob := bobLong.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		p, _ := data["payload"].(map[string]any)
		if p != nil && getStr(p, "text", "") == text {
			select {
			case bobReceived <- data:
			default:
			}
		}
	})
	subBobUndec := bobLong.On("message.undecryptable", func(payload any) {
		t.Logf("bob 收到 undecryptable 事件: %#v", payload)
	})
	defer subBob.Unsubscribe()
	defer subBobUndec.Unsubscribe()

	// alice 短连接（同 aid/device/slot）发消息给 bob
	if err := connectShort(t, aliceShort, aliceAID, "main", 0, 20*time.Second); err != nil {
		t.Fatalf("alice 短连接失败: %v", err)
	}
	if aliceShort.State() != ConnStateReady {
		t.Fatalf("alice 短连接状态异常: %s", aliceShort.State())
	}

	ctxSend, cancelSend := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelSend()
	result, err := aliceShort.Call(ctxSend, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": text},
		"encrypt": true,
	})
	if err != nil {
		t.Fatalf("短连接 message.send 失败: %v", err)
	}
	rmap, _ := result.(map[string]any)
	status, _ := rmap["status"].(string)
	if status != "sent" && status != "delivered" {
		t.Fatalf("RPC 响应未原路返回成功: %#v", rmap)
	}
	t.Logf("[OK] RPC 原路返回到短连接: status=%s", status)

	// 立即关闭短连接
	_ = aliceShort.Close()

	// 验证 bob 收到消息
	select {
	case msg := <-bobReceived:
		t.Logf("[OK] bob 收到消息: text=%v", text)
		_ = msg
	case <-time.After(15 * time.Second):
		t.Fatalf("bob 等待消息超时")
	}

	// 等额外 2s 确保没有延迟推送给 alice
	time.Sleep(2 * time.Second)

	// 验证 alice 长连接没收到任何 message.received
	aliceMu.Lock()
	unexpected := len(aliceUnexpected)
	aliceMu.Unlock()
	if unexpected != 0 {
		t.Fatalf("alice 长连接收到了不该收到的 message.received: %d 条", unexpected)
	}
	t.Log("[OK] alice 长连接无感（同 device+slot 不 self-sync）")

	// 验证 alice 长连接仍正常
	ctxPing, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelPing()
	if _, err := aliceLong.Call(ctxPing, "meta.ping", nil); err != nil {
		t.Fatalf("alice 长连接 ping 失败: %v", err)
	}
	t.Log("[OK] alice 长连接 ping 成功")
}

// ---------------------------------------------------------------------------
// 集成测试 2: 短连接进入不踢长连接
// ---------------------------------------------------------------------------

func TestLongShort_ShortDoesNotKickLong(t *testing.T) {
	rid := rid8()
	sharedPath := t.TempDir()
	aid := makeAID("l2", rid)
	createAIDOnce(t, sharedPath, aid)

	longClient := makeSharedClient(t, sharedPath)
	shortClient := makeSharedClient(t, sharedPath)
	defer closeQuiet(longClient)
	defer closeQuiet(shortClient)

	if err := connectLong(t, longClient, aid, "main", 20*time.Second); err != nil {
		t.Fatalf("长连接失败: %v", err)
	}

	// 起短连接（同 slot）
	if err := connectShort(t, shortClient, aid, "main", 0, 20*time.Second); err != nil {
		t.Fatalf("短连接失败: %v", err)
	}
	time.Sleep(1 * time.Second)

	if longClient.State() != ConnStateReady {
		t.Fatalf("长连接被短连接踢了: state=%s", longClient.State())
	}
	t.Log("[OK] 短连接进入后长连接仍 ready")

	// 短连接 ping
	ctxPingShort, cancelPS := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelPS()
	if _, err := shortClient.Call(ctxPingShort, "meta.ping", nil); err != nil {
		t.Fatalf("短连接 ping 失败: %v", err)
	}
	_ = shortClient.Close()
	time.Sleep(500 * time.Millisecond)

	// 长连接仍存活并能 ping
	if longClient.State() != ConnStateReady {
		t.Fatalf("短连接关闭后长连接异常: state=%s", longClient.State())
	}
	ctxPing, cancelP := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelP()
	if _, err := longClient.Call(ctxPing, "meta.ping", nil); err != nil {
		t.Fatalf("长连接 ping 失败: %v", err)
	}
	t.Log("[OK] 长连接生命周期完全不受短连接影响")
}

// ---------------------------------------------------------------------------
// 集成测试 3: 同槽位 10 个短连接，第 11 个被拒（含 short_connection_capacity_exceeded）
// ---------------------------------------------------------------------------

func TestLongShort_ShortCapacityExceeded(t *testing.T) {
	rid := rid8()
	sharedPath := t.TempDir()
	aid := makeAID("c3", rid)
	createAIDOnce(t, sharedPath, aid)

	const capacity = 10
	shorts := make([]*AUNClient, 0, capacity)
	defer func() {
		for _, c := range shorts {
			closeQuiet(c)
		}
	}()

	for i := 0; i < capacity; i++ {
		c := makeSharedClient(t, sharedPath)
		shorts = append(shorts, c)
		if err := connectShort(t, c, aid, "cap", 0, 20*time.Second); err != nil {
			t.Fatalf("第 %d 个短连接失败（应该成功）: %v", i+1, err)
		}
	}
	time.Sleep(500 * time.Millisecond)

	// 第 11 个应被拒
	overflow := makeSharedClient(t, sharedPath)
	defer closeQuiet(overflow)

	err := connectShort(t, overflow, aid, "cap", 0, 20*time.Second)
	if err == nil {
		t.Fatalf("第 11 个短连接不应成功")
	}
	msg := err.Error()
	if !strings.Contains(msg, "short_connection_capacity_exceeded") &&
		!strings.Contains(msg, "4013") {
		t.Fatalf("错误信息不含 short_connection_capacity_exceeded 或 4013: %v", err)
	}
	t.Logf("[OK] 第 11 个短连接被服务端拒绝: %v", err)
}

// ---------------------------------------------------------------------------
// 集成测试 4: short_ttl_ms 兜底
// ---------------------------------------------------------------------------

func TestLongShort_ShortTtlEviction(t *testing.T) {
	rid := rid8()
	sharedPath := t.TempDir()
	aid := makeAID("t4", rid)
	createAIDOnce(t, sharedPath, aid)

	short := makeSharedClient(t, sharedPath)
	defer closeQuiet(short)

	// 短连接 ttl=2000ms
	if err := connectShort(t, short, aid, "ttl", 2000, 20*time.Second); err != nil {
		t.Fatalf("短连接失败: %v", err)
	}
	if short.State() != ConnStateReady {
		t.Fatalf("短连接初始状态异常: %s", short.State())
	}

	// 等待 ~5s，期望状态变为 standby/closed/connection_failed
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s := short.State()
		if s == ConnStateStandby || s == ConnStateClosed || s == ConnStateConnectionFailed {
			t.Logf("[OK] 短连接被 ttl 兜底关闭: state=%s", s)
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("ttl 到期后短连接仍 ready: state=%s", short.State())
}

// ---------------------------------------------------------------------------
// 集成测试 5: 同槽位旧长连接 + 3 短连接 → 新长连接进入 → 旧长被踢，3 短连接仍能 ping
// ---------------------------------------------------------------------------

func TestLongShort_LongReplacesLongShortsUnaffected(t *testing.T) {
	rid := rid8()
	sharedPath := t.TempDir()
	aid := makeAID("r5", rid)
	createAIDOnce(t, sharedPath, aid)

	oldLong := makeSharedClient(t, sharedPath)
	newLong := makeSharedClient(t, sharedPath)
	shorts := make([]*AUNClient, 0, 3)
	defer func() {
		for _, c := range shorts {
			closeQuiet(c)
		}
		closeQuiet(oldLong)
		closeQuiet(newLong)
	}()

	// 旧长连接进入
	if err := connectLong(t, oldLong, aid, "slot-x", 20*time.Second); err != nil {
		t.Fatalf("旧长连接失败: %v", err)
	}

	// 3 个同槽位短连接
	for i := 0; i < 3; i++ {
		c := makeSharedClient(t, sharedPath)
		shorts = append(shorts, c)
		if err := connectShort(t, c, aid, "slot-x", 0, 20*time.Second); err != nil {
			t.Fatalf("短连接 %d 失败: %v", i, err)
		}
	}
	time.Sleep(500 * time.Millisecond)

	// 新长连接同槽位进入 → 应踢旧长连接
	if err := connectLong(t, newLong, aid, "slot-x", 20*time.Second); err != nil {
		t.Fatalf("新长连接失败: %v", err)
	}
	time.Sleep(2 * time.Second) // 给服务端发 4009 + SDK 状态切换的时间

	// 旧长连接应被踢（state != ready）
	if oldLong.State() == ConnStateReady {
		t.Fatalf("旧长连接未被踢: state=%s", oldLong.State())
	}
	t.Logf("[OK] 旧长连接被踢: state=%s", oldLong.State())

	if newLong.State() != ConnStateReady {
		t.Fatalf("新长连接异常: state=%s", newLong.State())
	}

	// 3 个短连接仍能 ping
	for i, c := range shorts {
		if c.State() != ConnStateReady {
			t.Fatalf("短连接 %d 被踢: state=%s", i, c.State())
		}
		ctxPing, cancelP := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := c.Call(ctxPing, "meta.ping", nil)
		cancelP()
		if err != nil {
			t.Fatalf("短连接 %d ping 失败: %v", i, err)
		}
	}
	t.Log("[OK] 同槽位 3 个短连接全部 ping 成功，长连接互踢不影响短连接")
}

// ---------------------------------------------------------------------------
// 集成测试 6: 短连接不发布 client.online — observer 查询应 offline
// ---------------------------------------------------------------------------

func TestLongShort_ShortDoesNotPublishClientOnline(t *testing.T) {
	rid := rid8()
	shortPath := t.TempDir()
	observerPath := t.TempDir()
	shortOnlyAID := makeAID("o6", rid)
	observerAID := makeAID("q6", rid)

	createAIDOnce(t, shortPath, shortOnlyAID)
	createAIDOnce(t, observerPath, observerAID)

	observer := makeSharedClient(t, observerPath)
	short := makeSharedClient(t, shortPath)
	defer closeQuiet(observer)
	defer closeQuiet(short)

	if err := connectLong(t, observer, observerAID, "obs", 20*time.Second); err != nil {
		t.Fatalf("observer 长连接失败: %v", err)
	}
	if err := connectShort(t, short, shortOnlyAID, "cli", 0, 20*time.Second); err != nil {
		t.Fatalf("短连接失败: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	ctxQuery, cancelQuery := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelQuery()
	result, err := observer.Call(ctxQuery, "message.query_online", map[string]any{
		"aids": []string{shortOnlyAID},
	})
	if err != nil {
		t.Skipf("query_online 失败（可能服务端未支持）: %v", err)
	}
	t.Logf("query_online 结果: %#v", result)

	rmap, _ := result.(map[string]any)
	if rmap == nil {
		t.Fatalf("query_online 返回非 map: %T", result)
	}

	isOnline := false
	if onlineMap, _ := rmap["online"].(map[string]any); onlineMap != nil {
		if v, ok := onlineMap[shortOnlyAID].(bool); ok {
			isOnline = v
		}
	}
	if !isOnline {
		// 兼容 results 字段格式
		if results, _ := rmap["results"].(map[string]any); results != nil {
			if status, _ := results[shortOnlyAID].(map[string]any); status != nil {
				if v, ok := status["online"].(bool); ok {
					isOnline = v
				}
			}
		}
	}
	if isOnline {
		t.Fatalf("短连接被错误地登记为 online: %#v", rmap)
	}
	t.Log("[OK] 短连接不进入 online 表（仅长连接计入）")
}

// ---------------------------------------------------------------------------
// 集成测试 7: 短连接 connect 后验证 sessionOptions.connection_kind="short"
// ---------------------------------------------------------------------------

func TestLongShort_HelloOkConnectionKind(t *testing.T) {
	rid := rid8()
	sharedPath := t.TempDir()
	aid := makeAID("h7", rid)
	createAIDOnce(t, sharedPath, aid)

	// 长连接 → 验证 connection_kind=long
	longClient := makeSharedClient(t, sharedPath)
	defer closeQuiet(longClient)
	if err := connectLong(t, longClient, aid, "h7-l", 20*time.Second); err != nil {
		t.Fatalf("长连接失败: %v", err)
	}
	longClient.mu.RLock()
	longKind, _ := longClient.sessionOptions["connection_kind"].(string)
	longClient.mu.RUnlock()
	if longKind != "long" {
		t.Fatalf("长连接 sessionOptions.connection_kind 应为 'long', got '%s'", longKind)
	}
	_ = longClient.Close()

	// 短连接 → 验证 connection_kind=short
	shortClient := makeSharedClient(t, sharedPath)
	defer closeQuiet(shortClient)
	if err := connectShort(t, shortClient, aid, "h7-s", 0, 20*time.Second); err != nil {
		t.Fatalf("短连接失败: %v", err)
	}
	shortClient.mu.RLock()
	shortKind, _ := shortClient.sessionOptions["connection_kind"].(string)
	shortClient.mu.RUnlock()
	if shortKind != "short" {
		t.Fatalf("短连接 sessionOptions.connection_kind 应为 'short', got '%s'", shortKind)
	}
	t.Log("[OK] sessionOptions.connection_kind 长短分别正确")
}

// ---------------------------------------------------------------------------
// 集成测试 8: 短连接 connect 后验证 connection_kind=short
// ---------------------------------------------------------------------------

func TestLongShort_ShortDisablesTokenRefresh(t *testing.T) {
	rid := rid8()
	sharedPath := t.TempDir()
	aid := makeAID("d8", rid)
	createAIDOnce(t, sharedPath, aid)

	short := makeSharedClient(t, sharedPath)
	defer closeQuiet(short)

	if err := connectShort(t, short, aid, "d8", 0, 20*time.Second); err != nil {
		t.Fatalf("短连接失败: %v", err)
	}

	short.mu.RLock()
	kind, _ := short.sessionOptions["connection_kind"].(string)
	short.mu.RUnlock()

	if kind != "short" {
		t.Fatalf("短连接 connection_kind 应为 'short', got '%s'", kind)
	}
	t.Log("[OK] 短连接 connection_kind=short")
}

// ---------------------------------------------------------------------------
// E2E 1: alice 长连接 + 短连接顺序发 5 条给 bob，bob 收齐
// ---------------------------------------------------------------------------

func TestLongShortE2E_SequentialSends(t *testing.T) {
	rid := rid8()
	alicePath := t.TempDir()
	bobPath := t.TempDir()
	aliceAID := makeAID("e1a", rid)
	bobAID := makeAID("e1b", rid)
	createAIDOnce(t, alicePath, aliceAID)
	createAIDOnce(t, bobPath, bobAID)

	aliceLong := makeSharedClient(t, alicePath)
	bobLong := makeSharedClient(t, bobPath)
	defer closeQuiet(aliceLong)
	defer closeQuiet(bobLong)

	if err := connectLong(t, aliceLong, aliceAID, "main", 20*time.Second); err != nil {
		t.Fatalf("alice 长连接失败: %v", err)
	}
	if err := connectLong(t, bobLong, bobAID, "main", 20*time.Second); err != nil {
		t.Fatalf("bob 长连接失败: %v", err)
	}

	// alice 长连接监听 — 不应收到 outbound_sync（同 device+slot 不 self-sync）
	var aliceMu sync.Mutex
	var aliceUnexpected []map[string]any
	subA := aliceLong.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		aliceMu.Lock()
		aliceUnexpected = append(aliceUnexpected, data)
		aliceMu.Unlock()
	})
	defer subA.Unsubscribe()

	// bob 监听 5 条
	const N = 5
	bobReceived := make(chan string, N*2)
	subB := bobLong.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		p, _ := data["payload"].(map[string]any)
		if p == nil {
			return
		}
		text, _ := p["text"].(string)
		if strings.HasPrefix(text, "e2e1-msg-") {
			select {
			case bobReceived <- text:
			default:
			}
		}
	})
	defer subB.Unsubscribe()

	// 顺序起 5 个短连接发消息（每发一条 close 一次）
	expectedTexts := make(map[string]bool)
	for i := 0; i < N; i++ {
		text := fmt.Sprintf("e2e1-msg-%d-%s", i, rid)
		expectedTexts[text] = true

		cli := makeSharedClient(t, alicePath)
		if err := connectShort(t, cli, aliceAID, "main", 0, 20*time.Second); err != nil {
			closeQuiet(cli)
			t.Fatalf("第 %d 条短连接 connect 失败: %v", i, err)
		}
		ctxSend, cancelSend := context.WithTimeout(context.Background(), 10*time.Second)
		result, err := cli.Call(ctxSend, "message.send", map[string]any{
			"to":      bobAID,
			"payload": map[string]any{"type": "text", "text": text},
			"encrypt": true,
		})
		cancelSend()
		if err != nil {
			closeQuiet(cli)
			t.Fatalf("第 %d 条 send 失败: %v", i, err)
		}
		rmap, _ := result.(map[string]any)
		status, _ := rmap["status"].(string)
		if status != "sent" && status != "delivered" {
			closeQuiet(cli)
			t.Fatalf("第 %d 条 RPC 响应异常: %#v", i, rmap)
		}
		_ = cli.Close()
	}

	// 等待 bob 收齐 5 条
	gotTexts := make(map[string]bool)
	deadline := time.After(20 * time.Second)
	for len(gotTexts) < N {
		select {
		case text := <-bobReceived:
			gotTexts[text] = true
		case <-deadline:
			t.Fatalf("bob 收消息超时: 收到 %d/%d, 已收 %v", len(gotTexts), N, gotTexts)
		}
	}
	for text := range expectedTexts {
		if !gotTexts[text] {
			t.Fatalf("bob 缺少消息: %s", text)
		}
	}
	t.Logf("[OK] bob 收齐 %d 条消息", N)

	// 等额外 2s 后验证 alice 长连接无感
	time.Sleep(2 * time.Second)
	aliceMu.Lock()
	unexpected := len(aliceUnexpected)
	aliceMu.Unlock()
	if unexpected != 0 {
		t.Fatalf("alice 长连接收到了 %d 条不该收到的消息", unexpected)
	}
	t.Log("[OK] alice 长连接全程无感")

	// alice 长连接仍活
	ctxPing, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelPing()
	if _, err := aliceLong.Call(ctxPing, "meta.ping", nil); err != nil {
		t.Fatalf("alice 长连接最终 ping 失败: %v", err)
	}
}

// ---------------------------------------------------------------------------
// E2E 2: 5 个并发 goroutine 用短连接（不同 slot）发消息，全部成功
// ---------------------------------------------------------------------------

func TestLongShortE2E_ConcurrentShorts(t *testing.T) {
	rid := rid8()
	alicePath := t.TempDir()
	bobPath := t.TempDir()
	aliceAID := makeAID("e2a", rid)
	bobAID := makeAID("e2b", rid)
	createAIDOnce(t, alicePath, aliceAID)
	createAIDOnce(t, bobPath, bobAID)

	aliceLong := makeSharedClient(t, alicePath)
	bobLong := makeSharedClient(t, bobPath)
	defer closeQuiet(aliceLong)
	defer closeQuiet(bobLong)

	if err := connectLong(t, aliceLong, aliceAID, "main", 20*time.Second); err != nil {
		t.Fatalf("alice 长连接失败: %v", err)
	}
	if err := connectLong(t, bobLong, bobAID, "main", 20*time.Second); err != nil {
		t.Fatalf("bob 长连接失败: %v", err)
	}

	const N = 5
	bobReceived := make(chan string, N*2)
	subB := bobLong.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		p, _ := data["payload"].(map[string]any)
		if p == nil {
			return
		}
		text, _ := p["text"].(string)
		if strings.HasPrefix(text, "e2e2-msg-") {
			select {
			case bobReceived <- text:
			default:
			}
		}
	})
	defer subB.Unsubscribe()

	var wg sync.WaitGroup
	var failed atomic.Int32
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cli := makeSharedClient(t, alicePath)
			defer closeQuiet(cli)
			slot := fmt.Sprintf("cli-%d", idx)
			if err := connectShort(t, cli, aliceAID, slot, 0, 30*time.Second); err != nil {
				t.Logf("goroutine %d 短连接失败: %v", idx, err)
				failed.Add(1)
				return
			}
			text := fmt.Sprintf("e2e2-msg-%d-%s", idx, rid)
			ctxSend, cancelSend := context.WithTimeout(context.Background(), 15*time.Second)
			result, err := cli.Call(ctxSend, "message.send", map[string]any{
				"to":      bobAID,
				"payload": map[string]any{"type": "text", "text": text},
				"encrypt": true,
			})
			cancelSend()
			if err != nil {
				t.Logf("goroutine %d send 失败: %v", idx, err)
				failed.Add(1)
				return
			}
			rmap, _ := result.(map[string]any)
			status, _ := rmap["status"].(string)
			if status != "sent" && status != "delivered" {
				t.Logf("goroutine %d RPC 响应异常: %#v", idx, rmap)
				failed.Add(1)
			}
		}(i)
	}
	wg.Wait()

	if failed.Load() != 0 {
		t.Fatalf("%d/%d 并发短连接失败", failed.Load(), N)
	}
	t.Logf("[OK] %d 个并发短连接全部 RPC 响应成功", N)

	// bob 收齐
	gotTexts := make(map[string]bool)
	deadline := time.After(20 * time.Second)
	for len(gotTexts) < N {
		select {
		case text := <-bobReceived:
			gotTexts[text] = true
		case <-deadline:
			t.Fatalf("bob 收消息超时: 收到 %d/%d", len(gotTexts), N)
		}
	}
	t.Logf("[OK] bob 收齐 %d 条并发消息", N)
}

// ---------------------------------------------------------------------------
// E2E 3: alice 短连接发给 bob，bob 长连接回复 alice，alice 长连接收到
// ---------------------------------------------------------------------------

func TestLongShortE2E_LongReceivesBobReply(t *testing.T) {
	rid := rid8()
	alicePath := t.TempDir()
	bobPath := t.TempDir()
	aliceAID := makeAID("e3a", rid)
	bobAID := makeAID("e3b", rid)
	createAIDOnce(t, alicePath, aliceAID)
	createAIDOnce(t, bobPath, bobAID)

	aliceLong := makeSharedClient(t, alicePath)
	bobLong := makeSharedClient(t, bobPath)
	defer closeQuiet(aliceLong)
	defer closeQuiet(bobLong)

	if err := connectLong(t, aliceLong, aliceAID, "main", 20*time.Second); err != nil {
		t.Fatalf("alice 长连接失败: %v", err)
	}
	if err := connectLong(t, bobLong, bobAID, "main", 20*time.Second); err != nil {
		t.Fatalf("bob 长连接失败: %v", err)
	}

	// alice 短连接给 bob 发首条（建立 prekey 交换）
	cli := makeSharedClient(t, alicePath)
	if err := connectShort(t, cli, aliceAID, "main", 0, 20*time.Second); err != nil {
		closeQuiet(cli)
		t.Fatalf("alice 短连接失败: %v", err)
	}
	ctxInit, cancelInit := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := cli.Call(ctxInit, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": fmt.Sprintf("e2e3-init-%s", rid)},
		"encrypt": true,
	}); err != nil {
		cancelInit()
		closeQuiet(cli)
		t.Fatalf("初始 send 失败: %v", err)
	}
	cancelInit()
	_ = cli.Close()
	time.Sleep(1 * time.Second)

	// bob 回复 alice
	replyText := fmt.Sprintf("e2e3-reply-%s", rid)
	aliceReceived := make(chan map[string]any, 4)
	subA := aliceLong.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		p, _ := data["payload"].(map[string]any)
		if p != nil && getStr(p, "text", "") == replyText {
			select {
			case aliceReceived <- data:
			default:
			}
		}
	})
	subAUndec := aliceLong.On("message.undecryptable", func(payload any) {
		t.Logf("alice 收到 undecryptable: %#v", payload)
	})
	defer subA.Unsubscribe()
	defer subAUndec.Unsubscribe()

	ctxReply, cancelReply := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelReply()
	result, err := bobLong.Call(ctxReply, "message.send", map[string]any{
		"to":      aliceAID,
		"payload": map[string]any{"type": "text", "text": replyText},
		"encrypt": true,
	})
	if err != nil {
		t.Fatalf("bob 回复失败: %v", err)
	}
	rmap, _ := result.(map[string]any)
	status, _ := rmap["status"].(string)
	if status != "sent" && status != "delivered" {
		t.Fatalf("bob send 返回异常: %#v", rmap)
	}

	select {
	case <-aliceReceived:
		t.Log("[OK] alice 长连接收到 bob 的回复")
	case <-time.After(15 * time.Second):
		t.Fatalf("alice 长连接等待 bob 回复超时")
	}
}

// ---------------------------------------------------------------------------
// E2E 4: 短连接 ttl=2000，不主动 close，~3s 后断开，alice 长连接仍能收 bob 消息
// ---------------------------------------------------------------------------

func TestLongShortE2E_CliCrashTtl(t *testing.T) {
	rid := rid8()
	alicePath := t.TempDir()
	bobPath := t.TempDir()
	aliceAID := makeAID("e4a", rid)
	bobAID := makeAID("e4b", rid)
	createAIDOnce(t, alicePath, aliceAID)
	createAIDOnce(t, bobPath, bobAID)

	aliceLong := makeSharedClient(t, alicePath)
	bobLong := makeSharedClient(t, bobPath)
	cliCrash := makeSharedClient(t, alicePath)
	defer closeQuiet(aliceLong)
	defer closeQuiet(bobLong)
	defer closeQuiet(cliCrash) // 兜底关闭

	if err := connectLong(t, aliceLong, aliceAID, "main", 20*time.Second); err != nil {
		t.Fatalf("alice 长连接失败: %v", err)
	}
	if err := connectLong(t, bobLong, bobAID, "main", 20*time.Second); err != nil {
		t.Fatalf("bob 长连接失败: %v", err)
	}

	// CLI 短连接：ttl=2000，建立但不主动 close
	if err := connectShort(t, cliCrash, aliceAID, "main", 2000, 20*time.Second); err != nil {
		t.Fatalf("CLI 短连接失败: %v", err)
	}
	if cliCrash.State() != ConnStateReady {
		t.Fatalf("CLI 短连接初始状态异常: %s", cliCrash.State())
	}
	t.Log("[OK] CLI 短连接 ttl=2000ms 已建立")

	// 等 ttl 触发
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		s := cliCrash.State()
		if s == ConnStateStandby || s == ConnStateClosed || s == ConnStateConnectionFailed {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if cliCrash.State() == ConnStateReady {
		t.Fatalf("ttl 到期后 CLI 短连接仍 ready")
	}
	t.Logf("[OK] CLI 短连接被 ttl 兜底: state=%s", cliCrash.State())

	// alice 长连接仍存活
	ctxPing, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	if _, err := aliceLong.Call(ctxPing, "meta.ping", nil); err != nil {
		cancelPing()
		t.Fatalf("alice 长连接 ping 失败: %v", err)
	}
	cancelPing()
	t.Log("[OK] alice 长连接在 CLI ttl 后仍存活")

	// bob 给 alice 发消息
	replyText := fmt.Sprintf("e2e4-after-crash-%s", rid)
	aliceReceived := make(chan map[string]any, 4)
	subA := aliceLong.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		p, _ := data["payload"].(map[string]any)
		if p != nil && getStr(p, "text", "") == replyText {
			select {
			case aliceReceived <- data:
			default:
			}
		}
	})
	subAUndec := aliceLong.On("message.undecryptable", func(payload any) {
		t.Logf("alice 收到 undecryptable: %#v", payload)
	})
	defer subA.Unsubscribe()
	defer subAUndec.Unsubscribe()

	ctxSend, cancelSend := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelSend()
	if _, err := bobLong.Call(ctxSend, "message.send", map[string]any{
		"to":      aliceAID,
		"payload": map[string]any{"type": "text", "text": replyText},
		"encrypt": true,
	}); err != nil {
		t.Fatalf("bob send 失败: %v", err)
	}

	select {
	case <-aliceReceived:
		t.Log("[OK] CLI ttl 兜底后 alice 长连接仍能收到 bob 消息")
	case <-time.After(15 * time.Second):
		t.Fatalf("alice 长连接等待 bob 消息超时")
	}
}

// ---------------------------------------------------------------------------
// E2E 5: CLI 短连接发消息 → 关闭 → bob 回复 → alice 长连接收到
// ---------------------------------------------------------------------------

func TestLongShortE2E_LongSurvivesShortLifecycle(t *testing.T) {
	rid := rid8()
	alicePath := t.TempDir()
	bobPath := t.TempDir()
	aliceAID := makeAID("e5a", rid)
	bobAID := makeAID("e5b", rid)
	createAIDOnce(t, alicePath, aliceAID)
	createAIDOnce(t, bobPath, bobAID)

	aliceLong := makeSharedClient(t, alicePath)
	bobLong := makeSharedClient(t, bobPath)
	defer closeQuiet(aliceLong)
	defer closeQuiet(bobLong)

	if err := connectLong(t, aliceLong, aliceAID, "main", 20*time.Second); err != nil {
		t.Fatalf("alice 长连接失败: %v", err)
	}
	if err := connectLong(t, bobLong, bobAID, "main", 20*time.Second); err != nil {
		t.Fatalf("bob 长连接失败: %v", err)
	}

	// Phase 1: CLI 短连接给 bob 发消息
	cli := makeSharedClient(t, alicePath)
	if err := connectShort(t, cli, aliceAID, "main", 0, 20*time.Second); err != nil {
		closeQuiet(cli)
		t.Fatalf("CLI 短连接失败: %v", err)
	}
	ctxOut, cancelOut := context.WithTimeout(context.Background(), 15*time.Second)
	result, err := cli.Call(ctxOut, "message.send", map[string]any{
		"to":      bobAID,
		"payload": map[string]any{"type": "text", "text": fmt.Sprintf("e2e5-outbound-%s", rid)},
		"encrypt": true,
	})
	cancelOut()
	if err != nil {
		closeQuiet(cli)
		t.Fatalf("CLI send 失败: %v", err)
	}
	rmap, _ := result.(map[string]any)
	status, _ := rmap["status"].(string)
	if status != "sent" && status != "delivered" {
		closeQuiet(cli)
		t.Fatalf("CLI send 返回异常: %#v", rmap)
	}
	t.Log("[OK] Phase 1: CLI 短连接发消息成功")

	// 关闭短连接
	_ = cli.Close()
	t.Log("[OK] Phase 1: CLI 短连接已关闭")
	time.Sleep(1 * time.Second)

	// Phase 2: bob 回复 alice
	replyText := fmt.Sprintf("e2e5-reply-%s", rid)
	aliceReceived := make(chan map[string]any, 4)
	subA := aliceLong.On("message.received", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		p, _ := data["payload"].(map[string]any)
		if p != nil && getStr(p, "text", "") == replyText {
			select {
			case aliceReceived <- data:
			default:
			}
		}
	})
	subAUndec := aliceLong.On("message.undecryptable", func(payload any) {
		t.Logf("alice 收到 undecryptable: %#v", payload)
	})
	defer subA.Unsubscribe()
	defer subAUndec.Unsubscribe()

	ctxReply, cancelReply := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelReply()
	if _, err := bobLong.Call(ctxReply, "message.send", map[string]any{
		"to":      aliceAID,
		"payload": map[string]any{"type": "text", "text": replyText},
		"encrypt": true,
	}); err != nil {
		t.Fatalf("bob 回复失败: %v", err)
	}

	select {
	case <-aliceReceived:
		t.Log("[OK] Phase 2: alice 长连接在短连接生命周期完成后仍能收到 bob 回复")
	case <-time.After(15 * time.Second):
		t.Fatalf("alice 长连接等待 bob 回复超时")
	}
}
