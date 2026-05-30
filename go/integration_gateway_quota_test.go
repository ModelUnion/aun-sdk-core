//go:build integration

package aun

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Gateway 长连接配额 + 短连接 idle TTL 集成测试
//
// 与 Python 服务端单元测试 extensions/services/codex-unit/gateway/test_gateway_quota.py
// 的 4 类语义对齐（这里跑端到端真实连接）：
//
//   1. TestGatewayQuota_AidDeviceSlot       — 同 (aid,device) 下 11 个 slot
//                                              → 触发 4015 + aid_device_slot_quota_exceeded
//   2. TestGatewayQuota_AidDevices          — 同 aid 下 11 个 device
//                                              → 触发 4015 + aid_devices_quota_exceeded
//   3. TestGatewayQuota_DeviceAids          — 同 device 下 11 个 aid
//                                              → 触发 4015 + device_aids_quota_exceeded
//   4. TestGatewayQuota_ShortIdleSliding    — 短连接 short_ttl_ms 滑动窗口：
//                                              keep-alive 不被踢；不保活则 ~ttl_ms 后被 4014
//
// 默认配额（来自 ws_server.py 环境变量，与 docker-compose 保持一致）：
//   _MAX_LONG_SLOTS_PER_AID_DEVICE = 10
//   _MAX_LONG_DEVICES_PER_AID      = 10
//   _MAX_LONG_AIDS_PER_DEVICE      = 10
//
// 运行：
//   MSYS_NO_PATHCONV=1 docker exec kite-go-tester sh -lc \
//     "cd /workspace/go && /usr/local/go/bin/go test -tags integration . \
//      -run TestGatewayQuota -count=1 -v"
// ---------------------------------------------------------------------------

const gatewayQuotaLimit = 10 // 服务端默认值；与三层配额常量一致

// quotaTestClient 创建配额测试客户端（每次都用独立 aun_path 以隔离 device_id）
func quotaTestClient(t *testing.T, aunPath string) *AUNClient {
	t.Helper()
	t.Setenv("AUN_ENV", "development")
	client := newClient(map[string]any{
		"aun_path": aunPath,
	}, true)
	client.configModel.RequireForwardSecrecy = false
	return client
}

// quotaConnectLong 建立长连接（aid 必须已注册）
func quotaConnectLong(t *testing.T, client *AUNClient, aid, slotID string, timeout time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	integrationLoadAIDIntoClient(t, client, aid, slotID)
	return client.Connect(ctx, ConnectionOptions{
		AutoReconnect:     boolPtr(false),
		HeartbeatInterval: 30 * time.Second,
		ConnectionKind:    "long",
	})
}

// quotaConnectShort 建立短连接（aid 必须已注册）
func quotaConnectShort(t *testing.T, client *AUNClient, aid, slotID string, shortTtlMs int, timeout time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	integrationLoadAIDIntoClient(t, client, aid, slotID)
	return client.Connect(ctx, ConnectionOptions{
		ConnectionKind: "short",
		ShortTtlMs:     shortTtlMs,
	})
}

// createAIDInPath 在指定目录创建 AID（不连接）
func createAIDInPath(t *testing.T, aunPath, aid string) {
	t.Helper()
	integrationRegisterAIDInPath(t, aunPath, aid)
}

// quotaDisconnectInfo 一次 gateway.disconnect 通知的关键信息
type quotaDisconnectInfo struct {
	code     int
	reason   string
	detail   map[string]any
	rawEvent map[string]any
}

// captureDisconnect 订阅 client 的 gateway.disconnect 事件，返回拿到首条事件的通道
func captureDisconnect(client *AUNClient) (<-chan quotaDisconnectInfo, func()) {
	ch := make(chan quotaDisconnectInfo, 4)
	sub := client.On("gateway.disconnect", func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		info := quotaDisconnectInfo{rawEvent: data}
		switch v := data["code"].(type) {
		case int:
			info.code = v
		case int64:
			info.code = int(v)
		case float64:
			info.code = int(v)
		}
		info.reason, _ = data["reason"].(string)
		info.detail, _ = data["detail"].(map[string]any)
		select {
		case ch <- info:
		default:
		}
	})
	return ch, func() { sub.Unsubscribe() }
}

// waitDisconnect 等待任意一个 client 收到 gateway.disconnect 事件
func waitDisconnect(t *testing.T, channels []<-chan quotaDisconnectInfo, timeout time.Duration) (int, quotaDisconnectInfo, bool) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			return -1, quotaDisconnectInfo{}, false
		default:
		}
		// 轮询所有 channel（小延迟）
		for i, ch := range channels {
			select {
			case info := <-ch:
				return i, info, true
			default:
			}
		}
		select {
		case <-deadline:
			return -1, quotaDisconnectInfo{}, false
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// ---------------------------------------------------------------------------
// Test 1: 同 (aid, device) 下 11 个 slot
//   占满 10 个 slot 后第 11 个进入 → 服务端踢"最早 slot"，4015 + aid_device_slot_quota_exceeded
// ---------------------------------------------------------------------------

func TestGatewayQuota_AidDeviceSlot(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("go-quota-ads-%s.%s", rid, testIssuer())

	// 同 aun_path → 同 device_id；只创建一次 AID
	sharedPath := t.TempDir()
	createAIDInPath(t, sharedPath, aid)

	// 占满 10 个 slot（同 device）
	clients := make([]*AUNClient, 0, gatewayQuotaLimit+1)
	channels := make([]<-chan quotaDisconnectInfo, 0, gatewayQuotaLimit+1)
	cleanups := make([]func(), 0, gatewayQuotaLimit+1)
	defer func() {
		for _, c := range cleanups {
			c()
		}
		for _, c := range clients {
			closeQuiet(c)
		}
	}()

	for i := 0; i < gatewayQuotaLimit; i++ {
		c := quotaTestClient(t, sharedPath)
		ch, cancelSub := captureDisconnect(c)
		clients = append(clients, c)
		channels = append(channels, ch)
		cleanups = append(cleanups, cancelSub)
		slot := fmt.Sprintf("slot-%02d", i)
		if err := quotaConnectLong(t, c, aid, slot, 30*time.Second); err != nil {
			t.Fatalf("第 %d 个长连接（slot=%s）失败: %v", i, slot, err)
		}
		// 让服务端按 created_at 顺序记录，避免毫秒同秒
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("[OK] 占满 %d 个同 (aid,device) 下的 slot", gatewayQuotaLimit)

	// 第 11 个新 slot（应踢 slot-00 — 最早进入的）
	overflow := quotaTestClient(t, sharedPath)
	overflowCh, overflowCancel := captureDisconnect(overflow)
	clients = append(clients, overflow)
	channels = append(channels, overflowCh)
	cleanups = append(cleanups, overflowCancel)
	slotNew := "slot-NEW"
	if err := quotaConnectLong(t, overflow, aid, slotNew, 30*time.Second); err != nil {
		t.Fatalf("第 11 个长连接（slot=%s）失败（应该成功 — 它是踢人方而非被踢方）: %v", slotNew, err)
	}
	t.Logf("[OK] 第 11 个长连接进入（slot=%s），等待服务端踢最早的 slot", slotNew)

	// 等待某个 client 收到 gateway.disconnect 4015
	idx, info, ok := waitDisconnect(t, channels, 15*time.Second)
	if !ok {
		t.Fatalf("超时未收到任何 gateway.disconnect 事件（预期：slot-00 被踢）")
	}
	if info.code != 4015 {
		raw, _ := json.Marshal(info.rawEvent)
		t.Fatalf("disconnect code 应为 4015, got=%d, raw=%s", info.code, string(raw))
	}
	quotaKind, _ := info.detail["quota_kind"].(string)
	if quotaKind != "aid_device_slot_quota_exceeded" {
		raw, _ := json.Marshal(info.detail)
		t.Fatalf("quota_kind 应为 aid_device_slot_quota_exceeded, got=%q, detail=%s",
			quotaKind, string(raw))
	}
	// detail 应含被踢的最早 slot
	kickedSlot, _ := info.detail["slot_id"].(string)
	if kickedSlot != "slot-00" {
		t.Logf("[WARN] 被踢的 slot 不是 slot-00（最早），got=%q（多客户端同秒可能扰动 created_at 顺序）", kickedSlot)
	}
	// evicted_by 应是 slot-NEW
	evictedBy, _ := info.detail["evicted_by"].(map[string]any)
	if evictedBy != nil {
		newSlot, _ := evictedBy["slot_id"].(string)
		if newSlot != slotNew {
			t.Fatalf("evicted_by.slot_id 应为 %q, got %q", slotNew, newSlot)
		}
	}
	t.Logf("[OK] 第 %d 个 client 收到 4015 + %s（kicked slot=%q, evicted_by=%v）",
		idx, quotaKind, kickedSlot, evictedBy)

	// 等待状态切换到 connection_failed / closed / standby
	time.Sleep(500 * time.Millisecond)
	if state := clients[idx].State(); state != ConnStateConnectionFailed && state != ConnStateClosed && state != ConnStateStandby {
		t.Fatalf("被踢的 client[%d] 状态应为 connection_failed/closed/standby, got=%s", idx, state)
	}
	t.Logf("[OK] 被踢 client[%d] 状态=%s（4015 不重连）", idx, clients[idx].State())
}

// ---------------------------------------------------------------------------
// Test 2: 同 aid 下 11 个 device
//   占满 10 个 device 后第 11 个进入 → 服务端踢"最早 device"，4015 + aid_devices_quota_exceeded
//
// 实现思路（与 Python 测试 integration_test_gateway_quota.py:Test 2 对齐）：
//   所有 client 共享同一 aun_path（共享 keystore、同私钥），
//   但每次构造 client 前覆写 .device_id 文件让 SDK 读到不同的 device_id。
//   create_aid 只在 device-0 调用一次（cert 跟随 keystore，与 device_id 无关）；
//   后续 device 仅 authenticate（同私钥+不同 device_id）。
//   服务端把它们视作同 AID 下的多个设备，11 个时第 1 个被踢。
// ---------------------------------------------------------------------------

func TestGatewayQuota_AidDevices(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("go-quota-ad-%s.%s", rid, testIssuer())

	sharedPath := t.TempDir()
	deviceIDFile := filepath.Join(sharedPath, ".device_id")

	// 先在 device-0 创建 AID（cert 写入共享 keystore）
	if err := os.WriteFile(deviceIDFile, []byte(fmt.Sprintf("qta-dev0-%s", rid)), 0o600); err != nil {
		t.Fatalf("写入 .device_id 失败: %v", err)
	}
	createAIDInPath(t, sharedPath, aid)

	clients := make([]*AUNClient, 0, gatewayQuotaLimit+1)
	channels := make([]<-chan quotaDisconnectInfo, 0, gatewayQuotaLimit+1)
	cleanups := make([]func(), 0, gatewayQuotaLimit+1)
	defer func() {
		for _, c := range cleanups {
			c()
		}
		for _, c := range clients {
			closeQuiet(c)
		}
	}()

	for i := 0; i < gatewayQuotaLimit; i++ {
		devID := fmt.Sprintf("qta-dev%d-%s", i, rid)
		if err := os.WriteFile(deviceIDFile, []byte(devID), 0o600); err != nil {
			t.Fatalf("覆写 .device_id 失败 (i=%d): %v", i, err)
		}
		c := quotaTestClient(t, sharedPath)
		// 防御性校验：client 真的读到了我们写的 device_id
		if c.deviceID != devID {
			closeQuiet(c)
			t.Fatalf("device_id mismatch (i=%d): expected %q, got %q", i, devID, c.deviceID)
		}
		ch, cancelSub := captureDisconnect(c)
		clients = append(clients, c)
		channels = append(channels, ch)
		cleanups = append(cleanups, cancelSub)
		slot := fmt.Sprintf("dev%d-main", i)
		if err := quotaConnectLong(t, c, aid, slot, 30*time.Second); err != nil {
			t.Fatalf("第 %d 个 device 长连接失败: %v", i, err)
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Logf("[OK] 同 aid 占满 %d 个 device", gatewayQuotaLimit)

	// 第 11 个 device
	newDev := fmt.Sprintf("qta-devNEW-%s", rid)
	if err := os.WriteFile(deviceIDFile, []byte(newDev), 0o600); err != nil {
		t.Fatalf("覆写 .device_id (overflow) 失败: %v", err)
	}
	overflow := quotaTestClient(t, sharedPath)
	if overflow.deviceID != newDev {
		closeQuiet(overflow)
		t.Fatalf("overflow device_id mismatch: expected %q, got %q", newDev, overflow.deviceID)
	}
	overflowCh, overflowCancel := captureDisconnect(overflow)
	clients = append(clients, overflow)
	channels = append(channels, overflowCh)
	cleanups = append(cleanups, overflowCancel)
	if err := quotaConnectLong(t, overflow, aid, "devNEW-main", 30*time.Second); err != nil {
		t.Fatalf("第 11 个 device 长连接失败（应该成功）: %v", err)
	}
	t.Logf("[OK] 第 11 个 device 进入，等待服务端踢最早 device")

	idx, info, ok := waitDisconnect(t, channels, 15*time.Second)
	if !ok {
		t.Fatalf("超时未收到任何 gateway.disconnect 事件（预期：最早 device 被踢）")
	}
	if info.code != 4015 {
		raw, _ := json.Marshal(info.rawEvent)
		t.Fatalf("disconnect code 应为 4015, got=%d, raw=%s", info.code, string(raw))
	}
	quotaKind, _ := info.detail["quota_kind"].(string)
	if quotaKind != "aid_devices_quota_exceeded" {
		raw, _ := json.Marshal(info.detail)
		t.Fatalf("quota_kind 应为 aid_devices_quota_exceeded, got=%q, detail=%s",
			quotaKind, string(raw))
	}
	t.Logf("[OK] 第 %d 个 client 收到 4015 + %s", idx, quotaKind)

	time.Sleep(500 * time.Millisecond)
	if state := clients[idx].State(); state != ConnStateConnectionFailed && state != ConnStateClosed && state != ConnStateStandby {
		t.Fatalf("被踢的 client[%d] 状态应为 connection_failed/closed/standby, got=%s", idx, state)
	}
}

// ---------------------------------------------------------------------------
// Test 3: 同 device 下 11 个 aid
//   占满 10 个 aid 后第 11 个进入 → 服务端踢"最早 aid"，4015 + device_aids_quota_exceeded
// ---------------------------------------------------------------------------

func TestGatewayQuota_DeviceAids(t *testing.T) {
	rid := runID()

	// 关键：所有 client 共享同 aun_path → 同 device_id；用 11 个不同 aid
	sharedPath := t.TempDir()

	clients := make([]*AUNClient, 0, gatewayQuotaLimit+1)
	channels := make([]<-chan quotaDisconnectInfo, 0, gatewayQuotaLimit+1)
	cleanups := make([]func(), 0, gatewayQuotaLimit+1)
	aids := make([]string, 0, gatewayQuotaLimit+1)
	defer func() {
		for _, c := range cleanups {
			c()
		}
		for _, c := range clients {
			closeQuiet(c)
		}
	}()

	for i := 0; i < gatewayQuotaLimit; i++ {
		aid := fmt.Sprintf("go-quota-da-%s-%02d.%s", rid, i, testIssuer())
		aids = append(aids, aid)
		createAIDInPath(t, sharedPath, aid)

		c := quotaTestClient(t, sharedPath)
		ch, cancelSub := captureDisconnect(c)
		clients = append(clients, c)
		channels = append(channels, ch)
		cleanups = append(cleanups, cancelSub)
		if err := quotaConnectLong(t, c, aid, "main", 30*time.Second); err != nil {
			t.Fatalf("第 %d 个 aid 长连接失败: %v", i, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("[OK] 同 device 占满 %d 个 aid", gatewayQuotaLimit)

	// 第 11 个 aid（用索引 10 命名，避免 AID 校验拒绝大写后缀）
	overflowAID := fmt.Sprintf("go-quota-da-%s-%02d.%s", rid, gatewayQuotaLimit, testIssuer())
	createAIDInPath(t, sharedPath, overflowAID)
	overflow := quotaTestClient(t, sharedPath)
	overflowCh, overflowCancel := captureDisconnect(overflow)
	clients = append(clients, overflow)
	channels = append(channels, overflowCh)
	cleanups = append(cleanups, overflowCancel)
	aids = append(aids, overflowAID)

	if err := quotaConnectLong(t, overflow, overflowAID, "main", 30*time.Second); err != nil {
		t.Fatalf("第 11 个 aid 长连接失败（应该成功）: %v", err)
	}
	t.Logf("[OK] 第 11 个 aid 进入，等待服务端踢最早 aid")

	idx, info, ok := waitDisconnect(t, channels, 15*time.Second)
	if !ok {
		t.Fatalf("超时未收到任何 gateway.disconnect 事件（预期：最早 aid 被踢）")
	}
	if info.code != 4015 {
		raw, _ := json.Marshal(info.rawEvent)
		t.Fatalf("disconnect code 应为 4015, got=%d, raw=%s", info.code, string(raw))
	}
	quotaKind, _ := info.detail["quota_kind"].(string)
	if quotaKind != "device_aids_quota_exceeded" {
		raw, _ := json.Marshal(info.detail)
		t.Fatalf("quota_kind 应为 device_aids_quota_exceeded, got=%q, detail=%s",
			quotaKind, string(raw))
	}
	t.Logf("[OK] 第 %d 个 client 收到 4015 + %s（aid=%s）", idx, quotaKind, aids[idx])

	time.Sleep(500 * time.Millisecond)
	if state := clients[idx].State(); state != ConnStateConnectionFailed && state != ConnStateClosed && state != ConnStateStandby {
		t.Fatalf("被踢的 client[%d] 状态应为 connection_failed/closed/standby, got=%s", idx, state)
	}
}

// ---------------------------------------------------------------------------
// Test 4: 短连接 short_ttl_ms 滑动窗口（保活 vs 不保活）
//
//   - 不保活：connect 后空闲 → ~ttl_ms 后被服务端 4014 关闭
//   - 保活  ：每 < ttl_ms 发一次 RPC → 不应被关闭
//
// 注：服务端 _short_connection_ttl_watch 用 last_rpc_at 做滑动窗口。
//     需要 short_ttl_ms 显式 > 0（默认 0 = 不启用）。
// ---------------------------------------------------------------------------

func TestGatewayQuota_ShortIdleSliding(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("go-quota-idle-%s.%s", rid, testIssuer())
	sharedPath := t.TempDir()
	createAIDInPath(t, sharedPath, aid)

	const ttlMs = 2000

	// ── 子用例 1: 不保活 → ~ttl 后被踢（4014）
	t.Run("idle_no_keepalive", func(t *testing.T) {
		c := quotaTestClient(t, sharedPath)
		defer closeQuiet(c)

		ch, cancelSub := captureDisconnect(c)
		defer cancelSub()

		if err := quotaConnectShort(t, c, aid, "idle1", ttlMs, 20*time.Second); err != nil {
			t.Fatalf("短连接失败: %v", err)
		}

		// 等 ttl + 余量 — 不发任何 RPC
		select {
		case info := <-ch:
			if info.code != 4014 {
				t.Fatalf("应被 4014 关闭, got code=%d, reason=%q", info.code, info.reason)
			}
			t.Logf("[OK] 不保活短连接被 4014 关闭, idle_ms=%v ttl_ms=%v",
				info.detail["idle_ms"], info.detail["ttl_ms"])
		case <-time.After(time.Duration(ttlMs)*time.Millisecond + 5*time.Second):
			t.Fatalf("超时未被服务端 idle ttl 关闭")
		}
		// 状态应已切到非 ready
		time.Sleep(300 * time.Millisecond)
		if state := c.State(); state == ConnStateReady {
			t.Fatalf("idle 关闭后状态仍为 ready: %s", state)
		}
	})

	// ── 子用例 2: 保活 → ttl×3 内始终在线
	t.Run("active_keepalive", func(t *testing.T) {
		c := quotaTestClient(t, sharedPath)
		defer closeQuiet(c)

		var disconnects atomic.Int32
		sub := c.On("gateway.disconnect", func(payload any) {
			data, ok := payload.(map[string]any)
			if !ok {
				return
			}
			t.Logf("[WARN] 保活期间收到 gateway.disconnect: %v", data)
			disconnects.Add(1)
		})
		defer sub.Unsubscribe()

		if err := quotaConnectShort(t, c, aid, "idle2", ttlMs, 20*time.Second); err != nil {
			t.Fatalf("短连接失败: %v", err)
		}

		// 在 ttl×3 (6s) 内每 700ms ping 一次（< ttl_ms）
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			tick := time.NewTicker(700 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					_, err := c.Call(ctx, "meta.ping", nil)
					cancel()
					if err != nil {
						t.Logf("[INFO] 保活 ping 失败: %v（连接可能已断）", err)
					}
				}
			}
		}()

		// 跑 ttl×3
		time.Sleep(time.Duration(ttlMs*3) * time.Millisecond)
		close(stop)
		wg.Wait()

		if got := disconnects.Load(); got != 0 {
			t.Fatalf("保活期间不应收到 gateway.disconnect, got=%d", got)
		}
		if state := c.State(); state != ConnStateReady {
			t.Fatalf("保活期间状态应为 ready, got=%s", state)
		}
		t.Logf("[OK] 保活短连接（ping 间隔 700ms < ttl=%dms）在 %d ms 内未被踢", ttlMs, ttlMs*3)
	})
}
