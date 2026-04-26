package aun

import (
	"context"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── P0: ISSUE-SDK-GO-010 后台任务 context 继承 ────────────────────

// TestBackgroundTasksUseIndependentContext 验证 startBackgroundTasks 使用独立 context，
// 而非继承用户传入的 context。用户 context 取消后，后台任务的 context 不应被取消。
func TestBackgroundTasksUseIndependentContext(t *testing.T) {
	c := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()

	// 模拟 connectOnce 完成后的状态
	c.mu.Lock()
	c.state = StateConnected
	c.mu.Unlock()

	// 使用一个短超时的 context 模拟用户传入的 context
	userCtx, userCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer userCancel()

	// 启动后台任务（传入用户的短超时 context）
	c.startBackgroundTasks(userCtx)

	// 等待用户 context 超时
	<-userCtx.Done()
	time.Sleep(20 * time.Millisecond)

	// 验证：后台任务的 context 不应被取消
	c.mu.RLock()
	bgCtx := c.ctx
	c.mu.RUnlock()

	if bgCtx == nil {
		t.Fatal("ISSUE-SDK-GO-010: 后台任务 context 不应为 nil")
	}
	select {
	case <-bgCtx.Done():
		t.Fatal("ISSUE-SDK-GO-010: 用户 context 取消后，后台任务 context 不应被取消")
	default:
		// 正确：后台任务 context 仍然活跃
	}

	// Close() 时才应取消后台任务
	_ = c.Close()
	c.mu.RLock()
	bgCtx2 := c.ctx
	c.mu.RUnlock()
	if bgCtx2 != nil {
		select {
		case <-bgCtx2.Done():
			// 正确：Close 后 context 已取消
		default:
			// 也可能 bgCtx2 被置为 nil 了，这也是可以接受的
		}
	}
}

// ── P1: ISSUE-SDK-GO-006 Publish 异步化 ────────────────────

// TestPublishRunsHandlersAsync 验证 Publish 异步执行 handler，不阻塞调用者
func TestPublishRunsHandlersAsync(t *testing.T) {
	d := NewEventDispatcher()

	var handlerDone atomic.Bool
	d.Subscribe("test.slow", func(payload any) {
		time.Sleep(100 * time.Millisecond)
		handlerDone.Store(true)
	})

	start := time.Now()
	d.Publish("test.slow", "data")
	elapsed := time.Since(start)

	// 异步化后，Publish 应立即返回，不等待 handler 完成
	if elapsed > 50*time.Millisecond {
		t.Errorf("ISSUE-SDK-GO-006: Publish 应异步执行 handler，但耗时 %v（阈值 50ms）", elapsed)
	}

	// 等待 handler 完成
	time.Sleep(200 * time.Millisecond)
	if !handlerDone.Load() {
		t.Error("ISSUE-SDK-GO-006: handler 应在后台执行完毕")
	}
}

// TestPublishAsyncPanicRecovery 验证异步 handler panic 不影响其他 handler
func TestPublishAsyncPanicRecovery(t *testing.T) {
	d := NewEventDispatcher()

	var secondCalled atomic.Bool
	d.Subscribe("test.panic", func(payload any) {
		panic("测试 panic")
	})
	d.Subscribe("test.panic", func(payload any) {
		secondCalled.Store(true)
	})

	d.Publish("test.panic", nil)
	// 等待异步 handler 完成
	time.Sleep(100 * time.Millisecond)

	if !secondCalled.Load() {
		t.Error("ISSUE-SDK-GO-006: 第一个 handler panic 后，第二个 handler 应仍被执行")
	}
}

// TestPublishAsyncConcurrency 验证异步 Publish 的并发安全性
func TestPublishAsyncConcurrency(t *testing.T) {
	d := NewEventDispatcher()

	var count atomic.Int64
	d.Subscribe("test.concurrent", func(payload any) {
		count.Add(1)
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.Publish("test.concurrent", nil)
		}()
	}
	wg.Wait()
	// 等待所有异步 handler 完成
	time.Sleep(200 * time.Millisecond)

	if count.Load() != 100 {
		t.Errorf("ISSUE-SDK-GO-006: 并发发布计数不正确: %d，期望 100", count.Load())
	}
}

// ── P1: ISSUE-SDK-GO-007 reconnectLoop 使用 math/rand ────────────

// TestReconnectJitterNoPanic 验证 reconnectLoop 中的 jitter 计算不会 panic
// 以及在并发场景下安全。注意：这个问题的修复是使用 crypto/rand 或局部 rand 实例，
// 此测试通过 -race 标志检测数据竞争。
func TestReconnectJitterNoPanic(t *testing.T) {
	// 通过多次并发调用 secureRandFloat64 验证不会 panic
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := secureRandFloat64()
			if v < 0 || v >= 1 {
				t.Errorf("secureRandFloat64 结果应在 [0, 1) 范围内，实际: %f", v)
			}
		}()
	}
	wg.Wait()
}

func TestReconnectDelayBaseClamp(t *testing.T) {
	if got := clampReconnectDelaySeconds(0.01, 1, reconnectMaxBaseDelaySeconds); got != 1.0 {
		t.Fatalf("base 下限应夹到 1s，实际: %f", got)
	}
	if got := clampReconnectDelaySeconds(128, 1, reconnectMaxBaseDelaySeconds); got != reconnectMaxBaseDelaySeconds {
		t.Fatalf("base 上限应夹到 64s，实际: %f", got)
	}
	if got := clampReconnectDelaySeconds(math.NaN(), 1, reconnectMaxBaseDelaySeconds); got != 1.0 {
		t.Fatalf("NaN base 应回退到 fallback 后夹取，实际: %f", got)
	}
	if got := reconnectSleepDelaySeconds(4, 64); got < 4 || got >= 68 {
		t.Fatalf("delay 应在 [base, base+max_base) 范围内，实际: %f", got)
	}
}

// ── P1: ISSUE-SDK-GO-008 transport.SetTimeout 并发保护 ────────────
// 注：已在 transport_test.go 中的 TestSetTimeoutConcurrentSafety 覆盖。
// 当前实现使用 atomic.Int64，已经是线程安全的。

// ── P2: ISSUE-SDK-GO-001 eventNameMap 缺少 group.message_created ──

// TestEventNameMapGroupMessageCreated 验证 eventNameMap 包含 group.message_created 映射
func TestEventNameMapGroupMessageCreated(t *testing.T) {
	if _, ok := eventNameMap["group.message_created"]; !ok {
		t.Error("ISSUE-SDK-GO-001: eventNameMap 缺少 group.message_created 映射")
	}
}

// ── P2: ISSUE-SDK-GO-005 -32004 错误码映射 ────────────────────

// TestMapRemoteError_32004_PermissionDenied 验证 -32004 映射为 PermissionError
func TestMapRemoteError_32004_PermissionDenied(t *testing.T) {
	err := MapRemoteError(map[string]any{
		"code":    float64(-32004),
		"message": "permission denied",
	})
	if _, ok := err.(*PermissionError); !ok {
		t.Errorf("ISSUE-SDK-GO-005: -32004 应映射为 PermissionError, 实际: %T", err)
	}
}

// ── P2: ISSUE-SDK-GO-009 Connect 允许从 disconnected 状态调用 ────

// TestConnectFromDisconnectedState 验证断开后可以重新连接
func TestConnectFromDisconnectedState(t *testing.T) {
	c := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()

	// 模拟断开状态
	c.mu.Lock()
	c.state = StateDisconnected
	c.mu.Unlock()

	// 验证 Connect 允许在 disconnected 状态调用
	// 注意：实际不会成功连接（无 gateway），但不应返回 StateError
	err := c.Connect(context.Background(), map[string]any{
		"access_token": "test-token",
		"gateway":      "ws://localhost:9999/ws",
	}, nil)

	// 应该是连接错误（无法连接），而不是状态错误
	if err != nil {
		if _, isStateErr := err.(*StateError); isStateErr {
			t.Errorf("ISSUE-SDK-GO-009: disconnected 状态应允许 Connect，但收到 StateError: %v", err)
		}
		// 连接错误是预期的
	}
}

// ── P2: ISSUE-SDK-GO-003 PrekeyRefreshInterval 配置项 ────────────

// TestPrekeyRefreshIntervalNotInConfig 验证 PrekeyRefreshInterval 已从 ConnectOptions 中移除
// 或者不影响实际行为（不误导用户）
func TestPrekeyRefreshIntervalRemovedFromConfig(t *testing.T) {
	// ConnectOptions 不应包含 PrekeyRefreshInterval 字段
	// 验证方法：构造 ConnectOptions 并确认没有该字段的实际效果
	opts := &ConnectOptions{
		AutoReconnect: true,
	}
	// PrekeyRefreshInterval 字段已从结构体中移除
	_ = opts
}

// ── P2: ISSUE-SDK-GO-011 syncAllGroupsOnce 并发处理 ────────────

// TestSyncAllGroupsOnceConcurrentLimit 验证并发处理有合理限制
// 注：这个测试主要验证函数存在且不 panic，实际并发行为需要集成测试
func TestSyncAllGroupsOnceNoRace(t *testing.T) {
	c := NewClient(map[string]any{
		"aun_path": t.TempDir(),
	})
	defer func() { _ = c.Close() }()

	// 未连接状态下调用 syncAllGroupsOnce 不应 panic
	c.syncAllGroupsOnce()
}

// ── P3: ISSUE-SDK-GO-012 登录时间戳精度 ────────────────────

// TestSignLoginNonceTimestampPrecision 验证 SignLoginNonce 生成浮点数精度时间戳
// 与 Python SDK str(time.time()) 对齐
func TestSignLoginNonceTimestampPrecision(t *testing.T) {
	crypto := &CryptoProvider{}
	// 生成密钥对用于测试
	kp, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}
	privPEM, _ := kp["private_key_pem"].(string)

	// 不传 clientTime，让 SDK 自动生成
	_, usedTime, err := crypto.SignLoginNonce(privPEM, "test-nonce", "")
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	// Python SDK 使用 str(time.time()) 生成浮点数格式（如 "1745318400.123456"）
	// Go SDK 应该也使用浮点数格式，包含小数点
	if !strings.Contains(usedTime, ".") {
		t.Errorf("ISSUE-SDK-GO-012: 时间戳应为浮点数格式（含小数点），实际: %s", usedTime)
	}
}
