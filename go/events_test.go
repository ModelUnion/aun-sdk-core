package aun

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSubscribeAndPublish 验证订阅后能收到发布的事件
// ISSUE-SDK-GO-006: Publish 改为异步执行，需等待 handler 完成
func TestSubscribeAndPublish(t *testing.T) {
	d := NewEventDispatcher()
	var received atomic.Value
	d.Subscribe("test.event", func(payload any) {
		received.Store(payload)
	})
	d.Publish("test.event", "hello")
	// 等待异步 handler 完成
	time.Sleep(50 * time.Millisecond)
	if received.Load() != "hello" {
		t.Errorf("收到的 payload 不正确: %v", received.Load())
	}
}

// TestUnsubscribe 验证取消订阅后不再收到事件
func TestUnsubscribe(t *testing.T) {
	d := NewEventDispatcher()
	var callCount atomic.Int64
	sub := d.Subscribe("test.event", func(payload any) {
		callCount.Add(1)
	})
	d.Publish("test.event", nil)
	time.Sleep(50 * time.Millisecond)
	if callCount.Load() != 1 {
		t.Fatalf("取消订阅前应被调用 1 次, 实际: %d", callCount.Load())
	}
	sub.Unsubscribe()
	d.Publish("test.event", nil)
	time.Sleep(50 * time.Millisecond)
	if callCount.Load() != 1 {
		t.Errorf("取消订阅后不应再被调用, 调用次数: %d", callCount.Load())
	}
}

// TestMultipleHandlers 验证同一事件的多个处理器都会执行
// ISSUE-SDK-GO-006: 异步化后不再保证执行顺序，改为验证全部执行完成
func TestMultipleHandlers(t *testing.T) {
	d := NewEventDispatcher()
	var count atomic.Int64
	d.Subscribe("test.event", func(payload any) {
		count.Add(1)
	})
	d.Subscribe("test.event", func(payload any) {
		count.Add(1)
	})
	d.Subscribe("test.event", func(payload any) {
		count.Add(1)
	})
	d.Publish("test.event", nil)
	time.Sleep(100 * time.Millisecond)
	if count.Load() != 3 {
		t.Fatalf("应有 3 个处理器执行, 实际: %d", count.Load())
	}
}

// TestPublishNoHandlers 验证发布无订阅者的事件不会 panic
func TestPublishNoHandlers(t *testing.T) {
	d := NewEventDispatcher()
	// 不应 panic
	d.Publish("nonexistent.event", "data")
}

// TestPublishPanicRecovery 验证处理器 panic 不影响后续处理器
// ISSUE-SDK-GO-006: 异步化后每个 handler 在独立 goroutine 中执行，panic 隔离更彻底
func TestPublishPanicRecovery(t *testing.T) {
	d := NewEventDispatcher()
	var secondCalled atomic.Bool
	d.Subscribe("test.event", func(payload any) {
		panic("测试 panic")
	})
	d.Subscribe("test.event", func(payload any) {
		secondCalled.Store(true)
	})
	d.Publish("test.event", nil)
	time.Sleep(100 * time.Millisecond)
	if !secondCalled.Load() {
		t.Error("第一个处理器 panic 后，第二个处理器应仍被执行")
	}
}

// TestSubscriptionUnsubscribeIdempotent 验证重复取消订阅不会 panic
func TestSubscriptionUnsubscribeIdempotent(t *testing.T) {
	d := NewEventDispatcher()
	sub := d.Subscribe("test.event", func(payload any) {})
	sub.Unsubscribe()
	sub.Unsubscribe() // 不应 panic
}

// TestConcurrentPublish 验证并发发布的线程安全
func TestConcurrentPublish(t *testing.T) {
	d := NewEventDispatcher()
	var count atomic.Int64
	d.Subscribe("test.event", func(payload any) {
		count.Add(1)
	})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.Publish("test.event", nil)
		}()
	}
	wg.Wait()
	// 等待所有异步 handler 完成
	time.Sleep(200 * time.Millisecond)
	if count.Load() != 100 {
		t.Errorf("并发发布计数不正确: %d", count.Load())
	}
}
