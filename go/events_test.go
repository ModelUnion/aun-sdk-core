package aun

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestSubscribeAndPublish 验证订阅后能收到发布的事件
// Fix-02: Publish 改为顺序同步执行，返回时 handler 已完成
func TestSubscribeAndPublish(t *testing.T) {
	d := NewEventDispatcher()
	var received atomic.Value
	d.Subscribe("test.event", func(payload any) {
		received.Store(payload)
	})
	d.Publish("test.event", "hello")
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
	if callCount.Load() != 1 {
		t.Fatalf("取消订阅前应被调用 1 次, 实际: %d", callCount.Load())
	}
	sub.Unsubscribe()
	d.Publish("test.event", nil)
	if callCount.Load() != 1 {
		t.Errorf("取消订阅后不应再被调用, 调用次数: %d", callCount.Load())
	}
}

// TestMultipleHandlers 验证同一事件的多个处理器按注册顺序全部执行
// Fix-02: 顺序同步执行，保证执行顺序与注册顺序一致
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
// Fix-02: 顺序执行下 panic 被 recover，不影响后续 handler 与调用方
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
	if count.Load() != 100 {
		t.Errorf("并发发布计数不正确: %d", count.Load())
	}
}
