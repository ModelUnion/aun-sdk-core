//go:build integration

package aun

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type appEventCollector struct {
	ch  chan map[string]any
	sub *Subscription
}

func collectAppEvent(client *AUNClient, event string, token string) *appEventCollector {
	collector := &appEventCollector{ch: make(chan map[string]any, 4)}
	collector.sub = client.On(event, func(payload any) {
		data, ok := payload.(map[string]any)
		if !ok {
			return
		}
		if fmt.Sprintf("%v", data["token"]) != token {
			return
		}
		select {
		case collector.ch <- data:
		default:
		}
	})
	return collector
}

func (c *appEventCollector) Wait(timeout time.Duration) (map[string]any, bool) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case msg := <-c.ch:
		return msg, true
	case <-timer.C:
		return nil, false
	}
}

func (c *appEventCollector) Close() {
	if c != nil && c.sub != nil {
		c.sub.Unsubscribe()
	}
}

func TestIntegrationNotifyAIDOnline(t *testing.T) {
	r := runID()
	aliceAID := fmt.Sprintf("go-notify-a-%s.agentid.pub", r)
	bobAID := fmt.Sprintf("go-notify-b-%s.agentid.pub", r)
	token := fmt.Sprintf("aid-%s", r)
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	collector := collectAppEvent(bob, "app.typing", token)
	defer collector.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := alice.Notify(ctx, "event/app.typing", map[string]any{
		"token":     token,
		"thread_id": fmt.Sprintf("thread-%s", r),
	}, NotifyOptions{To: bobAID, TTLMS: 5000}); err != nil {
		t.Fatalf("notify 发送失败: %v", err)
	}

	payload, ok := collector.Wait(8 * time.Second)
	if !ok {
		t.Fatal("Bob 未收到 app.typing notify")
	}
	if payload["thread_id"] != fmt.Sprintf("thread-%s", r) {
		t.Fatalf("payload 不匹配: %+v", payload)
	}
	meta, _ := payload["_notify"].(map[string]any)
	if meta == nil || meta["from_aid"] != aliceAID {
		t.Fatalf("_notify.from_aid 不匹配: %+v", meta)
	}
}

func TestIntegrationNotifyGroupOnline(t *testing.T) {
	r := runID()
	aliceAID := fmt.Sprintf("go-notify-ga-%s.agentid.pub", r)
	bobAID := fmt.Sprintf("go-notify-gb-%s.agentid.pub", r)
	token := fmt.Sprintf("group-%s", r)
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	groupID := createGroup(t, alice, fmt.Sprintf("go-notify-group-%s", r))
	addMember(t, alice, groupID, bobAID)
	time.Sleep(1 * time.Second)

	collector := collectAppEvent(bob, "app.presence", token)
	defer collector.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := alice.Notify(ctx, "event/app.presence", map[string]any{
		"token": token,
		"state": "active",
	}, NotifyOptions{GroupID: groupID}); err != nil {
		t.Fatalf("group notify 发送失败: %v", err)
	}

	payload, ok := collector.Wait(8 * time.Second)
	if !ok {
		t.Fatal("Bob 未收到 group notify")
	}
	if payload["state"] != "active" || payload["group_id"] != groupID {
		t.Fatalf("group notify payload 不匹配: %+v", payload)
	}
}

func TestE2ENotifyDeviceSlotAndOfflineNoStore(t *testing.T) {
	r := runID()
	aliceAID := fmt.Sprintf("go-notify-slot-a-%s.agentid.pub", r)
	bobAID := fmt.Sprintf("go-notify-slot-b-%s.agentid.pub", r)
	token := fmt.Sprintf("slot-%s", r)
	root := t.TempDir()
	targetSlot := fmt.Sprintf("target-%s", r)
	otherSlot := fmt.Sprintf("other-%s", r)

	alice := makeClient(t)
	bobTarget := makeIsolatedClient(t, root, targetSlot)
	bobOther := makeIsolatedClient(t, root, otherSlot)
	defer alice.Close()
	defer bobTarget.Close()
	defer bobOther.Close()

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bobTarget, bobAID)
	ensureConnected(t, bobOther, bobAID)

	current := bobTarget.CurrentAID()
	if current == nil || current.DeviceID == "" {
		t.Fatalf("无法读取目标 device_id: %+v", current)
	}

	targetCollector := collectAppEvent(bobTarget, "app.slot_probe", token)
	otherCollector := collectAppEvent(bobOther, "app.slot_probe", token)
	defer targetCollector.Close()
	defer otherCollector.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := alice.Notify(ctx, "event/app.slot_probe", map[string]any{
		"token": token,
		"slot":  targetSlot,
	}, NotifyOptions{
		To:       bobAID,
		DeviceID: current.DeviceID,
		SlotID:   targetSlot,
		TTLMS:    8000,
	}); err != nil {
		t.Fatalf("slot notify 发送失败: %v", err)
	}

	if payload, ok := targetCollector.Wait(8 * time.Second); !ok {
		t.Fatal("目标 slot 未收到 notify")
	} else if payload["slot"] != targetSlot {
		t.Fatalf("目标 slot payload 不匹配: %+v", payload)
	}
	if payload, ok := otherCollector.Wait(1500 * time.Millisecond); ok {
		t.Fatalf("非目标 slot 不应收到 notify: %+v", payload)
	}

	offlineToken := fmt.Sprintf("offline-%s", r)
	offlineAID := fmt.Sprintf("go-notify-off-b-%s.agentid.pub", r)
	offlineRoot := t.TempDir()
	integrationRegisterOrLoadAID(t, offlineRoot, offlineAID, "late")
	bobLate := makeIsolatedClient(t, offlineRoot, "late")
	defer bobLate.Close()
	offlineCollector := collectAppEvent(bobLate, "app.offline_probe", offlineToken)
	defer offlineCollector.Close()

	ctxOffline, cancelOffline := context.WithTimeout(context.Background(), 10*time.Second)
	if err := alice.Notify(ctxOffline, "event/app.offline_probe", map[string]any{
		"token": offlineToken,
		"phase": "while-offline",
	}, NotifyOptions{To: offlineAID, TTLMS: 3000}); err != nil {
		cancelOffline()
		t.Fatalf("offline notify 发送失败: %v", err)
	}
	cancelOffline()

	ensureConnected(t, bobLate, offlineAID)
	if payload, ok := offlineCollector.Wait(3 * time.Second); ok {
		t.Fatalf("离线 notify 不应重连补发: %+v", payload)
	}
}
