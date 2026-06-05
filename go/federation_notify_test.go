//go:build integration

package aun

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestFederationNotifyAIDOnline(t *testing.T) {
	rid := federationRunID()
	alice := makeFederationClient(t)
	bob := makeFederationClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := ensureFederationConnected(t, alice, fmt.Sprintf("go-notify-xa-%s.aid.com", rid))
	bobAID := ensureFederationConnected(t, bob, fmt.Sprintf("go-notify-xb-%s.aid.net", rid))
	token := fmt.Sprintf("cross-%s", rid)

	collector := collectAppEvent(bob, "app.cross_domain_ping", token)
	defer collector.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := alice.Notify(ctx, "event/app.cross_domain_ping", map[string]any{
		"token": token,
		"from":  aliceAID,
	}, NotifyOptions{To: bobAID, TTLMS: 10000}); err != nil {
		t.Fatalf("跨域 notify 发送失败: %v", err)
	}

	payload, ok := collector.Wait(12 * time.Second)
	if !ok {
		t.Fatal("Bob 未收到跨域 notify")
	}
	if payload["token"] != token {
		t.Fatalf("跨域 notify payload 不匹配: %+v", payload)
	}
	meta, _ := payload["_notify"].(map[string]any)
	if meta == nil || meta["from_aid"] != aliceAID {
		t.Fatalf("_notify.from_aid 不匹配: %+v", meta)
	}
}
