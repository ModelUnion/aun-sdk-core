package aun

import (
	"os"
	"strings"
	"testing"
)

func TestV2EventsNoRemovedEpochRotatedSubscription(t *testing.T) {
	source, err := os.ReadFile("v2_events.go")
	if err != nil {
		t.Fatalf("读取 v2_events.go 失败: %v", err)
	}
	text := string(source)
	for _, removed := range []string{"group.v2.epoch_rotated", "onV2EpochRotated"} {
		if strings.Contains(text, removed) {
			t.Fatalf("V1 epoch rotation 残留事件仍存在: %s", removed)
		}
	}
}
