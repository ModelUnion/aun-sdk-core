package aun

import "testing"

func TestSlotIsolationKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"evolclaw cli", "evolclaw"},
		{"evolclaw/cli", "evolclaw"},
		{"evolclaw:daemon", "evolclaw"},
		{"simple", "simple"},
		{"a/b/c", "a"},
		{"", ""},
	}
	for _, c := range cases {
		if got := SlotIsolationKey(c.in); got != c.want {
			t.Errorf("SlotIsolationKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeSlotID(t *testing.T) {
	cases := []struct {
		in, def string
		wantErr bool
		wantVal string
	}{
		{"evolclaw cli", "", false, "evolclaw cli"},
		{"evolclaw/cli", "", false, "evolclaw/cli"},
		{"/invalid", "", true, ""},
		{":invalid", "", true, ""},
		{"", "mydefault", false, "mydefault"},
	}
	for _, c := range cases {
		got, err := NormalizeSlotID(c.in, c.def)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeSlotID(%q, %q) 期望 error，但无错误", c.in, c.def)
			}
		} else {
			if err != nil {
				t.Errorf("NormalizeSlotID(%q, %q) 意外错误: %v", c.in, c.def, err)
			}
			if got != c.wantVal {
				t.Errorf("NormalizeSlotID(%q, %q) = %q, want %q", c.in, c.def, got, c.wantVal)
			}
		}
	}
}

func TestMessageTargetsCurrentInstance_SlotIsolation(t *testing.T) {
	cases := []struct {
		slotID string
		msg    map[string]any
		want   bool
	}{
		{"evolclaw cli", map[string]any{"slot_id": "evolclaw daemon"}, true},
		{"evolclaw cli", map[string]any{"slot_id": "other daemon"}, false},
		{"evolclaw cli", map[string]any{}, true},
	}
	for _, c := range cases {
		client := &AUNClient{slotID: c.slotID}
		if got := client.messageTargetsCurrentInstance(c.msg); got != c.want {
			t.Errorf("slotID=%q msg=%v: got %v, want %v", c.slotID, c.msg, got, c.want)
		}
	}
}

func TestInjectMessageCursorContextSlotSeparators(t *testing.T) {
	for _, slotID := range []string{"evolclaw cli", "evolclaw/cli", "evolclaw:cli"} {
		client := &AUNClient{deviceID: "test-device", slotID: slotID}
		params := map[string]any{"after_seq": 0, "limit": 10}
		if err := client.injectMessageCursorContext("message.pull", params); err != nil {
			t.Fatalf("slot_id=%q 不应被 message.pull/ack 上下文注入拒绝: %v", slotID, err)
		}
		if params["device_id"] != "test-device" || params["slot_id"] != slotID {
			t.Fatalf("slot_id=%q 注入结果不正确: %#v", slotID, params)
		}
	}
}

func TestInjectMessageCursorContextSlotIsolationKey(t *testing.T) {
	client := &AUNClient{deviceID: "test-device", slotID: "evolclaw cli"}
	params := map[string]any{"seq": 1, "slot_id": "evolclaw daemon"}
	if err := client.injectMessageCursorContext("message.ack", params); err != nil {
		t.Fatalf("同隔离键 slot_id 不应被拒绝: %v", err)
	}
	if params["device_id"] != "test-device" || params["slot_id"] != "evolclaw cli" {
		t.Fatalf("同隔离键 slot_id 应归一到当前实例: %#v", params)
	}

	params = map[string]any{"after_seq": 0, "slot_id": "other daemon"}
	if err := client.injectMessageCursorContext("message.pull", params); err == nil {
		t.Fatal("不同隔离键 slot_id 应被拒绝")
	}
}
