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
		in, def  string
		wantErr  bool
		wantVal  string
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
		slotID  string
		msg     map[string]any
		want    bool
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
