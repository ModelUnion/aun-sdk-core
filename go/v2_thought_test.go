// v2_thought_test.go — V2 thought 单元测试。
//
// 验证：
//   - isV2P2PThoughtEnvelope / isV2GroupThoughtEnvelope 识别逻辑
//   - 默认 capabilities 仅声明 V2 协议支持

package aun

import (
	"reflect"
	"testing"
)

func TestIsV2P2PThoughtEnvelope(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]any
		want bool
	}{
		{"nil", nil, false},
		{"v1", map[string]any{"type": "e2ee.encrypted"}, false},
		{"v2_p2p", map[string]any{"type": "e2ee.p2p_encrypted"}, true},
		{"v2_group", map[string]any{"type": "e2ee.group_encrypted"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isV2P2PThoughtEnvelope(tc.in)
			if got != tc.want {
				t.Fatalf("got=%v want=%v in=%#v", got, tc.want, tc.in)
			}
		})
	}
}

func TestIsV2GroupThoughtEnvelope(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]any
		want bool
	}{
		{"nil", nil, false},
		{"v1_group_no_recipients", map[string]any{"type": "e2ee.group_encrypted"}, false},
		{"v2_with_version", map[string]any{"type": "e2ee.group_encrypted", "version": "v2"}, true},
		{"v2_with_recipients", map[string]any{"type": "e2ee.group_encrypted", "recipients": []any{}}, true},
		{"v1_p2p_with_recipients", map[string]any{"type": "e2ee.p2p_encrypted", "recipients": []any{}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isV2GroupThoughtEnvelope(tc.in)
			if got != tc.want {
				t.Fatalf("got=%v want=%v in=%#v", got, tc.want, tc.in)
			}
		})
	}
}

func TestV2ThoughtE2EEMetadataPayloadType(t *testing.T) {
	meta := v2ThoughtE2EEMetadata(map[string]any{
		"suite":        "P256_HKDF_SHA256_AES_256_GCM",
		"payload_type": "text",
		"protected_headers": map[string]any{
			"payload_type": "fallback",
			"trace_id":     "trace-1",
			"_auth":        "secret",
		},
		"context": map[string]any{"type": "run", "id": "run-1", "_auth": "secret"},
	})
	if got := meta["payload_type"]; got != "text" {
		t.Fatalf("payload_type 应优先来自信封顶层，实际: %#v", got)
	}
	wantHeaders := map[string]any{"payload_type": "fallback", "trace_id": "trace-1"}
	if !reflect.DeepEqual(meta["protected_headers"], wantHeaders) {
		t.Fatalf("protected_headers 不正确: %#v", meta["protected_headers"])
	}

	fallback := v2ThoughtE2EEMetadata(map[string]any{
		"suite":             "P256_HKDF_SHA256_AES_256_GCM",
		"protected_headers": map[string]any{"payload_type": "fallback", "_auth": "secret"},
	})
	if got := fallback["payload_type"]; got != "fallback" {
		t.Fatalf("缺顶层 payload_type 时应从 protected_headers 回退，实际: %#v", got)
	}
}

// TestSeqTrackerLegacyV2SharedNamespace 验证历史消息与 V2 共享同一 P2P/Group seq 命名空间。
//
// 与 Python 一致：发送方 V2 send 后调 OnMessageSeq + MarkPublishedSeq；
// 历史推送/补拉再次见到同一 seq 时被 isPushedSeq 去重。
func TestSeqTrackerLegacyV2SharedNamespace(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	// P2P 命名空间共享：V2 send 推进 contig，历史消息同 seq 被去重
	c.mu.Lock()
	c.aid = "alice.example.com"
	c.mu.Unlock()
	ns := "p2p:alice.example.com"
	c.seqTracker.OnMessageSeq(ns, 1)
	c.markPushedSeq(ns, 1)
	if !c.isPushedSeq(ns, 1) {
		t.Fatalf("seq=1 应已标记为已发布")
	}
	if got := c.seqTracker.GetContiguousSeq(ns); got != 1 {
		t.Fatalf("contig=%d want=1", got)
	}

	// Group 命名空间共享
	gns := "group:g1"
	c.seqTracker.OnMessageSeq(gns, 5)
	c.markPushedSeq(gns, 5)
	if !c.isPushedSeq(gns, 5) {
		t.Fatalf("group seq=5 应已标记为已发布")
	}
}

// TestCapabilitiesDefaultIncludesV2 验证默认 capabilities 仅声明 V2 协议支持。
func TestCapabilitiesDefaultIncludesV2(t *testing.T) {
	caps := authConnectCapabilities(nil)
	// 默认 V2-only：supported_p2p_e2ee=[e2ee_v2]，supported_group_e2ee=[group_e2ee_v2]
	want := map[string][]string{
		"supported_p2p_e2ee":   {"e2ee_v2"},
		"supported_group_e2ee": {"group_e2ee_v2"},
	}
	for k, expect := range want {
		raw, ok := caps[k]
		if !ok {
			t.Fatalf("capabilities 缺少 %s: %#v", k, caps)
		}
		got := stringListFromAny(raw)
		if !reflect.DeepEqual(got, expect) {
			t.Fatalf("capabilities.%s got=%v want=%v", k, got, expect)
		}
	}
	if caps["e2ee"] != true {
		t.Fatalf("capabilities.e2ee should be true, got %#v", caps["e2ee"])
	}
	if caps["group_e2ee"] != true {
		t.Fatalf("capabilities.group_e2ee should be true, got %#v", caps["group_e2ee"])
	}
}

// TestCapabilitiesOverrideViaExtraInfo 已移除：测试代码不再通过 extra_info._capabilities
// 覆盖默认能力声明，所有测试一律以 SDK 默认 V2-only 能力运行。

func TestCapabilitiesIgnoreExtraInfoOverride(t *testing.T) {
	extraInfo := map[string]any{
		"note": "keep-me",
		"_capabilities": map[string]any{
			"e2ee":                 false,
			"group_e2ee":           false,
			"supported_p2p_e2ee":   []any{"e2ee", "e2ee_v2"},
			"supported_group_e2ee": []any{"group_e2ee", "group_e2ee_v2"},
		},
	}
	caps := authConnectCapabilities(extraInfo)
	want := map[string][]string{
		"supported_p2p_e2ee":   {"e2ee_v2"},
		"supported_group_e2ee": {"group_e2ee_v2"},
	}
	for k, expect := range want {
		raw, ok := caps[k]
		if !ok {
			t.Fatalf("capabilities 缺少 %s: %#v", k, caps)
		}
		got := stringListFromAny(raw)
		if !reflect.DeepEqual(got, expect) {
			t.Fatalf("capabilities.%s got=%v want=%v", k, got, expect)
		}
	}
	if caps["e2ee"] != true {
		t.Fatalf("capabilities.e2ee should be true, got %#v", caps["e2ee"])
	}
	if caps["group_e2ee"] != true {
		t.Fatalf("capabilities.group_e2ee should be true, got %#v", caps["group_e2ee"])
	}
}

// stringListFromAny 把 []any/[]string 统一为 []string，方便比较。
func stringListFromAny(v any) []string {
	switch x := v.(type) {
	case []string:
		return append([]string(nil), x...)
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
