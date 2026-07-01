package aun

import "testing"

func TestGroupIDConvertToGroupAIDCompatibleForms(t *testing.T) {
	tests := []struct {
		raw         string
		localIssuer string
		want        string
	}{
		{raw: "room-123.agentid.pub", want: "room-123.agentid.pub"},
		{raw: "group.agentid.pub/room-123", want: "room-123.agentid.pub"},
		{raw: "room-123@agentid.pub", want: "room-123.agentid.pub"},
		{raw: "g-abc123", localIssuer: "agentid.pub", want: "g-abc123.agentid.pub"},
		{raw: "group.pub/room-123@agentid", want: "room-123.agentid.pub"},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if got := ConvertToGroupAID(tt.raw, tt.localIssuer); got != tt.want {
				t.Fatalf("ConvertToGroupAID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGroupIDNormalizeLegacyNameReturnsGroupAID(t *testing.T) {
	if got := NormalizeGroupID("group.agentid.pub/room-123", ""); got != "room-123.agentid.pub" {
		t.Fatalf("NormalizeGroupID() = %q", got)
	}
}

func TestGroupIDSplitAndDiscoveryHostDoNotRSplitIssuer(t *testing.T) {
	base, issuer := SplitGroupID("room-123.agentid.pub")
	if base != "room-123" || issuer != "agentid.pub" {
		t.Fatalf("SplitGroupID() = (%q, %q)", base, issuer)
	}
	base, issuer = SplitGroupID("group.agentid.pub/room-123")
	if base != "room-123" || issuer != "agentid.pub" {
		t.Fatalf("SplitGroupID(legacy) = (%q, %q)", base, issuer)
	}
	if got := BuildDiscoveryHost("room-123.agentid.pub"); got != "agentid.pub" {
		t.Fatalf("BuildDiscoveryHost() = %q", got)
	}
}

func TestGroupIDEmptyAndSlashesDoNotCreateDefaultGroup(t *testing.T) {
	for _, raw := range []string{"", "   ", "///"} {
		if got := ConvertToGroupAID(raw, "agentid.pub"); got != "" {
			t.Fatalf("ConvertToGroupAID(%q) = %q, want empty", raw, got)
		}
	}
}

func TestGroupIDValidatorRejectsMalformedOrTooLongInput(t *testing.T) {
	tests := []any{
		"group.agentid.pub//room-123",
		"room#123.agentid.pub",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.agentid.pub",
	}
	for _, raw := range tests {
		if _, err := ValidateGroupAIDFormat(raw, "group_aid", ""); err == nil {
			t.Fatalf("ValidateGroupAIDFormat(%v) expected error", raw)
		}
	}
}
