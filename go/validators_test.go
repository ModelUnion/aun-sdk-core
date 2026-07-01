package aun

import (
	"strings"
	"testing"
)

func TestValidateAIDFormat(t *testing.T) {
	tests := []struct {
		name      string
		aid       any
		paramName string
		wantErr   bool
		errMsg    string
	}{
		// 正常情况
		{name: "valid aid", aid: "alice.aid.com", paramName: "aid", wantErr: false},
		{name: "valid aid with underscore", aid: "alice_bob.aid.com", paramName: "aid", wantErr: false},
		{name: "valid aid with dash", aid: "alice-bob.aid.com", paramName: "aid", wantErr: false},
		{name: "valid aid 4 chars", aid: "alex.aid.com", paramName: "aid", wantErr: false},
		{name: "valid aid uppercase normalized", aid: "Alice.Aid.Com", paramName: "aid", wantErr: false},

		// 空值
		{name: "nil aid", aid: nil, paramName: "aid", wantErr: true, errMsg: "cannot be empty"},
		{name: "empty string", aid: "", paramName: "aid", wantErr: true, errMsg: "cannot be empty"},
		{name: "whitespace only", aid: "   ", paramName: "aid", wantErr: true, errMsg: "cannot be empty"},

		// 缺少域名
		{name: "no issuer", aid: "alice", paramName: "aid", wantErr: true, errMsg: "must be in format"},
		{name: "trailing dot", aid: "alice.", paramName: "aid", wantErr: true, errMsg: "issuer part cannot be empty"},

		// name 部分不合法
		{name: "name too short", aid: "ali.aid.com", paramName: "aid", wantErr: true, errMsg: "must be 4-64 characters"},
		{name: "name starts with dash", aid: "-alice.aid.com", paramName: "aid", wantErr: true, errMsg: "cannot start with '-'"},
		{name: "name starts with guest", aid: "guest123.aid.com", paramName: "aid", wantErr: true, errMsg: "cannot start with 'guest'"},
		{name: "name with invalid char", aid: "alice@bob.aid.com", paramName: "aid", wantErr: true, errMsg: "must be 4-64 characters"},
		{name: "name with space", aid: "alice bob.aid.com", paramName: "aid", wantErr: true, errMsg: "must be 4-64 characters"},

		// issuer 部分不合法
		{name: "invalid issuer", aid: "alice.-aid.com", paramName: "aid", wantErr: true, errMsg: "is not a valid domain"},
		{name: "issuer with space", aid: "alice.aid com", paramName: "aid", wantErr: true, errMsg: "is not a valid domain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateAIDFormat(tt.aid, tt.paramName)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateAIDFormat() expected error but got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateAIDFormat() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateAIDFormat() unexpected error = %v", err)
					return
				}
				if result == "" {
					t.Errorf("ValidateAIDFormat() returned empty string for valid input")
				}
				// 验证结果是小写的
				if result != strings.ToLower(result) {
					t.Errorf("ValidateAIDFormat() result not lowercase: %s", result)
				}
			}
		})
	}
}

func TestValidateGroupIDFormat(t *testing.T) {
	tests := []struct {
		name      string
		groupID   any
		paramName string
		wantErr   bool
		errMsg    string
	}{
		// 正常情况 - Legacy 格式
		{name: "legacy format", groupID: "g-abcd1234", paramName: "group_id", wantErr: false},
		{name: "legacy format min", groupID: "g-abcd", paramName: "group_id", wantErr: false},
		{name: "legacy format max", groupID: "g-abcd1234567890abcd1234567890ab", paramName: "group_id", wantErr: false},

		// 正常情况 - 新格式
		{name: "new format 5 chars", groupID: "abcde", paramName: "group_id", wantErr: false},
		{name: "new format longer", groupID: "abcde12345", paramName: "group_id", wantErr: false},

		// 正常情况 - Group name 格式
		{name: "group name", groupID: "mygroup", paramName: "group_id", wantErr: false},
		{name: "group name with underscore", groupID: "my_group", paramName: "group_id", wantErr: false},
		{name: "group name with dash", groupID: "my-group", paramName: "group_id", wantErr: false},

		// 正常情况 - 带域名
		{name: "with domain dot", groupID: "mygroup.aid.com", paramName: "group_id", wantErr: false},
		{name: "with domain @", groupID: "mygroup@aid.com", paramName: "group_id", wantErr: false},
		{name: "canonical format", groupID: "group.aid.com/mygroup", paramName: "group_id", wantErr: false},
		{name: "polluted canonical format", groupID: "group.pub/room-123@agentid", paramName: "group_id", wantErr: false},
		{name: "legacy with domain", groupID: "g-abcd1234.aid.com", paramName: "group_id", wantErr: false},

		// 空值
		{name: "nil group_id", groupID: nil, paramName: "group_id", wantErr: true, errMsg: "cannot be empty"},
		{name: "empty string", groupID: "", paramName: "group_id", wantErr: true, errMsg: "cannot be empty"},
		{name: "whitespace only", groupID: "   ", paramName: "group_id", wantErr: true, errMsg: "cannot be empty"},

		// base 部分不合法
		{name: "legacy too short", groupID: "g-a", paramName: "group_id", wantErr: true, errMsg: "must be one of"},
		{name: "too short 3 chars", groupID: "abc", paramName: "group_id", wantErr: true, errMsg: "must be one of"},
		{name: "name starts with dash", groupID: "-mygroup", paramName: "group_id", wantErr: true, errMsg: "must be one of"},
		{name: "name with invalid char", groupID: "my@group", paramName: "group_id", wantErr: true, errMsg: "must be one of"},
		{name: "name with space", groupID: "my group", paramName: "group_id", wantErr: true, errMsg: "must be one of"},

		// domain 部分不合法
		{name: "invalid domain", groupID: "mygroup.-aid.com", paramName: "group_id", wantErr: true, errMsg: "is not a valid domain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateGroupIDFormat(tt.groupID, tt.paramName)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateGroupIDFormat() expected error but got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateGroupIDFormat() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateGroupIDFormat() unexpected error = %v", err)
					return
				}
				if result == "" {
					t.Errorf("ValidateGroupIDFormat() returned empty string for valid input")
				}
				// 验证结果是小写的
				if result != strings.ToLower(result) {
					t.Errorf("ValidateGroupIDFormat() result not lowercase: %s", result)
				}
				if strings.HasPrefix(result, "group.") && strings.Contains(result, "/") {
					t.Errorf("ValidateGroupIDFormat() must return group_aid target format, got %s", result)
				}
			}
		})
	}
}

func TestValidateGroupAIDFormat(t *testing.T) {
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
			got, err := ValidateGroupAIDFormat(tt.raw, "group_aid", tt.localIssuer)
			if err != nil {
				t.Fatalf("ValidateGroupAIDFormat() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ValidateGroupAIDFormat() = %q, want %q", got, tt.want)
			}
		})
	}
}
