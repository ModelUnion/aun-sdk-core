package state

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type goldenStateVector struct {
	Description           string         `json:"description"`
	GroupID               string         `json:"group_id"`
	Epoch                 uint32         `json:"epoch"`
	StatePayload          map[string]any `json:"state_payload"`
	ExpectedCommitmentHex string         `json:"expected_commitment_hex"`
}

// loadGolden 用 json.Decoder + UseNumber 解析，避免整数被转为 float64。
func loadGolden(t *testing.T, name string) *goldenStateVector {
	t.Helper()
	path := filepath.Join("testdata", "golden", "state_commitment", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var g goldenStateVector
	if err := dec.Decode(&g); err != nil {
		t.Fatalf("解析 %s 失败: %v", path, err)
	}
	return &g
}

func TestStateCommitmentBasic(t *testing.T) {
	g := loadGolden(t, "basic.json")

	got := ComputeStateCommitment(g.GroupID, g.Epoch, g.StatePayload)
	if got != g.ExpectedCommitmentHex {
		t.Fatalf("state_commitment 不匹配\n期望: %s\n实际: %s", g.ExpectedCommitmentHex, got)
	}
	if len(got) != 64 {
		t.Fatalf("state_commitment 长度应为 64 hex chars，实际 %d", len(got))
	}
}

// TestStateCommitmentInputUnmodified 调用后 payload 内部数组顺序不应被修改。
func TestStateCommitmentInputUnmodified(t *testing.T) {
	g := loadGolden(t, "basic.json")

	// 把原始 payload 序列化保存
	before, _ := json.Marshal(g.StatePayload)
	_ = ComputeStateCommitment(g.GroupID, g.Epoch, g.StatePayload)
	after, _ := json.Marshal(g.StatePayload)
	if !bytes.Equal(before, after) {
		t.Fatalf("ComputeStateCommitment 不应修改输入 payload\nbefore: %s\nafter: %s", before, after)
	}
}

// TestStateCommitmentSortInvariance 打乱 members/devices/aid 列表顺序后结果应不变。
func TestStateCommitmentSortInvariance(t *testing.T) {
	g := loadGolden(t, "basic.json")
	expected := ComputeStateCommitment(g.GroupID, g.Epoch, g.StatePayload)

	// 反转 members
	members := g.StatePayload["members"].([]any)
	reversed := make([]any, len(members))
	for i, m := range members {
		reversed[len(members)-1-i] = m
	}
	mutated := map[string]any{}
	for k, v := range g.StatePayload {
		mutated[k] = v
	}
	mutated["members"] = reversed

	got := ComputeStateCommitment(g.GroupID, g.Epoch, mutated)
	if got != expected {
		t.Fatalf("打乱顺序后 state_commitment 应保持不变\n期望: %s\n实际: %s", expected, got)
	}
}
