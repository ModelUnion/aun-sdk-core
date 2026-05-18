package crypto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type goldenRecipientsVector struct {
	Description        string     `json:"description"`
	InputRows          [][]string `json:"input_rows"`
	ExpectedSortedRows [][]string `json:"expected_sorted_rows"`
	ExpectedDigestHex  string     `json:"expected_digest_hex"`
}

func TestRecipientsGoldenVectors(t *testing.T) {
	dir := filepath.Join("testdata", "golden", "recipients_digest")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取 golden 目录失败: %v", err)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("读取失败: %v", err)
			}
			var g goldenRecipientsVector
			if err := json.Unmarshal(data, &g); err != nil {
				t.Fatalf("解析失败: %v", err)
			}

			sorted := SortRecipients(g.InputRows)

			// 比较 sorted_rows（空切片与 nil 等价处理）
			if len(sorted) == 0 && len(g.ExpectedSortedRows) == 0 {
				// 空对空，OK
			} else if !reflect.DeepEqual(sorted, g.ExpectedSortedRows) {
				t.Fatalf("sorted_rows 不匹配\n期望: %v\n实际: %v", g.ExpectedSortedRows, sorted)
			}

			digest := ComputeRecipientsDigest(sorted)

			if digest != g.ExpectedDigestHex {
				t.Fatalf("digest 不匹配\n期望: %s\n实际: %s", g.ExpectedDigestHex, digest)
			}
			if len(sorted) > 0 && len(digest) != 64 {
				t.Fatalf("非空 digest 长度应为 64 hex chars，实际 %d", len(digest))
			}
		})
		count++
	}
	if count == 0 {
		t.Fatal("未找到任何 recipients golden 向量")
	}
}

// TestRecipientsSortStable 同 aid 多设备/多角色排序顺序与 Python 一致。
func TestRecipientsSortStable(t *testing.T) {
	rows := [][]string{
		{"bob.aid", "dev-2", "member", "group_device", "fp", "", "n", "w"},
		{"bob.aid", "dev-1", "member", "group_device_prekey", "fp", "spk", "n", "w"},
	}
	sorted := SortRecipients(rows)
	if sorted[0][1] != "dev-1" || sorted[1][1] != "dev-2" {
		t.Fatalf("device_id 排序错误: %v", sorted)
	}

	rows2 := [][]string{
		{"bob.aid", "dev-1", "member", "group_device", "fp", "", "n", "w"},
		{"bob.aid", "dev-1", "audit", "aid_master", "fp", "", "n", "w"},
	}
	sorted2 := SortRecipients(rows2)
	if sorted2[0][2] != "audit" || sorted2[1][2] != "member" {
		t.Fatalf("role 排序错误: %v", sorted2)
	}
}

// TestMerkleProofRoundtrip 任一行的 proof + leaf 重建 root 应通过验证。
func TestMerkleProofRoundtrip(t *testing.T) {
	rows := [][]string{
		{"alice.aid", "d1", "member", "gd", "fp1", "", "n1", "w1"},
		{"bob.aid", "d2", "member", "gd", "fp2", "", "n2", "w2"},
		{"carol.aid", "d3", "member", "gd", "fp3", "", "n3", "w3"},
	}
	sorted := SortRecipients(rows)
	root := ComputeRecipientsDigest(sorted)
	for i := range sorted {
		proof := ComputeMerkleProof(sorted, i)
		leaf := ComputeLeafHash(sorted[i])
		if !VerifyMerkleProof(leaf, proof, root) {
			t.Fatalf("索引 %d proof 验证失败", i)
		}
	}
}

// TestSingleRecipientRootEqualsLeaf 单行的 root = leaf。
func TestSingleRecipientRootEqualsLeaf(t *testing.T) {
	rows := [][]string{{"a.aid", "d1", "member", "gd", "fp", "", "n", "w"}}
	leafHex := hexBytes(ComputeLeafHash(rows[0]))
	if got := ComputeRecipientsDigest(rows); got != leafHex {
		t.Fatalf("单行 root 应等于 leaf hash\n期望: %s\n实际: %s", leafHex, got)
	}
}

func hexBytes(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hexChars[x>>4]
		out[i*2+1] = hexChars[x&0x0f]
	}
	return string(out)
}
