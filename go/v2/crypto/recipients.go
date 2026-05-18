// Recipients 排序与 Merkle digest（V2 §10.3 / §5.3）。
//
// recipients 为二维数组，每行 8 个字符串字段：
//   [aid, device_id, role, key_source, fp, spk_id, wrap_nonce, wrapped_key]
// 排序键: (aid asc, device_id asc, role asc) 字典序。
//
// Digest = MerkleRoot(leaf_hashes)
//   leaf_i = SHA256(LEAF_PREFIX || aid \x00 device_id \x00 role \x00 key_source \x00 fp \x00 spk_id \x00 wrap_nonce wrapped_key)
//   inner = SHA256(NODE_PREFIX || left || right)
//   奇数节点复制最后一个
//
// 注意：wrap_nonce / wrapped_key 优先 base64 解码，失败则回退 utf-8 字节，
//       这与 Python 实现一致以兼容测试向量中既有 base64 也有明文的两种风格。

package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

const (
	leafPrefix = "AUN-V2-RCPT-LEAF-v1"
	nodePrefix = "AUN-V2-RCPT-NODE-v1"
)

// SortRecipients 按 (aid, device_id, role) 字典序对 recipients 行做稳定排序，
// 返回新切片，不修改入参。
//
// 行长度小于 3 的会被视为缺失字段，缺位补空字符串后参与排序键比较。
func SortRecipients(rows [][]string) [][]string {
	out := make([][]string, len(rows))
	for i := range rows {
		// 复制每行避免别名
		row := make([]string, len(rows[i]))
		copy(row, rows[i])
		out[i] = row
	}
	// 稳定排序，与 Python `sorted()` 行为一致
	stableSort(out, func(a, b []string) bool {
		ka0 := safeIdx(a, 0)
		kb0 := safeIdx(b, 0)
		if ka0 != kb0 {
			return ka0 < kb0
		}
		ka1 := safeIdx(a, 1)
		kb1 := safeIdx(b, 1)
		if ka1 != kb1 {
			return ka1 < kb1
		}
		return safeIdx(a, 2) < safeIdx(b, 2)
	})
	return out
}

func safeIdx(row []string, i int) string {
	if i < len(row) {
		return row[i]
	}
	return ""
}

// stableSort 实现稳定排序（插入排序，行数通常很小）。
// recipients 行数一般不大（成员设备数），插入排序简洁且稳定。
func stableSort(rows [][]string, less func(a, b []string) bool) {
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && less(rows[j], rows[j-1]); j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
}

// decodeOrRaw 优先 base64 解码 value；失败时回退 utf-8 字节。
// 与 Python 实现保持一致以兼容测试向量。
func decodeOrRaw(value string) []byte {
	if value == "" {
		return nil
	}
	if b, err := base64.StdEncoding.DecodeString(value); err == nil {
		return b
	}
	return []byte(value)
}

// ComputeLeafHash 计算单行 leaf hash。
// row 期望包含 8 个字符串字段；缺位以空字符串处理。
func ComputeLeafHash(row []string) []byte {
	aid := []byte(safeIdx(row, 0))
	deviceID := []byte(safeIdx(row, 1))
	role := []byte(safeIdx(row, 2))
	keySource := []byte(safeIdx(row, 3))
	fp := []byte(safeIdx(row, 4))
	spkID := []byte(safeIdx(row, 5))
	wrapNonce := decodeOrRaw(safeIdx(row, 6))
	wrappedKey := decodeOrRaw(safeIdx(row, 7))

	h := sha256.New()
	h.Write([]byte(leafPrefix))
	h.Write(aid)
	h.Write([]byte{0x00})
	h.Write(deviceID)
	h.Write([]byte{0x00})
	h.Write(role)
	h.Write([]byte{0x00})
	h.Write(keySource)
	h.Write([]byte{0x00})
	h.Write(fp)
	h.Write([]byte{0x00})
	h.Write(spkID)
	h.Write([]byte{0x00})
	h.Write(wrapNonce)
	h.Write(wrappedKey)
	return h.Sum(nil)
}

func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte(nodePrefix))
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// ComputeMerkleRoot 计算 recipients 的 Merkle root（hex）。
// 空 rows → 空字符串（与 Python 实现一致）。
func ComputeMerkleRoot(rows [][]string) string {
	if len(rows) == 0 {
		return ""
	}
	leaves := make([][]byte, len(rows))
	for i, row := range rows {
		leaves[i] = ComputeLeafHash(row)
	}
	return hex.EncodeToString(merkleRootFromLeaves(leaves))
}

func merkleRootFromLeaves(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	layer := make([][]byte, len(leaves))
	copy(layer, leaves)
	for len(layer) > 1 {
		if len(layer)%2 == 1 {
			layer = append(layer, layer[len(layer)-1]) // 奇数节点复制最后一个
		}
		next := make([][]byte, 0, len(layer)/2)
		for i := 0; i < len(layer); i += 2 {
			next = append(next, nodeHash(layer[i], layer[i+1]))
		}
		layer = next
	}
	return layer[0]
}

// ProofStep 表示 Merkle proof 中一步：sibling hash + 在合并时的位置（"L"/"R"）。
type ProofStep struct {
	Sibling  string `json:"sibling"`
	Position string `json:"position"`
}

// ComputeMerkleProof 为 targetIndex 行生成 Merkle proof。
// 越界或空 rows 返回空 proof。
func ComputeMerkleProof(rows [][]string, targetIndex int) []ProofStep {
	if len(rows) == 0 || targetIndex < 0 || targetIndex >= len(rows) {
		return nil
	}
	leaves := make([][]byte, len(rows))
	for i, row := range rows {
		leaves[i] = ComputeLeafHash(row)
	}
	proof := make([]ProofStep, 0)
	layer := make([][]byte, len(leaves))
	copy(layer, leaves)
	idx := targetIndex
	for len(layer) > 1 {
		if len(layer)%2 == 1 {
			layer = append(layer, layer[len(layer)-1])
		}
		siblingIdx := idx ^ 1
		sibling := layer[siblingIdx]
		position := "L"
		if siblingIdx > idx {
			position = "R"
		}
		proof = append(proof, ProofStep{
			Sibling:  hex.EncodeToString(sibling),
			Position: position,
		})
		next := make([][]byte, 0, len(layer)/2)
		for i := 0; i < len(layer); i += 2 {
			next = append(next, nodeHash(layer[i], layer[i+1]))
		}
		layer = next
		idx /= 2
	}
	return proof
}

// VerifyMerkleProof 验证 leaf 配合 proof 重建出的 root 是否等于 expectedRootHex。
func VerifyMerkleProof(leaf []byte, proof []ProofStep, expectedRootHex string) bool {
	if expectedRootHex == "" {
		return false
	}
	cur := leaf
	for _, step := range proof {
		sibling, err := hex.DecodeString(step.Sibling)
		if err != nil {
			return false
		}
		switch step.Position {
		case "L":
			cur = nodeHash(sibling, cur)
		case "R":
			cur = nodeHash(cur, sibling)
		default:
			return false
		}
	}
	return hex.EncodeToString(cur) == expectedRootHex
}

// ComputeRecipientsDigest 等价于 ComputeMerkleRoot；调用方应先 SortRecipients。
func ComputeRecipientsDigest(rows [][]string) string {
	return ComputeMerkleRoot(rows)
}
