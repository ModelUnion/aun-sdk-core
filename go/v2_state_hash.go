package aun

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MemberRole represents a member's AID and role for state hash computation.
type MemberRole struct {
	AID  string `json:"aid"`
	Role string `json:"role"`
}

// ComputeStateHash computes the group state hash binding members, roles, policy, and the previous state hash.
func ComputeStateHash(groupID string, stateVersion, keyEpoch int64, members []MemberRole, policy map[string]interface{}, prevStateHash string) string {
	sorted := make([]MemberRole, len(members))
	copy(sorted, members)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].AID < sorted[j].AID })

	parts := make([]string, len(sorted))
	for i, m := range sorted {
		parts[i] = m.AID + ":" + m.Role
	}
	membershipBlock := strings.Join(parts, "|")

	policyBlock := ""
	if len(policy) > 0 {
		b, _ := json.Marshal(policy)
		policyBlock = string(b)
	}

	var prevBytes [32]byte
	if prevStateHash != "" {
		decoded, _ := hex.DecodeString(prevStateHash)
		copy(prevBytes[:], decoded)
	}

	var buf bytes.Buffer
	buf.WriteString(groupID)
	buf.WriteByte(0)
	_ = binary.Write(&buf, binary.BigEndian, stateVersion)
	buf.WriteByte(0)
	_ = binary.Write(&buf, binary.BigEndian, keyEpoch)
	buf.WriteByte(0)
	buf.WriteString(membershipBlock)
	buf.WriteByte(0)
	buf.WriteString(policyBlock)
	buf.WriteByte(0)
	buf.Write(prevBytes[:])

	h := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(h[:])
}
