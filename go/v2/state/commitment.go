// Package state 提供 AUN E2EE V2 群状态承诺（state_commitment）计算。
//
// 规范引用 §6.2：
//
//	state_commitment = SHA256(
//	  "AUN-V2-SC-v1" ||
//	  group_aid ||
//	  uint32_BE(epoch) ||
//	  canonical_json(payload)
//	)
//
// payload 在序列化前需要内部规范化排序：
//   - members 按 aid 升序，每个 member 的 devices 按 device_id 升序
//   - audit_aids 升序
//   - admin_set.admin_aids 升序
//   - recovery_quorum.quorum_aids 升序
//
// 调用方不需要预排序，函数内部完成深拷贝 + 排序，避免修改原数据。
package state

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/modelunion/aun-sdk-core/go/v2/crypto"
)

// Prefix state_commitment 域分隔前缀
const Prefix = "AUN-V2-SC-v1"

// ComputeStateCommitment 计算群 state_commitment（hex 字符串）。
//
// statePayload 通常包含字段：members / audit_aids / join_policy_hash /
// admin_set / recovery_quorum / history_policy / wrap_protocol。
//
// 函数内部对 payload 做深拷贝并排序，输入数据不会被修改。
func ComputeStateCommitment(groupID string, epoch uint32, statePayload map[string]any) string {
	payload := deepCopyAny(statePayload).(map[string]any)
	sortPayload(payload)
	groupKey := normalizeGroupKey(groupID)

	var epochBytes [4]byte
	binary.BigEndian.PutUint32(epochBytes[:], epoch)

	canonical := crypto.CanonicalJSON(payload)

	h := sha256.New()
	h.Write([]byte(Prefix))
	h.Write([]byte(groupKey))
	h.Write(epochBytes[:])
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil))
}

func normalizeGroupKey(groupID string) string {
	value := strings.ToLower(strings.Trim(strings.TrimSpace(groupID), "/"))
	if value == "" {
		return ""
	}
	trimDots := func(s string) string {
		return strings.Trim(s, ".")
	}
	if strings.HasPrefix(value, "group.") && strings.Contains(value, "/") {
		issuerAndBase := value[6:]
		if slash := strings.Index(issuerAndBase, "/"); slash > 0 && slash < len(issuerAndBase)-1 {
			domain := trimDots(issuerAndBase[:slash])
			baseTail := strings.Trim(issuerAndBase[slash+1:], "/")
			if at := strings.Index(baseTail, "@"); at > 0 {
				base := trimDots(baseTail[:at])
				suffixDomain := trimDots(baseTail[at+1:])
				if base != "" && suffixDomain != "" {
					merged := suffixDomain
					if domain != "" {
						merged = suffixDomain + "." + domain
					}
					return base + "." + merged
				}
			}
			base := trimDots(baseTail)
			if base != "" && domain != "" {
				return base + "." + domain
			}
		}
		return value
	}
	if at := strings.Index(value, "@"); at > 0 {
		base := trimDots(value[:at])
		domain := trimDots(value[at+1:])
		if base != "" && domain != "" {
			return base + "." + domain
		}
	}
	return value
}

// sortPayload 在原 map 上递归排序需要规范化的字段。
func sortPayload(payload map[string]any) {
	if members, ok := payload["members"].([]any); ok {
		sort.SliceStable(members, func(i, j int) bool {
			return memberAID(members[i]) < memberAID(members[j])
		})
		for _, m := range members {
			memberMap, ok := m.(map[string]any)
			if !ok {
				continue
			}
			if devices, ok := memberMap["devices"].([]any); ok {
				sort.SliceStable(devices, func(i, j int) bool {
					return deviceID(devices[i]) < deviceID(devices[j])
				})
			}
		}
	}

	sortStringList(payload, "audit_aids")

	if adminSet, ok := payload["admin_set"].(map[string]any); ok {
		sortStringList(adminSet, "admin_aids")
	}

	if quorum, ok := payload["recovery_quorum"].(map[string]any); ok {
		sortStringList(quorum, "quorum_aids")
	}
}

func memberAID(v any) string {
	if m, ok := v.(map[string]any); ok {
		if s, ok := m["aid"].(string); ok {
			return s
		}
	}
	return ""
}

func deviceID(v any) string {
	if m, ok := v.(map[string]any); ok {
		if s, ok := m["device_id"].(string); ok {
			return s
		}
	}
	return ""
}

func sortStringList(parent map[string]any, key string) {
	list, ok := parent[key].([]any)
	if !ok {
		return
	}
	sort.SliceStable(list, func(i, j int) bool {
		si, _ := list[i].(string)
		sj, _ := list[j].(string)
		return si < sj
	})
}

// deepCopyAny 对任意（JSON 解析得到的）值做深拷贝，避免排序修改调用方数据。
func deepCopyAny(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = deepCopyAny(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = deepCopyAny(item)
		}
		return out
	default:
		// 基础值（string/bool/json.Number/float64/nil）按值复制即可
		return v
	}
}
