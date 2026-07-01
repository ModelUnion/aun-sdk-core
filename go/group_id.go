// group_id/group_aid 兼容转换工具。
//
// 目标态群组主标识是 group_aid，格式为 {base}.{issuer}。
// 历史 group_id 字段名继续保留，但旧函数名也返回 group_aid。

package aun

import "strings"

func trimDots(s string) string {
	return strings.Trim(s, ".")
}

// ConvertToGroupAID 将任意历史群标识转换为标准 group_aid。
func ConvertToGroupAID(raw string, localIssuer string) string {
	value := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "/"))
	if value == "" {
		return ""
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
			return value
		}
		return value
	}

	if at := strings.Index(value, "@"); at > 0 {
		base := trimDots(value[:at])
		domain := trimDots(value[at+1:])
		if base != "" && domain != "" {
			return base + "." + domain
		}
		return value
	}

	if strings.Contains(value, ".") {
		return value
	}
	issuer := strings.ToLower(trimDots(strings.TrimSpace(localIssuer)))
	if issuer != "" {
		return value + "." + issuer
	}
	return value
}

// NormalizeGroupID 是旧函数名兼容包装；目标态返回 group_aid。
func NormalizeGroupID(raw string, localIssuer string) string {
	return ConvertToGroupAID(raw, localIssuer)
}

func groupAIDOrRaw(raw string) string {
	value := strings.TrimSpace(raw)
	normalized := ConvertToGroupAID(value, "")
	if normalized != "" {
		return normalized
	}
	return value
}

func groupIdentifierPairFromParams(params map[string]any) (string, string) {
	if params == nil {
		return "", ""
	}
	wireGroupID := strings.TrimSpace(stringFromAny(params["group_id"]))
	groupAID := strings.TrimSpace(stringFromAny(params["group_aid"]))
	if groupAID == "" {
		groupAID = groupAIDOrRaw(wireGroupID)
	}
	if wireGroupID == "" {
		wireGroupID = groupAID
	}
	return wireGroupID, groupAID
}

// SplitGroupID 返回 (base, issuer)。对旧格式输入也先转换为 group_aid。
func SplitGroupID(raw string) (string, string) {
	groupAID := ConvertToGroupAID(raw, "")
	if dot := strings.Index(groupAID, "."); dot > 0 {
		return trimDots(groupAID[:dot]), trimDots(groupAID[dot+1:])
	}
	return trimDots(groupAID), ""
}

// BuildDiscoveryHost 构造 federation 发现 host。群服务发现走 issuer 域。
func BuildDiscoveryHost(raw string) string {
	_, domain := SplitGroupID(raw)
	return domain
}
