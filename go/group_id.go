// group_id 归一化工具。
//
// AUN 协议规定的 canonical 格式为 `group.{domain}/{base}`。
//
// 历史上出现过四种老/脏格式：
//   1. {base}.{domain}            例如 g-xxx.agentid.pub / 10086.agentid.pub
//   2. g-{slug}.{domain}          （属于 1 的一种）
//   3. {base}@{domain}            例如 g-xxx@agentid.pub
//   4. group.{A}/{base}@{B}       旧版服务端迁移脚本未识别 @ 导致的污染数据
//                                 真实语义：group.{B}.{A}/{base}
//
// 与 Python/TS/JS SDK 保持等价，零代码共享。

package aun

import (
	"strings"
)

func trimDots(s string) string {
	return strings.Trim(s, ".")
}

// NormalizeGroupID 将任意历史格式的 group_id 归一化为 canonical。
// localIssuer 不为空时，对无域前缀的本域简写补全为 group.{localIssuer}/{base}；
// 为空时原样返回。
func NormalizeGroupID(raw string, localIssuer string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return ""
	}

	// 情况 4：已迁移但 base 位置残留 @issuer 尾巴
	if strings.HasPrefix(value, "group.") && strings.Contains(value, "/") {
		issuerAndBase := value[6:]
		if slash := strings.Index(issuerAndBase, "/"); slash > 0 && slash < len(issuerAndBase)-1 {
			aDomain := trimDots(issuerAndBase[:slash])
			baseTail := issuerAndBase[slash+1:]
			if at := strings.Index(baseTail, "@"); at > 0 {
				base := trimDots(baseTail[:at])
				bDomain := trimDots(baseTail[at+1:])
				if base != "" && bDomain != "" {
					merged := bDomain
					if aDomain != "" {
						merged = bDomain + "." + aDomain
					}
					return "group." + merged + "/" + base
				}
			}
			if aDomain != "" {
				return "group." + aDomain + "/" + trimDots(baseTail)
			}
			return value
		}
		return value
	}

	// 情况 3：base@domain / g-{slug}@domain
	if at := strings.Index(value, "@"); at > 0 {
		base := trimDots(value[:at])
		domain := trimDots(value[at+1:])
		if base != "" && domain != "" {
			return "group." + domain + "/" + base
		}
		return value
	}

	issuer := strings.ToLower(trimDots(strings.TrimSpace(localIssuer)))

	// 情况 1/2：base.domain / g-{slug}.domain
	if strings.HasPrefix(value, "g-") {
		rest := value[2:]
		if dot := strings.Index(rest, "."); dot > 0 {
			slug := rest[:dot]
			domain := trimDots(rest[dot+1:])
			if slug != "" && domain != "" {
				return "group." + domain + "/g-" + slug
			}
		}
		if issuer != "" {
			return "group." + issuer + "/g-" + rest
		}
		return value
	}
	if dot := strings.Index(value, "."); dot > 0 {
		base := value[:dot]
		domain := trimDots(value[dot+1:])
		if base != "" && domain != "" {
			return "group." + domain + "/" + base
		}
	}
	if issuer != "" {
		return "group." + issuer + "/" + value
	}
	return value
}

// SplitGroupID 返回 (base, domain)。对污染格式也能还原出正确的 (base, domain)。
func SplitGroupID(raw string) (string, string) {
	canonical := NormalizeGroupID(raw, "")
	if strings.HasPrefix(canonical, "group.") && strings.Contains(canonical, "/") {
		issuerAndBase := canonical[6:]
		slash := strings.Index(issuerAndBase, "/")
		domain := trimDots(issuerAndBase[:slash])
		base := trimDots(issuerAndBase[slash+1:])
		return base, domain
	}
	return trimDots(canonical), ""
}

// BuildDiscoveryHost 构造 federation 发现 host：{base}.{domain}。
func BuildDiscoveryHost(raw string) string {
	base, domain := SplitGroupID(raw)
	if base == "" || domain == "" {
		return ""
	}
	return base + "." + domain
}
