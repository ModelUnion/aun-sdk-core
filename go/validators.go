package aun

import (
	"fmt"
	"regexp"
	"strings"
)

// AID name 规范：4-64 字符，仅 [a-z0-9_-]，首字符不为 -，不以 guest 开头
var aidNameRE = regexp.MustCompile(`^[a-z0-9_][a-z0-9_-]{3,63}$`)

// Group ID 格式（基于服务端实际实现）
// Legacy 格式：g- 后接 4-32 位小写字母数字
var groupIDLegacyPattern = regexp.MustCompile(`^g-[a-z0-9]{4,32}$`)

// 新格式 base：5 到 64 位小写字母数字
var groupIDNewBasePattern = regexp.MustCompile(`^[a-z0-9]{5,64}$`)

// Group name 格式：4-64 字符，首字符 [a-z0-9]，可包含 _-
var groupNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{3,63}$`)

// 域名基本格式（简化版，不做完整 DNS 校验）
var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// ValidateAIDFormat 校验 AID 格式是否合法。
//
// 格式规范：{name}.{issuer}
//   - name: 4-64 字节，仅 [a-z0-9_-]，首字符不能是 -，不能以 guest 开头
//   - issuer: 合法的可注册域名
//
// 参数：
//   - aid: 待校验的 AID
//   - paramName: 参数名称（用于错误消息）
//
// 返回：
//   - 规范化后的 AID（转小写、去空格）
//   - 错误（如果格式不合法）
func ValidateAIDFormat(aid any, paramName string) (string, error) {
	if paramName == "" {
		paramName = "aid"
	}

	if aid == nil {
		return "", NewValidationError(fmt.Sprintf("%s cannot be empty", paramName))
	}

	aidStr := strings.ToLower(strings.TrimSpace(fmt.Sprint(aid)))
	if aidStr == "" {
		return "", NewValidationError(fmt.Sprintf("%s cannot be empty", paramName))
	}

	// 检查是否包含点号（必须有 issuer）
	if !strings.Contains(aidStr, ".") {
		return "", NewValidationError(
			fmt.Sprintf("Invalid %s '%v': must be in format '{name}.{issuer}'", paramName, aid),
		)
	}

	// 分离 name 和 issuer
	parts := strings.SplitN(aidStr, ".", 2)
	if len(parts) != 2 {
		return "", NewValidationError(
			fmt.Sprintf("Invalid %s '%v': must be in format '{name}.{issuer}'", paramName, aid),
		)
	}

	name, issuer := parts[0], parts[1]

	// 校验 name 部分
	if name == "" {
		return "", NewValidationError(fmt.Sprintf("Invalid %s '%v': name part cannot be empty", paramName, aid))
	}

	if !aidNameRE.MatchString(name) {
		return "", NewValidationError(
			fmt.Sprintf("Invalid %s '%v': name '%s' must be 4-64 characters, only [a-z0-9_-], cannot start with '-'", paramName, aid, name),
		)
	}

	if strings.HasPrefix(name, "guest") {
		return "", NewValidationError(
			fmt.Sprintf("Invalid %s '%v': name cannot start with 'guest'", paramName, aid),
		)
	}

	// 校验 issuer 部分
	if issuer == "" {
		return "", NewValidationError(fmt.Sprintf("Invalid %s '%v': issuer part cannot be empty", paramName, aid))
	}

	if !domainRE.MatchString(issuer) {
		return "", NewValidationError(
			fmt.Sprintf("Invalid %s '%v': issuer '%s' is not a valid domain", paramName, aid, issuer),
		)
	}

	return aidStr, nil
}

func validateGroupAIDParts(raw any, groupAID string, paramName string) error {
	var base, domain string
	if dot := strings.Index(groupAID, "."); dot >= 0 {
		base = strings.Trim(groupAID[:dot], ".")
		domain = strings.Trim(groupAID[dot+1:], ".")
	} else {
		base = groupAID
	}

	if base == "" {
		return NewValidationError(fmt.Sprintf("Invalid %s '%v': base part cannot be empty", paramName, raw))
	}

	isValidBase := groupIDLegacyPattern.MatchString(base) ||
		groupIDNewBasePattern.MatchString(base) ||
		groupNamePattern.MatchString(base)

	if !isValidBase {
		return NewValidationError(
			fmt.Sprintf("Invalid %s '%v': base '%s' must be one of: legacy format 'g-[a-z0-9]{4,32}', new format '[a-z0-9]{5,64}', or group name format '[a-z0-9][a-z0-9_-]{3,63}'", paramName, raw, base),
		)
	}

	if domain != "" && !domainRE.MatchString(domain) {
		return NewValidationError(
			fmt.Sprintf("Invalid %s '%v': domain '%s' is not a valid domain", paramName, raw, domain),
		)
	}

	return nil
}

// ValidateGroupAIDFormat 校验群组标识并返回目标态 group_aid。
func ValidateGroupAIDFormat(groupAID any, paramName string, localIssuer string) (string, error) {
	if paramName == "" {
		paramName = "group_aid"
	}

	if groupAID == nil {
		return "", NewValidationError(fmt.Sprintf("%s cannot be empty", paramName))
	}

	rawText := strings.TrimSpace(fmt.Sprint(groupAID))
	if strings.Contains(rawText, "//") {
		return "", NewValidationError(fmt.Sprintf("Invalid %s '%v': empty path segment is not allowed", paramName, groupAID))
	}

	groupAIDStr := ConvertToGroupAID(rawText, localIssuer)
	if groupAIDStr == "" {
		return "", NewValidationError(fmt.Sprintf("%s cannot be empty", paramName))
	}

	if err := validateGroupAIDParts(groupAID, groupAIDStr, paramName); err != nil {
		return "", err
	}

	return groupAIDStr, nil
}

// ValidateGroupIDFormat 校验 Group ID 格式是否合法。
//
// 接受的 base 格式（不含域名部分）：
//  1. Legacy 格式：g-[a-z0-9]{4,32} — 以 g- 开头，后接 4 到 32 位小写字母或数字
//  2. 新格式：[a-z0-9]{5,64} — 5 到 64 位小写字母或数字
//  3. Group name 格式：[a-z0-9][a-z0-9_-]{3,63} — 4 到 64 个字符，可包含 _-
//
// 完整格式：
//   - group.{issuer}/{base} (canonical)
//   - {base}.{issuer} (旧格式)
//   - {base}@{issuer} (兼容格式)
//   - {base} (本域简写)
//
// 参数：
//   - groupID: 待校验的 Group ID
//   - paramName: 参数名称（用于错误消息）
//
// 返回：
//   - 规范化后的 Group ID（转小写、去空格）
//   - 错误（如果格式不合法）
func ValidateGroupIDFormat(groupID any, paramName string) (string, error) {
	if paramName == "" {
		paramName = "group_id"
	}

	return ValidateGroupAIDFormat(groupID, paramName, "")
}
