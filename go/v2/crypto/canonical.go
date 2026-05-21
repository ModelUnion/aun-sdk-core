// Package crypto provides cryptographic utilities for the AUN SDK v2,
// including canonical JSON serialization for E2EE protocol compliance.
package crypto

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// CanonicalJSON 将任意值序列化为 canonical JSON 字节序列。
// 规则：键递归字典序排序、UTF-8 直出、紧凑格式、最小转义。
// 输入值应通过 json.Decoder + UseNumber() 解析，以保留整数精度。
func CanonicalJSON(v any) []byte {
	var buf strings.Builder
	writeValue(&buf, v)
	return []byte(buf.String())
}

func writeValue(buf *strings.Builder, v any) {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(val.String())
	case float64:
		// 不应出现（使用 UseNumber 解析），但作为兜底
		// 对齐 Python：整数值保留 ".0"，非整数用定点（不用科学计数法）
		if val == float64(int64(val)) && val >= -1e15 && val <= 1e15 {
			buf.WriteString(fmt.Sprintf("%.1f", val))
		} else {
			s := fmt.Sprintf("%.20f", val)
			s = strings.TrimRight(s, "0")
			if s[len(s)-1] == '.' {
				s += "0"
			}
			buf.WriteString(s)
		}
	case string:
		writeString(buf, val)
	case []any:
		writeArray(buf, val)
	case map[string]any:
		writeObject(buf, val)
	default:
		// 未知类型，尝试用 json.Marshal 兜底
		b, _ := json.Marshal(val)
		buf.Write(b)
	}
}

func writeString(buf *strings.Builder, s string) {
	buf.WriteByte('"')
	for i := 0; i < len(s); {
		b := s[i]
		switch {
		case b == '"':
			buf.WriteString(`\"`)
			i++
		case b == '\\':
			buf.WriteString(`\\`)
			i++
		case b == '\b':
			buf.WriteString(`\b`)
			i++
		case b == '\f':
			buf.WriteString(`\f`)
			i++
		case b == '\n':
			buf.WriteString(`\n`)
			i++
		case b == '\r':
			buf.WriteString(`\r`)
			i++
		case b == '\t':
			buf.WriteString(`\t`)
			i++
		case b < 0x20:
			// 其它控制字符用 \u00XX
			buf.WriteString(fmt.Sprintf(`\u%04x`, b))
			i++
		default:
			// UTF-8 直出（非 ASCII 不转义）
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size == 1 {
				// 无效 UTF-8 字节，用 \u 转义
				buf.WriteString(fmt.Sprintf(`\u%04x`, b))
				i++
			} else {
				buf.WriteString(s[i : i+size])
				i += size
			}
		}
	}
	buf.WriteByte('"')
}

func writeArray(buf *strings.Builder, arr []any) {
	buf.WriteByte('[')
	for i, item := range arr {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeValue(buf, item)
	}
	buf.WriteByte(']')
}

func writeObject(buf *strings.Builder, obj map[string]any) {
	// 键递归字典序排序
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeString(buf, k)
		buf.WriteByte(':')
		writeValue(buf, obj[k])
	}
	buf.WriteByte('}')
}
