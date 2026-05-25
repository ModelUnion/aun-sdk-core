// Package crypto provides cryptographic utilities for the AUN SDK v2,
// including canonical JSON serialization for E2EE protocol compliance.
package crypto

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxSafeJSONInteger = 9007199254740991

// CanonicalJSON 将任意值序列化为 canonical JSON 字节序列。
// 规则：键递归按 Unicode code point 排序、UTF-8 直出、紧凑格式、最小转义。
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
		buf.WriteString(formatJSONNumber(val))
	case float64:
		buf.WriteString(formatFloat(val))
	case float32:
		buf.WriteString(formatFloat(float64(val)))
	case int:
		buf.WriteString(formatInt(int64(val)))
	case int8:
		buf.WriteString(formatInt(int64(val)))
	case int16:
		buf.WriteString(formatInt(int64(val)))
	case int32:
		buf.WriteString(formatInt(int64(val)))
	case int64:
		buf.WriteString(formatInt(val))
	case uint:
		buf.WriteString(formatUint(uint64(val)))
	case uint8:
		buf.WriteString(formatUint(uint64(val)))
	case uint16:
		buf.WriteString(formatUint(uint64(val)))
	case uint32:
		buf.WriteString(formatUint(uint64(val)))
	case uint64:
		buf.WriteString(formatUint(val))
	case string:
		writeString(buf, val)
	case []any:
		writeArray(buf, val)
	case map[string]any:
		writeObject(buf, val)
	default:
		writeReflectValue(buf, reflect.ValueOf(v))
	}
}

func formatJSONNumber(n json.Number) string {
	s := n.String()
	if strings.ContainsAny(s, ".eE") {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			panic(fmt.Errorf("canonical_json: invalid number %s", s))
		}
		return formatFloat(f)
	}
	i, err := strconv.ParseInt(s, 10, 64)
	if err == nil {
		return formatInt(i)
	}
	u, err := strconv.ParseUint(s, 10, 64)
	if err == nil {
		return formatUint(u)
	}
	panic(fmt.Errorf("canonical_json: invalid number %s", s))
}

func formatInt(n int64) string {
	if n < -maxSafeJSONInteger || n > maxSafeJSONInteger {
		panic(fmt.Errorf("canonical_json: integer outside safe range %d", n))
	}
	return strconv.FormatInt(n, 10)
}

func formatUint(n uint64) string {
	if n > maxSafeJSONInteger {
		panic(fmt.Errorf("canonical_json: integer outside safe range %d", n))
	}
	return strconv.FormatUint(n, 10)
}

func formatFloat(f float64) string {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		panic(fmt.Errorf("canonical_json: Infinity and NaN not allowed"))
	}
	if f == 0 {
		return "0"
	}
	if math.Trunc(f) == f {
		if math.Abs(f) > maxSafeJSONInteger {
			panic(fmt.Errorf("canonical_json: integer outside safe range %.0f", f))
		}
		return strconv.FormatInt(int64(f), 10)
	}
	return expandExponent(strconv.FormatFloat(f, 'g', -1, 64))
}

func expandExponent(s string) string {
	epos := strings.IndexAny(s, "eE")
	if epos < 0 {
		return s
	}
	mantissa := s[:epos]
	exp, err := strconv.Atoi(s[epos+1:])
	if err != nil {
		panic(fmt.Errorf("canonical_json: invalid number %s", s))
	}
	sign := ""
	if strings.HasPrefix(mantissa, "-") {
		sign = "-"
		mantissa = mantissa[1:]
	}
	intPart := mantissa
	fracPart := ""
	if dot := strings.IndexByte(mantissa, '.'); dot >= 0 {
		intPart = mantissa[:dot]
		fracPart = mantissa[dot+1:]
	}
	digits := intPart + fracPart
	point := len(intPart) + exp
	switch {
	case point <= 0:
		return sign + "0." + strings.Repeat("0", -point) + digits
	case point >= len(digits):
		return sign + digits + strings.Repeat("0", point-len(digits))
	default:
		return sign + digits[:point] + "." + digits[point:]
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
	// 键递归按 Unicode code point 排序
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return compareCodePoints(keys[i], keys[j]) < 0
	})

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

func compareCodePoints(a, b string) int {
	ar := []rune(a)
	br := []rune(b)
	n := len(ar)
	if len(br) < n {
		n = len(br)
	}
	for i := 0; i < n; i++ {
		if ar[i] < br[i] {
			return -1
		}
		if ar[i] > br[i] {
			return 1
		}
	}
	switch {
	case len(ar) < len(br):
		return -1
	case len(ar) > len(br):
		return 1
	default:
		return 0
	}
}

func writeReflectValue(buf *strings.Builder, rv reflect.Value) {
	if !rv.IsValid() {
		buf.WriteString("null")
		return
	}
	if rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			buf.WriteString("null")
			return
		}
		writeReflectValue(buf, rv.Elem())
		return
	}
	switch rv.Kind() {
	case reflect.Bool:
		if rv.Bool() {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case reflect.String:
		writeString(buf, rv.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		buf.WriteString(formatInt(rv.Int()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		buf.WriteString(formatUint(rv.Uint()))
	case reflect.Float32, reflect.Float64:
		buf.WriteString(formatFloat(rv.Float()))
	case reflect.Slice, reflect.Array:
		buf.WriteByte('[')
		for i := 0; i < rv.Len(); i++ {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeReflectValue(buf, rv.Index(i))
		}
		buf.WriteByte(']')
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			panic(fmt.Errorf("canonical_json: map key must be string"))
		}
		keys := make([]string, 0, rv.Len())
		for _, key := range rv.MapKeys() {
			keys = append(keys, key.String())
		}
		sort.Slice(keys, func(i, j int) bool {
			return compareCodePoints(keys[i], keys[j]) < 0
		})
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, key)
			buf.WriteByte(':')
			writeReflectValue(buf, rv.MapIndex(reflect.ValueOf(key)))
		}
		buf.WriteByte('}')
	default:
		panic(fmt.Errorf("canonical_json: unsupported type %s", rv.Type()))
	}
}
