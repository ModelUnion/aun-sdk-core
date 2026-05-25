package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCanonicalControlChar 单独测试控制字符转义（golden 文件含原始控制字符，
// 标准 JSON 解析器无法处理，因此用代码构造测试向量）。
func TestCanonicalControlChar(t *testing.T) {
	// 输入: 字符串 "a" + U+0001 + "b"
	input := string([]byte{'a', 0x01, 'b'})
	// 期望: base64("\"a\\u0001b\"") = "ImFcdTAwMDFiIg=="
	expectedB64 := "ImFcdTAwMDFiIg=="
	expected, _ := base64.StdEncoding.DecodeString(expectedB64)
	got := CanonicalJSON(input)
	if !bytes.Equal(got, expected) {
		t.Errorf("控制字符转义不一致\n  期望: %q\n  实际: %q", expected, got)
	}
}

// TestCanonicalGolden 加载 golden 向量文件，验证 CanonicalJSON 输出字节一致性。
func TestCanonicalGolden(t *testing.T) {
	goldenDir := filepath.Join("testdata", "golden", "canonical")
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("无法读取 golden 目录: %v", err)
	}

	count := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			// string_escape_control.json 含原始控制字符，Go JSON 解析器无法处理，
			// 已在 TestCanonicalControlChar 中用代码构造测试
			if name == "string_escape_control.json" {
				t.Skip("控制字符用例由 TestCanonicalControlChar 覆盖")
			}

			path := filepath.Join(goldenDir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("读取文件失败: %v", err)
			}

			// 用 Decoder + UseNumber 解析整个文件
			dec := json.NewDecoder(bytes.NewReader(data))
			dec.UseNumber()

			var fileObj map[string]any
			if err := dec.Decode(&fileObj); err != nil {
				t.Fatalf("解析 JSON 失败: %v", err)
			}

			input := fileObj["input"]
			expectedB64, ok := fileObj["expected_output_b64"].(string)
			if !ok {
				t.Fatalf("expected_output_b64 字段缺失或类型错误")
			}

			expected, err := base64.StdEncoding.DecodeString(expectedB64)
			if err != nil {
				t.Fatalf("base64 解码失败: %v", err)
			}

			got := CanonicalJSON(input)
			if !bytes.Equal(got, expected) {
				t.Errorf("字节不一致\n  期望: %s\n  实际: %s", string(expected), string(got))
			}
		})
		count++
	}

	if count == 0 {
		t.Fatal("未找到任何 golden 向量文件")
	}
	t.Logf("共测试 %d 个 golden 向量", count)
}

func TestCanonicalNumberNormalization(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"float_integer", 1.0, "1"},
		{"small_exponent", 1e-7, "0.0000001"},
		{"negative_zero", math.Copysign(0, -1), "0"},
		{"json_number_fraction", json.Number("1.2300"), "1.23"},
		{"json_number_exponent", json.Number("1e-7"), "0.0000001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(CanonicalJSON(tc.in)); got != tc.want {
				t.Fatalf("期望 %q，实际 %q", tc.want, got)
			}
		})
	}
}

func TestCanonicalRejectsUnsafeNumbers(t *testing.T) {
	cases := []any{
		int64(9007199254740992),
		uint64(9007199254740992),
		json.Number("9007199254740992"),
		math.NaN(),
		math.Inf(1),
	}
	for _, in := range cases {
		t.Run(fmtAny(in), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("期望 CanonicalJSON 拒绝非法数字: %#v", in)
				}
			}()
			_ = CanonicalJSON(in)
		})
	}
}

func TestCanonicalUnicodeCodePointKeyOrder(t *testing.T) {
	got := string(CanonicalJSON(map[string]any{
		"\U00010000": 1,
		"\uE000":     2,
	}))
	want := "{\"\uE000\":2,\"𐀀\":1}"
	if got != want {
		t.Fatalf("Unicode code point 排序不一致\n期望: %s\n实际: %s", want, got)
	}
}

func fmtAny(v any) string {
	return strings.NewReplacer(" ", "_", "+", "plus", "-", "minus").Replace(jsonSafeString(v))
}

func jsonSafeString(v any) string {
	switch x := v.(type) {
	case json.Number:
		return "json_number_" + x.String()
	case float64:
		if math.IsNaN(x) {
			return "nan"
		}
		if math.IsInf(x, 1) {
			return "inf"
		}
	}
	b, _ := json.Marshal(v)
	return string(b)
}
