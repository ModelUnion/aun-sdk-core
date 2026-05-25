package e2ee

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// goldenEnvelopeRoot 指向 golden 向量目录。
//
// 使用 testdata/ 子目录（Go 标准约定），确保容器内也能访问。
const goldenEnvelopeRoot = "testdata/golden/envelope"

// runInteropTest 加载指定向量文件，按 inputsKey 选取 decryption_inputs，
// 调 DecryptMessage 后与 expected_payload 比对。
//
// inputsKey: 单接收方为 "decryption_inputs"，多接收方为
// "decryption_inputs_<who>"（如 "decryption_inputs_bob"）。
func runInteropTest(t *testing.T, fileName, inputsKey string) {
	t.Helper()

	path := filepath.Join(goldenEnvelopeRoot, fileName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取向量文件失败: %v", err)
	}

	// 用 UseNumber 解析整个向量，避免数字类型从 int 变 float64 导致 canonical_aad 不一致
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var fileObj map[string]any
	if err := dec.Decode(&fileObj); err != nil {
		t.Fatalf("解析 JSON 失败: %v", err)
	}

	envelope, ok := fileObj["envelope"].(map[string]any)
	if !ok {
		t.Fatalf("envelope 字段缺失或类型错误")
	}

	inputs, ok := fileObj[inputsKey].(map[string]any)
	if !ok {
		t.Fatalf("缺少 %s 字段", inputsKey)
	}

	selfAID, _ := inputs["self_aid"].(string)
	selfDeviceID, _ := inputs["self_device_id"].(string)

	selfIKPriv, err := decodeB64Field(inputs, "self_ik_priv_b64")
	if err != nil {
		t.Fatalf("self_ik_priv_b64 解析失败: %v", err)
	}
	selfSPKPriv, err := decodeB64FieldOptional(inputs, "self_spk_priv_b64")
	if err != nil {
		t.Fatalf("self_spk_priv_b64 解析失败: %v", err)
	}
	senderPubDER, err := decodeB64Field(inputs, "sender_pub_der_b64")
	if err != nil {
		t.Fatalf("sender_pub_der_b64 解析失败: %v", err)
	}

	expected, ok := fileObj["expected_payload"].(map[string]any)
	if !ok {
		t.Fatalf("expected_payload 字段缺失或类型错误")
	}

	got, err := DecryptMessage(envelope, selfAID, selfDeviceID, selfIKPriv, selfSPKPriv, senderPubDER)
	if err != nil {
		t.Fatalf("DecryptMessage 失败: %v", err)
	}
	if got == nil {
		t.Fatalf("DecryptMessage 返回 nil（找不到自己的 row）")
	}

	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("payload 不一致\n期望: %#v\n实际: %#v", expected, got)
	}
}

// decodeB64Field 将 inputs[key] 视为 base64 字符串解码。
func decodeB64Field(inputs map[string]any, key string) ([]byte, error) {
	s, _ := inputs[key].(string)
	return base64.StdEncoding.DecodeString(s)
}

// decodeB64FieldOptional 兼容值为 null（解析后 nil）的字段，返回 nil。
func decodeB64FieldOptional(inputs map[string]any, key string) ([]byte, error) {
	v, ok := inputs[key]
	if !ok || v == nil {
		return nil, nil
	}
	s, isStr := v.(string)
	if !isStr || s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// 6 个互通测试用例（4 个文件 + 2 个多接收方扩展）。

func TestDecryptInteropP2P3DH(t *testing.T) {
	runInteropTest(t, "p2p_3dh.json", "decryption_inputs")
}

func TestDecryptInteropP2P1DH(t *testing.T) {
	runInteropTest(t, "p2p_1dh.json", "decryption_inputs")
}

func TestDecryptInteropP2PMultiBob(t *testing.T) {
	runInteropTest(t, "p2p_multi.json", "decryption_inputs_bob")
}

func TestDecryptInteropP2PMultiAlice2(t *testing.T) {
	runInteropTest(t, "p2p_multi.json", "decryption_inputs_alice2")
}

func TestDecryptInteropGroupBob(t *testing.T) {
	runInteropTest(t, "group_3dh_1dh.json", "decryption_inputs_bob")
}

func TestDecryptInteropGroupCarol(t *testing.T) {
	runInteropTest(t, "group_3dh_1dh.json", "decryption_inputs_carol")
}

func TestDecryptWrongSPKReportsWrapKeyDecryptFailed(t *testing.T) {
	path := filepath.Join(goldenEnvelopeRoot, "group_3dh_1dh.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取向量文件失败: %v", err)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var fileObj map[string]any
	if err := dec.Decode(&fileObj); err != nil {
		t.Fatalf("解析 JSON 失败: %v", err)
	}
	envelope, ok := fileObj["envelope"].(map[string]any)
	if !ok {
		t.Fatalf("envelope 字段缺失或类型错误")
	}
	inputs, ok := fileObj["decryption_inputs_bob"].(map[string]any)
	if !ok {
		t.Fatalf("缺少 decryption_inputs_bob 字段")
	}
	selfAID, _ := inputs["self_aid"].(string)
	selfDeviceID, _ := inputs["self_device_id"].(string)
	selfIKPriv, err := decodeB64Field(inputs, "self_ik_priv_b64")
	if err != nil {
		t.Fatalf("self_ik_priv_b64 解析失败: %v", err)
	}
	senderPubDER, err := decodeB64Field(inputs, "sender_pub_der_b64")
	if err != nil {
		t.Fatalf("sender_pub_der_b64 解析失败: %v", err)
	}

	_, err = DecryptMessage(envelope, selfAID, selfDeviceID, selfIKPriv, selfIKPriv, senderPubDER)
	if err == nil {
		t.Fatalf("错误 SPK 应返回解密错误")
	}
	errText := err.Error()
	if !strings.Contains(errText, "wrap_key_decrypt_failed") ||
		!strings.Contains(errText, "key_source=group_device_prekey") ||
		!strings.Contains(errText, "spk_id=") {
		t.Fatalf("错误 SPK 应返回精确 wrap 错误，实际: %v", err)
	}
}

func TestPerDeviceMerkleProofMismatchReturnsNil(t *testing.T) {
	envelope := map[string]any{
		"ciphertext":        "",
		"tag":               "",
		"sender_signature":  "",
		"recipients_digest": "00",
		"recipient": map[string]any{
			"aid":         "bob.example.com",
			"device_id":   "dev-bob",
			"role":        "peer",
			"key_source":  "peer_device_prekey",
			"fp":          "sha256:deadbeef",
			"spk_id":      "spk-1",
			"wrap_nonce":  "AA==",
			"wrapped_key": "AA==",
		},
		"merkle_proof": []any{map[string]any{"sibling": "not-hex", "position": "R"}},
	}
	row, err := locateRecipientRow(envelope, "bob.example.com", "dev-bob")
	if err != nil {
		t.Fatalf("per-device merkle proof 无效时应返回 nil, nil 对齐 Python，got err=%v", err)
	}
	if row != nil {
		t.Fatalf("per-device merkle proof 无效时不应返回 recipient row: %#v", row)
	}
}
