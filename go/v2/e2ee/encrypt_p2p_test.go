package e2ee

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/modelunion/aun-sdk-core/go/v2/crypto"
)

// 复用与 conformance 向量一致的固定身份（base64 私钥与公钥 DER）。
const (
	alicePrivB64  = "PpO+iIaSqAFhaqDeqkX+RlMcKfLgvAxlwAxqU8jYBYE=" // 占位，下文从 sender_pub 反推
	alicePubB64   = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDU8HhWlb8vRbPSiisDf/jOfGz72hFuyLcJ/+EGJM4fu6KPzKFPAGPWe+QTjqUKmklvGNk9BlKYnCRYM+hwyT1w=="
	bobPrivB64    = "kucXls+1l1JEL84puz+hIVGNMQpaBu2GVO1FSAC1Gpg="
	bobSPKPrivB64 = "YSJfT/BHTE6J9sDXN495hou7PdjbRqBMLvi46W0NSI4="
)

// 由于 conformance 向量没有暴露 alice 的私钥，roundtrip 测试我们生成一对随机
// keypair 作为 sender；bob 的公钥/SPK 也现场生成，自加密自解密只验证算法正确性。

func makeTestSender(t *testing.T) Sender {
	t.Helper()
	priv, pub, err := crypto.GenerateP256Keypair()
	if err != nil {
		t.Fatalf("生成 sender 密钥失败: %v", err)
	}
	return Sender{
		AID:      "alice.aid.com",
		DeviceID: "dev-alice-1",
		IKPriv:   priv,
		IKPubDER: pub,
	}
}

func makeTestRecipient(t *testing.T, role, keySource string, withSPK bool) (Target, []byte, []byte) {
	t.Helper()
	ikPriv, ikPub, err := crypto.GenerateP256Keypair()
	if err != nil {
		t.Fatalf("生成 IK 失败: %v", err)
	}
	var spkPriv, spkPub []byte
	if withSPK {
		spkPriv, spkPub, err = crypto.GenerateP256Keypair()
		if err != nil {
			t.Fatalf("生成 SPK 失败: %v", err)
		}
	}
	target := Target{
		AID:       "bob.aid.com",
		DeviceID:  "dev-bob-1",
		Role:      role,
		KeySource: keySource,
		IKPkDER:   ikPub,
		SPKPkDER:  spkPub,
		SPKID:     ifThen(withSPK, "sha256:bob_spk_1", ""),
	}
	return target, ikPriv, spkPriv
}

func ifThen(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// TestEncryptP2PRoundtrip3DH Go 加密 → Go 解密 round-trip（3DH 路径）
func TestEncryptP2PRoundtrip3DH(t *testing.T) {
	sender := makeTestSender(t)
	target, ikPriv, spkPriv := makeTestRecipient(t, "peer", "peer_device_prekey", true)
	targetSet := TargetSet{Targets: []Target{target}}

	payload := map[string]any{
		"text": "Hello, Go E2EE V2!",
		"type": "text",
	}

	envelope, err := EncryptP2PMessage(sender, targetSet, payload, EncryptOptions{})
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// 验证 envelope 关键字段
	if envelope["type"] != "e2ee.p2p_encrypted" {
		t.Fatalf("type 字段错误: %v", envelope["type"])
	}
	if envelope["aad"].(map[string]any)["wrap_protocol"] != "3DH" {
		t.Fatalf("wrap_protocol 错误: %v", envelope["aad"])
	}

	// recipients_digest 与重算结果一致
	rows, _ := convertRecipientsToStringMatrix(envelope["recipients"])
	gotDigest := crypto.ComputeMerkleRoot(rows)
	if gotDigest != envelope["recipients_digest"].(string) {
		t.Fatalf("digest 自洽失败: %s vs %s", gotDigest, envelope["recipients_digest"])
	}

	decrypted, err := DecryptMessage(envelope, target.AID, target.DeviceID, ikPriv, spkPriv, sender.IKPubDER)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if !reflect.DeepEqual(decrypted, payload) {
		t.Fatalf("payload 不一致\n期望: %v\n实际: %v", payload, decrypted)
	}
}

// TestEncryptP2PRoundtrip1DH Go 加密 → Go 解密 round-trip（1DH 路径）
func TestEncryptP2PRoundtrip1DH(t *testing.T) {
	sender := makeTestSender(t)
	target, ikPriv, _ := makeTestRecipient(t, "peer", "aid_master", false)
	targetSet := TargetSet{Targets: []Target{target}}

	payload := map[string]any{
		"text": "1DH path test",
	}

	envelope, err := EncryptP2PMessage(sender, targetSet, payload, EncryptOptions{
		MessageID: "m-roundtrip-1dh",
		Timestamp: 1710504000000,
	})
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	if envelope["aad"].(map[string]any)["wrap_protocol"] != "1DH" {
		t.Fatalf("wrap_protocol 错误: %v", envelope["aad"])
	}

	decrypted, err := DecryptMessage(envelope, target.AID, target.DeviceID, ikPriv, nil, sender.IKPubDER)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if !reflect.DeepEqual(decrypted, payload) {
		t.Fatalf("payload 不一致\n期望: %v\n实际: %v", payload, decrypted)
	}
}

func TestEncryptP2PSPKPublicKeyWithoutIDUses1DH(t *testing.T) {
	sender := makeTestSender(t)
	target, ikPriv, _ := makeTestRecipient(t, "peer", "peer_device_prekey", true)
	target.SPKID = ""
	targetSet := TargetSet{Targets: []Target{target}}

	payload := map[string]any{"text": "SPK pub without SPK ID must use IK"}
	envelope, err := EncryptP2PMessage(sender, targetSet, payload, EncryptOptions{})
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if got := envelope["aad"].(map[string]any)["wrap_protocol"]; got != "1DH" {
		t.Fatalf("wrap_protocol 应为 1DH，实际: %v", got)
	}
	rows, err := convertRecipientsToStringMatrix(envelope["recipients"])
	if err != nil {
		t.Fatal(err)
	}
	if rows[0][3] != "aid_master" || rows[0][5] != "" {
		t.Fatalf("1DH row 应写 aid_master/空 spk_id，实际: %v", rows[0])
	}
	decrypted, err := DecryptMessage(envelope, target.AID, target.DeviceID, ikPriv, nil, sender.IKPubDER)
	if err != nil {
		t.Fatalf("1DH 解密失败: %v", err)
	}
	if !reflect.DeepEqual(decrypted, payload) {
		t.Fatalf("payload 不一致\n期望: %v\n实际: %v", payload, decrypted)
	}
}

func TestEncryptP2PPayloadTypeTopLevel(t *testing.T) {
	sender := makeTestSender(t)
	target, ikPriv, _ := makeTestRecipient(t, "peer", "aid_master", false)
	payload := map[string]any{"type": "text", "text": "visible type"}

	envelope, err := EncryptP2PMessage(sender, TargetSet{Targets: []Target{target}}, payload, EncryptOptions{})
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if got := envelope["payload_type"]; got != "text" {
		t.Fatalf("payload_type 应在信封顶层透传，实际: %#v", got)
	}
	headers, ok := envelope["protected_headers"].(map[string]any)
	if !ok {
		t.Fatalf("protected_headers 应存在，实际: %#v", envelope["protected_headers"])
	}
	if got := headers["payload_type"]; got != "text" {
		t.Fatalf("protected_headers.payload_type 应保留兼容校验，实际: %#v", got)
	}
	if headers["sdk_lang"] != e2eeSDKLang || headers["sdk_vesion"] != e2eeSDKVersion {
		t.Fatalf("protected_headers SDK 元信息错误: %#v", headers)
	}
	decrypted, err := DecryptMessage(envelope, target.AID, target.DeviceID, ikPriv, nil, sender.IKPubDER)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if !reflect.DeepEqual(decrypted, payload) {
		t.Fatalf("payload 不一致\n期望: %v\n实际: %v", payload, decrypted)
	}
}

func TestDecryptP2P3DHMissingSPKReportsPreciseError(t *testing.T) {
	sender := makeTestSender(t)
	target, ikPriv, _ := makeTestRecipient(t, "peer", "peer_device_prekey", true)
	envelope, err := EncryptP2PMessage(sender, TargetSet{Targets: []Target{target}}, map[string]any{"text": "missing"}, EncryptOptions{})
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	_, err = DecryptMessage(envelope, target.AID, target.DeviceID, ikPriv, nil, sender.IKPubDER)
	if err == nil || !strings.Contains(err.Error(), "spk_missing: spk_id=sha256:bob_spk_1") {
		t.Fatalf("missing SPK 应报 spk_missing，实际: %v", err)
	}
}

// TestEncryptP2PMixedProtocol 多设备 fan-out（一个 3DH + 一个 1DH self_sync）
func TestEncryptP2PMixedProtocol(t *testing.T) {
	sender := makeTestSender(t)

	bob, bobIKPriv, bobSPKPriv := makeTestRecipient(t, "peer", "peer_device_prekey", true)

	alice2IKPriv, alice2IKPub, err := crypto.GenerateP256Keypair()
	if err != nil {
		t.Fatalf("生成 alice2 失败: %v", err)
	}
	alice2 := Target{
		AID:       "alice.aid.com",
		DeviceID:  "dev-alice-2",
		Role:      "self_sync",
		KeySource: "aid_master",
		IKPkDER:   alice2IKPub,
	}

	targetSet := TargetSet{Targets: []Target{bob, alice2}}

	payload := map[string]any{
		"text":       "Multi-device fan-out",
		"to_devices": int64(2),
	}

	envelope, err := EncryptP2PMessage(sender, targetSet, payload, EncryptOptions{})
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// wrap_protocol 应为 "1DH+3DH"
	if got := envelope["aad"].(map[string]any)["wrap_protocol"]; got != "1DH+3DH" {
		t.Fatalf("wrap_protocol 错误: %v", got)
	}

	// Bob 解密
	decrypted, err := DecryptMessage(envelope, bob.AID, bob.DeviceID, bobIKPriv, bobSPKPriv, sender.IKPubDER)
	if err != nil {
		t.Fatalf("Bob 解密失败: %v", err)
	}
	// JSON Number 与 int64 都可以表示同一值，比较 String 表示
	gotText := decrypted["text"].(string)
	if gotText != "Multi-device fan-out" {
		t.Fatalf("Bob payload text 错误: %v", gotText)
	}

	// Alice-2 解密
	decrypted2, err := DecryptMessage(envelope, "alice.aid.com", "dev-alice-2", alice2IKPriv, nil, sender.IKPubDER)
	if err != nil {
		t.Fatalf("Alice-2 解密失败: %v", err)
	}
	if decrypted2["text"].(string) != "Multi-device fan-out" {
		t.Fatalf("Alice-2 payload text 错误: %v", decrypted2["text"])
	}
}

// TestEncryptP2PSenderSignatureVerifies 加密产生的签名应能用 sender 公钥验证。
func TestEncryptP2PSenderSignatureVerifies(t *testing.T) {
	sender := makeTestSender(t)
	target, _, _ := makeTestRecipient(t, "peer", "aid_master", false)
	targetSet := TargetSet{Targets: []Target{target}}

	envelope, err := EncryptP2PMessage(sender, targetSet, map[string]any{"x": "y"}, EncryptOptions{})
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if err := verifySenderSignature(envelope, sender.IKPubDER); err != nil {
		t.Fatalf("签名验证失败: %v", err)
	}

	// 用错误的公钥应该验证失败
	_, wrongPub, _ := crypto.GenerateP256Keypair()
	if err := verifySenderSignature(envelope, wrongPub); err == nil {
		t.Fatal("用错误公钥验证应失败但通过了")
	}
}

// 抑制未使用变量 / 消除潜在 lint 警告
var _ = base64.StdEncoding
var _ = alicePrivB64
var _ = alicePubB64
var _ = bobPrivB64
var _ = bobSPKPrivB64
