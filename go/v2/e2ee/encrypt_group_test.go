package e2ee

import (
	"reflect"
	"testing"

	"github.com/modelunion/aun-sdk-core/go/v2/crypto"
)

// TestEncryptGroupRoundtrip3DH 单成员 3DH 群消息 round-trip。
func TestEncryptGroupRoundtrip3DH(t *testing.T) {
	sender := makeTestSender(t)
	target, ikPriv, spkPriv := makeTestRecipient(t, "member", "group_device_prekey", true)

	payload := map[string]any{
		"text": "Group hello",
		"type": "group_text",
	}

	envelope, err := EncryptGroupMessage(sender, "g-test.aid.com", 5,
		[]Target{target}, payload, EncryptOptions{}, &StateCommitmentAAD{
			StateVersion: 1,
			StateHash:    "abc123",
			StateChain:   "chain-link-1",
		})
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	if envelope["type"] != "e2ee.group_encrypted" {
		t.Fatalf("type 字段错误: %v", envelope["type"])
	}
	if envelope["group_id"] != "g-test.aid.com" {
		t.Fatalf("group_id 错误: %v", envelope["group_id"])
	}
	if envelope["epoch"].(int) != 5 {
		t.Fatalf("epoch 错误: %v", envelope["epoch"])
	}

	aad := envelope["aad"].(map[string]any)
	if aad["wrap_protocol"] != "3DH" {
		t.Fatalf("wrap_protocol 错误: %v", aad["wrap_protocol"])
	}
	sc := aad["state_commitment"].(map[string]any)
	if sc["state_version"] != 1 {
		t.Fatalf("state_version 错误: %v", sc["state_version"])
	}

	decrypted, err := DecryptMessage(envelope, target.AID, target.DeviceID, ikPriv, spkPriv, sender.IKPubDER)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if !reflect.DeepEqual(decrypted, payload) {
		t.Fatalf("payload 不一致\n期望: %v\n实际: %v", payload, decrypted)
	}
}

// TestEncryptGroupMixedProtocol 群多成员（3DH + 1DH）。
func TestEncryptGroupMixedProtocol(t *testing.T) {
	sender := makeTestSender(t)

	bob, bobIK, bobSPK := makeTestRecipient(t, "member", "group_device_prekey", true)

	carolIK, carolPub, err := crypto.GenerateP256Keypair()
	if err != nil {
		t.Fatalf("生成 carol 失败: %v", err)
	}
	carol := Target{
		AID:       "carol.aid.com",
		DeviceID:  "dev-carol-1",
		Role:      "member",
		KeySource: "aid_master",
		IKPkDER:   carolPub,
	}

	payload := map[string]any{
		"text": "Group message",
		"type": "group_text",
	}

	envelope, err := EncryptGroupMessage(sender, "g-mixed.aid.com", 7,
		[]Target{bob, carol}, payload, EncryptOptions{}, nil)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	if got := envelope["aad"].(map[string]any)["wrap_protocol"]; got != "1DH+3DH" {
		t.Fatalf("wrap_protocol 错误: %v", got)
	}

	// 默认占位 state_commitment
	sc := envelope["aad"].(map[string]any)["state_commitment"].(map[string]any)
	if sc["state_version"] != 0 || sc["state_hash"] != "" || sc["state_chain"] != "" {
		t.Fatalf("默认 state_commitment 应全 0/空: %v", sc)
	}

	// Bob 解密
	gotBob, err := DecryptMessage(envelope, bob.AID, bob.DeviceID, bobIK, bobSPK, sender.IKPubDER)
	if err != nil {
		t.Fatalf("Bob 解密失败: %v", err)
	}
	if !reflect.DeepEqual(gotBob, payload) {
		t.Fatalf("Bob payload 不一致")
	}

	// Carol 解密（1DH，无 SPK）
	gotCarol, err := DecryptMessage(envelope, carol.AID, carol.DeviceID, carolIK, nil, sender.IKPubDER)
	if err != nil {
		t.Fatalf("Carol 解密失败: %v", err)
	}
	if !reflect.DeepEqual(gotCarol, payload) {
		t.Fatalf("Carol payload 不一致")
	}
}

// TestEncryptGroupSignatureVerifies 群消息签名验证。
func TestEncryptGroupSignatureVerifies(t *testing.T) {
	sender := makeTestSender(t)
	target, _, _ := makeTestRecipient(t, "member", "aid_master", false)

	envelope, err := EncryptGroupMessage(sender, "g.aid.com", 1,
		[]Target{target}, map[string]any{"x": "y"}, EncryptOptions{}, nil)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if err := verifySenderSignature(envelope, sender.IKPubDER); err != nil {
		t.Fatalf("签名验证失败: %v", err)
	}
}
