package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// goldenECDHVector 兼容 alice_bob.json 与 session_alice.json 两种字段命名。
type goldenECDHVector struct {
	Description string `json:"description"`

	// alice_bob.json 字段
	AlicePrivB64 string `json:"alice_priv_b64,omitempty"`
	BobPubDERB64 string `json:"bob_pub_der_b64,omitempty"`

	// session_alice.json 字段
	SessionPrivB64 string `json:"session_priv_b64,omitempty"`
	AlicePubDERB64 string `json:"alice_pub_der_b64,omitempty"`

	ExpectedSharedB64 string `json:"expected_shared_b64"`
}

// resolvePrivAndPub 根据存在的字段返回 (priv, peerPubDER)。
func (g *goldenECDHVector) resolvePrivAndPub(t *testing.T) ([]byte, []byte) {
	t.Helper()

	var privB64, pubB64 string
	switch {
	case g.AlicePrivB64 != "" && g.BobPubDERB64 != "":
		privB64, pubB64 = g.AlicePrivB64, g.BobPubDERB64
	case g.SessionPrivB64 != "" && g.AlicePubDERB64 != "":
		privB64, pubB64 = g.SessionPrivB64, g.AlicePubDERB64
	default:
		t.Fatalf("golden 向量缺少私钥/公钥字段：%+v", g)
	}

	priv, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		t.Fatalf("解码私钥失败: %v", err)
	}
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatalf("解码公钥失败: %v", err)
	}
	return priv, pub
}

func loadECDHGolden(t *testing.T, name string) *goldenECDHVector {
	t.Helper()
	path := filepath.Join("testdata", "golden", "ecdh", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	var g goldenECDHVector
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatalf("解析 %s 失败: %v", path, err)
	}
	return &g
}

// TestECDHGoldenVectors 验证 ECDH 输出与 Python SDK 生成的 golden 向量字节级一致。
func TestECDHGoldenVectors(t *testing.T) {
	cases := []string{"alice_bob.json", "session_alice.json"}

	for _, name := range cases {
		name := name
		t.Run(name, func(t *testing.T) {
			g := loadECDHGolden(t, name)
			priv, pubDER := g.resolvePrivAndPub(t)

			expected, err := base64.StdEncoding.DecodeString(g.ExpectedSharedB64)
			if err != nil {
				t.Fatalf("解码期望共享秘密失败: %v", err)
			}

			shared, err := ECDHComputeShared(priv, pubDER)
			if err != nil {
				t.Fatalf("ECDHComputeShared 失败: %v", err)
			}

			if len(shared) != 32 {
				t.Fatalf("共享秘密长度错误：期望 32，实际 %d", len(shared))
			}

			if !bytes.Equal(shared, expected) {
				t.Fatalf("共享秘密不匹配\n期望: %x\n实际: %x", expected, shared)
			}
		})
	}
}

// TestECDHSymmetry 验证 ECDH(A_priv, B_pub) == ECDH(B_priv, A_pub)。
func TestECDHSymmetry(t *testing.T) {
	aPriv, aPubDER, err := GenerateP256Keypair()
	if err != nil {
		t.Fatalf("生成 A 密钥对失败: %v", err)
	}
	bPriv, bPubDER, err := GenerateP256Keypair()
	if err != nil {
		t.Fatalf("生成 B 密钥对失败: %v", err)
	}

	sharedAB, err := ECDHComputeShared(aPriv, bPubDER)
	if err != nil {
		t.Fatalf("ECDH(A_priv, B_pub) 失败: %v", err)
	}
	sharedBA, err := ECDHComputeShared(bPriv, aPubDER)
	if err != nil {
		t.Fatalf("ECDH(B_priv, A_pub) 失败: %v", err)
	}

	if !bytes.Equal(sharedAB, sharedBA) {
		t.Fatalf("ECDH 对称性失败\nA→B: %x\nB→A: %x", sharedAB, sharedBA)
	}
	if len(sharedAB) != 32 {
		t.Fatalf("共享秘密长度错误：期望 32，实际 %d", len(sharedAB))
	}
}

// TestECDHGenerateKeypair 验证生成的密钥对可成功 ECDH。
func TestECDHGenerateKeypair(t *testing.T) {
	priv, pubDER, err := GenerateP256Keypair()
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}
	if len(priv) != 32 {
		t.Fatalf("私钥标量长度错误：期望 32，实际 %d", len(priv))
	}
	if len(pubDER) == 0 {
		t.Fatalf("公钥 DER 为空")
	}

	// 用同一密钥对自身 ECDH（合法操作，应返回 32 字节）
	shared, err := ECDHComputeShared(priv, pubDER)
	if err != nil {
		t.Fatalf("自身 ECDH 失败: %v", err)
	}
	if len(shared) != 32 {
		t.Fatalf("共享秘密长度错误：期望 32，实际 %d", len(shared))
	}
}

// TestECDHPrivateToPublicDER 验证 PrivateToPublicDER 与 GenerateP256Keypair 输出的公钥一致。
func TestECDHPrivateToPublicDER(t *testing.T) {
	priv, pubDER, err := GenerateP256Keypair()
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}

	derived, err := PrivateToPublicDER(priv)
	if err != nil {
		t.Fatalf("PrivateToPublicDER 失败: %v", err)
	}

	if !bytes.Equal(pubDER, derived) {
		t.Fatalf("PrivateToPublicDER 输出与 GenerateP256Keypair 不一致\n期望: %x\n实际: %x", pubDER, derived)
	}
}

// TestECDHInvalidPrivateKeyLength 验证私钥长度校验。
func TestECDHInvalidPrivateKeyLength(t *testing.T) {
	_, pubDER, err := GenerateP256Keypair()
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}

	_, err = ECDHComputeShared(make([]byte, 31), pubDER)
	if err == nil {
		t.Fatalf("期望长度校验失败，实际成功")
	}
}
