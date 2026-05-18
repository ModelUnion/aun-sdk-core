package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type golden1DHVector struct {
	Description         string `json:"description"`
	SenderSessionPrivB64 string `json:"sender_session_priv_b64"`
	RecvIKPubDERB64      string `json:"recv_ik_pub_der_b64"`
	SaltB64              string `json:"salt_b64"`
	ExpectedWrapKeyB64   string `json:"expected_wrap_key_b64"`
}

type golden3DHVector struct {
	Description          string `json:"description"`
	SenderSessionPrivB64 string `json:"sender_session_priv_b64"`
	SenderMasterPrivB64  string `json:"sender_master_priv_b64"`
	RecvIKPubDERB64      string `json:"recv_ik_pub_der_b64"`
	RecvSPKPubDERB64     string `json:"recv_spk_pub_der_b64"`
	SaltB64              string `json:"salt_b64"`
	ExpectedWrapKeyB64   string `json:"expected_wrap_key_b64"`
}

func decodeB64(t *testing.T, name, s string) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("解码 %s: %v", name, err)
	}
	return out
}

func TestCompute1DHWrap(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "golden", "1dh", "basic.json"))
	if err != nil {
		t.Fatalf("读取 golden: %v", err)
	}
	var g golden1DHVector
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatalf("解析 golden: %v", err)
	}

	priv := decodeB64(t, "sender_session_priv", g.SenderSessionPrivB64)
	ikPub := decodeB64(t, "recv_ik_pub_der", g.RecvIKPubDERB64)
	salt := decodeB64(t, "salt", g.SaltB64)
	expected := decodeB64(t, "expected_wrap_key", g.ExpectedWrapKeyB64)

	wrap, err := Compute1DHWrap(priv, ikPub, salt)
	if err != nil {
		t.Fatalf("Compute1DHWrap: %v", err)
	}
	if !bytes.Equal(wrap, expected) {
		t.Fatalf("1DH wrap_key 不匹配\n期望: %x\n实际: %x", expected, wrap)
	}
	if len(wrap) != WrapKeyLen {
		t.Fatalf("wrap_key 长度错误：期望 %d，实际 %d", WrapKeyLen, len(wrap))
	}
}

func TestCompute3DHWrap(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "golden", "3dh", "basic.json"))
	if err != nil {
		t.Fatalf("读取 golden: %v", err)
	}
	var g golden3DHVector
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatalf("解析 golden: %v", err)
	}

	sessionPriv := decodeB64(t, "sender_session_priv", g.SenderSessionPrivB64)
	masterPriv := decodeB64(t, "sender_master_priv", g.SenderMasterPrivB64)
	ikPub := decodeB64(t, "recv_ik_pub_der", g.RecvIKPubDERB64)
	spkPub := decodeB64(t, "recv_spk_pub_der", g.RecvSPKPubDERB64)
	salt := decodeB64(t, "salt", g.SaltB64)
	expected := decodeB64(t, "expected_wrap_key", g.ExpectedWrapKeyB64)

	wrap, err := Compute3DHWrap(sessionPriv, masterPriv, ikPub, spkPub, salt)
	if err != nil {
		t.Fatalf("Compute3DHWrap: %v", err)
	}
	if !bytes.Equal(wrap, expected) {
		t.Fatalf("3DH wrap_key 不匹配\n期望: %x\n实际: %x", expected, wrap)
	}
	if len(wrap) != WrapKeyLen {
		t.Fatalf("wrap_key 长度错误：期望 %d，实际 %d", WrapKeyLen, len(wrap))
	}
}
