package aun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"strconv"
	"strings"

	v2crypto "github.com/modelunion/aun-sdk-core/go/v2/crypto"
	"github.com/modelunion/aun-sdk-core/go/v2/e2ee"
)

func (c *AUNClient) v2TrustedIKPubDER(ctx context.Context, state *v2P2PState, aid string) ([]byte, error) {
	aid = strings.TrimSpace(aid)
	if aid == "" {
		return nil, fmt.Errorf("spk_aid_missing")
	}
	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	if aid == myAID {
		if state == nil || state.session == nil {
			return nil, fmt.Errorf("V2 session not initialized")
		}
		return state.session.IKPubDER()
	}
	certBytes, err := c.fetchPeerCert(ctx, aid, "")
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certBytes)
	var cert *x509.Certificate
	if block != nil {
		cert, err = x509.ParseCertificate(block.Bytes)
	} else {
		cert, err = x509.ParseCertificate(certBytes)
	}
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(cert.PublicKey)
}

func v2SPKTimestampText(value any, aid, deviceID, spkID string) (string, error) {
	if value == nil {
		return "", fmt.Errorf("spk_timestamp_missing: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
	}
	switch v := value.(type) {
	case bool:
		return "", fmt.Errorf("spk_timestamp_invalid: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
	case int:
		if v < 0 {
			return "", fmt.Errorf("spk_timestamp_invalid: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
		}
		return strconv.FormatInt(int64(v), 10), nil
	case int64:
		if v < 0 {
			return "", fmt.Errorf("spk_timestamp_invalid: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
		}
		return strconv.FormatInt(v, 10), nil
	case int32:
		if v < 0 {
			return "", fmt.Errorf("spk_timestamp_invalid: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
		}
		return strconv.FormatInt(int64(v), 10), nil
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Trunc(v) != v || v < 0 {
			return "", fmt.Errorf("spk_timestamp_invalid: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
		}
		return strconv.FormatInt(int64(v), 10), nil
	case float32:
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) || math.Trunc(f) != f || f < 0 {
			return "", fmt.Errorf("spk_timestamp_invalid: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
		}
		return strconv.FormatInt(int64(f), 10), nil
	case json.Number:
		i, err := v.Int64()
		if err != nil || i < 0 {
			return "", fmt.Errorf("spk_timestamp_invalid: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
		}
		return strconv.FormatInt(i, 10), nil
	case string:
		text := strings.TrimSpace(v)
		if text == "" {
			return "", fmt.Errorf("spk_timestamp_missing: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
		}
		i, err := strconv.ParseInt(text, 10, 64)
		if err != nil || i < 0 {
			return "", fmt.Errorf("spk_timestamp_invalid: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
		}
		return strconv.FormatInt(i, 10), nil
	default:
		return "", fmt.Errorf("spk_timestamp_invalid: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
	}
}

func (c *AUNClient) v2VerifySPKDevice(ctx context.Context, state *v2P2PState, dev map[string]any, aid, deviceID string, ikDER, spkDER []byte, keySource string) error {
	if state == nil || state.session == nil {
		return fmt.Errorf("V2 session not initialized")
	}
	spkID := strings.TrimSpace(v2AsString(dev["spk_id"]))
	if spkID == "" {
		return nil
	}
	if keySource != "peer_device_prekey" && keySource != "group_device_prekey" {
		return fmt.Errorf("spk_key_source_invalid: aid=%s device_id=%s spk_id=%s key_source=%s", aid, deviceID, spkID, keySource)
	}
	if len(spkDER) == 0 {
		return fmt.Errorf("spk_public_key_missing: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
	}
	sum := sha256.Sum256(spkDER)
	expectedSPKID := "sha256:" + hex.EncodeToString(sum[:])[:16]
	if spkID != expectedSPKID {
		return fmt.Errorf("spk_id_mismatch: aid=%s device_id=%s spk_id=%s expected=%s", aid, deviceID, spkID, expectedSPKID)
	}
	trustedIK, err := c.v2TrustedIKPubDER(ctx, state, aid)
	if err != nil {
		return err
	}
	if !bytes.Equal(trustedIK, ikDER) {
		return fmt.Errorf("spk_ik_mismatch: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
	}
	if bytes.Equal(spkDER, trustedIK) {
		state.session.MarkPeerSPKVerified(aid, deviceID, spkID)
		return nil
	}
	sigB64 := strings.TrimSpace(v2AsString(dev["spk_signature"]))
	if sigB64 == "" {
		return fmt.Errorf("spk_signature_missing: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
	}
	signature, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("spk_signature_invalid_base64: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
	}
	tsText, err := v2SPKTimestampText(dev["spk_timestamp"], aid, deviceID, spkID)
	if err != nil {
		return err
	}
	signData := make([]byte, 0, len(spkDER)+len(spkID)+len(tsText))
	signData = append(signData, spkDER...)
	signData = append(signData, []byte(spkID)...)
	signData = append(signData, []byte(tsText)...)
	if !v2crypto.ECDSAVerifyRaw(trustedIK, signature, signData) {
		return fmt.Errorf("spk_signature_invalid: aid=%s device_id=%s spk_id=%s", aid, deviceID, spkID)
	}
	state.session.MarkPeerSPKVerified(aid, deviceID, spkID)
	return nil
}

func v2DeviceIDFromDevice(dev map[string]any) (string, bool) {
	if v, ok := dev["device_id"]; ok {
		return strings.TrimSpace(v2AsString(v)), true
	}
	if v, ok := dev["owner_device_id"]; ok {
		return strings.TrimSpace(v2AsString(v)), true
	}
	return "", false
}

func (c *AUNClient) v2BuildTargetFromDevice(ctx context.Context, state *v2P2PState, dev map[string]any, aid, deviceID, role, defaultKeySource string) (e2ee.Target, bool, error) {
	aid = strings.TrimSpace(aid)
	resolvedDeviceID, hasDeviceID := v2DeviceIDFromDevice(dev)
	if hasDeviceID {
		deviceID = resolvedDeviceID
	} else {
		deviceID = strings.TrimSpace(deviceID)
	}
	ikDER := v2DecodeBase64Field(dev, "ik_pk")
	if aid == "" || !hasDeviceID || len(ikDER) == 0 {
		return e2ee.Target{}, false, nil
	}
	spkDER := v2DecodeBase64Field(dev, "spk_pk")
	keySource := v2DefaultStr(strings.TrimSpace(v2AsString(dev["key_source"])), defaultKeySource)
	if err := c.v2VerifySPKDevice(ctx, state, dev, aid, deviceID, ikDER, spkDER, keySource); err != nil {
		return e2ee.Target{}, false, err
	}
	state.session.CachePeerIK(aid, deviceID, ikDER)
	return e2ee.Target{
		AID:       aid,
		DeviceID:  deviceID,
		Role:      role,
		KeySource: keySource,
		IKPkDER:   ikDER,
		SPKPkDER:  spkDER,
		SPKID:     strings.TrimSpace(v2AsString(dev["spk_id"])),
	}, true, nil
}
