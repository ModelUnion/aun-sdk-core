package e2ee

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/modelunion/aun-sdk-core/go/v2/crypto"
)

const (
	e2eeSDKLang    = "go"
	e2eeSDKVersion = "0.3.6"
)

// EncryptP2PMessage 构造完整的 V2 P2P 加密 envelope（type=e2ee.p2p_encrypted）。
//
// 与 Python `encrypt_p2p_message` 字节级对齐：
//
//  1. 生成 master_key(32B) + msg_nonce(12B)
//  2. 决定 message_id / timestamp（缺省自动生成）
//  3. 选取第一个非 audit 的 target.AID 作为 AAD.to
//  4. 根据 (spk_id, key_source, spk_pk_der) 推导 wrap_protocol（"3DH" / "1DH" / "1DH+3DH"）
//  5. 用 AAD 加密 payload，得到 ciphertext + tag
//  6. 生成一次性 sender_session keypair，计算 wrap_salt
//  7. 为每个 recipient（targets + audit_recipients）wrap master_key
//  8. 排序 recipients，计算 Merkle digest
//  9. 用 IK 私钥对 (ct||tag||aad||digest) 做 ECDSA RAW 签名
//  10. 组装并返回 envelope
func EncryptP2PMessage(sender Sender, targetSet TargetSet, payload map[string]any, opts EncryptOptions) (map[string]any, error) {
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("encrypt_p2p: 生成 master_key 失败: %w", err)
	}
	msgNonce := make([]byte, 12)
	if _, err := rand.Read(msgNonce); err != nil {
		return nil, fmt.Errorf("encrypt_p2p: 生成 msg_nonce 失败: %w", err)
	}

	messageID := opts.MessageID
	if messageID == "" {
		messageID = "m-" + strings.ReplaceAll(uuid.New().String(), "-", "")
	}
	timestamp := opts.Timestamp
	if timestamp == 0 {
		timestamp = time.Now().UnixMilli()
	}

	// peer_aid: 第一个非 audit 的 target
	peerAID := ""
	for _, t := range targetSet.Targets {
		if t.Role != "audit" {
			peerAID = t.AID
			break
		}
	}

	// wrap_protocol: 根据所有 target（含 audit）的 (spk_id, spk_pk_der, key_source) 聚合
	allTargets := make([]Target, 0, len(targetSet.Targets)+len(targetSet.AuditRecipients))
	allTargets = append(allTargets, targetSet.Targets...)
	allTargets = append(allTargets, targetSet.AuditRecipients...)

	wrapProtocolStr := deriveWrapProtocol(allTargets)

	// 构造 AAD（注意：timestamp 是 int64，CanonicalJSON 会兜底转 int 字符串）
	aad := map[string]any{
		"from":          sender.AID,
		"from_device":   sender.DeviceID,
		"to":            peerAID,
		"message_id":    messageID,
		"timestamp":     timestamp,
		"suite":         SuiteName,
		"wrap_protocol": wrapProtocolStr,
	}

	plaintextBytes := crypto.CanonicalJSON(payload)
	aadBytes := crypto.CanonicalJSON(aad)

	ct, tag, err := crypto.AESGCMEncrypt(masterKey, msgNonce, plaintextBytes, aadBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt_p2p: 加密正文失败: %w", err)
	}

	senderSessionPriv, senderSessionPubDER, err := crypto.GenerateP256Keypair()
	if err != nil {
		return nil, fmt.Errorf("encrypt_p2p: 生成 sender_session keypair 失败: %w", err)
	}

	wrapSalt := computeWrapSalt(aadBytes, senderSessionPubDER, SuiteName)

	recipientsRows := make([][]string, 0, len(allTargets))
	for _, target := range allTargets {
		row, err := wrapForRecipient(target, masterKey, senderSessionPriv, sender.IKPriv, wrapSalt)
		if err != nil {
			return nil, fmt.Errorf("encrypt_p2p: wrap recipient %s/%s 失败: %w", target.AID, target.DeviceID, err)
		}
		recipientsRows = append(recipientsRows, row)
	}

	sortedRows := crypto.SortRecipients(recipientsRows)
	digestHex := crypto.ComputeMerkleRoot(sortedRows)

	digestBytes, err := hex.DecodeString(digestHex)
	if err != nil {
		return nil, fmt.Errorf("encrypt_p2p: 解析 digest 失败: %w", err)
	}

	signInput := make([]byte, 0, len(ct)+len(tag)+len(aadBytes)+len(digestBytes))
	signInput = append(signInput, ct...)
	signInput = append(signInput, tag...)
	signInput = append(signInput, aadBytes...)
	signInput = append(signInput, digestBytes...)
	senderSig, err := crypto.ECDSASignRaw(sender.IKPriv, signInput)
	if err != nil {
		return nil, fmt.Errorf("encrypt_p2p: ECDSA 签名失败: %w", err)
	}

	certFp := computeCertFingerprint(sender.IKPubDER)

	// 转 sortedRows 为 []any（保证后续 json.Marshal 与 Python 输出格式一致）
	recipientsAny := make([]any, len(sortedRows))
	for i, row := range sortedRows {
		anyRow := make([]any, len(row))
		for j, v := range row {
			anyRow[j] = v
		}
		recipientsAny[i] = anyRow
	}

	envelope := map[string]any{
		"type":                    "e2ee.p2p_encrypted",
		"version":                 "v2",
		"suite":                   SuiteName,
		"msg_type":                "original",
		"t_send":                  timestamp,
		"t_supplement":            nil,
		"t_server":                nil,
		"nonce":                   base64.StdEncoding.EncodeToString(msgNonce),
		"ciphertext":              base64.StdEncoding.EncodeToString(ct),
		"tag":                     base64.StdEncoding.EncodeToString(tag),
		"sender_signature":        base64.StdEncoding.EncodeToString(senderSig),
		"sender_cert_fingerprint": certFp,
		"sender_session_pk":       base64.StdEncoding.EncodeToString(senderSessionPubDER),
		"recipients_digest":       digestHex,
		"recipients":              recipientsAny,
		"aad":                     aad,
	}
	if payloadType, err := payloadTypeFromPayload(payload); err != nil {
		return nil, fmt.Errorf("encrypt_p2p: payload_type 无效: %w", err)
	} else if payloadType != "" {
		envelope["payload_type"] = payloadType
	}

	// protected_headers / context：HMAC 签名（与 V1 对齐），不进 AAD
	// payload_type 自动注入 + value 转 string（与 Python _normalize_headers 对齐）
	normalizedHeaders, err := normalizeProtectedHeaders(opts.ProtectedHeaders, payload)
	if err != nil {
		return nil, fmt.Errorf("encrypt_p2p: protected_headers 无效: %w", err)
	}
	if len(normalizedHeaders) > 0 {
		envelope["protected_headers"] = withMetadataAuth(normalizedHeaders, masterKey, protectedHeadersDomain)
	}
	if len(opts.Context) > 0 {
		envelope["context"] = withMetadataAuth(opts.Context, masterKey, protectedContextDomain)
	}

	return envelope, nil
}

// deriveWrapProtocol 根据 targets 聚合 wrap_protocol 字符串。
// 与 Python 一致：仅当 spk_id/spk_pk_der 非空且 key_source ∈
// {peer_device_prekey, group_device_prekey} 时记 3DH，其它记 1DH；
// 空集合兜底返回 "1DH"。
func deriveWrapProtocol(targets []Target) string {
	protoSet := map[string]bool{}
	for _, t := range targets {
		if usesSPKWrap(t) {
			protoSet["3DH"] = true
		} else {
			protoSet["1DH"] = true
		}
	}
	if len(protoSet) == 0 {
		return "1DH"
	}
	protocols := make([]string, 0, len(protoSet))
	for p := range protoSet {
		protocols = append(protocols, p)
	}
	sort.Strings(protocols)
	return strings.Join(protocols, "+")
}

// computeWrapSalt = SHA256(canonical_aad || sender_session_pk_der || suite)[:16]
//
// 切断 recipients_digest 循环依赖；绑定到 sender_session_pk + AAD 防跨消息重放。
func computeWrapSalt(aadBytes, senderSessionPubDER []byte, suite string) []byte {
	h := sha256.New()
	h.Write(aadBytes)
	h.Write(senderSessionPubDER)
	h.Write([]byte(suite))
	full := h.Sum(nil)
	out := make([]byte, 16)
	copy(out, full[:16])
	return out
}

// computeCertFingerprint = "sha256:" + hex(SHA256(ik_pub_der))[:16]
func computeCertFingerprint(ikPubDER []byte) string {
	sum := sha256.Sum256(ikPubDER)
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}

func payloadTypeFromPayload(payload map[string]any) (string, error) {
	if payload == nil {
		return "", nil
	}
	value, ok := payload["type"]
	if !ok {
		return "", nil
	}
	return protectedHeaderValueString(value)
}

// normalizeProtectedHeaders 规范化 protected_headers：value 转 string + 自动注入 payload_type。
// 与 Python `_normalize_headers` 对齐。
func normalizeProtectedHeaders(headers map[string]any, payload map[string]any) (map[string]any, error) {
	normalized := make(map[string]any)
	for k, v := range headers {
		key, err := normalizeProtectedHeaderKey(k)
		if err != nil {
			return nil, err
		}
		value, err := protectedHeaderValueString(v)
		if err != nil {
			return nil, err
		}
		normalized[key] = value
	}
	// payload_type 自动注入（与 Python 对齐：payload.get("type") → protected_headers["payload_type"]）
	if payload != nil {
		if pt, ok := payload["type"]; ok {
			ptStr, err := protectedHeaderValueString(pt)
			if err != nil {
				return nil, err
			}
			if ptStr != "" {
				if _, exists := normalized["payload_type"]; !exists {
					normalized["payload_type"] = ptStr
				}
			}
		}
	}
	normalized["sdk_lang"] = e2eeSDKLang
	delete(normalized, "sdk_vesion")
	normalized["sdk_version"] = e2eeSDKVersion
	return normalized, nil
}

// wrapForRecipient 为单个 recipient 生成 8 字段 wrap row：
//
//	[aid, device_id, role, key_source, fp, spk_id, wrap_nonce_b64, wrapped_key_b64]
//
// 选择 3DH 或 1DH 路径与 Python `_wrap_for_recipient` 完全一致。
func wrapForRecipient(target Target, masterKey, senderSessionPriv, senderMasterPriv, wrapSalt []byte) ([]string, error) {
	fpHash := sha256.Sum256(target.IKPkDER)
	fp := "sha256:" + hex.EncodeToString(fpHash[:])[:16]

	wrapNonce := make([]byte, 12)
	if _, err := rand.Read(wrapNonce); err != nil {
		return nil, fmt.Errorf("生成 wrap_nonce 失败: %w", err)
	}

	var wrapKey []byte
	var err error
	use3DH := usesSPKWrap(target)
	rowKeySource := "aid_master"
	rowSPKID := ""
	if use3DH {
		rowKeySource = target.KeySource
		rowSPKID = target.SPKID
		wrapKey, err = crypto.Compute3DHWrap(senderSessionPriv, senderMasterPriv, target.IKPkDER, target.SPKPkDER, wrapSalt)
	} else {
		wrapKey, err = crypto.Compute1DHWrap(senderSessionPriv, target.IKPkDER, wrapSalt)
	}
	if err != nil {
		return nil, fmt.Errorf("派生 wrap_key 失败: %w", err)
	}

	wrappedCT, wrappedTag, err := crypto.AESGCMEncrypt(wrapKey, wrapNonce, masterKey, nil)
	if err != nil {
		return nil, fmt.Errorf("AEAD wrap master_key 失败: %w", err)
	}
	wrappedKey := make([]byte, 0, len(wrappedCT)+len(wrappedTag))
	wrappedKey = append(wrappedKey, wrappedCT...)
	wrappedKey = append(wrappedKey, wrappedTag...)

	return []string{
		target.AID,
		target.DeviceID,
		target.Role,
		rowKeySource,
		fp,
		rowSPKID,
		base64.StdEncoding.EncodeToString(wrapNonce),
		base64.StdEncoding.EncodeToString(wrappedKey),
	}, nil
}

func usesSPKWrap(target Target) bool {
	return target.SPKID != "" &&
		len(target.SPKPkDER) > 0 &&
		(target.KeySource == "peer_device_prekey" || target.KeySource == "group_device_prekey")
}
