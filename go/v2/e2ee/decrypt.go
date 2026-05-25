package e2ee

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/modelunion/aun-sdk-core/go/v2/crypto"
)

// DecryptMessage 解密 V2 加密消息（P2P 或 Group），按 envelope 内容自动分流。
//
// 与 Python `decrypt_message` 行为对齐：
//
//  1. 验证 sender_signature（ECDSA RAW，输入为 ct||tag||canonical_aad||digest_bytes）
//  2. 处理两种 envelope 形态：
//     - 完整：recipients[]（验 Merkle root + 找自己的行）
//     - per-device：recipient{} + 可选 merkle_proof（用 proof 验证 leaf）
//  3. 计算 wrap_salt，根据 spk_id 选 3DH/1DH 路径派生 wrap_key
//  4. 解 wrap_key 得 master_key（注意 wrapped_key = ct(32B)||tag(16B)）
//  5. 用 master_key + msg_nonce + canonical_aad 解密正文
//  6. 解析为 JSON 对象返回
//
// 找不到自己 row 时返回 nil, nil（与 Python `return None` 等价）。
// 验签 / digest / 解密失败返回 error。
//
// selfSPKPriv 为 nil 表示自己只有 1DH 路径；row 的 spk_id 非空但
// selfSPKPriv 为空时返回 spk_missing，不允许静默降级到 1DH。
func DecryptMessage(envelope map[string]any, selfAID, selfDeviceID string,
	selfIKPriv []byte, selfSPKPriv []byte, senderPubDER []byte) (map[string]any, error) {

	// 1. 验签
	if err := verifySenderSignature(envelope, senderPubDER); err != nil {
		return nil, err
	}

	// 2. 找自己的 row
	row, err := locateRecipientRow(envelope, selfAID, selfDeviceID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, nil
	}

	// 3. wrap_salt + wrap_key
	senderSessionPKB64, _ := envelope["sender_session_pk"].(string)
	senderSessionPKDER, err := base64.StdEncoding.DecodeString(senderSessionPKB64)
	if err != nil {
		return nil, fmt.Errorf("decrypt: sender_session_pk base64 解析失败: %w", err)
	}

	aadVal, ok := envelope["aad"]
	if !ok {
		return nil, errors.New("decrypt: envelope 缺少 aad 字段")
	}
	aadBytes := crypto.CanonicalJSON(aadVal)

	suiteStr, _ := envelope["suite"].(string)
	if suiteStr == "" {
		suiteStr = SuiteName
	}
	wrapSalt := computeWrapSalt(aadBytes, senderSessionPKDER, suiteStr)

	wrapKey, err := computeWrapKey(row, selfIKPriv, selfSPKPriv, senderSessionPKDER, senderPubDER, wrapSalt)
	if err != nil {
		return nil, fmt.Errorf("decrypt: 派生 wrap_key 失败: %w", err)
	}

	// 4. 解 master_key
	wrapNonce, err := base64.StdEncoding.DecodeString(safe(row, 6))
	if err != nil {
		return nil, fmt.Errorf("decrypt: wrap_nonce base64 解析失败: %w", err)
	}
	wrappedKey, err := base64.StdEncoding.DecodeString(safe(row, 7))
	if err != nil {
		return nil, fmt.Errorf("decrypt: wrapped_key base64 解析失败: %w", err)
	}
	if len(wrappedKey) < 16 {
		return nil, fmt.Errorf("decrypt: wrapped_key 长度异常 %d", len(wrappedKey))
	}
	wrappedCT := wrappedKey[:len(wrappedKey)-16]
	wrappedTag := wrappedKey[len(wrappedKey)-16:]
	masterKey, err := crypto.AESGCMDecrypt(wrapKey, wrapNonce, wrappedCT, wrappedTag, nil)
	if err != nil {
		return nil, fmt.Errorf(
			"wrap_key_decrypt_failed: %s; master_key unwrap AEAD authentication failed; likely wrong local SPK/IK, stale sender bootstrap, or tampered recipient wrap; cause=%w",
			rowContext(row), err,
		)
	}
	if err := verifyMetadataAuth(envelope["protected_headers"], masterKey, protectedHeadersDomain, "protected_headers"); err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	if err := verifyMetadataAuth(envelope["context"], masterKey, protectedContextDomain, "context"); err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	// 5. 解密正文
	msgNonce, err := base64.StdEncoding.DecodeString(envStr(envelope, "nonce"))
	if err != nil {
		return nil, fmt.Errorf("decrypt: nonce base64 解析失败: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(envStr(envelope, "ciphertext"))
	if err != nil {
		return nil, fmt.Errorf("decrypt: ciphertext base64 解析失败: %w", err)
	}
	tag, err := base64.StdEncoding.DecodeString(envStr(envelope, "tag"))
	if err != nil {
		return nil, fmt.Errorf("decrypt: tag base64 解析失败: %w", err)
	}
	plaintext, err := crypto.AESGCMDecrypt(masterKey, msgNonce, ct, tag, aadBytes)
	if err != nil {
		return nil, fmt.Errorf(
			"body_decrypt_failed: %s; message body AEAD authentication failed after master_key unwrap; likely AAD/ciphertext/tag mismatch or envelope body corruption; cause=%w",
			envelopeContext(envelope, row), err,
		)
	}

	// 6. JSON 解析（保留数字精度）
	dec := json.NewDecoder(bytes.NewReader(plaintext))
	dec.UseNumber()
	var payload map[string]any
	if err := dec.Decode(&payload); err != nil {
		return nil, fmt.Errorf("decrypt: 解析 payload JSON 失败: %w", err)
	}
	return payload, nil
}

// verifySenderSignature 校验 sender_signature。
//
// 输入 = base64.decode(ciphertext) || base64.decode(tag) || canonical_json(aad) || hex.decode(recipients_digest)
func verifySenderSignature(envelope map[string]any, senderPubDER []byte) error {
	sigB64, _ := envelope["sender_signature"].(string)
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decrypt: sender_signature base64 解析失败: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(envStr(envelope, "ciphertext"))
	if err != nil {
		return fmt.Errorf("decrypt: ciphertext base64 解析失败: %w", err)
	}
	tag, err := base64.StdEncoding.DecodeString(envStr(envelope, "tag"))
	if err != nil {
		return fmt.Errorf("decrypt: tag base64 解析失败: %w", err)
	}
	aadVal, ok := envelope["aad"]
	if !ok {
		return errors.New("decrypt: envelope 缺少 aad")
	}
	aadBytes := crypto.CanonicalJSON(aadVal)
	digestHex, _ := envelope["recipients_digest"].(string)
	digestBytes, err := hex.DecodeString(digestHex)
	if err != nil {
		return fmt.Errorf("decrypt: recipients_digest 解析失败: %w", err)
	}
	signInput := make([]byte, 0, len(ct)+len(tag)+len(aadBytes)+len(digestBytes))
	signInput = append(signInput, ct...)
	signInput = append(signInput, tag...)
	signInput = append(signInput, aadBytes...)
	signInput = append(signInput, digestBytes...)
	if !crypto.ECDSAVerifyRaw(senderPubDER, sig, signInput) {
		return errors.New("decrypt: sender_signature 验证失败")
	}
	return nil
}

// locateRecipientRow 在 envelope 中找到自己的 8 字段 row。
//
// 完整 envelope（recipients）→ 验 Merkle root + 查表；
// per-device envelope（recipient + 可选 merkle_proof）→ 用 proof 验证 leaf。
//
// 返回 (nil, nil) 表示找不到自己（不视作错误，与 Python 一致）。
func locateRecipientRow(envelope map[string]any, selfAID, selfDeviceID string) ([]string, error) {
	if rcptsRaw, ok := envelope["recipients"]; ok {
		rows, err := convertRecipientsToStringMatrix(rcptsRaw)
		if err != nil {
			return nil, err
		}
		expectedDigest, _ := envelope["recipients_digest"].(string)
		actualDigest := crypto.ComputeMerkleRoot(rows)
		if actualDigest != expectedDigest {
			return nil, fmt.Errorf("decrypt: recipients_digest 不匹配（期望 %s，实际 %s）", expectedDigest, actualDigest)
		}
		for _, row := range rows {
			if safe(row, 0) == selfAID && safe(row, 1) == selfDeviceID {
				return row, nil
			}
		}
		return nil, nil
	}

	if rRaw, ok := envelope["recipient"]; ok {
		rMap, ok := rRaw.(map[string]any)
		if !ok {
			return nil, errors.New("decrypt: recipient 字段类型错误")
		}
		row := []string{
			mapStr(rMap, "aid"),
			mapStr(rMap, "device_id"),
			mapStr(rMap, "role"),
			mapStr(rMap, "key_source"),
			mapStr(rMap, "fp"),
			mapStr(rMap, "spk_id"),
			mapStr(rMap, "wrap_nonce"),
			mapStr(rMap, "wrapped_key"),
		}
		// 可选 Merkle proof 验证（向后兼容缺省）
		if proofRaw, ok := envelope["merkle_proof"]; ok && proofRaw != nil {
			expectedRoot, _ := envelope["recipients_digest"].(string)
			if expectedRoot != "" {
				proof, err := decodeMerkleProof(proofRaw)
				if err != nil {
					return nil, nil
				}
				leaf := crypto.ComputeLeafHash(row)
				if !crypto.VerifyMerkleProof(leaf, proof, expectedRoot) {
					return nil, nil
				}
			}
		}
		// per-device 形态下，row 必然是给当前设备的（服务端拆分后投递）
		return row, nil
	}

	return nil, nil
}

// computeWrapKey 根据 row 的 spk_id 与 selfSPKPriv 是否齐备分流 3DH/1DH。
func computeWrapKey(row []string, selfIKPriv, selfSPKPriv, senderSessionPKDER, senderMasterPKDER, salt []byte) ([]byte, error) {
	spkID := safe(row, 5)
	if spkID != "" && len(selfSPKPriv) == 0 {
		return nil, fmt.Errorf("spk_missing: spk_id=%s", spkID)
	}
	if spkID != "" && len(selfSPKPriv) > 0 {
		// 3DH 接收方：
		//   DH1 = ECDH(self_ik_priv, sender_session_pk)
		//   DH2 = ECDH(self_spk_priv, sender_master_pk)
		//   DH3 = ECDH(self_spk_priv, sender_session_pk)
		dh1, err := crypto.ECDHComputeShared(selfIKPriv, senderSessionPKDER)
		if err != nil {
			return nil, fmt.Errorf("DH1 失败: %w", err)
		}
		dh2, err := crypto.ECDHComputeShared(selfSPKPriv, senderMasterPKDER)
		if err != nil {
			return nil, fmt.Errorf("DH2 失败: %w", err)
		}
		dh3, err := crypto.ECDHComputeShared(selfSPKPriv, senderSessionPKDER)
		if err != nil {
			return nil, fmt.Errorf("DH3 失败: %w", err)
		}
		ikm := make([]byte, 0, len(dh1)+len(dh2)+len(dh3))
		ikm = append(ikm, dh1...)
		ikm = append(ikm, dh2...)
		ikm = append(ikm, dh3...)
		return crypto.HKDFDerive(ikm, salt, []byte(crypto.Info3DH), crypto.WrapKeyLen)
	}
	// 1DH 接收方
	dh1, err := crypto.ECDHComputeShared(selfIKPriv, senderSessionPKDER)
	if err != nil {
		return nil, fmt.Errorf("DH1 失败: %w", err)
	}
	return crypto.HKDFDerive(dh1, salt, []byte(crypto.Info1DH), crypto.WrapKeyLen)
}

// convertRecipientsToStringMatrix 把 envelope["recipients"] 转为 [][]string。
//
// 兼容两种来源：
//   - 通过本包加密生成（[][]any，每行 []any 包字符串）
//   - 通过 json.Decoder 解析 envelope（[]any，每行 []any 包字符串）
func convertRecipientsToStringMatrix(raw any) ([][]string, error) {
	switch v := raw.(type) {
	case [][]string:
		out := make([][]string, len(v))
		for i, row := range v {
			cp := make([]string, len(row))
			copy(cp, row)
			out[i] = cp
		}
		return out, nil
	case []any:
		out := make([][]string, 0, len(v))
		for i, item := range v {
			row, err := convertRowToStrings(item)
			if err != nil {
				return nil, fmt.Errorf("recipients[%d]: %w", i, err)
			}
			out = append(out, row)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("recipients 类型不支持: %T", raw)
	}
}

func convertRowToStrings(item any) ([]string, error) {
	switch row := item.(type) {
	case []any:
		out := make([]string, len(row))
		for i, cell := range row {
			s, ok := cell.(string)
			if !ok {
				return nil, fmt.Errorf("第 %d 列非字符串: %T", i, cell)
			}
			out[i] = s
		}
		return out, nil
	case []string:
		cp := make([]string, len(row))
		copy(cp, row)
		return cp, nil
	default:
		return nil, fmt.Errorf("行类型不支持: %T", item)
	}
}

// decodeMerkleProof 把 envelope["merkle_proof"] 解析为 []crypto.ProofStep。
func decodeMerkleProof(raw any) ([]crypto.ProofStep, error) {
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("merkle_proof 类型不支持: %T", raw)
	}
	out := make([]crypto.ProofStep, 0, len(arr))
	for i, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("merkle_proof[%d] 类型不支持: %T", i, item)
		}
		sib, _ := obj["sibling"].(string)
		pos, _ := obj["position"].(string)
		out = append(out, crypto.ProofStep{Sibling: sib, Position: pos})
	}
	return out, nil
}

// 工具函数 ----------------------------------------------------------------

func safe(row []string, i int) string {
	if i < len(row) {
		return row[i]
	}
	return ""
}

func envStr(envelope map[string]any, key string) string {
	s, _ := envelope[key].(string)
	return s
}

func mapStr(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func rowContext(row []string) string {
	spkID := safe(row, 5)
	if spkID == "" {
		spkID = "<empty>"
	}
	return fmt.Sprintf("recipient=%s/%s; role=%s; key_source=%s; spk_id=%s",
		safe(row, 0), safe(row, 1), safe(row, 2), safe(row, 3), spkID)
}

func envelopeContext(envelope map[string]any, row []string) string {
	aad, _ := envelope["aad"].(map[string]any)
	messageID := v2String(aad["message_id"])
	if messageID == "" {
		messageID = v2String(envelope["message_id"])
	}
	groupID := v2String(aad["group_id"])
	if groupID == "" {
		groupID = v2String(envelope["group_id"])
	}
	if groupID == "" {
		groupID = "<p2p>"
	}
	return fmt.Sprintf("message_id=%s; group_id=%s; from=%s; from_device=%s; %s",
		messageID, groupID, v2String(aad["from"]), v2String(aad["from_device"]), rowContext(row))
}

func v2String(value any) string {
	s, _ := value.(string)
	return s
}
