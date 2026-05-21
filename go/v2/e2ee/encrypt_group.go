package e2ee

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/modelunion/aun-sdk-core/go/v2/crypto"
)

// EncryptGroupMessage 构造完整的 V2 Group 加密 envelope（type=e2ee.group_encrypted）。
//
// 与 P2P 引擎同构，差异在 AAD：
//   - AAD 多 group_id / epoch / state_commitment 字段
//   - envelope 顶层多 group_id / epoch，无 to / t_supplement
//   - targets 是单层 list（无 audit_recipients 区分）
//
// stateCommitment 为 nil 时填充 sv=0 的占位（兼容未启用 state 的群），
// 与 Python `encrypt_group_message` 字节级一致。
func EncryptGroupMessage(sender Sender, groupID string, epoch int, targets []Target,
	payload map[string]any, opts EncryptOptions, stateCommitment *StateCommitmentAAD) (map[string]any, error) {

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("encrypt_group: 生成 master_key 失败: %w", err)
	}
	msgNonce := make([]byte, 12)
	if _, err := rand.Read(msgNonce); err != nil {
		return nil, fmt.Errorf("encrypt_group: 生成 msg_nonce 失败: %w", err)
	}

	messageID := opts.MessageID
	if messageID == "" {
		messageID = "m-" + strings.ReplaceAll(uuid.New().String(), "-", "")
	}
	timestamp := opts.Timestamp
	if timestamp == 0 {
		timestamp = time.Now().UnixMilli()
	}

	wrapProtocolStr := deriveWrapProtocol(targets)

	// state_commitment 占位：与 Python 一致 sv=0 / hash="" / chain=""
	scAAD := map[string]any{
		"state_version": 0,
		"state_hash":    "",
		"state_chain":   "",
	}
	if stateCommitment != nil {
		scAAD["state_version"] = stateCommitment.StateVersion
		scAAD["state_hash"] = stateCommitment.StateHash
		scAAD["state_chain"] = stateCommitment.StateChain
	}

	aad := map[string]any{
		"from":             sender.AID,
		"from_device":      sender.DeviceID,
		"group_id":         groupID,
		"epoch":            epoch,
		"message_id":       messageID,
		"timestamp":        timestamp,
		"suite":            SuiteName,
		"wrap_protocol":    wrapProtocolStr,
		"state_commitment": scAAD,
	}

	plaintextBytes := crypto.CanonicalJSON(payload)
	aadBytes := crypto.CanonicalJSON(aad)

	ct, tag, err := crypto.AESGCMEncrypt(masterKey, msgNonce, plaintextBytes, aadBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt_group: 加密正文失败: %w", err)
	}

	senderSessionPriv, senderSessionPubDER, err := crypto.GenerateP256Keypair()
	if err != nil {
		return nil, fmt.Errorf("encrypt_group: 生成 sender_session keypair 失败: %w", err)
	}

	wrapSalt := computeWrapSalt(aadBytes, senderSessionPubDER, SuiteName)

	recipientsRows := make([][]string, 0, len(targets))
	for _, target := range targets {
		row, err := wrapForRecipient(target, masterKey, senderSessionPriv, sender.IKPriv, wrapSalt)
		if err != nil {
			return nil, fmt.Errorf("encrypt_group: wrap recipient %s/%s 失败: %w", target.AID, target.DeviceID, err)
		}
		recipientsRows = append(recipientsRows, row)
	}

	sortedRows := crypto.SortRecipients(recipientsRows)
	digestHex := crypto.ComputeMerkleRoot(sortedRows)

	digestBytes, err := hex.DecodeString(digestHex)
	if err != nil {
		return nil, fmt.Errorf("encrypt_group: 解析 digest 失败: %w", err)
	}

	signInput := make([]byte, 0, len(ct)+len(tag)+len(aadBytes)+len(digestBytes))
	signInput = append(signInput, ct...)
	signInput = append(signInput, tag...)
	signInput = append(signInput, aadBytes...)
	signInput = append(signInput, digestBytes...)
	senderSig, err := crypto.ECDSASignRaw(sender.IKPriv, signInput)
	if err != nil {
		return nil, fmt.Errorf("encrypt_group: ECDSA 签名失败: %w", err)
	}

	certFp := computeCertFingerprint(sender.IKPubDER)

	recipientsAny := make([]any, len(sortedRows))
	for i, row := range sortedRows {
		anyRow := make([]any, len(row))
		for j, v := range row {
			anyRow[j] = v
		}
		recipientsAny[i] = anyRow
	}

	envelope := map[string]any{
		"type":                    "e2ee.group_encrypted",
		"version":                 "v2",
		"suite":                   SuiteName,
		"msg_type":                "original",
		"group_id":                groupID,
		"epoch":                   epoch,
		"t_send":                  timestamp,
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

	// protected_headers / context：HMAC 签名（与 V1 对齐），不进 AAD
	// payload_type 自动注入 + value 转 string（与 Python _normalize_headers 对齐）
	normalizedHeaders, err := normalizeProtectedHeaders(opts.ProtectedHeaders, payload)
	if err != nil {
		return nil, fmt.Errorf("encrypt_group: protected_headers 无效: %w", err)
	}
	if len(normalizedHeaders) > 0 {
		envelope["protected_headers"] = withMetadataAuth(normalizedHeaders, masterKey, protectedHeadersDomain)
	}
	if len(opts.Context) > 0 {
		envelope["context"] = withMetadataAuth(opts.Context, masterKey, protectedContextDomain)
	}

	return envelope, nil
}
