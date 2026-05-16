package aun

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
	"golang.org/x/crypto/hkdf"
)

func groupKeyResponseSignData(payload map[string]any) []byte {
	fields := []string{
		fmt.Sprint(valueOrDefault(payload["response_version"], 1)),
		fmt.Sprint(payload["group_id"]),
		fmt.Sprint(valueOrDefault(payload["epoch"], 0)),
		fmt.Sprint(payload["requester_aid"]),
		fmt.Sprint(payload["request_id"]),
		fmt.Sprint(payload["responder_aid"]),
		fmt.Sprint(payload["commitment"]),
		strings.Join(sorted(toStringSlice(payload["member_aids"])), "|"),
		fmt.Sprint(valueOrDefault(payload["issued_at"], 0)),
	}
	return []byte(strings.Join(fields, "\n"))
}

func valueOrDefault(v any, fallback any) any {
	if v == nil || fmt.Sprint(v) == "" {
		return fallback
	}
	return v
}

func SignGroupKeyResponse(payload map[string]any, privateKeyPEM string) (map[string]any, error) {
	signed := copyMapShallow(payload)
	if signed["response_version"] == nil {
		signed["response_version"] = 1
	}
	if signed["issued_at"] == nil {
		signed["issued_at"] = time.Now().UnixMilli()
	}
	priv, err := parseECPrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(groupKeyResponseSignData(signed))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		return nil, err
	}
	signed["response_signature"] = base64.StdEncoding.EncodeToString(sig)
	return signed, nil
}

func VerifyGroupKeyResponseSignature(payload map[string]any, responderCertPEM []byte) bool {
	sigB64, _ := payload["response_signature"].(string)
	if sigB64 == "" {
		return false
	}
	cert, err := parseCertPEM(responderCertPEM)
	if err != nil {
		return false
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	hash := sha256.Sum256(groupKeyResponseSignData(payload))
	return ecdsa.VerifyASN1(pub, hash[:], sig)
}

type groupSecretEpochLoader interface {
	LoadGroupSecretEpoch(aid, groupID string, epoch *int) (map[string]any, error)
}

type groupSecretEpochListLoader interface {
	LoadGroupSecretEpochs(aid, groupID string) ([]map[string]any, error)
}

type groupSecretTransitionStore interface {
	StoreGroupSecretTransition(aid, groupID string, opts keystore.GroupSecretTransitionOptions) (bool, error)
}

type groupSecretEpochStore interface {
	StoreGroupSecretEpoch(aid, groupID string, opts keystore.GroupSecretTransitionOptions) (bool, error)
}

type groupSecretPendingDiscardStore interface {
	DiscardPendingGroupSecretState(aid, groupID string, epoch int, rotationID string) (bool, error)
}

type groupOldEpochCleanupStore interface {
	CleanupGroupOldEpochsState(aid, groupID string, cutoffMs int64) (int, error)
}

type groupSecretIDLister interface {
	ListGroupSecretIDs(aid string) ([]string, error)
}

type groupSecretDeleteStore interface {
	DeleteGroupSecretState(aid, groupID string) error
}

// ── 群组 AAD 字段 ──────────────────────────────────────────

var (
	aadFieldsGroup = []string{
		"group_id", "from", "message_id", "timestamp",
		"epoch", "encryption_mode", "suite",
	}
	aadMatchFieldsGroup = []string{
		"group_id", "from", "message_id",
		"epoch", "encryption_mode", "suite",
	}
)

func loadKeyStoreGroupEpoch(ks keystore.KeyStore, aid, groupID string, epoch *int) map[string]any {
	if rowStore, ok := ks.(groupSecretEpochLoader); ok {
		entry, err := rowStore.LoadGroupSecretEpoch(aid, groupID, epoch)
		if err == nil {
			return entry
		}
	}
	return nil
}

func loadKeyStoreGroupEpochs(ks keystore.KeyStore, aid, groupID string) []map[string]any {
	if rowStore, ok := ks.(groupSecretEpochListLoader); ok {
		entries, err := rowStore.LoadGroupSecretEpochs(aid, groupID)
		if err == nil {
			return entries
		}
	}
	return nil
}

func storeKeyStoreGroupTransition(ks keystore.KeyStore, aid, groupID string, epoch int, groupSecret []byte, commitment string, memberAIDs []string, opts GroupSecretStoreOptions) (bool, bool, error) {
	rowStore, ok := ks.(groupSecretTransitionStore)
	if !ok {
		return false, false, nil
	}
	stored, err := rowStore.StoreGroupSecretTransition(aid, groupID, keystore.GroupSecretTransitionOptions{
		Epoch:                      epoch,
		Secret:                     base64.StdEncoding.EncodeToString(groupSecret),
		Commitment:                 commitment,
		MemberAIDs:                 memberAIDs,
		EpochChain:                 strings.TrimSpace(opts.EpochChain),
		PendingRotationID:          strings.TrimSpace(opts.PendingRotationID),
		EpochChainUnverified:       opts.EpochChainUnverified,
		EpochChainUnverifiedSet:    opts.EpochChainUnverifiedSet,
		EpochChainUnverifiedReason: strings.TrimSpace(opts.EpochChainUnverifiedReason),
		OldEpochRetentionMillis:    int64(OldEpochRetentionSeconds) * 1000,
	})
	return stored, true, err
}

func storeKeyStoreGroupEpoch(ks keystore.KeyStore, aid, groupID string, epoch int, groupSecret []byte, commitment string, memberAIDs []string, opts GroupSecretStoreOptions) (bool, bool, error) {
	rowStore, ok := ks.(groupSecretEpochStore)
	if !ok {
		return false, false, nil
	}
	stored, err := rowStore.StoreGroupSecretEpoch(aid, groupID, keystore.GroupSecretTransitionOptions{
		Epoch:                      epoch,
		Secret:                     base64.StdEncoding.EncodeToString(groupSecret),
		Commitment:                 commitment,
		MemberAIDs:                 memberAIDs,
		EpochChain:                 strings.TrimSpace(opts.EpochChain),
		PendingRotationID:          strings.TrimSpace(opts.PendingRotationID),
		EpochChainUnverified:       opts.EpochChainUnverified,
		EpochChainUnverifiedSet:    opts.EpochChainUnverifiedSet,
		EpochChainUnverifiedReason: strings.TrimSpace(opts.EpochChainUnverifiedReason),
		OldEpochRetentionMillis:    int64(OldEpochRetentionSeconds) * 1000,
	})
	return stored, true, err
}

func cleanupKeyStoreGroupOldEpochs(ks keystore.KeyStore, aid, groupID string, cutoffMs int64) int {
	if structured, ok := ks.(groupOldEpochCleanupStore); ok {
		removed, err := structured.CleanupGroupOldEpochsState(aid, groupID, cutoffMs)
		if err == nil {
			return removed
		}
		return 0
	}
	pkgLogEG().Warn("keystore does not support CleanupGroupOldEpochsState, skipping old epoch cleanup")
	return 0
}

func listKeyStoreGroupIDs(ks keystore.KeyStore, aid string) []string {
	if lister, ok := ks.(groupSecretIDLister); ok {
		groupIDs, err := lister.ListGroupSecretIDs(aid)
		if err == nil {
			return groupIDs
		}
		pkgLogEG().Warn("ListGroupSecretIDs failed: %v", err)
	}
	return nil
}

// ── 群组消息加密（纯函数）──────────────────────────────────

// EncryptGroupMessage 加密群组消息，返回 e2ee.group_encrypted 信封
// senderPrivateKeyPEM 可选，传入时附加发送方 ECDSA 签名（不可否认性）
func EncryptGroupMessage(
	groupSecret []byte,
	payload map[string]any,
	groupID, senderAID, messageID string,
	timestamp int64,
	epoch int,
	senderPrivateKeyPEM string,
	senderCertPEM []byte,
	options ...E2EEEncryptOptions,
) (map[string]any, error) {
	opts := firstE2EEEncryptOptions(options)
	// 派生单条消息密钥
	msgKey, err := deriveGroupMsgKey(groupSecret, groupID, messageID)
	if err != nil {
		return nil, fmt.Errorf("group message key derivation failed: %w", err)
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize payload: %w", err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	aad := map[string]any{
		"group_id":        groupID,
		"from":            senderAID,
		"message_id":      messageID,
		"timestamp":       timestamp,
		"epoch":           epoch,
		"encryption_mode": ModeEpochGroupKey,
		"suite":           SuiteP256,
	}
	envelope := map[string]any{
		"type":            "e2ee.group_encrypted",
		"version":         "1",
		"encryption_mode": ModeEpochGroupKey,
		"suite":           SuiteP256,
		"epoch":           epoch,
	}
	if err := copyOptionalEnvelopeMetadata(envelope, payload, opts, msgKey); err != nil {
		return nil, err
	}
	aadBytes := aadBytesGroup(aad)

	block, err := aes.NewCipher(msgKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	ciphertextWithTag := gcm.Seal(nil, nonce, plaintext, aadBytes)
	tagStart := len(ciphertextWithTag) - 16
	ciphertext := ciphertextWithTag[:tagStart]
	tag := ciphertextWithTag[tagStart:]

	envelope["nonce"] = base64.StdEncoding.EncodeToString(nonce)
	envelope["ciphertext"] = base64.StdEncoding.EncodeToString(ciphertext)
	envelope["tag"] = base64.StdEncoding.EncodeToString(tag)
	envelope["aad"] = aad

	// 发送方签名
	if senderPrivateKeyPEM != "" {
		pk, err := parseECPrivateKeyPEM(senderPrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse sender private key: %w", err)
		}
		signPayload := make([]byte, 0, len(ciphertext)+len(tag)+len(aadBytes))
		signPayload = append(signPayload, ciphertext...)
		signPayload = append(signPayload, tag...)
		signPayload = append(signPayload, aadBytes...)
		hash := sha256.Sum256(signPayload)
		sig, err := ecdsa.SignASN1(rand.Reader, pk, hash[:])
		if err != nil {
			return nil, fmt.Errorf("group message sender signature failed: %w", err)
		}
		envelope["sender_signature"] = base64.StdEncoding.EncodeToString(sig)
		if len(senderCertPEM) > 0 {
			if cert, certErr := parseCertPEM(senderCertPEM); certErr == nil {
				envelope["sender_cert_fingerprint"] = certificateSHA256Fingerprint(cert)
			}
		}
	}

	return envelope, nil
}

// DecryptGroupMessage 解密群组消息（纯函数）
// groupSecrets: {epoch: groupSecretBytes} 映射
// senderCertPEM: 发送方证书，用于验证签名
// requireSignature: 为 true 时强制要求签名 + 证书验证
func DecryptGroupMessage(
	groupSecrets map[int][]byte,
	message map[string]any,
	senderCertPEM []byte,
	requireSignature bool,
) map[string]any {
	payload, ok := message["payload"].(map[string]any)
	if !ok {
		return nil
	}
	payloadType, _ := payload["type"].(string)
	if payloadType != "e2ee.group_encrypted" {
		return nil
	}

	epoch := int(toInt64(payload["epoch"]))
	groupSecret, ok := groupSecrets[epoch]
	if !ok {
		return nil
	}

	// 解析 AAD 和路由字段
	aad, _ := payload["aad"].(map[string]any)
	outerGroupID, _ := message["group_id"].(string)

	var groupID, msgID, aadFrom string
	if aad != nil {
		groupID, _ = aad["group_id"].(string)
		if groupID == "" {
			groupID = outerGroupID
		}
		msgID, _ = aad["message_id"].(string)
		if msgID == "" {
			msgID, _ = message["message_id"].(string)
		}
		aadFrom, _ = aad["from"].(string)

		// 外层路由字段校验
		if outerGroupID != "" && groupID != outerGroupID {
			return nil
		}
		if aadFrom != "" {
			outerFrom, _ := message["from"].(string)
			outerSender, _ := message["sender_aid"].(string)
			if outerFrom != "" && outerFrom != aadFrom {
				return nil
			}
			if outerSender != "" && outerSender != aadFrom {
				return nil
			}
		}
	} else {
		groupID = outerGroupID
		msgID, _ = message["message_id"].(string)
	}

	if groupID == "" || msgID == "" {
		return nil
	}

	// 派生消息密钥 + 解密
	msgKey, err := deriveGroupMsgKey(groupSecret, groupID, msgID)
	if err != nil {
		return nil
	}

	// GO-003: 安全类型断言，避免无效 payload 字段导致 panic
	nonceStr, _ := payload["nonce"].(string)
	ciphertextStr, _ := payload["ciphertext"].(string)
	tagStr, _ := payload["tag"].(string)
	if nonceStr == "" || ciphertextStr == "" || tagStr == "" {
		return nil
	}
	nonce, _ := base64.StdEncoding.DecodeString(nonceStr)
	ciphertext, _ := base64.StdEncoding.DecodeString(ciphertextStr)
	tag, _ := base64.StdEncoding.DecodeString(tagStr)

	var aadBytes []byte
	if aad != nil {
		aadBytes = aadBytesGroup(aad)
	}
	if !verifyEnvelopeMetadataAuth(payload, msgKey) {
		return nil
	}

	plaintext, err := aesGCMDecrypt(msgKey, nonce, ciphertext, tag, aadBytes)
	if err != nil {
		return nil
	}

	var decoded map[string]any
	if err := json.Unmarshal(plaintext, &decoded); err != nil {
		return nil
	}
	if !validateDecryptedEnvelopeMetadata(decoded, payload, message) {
		return nil
	}

	result := copyMapShallow(message)
	result["payload"] = decoded
	result["encrypted"] = true
	e2ee := map[string]any{
		"encryption_mode": ModeEpochGroupKey,
		"suite":           SuiteP256,
		"epoch":           epoch,
		"sender_verified": false,
	}
	if protectedHeaders := exposedEnvelopeMetadata(payload["protected_headers"]); protectedHeaders != nil {
		e2ee["protected_headers"] = protectedHeaders
	}
	if context := exposedEnvelopeMetadata(payload["context"]); context != nil {
		e2ee["context"] = context
	}
	result["e2ee"] = e2ee

	// 发送方签名验证
	sigB64, _ := payload["sender_signature"].(string)

	if requireSignature {
		// 零信任模式：必须有签名且有证书
		if sigB64 == "" {
			pkgLogEG().Error("rejected unsigned group message: group=%s from=%s", groupID, aadFrom)
			return nil
		}
		if senderCertPEM == nil {
			pkgLogEG().Error("rejected group message: has signature but no certificate: group=%s from=%s", groupID, aadFrom)
			return nil
		}
		if !verifyGroupSenderSignature(senderCertPEM, sigB64, ciphertext, tag, aadBytes) {
			pkgLogEG().Error("group message signature verification failed: group=%s from=%s", groupID, aadFrom)
			return nil
		}
		e2ee["sender_verified"] = true
	} else if senderCertPEM != nil {
		// 非零信任但有证书：有证书时强制验签
		if sigB64 == "" {
			pkgLogEG().Error("rejected unsigned group message: group=%s from=%s", groupID, aadFrom)
			return nil
		}
		if !verifyGroupSenderSignature(senderCertPEM, sigB64, ciphertext, tag, aadBytes) {
			pkgLogEG().Error("group message signature verification failed: group=%s from=%s", groupID, aadFrom)
			return nil
		}
		e2ee["sender_verified"] = true
	}

	return result
}

// verifyGroupSenderSignature 验证群消息发送方签名
func verifyGroupSenderSignature(certPEM []byte, sigB64 string, ciphertext, tag, aadBytes []byte) bool {
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return false
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	verifyPayload := make([]byte, 0, len(ciphertext)+len(tag)+len(aadBytes))
	verifyPayload = append(verifyPayload, ciphertext...)
	verifyPayload = append(verifyPayload, tag...)
	verifyPayload = append(verifyPayload, aadBytes...)
	hash := sha256.Sum256(verifyPayload)
	return ecdsa.VerifyASN1(pub, hash[:], sigBytes)
}

// ── Epoch Transcript Chain ─────────────────────────────────

var epochChainGenesisPrefix = []byte("aun-epoch-chain:genesis")

// ComputeEpochChain 计算 epoch transcript chain
// prevChain 为空字符串时表示 genesis（首个 epoch）
func ComputeEpochChain(prevChain string, epoch int, commitment string, rotatorAID string) string {
	var prefix []byte
	if prevChain == "" {
		prefix = epochChainGenesisPrefix
	} else {
		decoded, err := hex.DecodeString(prevChain)
		if err != nil {
			// 非法 hex 输入，使用原始字节降级
			prefix = []byte(prevChain)
		} else {
			prefix = decoded
		}
	}
	epochBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(epochBytes, uint32(epoch))
	data := append(prefix, epochBytes...)
	data = append(data, []byte(commitment)...)
	data = append(data, []byte(rotatorAID)...)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// VerifyEpochChain 验证 epoch transcript chain（常量时间比较）
func VerifyEpochChain(epochChain string, prevChain string, epoch int, commitment string, rotatorAID string) bool {
	expected := ComputeEpochChain(prevChain, epoch, commitment, rotatorAID)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(epochChain)) == 1
}

// ── State Hash ────────────────────────────────────────────

// MemberRole represents a member's AID and role for state hash computation.
type MemberRole struct {
	AID  string `json:"aid"`
	Role string `json:"role"`
}

// ComputeStateHash computes the group state hash binding members+roles+policy.
// state_hash = SHA-256(group_id | 0x00 | state_version(uint64 BE) | 0x00 |
//
//	key_epoch(uint64 BE) | 0x00 | membership_block | 0x00 |
//	policy_block | 0x00 | prev_state_hash(32 bytes))
func ComputeStateHash(groupID string, stateVersion, keyEpoch int64, members []MemberRole, policy map[string]interface{}, prevStateHash string) string {
	// Sort members by AID
	sorted := make([]MemberRole, len(members))
	copy(sorted, members)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].AID < sorted[j].AID })

	// membership_block
	parts := make([]string, len(sorted))
	for i, m := range sorted {
		parts[i] = m.AID + ":" + m.Role
	}
	membershipBlock := strings.Join(parts, "|")

	// policy_block: canonical JSON (Go json.Marshal sorts keys by default)
	policyBlock := ""
	if len(policy) > 0 {
		b, _ := json.Marshal(policy)
		policyBlock = string(b)
	}

	// prev_state_hash bytes
	var prevBytes [32]byte
	if prevStateHash != "" {
		decoded, _ := hex.DecodeString(prevStateHash)
		copy(prevBytes[:], decoded)
	}

	// Concatenate and hash
	var buf bytes.Buffer
	buf.WriteString(groupID)
	buf.WriteByte(0x00)
	_ = binary.Write(&buf, binary.BigEndian, stateVersion)
	buf.WriteByte(0x00)
	_ = binary.Write(&buf, binary.BigEndian, keyEpoch)
	buf.WriteByte(0x00)
	buf.WriteString(membershipBlock)
	buf.WriteByte(0x00)
	buf.WriteString(policyBlock)
	buf.WriteByte(0x00)
	buf.Write(prevBytes[:])

	h := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(h[:])
}

// ── Membership Commitment ──────────────────────────────────

// ComputeMembershipCommitment 计算成员承诺哈希
// commitment = SHA-256(sort(aids).join("|") + "|" + str(epoch) + "|" + group_id + "|" + SHA256(group_secret).hex())
func ComputeMembershipCommitment(memberAIDs []string, epoch int, groupID string, groupSecret []byte) string {
	sorted := make([]string, len(memberAIDs))
	copy(sorted, memberAIDs)
	sort.Strings(sorted)

	secretHash := sha256.Sum256(groupSecret)
	data := strings.Join(sorted, "|") + "|" + fmt.Sprintf("%d", epoch) + "|" + groupID + "|" + fmt.Sprintf("%x", secretHash)

	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// VerifyMembershipCommitment 验证成员承诺
// 1. 重算 commitment 是否匹配
// 2. 检查 myAID 是否在 memberAIDs 中
func VerifyMembershipCommitment(commitment string, memberAIDs []string, epoch int, groupID, myAID string, groupSecret []byte) bool {
	found := false
	for _, aid := range memberAIDs {
		if aid == myAID {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	expected := ComputeMembershipCommitment(memberAIDs, epoch, groupID, groupSecret)
	// 常量时间比较
	if len(expected) != len(commitment) {
		return false
	}
	result := byte(0)
	for i := 0; i < len(expected); i++ {
		result |= expected[i] ^ commitment[i]
	}
	return result == 0
}

// ── Membership Manifest ────────────────────────────────────

// BuildMembershipManifest 构建 Membership Manifest（未签名）
func BuildMembershipManifest(
	groupID string, epoch int, prevEpoch *int,
	memberAIDs, added, removed []string,
	initiatorAID string,
) map[string]any {
	sortedMembers := make([]string, len(memberAIDs))
	copy(sortedMembers, memberAIDs)
	sort.Strings(sortedMembers)

	sortedAdded := make([]string, 0)
	if added != nil {
		sortedAdded = make([]string, len(added))
		copy(sortedAdded, added)
		sort.Strings(sortedAdded)
	}

	sortedRemoved := make([]string, 0)
	if removed != nil {
		sortedRemoved = make([]string, len(removed))
		copy(sortedRemoved, removed)
		sort.Strings(sortedRemoved)
	}

	result := map[string]any{
		"manifest_version": 1,
		"group_id":         groupID,
		"epoch":            epoch,
		"prev_epoch":       prevEpoch,
		"member_aids":      sortedMembers,
		"added":            sortedAdded,
		"removed":          sortedRemoved,
		"initiator_aid":    initiatorAID,
		"issued_at":        time.Now().UnixMilli(),
	}
	return result
}

// manifestSignData 序列化 manifest 为签名输入
func manifestSignData(manifest map[string]any) []byte {
	prevEpochStr := ""
	if pe := manifest["prev_epoch"]; pe != nil {
		prevEpochStr = numToStr(pe)
	}

	memberAIDs := toStringSlice(manifest["member_aids"])
	addedAIDs := toStringSlice(manifest["added"])
	removedAIDs := toStringSlice(manifest["removed"])

	fields := []string{
		numToStr(manifest["manifest_version"]),
		fmt.Sprintf("%v", manifest["group_id"]),
		numToStr(manifest["epoch"]),
		prevEpochStr,
		strings.Join(memberAIDs, "|"),
		strings.Join(addedAIDs, "|"),
		strings.Join(removedAIDs, "|"),
		fmt.Sprintf("%v", manifest["initiator_aid"]),
		numToStr(manifest["issued_at"]),
	}
	return []byte(strings.Join(fields, "\n"))
}

// numToStr 将数值类型转为字符串（避免 float64 的科学计数法，处理指针类型）
func numToStr(v any) string {
	switch n := v.(type) {
	case float64:
		return fmt.Sprintf("%d", int64(n))
	case int:
		return fmt.Sprintf("%d", n)
	case int64:
		return fmt.Sprintf("%d", n)
	case *int:
		if n != nil {
			return fmt.Sprintf("%d", *n)
		}
		return ""
	case *int64:
		if n != nil {
			return fmt.Sprintf("%d", *n)
		}
		return ""
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

// SignMembershipManifest 签名 Membership Manifest
func SignMembershipManifest(manifest map[string]any, privateKeyPEM string) (map[string]any, error) {
	pk, err := parseECPrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	signData := manifestSignData(manifest)
	hash := sha256.Sum256(signData)
	sig, err := ecdsa.SignASN1(rand.Reader, pk, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	signed := copyMapShallow(manifest)
	signed["signature"] = base64.StdEncoding.EncodeToString(sig)
	return signed, nil
}

// VerifyMembershipManifest 验证 Membership Manifest 签名
func VerifyMembershipManifest(manifest map[string]any, initiatorCertPEM []byte) (bool, error) {
	sigB64, _ := manifest["signature"].(string)
	if sigB64 == "" {
		return false, nil
	}
	cert, err := parseCertPEM(initiatorCertPEM)
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("certificate is not an EC public key")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}
	signData := manifestSignData(manifest)
	hash := sha256.Sum256(signData)
	return ecdsa.VerifyASN1(pub, hash[:], sigBytes), nil
}

// ── Group Secret 生命周期管理 ──────────────────────────────

// groupSecretMu 保护 StoreGroupSecret 的 load-check-save 原子性（per aid:groupID 粒度）
type countedGroupSecretLock struct {
	mu   sync.Mutex
	refs int
}

var groupSecretMu struct {
	sync.Mutex
	locks map[string]*countedGroupSecretLock
}

func init() {
	groupSecretMu.locks = make(map[string]*countedGroupSecretLock)
}

func acquireGroupSecretLock(aid, groupID string) (string, *countedGroupSecretLock) {
	key := aid + ":" + groupID
	groupSecretMu.Lock()
	mu, ok := groupSecretMu.locks[key]
	if !ok {
		mu = &countedGroupSecretLock{}
		groupSecretMu.locks[key] = mu
	}
	mu.refs++
	groupSecretMu.Unlock()
	mu.mu.Lock()
	return key, mu
}

func releaseGroupSecretLock(key string, lock *countedGroupSecretLock) {
	lock.mu.Unlock()
	groupSecretMu.Lock()
	lock.refs--
	if lock.refs <= 0 && groupSecretMu.locks[key] == lock {
		delete(groupSecretMu.locks, key)
	}
	groupSecretMu.Unlock()
}

// GenerateGroupSecret 生成 32 字节随机 group_secret
func GenerateGroupSecret() []byte {
	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		panic(fmt.Sprintf("crypto/rand unavailable, cannot generate secure random: %v", err))
	}
	return secret
}

type GroupSecretStoreOptions struct {
	EpochChain                 string
	PendingRotationID          string
	EpochChainUnverified       bool
	EpochChainUnverifiedSet    bool
	EpochChainUnverifiedReason string
}

// StoreGroupSecret 存储 group_secret 到 keystore metadata
// 拒绝低于本地最新 epoch 的写入（防降级攻击）
// 返回 (true, nil) 已存储; (false, nil) epoch 降级被拒; (false, err) 存储出错
// 整个 load-check-save 操作在 per-group mutex 保护下原子执行
func StoreGroupSecret(ks keystore.KeyStore, aid, groupID string, epoch int, groupSecret []byte, commitment string, memberAIDs []string, epochChain string, pendingRotationIDs ...string) (bool, error) {
	pendingRotationID := ""
	if len(pendingRotationIDs) > 0 {
		pendingRotationID = strings.TrimSpace(pendingRotationIDs[0])
	}
	return StoreGroupSecretWithOptions(ks, aid, groupID, epoch, groupSecret, commitment, memberAIDs, GroupSecretStoreOptions{
		EpochChain:        epochChain,
		PendingRotationID: pendingRotationID,
	})
}

// DiscardPendingGroupSecret 仅回滚指定 rotation 写入的本地 target epoch key。
func DiscardPendingGroupSecret(ks keystore.KeyStore, aid, groupID string, epoch int, rotationID string) (bool, error) {
	rotationID = strings.TrimSpace(rotationID)
	if rotationID == "" {
		return false, nil
	}
	lockKey, mu := acquireGroupSecretLock(aid, groupID)
	defer releaseGroupSecretLock(lockKey, mu)

	if rowStore, ok := ks.(groupSecretPendingDiscardStore); ok {
		return rowStore.DiscardPendingGroupSecretState(aid, groupID, epoch, rotationID)
	}
	return false, fmt.Errorf("keystore does not support DiscardPendingGroupSecretState")
}

func StoreGroupSecretWithOptions(ks keystore.KeyStore, aid, groupID string, epoch int, groupSecret []byte, commitment string, memberAIDs []string, opts GroupSecretStoreOptions) (bool, error) {
	lockKey, mu := acquireGroupSecretLock(aid, groupID)
	defer releaseGroupSecretLock(lockKey, mu)

	pkgLogEG().Debug("StoreGroupSecret started: group=%s epoch=%d aid=%s", groupID, epoch, aid)
	if stored, handled, err := storeKeyStoreGroupTransition(ks, aid, groupID, epoch, groupSecret, commitment, memberAIDs, opts); handled {
		if err != nil {
			pkgLogEG().Error("StoreGroupSecret failed: group=%s epoch=%d err=%v", groupID, epoch, err)
			return false, fmt.Errorf("failed to save group_secret: %w", err)
		}
		if stored {
			pkgLogEG().Debug("StoreGroupSecret succeeded: group=%s epoch=%d", groupID, epoch)
		} else {
			pkgLogEG().Debug("StoreGroupSecret rejected (epoch downgrade): group=%s epoch=%d", groupID, epoch)
		}
		return stored, nil
	}
	return false, fmt.Errorf("keystore does not support StoreGroupSecretTransition")
}

// StoreGroupSecretEpochWithOptions 保存指定 epoch key。低于 current 时写入 old epoch row，不覆盖 current。
func StoreGroupSecretEpochWithOptions(ks keystore.KeyStore, aid, groupID string, epoch int, groupSecret []byte, commitment string, memberAIDs []string, opts GroupSecretStoreOptions) (bool, error) {
	lockKey, mu := acquireGroupSecretLock(aid, groupID)
	defer releaseGroupSecretLock(lockKey, mu)

	if stored, handled, err := storeKeyStoreGroupEpoch(ks, aid, groupID, epoch, groupSecret, commitment, memberAIDs, opts); handled {
		if err != nil {
			return false, fmt.Errorf("failed to save group_secret epoch: %w", err)
		}
		return stored, nil
	}
	return false, fmt.Errorf("keystore does not support StoreGroupSecretEpoch")
}

// LoadGroupSecret 加载 group_secret
// epoch=nil 时返回最新 epoch；指定 epoch 时按 epoch row 查询。
func LoadGroupSecret(ks keystore.KeyStore, aid, groupID string, epoch *int) (map[string]any, error) {
	entry := loadKeyStoreGroupEpoch(ks, aid, groupID, epoch)
	if entry == nil {
		return nil, nil
	}

	entryEpoch := int(toInt64(entry["epoch"]))
	secretStr, _ := entry["secret"].(string)
	if secretStr == "" {
		return nil, nil
	}
	secretBytes, err := base64.StdEncoding.DecodeString(secretStr)
	if err != nil {
		return nil, nil
	}
	result := map[string]any{
		"epoch":       entryEpoch,
		"secret":      secretBytes,
		"commitment":  entry["commitment"],
		"member_aids": toStringSlice(entry["member_aids"]),
	}
	if ec, ok := entry["epoch_chain"]; ok && ec != nil && ec != "" {
		result["epoch_chain"] = ec
	}
	if pending, ok := entry["pending_rotation_id"]; ok && pending != nil && pending != "" {
		result["pending_rotation_id"] = pending
	}
	if uv, ok := entry["epoch_chain_unverified"]; ok && uv != nil {
		result["epoch_chain_unverified"] = uv
	}
	if reason, ok := entry["epoch_chain_unverified_reason"]; ok && reason != nil && reason != "" {
		result["epoch_chain_unverified_reason"] = reason
	}
	return result, nil
}

type epochChainAssessment struct {
	ok         bool
	set        bool
	unverified bool
	reason     string
}

func assessIncomingEpochChain(
	ks keystore.KeyStore,
	aid string,
	groupID string,
	epoch int,
	commitment string,
	incomingChain string,
	rotationID string,
	rotatorAID string,
	source string,
) epochChainAssessment {
	chain := strings.TrimSpace(incomingChain)
	rid := strings.TrimSpace(rotationID)
	rotator := strings.TrimSpace(rotatorAID)

	if rid != "" && chain == "" {
		pkgLogEG().Error("rejected rotation key missing epoch_chain: source=%s group=%s epoch=%d rotation=%s", source, groupID, epoch, rid)
		return epochChainAssessment{ok: false}
	}

	currentData, _ := LoadGroupSecret(ks, aid, groupID, nil)
	if currentData != nil && int(toInt64(currentData["epoch"])) == epoch {
		currentChain, _ := currentData["epoch_chain"].(string)
		currentPendingRotationID, _ := currentData["pending_rotation_id"].(string)
		if chain != "" && currentChain == chain {
			return epochChainAssessment{ok: true}
		}
		if rid != "" && chain != "" && currentChain != "" && currentChain != chain {
			if !(strings.TrimSpace(currentPendingRotationID) != "" && strings.TrimSpace(currentPendingRotationID) != rid) {
				pkgLogEG().Error("rejected same-epoch forked chain: source=%s group=%s epoch=%d rotation=%s", source, groupID, epoch, rid)
				return epochChainAssessment{ok: false}
			}
		}
	}

	prevEpoch := epoch - 1
	prevData, _ := LoadGroupSecret(ks, aid, groupID, &prevEpoch)
	prevChain := ""
	if prevData != nil {
		prevChain, _ = prevData["epoch_chain"].(string)
	}
	if chain == "" {
		return epochChainAssessment{ok: true, set: true, unverified: true, reason: "missing_epoch_chain"}
	}
	if prevChain == "" {
		return epochChainAssessment{ok: true, set: true, unverified: true, reason: "missing_prev_chain"}
	}
	if rotator == "" {
		if rid != "" {
			pkgLogEG().Error("rejected rotation key missing rotator_aid: source=%s group=%s epoch=%d rotation=%s", source, groupID, epoch, rid)
			return epochChainAssessment{ok: false}
		}
		return epochChainAssessment{ok: true, set: true, unverified: true, reason: "missing_rotator_aid"}
	}
	if !VerifyEpochChain(chain, prevChain, epoch, commitment, rotator) {
		expectedChain := ComputeEpochChain(prevChain, epoch, commitment, rotator)
		pkgLogEG().Warn("DEBUG-CHAIN-VERIFY: FAILED group=%s epoch=%d source=%s rotation=%s rotator=%s incoming_chain=%s expected_chain=%s prev_chain=%s commitment=%s",
			groupID, epoch, source, rid, rotator, chain[:min(len(chain), 16)], expectedChain[:min(len(expectedChain), 16)], prevChain[:min(len(prevChain), 16)], commitment[:min(len(commitment), 16)])
		if rid != "" {
			pkgLogEG().Error("rejected rotation key with failed epoch_chain verification: source=%s group=%s epoch=%d rotation=%s", source, groupID, epoch, rid)
			return epochChainAssessment{ok: false}
		}
		pkgLogEG().Error("epoch_chain verification failed, accepting in compatibility mode and marking unverified: source=%s group=%s epoch=%d", source, groupID, epoch)
		return epochChainAssessment{ok: true, set: true, unverified: true, reason: "chain_mismatch_legacy"}
	}
	if rid == "" {
		return epochChainAssessment{ok: true, set: true, unverified: true, reason: "missing_rotation_id"}
	}
	return epochChainAssessment{ok: true, set: true, unverified: false}
}

// LoadAllGroupSecrets 加载某群组所有 epoch 的 group_secret
// 返回 {epoch: secretBytes} 映射
func LoadAllGroupSecrets(ks keystore.KeyStore, aid, groupID string) map[int][]byte {
	entries := loadKeyStoreGroupEpochs(ks, aid, groupID)
	if len(entries) == 0 {
		return nil
	}

	result := make(map[int][]byte)
	for _, entry := range entries {
		secretStr, _ := entry["secret"].(string)
		entryEpoch := int(toInt64(entry["epoch"]))
		if secretStr != "" {
			if decoded, err := base64.StdEncoding.DecodeString(secretStr); err == nil {
				result[entryEpoch] = decoded
			}
		}
	}

	return result
}

// CleanupOldEpochs 清理过期的旧 epoch 记录，返回 (清理数量, error)
func CleanupOldEpochs(ks keystore.KeyStore, aid, groupID string, retentionSeconds int) (int, error) {
	cutoffMs := time.Now().UnixMilli() - int64(retentionSeconds)*1000
	return cleanupKeyStoreGroupOldEpochs(ks, aid, groupID, cutoffMs), nil
}

// ── GroupReplayGuard 群组消息防重放守卫 ──────────────────────

// GroupReplayGuard 群组消息防重放守卫
// key = "{group_id}:{sender_aid}:{message_id}"，内置 LRU 裁剪
type GroupReplayGuard struct {
	mu      sync.Mutex
	seen    map[string]bool
	maxSize int
}

// NewGroupReplayGuard 创建防重放守卫
func NewGroupReplayGuard(maxSize int) *GroupReplayGuard {
	if maxSize <= 0 {
		maxSize = 50000
	}
	return &GroupReplayGuard{
		seen:    make(map[string]bool),
		maxSize: maxSize,
	}
}

// CheckAndRecord 检查并记录。返回 true 表示首次（通过），false 表示重放
func (g *GroupReplayGuard) CheckAndRecord(groupID, senderAID, messageID string) bool {
	key := groupID + ":" + senderAID + ":" + messageID
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen[key] {
		return false
	}
	g.seen[key] = true
	g.trim()
	return true
}

// IsSeen 仅检查是否已记录
func (g *GroupReplayGuard) IsSeen(groupID, senderAID, messageID string) bool {
	key := groupID + ":" + senderAID + ":" + messageID
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.seen[key]
}

// Record 仅记录，不检查
func (g *GroupReplayGuard) Record(groupID, senderAID, messageID string) {
	key := groupID + ":" + senderAID + ":" + messageID
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seen[key] = true
	g.trim()
}

// Unrecord 移除已记录的条目（解密失败回退时使用）
func (g *GroupReplayGuard) Unrecord(groupID, senderAID, messageID string) {
	key := groupID + ":" + senderAID + ":" + messageID
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.seen, key)
}

// Size 返回已记录的数量
func (g *GroupReplayGuard) Size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}

// trim LRU 裁剪（需在持锁状态调用）
func (g *GroupReplayGuard) trim() {
	if len(g.seen) > g.maxSize {
		trimCount := len(g.seen) - int(float64(g.maxSize)*0.8)
		i := 0
		for k := range g.seen {
			if i >= trimCount {
				break
			}
			delete(g.seen, k)
			i++
		}
	}
}

// Trim LRU 裁剪（供外部调用，自动加锁）
func (g *GroupReplayGuard) Trim() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.trim()
}

// ── GroupKeyRequestThrottle 密钥请求频率限制 ────────────────

// GroupKeyRequestThrottle 群组密钥请求/响应频率限制
type GroupKeyRequestThrottle struct {
	mu       sync.Mutex
	last     map[string]float64
	cooldown float64
}

// NewGroupKeyRequestThrottle 创建频率限制器
func NewGroupKeyRequestThrottle(cooldown float64) *GroupKeyRequestThrottle {
	if cooldown <= 0 {
		cooldown = 30.0
	}
	return &GroupKeyRequestThrottle{
		last:     make(map[string]float64),
		cooldown: cooldown,
	}
}

// Allow 检查是否允许操作。返回 true 并记录时间戳，或 false 表示被限制
func (t *GroupKeyRequestThrottle) Allow(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := float64(time.Now().UnixMilli()) / 1000.0
	if last, ok := t.last[key]; ok && (now-last) < t.cooldown {
		return false
	}
	t.last[key] = now
	return true
}

// Reset 重置指定 key 的频率限制
func (t *GroupKeyRequestThrottle) Reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.last, key)
}

// ── Group Key 分发与恢复协议 ──────────────────────────────

// BuildKeyDistribution 构建 group key 分发消息 payload
// manifest: 可选的已签名 Membership Manifest
func BuildKeyDistribution(
	groupID string, epoch int, groupSecret []byte,
	memberAIDs []string, distributedBy string,
	manifest map[string]any,
	epochChain string,
) map[string]any {
	commitment := ComputeMembershipCommitment(memberAIDs, epoch, groupID, groupSecret)
	sorted := make([]string, len(memberAIDs))
	copy(sorted, memberAIDs)
	sort.Strings(sorted)

	result := map[string]any{
		"type":           "e2ee.group_key_distribution",
		"group_id":       groupID,
		"epoch":          epoch,
		"group_secret":   base64.StdEncoding.EncodeToString(groupSecret),
		"commitment":     commitment,
		"member_aids":    sorted,
		"distributed_by": distributedBy,
		"distributed_at": time.Now().UnixMilli(),
	}
	if manifest != nil {
		result["manifest"] = manifest
	}
	if epochChain != "" {
		result["epoch_chain"] = epochChain
	}
	return result
}

// HandleKeyDistribution 处理收到的 group key 分发消息
// 验证 manifest 签名 -> commitment -> 成员资格 -> 存储
func HandleKeyDistribution(
	message map[string]any,
	ks keystore.KeyStore,
	aid string,
	initiatorCertPEM []byte,
) bool {
	payload := extractPayload(message)

	groupID, _ := payload["group_id"].(string)
	epoch := int(toInt64(payload["epoch"]))
	secretB64, _ := payload["group_secret"].(string)
	commitment, _ := payload["commitment"].(string)
	memberAIDs := toStringSlice(payload["member_aids"])
	epochChain, _ := payload["epoch_chain"].(string)

	pkgLogEG().Debug("HandleKeyDistribution started: group=%s epoch=%d aid=%s", groupID, epoch, aid)

	if groupID == "" || secretB64 == "" || commitment == "" {
		pkgLogEG().Error("HandleKeyDistribution params incomplete: group=%s epoch=%d", groupID, epoch)
		return false
	}

	// 验证 Membership Manifest 签名
	manifest, _ := payload["manifest"].(map[string]any)
	if initiatorCertPEM != nil {
		if manifest == nil {
			pkgLogEG().Error("rejected key distribution without manifest: group=%s epoch=%d", groupID, epoch)
			return false
		}
		valid, _ := VerifyMembershipManifest(manifest, initiatorCertPEM)
		if !valid {
			pkgLogEG().Error("manifest signature verification failed: group=%s epoch=%d", groupID, epoch)
			return false
		}
		// manifest 与分发消息一致性检查
		mGroupID, _ := manifest["group_id"].(string)
		mEpoch := int(toInt64(manifest["epoch"]))
		if mGroupID != groupID || mEpoch != epoch {
			return false
		}
		mMembers := toStringSlice(manifest["member_aids"])
		if !stringSliceEqual(sorted(mMembers), sorted(memberAIDs)) {
			return false
		}
	} else if manifest != nil {
		mGroupID, _ := manifest["group_id"].(string)
		mEpoch := int(toInt64(manifest["epoch"]))
		if mGroupID != groupID || mEpoch != epoch {
			return false
		}
		mMembers := toStringSlice(manifest["member_aids"])
		if !stringSliceEqual(sorted(mMembers), sorted(memberAIDs)) {
			return false
		}
	}

	groupSecret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		return false
	}

	// 验证 commitment
	if !VerifyMembershipCommitment(commitment, memberAIDs, epoch, groupID, aid, groupSecret) {
		pkgLogEG().Error("HandleKeyDistribution commitment verification failed: group=%s epoch=%d", groupID, epoch)
		return false
	}

	rotationID, _ := payload["rotation_id"].(string)
	chainAssessment := assessIncomingEpochChain(
		ks, aid, groupID, epoch, commitment, epochChain, rotationID,
		getStr(payload, "distributed_by", getStr(payload, "rotator_aid", "")),
		"key_distribution",
	)
	if !chainAssessment.ok {
		return false
	}

	ok, storeErr := StoreGroupSecretWithOptions(ks, aid, groupID, epoch, groupSecret, commitment, memberAIDs, GroupSecretStoreOptions{
		EpochChain:                 epochChain,
		PendingRotationID:          rotationID,
		EpochChainUnverifiedSet:    chainAssessment.set,
		EpochChainUnverified:       chainAssessment.unverified,
		EpochChainUnverifiedReason: chainAssessment.reason,
	})
	if storeErr != nil {
		pkgLogEG().Warn("HandleKeyDistribution failed to store group secret: group=%s epoch=%d err=%v", groupID, epoch, storeErr)
	}
	if ok {
		pkgLogEG().Debug("HandleKeyDistribution succeeded: group=%s epoch=%d", groupID, epoch)
	}
	return ok
}

// BuildKeyRequest 构建密钥请求 payload
func BuildKeyRequest(groupID string, epoch int, requesterAID string, requestID ...string) map[string]any {
	rid := ""
	if len(requestID) > 0 {
		rid = requestID[0]
	}
	if strings.TrimSpace(rid) == "" {
		rid = generateUUID4()
	}
	return map[string]any{
		"type":          "e2ee.group_key_request",
		"group_id":      groupID,
		"epoch":         epoch,
		"requester_aid": requesterAID,
		"request_id":    rid,
		"requested_at":  time.Now().UnixMilli(),
	}
}

// HandleKeyRequest 处理收到的密钥请求
// 验证请求者是群成员 -> 查本地密钥 -> 构建响应
func HandleKeyRequest(
	request map[string]any,
	ks keystore.KeyStore,
	aid string,
	currentMembers []string,
) map[string]any {
	payload := extractPayload(request)

	requesterAID, _ := payload["requester_aid"].(string)
	groupID, _ := payload["group_id"].(string)
	epoch := int(toInt64(payload["epoch"]))

	pkgLogEG().Debug("HandleKeyRequest started: group=%s epoch=%d requester=%s aid=%s", groupID, epoch, requesterAID, aid)

	if requesterAID == "" || groupID == "" {
		pkgLogEG().Error("HandleKeyRequest params incomplete: group=%s requester=%s", groupID, requesterAID)
		return nil
	}

	// 验证请求者是群成员
	found := false
	for _, m := range currentMembers {
		if m == requesterAID {
			found = true
			break
		}
	}
	if !found {
		pkgLogEG().Warn("HandleKeyRequest requester not in current member list: group=%s requester=%s", groupID, requesterAID)
		return nil
	}

	// 查本地密钥
	epochPtr := &epoch
	secretData, _ := LoadGroupSecret(ks, aid, groupID, epochPtr)
	if secretData == nil {
		pkgLogEG().Warn("HandleKeyRequest no local key for epoch: group=%s epoch=%d", groupID, epoch)
		return nil
	}

	secret, _ := secretData["secret"].([]byte)
	commitmentStr, _ := secretData["commitment"].(string)
	members := sorted(toStringSlice(secretData["member_aids"]))

	// P0 历史隔离：如果 epoch 记录了 member_aids，请求者必须在其中
	// 不允许用当前成员列表替换历史 epoch 的成员列表
	if len(members) > 0 {
		requesterInEpoch := false
		for _, m := range members {
			if m == requesterAID {
				requesterInEpoch = true
				break
			}
		}
		if !requesterInEpoch {
			pkgLogEG().Error("group key request rejected: %s is not in epoch %d member list (group=%s)", requesterAID, epoch, groupID)
			return nil
		}
	}

	responseMembers := members
	if len(responseMembers) == 0 {
		responseMembers = sorted(currentMembers)
	}
	if commitmentStr == "" {
		commitmentStr = ComputeMembershipCommitment(responseMembers, epoch, groupID, secret)
	}

	response := map[string]any{
		"type":          "e2ee.group_key_response",
		"group_id":      groupID,
		"epoch":         epoch,
		"group_secret":  base64.StdEncoding.EncodeToString(secret),
		"commitment":    commitmentStr,
		"member_aids":   responseMembers,
		"requester_aid": requesterAID,
		"request_id":    fmt.Sprint(payload["request_id"]),
		"responder_aid": aid,
		"issued_at":     time.Now().UnixMilli(),
	}
	// epoch_chain 始终包含（如果存在）
	if ec, ok := secretData["epoch_chain"].(string); ok && ec != "" {
		response["epoch_chain"] = ec
	}
	pkgLogEG().Debug("HandleKeyRequest response built successfully: group=%s epoch=%d requester=%s", groupID, epoch, requesterAID)
	return response
}

// HandleKeyResponse 处理收到的密钥响应
// 验证 commitment -> 存储
type KeyResponseVerifyOptions struct {
	ExpectedRequest  map[string]any
	ResponderCertPEM []byte
	CurrentMembers   []string
	Strict           bool
}

func HandleKeyResponse(
	response map[string]any,
	ks keystore.KeyStore,
	aid string,
	opts ...KeyResponseVerifyOptions,
) bool {
	payload := extractPayload(response)

	groupID, _ := payload["group_id"].(string)
	epoch := int(toInt64(payload["epoch"]))
	secretB64, _ := payload["group_secret"].(string)
	commitment, _ := payload["commitment"].(string)
	memberAIDs := toStringSlice(payload["member_aids"])

	pkgLogEG().Debug("HandleKeyResponse started: group=%s epoch=%d aid=%s", groupID, epoch, aid)

	if groupID == "" || secretB64 == "" || commitment == "" {
		pkgLogEG().Error("HandleKeyResponse params incomplete: group=%s epoch=%d", groupID, epoch)
		return false
	}

	var opt KeyResponseVerifyOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	// future-epoch 守卫：未带 ExpectedRequest 时，本地已有 epoch 的情况下拒绝高于本地最高 epoch 的响应。
	// 防止恶意/错误响应绕过轮换流程把本地推进到未来 epoch。
	// 本地完全没有 epoch（首次加群）时放行，由后续 commitment / chain 校验把关。
	if opt.ExpectedRequest == nil {
		if rowStore, ok := ks.(interface {
			LoadGroupSecretEpochs(aid, groupID string) ([]map[string]any, error)
		}); ok {
			entries, _ := rowStore.LoadGroupSecretEpochs(aid, groupID)
			localMax := -1
			for _, entry := range entries {
				if e := int(toInt64(entry["epoch"])); e > localMax {
					localMax = e
				}
			}
			if localMax >= 0 && epoch > localMax {
				pkgLogEG().Error("rejected group key response: epoch exceeds local max known epoch aid=%s group=%s epoch=%d local_max=%d", aid, groupID, epoch, localMax)
				return false
			}
		}
	}

	responderAID, _ := payload["responder_aid"].(string)
	if opt.ExpectedRequest != nil {
		requester, _ := payload["requester_aid"].(string)
		requestID, _ := payload["request_id"].(string)
		if requester != aid {
			return false
		}
		expectedResponder := getStr(opt.ExpectedRequest, "_expected_responder_aid", "")
		if expectedResponder != "" && responderAID != expectedResponder {
			return false
		}
		if requestID != fmt.Sprint(opt.ExpectedRequest["request_id"]) {
			return false
		}
		if groupID != fmt.Sprint(opt.ExpectedRequest["group_id"]) {
			return false
		}
		if epoch != int(toInt64(opt.ExpectedRequest["epoch"])) {
			return false
		}
	}
	if opt.Strict {
		if responderAID == "" || opt.ResponderCertPEM == nil {
			return false
		}
		if len(opt.CurrentMembers) > 0 && !stringSliceContains(opt.CurrentMembers, responderAID) {
			return false
		}
		if !VerifyGroupKeyResponseSignature(payload, opt.ResponderCertPEM) {
			return false
		}
	} else if opt.ResponderCertPEM != nil {
		if sig, _ := payload["response_signature"].(string); sig != "" && !VerifyGroupKeyResponseSignature(payload, opt.ResponderCertPEM) {
			return false
		}
	}

	groupSecret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		return false
	}

	if !VerifyMembershipCommitment(commitment, memberAIDs, epoch, groupID, aid, groupSecret) {
		pkgLogEG().Error("HandleKeyResponse commitment verification failed: group=%s epoch=%d", groupID, epoch)
		return false
	}

	if manifest, _ := payload["manifest"].(map[string]any); manifest != nil {
		mGroupID, _ := manifest["group_id"].(string)
		mEpoch := int(toInt64(manifest["epoch"]))
		if mGroupID != groupID || mEpoch != epoch {
			return false
		}
		mMembers := toStringSlice(manifest["member_aids"])
		if len(mMembers) > 0 && !stringSliceEqual(sorted(mMembers), sorted(memberAIDs)) {
			return false
		}
	}

	epochChain, _ := payload["epoch_chain"].(string)
	rotationID, _ := payload["rotation_id"].(string)
	chainAssessment := assessIncomingEpochChain(
		ks, aid, groupID, epoch, commitment, epochChain, rotationID,
		getStr(payload, "distributed_by", getStr(payload, "rotator_aid", responderAID)),
		"key_response",
	)
	if !chainAssessment.ok {
		return false
	}

	ok, storeErr := StoreGroupSecretEpochWithOptions(ks, aid, groupID, epoch, groupSecret, commitment, memberAIDs, GroupSecretStoreOptions{
		EpochChain:                 epochChain,
		PendingRotationID:          rotationID,
		EpochChainUnverifiedSet:    chainAssessment.set,
		EpochChainUnverified:       chainAssessment.unverified,
		EpochChainUnverifiedReason: chainAssessment.reason,
	})
	if storeErr != nil {
		pkgLogEG().Warn("HandleKeyResponse failed to store group secret: group=%s epoch=%d err=%v", groupID, epoch, storeErr)
	}
	if ok {
		pkgLogEG().Debug("HandleKeyResponse succeeded: group=%s epoch=%d", groupID, epoch)
	}
	return ok
}

// ── 群组 AAD 工具 ──────────────────────────────────────────

// aadBytesGroup 群组 AAD 序列化
func aadBytesGroup(aad map[string]any) []byte {
	return aadBytesWithOptionalFields(aad, aadFieldsGroup)
}

// deriveGroupMsgKey 从 group_secret 派生单条群消息的加密密钥
func deriveGroupMsgKey(groupSecret []byte, groupID, messageID string) ([]byte, error) {
	info := []byte(fmt.Sprintf("aun-group:%s:msg:%s", groupID, messageID))
	reader := hkdf.New(sha256.New, groupSecret, nil, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// ── 辅助函数 ─────────────────────────────────────────────

// extractPayload 从消息中提取 payload（兼容直接传入 payload 或包装消息）
func extractPayload(message map[string]any) map[string]any {
	if _, ok := message["group_id"]; ok {
		return message
	}
	if p, ok := message["payload"].(map[string]any); ok {
		return p
	}
	return message
}

// toStringSlice 将 any 转换为 []string
func toStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}

// sorted 返回排序后的字符串切片副本
func sorted(s []string) []string {
	result := make([]string, len(s))
	copy(result, s)
	sort.Strings(result)
	return result
}

// stringSliceEqual 比较两个字符串切片是否相等
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── ECIES (P-256 ECDH + HKDF-SHA256 + AES-256-GCM) ──────────

var eciesHKDFInfo = []byte("aun-epoch-key-ecies")

// EciesEncrypt 使用 P-256 ECDH + HKDF-SHA256 + AES-256-GCM 加密。
// peerPubkeyBytes: 65 字节未压缩 P-256 公钥 (0x04 开头)
// 返回: ephemeral_pubkey(65B) || iv(12B) || ciphertext || tag(16B)
func EciesEncrypt(peerPubkeyBytes []byte, plaintext []byte) ([]byte, error) {
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, peerPubkeyBytes)
	if x == nil {
		return nil, fmt.Errorf("ecies: invalid peer public key")
	}

	// 生成临时密钥对
	ephPriv, ephX, ephY, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecies: generate ephemeral key: %w", err)
	}
	ephPubBytes := elliptic.Marshal(curve, ephX, ephY)

	// ECDH 共享密钥
	sharedX, _ := curve.ScalarMult(x, y, ephPriv)
	shared := sharedX.Bytes()
	if len(shared) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(shared):], shared)
		shared = padded
	}

	// HKDF 派生 32 字节 AES 密钥
	hkdfReader := hkdf.New(sha256.New, shared, nil, eciesHKDFInfo)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("ecies: hkdf derive: %w", err)
	}

	// AES-256-GCM 加密
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("ecies: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ecies: gcm: %w", err)
	}
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("ecies: random iv: %w", err)
	}
	ciphertextWithTag := gcm.Seal(nil, iv, plaintext, nil)

	result := make([]byte, 0, 65+12+len(ciphertextWithTag))
	result = append(result, ephPubBytes...)
	result = append(result, iv...)
	result = append(result, ciphertextWithTag...)
	return result, nil
}

// EciesDecrypt 使用 ECIES 解密，对应 EciesEncrypt。
// privKey: 自己的 ECDSA P-256 私钥
// ciphertext 格式: ephemeral_pubkey(65B) || iv(12B) || encrypted || tag(16B)
func EciesDecrypt(privKey *ecdsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 65+12+16 {
		return nil, fmt.Errorf("ecies: ciphertext too short")
	}
	ephPubBytes := ciphertext[:65]
	iv := ciphertext[65:77]
	encryptedWithTag := ciphertext[77:]

	curve := elliptic.P256()
	ephX, ephY := elliptic.Unmarshal(curve, ephPubBytes)
	if ephX == nil {
		return nil, fmt.Errorf("ecies: invalid ephemeral public key")
	}

	// ECDH 共享密钥
	sharedX, _ := curve.ScalarMult(ephX, ephY, privKey.D.Bytes())
	shared := sharedX.Bytes()
	if len(shared) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(shared):], shared)
		shared = padded
	}

	// HKDF 派生 AES 密钥
	hkdfReader := hkdf.New(sha256.New, shared, nil, eciesHKDFInfo)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("ecies: hkdf derive: %w", err)
	}

	// AES-256-GCM 解密
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("ecies: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ecies: gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, iv, encryptedWithTag, nil)
	if err != nil {
		return nil, fmt.Errorf("ecies: decrypt failed: %w", err)
	}
	return plaintext, nil
}
