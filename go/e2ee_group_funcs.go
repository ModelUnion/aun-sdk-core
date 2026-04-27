package aun

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/anthropics/aun-sdk-core/go/keystore"
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
	log.Printf("[e2ee_group] keystore 不支持 CleanupGroupOldEpochsState，跳过旧 epoch 清理")
	return 0
}

func listKeyStoreGroupIDs(ks keystore.KeyStore, aid string) []string {
	if lister, ok := ks.(groupSecretIDLister); ok {
		groupIDs, err := lister.ListGroupSecretIDs(aid)
		if err == nil {
			return groupIDs
		}
		log.Printf("[e2ee_group] ListGroupSecretIDs 失败: %v", err)
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
) (map[string]any, error) {
	// 派生单条消息密钥
	msgKey, err := deriveGroupMsgKey(groupSecret, groupID, messageID)
	if err != nil {
		return nil, fmt.Errorf("群消息密钥派生失败: %w", err)
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化 payload 失败: %w", err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("生成 nonce 失败: %w", err)
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
	aadBytes := aadBytesGroup(aad)

	block, err := aes.NewCipher(msgKey)
	if err != nil {
		return nil, fmt.Errorf("创建 AES cipher 失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建 GCM 失败: %w", err)
	}
	ciphertextWithTag := gcm.Seal(nil, nonce, plaintext, aadBytes)
	tagStart := len(ciphertextWithTag) - 16
	ciphertext := ciphertextWithTag[:tagStart]
	tag := ciphertextWithTag[tagStart:]

	envelope := map[string]any{
		"type":            "e2ee.group_encrypted",
		"version":         "1",
		"encryption_mode": ModeEpochGroupKey,
		"suite":           SuiteP256,
		"epoch":           epoch,
		"nonce":           base64.StdEncoding.EncodeToString(nonce),
		"ciphertext":      base64.StdEncoding.EncodeToString(ciphertext),
		"tag":             base64.StdEncoding.EncodeToString(tag),
		"aad":             aad,
	}

	// 发送方签名
	if senderPrivateKeyPEM != "" {
		pk, err := parseECPrivateKeyPEM(senderPrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("解析发送方私钥失败: %w", err)
		}
		signPayload := make([]byte, 0, len(ciphertext)+len(tag)+len(aadBytes))
		signPayload = append(signPayload, ciphertext...)
		signPayload = append(signPayload, tag...)
		signPayload = append(signPayload, aadBytes...)
		hash := sha256.Sum256(signPayload)
		sig, err := ecdsa.SignASN1(rand.Reader, pk, hash[:])
		if err != nil {
			return nil, fmt.Errorf("群消息发送方签名失败: %w", err)
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

	plaintext, err := aesGCMDecrypt(msgKey, nonce, ciphertext, tag, aadBytes)
	if err != nil {
		return nil
	}

	var decoded map[string]any
	if err := json.Unmarshal(plaintext, &decoded); err != nil {
		return nil
	}

	result := copyMapShallow(message)
	result["payload"] = decoded
	result["encrypted"] = true
	result["e2ee"] = map[string]any{
		"encryption_mode": ModeEpochGroupKey,
		"suite":           SuiteP256,
		"epoch":           epoch,
		"sender_verified": false,
	}

	// 发送方签名验证
	sigB64, _ := payload["sender_signature"].(string)

	if requireSignature {
		// 零信任模式：必须有签名且有证书
		if sigB64 == "" {
			log.Printf("[e2ee_group] 拒绝无签名群消息: group=%s from=%s", groupID, aadFrom)
			return nil
		}
		if senderCertPEM == nil {
			log.Printf("[e2ee_group] 拒绝群消息：有签名但无证书: group=%s from=%s", groupID, aadFrom)
			return nil
		}
		if !verifyGroupSenderSignature(senderCertPEM, sigB64, ciphertext, tag, aadBytes) {
			log.Printf("[e2ee_group] 群消息签名验证失败: group=%s from=%s", groupID, aadFrom)
			return nil
		}
		result["e2ee"].(map[string]any)["sender_verified"] = true
	} else if senderCertPEM != nil {
		// 非零信任但有证书：有证书时强制验签
		if sigB64 == "" {
			log.Printf("[e2ee_group] 拒绝无签名群消息: group=%s from=%s", groupID, aadFrom)
			return nil
		}
		if !verifyGroupSenderSignature(senderCertPEM, sigB64, ciphertext, tag, aadBytes) {
			log.Printf("[e2ee_group] 群消息签名验证失败: group=%s from=%s", groupID, aadFrom)
			return nil
		}
		result["e2ee"].(map[string]any)["sender_verified"] = true
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
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}
	signData := manifestSignData(manifest)
	hash := sha256.Sum256(signData)
	sig, err := ecdsa.SignASN1(rand.Reader, pk, hash[:])
	if err != nil {
		return nil, fmt.Errorf("签名失败: %w", err)
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
		return false, fmt.Errorf("解析证书失败: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("证书非 EC 公钥")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, fmt.Errorf("解码签名失败: %w", err)
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
		panic(fmt.Sprintf("crypto/rand 不可用，无法生成安全随机数: %v", err))
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
	return false, fmt.Errorf("keystore 不支持 DiscardPendingGroupSecretState")
}

func StoreGroupSecretWithOptions(ks keystore.KeyStore, aid, groupID string, epoch int, groupSecret []byte, commitment string, memberAIDs []string, opts GroupSecretStoreOptions) (bool, error) {
	lockKey, mu := acquireGroupSecretLock(aid, groupID)
	defer releaseGroupSecretLock(lockKey, mu)

	if stored, handled, err := storeKeyStoreGroupTransition(ks, aid, groupID, epoch, groupSecret, commitment, memberAIDs, opts); handled {
		if err != nil {
			return false, fmt.Errorf("保存 group_secret 失败: %w", err)
		}
		return stored, nil
	}
	return false, fmt.Errorf("keystore 不支持 StoreGroupSecretTransition")
}

// StoreGroupSecretEpochWithOptions 保存指定 epoch key。低于 current 时写入 old epoch row，不覆盖 current。
func StoreGroupSecretEpochWithOptions(ks keystore.KeyStore, aid, groupID string, epoch int, groupSecret []byte, commitment string, memberAIDs []string, opts GroupSecretStoreOptions) (bool, error) {
	lockKey, mu := acquireGroupSecretLock(aid, groupID)
	defer releaseGroupSecretLock(lockKey, mu)

	if stored, handled, err := storeKeyStoreGroupEpoch(ks, aid, groupID, epoch, groupSecret, commitment, memberAIDs, opts); handled {
		if err != nil {
			return false, fmt.Errorf("保存 group_secret epoch 失败: %w", err)
		}
		return stored, nil
	}
	return false, fmt.Errorf("keystore 不支持 StoreGroupSecretEpoch")
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
		log.Printf("[e2ee_group] 拒绝缺少 epoch_chain 的新 rotation key: source=%s group=%s epoch=%d rotation=%s", source, groupID, epoch, rid)
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
				log.Printf("[e2ee_group] 拒绝同 epoch 分叉 chain: source=%s group=%s epoch=%d rotation=%s", source, groupID, epoch, rid)
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
			log.Printf("[e2ee_group] 拒绝缺少 rotator_aid 的新 rotation key: source=%s group=%s epoch=%d rotation=%s", source, groupID, epoch, rid)
			return epochChainAssessment{ok: false}
		}
		return epochChainAssessment{ok: true, set: true, unverified: true, reason: "missing_rotator_aid"}
	}
	if !VerifyEpochChain(chain, prevChain, epoch, commitment, rotator) {
		if rid != "" {
			log.Printf("[e2ee_group] 拒绝 epoch_chain 验证失败的新 rotation key: source=%s group=%s epoch=%d rotation=%s", source, groupID, epoch, rid)
			return epochChainAssessment{ok: false}
		}
		log.Printf("[e2ee_group] epoch_chain 验证失败，按兼容档接收并标记未验证: source=%s group=%s epoch=%d", source, groupID, epoch)
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

	if groupID == "" || secretB64 == "" || commitment == "" {
		return false
	}

	// 验证 Membership Manifest 签名
	manifest, _ := payload["manifest"].(map[string]any)
	if initiatorCertPEM != nil {
		if manifest == nil {
			log.Printf("[e2ee_group] 拒绝无 manifest 的密钥分发: group=%s epoch=%d", groupID, epoch)
			return false
		}
		valid, _ := VerifyMembershipManifest(manifest, initiatorCertPEM)
		if !valid {
			log.Printf("[e2ee_group] manifest 签名验证失败: group=%s epoch=%d", groupID, epoch)
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
		log.Printf("[e2ee_group] HandleKeyDistribution 存储 group secret 失败: group=%s epoch=%d err=%v", groupID, epoch, storeErr)
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

	if requesterAID == "" || groupID == "" {
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
		return nil
	}

	// 查本地密钥
	epochPtr := &epoch
	secretData, _ := LoadGroupSecret(ks, aid, groupID, epochPtr)
	if secretData == nil {
		return nil
	}

	secret, _ := secretData["secret"].([]byte)
	commitmentStr, _ := secretData["commitment"].(string)
	members := toStringSlice(secretData["member_aids"])
	if commitmentStr == "" {
		if len(members) == 0 {
			members = currentMembers
		}
		commitmentStr = ComputeMembershipCommitment(members, epoch, groupID, secret)
	}

	sorted := make([]string, len(members))
	copy(sorted, members)
	if len(sorted) == 0 {
		sorted = make([]string, len(currentMembers))
		copy(sorted, currentMembers)
	}
	sort.Strings(sorted)

	response := map[string]any{
		"type":          "e2ee.group_key_response",
		"group_id":      groupID,
		"epoch":         epoch,
		"group_secret":  base64.StdEncoding.EncodeToString(secret),
		"commitment":    commitmentStr,
		"member_aids":   sorted,
		"requester_aid": requesterAID,
		"request_id":    fmt.Sprint(payload["request_id"]),
		"responder_aid": aid,
		"issued_at":     time.Now().UnixMilli(),
	}
	if ec, ok := secretData["epoch_chain"].(string); ok && ec != "" {
		response["epoch_chain"] = ec
	}
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

	if groupID == "" || secretB64 == "" || commitment == "" {
		return false
	}

	var opt KeyResponseVerifyOptions
	if len(opts) > 0 {
		opt = opts[0]
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
		return false
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
		log.Printf("[e2ee_group] HandleKeyResponse 存储 group secret 失败: group=%s epoch=%d err=%v", groupID, epoch, storeErr)
	}
	return ok
}

// ── 群组 AAD 工具 ──────────────────────────────────────────

// aadBytesGroup 群组 AAD 序列化
func aadBytesGroup(aad map[string]any) []byte {
	filtered := make(map[string]any, len(aadFieldsGroup))
	for _, field := range aadFieldsGroup {
		filtered[field] = aad[field]
	}
	data := canonicalJSONMarshal(filtered)
	return data
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
