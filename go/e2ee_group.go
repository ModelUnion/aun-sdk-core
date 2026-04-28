package aun

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
)

// ErrReplayDetected 表示消息被防重放守卫拦截（非解密失败）。
var ErrReplayDetected = errors.New("replay detected")

// ── 群组 E2EE 常量 ──────────────────────────────────────────

const (
	// ModeEpochGroupKey 群组 epoch 密钥加密模式
	ModeEpochGroupKey = "epoch_group_key"
	// OldEpochRetentionSeconds 旧 epoch 默认保留 7 天
	OldEpochRetentionSeconds = 7 * 24 * 3600
)

// ── GroupE2EEManager 群组端到端加密管理器 ────────────────────

// GroupE2EEManager 群组端到端加密工具类
// 纯密码学 + 本地状态，零 I/O 依赖。
// 所有网络操作（P2P 发送、RPC 调用）由调用方负责。
// 内置防重放、epoch 降级防护、密钥请求频率限制。
type GroupE2EEManager struct {
	identityFn            func() map[string]any       // 获取当前身份的回调
	keystore              keystore.KeyStore           // 密钥存储后端
	config                *AUNConfig                  // SDK 配置
	replayGuard           *GroupReplayGuard           // 防重放守卫
	requestThrottle       *GroupKeyRequestThrottle    // 密钥请求频率限制
	responseThrottle      *GroupKeyRequestThrottle    // 密钥响应频率限制
	senderCertResolver    func(string, string) string // 发送方证书解析器（AID, fingerprint）
	initiatorCertResolver func(string, string) string // 发起者证书解析器（AID, fingerprint）
	pendingKeyRequests    map[string]map[string]any
	pendingKeyRequestsMu  sync.Mutex
}

// GroupE2EEManagerConfig 群组 E2EE 配置
type GroupE2EEManagerConfig struct {
	IdentityFn            func() map[string]any       // 获取当前身份的回调
	Keystore              keystore.KeyStore           // 密钥存储后端
	Config                *AUNConfig                  // SDK 配置
	RequestCooldown       float64                     // 密钥请求冷却时间（秒），默认 30
	ResponseCooldown      float64                     // 密钥响应冷却时间（秒），默认 30
	SenderCertResolver    func(string, string) string // 通过 AID + fingerprint 获取发送方证书 PEM
	InitiatorCertResolver func(string, string) string // 通过 AID + fingerprint 获取发起者证书 PEM
}

// NewGroupE2EEManager 创建群组 E2EE 管理器
func NewGroupE2EEManager(cfg GroupE2EEManagerConfig) *GroupE2EEManager {
	reqCooldown := cfg.RequestCooldown
	if reqCooldown == 0 {
		reqCooldown = 30.0
	}
	resCooldown := cfg.ResponseCooldown
	if resCooldown == 0 {
		resCooldown = 30.0
	}
	return &GroupE2EEManager{
		identityFn:            cfg.IdentityFn,
		keystore:              cfg.Keystore,
		config:                cfg.Config,
		replayGuard:           NewGroupReplayGuard(50000),
		requestThrottle:       NewGroupKeyRequestThrottle(reqCooldown),
		responseThrottle:      NewGroupKeyRequestThrottle(resCooldown),
		senderCertResolver:    cfg.SenderCertResolver,
		initiatorCertResolver: cfg.InitiatorCertResolver,
		pendingKeyRequests:    make(map[string]map[string]any),
	}
}

// ── 密钥管理 ──────────────────────────────────────────────

// signManifest 用当前身份私钥签名 manifest
// 签名失败时返回 error，不再静默回退未签名 manifest
func (m *GroupE2EEManager) signManifest(manifest map[string]any) (map[string]any, error) {
	identity := m.identityFn()
	pkPEM, _ := identity["private_key_pem"].(string)
	if pkPEM == "" {
		return nil, fmt.Errorf("无可用私钥，无法签名 manifest")
	}
	signed, err := SignMembershipManifest(manifest, pkPEM)
	if err != nil {
		return nil, fmt.Errorf("manifest 签名失败: %w", err)
	}
	return signed, nil
}

// CreateEpoch 创建首个 epoch
// 返回 {epoch, commitment, distributions: [{to, payload}]}
func (m *GroupE2EEManager) CreateEpoch(groupID string, memberAIDs []string) (map[string]any, error) {
	aid := m.currentAID()
	if aid == "" {
		return nil, fmt.Errorf("identity not set: cannot create epoch without AID")
	}
	gs := GenerateGroupSecret()
	epoch := 1
	commitment := ComputeMembershipCommitment(memberAIDs, epoch, groupID, gs)
	epochChain := ComputeEpochChain("", epoch, commitment, aid)
	_, err := StoreGroupSecret(m.keystore, aid, groupID, epoch, gs, commitment, memberAIDs, epochChain)
	if err != nil {
		return nil, err
	}

	manifest, err := m.signManifest(BuildMembershipManifest(groupID, epoch, nil, memberAIDs, nil, nil, aid))
	if err != nil {
		return nil, fmt.Errorf("CreateEpoch 签名失败: %w", err)
	}
	distPayload := BuildKeyDistribution(groupID, epoch, gs, memberAIDs, aid, manifest, epochChain)

	distributions := make([]map[string]any, 0)
	for _, member := range memberAIDs {
		if member != aid {
			distributions = append(distributions, map[string]any{
				"to":      member,
				"payload": distPayload,
			})
		}
	}

	return map[string]any{
		"epoch":         epoch,
		"commitment":    commitment,
		"distributions": distributions,
	}, nil
}

// RotateEpoch 轮换 epoch（踢人/退出后调用）
func (m *GroupE2EEManager) RotateEpoch(groupID string, memberAIDs []string) (map[string]any, error) {
	aid := m.currentAID()
	if aid == "" {
		return nil, fmt.Errorf("identity not set: cannot rotate epoch without AID")
	}
	ks := m.keystore
	current, err := LoadGroupSecret(ks, aid, groupID, nil)
	if err != nil {
		return nil, fmt.Errorf("加载当前 epoch 失败: %w", err)
	}
	var prevEpoch *int
	newEpoch := 1
	prevChain := ""
	if current != nil {
		if ep, ok := current["epoch"]; ok {
			e := int(toInt64(ep))
			prevEpoch = &e
			newEpoch = e + 1
		}
		if ec, ok := current["epoch_chain"].(string); ok {
			prevChain = ec
		}
	}

	gs := GenerateGroupSecret()
	commitment := ComputeMembershipCommitment(memberAIDs, newEpoch, groupID, gs)
	epochChain := ComputeEpochChain(prevChain, newEpoch, commitment, aid)
	stored, err := StoreGroupSecret(ks, aid, groupID, newEpoch, gs, commitment, memberAIDs, epochChain)
	if err != nil {
		return nil, err
	}
	if !stored {
		return nil, fmt.Errorf("group %s epoch %d secret already exists or is newer; abort distribution", groupID, newEpoch)
	}

	manifest, err := m.signManifest(BuildMembershipManifest(groupID, newEpoch, prevEpoch, memberAIDs, nil, nil, aid))
	if err != nil {
		return nil, fmt.Errorf("RotateEpoch 签名失败: %w", err)
	}
	distPayload := BuildKeyDistribution(groupID, newEpoch, gs, memberAIDs, aid, manifest, epochChain)

	distributions := make([]map[string]any, 0)
	for _, member := range memberAIDs {
		if member != aid {
			distributions = append(distributions, map[string]any{
				"to":      member,
				"payload": distPayload,
			})
		}
	}

	return map[string]any{
		"epoch":         newEpoch,
		"commitment":    commitment,
		"distributions": distributions,
	}, nil
}

// RotateEpochTo 指定目标 epoch 号轮换（配合服务端两阶段 rotation 使用）
func (m *GroupE2EEManager) RotateEpochTo(groupID string, targetEpoch int, memberAIDs []string, rotationIDs ...string) (map[string]any, error) {
	aid := m.currentAID()
	if aid == "" {
		return nil, fmt.Errorf("identity not set: cannot rotate epoch without AID")
	}
	// 优先使用 targetEpoch-1 的已提交前链；若本地当前是同 epoch 的旧 pending，
	// 不能把旧 pending chain 当作新 rotation 的前链。
	prevEpoch := targetEpoch - 1
	current, _ := LoadGroupSecret(m.keystore, aid, groupID, &prevEpoch)
	if current == nil {
		current, _ = LoadGroupSecret(m.keystore, aid, groupID, nil)
	}
	prevChain := ""
	if current != nil {
		if ec, ok := current["epoch_chain"].(string); ok {
			prevChain = ec
		}
	}

	gs := GenerateGroupSecret()
	commitment := ComputeMembershipCommitment(memberAIDs, targetEpoch, groupID, gs)
	epochChain := ComputeEpochChain(prevChain, targetEpoch, commitment, aid)
	rotationID := ""
	if len(rotationIDs) > 0 {
		rotationID = strings.TrimSpace(rotationIDs[0])
	}
	stored, err := StoreGroupSecret(m.keystore, aid, groupID, targetEpoch, gs, commitment, memberAIDs, epochChain, rotationID)
	if err != nil {
		return nil, err
	}
	if !stored {
		return nil, fmt.Errorf("group %s epoch %d secret already exists or is newer; abort distribution", groupID, targetEpoch)
	}

	manifest, err := m.signManifest(BuildMembershipManifest(groupID, targetEpoch, &prevEpoch, memberAIDs, nil, nil, aid))
	if err != nil {
		return nil, fmt.Errorf("RotateEpochTo 签名失败: %w", err)
	}
	distPayload := BuildKeyDistribution(groupID, targetEpoch, gs, memberAIDs, aid, manifest, epochChain)
	if rotationID != "" {
		distPayload["rotation_id"] = rotationID
	}

	distributions := make([]map[string]any, 0)
	for _, member := range memberAIDs {
		if member != aid {
			distributions = append(distributions, map[string]any{
				"to":      member,
				"payload": distPayload,
			})
		}
	}

	return map[string]any{
		"epoch":         targetEpoch,
		"commitment":    commitment,
		"distributions": distributions,
	}, nil
}

// StoreSecret 手动存储 group_secret。返回 false 表示 epoch 降级被拒。
func (m *GroupE2EEManager) StoreSecret(groupID string, epoch int, groupSecret []byte, commitment string, memberAIDs []string, epochChain string) (bool, error) {
	return StoreGroupSecret(m.keystore, m.currentAID(), groupID, epoch, groupSecret, commitment, memberAIDs, epochChain)
}

// DiscardPendingSecret 仅回滚指定 pending rotation 的本地 target epoch key。
func (m *GroupE2EEManager) DiscardPendingSecret(groupID string, epoch int, rotationID string) (bool, error) {
	return DiscardPendingGroupSecret(m.keystore, m.currentAID(), groupID, epoch, rotationID)
}

// LoadSecret 加载群组密钥
func (m *GroupE2EEManager) LoadSecret(groupID string) (map[string]any, error) {
	return LoadGroupSecret(m.keystore, m.currentAID(), groupID, nil)
}

// LoadSecretForEpoch 加载指定 epoch 的群组密钥
func (m *GroupE2EEManager) LoadSecretForEpoch(groupID string, epoch int) (map[string]any, error) {
	return LoadGroupSecret(m.keystore, m.currentAID(), groupID, &epoch)
}

// LoadAllSecrets 加载所有 epoch 的群组密钥
func (m *GroupE2EEManager) LoadAllSecrets(groupID string) map[int][]byte {
	return LoadAllGroupSecrets(m.keystore, m.currentAID(), groupID)
}

// Cleanup 清理过期的旧 epoch
func (m *GroupE2EEManager) Cleanup(groupID string, retentionSeconds int) (int, error) {
	if retentionSeconds == 0 {
		retentionSeconds = OldEpochRetentionSeconds
	}
	return CleanupOldEpochs(m.keystore, m.currentAID(), groupID, retentionSeconds)
}

// CleanExpiredCaches 清理过期缓存（replay guard 等），供外部定时调用
func (m *GroupE2EEManager) CleanExpiredCaches() {
	m.replayGuard.Trim()
}

// ── 加解密 ────────────────────────────────────────────────

// Encrypt 加密群组消息（含发送方签名）
// 无密钥时返回 E2EEGroupSecretMissingError
func (m *GroupE2EEManager) Encrypt(groupID string, payload map[string]any) (map[string]any, error) {
	aid := m.currentAID()
	lockKey, mu := acquireGroupSecretLock(aid, groupID)
	secretData, err := LoadGroupSecret(m.keystore, aid, groupID, nil)
	releaseGroupSecretLock(lockKey, mu)
	if err != nil {
		return nil, fmt.Errorf("加载群 %s 密钥失败: %w", groupID, err)
	}
	if secretData == nil {
		return nil, NewE2EEGroupSecretMissingError(fmt.Sprintf("群 %s 无密钥", groupID))
	}

	identity := m.identityFn()
	senderPkPEM, _ := identity["private_key_pem"].(string)
	senderCertPEM, _ := identity["cert"].(string)

	epoch := int(toInt64(secretData["epoch"]))
	secret, _ := secretData["secret"].([]byte)

	msgID := fmt.Sprintf("gm-%s", generateUUID4())
	ts := time.Now().UnixMilli()

	return EncryptGroupMessage(secret, payload, groupID, aid, msgID, ts, epoch, senderPkPEM, []byte(senderCertPEM))
}

// EncryptWithEpoch 使用指定 committed epoch 加密群组消息。
func (m *GroupE2EEManager) EncryptWithEpoch(groupID string, epoch int, payload map[string]any) (map[string]any, error) {
	aid := m.currentAID()
	lockKey, mu := acquireGroupSecretLock(aid, groupID)
	secretData, err := LoadGroupSecret(m.keystore, aid, groupID, &epoch)
	releaseGroupSecretLock(lockKey, mu)
	if err != nil {
		return nil, fmt.Errorf("加载群 %s epoch %d 密钥失败: %w", groupID, epoch, err)
	}
	if secretData == nil {
		return nil, NewE2EEGroupSecretMissingError(fmt.Sprintf("群 %s epoch %d 无密钥", groupID, epoch))
	}

	identity := m.identityFn()
	senderPkPEM, _ := identity["private_key_pem"].(string)
	if senderPkPEM == "" {
		return nil, NewE2EEError("sender identity private key unavailable for group message signing", "E2EE_SIGN_FAILED")
	}
	senderCertPEM, _ := identity["cert"].(string)
	secret, _ := secretData["secret"].([]byte)
	msgID := fmt.Sprintf("gm-%s", generateUUID4())
	ts := time.Now().UnixMilli()
	return EncryptGroupMessage(secret, payload, groupID, aid, msgID, ts, epoch, senderPkPEM, []byte(senderCertPEM))
}

// Decrypt 解密单条群组消息
// 内置防重放 + 发送方验签 + 外层字段校验
// 非加密消息原样返回，解密失败返回 nil
func (m *GroupE2EEManager) Decrypt(message map[string]any, skipReplay bool) (map[string]any, error) {
	payload, ok := message["payload"].(map[string]any)
	if !ok {
		return message, nil
	}
	payloadType, _ := payload["type"].(string)
	if payloadType != "e2ee.group_encrypted" {
		return message, nil
	}

	groupID, _ := message["group_id"].(string)
	sender, _ := message["from"].(string)
	if sender == "" {
		sender, _ = message["sender_aid"].(string)
	}

	// 防重放预检：优先使用 AAD 内 message_id
	aad, _ := payload["aad"].(map[string]any)
	aadMsgID := ""
	if aad != nil {
		aadMsgID, _ = aad["message_id"].(string)
	}
	msgID := aadMsgID
	if msgID == "" {
		msgID, _ = message["message_id"].(string)
	}
	if !skipReplay && groupID != "" && sender != "" && msgID != "" {
		if !m.replayGuard.CheckAndRecord(groupID, sender, msgID) {
			return nil, fmt.Errorf("%w: group=%s sender=%s msg=%s", ErrReplayDetected, groupID, sender, msgID)
		}
	}

	// 解析发送方证书（零信任：无证书则拒绝）
	// 从 payload 或 aad 提取 sender_cert_fingerprint 以精确匹配证书版本
	senderFP := ""
	if fp, ok := payload["sender_cert_fingerprint"].(string); ok && fp != "" {
		senderFP = fp
	} else if aad != nil {
		senderFP, _ = aad["sender_cert_fingerprint"].(string)
	}
	var senderCertPEM []byte
	if m.senderCertResolver != nil && sender != "" {
		raw := m.senderCertResolver(sender, senderFP)
		if raw != "" {
			senderCertPEM = []byte(raw)
		}
	}
	if senderCertPEM == nil {
		log.Printf("[e2ee_group] 拒绝群消息：无法获取发送方 %s 的证书: group=%s", sender, groupID)
		if !skipReplay && groupID != "" && sender != "" && msgID != "" {
			m.replayGuard.Unrecord(groupID, sender, msgID)
		}
		return nil, fmt.Errorf("sender cert not found: aid=%s group=%s", sender, groupID)
	}

	allSecrets := LoadAllGroupSecrets(m.keystore, m.currentAID(), groupID)
	if len(allSecrets) == 0 {
		// 解密失败，回退 replay guard 记录以允许后续重试
		if !skipReplay && groupID != "" && sender != "" && msgID != "" {
			m.replayGuard.Unrecord(groupID, sender, msgID)
		}
		return nil, fmt.Errorf("no group secret available: group=%s", groupID)
	}

	result := DecryptGroupMessage(allSecrets, message, senderCertPEM, true)
	if result == nil {
		// GO-003: 解密失败时回退 replay guard 记录并返回 error
		if !skipReplay && groupID != "" && sender != "" && msgID != "" {
			m.replayGuard.Unrecord(groupID, sender, msgID)
		}
		return nil, fmt.Errorf("群消息解密失败: group=%s sender=%s", groupID, sender)
	}
	// CheckAndRecord 已在预检阶段原子记录，解密成功无需再次 Record
	return result, nil
}

// DecryptResult 单条解密结果，包含明文和可能的错误
type DecryptResult struct {
	Message map[string]any // 解密后的消息（成功时），或原始消息（非加密消息时）
	Error   error          // 解密错误（nil 表示成功或非加密消息）
}

// DecryptBatch 批量解密群组消息（兼容旧接口，静默忽略错误）
// 已废弃：请使用 DecryptBatchWithErrors 获取每条的错误详情。
func (m *GroupE2EEManager) DecryptBatch(messages []map[string]any, skipReplay bool) []map[string]any {
	results := make([]map[string]any, len(messages))
	for i, msg := range messages {
		decrypted, err := m.Decrypt(msg, skipReplay)
		if err != nil {
			log.Printf("[e2ee_group] DecryptBatch 第 %d 条解密失败: %v", i, err)
			results[i] = msg
		} else if decrypted != nil {
			results[i] = decrypted
		} else {
			results[i] = msg
		}
	}
	return results
}

// DecryptBatchWithErrors 批量解密群组消息，返回每条的解密结果（含 error）
// GO-003: 调用方可通过 DecryptResult.Error 了解每条消息的解密状态
func (m *GroupE2EEManager) DecryptBatchWithErrors(messages []map[string]any, skipReplay bool) []DecryptResult {
	results := make([]DecryptResult, len(messages))
	for i, msg := range messages {
		decrypted, err := m.Decrypt(msg, skipReplay)
		if err != nil {
			results[i] = DecryptResult{Message: msg, Error: err}
		} else if decrypted != nil {
			results[i] = DecryptResult{Message: decrypted, Error: nil}
		} else {
			results[i] = DecryptResult{Message: msg, Error: nil}
		}
	}
	return results
}

// ── 密钥协议消息处理 ──────────────────────────────────────

// HandleIncoming 处理已解密的 P2P 密钥消息
// 返回 "distribution"/"request"/"response" 表示已成功处理
// 返回 "distribution_rejected"/"response_rejected" 表示被拒绝
// 返回 "" 表示不是密钥消息
func (m *GroupE2EEManager) HandleIncoming(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	msgType, _ := payload["type"].(string)
	aid := m.currentAID()

	switch msgType {
	case "e2ee.group_key_distribution":
		// 解析发起者证书用于 manifest 验证
		var initiatorCert []byte
		distributedBy, _ := payload["distributed_by"].(string)
		// 从 payload 提取 fingerprint 以精确匹配证书版本
		initiatorFP, _ := payload["distributor_cert_fingerprint"].(string)
		if m.initiatorCertResolver != nil && distributedBy != "" {
			raw := m.initiatorCertResolver(distributedBy, initiatorFP)
			if raw != "" {
				initiatorCert = []byte(raw)
			}
		}
		ok := HandleKeyDistribution(payload, m.keystore, aid, initiatorCert)
		if ok {
			return "distribution"
		}
		return "distribution_rejected"

	case "e2ee.group_key_response":
		pendingKey := fmt.Sprintf("%s:%v:%s", getStr(payload, "group_id", ""), payload["epoch"], getStr(payload, "request_id", ""))
		m.pendingKeyRequestsMu.Lock()
		expected := m.pendingKeyRequests[pendingKey]
		if expected != nil {
			delete(m.pendingKeyRequests, pendingKey)
		}
		m.pendingKeyRequestsMu.Unlock()
		if expected == nil {
			return "response_rejected"
		}
		responderAID, _ := payload["responder_aid"].(string)
		var responderCert []byte
		if m.initiatorCertResolver != nil && responderAID != "" {
			if raw := m.initiatorCertResolver(responderAID, ""); raw != "" {
				responderCert = []byte(raw)
			}
		}
		ok := HandleKeyResponse(payload, m.keystore, aid, KeyResponseVerifyOptions{
			ExpectedRequest:  expected,
			ResponderCertPEM: responderCert,
			CurrentMembers:   m.GetMemberAIDs(getStr(payload, "group_id", "")),
			Strict:           true,
		})
		if !ok {
			m.pendingKeyRequestsMu.Lock()
			if _, exists := m.pendingKeyRequests[pendingKey]; !exists {
				m.pendingKeyRequests[pendingKey] = expected
			}
			m.pendingKeyRequestsMu.Unlock()
		}
		if ok {
			return "response"
		}
		return "response_rejected"

	case "e2ee.group_key_request":
		return "request"
	}
	return ""
}

// BuildRecoveryRequest 构建密钥恢复请求
// 返回 {to, payload} 或 nil（限流/无目标）
func (m *GroupE2EEManager) BuildRecoveryRequest(groupID string, epoch int, senderAID string) map[string]any {
	aid := m.currentAID()
	throttleKey := fmt.Sprintf("request:%s:%d", groupID, epoch)
	if !m.requestThrottle.Allow(throttleKey) {
		return nil
	}

	var candidates []string
	secretData, err := LoadGroupSecret(m.keystore, aid, groupID, nil)
	if err != nil {
		log.Printf("[e2ee_group] BuildRecoveryRequest 加载密钥失败: group=%s %v", groupID, err)
	}
	if secretData != nil {
		if members, ok := secretData["member_aids"].([]string); ok {
			for _, member := range members {
				if member != aid {
					candidates = append(candidates, member)
				}
			}
		}
	}
	if len(candidates) == 0 && senderAID != "" && senderAID != aid {
		candidates = []string{senderAID}
	}
	if len(candidates) == 0 {
		return nil
	}

	payload := BuildKeyRequest(groupID, epoch, aid)
	m.RememberKeyRequest(payload, candidates[0])
	return map[string]any{
		"to":      candidates[0],
		"payload": payload,
	}
}

func (m *GroupE2EEManager) RememberKeyRequest(payload map[string]any, expectedResponder ...string) {
	if payload == nil || getStr(payload, "type", "") != "e2ee.group_key_request" {
		return
	}
	requestID := getStr(payload, "request_id", "")
	if requestID == "" {
		return
	}
	key := fmt.Sprintf("%s:%v:%s", getStr(payload, "group_id", ""), payload["epoch"], requestID)
	pending := copyMapShallow(payload)
	if len(expectedResponder) > 0 && expectedResponder[0] != "" {
		pending["_expected_responder_aid"] = expectedResponder[0]
	}
	m.pendingKeyRequestsMu.Lock()
	m.pendingKeyRequests[key] = pending
	m.pendingKeyRequestsMu.Unlock()
}

// HandleKeyRequestMsg 处理密钥请求
// 返回响应 payload（受频率限制 + 成员资格验证），或 nil 拒绝
func (m *GroupE2EEManager) HandleKeyRequestMsg(requestPayload map[string]any, currentMembers []string) map[string]any {
	requester, _ := requestPayload["requester_aid"].(string)
	groupID, _ := requestPayload["group_id"].(string)
	if requester == "" || groupID == "" {
		return nil
	}

	// 成员资格验证
	found := false
	for _, member := range currentMembers {
		if member == requester {
			found = true
			break
		}
	}
	if !found {
		log.Printf("[e2ee_group] 拒绝密钥恢复请求：%s 不在群 %s 成员列表中", requester, groupID)
		return nil
	}

	throttleKey := fmt.Sprintf("response:%s:%s", groupID, requester)
	if !m.responseThrottle.Allow(throttleKey) {
		return nil
	}

	response := HandleKeyRequest(requestPayload, m.keystore, m.currentAID(), currentMembers)
	if response == nil {
		return nil
	}
	identity := m.identityFn()
	pk, _ := identity["private_key_pem"].(string)
	if pk == "" {
		log.Printf("[e2ee_group] 拒绝密钥恢复响应：本地身份私钥不可用 group=%s requester=%s", groupID, requester)
		return nil
	}
	signed, err := SignGroupKeyResponse(response, pk)
	if err != nil {
		log.Printf("[e2ee_group] group key response 签名失败: group=%s err=%v", groupID, err)
		return nil
	}
	return signed
}

// ── 状态查询 ──────────────────────────────────────────────

// HasSecret 判断是否持有群组密钥
func (m *GroupE2EEManager) HasSecret(groupID string) bool {
	data, err := LoadGroupSecret(m.keystore, m.currentAID(), groupID, nil)
	if err != nil {
		log.Printf("[e2ee_group] HasSecret 加载密钥失败: group=%s %v", groupID, err)
		return false
	}
	return data != nil
}

// CurrentEpoch 获取群组当前 epoch，未知则返回 nil
func (m *GroupE2EEManager) CurrentEpoch(groupID string) *int {
	data, err := LoadGroupSecret(m.keystore, m.currentAID(), groupID, nil)
	if err != nil {
		log.Printf("[e2ee_group] CurrentEpoch 加载密钥失败: group=%s %v", groupID, err)
		return nil
	}
	if data == nil {
		return nil
	}
	ep := int(toInt64(data["epoch"]))
	return &ep
}

// GetMemberAIDs 获取群组成员列表
func (m *GroupE2EEManager) GetMemberAIDs(groupID string) []string {
	data, err := LoadGroupSecret(m.keystore, m.currentAID(), groupID, nil)
	if err != nil {
		log.Printf("[e2ee_group] GetMemberAIDs 加载密钥失败: group=%s %v", groupID, err)
		return nil
	}
	if data == nil {
		return nil
	}
	if members, ok := data["member_aids"].([]string); ok {
		return members
	}
	return nil
}

// currentAID 获取当前 AID
func (m *GroupE2EEManager) currentAID() string {
	identity := m.identityFn()
	if aid, ok := identity["aid"].(string); ok {
		return aid
	}
	return ""
}

// PurgeGroupData 清理指定群组的所有本地密钥数据（dissolve/退出时调用）
// GO-006: 删除 current epoch + 所有 old epoch 密钥
func (m *GroupE2EEManager) PurgeGroupData(groupID string) {
	aid := m.currentAID()
	if aid == "" {
		return
	}
	deleter, ok := m.keystore.(groupSecretDeleteStore)
	if !ok {
		log.Printf("[e2ee_group] PurgeGroupData 清理群 %s 密钥失败: keystore 不支持 DeleteGroupSecretState", groupID)
		return
	}
	if err := deleter.DeleteGroupSecretState(aid, groupID); err != nil {
		log.Printf("[e2ee_group] PurgeGroupData 清理群 %s 密钥失败: %v", groupID, err)
	}
}
