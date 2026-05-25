// v2_state.go — V2 State 安全增强层（验签 + fork 检测 + auto_propose）。
//
// 与 Python aun_core.client 的对应方法对齐：
//   - _v2_verify_state_signature → v2VerifyStateSignature
//   - _v2_check_fork             → v2CheckFork
//   - _v2_auto_propose_state     → v2AutoProposeState
//   - _v2_auto_confirm_pending_proposals → v2AutoConfirmPendingProposals

package aun

import (
	"context"
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	v2crypto "github.com/modelunion/aun-sdk-core/go/v2/crypto"
	"github.com/modelunion/aun-sdk-core/go/v2/state"
)

// ── 常量 ──────────────────────────────────────────────

const (
	v2SigCacheTTL = 600   // 秒
	v2SigCacheMax = 16384 // 最大缓存条目
)

// ── 状态字段（嵌入 v2P2PState 或 client 级别） ──────────────────

// v2StateSecurityState 聚合 state 验签 + fork 检测的运行时状态。
type v2StateSecurityState struct {
	sigCache   map[[32]byte]int64 // sha256(actor+payload+sig) → expiry_unix
	sigCacheMu sync.Mutex

	stateChains   map[string]v2StateChainEntry // group_id → (state_version, state_chain)
	stateChainsMu sync.Mutex
}

type v2StateChainEntry struct {
	Version int
	Chain   string
}

func newV2StateSecurityState() *v2StateSecurityState {
	return &v2StateSecurityState{
		sigCache:    make(map[[32]byte]int64),
		stateChains: make(map[string]v2StateChainEntry),
	}
}

// v2GetSecurityState 获取或懒初始化安全状态。
func (c *AUNClient) v2GetSecurityState() *v2StateSecurityState {
	c.mu.RLock()
	st := c.v2Security
	c.mu.RUnlock()
	if st != nil {
		return st
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.v2Security == nil {
		c.v2Security = newV2StateSecurityState()
	}
	return c.v2Security
}

// ── v2VerifyStateSignature ──────────────────────────────────────────────

// v2VerifyStateSignature 验证 owner/admin 对 state 的 ECDSA 签名（防服务端篡改 bootstrap 字段）。
//
//   - 无签名（state_version=0 或新建群）→ 跳过
//   - 签名验证失败 → 返回 error
//   - 验证通过 → 校验 bootstrap 返回的 member_aids 是否在签名快照中
func (c *AUNClient) v2VerifyStateSignature(ctx context.Context, groupID string, bootstrap map[string]any) error {
	if bootstrap == nil {
		return nil
	}
	stateSignature := strings.TrimSpace(v2AsString(bootstrap["state_signature"]))
	actorAID := strings.TrimSpace(v2AsString(bootstrap["state_actor_aid"]))
	stateHashSigned := strings.TrimSpace(v2AsString(bootstrap["state_hash_signed"]))
	membershipSnapshot := strings.TrimSpace(v2AsString(bootstrap["state_membership_snapshot"]))
	stateVersion := int(toInt64(bootstrap["state_version"]))

	if stateVersion == 0 || stateSignature == "" || actorAID == "" {
		return nil // 群刚创建或没有签名 state
	}

	// 构造 sign_payload（key 排序，紧凑 JSON）
	signPayloadMap := map[string]any{
		"group_id":            groupID,
		"membership_snapshot": membershipSnapshot,
		"state_hash":          stateHashSigned,
		"state_version":       stateVersion,
	}
	signPayload, err := marshalSortedCompactJSON(signPayloadMap)
	if err != nil {
		return fmt.Errorf("V2 state verify: marshal sign_payload failed: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(stateSignature)
	if err != nil {
		return fmt.Errorf("V2 state verify: decode signature failed: %w", err)
	}

	// 计算缓存 key：使用长度前缀，避免本地业务缓存 key 继续生成 NUL 分隔符。
	cacheKey := sha256.Sum256(buildLengthPrefixedBytesKey([]byte(actorAID), signPayload, sigBytes))

	sec := c.v2GetSecurityState()
	nowTS := time.Now().Unix()

	// 缓存命中检查
	sec.sigCacheMu.Lock()
	if exp, ok := sec.sigCache[cacheKey]; ok && exp > nowTS {
		sec.sigCacheMu.Unlock()
		c.logE2.Debug("V2 state signature cache hit: group=%s sv=%d", groupID, stateVersion)
		// 即使缓存命中也要做 member 校验
		c.v2CheckMembershipTamper(ctx, groupID, bootstrap, membershipSnapshot)
		return nil
	}
	sec.sigCacheMu.Unlock()

	// 获取 actor 证书（与 Python 一致：通过 peer certificate HTTP 端点）
	certBytes, err := c.fetchPeerCert(ctx, actorAID, "")
	if err != nil || len(certBytes) == 0 {
		c.logE2.Warn("V2 state verify: no cert for actor=%s, group=%s", actorAID, groupID)
		if err != nil {
			return fmt.Errorf("V2 state verify: cannot fetch actor cert for %s: %w", actorAID, err)
		}
		return fmt.Errorf("V2 state verify: cannot fetch actor cert for %s", actorAID)
	}

	// 解析证书 → 提取公钥 → ECDSA-SHA256 验签
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return fmt.Errorf("V2 state verify: invalid PEM cert for %s", actorAID)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("V2 state verify: parse cert failed for %s: %w", actorAID, err)
	}
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("V2 state verify: cert public key is not ECDSA for %s", actorAID)
	}

	// DER 格式签名验证（ECDSA-SHA256）
	payloadHash := sha256.Sum256(signPayload)
	if !ecdsa.VerifyASN1(pubKey, payloadHash[:], sigBytes) {
		return fmt.Errorf("V2 state signature verification failed: group=%s actor=%s", groupID, actorAID)
	}

	// 写入缓存
	sec.sigCacheMu.Lock()
	sec.sigCache[cacheKey] = nowTS + v2SigCacheTTL
	// 缓存淘汰
	if len(sec.sigCache) > v2SigCacheMax {
		stale := make([][32]byte, 0)
		for k, exp := range sec.sigCache {
			if exp <= nowTS {
				stale = append(stale, k)
			}
		}
		for _, k := range stale {
			delete(sec.sigCache, k)
		}
		if len(sec.sigCache) > v2SigCacheMax {
			// 淘汰最旧的 1/4
			type kv struct {
				key [32]byte
				exp int64
			}
			items := make([]kv, 0, len(sec.sigCache))
			for k, exp := range sec.sigCache {
				items = append(items, kv{k, exp})
			}
			sort.Slice(items, func(i, j int) bool { return items[i].exp < items[j].exp })
			evict := len(items) / 4
			for i := 0; i < evict; i++ {
				delete(sec.sigCache, items[i].key)
			}
		}
	}
	sec.sigCacheMu.Unlock()

	c.logE2.Debug("V2 state signature verified: group=%s sv=%d actor=%s", groupID, stateVersion, actorAID)

	// 验证 member_aids 是否在签名快照中
	c.v2CheckMembershipTamper(ctx, groupID, bootstrap, membershipSnapshot)
	return nil
}

// v2CheckMembershipTamper 校验 bootstrap 返回的 member_aids 是否在签名快照中。
func (c *AUNClient) v2CheckMembershipTamper(ctx context.Context, groupID string, bootstrap map[string]any, membershipSnapshot string) {
	if membershipSnapshot == "" || !strings.HasPrefix(membershipSnapshot, "[") {
		return
	}
	var signedSnapshot []string
	if err := json.Unmarshal([]byte(membershipSnapshot), &signedSnapshot); err != nil {
		return
	}
	signedSet := make(map[string]bool, len(signedSnapshot))
	for _, aid := range signedSnapshot {
		signedSet[aid] = true
	}

	serverMembers := v2ToStringList(bootstrap["member_aids"])
	var extra []string
	for _, aid := range serverMembers {
		if !signedSet[aid] {
			extra = append(extra, aid)
		}
	}
	if len(extra) == 0 {
		return
	}

	// 检查是否是 open/invite_code 群（允许 pending）
	mode := ""
	reqResp, err := c.Call(ctx, "group.get_join_requirements", map[string]any{"group_id": groupID})
	if err == nil {
		if reqMap, ok := reqResp.(map[string]any); ok {
			mode = strings.TrimSpace(v2AsString(reqMap["mode"]))
		}
	}
	if mode == "open" || mode == "invite_code" || mode == "invite_only" {
		return
	}

	sort.Strings(extra)
	c.logE2.Warn("V2 state tamper detected: group=%s pending_extra=%v mode=%s", groupID, extra, mode)
	c.events.Publish("group.v2.state_tampered", map[string]any{
		"group_id":      groupID,
		"pending_extra": extra,
		"mode":          mode,
	})
}

// ── v2CheckFork ──────────────────────────────────────────────

// v2CheckFork 分叉检测：比对服务端 state_chain 与本地存储。
func (c *AUNClient) v2CheckFork(ctx context.Context, groupID string, serverChain string) {
	if serverChain == "" {
		return
	}
	sec := c.v2GetSecurityState()

	sec.stateChainsMu.Lock()
	local, exists := sec.stateChains[groupID]
	if !exists {
		sec.stateChains[groupID] = v2StateChainEntry{Version: 0, Chain: serverChain}
		sec.stateChainsMu.Unlock()
		return
	}
	localChain := local.Chain
	localSV := local.Version
	sec.stateChainsMu.Unlock()

	if localChain == serverChain {
		return
	}

	// 不一致：尝试通过 get_state 判断是正常推进还是分叉
	stateResp, err := c.Call(ctx, "group.get_state", map[string]any{"group_id": groupID})
	if err == nil {
		if stateMap, ok := stateResp.(map[string]any); ok {
			serverSV := int(toInt64(stateMap["state_version"]))
			if serverSV > localSV {
				// 正常推进
				sec.stateChainsMu.Lock()
				sec.stateChains[groupID] = v2StateChainEntry{Version: serverSV, Chain: serverChain}
				sec.stateChainsMu.Unlock()
				return
			}
			if serverSV < localSV {
				c.logE2.Warn("V2 state chain rollback detected: group=%s server_sv=%d local_sv=%d", groupID, serverSV, localSV)
			}
		}
	}

	// 告警
	localPrefix := localChain
	if len(localPrefix) > 16 {
		localPrefix = localPrefix[:16]
	}
	serverPrefix := serverChain
	if len(serverPrefix) > 16 {
		serverPrefix = serverPrefix[:16]
	}
	c.logE2.Warn("V2 state chain fork detected: group=%s local_chain=%s... server_chain=%s...", groupID, localPrefix, serverPrefix)
	c.events.Publish("group.v2.fork_detected", map[string]any{
		"group_id":     groupID,
		"local_chain":  localChain,
		"server_chain": serverChain,
	})
}

// ── v2AutoProposeState ──────────────────────────────────────────────

// v2AutoProposeState 成员变更后自动 propose state（仅 owner/admin 执行）。
func (c *AUNClient) v2AutoProposeState(ctx context.Context, groupID string) {
	normalizedGroupID := NormalizeGroupID(strings.TrimSpace(groupID), "")
	if normalizedGroupID == "" {
		return
	}
	lock := c.v2AutoProposeLock(normalizedGroupID)
	lock.Lock()
	defer lock.Unlock()
	c.v2AutoProposeStateLocked(ctx, normalizedGroupID)
}

// v2AutoProposeStateFromEvent 用于 group.changed 事件触发的兜底提案。
// 直接成员变更调用方同步提案；事件路径先做在线 owner/admin leader 选举，非 leader jitter 后再兜底。
func (c *AUNClient) v2AutoProposeStateFromEvent(ctx context.Context, groupID string) {
	normalizedGroupID := NormalizeGroupID(strings.TrimSpace(groupID), "")
	if normalizedGroupID == "" {
		return
	}
	if !c.v2AutoProposeLeaderDelay(ctx, normalizedGroupID) {
		return
	}
	c.v2AutoProposeState(ctx, normalizedGroupID)
}

func (c *AUNClient) v2AutoProposeLeaderDelay(ctx context.Context, groupID string) bool {
	membersResp, err := c.Call(ctx, "group.get_online_members", map[string]any{"group_id": groupID})
	if err != nil {
		c.logE2.Debug("V2 auto propose leader check failed, fallback immediate: group=%s err=%v", groupID, err)
		return true
	}
	membersMap, _ := membersResp.(map[string]any)
	membersList := v2ToMapList(membersMap["members"])
	if len(membersList) == 0 {
		membersList = v2ToMapList(membersMap["items"])
	}
	if len(membersList) == 0 {
		membersList = v2ToMapList(membersMap["online_members"])
	}

	c.mu.RLock()
	myAID := c.aid
	myDeviceID := c.deviceID
	c.mu.RUnlock()

	myRole := ""
	onlineAdminSet := make(map[string]bool)
	var onlineAdminAIDs []string
	for _, member := range membersList {
		aid := strings.TrimSpace(v2AsString(member["aid"]))
		role := strings.TrimSpace(v2AsString(member["role"]))
		if aid == "" {
			continue
		}
		if online, ok := member["online"].(bool); ok && !online {
			continue
		}
		if role == "owner" || role == "admin" {
			if !onlineAdminSet[aid] {
				onlineAdminSet[aid] = true
				onlineAdminAIDs = append(onlineAdminAIDs, aid)
			}
		}
		if aid == myAID {
			myRole = role
		}
	}
	if myRole != "owner" && myRole != "admin" {
		return false
	}

	bootstrapResp, err := c.Call(ctx, "group.v2.bootstrap", map[string]any{"group_id": groupID})
	if err != nil {
		c.logE2.Debug("V2 auto propose leader bootstrap failed, fallback immediate: group=%s err=%v", groupID, err)
		return true
	}
	bootstrapMap, _ := bootstrapResp.(map[string]any)
	devices := v2ToMapList(bootstrapMap["devices"])
	candidates := make([]string, 0)
	for _, dev := range devices {
		aid := strings.TrimSpace(v2AsString(dev["aid"]))
		deviceID, hasDeviceID := v2DeviceIDFromDevice(dev)
		if aid != "" && hasDeviceID && onlineAdminSet[aid] {
			candidates = append(candidates, aid+"\x1f"+deviceID)
		}
	}
	if len(candidates) == 0 {
		sort.Strings(onlineAdminAIDs)
		for _, aid := range onlineAdminAIDs {
			candidates = append(candidates, aid+"\x1f")
		}
	}
	myKey := myAID + "\x1f" + myDeviceID
	foundSelf := false
	for _, candidate := range candidates {
		if candidate == myKey {
			foundSelf = true
			break
		}
	}
	if !foundSelf {
		candidates = append(candidates, myKey)
	}
	sort.Strings(candidates)
	leader := candidates[0]
	if leader == myKey {
		c.logE2.Debug("V2 auto propose leader elected: group=%s leader=%s", groupID, leader)
		return true
	}

	sum := sha256.Sum256([]byte(buildLengthPrefixedTextKey(groupID, myKey)))
	delayMs := 2000 + int(uint32(sum[0])<<24|uint32(sum[1])<<16|uint32(sum[2])<<8|uint32(sum[3]))%4000
	c.logE2.Debug("V2 auto propose non-leader delay: group=%s leader=%s self=%s delay_ms=%d", groupID, leader, myKey, delayMs)
	timer := time.NewTimer(time.Duration(delayMs) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (c *AUNClient) v2AutoProposeLock(groupID string) *sync.Mutex {
	c.v2AutoProposeLocksMu.Lock()
	defer c.v2AutoProposeLocksMu.Unlock()
	if c.v2AutoProposeLocks == nil {
		c.v2AutoProposeLocks = make(map[string]*sync.Mutex)
	}
	if c.v2AutoProposeLastSnapshot == nil {
		c.v2AutoProposeLastSnapshot = make(map[string]string)
	}
	lock := c.v2AutoProposeLocks[groupID]
	if lock == nil {
		lock = &sync.Mutex{}
		c.v2AutoProposeLocks[groupID] = lock
	}
	return lock
}

func (c *AUNClient) v2AutoProposeStateLocked(ctx context.Context, groupID string) {
	defer func() {
		if r := recover(); r != nil {
			c.logE2.Warn("v2AutoProposeState panic: group=%s err=%v", groupID, r)
		}
	}()

	// 获取当前成员列表 + 角色
	membersResp, err := c.Call(ctx, "group.get_members", map[string]any{"group_id": groupID})
	if err != nil {
		c.logE2.Debug("V2 auto propose_state failed (non-fatal): group=%s err=%v", groupID, err)
		return
	}
	membersMap, _ := membersResp.(map[string]any)
	membersList := v2ToMapList(membersMap["members"])
	if len(membersList) == 0 {
		membersList = v2ToMapList(membersMap["items"])
	}

	c.mu.RLock()
	myAID := c.aid
	identity := c.identity
	c.mu.RUnlock()

	myRole := ""
	var memberAIDs []string
	var adminAIDs []string
	for _, m := range membersList {
		aid := strings.TrimSpace(v2AsString(m["aid"]))
		role := strings.TrimSpace(v2AsString(m["role"]))
		if aid != "" {
			memberAIDs = append(memberAIDs, aid)
			if role == "owner" || role == "admin" {
				adminAIDs = append(adminAIDs, aid)
			}
		}
		if aid == myAID {
			myRole = role
		}
	}

	if myRole != "owner" && myRole != "admin" {
		return
	}

	// 前置检查：如果已有 pending proposal，先尝试 confirm 而非重复 propose
	proposalResp, err := c.Call(ctx, "group.v2.get_proposal", map[string]any{"group_id": groupID})
	if err == nil {
		if proposalMap, ok := proposalResp.(map[string]any); ok {
			if proposal, ok := proposalMap["proposal"].(map[string]any); ok && proposal != nil {
				if strings.TrimSpace(v2AsString(proposal["proposal_id"])) != "" {
					if c.v2ConfirmPendingProposal(ctx, groupID) {
						return
					}
					autoConfirmAt := toInt64(proposal["auto_confirm_at"])
					nowMs := time.Now().UnixMilli()
					if autoConfirmAt > nowMs {
						waitMs := autoConfirmAt - nowMs + 500
						if waitMs > 35000 {
							waitMs = 35000
						}
						c.logE2.Debug("V2 auto propose: pending proposal exists, waiting %dms group=%s", waitMs, groupID)
						timer := time.NewTimer(time.Duration(waitMs) * time.Millisecond)
						defer timer.Stop()
						select {
						case <-ctx.Done():
							return
						case <-timer.C:
						}
					}
				}
			}
		}
	}

	// 获取群所有成员的设备列表（V2 bootstrap）
	bootstrapResp, err := c.Call(ctx, "group.v2.bootstrap", map[string]any{"group_id": groupID})
	if err != nil {
		c.logE2.Debug("V2 auto propose_state failed (non-fatal): group=%s err=%v", groupID, err)
		return
	}
	bsMap, _ := bootstrapResp.(map[string]any)
	allDevices := v2ToMapList(bsMap["devices"])
	auditRecipients := v2ToMapList(bsMap["audit_recipients"])

	// 收集 audit_aids
	auditAIDSet := make(map[string]bool)
	for _, r := range auditRecipients {
		aid := strings.TrimSpace(v2AsString(r["aid"]))
		if aid != "" {
			auditAIDSet[aid] = true
		}
	}
	auditAIDsList := make([]string, 0, len(auditAIDSet))
	for aid := range auditAIDSet {
		auditAIDsList = append(auditAIDsList, aid)
	}
	sort.Strings(auditAIDsList)

	// 按 aid 分组设备
	membersWithDevices := make(map[string][]map[string]any)
	for _, aid := range memberAIDs {
		membersWithDevices[aid] = nil
	}
	for _, dev := range allDevices {
		devAID := strings.TrimSpace(v2AsString(dev["aid"]))
		if _, ok := membersWithDevices[devAID]; ok {
			membersWithDevices[devAID] = append(membersWithDevices[devAID], map[string]any{
				"device_id": v2AsString(dev["device_id"]),
				"ik_fp":     v2AsString(dev["ik_fp"]),
			})
		}
	}

	// 构造 members payload
	membersPayload := make([]any, 0, len(membersWithDevices))
	for _, aid := range memberAIDs {
		devices := membersWithDevices[aid]
		devList := make([]any, 0, len(devices))
		for _, d := range devices {
			devList = append(devList, d)
		}
		membersPayload = append(membersPayload, map[string]any{
			"aid":     aid,
			"devices": devList,
		})
	}

	sort.Strings(adminAIDs)
	statePayload := map[string]any{
		"members":          membersPayload,
		"audit_aids":       v2ToAnySlice(auditAIDsList),
		"admin_set":        map[string]any{"admin_aids": v2ToAnySlice(adminAIDs), "threshold": 1},
		"join_policy_hash": nil,
		"recovery_quorum":  nil,
		"history_policy":   "recent_7_days",
		"wrap_protocol":    "3DH",
	}

	// 获取当前 state
	stateResp, err := c.Call(ctx, "group.get_state", map[string]any{"group_id": groupID})
	if err != nil {
		c.logE2.Debug("V2 auto propose_state failed (non-fatal): group=%s err=%v", groupID, err)
		return
	}
	stateMap, ok := stateResp.(map[string]any)
	if !ok {
		return
	}
	if !c.v2VerifyCommittedStateBase(groupID, stateMap) {
		return
	}
	currentSV := int(toInt64(stateMap["state_version"]))
	currentSH := v2AsString(stateMap["state_hash"])
	keyEpoch := int(toInt64(stateMap["key_epoch"]))

	// 计算 state_hash
	stateHash := state.ComputeStateCommitment(groupID, uint32(currentSV+1), statePayload)

	// 签名 state proposal
	membershipSnapshotBytes, _ := marshalSortedCompactJSON(statePayload)
	membershipSnapshot := string(membershipSnapshotBytes)
	c.v2AutoProposeLocksMu.Lock()
	lastMembershipSnapshot := c.v2AutoProposeLastSnapshot[groupID]
	c.v2AutoProposeLocksMu.Unlock()
	if lastMembershipSnapshot == membershipSnapshot {
		return
	}
	if currentMembership := strings.TrimSpace(v2AsString(stateMap["membership_snapshot"])); currentMembership != "" && currentMembership == membershipSnapshot {
		c.v2AutoProposeLocksMu.Lock()
		c.v2AutoProposeLastSnapshot[groupID] = membershipSnapshot
		c.v2AutoProposeLocksMu.Unlock()
		return
	}

	signature := ""
	privPEM, _ := identity["private_key_pem"].(string)
	if privPEM != "" {
		signPayloadMap := map[string]any{
			"group_id":            groupID,
			"membership_snapshot": membershipSnapshot,
			"state_hash":          stateHash,
			"state_version":       currentSV + 1,
		}
		signPayloadBytes, err := marshalSortedCompactJSON(signPayloadMap)
		if err == nil {
			pk, err := parseECPrivateKeyPEM(privPEM)
			if err == nil {
				payloadHash := sha256.Sum256(signPayloadBytes)
				sigDER, err := ecdsa.SignASN1(cryptorand.Reader, pk, payloadHash[:])
				if err == nil {
					signature = base64.StdEncoding.EncodeToString(sigDER)
				}
			}
		}
	}

	proposeResp, err := c.Call(ctx, "group.v2.propose_state", map[string]any{
		"group_id":             groupID,
		"state_version":        currentSV + 1,
		"key_epoch":            keyEpoch,
		"state_hash":           stateHash,
		"prev_state_hash":      currentSH,
		"membership_snapshot":  membershipSnapshot,
		"signature":            signature,
		"reason":               "membership_changed",
		"auto_confirm_seconds": 30,
	})
	if err != nil {
		c.logE2.Debug("V2 auto propose_state failed (non-fatal): group=%s err=%v", groupID, err)
		return
	}
	c.logE2.Debug("V2 auto propose_state: group=%s sv=%d", groupID, currentSV+1)
	if proposalMap, ok := proposeResp.(map[string]any); ok {
		proposalID := strings.TrimSpace(v2AsString(proposalMap["proposal_id"]))
		if proposalID != "" {
			if _, confirmErr := c.Call(ctx, "group.v2.confirm_state", map[string]any{"proposal_id": proposalID}); confirmErr != nil {
				c.logE2.Debug("V2 auto confirm_state failed (non-fatal): group=%s err=%v", groupID, confirmErr)
			} else {
				c.v2AutoProposeLocksMu.Lock()
				c.v2AutoProposeLastSnapshot[groupID] = membershipSnapshot
				c.v2AutoProposeLocksMu.Unlock()
				c.logE2.Debug("V2 auto confirm_state: group=%s proposal=%s", groupID, proposalID)
			}
		}
	}
}

func (c *AUNClient) v2VerifyCommittedStateBase(groupID string, stateMap map[string]any) bool {
	currentSV := int(toInt64(stateMap["state_version"]))
	if currentSV <= 0 {
		return true
	}
	currentSH := strings.TrimSpace(v2AsString(stateMap["state_hash"]))
	membershipSnapshot := strings.TrimSpace(v2AsString(stateMap["membership_snapshot"]))
	if currentSH == "" || membershipSnapshot == "" {
		c.logE2.Warn("V2 committed state base incomplete: group=%s sv=%d", groupID, currentSV)
		return false
	}
	payload, ok := v2DecodeMembershipSnapshot(membershipSnapshot)
	if !ok {
		c.logE2.Warn("V2 committed state base snapshot is not object: group=%s sv=%d", groupID, currentSV)
		return false
	}
	computed := state.ComputeStateCommitment(groupID, uint32(currentSV), payload)
	if computed != currentSH {
		c.logE2.Warn("V2 committed state base hash mismatch: group=%s sv=%d", groupID, currentSV)
		return false
	}
	return true
}

func (c *AUNClient) v2VerifyPendingProposalAgainstBase(groupID string, proposal map[string]any, stateMap map[string]any) bool {
	if !c.v2VerifyCommittedStateBase(groupID, stateMap) {
		return false
	}
	currentSV := int(toInt64(stateMap["state_version"]))
	currentSH := strings.TrimSpace(v2AsString(stateMap["state_hash"]))
	proposalSV := int(toInt64(proposal["state_version"]))
	proposalHash := strings.TrimSpace(v2AsString(proposal["state_hash"]))
	proposalPrev := strings.TrimSpace(v2AsString(proposal["prev_state_hash"]))
	membershipSnapshot := strings.TrimSpace(v2AsString(proposal["membership_snapshot"]))
	if proposalSV != currentSV+1 || proposalPrev != currentSH || proposalHash == "" || membershipSnapshot == "" {
		c.logE2.Warn("V2 pending proposal base mismatch: group=%s current_sv=%d proposal_sv=%d", groupID, currentSV, proposalSV)
		return false
	}
	payload, ok := v2DecodeMembershipSnapshot(membershipSnapshot)
	if !ok {
		return false
	}
	computed := state.ComputeStateCommitment(groupID, uint32(proposalSV), payload)
	if computed != proposalHash {
		c.logE2.Warn("V2 pending proposal hash mismatch: group=%s proposal_sv=%d", groupID, proposalSV)
		return false
	}
	return true
}

func (c *AUNClient) v2ConfirmPendingProposal(ctx context.Context, groupID string) bool {
	proposalResp, err := c.Call(ctx, "group.v2.get_proposal", map[string]any{"group_id": groupID})
	if err != nil {
		c.logE2.Debug("V2 auto confirm proposal failed (non-fatal): group=%s err=%v", groupID, err)
		return false
	}
	proposalMap, _ := proposalResp.(map[string]any)
	proposal, _ := proposalMap["proposal"].(map[string]any)
	if proposal == nil {
		return false
	}
	proposalID := strings.TrimSpace(v2AsString(proposal["proposal_id"]))
	if proposalID == "" {
		return false
	}

	stateResp, err := c.Call(ctx, "group.get_state", map[string]any{"group_id": groupID})
	if err != nil {
		c.logE2.Debug("V2 auto confirm proposal failed (non-fatal): group=%s err=%v", groupID, err)
		return false
	}
	stateMap, ok := stateResp.(map[string]any)
	if !ok {
		return false
	}
	currentSV := int(toInt64(stateMap["state_version"]))
	proposalSV := int(toInt64(proposal["state_version"]))
	if proposalSV <= currentSV {
		c.logE2.Debug("V2 pending proposal already settled: group=%s current_sv=%d proposal_sv=%d", groupID, currentSV, proposalSV)
		return false
	}
	if !c.v2VerifyPendingProposalAgainstBase(groupID, proposal, stateMap) {
		return false
	}

	if _, err = c.Call(ctx, "group.v2.confirm_state", map[string]any{"proposal_id": proposalID}); err != nil {
		c.logE2.Debug("V2 auto confirm proposal failed (non-fatal): group=%s err=%v", groupID, err)
		return false
	}
	c.logE2.Info("V2 confirmed pending proposal: group=%s proposal=%s", groupID, proposalID)
	return true
}

// ── v2AutoConfirmPendingProposals ──────────────────────────────────────────────

// v2AutoConfirmPendingProposals Owner 上线时自动检查并签名确认 pending state proposals。
func (c *AUNClient) v2AutoConfirmPendingProposals(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			c.logE2.Warn("v2AutoConfirmPendingProposals panic: %v", r)
		}
	}()

	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	if myAID == "" {
		return
	}

	groupsResp, err := c.Call(ctx, "group.list_my", map[string]any{})
	if err != nil {
		c.logE2.Debug("V2 auto confirm pending proposals failed (non-fatal): %v", err)
		return
	}
	groupsMap, _ := groupsResp.(map[string]any)
	groups := v2ToMapList(groupsMap["groups"])
	if len(groups) == 0 {
		groups = v2ToMapList(groupsMap["items"])
	}

	for _, g := range groups {
		groupID := strings.TrimSpace(v2AsString(g["group_id"]))
		myRole := strings.TrimSpace(v2AsString(g["role"]))
		if myRole == "" {
			myRole = strings.TrimSpace(v2AsString(g["my_role"]))
		}
		if groupID == "" || (myRole != "owner" && myRole != "admin") {
			continue
		}

		if !c.v2ConfirmPendingProposal(ctx, groupID) {
			// 没有 pending proposal，检查是否有 pending members 需要发起新 propose
			c.v2AutoProposeState(ctx, groupID)
		}
	}
}

// v2MaybeTriggerAutoPropose lazy sync 路径：发现 pending members 时异步触发 auto propose（去重 10s）。
func (c *AUNClient) v2MaybeTriggerAutoPropose(groupID string) {
	c.v2AutoProposeLocksMu.Lock()
	if c.v2LazyProposeTriggered == nil {
		c.v2LazyProposeTriggered = make(map[string]int64)
	}
	now := time.Now().Unix()
	last := c.v2LazyProposeTriggered[groupID]
	if now-last < 10 {
		c.v2AutoProposeLocksMu.Unlock()
		return
	}
	c.v2LazyProposeTriggered[groupID] = now
	c.v2AutoProposeLocksMu.Unlock()
	go c.v2AutoProposeStateFromEvent(context.Background(), groupID)
}

// ── 辅助函数 ──────────────────────────────────────────────

// marshalSortedCompactJSON 生成 key 排序的紧凑 JSON（无空格，无换行）。
func marshalSortedCompactJSON(v map[string]any) ([]byte, error) {
	// 与 Python json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False) 对齐，
	// 复用 V2 canonical serializer，避免 encoding/json 的 HTML 过度转义。
	return v2crypto.CanonicalJSON(v), nil
}

func v2DecodeMembershipSnapshot(snapshot string) (map[string]any, bool) {
	var payload map[string]any
	decoder := json.NewDecoder(strings.NewReader(snapshot))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, false
	}
	if payload == nil {
		return nil, false
	}
	return payload, true
}

// v2ToStringList 把 any → []string（支持 []any 和 []string）。
func v2ToStringList(v any) []string {
	switch arr := v.(type) {
	case []string:
		return arr
	case []any:
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// v2ToAnySlice 把 []string 转为 []any（用于 JSON 序列化兼容）。
func v2ToAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
