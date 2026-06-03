package aun

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/modelunion/aun-sdk-core/go/v2/session"
)

type v2E2EECoordinator struct {
	runtime                        *clientRuntime
	groupSpkMu                     sync.Mutex
	groupSpkRegistrationInflight   map[string]bool
	groupSpkRotationInflight       map[string]bool
	groupSpkPeerFallbackRegistered map[string]bool
}

func newV2E2EECoordinator(runtime *clientRuntime) *v2E2EECoordinator {
	return &v2E2EECoordinator{
		runtime:                        runtime,
		groupSpkRegistrationInflight:   make(map[string]bool),
		groupSpkRotationInflight:       make(map[string]bool),
		groupSpkPeerFallbackRegistered: make(map[string]bool),
	}
}

func (v *v2E2EECoordinator) onConnected(ctx context.Context, backgroundSync bool) {
	c := v.runtime.client
	if err := v.initV2Session(ctx); err != nil {
		c.logE2.Warn("V2 session init failed (non-fatal): %v", err)
	}
	if !backgroundSync || c.v2GetState() == nil {
		return
	}
	c.mu.RLock()
	bgCtx := c.ctx
	c.mu.RUnlock()
	if bgCtx == nil {
		bgCtx = ctx
	}
	if bgCtx == nil {
		bgCtx = context.Background()
	}
	go c.v2AutoConfirmPendingProposals(bgCtx)
}

// initV2Session 在 connect 成功后初始化 V2 session 并注册设备 SPK。
//
//   - 若 AID 缺失或 identity 无私钥，跳过（返回 nil）。
//   - IK = AID 长期密钥，从 identity["private_key_pem"] 解析为 raw scalar (32B P-256) + DER 公钥。
//   - 调用 V2Session.EnsureKeys 加载或生成 SPK；EnsureRegistered 上传 message.v2.put_peer_pk。
func (v *v2E2EECoordinator) initV2Session(ctx context.Context) error {
	c := v.runtime.client
	c.mu.RLock()
	aid := c.aid
	currentAID := c.currentAIDObj
	deviceID := c.deviceID
	aunPath := ""
	if c.configModel != nil {
		aunPath = c.configModel.AUNPath
	}
	c.mu.RUnlock()

	if aid == "" {
		return nil
	}
	privPEM := ""
	if currentAID != nil {
		privPEM = currentAID.PrivateKeyPem
	}
	if privPEM == "" {
		c.logE2.Warn("V2 session init skipped: no AID private key")
		return nil
	}

	ecKey, err := parseECPrivateKeyPEM(privPEM)
	if err != nil {
		return fmt.Errorf("V2 session init: 解析 AID 私钥失败: %w", err)
	}
	if ecKey.Curve.Params().BitSize != 256 {
		return fmt.Errorf("V2 session init: AID 私钥必须为 P-256 曲线")
	}
	aidPriv := ecKey.D.FillBytes(make([]byte, 32))
	aidPubDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		return fmt.Errorf("V2 session init: 编码 AID 公钥失败: %w", err)
	}

	c.releaseV2State()

	store, err := openV2Keystore(aunPath, aid)
	if err != nil {
		return err
	}

	v2 := session.NewV2Session(store.store, deviceID, aid, aidPriv, aidPubDER)
	if err := v2.EnsureKeys(); err != nil {
		_ = store.Close()
		return fmt.Errorf("V2 session init: EnsureKeys 失败: %w", err)
	}

	state := &v2P2PState{
		session:             v2,
		keystore:            store,
		bootstrapCache:      make(map[string]v2BootstrapEntry),
		groupBootstrapCache: make(map[string]*v2GroupBootstrapEntry),
	}
	c.mu.Lock()
	c.v2State = state
	c.mu.Unlock()

	if err := v2.EnsureRegistered(ctx, c.v2CallFn()); err != nil {
		// 注册失败时仍保留 session 状态：消费方面（pull/decrypt）依旧可用，
		// 发送方在 send_v2 调用时会自然透传错误。这里仅日志告警。
		c.logE2.Warn("V2 session init: EnsureRegistered 失败（保留 session 状态）: %v", err)
	} else {
		c.logE2.Debug("V2 session initialized: aid=%s device=%s", aid, deviceID)
	}

	return nil
}

func (v *v2E2EECoordinator) deletePeerBootstrapCache(peerAID string) {
	state := v.runtime.client.v2GetState()
	if state == nil {
		return
	}
	state.bootstrapCacheM.Lock()
	delete(state.bootstrapCache, peerAID)
	state.bootstrapCacheM.Unlock()
}

func (v *v2E2EECoordinator) getPeerBootstrapCache(state *v2P2PState, peerAID string) (v2BootstrapEntry, bool) {
	if state == nil {
		return v2BootstrapEntry{}, false
	}
	state.bootstrapCacheM.Lock()
	entry, ok := state.bootstrapCache[peerAID]
	state.bootstrapCacheM.Unlock()
	return entry, ok
}

func (v *v2E2EECoordinator) setPeerBootstrapCache(state *v2P2PState, peerAID string, entry v2BootstrapEntry) {
	if state == nil {
		return
	}
	state.bootstrapCacheM.Lock()
	state.bootstrapCache[peerAID] = entry
	state.bootstrapCacheM.Unlock()
}

func (v *v2E2EECoordinator) deleteGroupBootstrapCache(groupID string) {
	state := v.runtime.client.v2GetState()
	if state == nil {
		return
	}
	state.bootstrapCacheM.Lock()
	delete(state.groupBootstrapCache, groupID)
	state.bootstrapCacheM.Unlock()
}

func (v *v2E2EECoordinator) getGroupBootstrapCache(state *v2P2PState, groupID string) (*v2GroupBootstrapEntry, bool) {
	if state == nil {
		return nil, false
	}
	state.bootstrapCacheM.Lock()
	entry, ok := state.groupBootstrapCache[groupID]
	state.bootstrapCacheM.Unlock()
	return entry, ok
}

func (v *v2E2EECoordinator) setGroupBootstrapCache(state *v2P2PState, groupID string, entry *v2GroupBootstrapEntry) {
	if state == nil {
		return
	}
	state.bootstrapCacheM.Lock()
	state.groupBootstrapCache[groupID] = entry
	state.bootstrapCacheM.Unlock()
}

func encryptedPushEnvelope(msg map[string]any) (map[string]any, bool) {
	if msg == nil {
		return nil, false
	}
	if pm, ok := msg["payload"].(map[string]any); ok && isEncryptedEnvelopePayload(pm) {
		return pm, true
	}
	raw := strings.TrimSpace(stringFromAny(msg["envelope_json"]))
	if raw == "" {
		return nil, false
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var envelope map[string]any
	if err := dec.Decode(&envelope); err != nil {
		return nil, false
	}
	if !isEncryptedEnvelopePayload(envelope) {
		return nil, false
	}
	return envelope, true
}

func isEncryptedPushMessage(msg map[string]any) bool {
	if msg == nil {
		return false
	}
	if truthyBool(msg["encrypted"]) {
		return true
	}
	_, ok := encryptedPushEnvelope(msg)
	return ok
}

func isEncryptedEnvelopePayload(payload any) bool {
	pm, ok := payload.(map[string]any)
	if !ok || pm == nil {
		return false
	}
	payloadType := strings.TrimSpace(stringFromAny(pm["type"]))
	if strings.HasPrefix(payloadType, "e2ee.") {
		return true
	}
	if strings.TrimSpace(stringFromAny(pm["ciphertext"])) == "" {
		return false
	}
	return pm["nonce"] != nil || pm["tag"] != nil || pm["recipient"] != nil ||
		pm["recipients"] != nil || pm["wrapped_key"] != nil || pm["recipients_digest"] != nil
}

func isV2EncryptedEnvelopePayload(envelope map[string]any) bool {
	if envelope == nil {
		return false
	}
	payloadType := strings.TrimSpace(stringFromAny(envelope["type"]))
	if payloadType == "e2ee.p2p_encrypted" || payloadType == "e2ee.group_encrypted" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(stringFromAny(envelope["version"])), "v2") &&
		strings.HasPrefix(payloadType, "e2ee.")
}

func safeUndecryptablePushEvent(msg map[string]any, group bool) map[string]any {
	event := map[string]any{
		"message_id":     msg["message_id"],
		"from":           msg["from"],
		"seq":            msg["seq"],
		"timestamp":      msg["timestamp"],
		"device_id":      msg["device_id"],
		"slot_id":        msg["slot_id"],
		"_decrypt_error": "encrypted push payload is not decryptable on raw push path",
		"_decrypt_stage": "push_envelope",
	}
	if event["timestamp"] == nil {
		event["timestamp"] = msg["t_server"]
	}
	if group {
		event["group_id"] = msg["group_id"]
	} else {
		event["to"] = msg["to"]
	}
	if envelope, ok := encryptedPushEnvelope(msg); ok {
		event["_envelope_type"] = stringFromAny(envelope["type"])
		event["_suite"] = stringFromAny(envelope["suite"])
		if isV2EncryptedEnvelopePayload(envelope) {
			attachV2EnvelopeMetadata(event, v2MessageE2EEMetadata(envelope))
		}
	}
	return event
}

func (v *v2E2EECoordinator) publishEncryptedPushAsUndecryptable(eventName, ns string, seq int, msg map[string]any, group bool) bool {
	c := v.runtime.client
	safeEvent := safeUndecryptablePushEvent(msg, group)
	c.logMessageDebug("decrypt-fail", "push.encrypted", eventName, safeEvent, nil)
	if ns != "" && seq > 0 {
		return c.publishOrderedMessage(eventName, ns, seq, safeEvent)
	}
	c.publishAppEvent(eventName, safeEvent)
	return true
}

func (v *v2E2EECoordinator) decryptEncryptedPushPayload(msg map[string]any, group bool) map[string]any {
	c := v.runtime.client
	envelope, ok := encryptedPushEnvelope(msg)
	if !ok || !isV2EncryptedEnvelopePayload(envelope) {
		return nil
	}
	fromAID := strings.TrimSpace(stringFromAny(msg["from_aid"]))
	if fromAID == "" {
		fromAID = strings.TrimSpace(stringFromAny(msg["from"]))
	}
	if fromAID == "" {
		fromAID = strings.TrimSpace(stringFromAny(msg["sender_aid"]))
	}
	if fromAID == "" {
		if aad, ok := envelope["aad"].(map[string]any); ok {
			fromAID = strings.TrimSpace(stringFromAny(aad["from"]))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	plaintext := v.decryptV2EnvelopeForThought(ctx, envelope, fromAID)
	if plaintext == nil {
		return nil
	}
	meta := v2MessageE2EEMetadata(envelope)
	result := map[string]any{
		"message_id": stringFromAny(msg["message_id"]),
		"from":       fromAID,
		"seq":        msg["seq"],
		"timestamp":  msg["timestamp"],
		"payload":    plaintext,
		"encrypted":  true,
		"e2ee":       meta,
	}
	direction := strings.TrimSpace(stringFromAny(msg["direction"]))
	if direction == "" {
		c.mu.RLock()
		selfAID := c.aid
		c.mu.RUnlock()
		if fromAID != "" && fromAID == selfAID {
			direction = "outbound_sync"
		} else {
			direction = "inbound"
		}
	}
	result["direction"] = direction
	if msg["t_server"] != nil {
		result["t_server"] = msg["t_server"]
		result["timestamp"] = msg["t_server"]
	}
	if msg["device_id"] != nil {
		result["device_id"] = msg["device_id"]
	}
	if msg["slot_id"] != nil {
		result["slot_id"] = msg["slot_id"]
	}
	if group {
		groupID := msg["group_id"]
		if groupID == nil {
			if aad, ok := envelope["aad"].(map[string]any); ok {
				groupID = aad["group_id"]
			}
		}
		if groupID == nil {
			groupID = envelope["group_id"]
		}
		result["group_id"] = groupID
	} else {
		to := msg["to"]
		if to == nil {
			c.mu.RLock()
			to = c.aid
			c.mu.RUnlock()
		}
		result["to"] = to
	}
	attachGatewayProximity(result, msg)
	attachV2EnvelopeMetadata(result, meta)
	c.logMessageDebug("decrypt-ok", "push.encrypted", map[bool]string{true: "group.message_created", false: "message.received"}[group], result, nil)
	return result
}

func (v *v2E2EECoordinator) publishEncryptedPushMessage(normalEvent, undecryptableEvent, ns string, seq int, msg map[string]any, group bool) bool {
	c := v.runtime.client
	decrypted := v.decryptEncryptedPushPayload(msg, group)
	if decrypted != nil {
		if ns != "" && seq > 0 {
			return c.publishOrderedMessage(normalEvent, ns, seq, decrypted)
		}
		c.publishAppEvent(normalEvent, decrypted)
		return true
	}
	return v.publishEncryptedPushAsUndecryptable(undecryptableEvent, ns, seq, msg, group)
}

func (v *v2E2EECoordinator) scheduleGroupSpkRegistration(groupID, reason string) {
	c := v.runtime.client
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return
	}
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return
	}
	v.groupSpkMu.Lock()
	if v.groupSpkRegistrationInflight[groupID] {
		v.groupSpkMu.Unlock()
		return
	}
	v.groupSpkRegistrationInflight[groupID] = true
	v.groupSpkMu.Unlock()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.logE2.Warn("V2 group SPK registration panic: %v", r)
			}
			v.groupSpkMu.Lock()
			delete(v.groupSpkRegistrationInflight, groupID)
			v.groupSpkMu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := state.session.EnsureGroupRegistered(ctx, groupID, c.v2CallFn()); err != nil {
			c.logE2.Debug("group SPK registration failed (non-fatal): group=%s reason=%s err=%v", groupID, reason, err)
		} else {
			c.logE2.Debug("group SPK registered: group=%s reason=%s", groupID, reason)
		}
	}()
}

func (v *v2E2EECoordinator) scheduleGroupSpkRotation(groupID, reason string) {
	c := v.runtime.client
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return
	}
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return
	}
	v.groupSpkMu.Lock()
	if v.groupSpkRotationInflight[groupID] {
		v.groupSpkMu.Unlock()
		return
	}
	v.groupSpkRotationInflight[groupID] = true
	v.groupSpkMu.Unlock()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.logE2.Warn("V2 group SPK rotation panic: %v", r)
			}
			v.groupSpkMu.Lock()
			delete(v.groupSpkRotationInflight, groupID)
			v.groupSpkMu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := state.session.RotateGroupSPK(ctx, groupID, c.v2CallFn()); err != nil {
			c.logE2.Debug("group SPK rotation failed (non-fatal): group=%s reason=%s err=%v", groupID, reason, err)
		} else {
			c.logE2.Debug("group SPK rotated: group=%s reason=%s", groupID, reason)
		}
	}()
}

func (v *v2E2EECoordinator) scheduleGroupSpkRegistrationAfterPeerFallback(groupID string) {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return
	}
	v.groupSpkMu.Lock()
	if v.groupSpkPeerFallbackRegistered[groupID] {
		v.groupSpkMu.Unlock()
		return
	}
	v.groupSpkPeerFallbackRegistered[groupID] = true
	v.groupSpkMu.Unlock()
	v.scheduleGroupSpkRegistration(groupID, "peer_device_prekey_fallback")
}

func (v *v2E2EECoordinator) handleGroupChangedSpk(groupID, action string, data map[string]any) {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" || !isV2GroupMembershipAction(action) {
		return
	}
	joinedAID := strings.TrimSpace(stringFromAny(data["joined_aid"]))
	if joinedAID == "" {
		joinedAID = strings.TrimSpace(stringFromAny(data["member_aid"]))
	}
	if joinedAID == "" {
		joinedAID = strings.TrimSpace(stringFromAny(data["aid"]))
	}
	actorAID := strings.TrimSpace(stringFromAny(data["actor_aid"]))
	selfAID := strings.TrimSpace(v.runtime.client.GetAID())
	isSelfJoin := isV2GroupJoinAction(action) && selfAID != "" &&
		(joinedAID == selfAID || (joinedAID == "" && (action == "joined" || action == "invite_code_used") && actorAID == selfAID))
	if isSelfJoin {
		v.scheduleGroupSpkRegistration(groupID, "group_changed:"+action)
	} else {
		v.scheduleGroupSpkRotation(groupID, "group_changed:"+action)
	}
}

func (v *v2E2EECoordinator) handleV2EpochRotated(data any) {
	c := v.runtime.client
	dataMap, ok := data.(map[string]any)
	if !ok {
		return
	}
	groupID := strings.TrimSpace(v2AsString(dataMap["group_id"]))
	if groupID == "" {
		return
	}
	newEpoch := dataMap["epoch"]
	c.logE2.Debug("onV2EpochRotated: group=%s epoch=%v", groupID, newEpoch)
	v.deleteGroupBootstrapCache(groupID)
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.logE2.Warn("SPK rotation after epoch change panic: %v", r)
			}
		}()
		rotateCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := state.session.RotateSPK(rotateCtx, c.v2CallFn()); err != nil {
			c.logE2.Debug("SPK rotation after epoch change failed (non-fatal): %v", err)
		} else {
			c.logE2.Info("SPK rotated after epoch change: group=%s epoch=%v", groupID, newEpoch)
		}
	}()
}

func isV2GroupMembershipAction(action string) bool {
	switch action {
	case "member_added", "member_left", "member_removed", "role_changed", "owner_transferred", "joined", "join_approved", "invite_code_used":
		return true
	default:
		return false
	}
}

func isV2GroupJoinAction(action string) bool {
	switch action {
	case "member_added", "joined", "join_approved", "invite_code_used":
		return true
	default:
		return false
	}
}
