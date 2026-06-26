package aun

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/modelunion/aun-sdk-core/go/v2/e2ee"
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
	v.runtime.v2.setStateLocked(state)
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
	sess := state.session // 捕获局部变量，避免 goroutine 内 use-after-close
	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.logE2.Warn("V2 group SPK registration panic: %v", r)
			}
			v.groupSpkMu.Lock()
			delete(v.groupSpkRegistrationInflight, groupID)
			v.groupSpkMu.Unlock()
		}()
		// 操作前重新检查 state 是否已被释放
		if cur := c.v2GetState(); cur == nil || cur.session != sess {
			c.logE2.Debug("group SPK registration skipped (session released): group=%s", groupID)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := sess.EnsureGroupRegistered(ctx, groupID, c.v2CallFn()); err != nil {
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
	sess := state.session // 捕获局部变量，避免 goroutine 内 use-after-close
	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.logE2.Warn("V2 group SPK rotation panic: %v", r)
			}
			v.groupSpkMu.Lock()
			delete(v.groupSpkRotationInflight, groupID)
			v.groupSpkMu.Unlock()
		}()
		// 操作前重新检查 state 是否已被释放
		if cur := c.v2GetState(); cur == nil || cur.session != sess {
			c.logE2.Debug("group SPK rotation skipped (session released): group=%s", groupID)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := sess.RotateGroupSPK(ctx, groupID, c.v2CallFn()); err != nil {
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
func v2PubDERMatchesFingerprint(pubDER []byte, certFingerprint string) bool {
	expected := strings.TrimSpace(strings.ToLower(certFingerprint))
	if expected == "" {
		return true
	}
	if !strings.HasPrefix(expected, "sha256:") {
		return false
	}
	expectedHex := strings.TrimPrefix(expected, "sha256:")
	if len(expectedHex) != 16 && len(expectedHex) != 64 {
		return false
	}
	for _, ch := range expectedHex {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	sum := sha256.Sum256(pubDER)
	spkiHex := fmt.Sprintf("%x", sum[:])
	if len(expectedHex) == 16 {
		return spkiHex[:16] == expectedHex
	}
	return spkiHex == expectedHex
}

func (c *AUNClient) getV2SenderPubDER(ctx context.Context, state *v2P2PState, fromAID, senderDeviceID, certFingerprint string) []byte {
	if state == nil || state.session == nil || strings.TrimSpace(fromAID) == "" {
		return nil
	}
	if senderPubDER := state.session.GetPeerIK(fromAID, senderDeviceID); len(senderPubDER) > 0 {
		if v2PubDERMatchesFingerprint(senderPubDER, certFingerprint) {
			return senderPubDER
		}
	}

	fetchCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		fetchCtx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	} else {
		var cctx context.Context
		cctx, cancel = context.WithTimeout(ctx, 3*time.Second)
		fetchCtx = cctx
	}
	defer cancel()

	certBytes, certErr := c.fetchPeerCert(fetchCtx, fromAID, certFingerprint)
	if certErr != nil {
		c.logE2.Warn("V2 decrypt: PKI cert sender IK fallback failed for %s: %v", fromAID, certErr)
		return nil
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		c.logE2.Warn("V2 decrypt: PKI cert sender IK fallback failed for %s: invalid PEM", fromAID)
		return nil
	}
	cert, parseErr := x509.ParseCertificate(block.Bytes)
	if parseErr != nil {
		c.logE2.Warn("V2 decrypt: PKI cert sender IK fallback failed for %s: %v", fromAID, parseErr)
		return nil
	}
	der, marshalErr := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if marshalErr != nil {
		c.logE2.Warn("V2 decrypt: PKI cert sender IK fallback failed for %s: %v", fromAID, marshalErr)
		return nil
	}
	if !v2PubDERMatchesFingerprint(der, certFingerprint) {
		c.logE2.Warn("V2 decrypt: PKI cert sender IK fingerprint mismatch for %s", fromAID)
		return nil
	}
	state.session.CachePeerIK(fromAID, senderDeviceID, der)
	c.logE2.Debug("V2 decrypt: sender IK fallback from PKI cert for %s", fromAID)
	return der
}

func (c *AUNClient) cacheV2PeerIKFromDevice(state *v2P2PState, dev map[string]any, fallbackAID string) {
	if state == nil || state.session == nil || dev == nil {
		return
	}
	devID, hasDeviceID := v2DeviceIDFromDevice(dev)
	aid := strings.TrimSpace(v2AsString(dev["aid"]))
	if aid == "" {
		aid = strings.TrimSpace(fallbackAID)
	}
	ikDER := v2DecodeBase64Field(dev, "ik_pk")
	if !hasDeviceID || aid == "" || len(ikDER) == 0 {
		return
	}
	state.session.CachePeerIK(aid, devID, ikDER)
}

func (v *v2E2EECoordinator) v2PendingSenderIKMessageKey(msg map[string]any, groupID string) string {
	c := v.runtime.client
	messageID := strings.TrimSpace(v2AsString(msg["message_id"]))
	seqText := strings.TrimSpace(fmt.Sprint(msg["seq"]))
	prefix := "p2p:" + c.AID()
	if strings.TrimSpace(groupID) != "" {
		prefix = "group:" + groupID
	}
	if messageID != "" {
		return prefix + ":" + messageID
	}
	if seqText != "" && seqText != "<nil>" {
		return prefix + ":" + seqText
	}
	return fmt.Sprintf("%s:pending:%d", prefix, time.Now().UnixNano())
}

func v2PendingSenderIKFetchKey(fromAID, senderDeviceID, groupID string) string {
	return strings.TrimSpace(fromAID) + "#" + senderDeviceID + "#" + strings.TrimSpace(groupID)
}

func (v *v2E2EECoordinator) scheduleV2SenderIKPending(msg map[string]any, fromAID, senderDeviceID, groupID string) {
	c := v.runtime.client
	fromAID = strings.TrimSpace(fromAID)
	if fromAID == "" {
		return
	}
	groupID = strings.TrimSpace(groupID)
	messageKey := v.v2PendingSenderIKMessageKey(msg, groupID)
	fetchKey := v2PendingSenderIKFetchKey(fromAID, senderDeviceID, groupID)
	shouldFetch := false
	c.v2SenderIKMu.Lock()
	c.v2SenderIKPending[messageKey] = v2SenderIKPendingEntry{
		Msg:            copyMapShallow(msg),
		FromAID:        fromAID,
		SenderDeviceID: senderDeviceID,
		GroupID:        groupID,
		CreatedAt:      time.Now(),
	}
	if !c.v2SenderIKFetching[fetchKey] {
		c.v2SenderIKFetching[fetchKey] = true
		shouldFetch = true
	}
	pendingCount := len(c.v2SenderIKPending)
	c.v2SenderIKMu.Unlock()
	c.logE2.Debug("V2 decrypt pending sender IK: key=%s from=%s device=%s group=%s pending=%d",
		messageKey, fromAID, valueOrDefault(senderDeviceID, "-"), valueOrDefault(groupID, "<p2p>"), pendingCount)
	if shouldFetch {
		go v.resolveV2SenderIKPending(fromAID, senderDeviceID, groupID, fetchKey)
	}
}

func (v *v2E2EECoordinator) scheduleV2SenderIKFetch(fromAID, senderDeviceID, groupID string) {
	c := v.runtime.client
	fromAID = strings.TrimSpace(fromAID)
	if fromAID == "" {
		return
	}
	groupID = strings.TrimSpace(groupID)
	fetchKey := v2PendingSenderIKFetchKey(fromAID, senderDeviceID, groupID)
	c.v2SenderIKMu.Lock()
	if c.v2SenderIKFetching[fetchKey] {
		c.v2SenderIKMu.Unlock()
		return
	}
	c.v2SenderIKFetching[fetchKey] = true
	c.v2SenderIKMu.Unlock()
	go v.resolveV2SenderIKPending(fromAID, senderDeviceID, groupID, fetchKey)
}

func (v *v2E2EECoordinator) resolveV2SenderIKPending(fromAID, senderDeviceID, groupID, fetchKey string) {
	c := v.runtime.client
	defer func() {
		if r := recover(); r != nil {
			c.logE2.Warn("V2 sender IK pending resolver panic: from=%s device=%s group=%s panic=%v", fromAID, senderDeviceID, groupID, r)
		}
		c.v2SenderIKMu.Lock()
		delete(c.v2SenderIKFetching, fetchKey)
		c.v2SenderIKMu.Unlock()
	}()

	state := c.v2GetState()
	if state == nil || state.session == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if raw, err := c.Call(ctx, "message.v2.bootstrap", map[string]any{
		"peer_aid":               fromAID,
		"e2ee_wrap_capabilities": v2WrapCapabilities(),
	}); err == nil {
		if bs, _ := raw.(map[string]any); bs != nil {
			for _, dev := range v2ToMapList(bs["peer_devices"]) {
				c.cacheV2PeerIKFromDevice(state, dev, fromAID)
			}
		}
	} else {
		c.logE2.Warn("V2 sender IK pending bootstrap failed peer=%s: %v", fromAID, err)
	}
	if strings.TrimSpace(groupID) != "" {
		if raw, err := c.Call(ctx, "group.v2.bootstrap", map[string]any{
			"group_id":               groupID,
			"e2ee_wrap_capabilities": v2WrapCapabilities(),
		}); err == nil {
			if bs, _ := raw.(map[string]any); bs != nil {
				for _, dev := range v2ToMapList(bs["devices"]) {
					c.cacheV2PeerIKFromDevice(state, dev, "")
				}
				for _, dev := range v2ToMapList(bs["audit_recipients"]) {
					c.cacheV2PeerIKFromDevice(state, dev, "")
				}
			}
		} else {
			c.logE2.Warn("V2 sender IK pending group bootstrap failed group=%s: %v", groupID, err)
		}
	}
	if len(state.session.GetPeerIK(fromAID, senderDeviceID)) == 0 {
		shortCtx, shortCancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = c.getV2SenderPubDER(shortCtx, state, fromAID, senderDeviceID, "")
		shortCancel()
	}

	// 持锁复制 pending 列表后释放锁，锁外处理，处理完持锁删已处理条目
	c.v2SenderIKMu.Lock()
	pendingItems := make(map[string]v2SenderIKPendingEntry)
	for key, entry := range c.v2SenderIKPending {
		if entry.FromAID == fromAID && entry.SenderDeviceID == senderDeviceID && entry.GroupID == groupID {
			pendingItems[key] = entry
		}
	}
	c.v2SenderIKMu.Unlock()

	processedKeys := make([]string, 0, len(pendingItems))
	for key, entry := range pendingItems {
		retryCtx, retryCancel := context.WithTimeout(context.Background(), 30*time.Second)
		plaintext := c.decryptV2MessageWithPending(retryCtx, state, entry.Msg, false)
		retryCancel()
		processedKeys = append(processedKeys, key)
		if plaintext == nil {
			c.logE2.Debug("V2 sender IK pending retry failed: key=%s", key)
			continue
		}
		seq := int(toInt64(entry.Msg["seq"]))
		if entry.GroupID != "" {
			plaintext["group_id"] = entry.GroupID
			c.publishPulledMessage("group.message_created", "group:"+entry.GroupID, seq, plaintext)
		} else {
			c.publishPulledMessage("message.received", "p2p:"+c.AID(), seq, plaintext)
		}
		c.logE2.Debug("V2 sender IK pending retry delivered: key=%s", key)
	}
	// 批量删除已处理条目，仅删除未被替换的（CreatedAt 一致）
	if len(processedKeys) > 0 {
		c.v2SenderIKMu.Lock()
		for _, key := range processedKeys {
			if cur, ok := c.v2SenderIKPending[key]; ok && cur.CreatedAt == pendingItems[key].CreatedAt {
				delete(c.v2SenderIKPending, key)
			}
		}
		c.v2SenderIKMu.Unlock()
	}
}

// SendV2 V2 P2P 推测性加密发送。
//
//   - 优先使用 bootstrap 缓存（TTL = v2BootstrapTTL）。
//   - 缓存命中则直接发送；命中失败时刷新缓存重试 1 次。
//   - 同时携带 audit_recipients（监管方）和 self_sync（本 AID 其它设备）。
func (v *v2E2EECoordinator) sendV2(ctx context.Context, to string, payload map[string]any) (map[string]any, error) {
	return v.SendV2WithOpts(ctx, to, payload, e2ee.EncryptOptions{})
}

// SendV2WithOpts 与 SendV2 相同，但允许传入 EncryptOptions（含 ProtectedHeaders / Context）。
func (v *v2E2EECoordinator) SendV2WithOpts(ctx context.Context, to string, payload map[string]any, opts e2ee.EncryptOptions) (map[string]any, error) {
	c := v.runtime.client
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return nil, errors.New("V2 session not initialized (not connected?)")
	}
	if to == "" {
		return nil, errors.New("send_v2: to 不能为空")
	}
	c.logMessageDebugWithPayload("send-plaintext", "message.send.v2", "message.send", map[string]any{
		"to":      to,
		"payload": payload,
	}, payload, nil)
	resultParams := map[string]any{
		"to":                to,
		"payload":           payload,
		"protected_headers": opts.ProtectedHeaders,
		"context":           opts.Context,
	}
	if opts.Timestamp > 0 {
		resultParams["timestamp"] = opts.Timestamp
	}

	resp, err := v.v2SendOnce(ctx, state, to, payload, true, opts)
	if err == nil {
		return c.delivery().attachSendResultEnvelope("message.send", resultParams, resp, true).(map[string]any), nil
	}

	if isV2RetryableError(err) {
		c.logE2.Debug("V2 P2P speculative send rejected (code=%d), refreshing bootstrap", v2ErrorCode(err))
		v.deletePeerBootstrapCache(to)
		resp, retryErr := v.v2SendOnce(ctx, state, to, payload, false, opts)
		if retryErr != nil {
			return nil, retryErr
		}
		return c.delivery().attachSendResultEnvelope("message.send", resultParams, resp, true).(map[string]any), nil
	}
	return nil, err
}

func (v *v2E2EECoordinator) v2SendOnce(ctx context.Context, state *v2P2PState, to string, payload map[string]any, useCache bool, opts e2ee.EncryptOptions) (map[string]any, error) {
	c := v.runtime.client
	c.logE2.Debug("message.v2.send attempt: to=%s use_cache=%v", to, useCache)
	peerDevices, auditRaw, wrapPolicy, err := v.v2ResolveBootstrap(ctx, state, to, useCache)
	if err != nil {
		return nil, err
	}
	if len(peerDevices) == 0 {
		return nil, fmt.Errorf("V2 bootstrap: no devices found for %s", to)
	}

	targets := make([]e2ee.Target, 0, len(peerDevices))
	for _, dev := range peerDevices {
		devID := v2AsString(dev["device_id"])
		target, ok, err := c.v2BuildTargetFromDevice(ctx, state, dev, to, devID, "peer", "peer_device_prekey")
		if err != nil {
			return nil, err
		}
		if ok {
			targets = append(targets, target)
		}
	}

	auditTargets := make([]e2ee.Target, 0, len(auditRaw))
	for _, dev := range auditRaw {
		target, ok, err := c.v2BuildTargetFromDevice(ctx, state, dev, v2AsString(dev["aid"]), v2AsString(dev["device_id"]), "audit", "peer_device_prekey")
		if err != nil {
			return nil, err
		}
		if ok {
			auditTargets = append(auditTargets, target)
		}
	}

	// self-sync：同 AID 其它设备
	c.mu.RLock()
	myAID := c.aid
	myDeviceID := c.deviceID
	c.mu.RUnlock()
	if myAID != "" && myAID != to {
		selfDevices := v.v2FetchSelfDevices(ctx, state, myAID)
		for _, dev := range selfDevices {
			devID, hasDeviceID := v2DeviceIDFromDevice(dev)
			if !hasDeviceID || devID == myDeviceID {
				continue
			}
			target, ok, err := c.v2BuildTargetFromDevice(ctx, state, dev, myAID, devID, "self_sync", "peer_device_prekey")
			if err != nil {
				return nil, err
			}
			if ok {
				targets = append(targets, target)
			}
		}
	}

	sender, err := state.session.GetSenderIdentity()
	if err != nil {
		return nil, fmt.Errorf("send_v2: 获取 sender identity 失败: %w", err)
	}

	sendTargets := v2ApplyWrapPolicyToTargets(targets, wrapPolicy)
	sendAuditTargets := v2ApplyWrapPolicyToTargets(auditTargets, wrapPolicy)
	envelope, err := e2ee.EncryptP2PMessage(
		e2ee.Sender{
			AID:      sender.AID,
			DeviceID: sender.DeviceID,
			IKPriv:   sender.IKPriv,
			IKPubDER: sender.IKPubDER,
		},
		e2ee.TargetSet{Targets: sendTargets, AuditRecipients: sendAuditTargets},
		payload,
		opts,
	)
	if err != nil {
		return nil, fmt.Errorf("send_v2: 加密失败: %w", err)
	}
	c.logMessageDebugWithPayload("send-envelope", "message.send.v2", "message.send", map[string]any{
		"to":         to,
		"message_id": envelope["message_id"],
		"type":       envelope["type"],
		"version":    envelope["version"],
	}, envelope, map[string]any{
		"plaintext_payload": payload,
		"target_count":      len(sendTargets),
		"audit_count":       len(sendAuditTargets),
		"use_cache":         useCache,
	})

	raw, err := c.Call(ctx, "message.send", map[string]any{
		"to":                         to,
		"payload":                    envelope,
		"encrypt":                    false,
		"_skip_send_result_envelope": true,
	})
	if err != nil {
		return nil, err
	}
	if m, ok := raw.(map[string]any); ok {
		c.logE2.Debug("message.v2.send ok: to=%s use_cache=%v seq=%d", to, useCache, toInt64(m["seq"]))
		return m, nil
	}
	c.logE2.Debug("message.v2.send ok: to=%s use_cache=%v seq=<unknown>", to, useCache)
	return map[string]any{}, nil
}

// v2ResolveBootstrap 根据 useCache 决定是否使用缓存，未命中则调 message.v2.bootstrap。
func (v *v2E2EECoordinator) v2ResolveBootstrap(ctx context.Context, state *v2P2PState, peerAID string, useCache bool) ([]map[string]any, []map[string]any, *v2WrapPolicy, error) {
	c := v.runtime.client
	if useCache {
		entry, ok := v.getPeerBootstrapCache(state, peerAID)
		if ok && time.Since(entry.CachedAt) < v2BootstrapTTL {
			c.logE2.Debug("message.v2.bootstrap cache hit: peer=%s devices=%d audit=%d", peerAID, len(entry.Devices), len(entry.AuditRecipients))
			return entry.Devices, entry.AuditRecipients, entry.WrapPolicy, nil
		}
	}
	raw, err := c.Call(ctx, "message.v2.bootstrap", map[string]any{
		"peer_aid":               peerAID,
		"e2ee_wrap_capabilities": v2WrapCapabilities(),
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("V2 bootstrap: %w", err)
	}
	bs, _ := raw.(map[string]any)
	devices := v2ToMapList(bs["peer_devices"])
	audit := v2ToMapList(bs["audit_recipients"])
	wrapPolicy := v2NormalizeWrapPolicy(bs["e2ee_wrap_policy"])
	c.logE2.Debug("message.v2.bootstrap fetched: peer=%s devices=%d audit=%d", peerAID, len(devices), len(audit))
	if len(devices) > 0 {
		v.setPeerBootstrapCache(state, peerAID, v2BootstrapEntry{
			Devices:         devices,
			AuditRecipients: audit,
			CachedAt:        time.Now(),
			WrapPolicy:      wrapPolicy,
		})
	}
	return devices, audit, wrapPolicy, nil
}

// v2FetchSelfDevices 缓存优先获取本 AID 其它设备列表（best-effort，错误吞掉返回空）。
func (v *v2E2EECoordinator) v2FetchSelfDevices(ctx context.Context, state *v2P2PState, myAID string) []map[string]any {
	c := v.runtime.client
	entry, ok := v.getPeerBootstrapCache(state, myAID)
	if ok && time.Since(entry.CachedAt) < v2BootstrapTTL {
		return entry.Devices
	}
	raw, err := c.Call(ctx, "message.v2.bootstrap", map[string]any{
		"peer_aid":               myAID,
		"e2ee_wrap_capabilities": v2WrapCapabilities(),
	})
	if err != nil {
		c.logE2.Debug("V2 self-sync bootstrap failed (non-fatal): %v", err)
		return nil
	}
	bs, _ := raw.(map[string]any)
	devices := v2ToMapList(bs["peer_devices"])
	if len(devices) > 0 {
		v.setPeerBootstrapCache(state, myAID, v2BootstrapEntry{
			Devices:  devices,
			CachedAt: time.Now(),
		})
	}
	return devices
}

// PullV2 拉取并解密 V2 P2P 消息。
//
// afterSeq=0 时使用本地 SeqTracker 的 contiguous_seq（对齐 Python pull_v2）。
// limit=0 时默认 50。
func (v *v2E2EECoordinator) pullV2(ctx context.Context, afterSeq int64, limit int) ([]map[string]any, error) {
	msgs, _, err := v.pullV2WithForce(ctx, afterSeq, limit, false)
	return msgs, err
}

func (v *v2E2EECoordinator) pullV2WithForce(ctx context.Context, afterSeq int64, limit int, force bool) ([]map[string]any, v2PullPageMeta, error) {
	c := v.runtime.client
	meta := v2PullPageMeta{}
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return nil, meta, errors.New("V2 session not initialized (not connected?)")
	}
	if limit <= 0 {
		limit = 50
	}

	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	ns := ""
	if myAID != "" {
		ns = "p2p:" + myAID
	}

	effectiveAfterSeq := afterSeq
	if !force && effectiveAfterSeq == 0 && ns != "" {
		effectiveAfterSeq = int64(c.seqTracker.GetContiguousSeq(ns))
	}

	c.logE2.Debug("message.v2.pull request: after_seq=%d limit=%d ns=%s", effectiveAfterSeq, limit, ns)
	pullParams := map[string]any{
		"after_seq": effectiveAfterSeq,
		"limit":     limit,
	}
	if force {
		pullParams["force"] = true
	}
	if err := c.signClientOperation("message.v2.pull", pullParams); err != nil {
		return nil, meta, err
	}
	if rpcBackgroundFromContext(ctx) {
		pullParams["_rpc_background"] = true
	}
	raw, err := c.transport.Call(ctx, "message.v2.pull", pullParams)
	if err != nil {
		return nil, meta, err
	}
	result, _ := raw.(map[string]any)
	messages := v2ToMapList(result["messages"])
	_, hasServerAckSeq := result["server_ack_seq"]
	serverAckSeq := toInt64(result["server_ack_seq"])
	meta = v2PullPageMeta{
		rawCount:     len(messages),
		serverAckSeq: serverAckSeq,
		hasServerAck: hasServerAckSeq,
	}
	c.logE2.Debug("message.v2.pull response: raw_count=%d server_ack_seq=%d has_more=%v", len(messages), serverAckSeq, result["has_more"])
	for _, msg := range messages {
		c.logMessageDebug("pull-raw", "message.v2.pull", "message.received", msg, nil)
	}

	decrypted := make([]map[string]any, 0, len(messages))
	contigBefore := 0
	if ns != "" {
		contigBefore = c.seqTracker.GetContiguousSeq(ns)
	}
	maxSeq := int64(0)
	for _, msg := range messages {
		seq := toInt64(msg["seq"])
		if seq <= 0 {
			continue
		}
		if seq > maxSeq {
			maxSeq = seq
		}
	}

	if v.canParallelDecryptV2Page(messages, "", true) {
		for _, plaintext := range v.decryptV2PageParallel(ctx, state, messages, "", true) {
			if plaintext != nil {
				decrypted = append(decrypted, plaintext)
				c.logMessageDebug("decrypt-ok", "message.v2.pull", "message.received", plaintext, nil)
			}
		}
	} else {
		for _, msg := range messages {
			seq := toInt64(msg["seq"])
			if seq <= 0 {
				continue
			}

			if v2AsString(msg["version"]) == "v1" {
				if legacy, ok := v2BuildLegacyP2PMessage(msg, myAID); ok {
					decrypted = append(decrypted, legacy)
					c.logE2.Debug("message.v2.pull plaintext V1 decrypted: seq=%d ns=%s", seq, ns)
				} else {
					c.logE2.Debug("V2 pull skipped legacy V1 encrypted/empty message: seq=%d", seq)
				}
				continue
			}

			// 跟踪每个旧 SPK 引用的最大 seq（用于消费后销毁）
			msgSpkID := v2AsString(msg["spk_id"])
			if msgSpkID != "" && !state.session.IsCurrentSPK(msgSpkID) {
				state.session.TrackOldSPKMaxSeq(msgSpkID, seq)
			}

			plaintext := c.decryptV2Message(ctx, state, msg)
			if plaintext != nil {
				decrypted = append(decrypted, plaintext)
				c.logMessageDebug("decrypt-ok", "message.v2.pull", "message.received", plaintext, nil)
			} else {
				c.logE2.Debug("message.v2.pull decrypt returned nil: seq=%d ns=%s", seq, ns)
			}
		}
	}

	if ns != "" {
		if maxSeq > 0 {
			currentContig := c.seqTracker.GetContiguousSeq(ns)
			if int(maxSeq) > currentContig {
				c.seqTracker.ForceContiguousSeq(ns, int(maxSeq))
				c.logE2.Debug("V2 P2P pull force-advanced contig: %d -> %d", currentContig, maxSeq)
				c.drainOrderedMessages(ns)
			}
		}
		if serverAckSeq > 0 {
			currentContig := c.seqTracker.GetContiguousSeq(ns)
			if int(serverAckSeq) > currentContig {
				c.seqTracker.ForceContiguousSeq(ns, int(serverAckSeq))
				c.logE2.Info("V2 P2P pull retention-floor advanced: ns=%s contiguous=%d -> server_ack_seq=%d", ns, currentContig, serverAckSeq)
				c.drainOrderedMessages(ns)
			}
		}
		if c.seqTracker.GetContiguousSeq(ns) != contigBefore {
			c.persistSeq(ns)
		}
	}

	c.logE2.Debug("message.v2.pull done: requested_after_seq=%d raw_count=%d decrypted=%d ns=%s", afterSeq, len(messages), len(decrypted), ns)
	return decrypted, meta, nil
}

// AckV2 确认 V2 消息已消费 + 自检销毁旧 SPK。
//
// upToSeq=0 时使用本地 SeqTracker 的 contiguous_seq。返回 {"acked": int64} 兜底。
func (v *v2E2EECoordinator) ackV2(ctx context.Context, upToSeq int64) (map[string]any, error) {
	c := v.runtime.client
	state := c.v2GetState()

	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	ns := ""
	if myAID != "" {
		ns = "p2p:" + myAID
	}

	seq := upToSeq
	if seq == 0 && ns != "" {
		seq = int64(c.seqTracker.GetContiguousSeq(ns))
	}
	if seq <= 0 {
		c.logE2.Debug("message.v2.ack skipped: ns=%s up_to_seq=%d", ns, upToSeq)
		return map[string]any{"acked": int64(0)}, nil
	}
	if ns != "" {
		seq = c.clampAckSeq("message.v2.ack", "up_to_seq", ns, seq)
		if seq <= 0 {
			return map[string]any{"acked": int64(0)}, nil
		}
	}

	c.logE2.Debug("message.v2.ack send: ns=%s up_to_seq=%d", ns, seq)
	ackParams := map[string]any{"up_to_seq": seq}
	if rpcBackgroundFromContext(ctx) {
		ackParams["_rpc_background"] = true
	}
	raw, err := c.Call(ctx, "message.v2.ack", ackParams)
	if err != nil {
		return nil, err
	}
	result, _ := raw.(map[string]any)
	if result == nil {
		result = map[string]any{}
	}
	actualAckSeq := seq
	if _, ok := result["effective_ack_seq"]; ok {
		actualAckSeq = toInt64(result["effective_ack_seq"])
	} else if _, ok := result["ack_seq"]; ok {
		actualAckSeq = toInt64(result["ack_seq"])
	} else if _, ok := result["cursor"]; ok {
		actualAckSeq = toInt64(result["cursor"])
	}

	if state != nil && state.session != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					c.logE2.Debug("V2 SPK destroy failed (non-fatal): %v", r)
				}
			}()
			destroyed := state.session.MaybeDestroyOldSPKs(actualAckSeq)
			if len(destroyed) > 0 {
				limit := len(destroyed)
				if limit > 3 {
					limit = 3
				}
				c.logE2.Info("V2 destroyed old SPKs after ack: %v (PFS)", destroyed[:limit])
			}
		}()
	}
	result["ack_seq"] = actualAckSeq
	result["success"] = true
	if toInt64(result["acked"]) == 0 && actualAckSeq > 0 {
		result["acked"] = actualAckSeq
	}
	c.logE2.Debug("message.v2.ack ok: ns=%s requested=%d effective=%d result=%v", ns, seq, actualAckSeq, result)
	return result, nil
}

type v2DecryptPageJob struct {
	seq                int64
	msg                map[string]any
	envelope           map[string]any
	spkID              string
	recipientKeySource string
	groupIDForKeys     string
	fromAID            string
	senderDeviceID     string
	ikPriv             []byte
	spkPriv            []byte
	senderPubDER       []byte
	e2eeMeta           map[string]any
	undecryptableEvent string
}

type v2DecryptPageResult struct {
	job       v2DecryptPageJob
	plaintext map[string]any
	err       error
}

func decodeV2EnvelopeJSON(msg map[string]any) (map[string]any, error) {
	envJSON := v2AsString(msg["envelope_json"])
	if envJSON == "" {
		return nil, errors.New("missing envelope_json")
	}
	dec := json.NewDecoder(strings.NewReader(envJSON))
	dec.UseNumber()
	var envelope map[string]any
	if err := dec.Decode(&envelope); err != nil {
		return nil, err
	}
	return envelope, nil
}

func v2EnvelopeGroupID(msg map[string]any, envelope map[string]any) string {
	if aad, ok := envelope["aad"].(map[string]any); ok {
		if gid := strings.TrimSpace(v2AsString(aad["group_id"])); gid != "" {
			return gid
		}
	}
	if gid := strings.TrimSpace(v2AsString(msg["group_id"])); gid != "" {
		return gid
	}
	return strings.TrimSpace(v2AsString(envelope["group_id"]))
}

func (v *v2E2EECoordinator) canParallelDecryptV2Page(messages []map[string]any, expectedGroupID string, p2p bool) bool {
	if len(messages) <= 1 {
		return false
	}
	for _, msg := range messages {
		if toInt64(msg["seq"]) <= 0 {
			return false
		}
		if v2AsString(msg["version"]) == "v1" {
			return false
		}
		envelope, err := decodeV2EnvelopeJSON(msg)
		if err != nil {
			return false
		}
		groupIDForKeys := v2EnvelopeGroupID(msg, envelope)
		if p2p {
			if groupIDForKeys != "" {
				return false
			}
		} else if groupIDForKeys != expectedGroupID {
			return false
		}
	}
	return true
}

func (v *v2E2EECoordinator) prepareDecryptPageJob(ctx context.Context, state *v2P2PState, msg map[string]any, expectedGroupID string, p2p bool) (v2DecryptPageJob, bool) {
	c := v.runtime.client
	seq := toInt64(msg["seq"])
	envelope, err := decodeV2EnvelopeJSON(msg)
	if err != nil {
		c.logE2.Warn("V2 decrypt: invalid envelope_json for msg seq=%v: %v", msg["seq"], err)
		return v2DecryptPageJob{}, false
	}
	e2eeMeta := v2MessageE2EEMetadata(envelope)
	c.observeAgentMDFromEnvelope(envelope)

	c.mu.RLock()
	selfAID := c.aid
	selfDeviceID := c.deviceID
	c.mu.RUnlock()

	spkID := ""
	recipientKeySource := ""
	if r, ok := envelope["recipient"].(map[string]any); ok {
		spkID = v2AsString(r["spk_id"])
		recipientKeySource = v2AsString(r["key_source"])
	} else if rows, ok := envelope["recipients"]; ok {
		spkID = v2AsString(msg["spk_id"])
		if recipients, ok := rows.([]any); ok {
			for _, row := range recipients {
				cells, ok := row.([]any)
				if !ok || len(cells) < 6 {
					continue
				}
				if v2AsString(cells[0]) != selfAID || v2AsString(cells[1]) != selfDeviceID {
					continue
				}
				if spkID == "" {
					spkID = v2AsString(cells[5])
				}
				if len(cells) > 3 {
					recipientKeySource = v2AsString(cells[3])
				}
				break
			}
		}
	}

	groupIDForKeys := v2EnvelopeGroupID(msg, envelope)
	if p2p {
		if groupIDForKeys != "" {
			return v2DecryptPageJob{}, false
		}
	} else if groupIDForKeys != expectedGroupID {
		return v2DecryptPageJob{}, false
	}
	undecryptableEvent := "message.undecryptable"
	if groupIDForKeys != "" {
		undecryptableEvent = "group.message_undecryptable"
	}
	c.logE2.Debug("V2 decrypt start: seq=%v message_id=%s group=%s from=%s spk_id=%s key_source=%s has_recipient=%v has_recipients=%v",
		msg["seq"], v2AsString(msg["message_id"]), valueOrDefault(groupIDForKeys, "<p2p>"), v2AsString(msg["from_aid"]), valueOrDefault(spkID, "<empty>"), valueOrDefault(recipientKeySource, "<empty>"),
		envelope["recipient"] != nil, envelope["recipients"] != nil)

	var ikPriv, spkPriv []byte
	if groupIDForKeys != "" {
		ikPriv, spkPriv, err = state.session.GetGroupDecryptKeys(groupIDForKeys, spkID)
	} else {
		ikPriv, spkPriv, err = state.session.GetDecryptKeys(spkID)
	}
	if err != nil {
		c.logE2.Warn("V2 decrypt: GetDecryptKeys 失败 seq=%v group=%s: %v", msg["seq"], groupIDForKeys, err)
		event := map[string]any{
			"message_id":     v2AsString(msg["message_id"]),
			"from":           v2AsString(msg["from_aid"]),
			"to":             v2AsString(msg["to"]),
			"seq":            msg["seq"],
			"timestamp":      msg["t_server"],
			"device_id":      v2AsString(msg["device_id"]),
			"slot_id":        v2AsString(msg["slot_id"]),
			"_decrypt_error": err.Error(),
			"_decrypt_stage": "spk_lookup",
			"_envelope_type": v2AsString(envelope["type"]),
			"_suite":         v2AsString(envelope["suite"]),
			"_spk_id":        spkID,
		}
		attachV2EnvelopeMetadata(event, e2eeMeta)
		c.logMessageDebug("decrypt-fail", "v2.decrypt", undecryptableEvent, event, nil)
		c.publishAppEventSync(undecryptableEvent, event)
		return v2DecryptPageJob{}, false
	}
	c.logE2.Debug("V2 decrypt key lookup ok: seq=%v group=%s ik_len=%d spk_len=%d", msg["seq"], valueOrDefault(groupIDForKeys, "<p2p>"), len(ikPriv), len(spkPriv))

	if p2p {
		msgSpkID := v2AsString(msg["spk_id"])
		if msgSpkID != "" && !state.session.IsCurrentSPK(msgSpkID) {
			state.session.TrackOldSPKMaxSeq(msgSpkID, seq)
		}
	}

	fromAID := v2AsString(msg["from_aid"])
	senderDeviceID := ""
	if aad, ok := envelope["aad"].(map[string]any); ok {
		senderDeviceID = v2AsString(aad["from_device"])
	}
	senderCertFingerprint := strings.TrimSpace(stringFromAny(envelope["sender_cert_fingerprint"]))
	senderPubDER := c.getV2SenderPubDER(ctx, state, fromAID, senderDeviceID, senderCertFingerprint)
	if len(senderPubDER) == 0 {
		c.logE2.Warn("V2 decrypt: no sender IK for %s device=%s", fromAID, senderDeviceID)
		c.scheduleV2SenderIKPending(msg, fromAID, senderDeviceID, groupIDForKeys)
		return v2DecryptPageJob{}, false
	}

	return v2DecryptPageJob{
		seq:                seq,
		msg:                msg,
		envelope:           envelope,
		spkID:              spkID,
		recipientKeySource: recipientKeySource,
		groupIDForKeys:     groupIDForKeys,
		fromAID:            fromAID,
		senderDeviceID:     senderDeviceID,
		ikPriv:             ikPriv,
		spkPriv:            spkPriv,
		senderPubDER:       senderPubDER,
		e2eeMeta:           e2eeMeta,
		undecryptableEvent: undecryptableEvent,
	}, true
}

func (v *v2E2EECoordinator) decryptV2PageParallel(ctx context.Context, state *v2P2PState, messages []map[string]any, expectedGroupID string, p2p bool) []map[string]any {
	c := v.runtime.client
	jobs := make([]v2DecryptPageJob, 0, len(messages))
	for _, msg := range messages {
		if toInt64(msg["seq"]) <= 0 {
			continue
		}
		job, ok := v.prepareDecryptPageJob(ctx, state, msg, expectedGroupID, p2p)
		if ok {
			jobs = append(jobs, job)
		}
	}
	if len(jobs) == 0 {
		return nil
	}

	c.mu.RLock()
	selfAID := c.aid
	selfDeviceID := c.deviceID
	c.mu.RUnlock()

	results := make([]v2DecryptPageResult, len(jobs))
	var wg sync.WaitGroup
	wg.Add(len(jobs))
	for i, job := range jobs {
		go func(i int, job v2DecryptPageJob) {
			defer wg.Done()
			plaintext, err := e2ee.DecryptMessage(job.envelope, selfAID, selfDeviceID, job.ikPriv, job.spkPriv, job.senderPubDER)
			results[i] = v2DecryptPageResult{job: job, plaintext: plaintext, err: err}
		}(i, job)
	}
	wg.Wait()

	decrypted := make([]map[string]any, 0, len(results))
	for _, item := range results {
		job := item.job
		msg := job.msg
		if item.err != nil {
			c.logE2.Warn("V2 decrypt failed for msg seq=%v: %v", msg["seq"], item.err)
			event := map[string]any{
				"message_id":     v2AsString(msg["message_id"]),
				"from":           job.fromAID,
				"to":             v2AsString(msg["to"]),
				"seq":            msg["seq"],
				"timestamp":      msg["t_server"],
				"device_id":      v2AsString(msg["device_id"]),
				"slot_id":        v2AsString(msg["slot_id"]),
				"_decrypt_error": item.err.Error(),
				"_decrypt_stage": "decrypt",
				"_envelope_type": v2AsString(job.envelope["type"]),
				"_suite":         v2AsString(job.envelope["suite"]),
			}
			attachV2EnvelopeMetadata(event, job.e2eeMeta)
			c.logMessageDebug("decrypt-fail", "v2.decrypt", job.undecryptableEvent, event, nil)
			c.publishAppEventSync(job.undecryptableEvent, event)
			continue
		}
		if item.plaintext == nil {
			c.logE2.Debug("V2 decrypt returned nil plaintext: seq=%v group=%s", msg["seq"], valueOrDefault(job.groupIDForKeys, "<p2p>"))
			continue
		}

		if job.groupIDForKeys != "" && job.recipientKeySource == "group_device_prekey" && state.session.IsLastUploadedGroupSPK(job.groupIDForKeys, job.spkID) {
			c.getV2E2EECoordinator().scheduleGroupSpkRotation(job.groupIDForKeys, "group_spk_consumed")
		} else if job.groupIDForKeys != "" && job.recipientKeySource == "peer_device_prekey" {
			c.getV2E2EECoordinator().scheduleGroupSpkRegistrationAfterPeerFallback(job.groupIDForKeys)
		} else if job.groupIDForKeys == "" && state.session.IsLastUploadedSPK(job.spkID) {
			go func() {
				defer func() {
					if r := recover(); r != nil {
						c.logE2.Warn("V2 SPK rotation panic: %v", r)
					}
				}()
				rotateCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := state.session.RotateSPK(rotateCtx, c.v2CallFn()); err != nil {
					c.logE2.Warn("V2 SPK rotation failed (non-fatal): %v", err)
				} else {
					c.logE2.Debug("V2 SPK rotated after consumption: aid=%s", selfAID)
				}
			}()
		}

		result := map[string]any{
			"message_id": v2AsString(msg["message_id"]),
			"from":       job.fromAID,
			"to":         selfAID,
			"seq":        msg["seq"],
			"t_server":   msg["t_server"],
			"payload":    item.plaintext,
			"encrypted":  true,
			"e2ee":       job.e2eeMeta,
		}
		direction := strings.TrimSpace(v2AsString(msg["direction"]))
		if direction == "" {
			if job.fromAID != "" && job.fromAID == selfAID {
				direction = "outbound_sync"
			} else {
				direction = "inbound"
			}
		}
		result["direction"] = direction
		if v, ok := msg["device_id"]; ok {
			result["device_id"] = v
		}
		if v, ok := msg["slot_id"]; ok {
			result["slot_id"] = v
		}
		attachGatewayProximity(result, msg)
		attachV2EnvelopeMetadata(result, job.e2eeMeta)
		if job.groupIDForKeys != "" {
			c.logMessageDebug("decrypt-ok", "v2.decrypt", "group.message_created", result, nil)
		} else {
			c.logMessageDebug("decrypt-ok", "v2.decrypt", "message.received", result, nil)
		}
		decrypted = append(decrypted, result)
	}
	return decrypted
}

// decryptV2Message 解密单条 V2 P2P 消息（pull 内部使用）。
//
// 返回值：
//   - 解密成功 → 应用层消息 dict（包含 message_id / from / to / seq / payload / e2ee）
//   - 解密失败或无 envelope_json → nil（必要时发布 undecryptable 事件）
func (c *AUNClient) decryptV2Message(ctx context.Context, state *v2P2PState, msg map[string]any) map[string]any {
	return c.decryptV2MessageWithPending(ctx, state, msg, true)
}

func (c *AUNClient) decryptV2MessageWithPending(ctx context.Context, state *v2P2PState, msg map[string]any, allowPending bool) map[string]any {
	envJSON := v2AsString(msg["envelope_json"])
	if envJSON == "" {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(envJSON))
	dec.UseNumber()
	var envelope map[string]any
	if err := dec.Decode(&envelope); err != nil {
		c.logE2.Warn("V2 decrypt: invalid envelope_json for msg seq=%v: %v", msg["seq"], err)
		return nil
	}
	e2eeMeta := v2MessageE2EEMetadata(envelope)
	c.observeAgentMDFromEnvelope(envelope)

	// 确定 spk_id
	spkID := ""
	recipientKeySource := ""
	if r, ok := envelope["recipient"].(map[string]any); ok {
		spkID = v2AsString(r["spk_id"])
		recipientKeySource = v2AsString(r["key_source"])
	} else if rows, ok := envelope["recipients"]; ok {
		spkID = v2AsString(msg["spk_id"])
		if recipients, ok := rows.([]any); ok {
			for _, row := range recipients {
				cells, ok := row.([]any)
				if !ok || len(cells) < 6 {
					continue
				}
				if v2AsString(cells[0]) != c.aid || v2AsString(cells[1]) != c.deviceID {
					continue
				}
				if spkID == "" {
					spkID = v2AsString(cells[5])
				}
				if len(cells) > 3 {
					recipientKeySource = v2AsString(cells[3])
				}
				break
			}
		}
	}

	// group_id 只表示群上下文；GetGroupDecryptKeys 内部必须按 group SPK -> P2P device SPK -> IK fallback 查找。
	groupIDForKeys := ""
	if aad, ok := envelope["aad"].(map[string]any); ok {
		groupIDForKeys = strings.TrimSpace(v2AsString(aad["group_id"]))
	}
	if groupIDForKeys == "" {
		groupIDForKeys = strings.TrimSpace(v2AsString(msg["group_id"]))
	}
	undecryptableEvent := "message.undecryptable"
	if groupIDForKeys != "" {
		undecryptableEvent = "group.message_undecryptable"
	}
	c.logE2.Debug("V2 decrypt start: seq=%v message_id=%s group=%s from=%s spk_id=%s key_source=%s has_recipient=%v has_recipients=%v",
		msg["seq"], v2AsString(msg["message_id"]), valueOrDefault(groupIDForKeys, "<p2p>"), v2AsString(msg["from_aid"]), valueOrDefault(spkID, "<empty>"), valueOrDefault(recipientKeySource, "<empty>"),
		envelope["recipient"] != nil, envelope["recipients"] != nil)
	var ikPriv, spkPriv []byte
	var err error
	if groupIDForKeys != "" {
		ikPriv, spkPriv, err = state.session.GetGroupDecryptKeys(groupIDForKeys, spkID)
	} else {
		ikPriv, spkPriv, err = state.session.GetDecryptKeys(spkID)
	}
	if err != nil {
		c.logE2.Warn("V2 decrypt: GetDecryptKeys 失败 seq=%v group=%s: %v", msg["seq"], groupIDForKeys, err)
		event := map[string]any{
			"message_id":     v2AsString(msg["message_id"]),
			"from":           v2AsString(msg["from_aid"]),
			"to":             v2AsString(msg["to"]),
			"seq":            msg["seq"],
			"timestamp":      msg["t_server"],
			"device_id":      v2AsString(msg["device_id"]),
			"slot_id":        v2AsString(msg["slot_id"]),
			"_decrypt_error": err.Error(),
			"_decrypt_stage": "spk_lookup",
			"_envelope_type": v2AsString(envelope["type"]),
			"_suite":         v2AsString(envelope["suite"]),
			"_spk_id":        spkID,
		}
		attachV2EnvelopeMetadata(event, e2eeMeta)
		c.logMessageDebug("decrypt-fail", "v2.decrypt", undecryptableEvent, event, nil)
		c.publishAppEventSync(undecryptableEvent, event)
		return nil
	}
	c.logE2.Debug("V2 decrypt key lookup ok: seq=%v group=%s ik_len=%d spk_len=%d", msg["seq"], valueOrDefault(groupIDForKeys, "<p2p>"), len(ikPriv), len(spkPriv))

	// sender 公钥（按 sender device_id 精确匹配）
	fromAID := v2AsString(msg["from_aid"])
	senderDeviceID := ""
	if aad, ok := envelope["aad"].(map[string]any); ok {
		senderDeviceID = v2AsString(aad["from_device"])
	}
	senderCertFingerprint := strings.TrimSpace(stringFromAny(envelope["sender_cert_fingerprint"]))
	senderPubDER := c.getV2SenderPubDER(ctx, state, fromAID, senderDeviceID, senderCertFingerprint)
	if len(senderPubDER) == 0 {
		c.logE2.Warn("V2 decrypt: no sender IK for %s device=%s", fromAID, senderDeviceID)
		if allowPending {
			c.scheduleV2SenderIKPending(msg, fromAID, senderDeviceID, groupIDForKeys)
			return nil
		}
		event := map[string]any{
			"message_id":     v2AsString(msg["message_id"]),
			"from":           fromAID,
			"to":             v2AsString(msg["to"]),
			"seq":            msg["seq"],
			"timestamp":      msg["t_server"],
			"device_id":      v2AsString(msg["device_id"]),
			"slot_id":        v2AsString(msg["slot_id"]),
			"_decrypt_error": "sender_ik_not_found",
			"_decrypt_stage": "sender_ik",
			"_envelope_type": v2AsString(envelope["type"]),
			"_suite":         v2AsString(envelope["suite"]),
		}
		attachV2EnvelopeMetadata(event, e2eeMeta)
		c.logMessageDebug("decrypt-fail", "v2.decrypt", undecryptableEvent, event, nil)
		c.publishAppEventSync(undecryptableEvent, event)
		return nil
	}

	c.mu.RLock()
	selfAID := c.aid
	selfDeviceID := c.deviceID
	c.mu.RUnlock()

	plaintext, err := e2ee.DecryptMessage(envelope, selfAID, selfDeviceID, ikPriv, spkPriv, senderPubDER)
	if err != nil {
		c.logE2.Warn("V2 decrypt failed for msg seq=%v: %v", msg["seq"], err)
		event := map[string]any{
			"message_id":     v2AsString(msg["message_id"]),
			"from":           fromAID,
			"to":             v2AsString(msg["to"]),
			"seq":            msg["seq"],
			"timestamp":      msg["t_server"],
			"device_id":      v2AsString(msg["device_id"]),
			"slot_id":        v2AsString(msg["slot_id"]),
			"_decrypt_error": err.Error(),
			"_decrypt_stage": "decrypt",
			"_envelope_type": v2AsString(envelope["type"]),
			"_suite":         v2AsString(envelope["suite"]),
		}
		attachV2EnvelopeMetadata(event, e2eeMeta)
		c.logMessageDebug("decrypt-fail", "v2.decrypt", undecryptableEvent, event, nil)
		c.publishAppEventSync(undecryptableEvent, event)
		return nil
	}
	if plaintext == nil {
		c.logE2.Debug("V2 decrypt returned nil plaintext: seq=%v group=%s", msg["seq"], valueOrDefault(groupIDForKeys, "<p2p>"))
		return nil
	}

	// SPK 轮换：当前活跃 SPK 被消费后立即轮换（后台执行，不阻塞）
	if groupIDForKeys != "" && recipientKeySource == "group_device_prekey" && state.session.IsLastUploadedGroupSPK(groupIDForKeys, spkID) {
		c.getV2E2EECoordinator().scheduleGroupSpkRotation(groupIDForKeys, "group_spk_consumed")
	} else if groupIDForKeys != "" && recipientKeySource == "peer_device_prekey" {
		c.getV2E2EECoordinator().scheduleGroupSpkRegistrationAfterPeerFallback(groupIDForKeys)
	} else if groupIDForKeys == "" && state.session.IsLastUploadedSPK(spkID) {
		// P2P SPK 消费触发轮换
		go func() {
			defer func() {
				if r := recover(); r != nil {
					c.logE2.Warn("V2 SPK rotation panic: %v", r)
				}
			}()
			rotateCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := state.session.RotateSPK(rotateCtx, c.v2CallFn()); err != nil {
				c.logE2.Warn("V2 SPK rotation failed (non-fatal): %v", err)
			} else {
				c.logE2.Debug("V2 SPK rotated after consumption: aid=%s", selfAID)
			}
		}()
	}

	e2ee := v2MessageE2EEMetadata(envelope)
	result := map[string]any{
		"message_id": v2AsString(msg["message_id"]),
		"from":       fromAID,
		"to":         selfAID,
		"seq":        msg["seq"],
		"t_server":   msg["t_server"],
		"payload":    plaintext,
		"encrypted":  true,
		"e2ee":       e2ee,
	}
	direction := strings.TrimSpace(v2AsString(msg["direction"]))
	if direction == "" {
		if fromAID != "" && fromAID == selfAID {
			direction = "outbound_sync"
		} else {
			direction = "inbound"
		}
	}
	result["direction"] = direction
	if v, ok := msg["device_id"]; ok {
		result["device_id"] = v
	}
	if v, ok := msg["slot_id"]; ok {
		result["slot_id"] = v
	}
	attachGatewayProximity(result, msg)
	attachV2EnvelopeMetadata(result, e2ee)
	if groupIDForKeys != "" {
		c.logMessageDebug("decrypt-ok", "v2.decrypt", "group.message_created", result, nil)
	} else {
		c.logMessageDebug("decrypt-ok", "v2.decrypt", "message.received", result, nil)
	}
	return result
}

// v2RetryableCodes 是推测性发送可重试的服务端错误码集合。
var v2RetryableCodes = map[int]bool{
	-33011: true, // device_not_found
	-33012: true, // prekey_stale
	-33050: true, // recipient_mismatch
	-33052: true, // epoch_mismatch
	-33054: true, // member_list_changed
}

func isV2RetryableError(err error) bool {
	var ae *AUNError
	if errors.As(err, &ae) {
		return v2RetryableCodes[ae.Code]
	}
	return false
}

func v2ErrorCode(err error) int {
	var ae *AUNError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return 0
}
