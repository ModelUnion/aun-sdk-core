// v2_thought.go — V2 thought.put / thought.get 支持。
//
// 与 Python aun_core.client 的对应方法对齐：
//   - _build_v2_p2p_envelope            → buildV2P2PEnvelope
//   - _build_v2_group_envelope          → buildV2GroupEnvelope
//   - _put_message_thought_encrypted_v2 → putMessageThoughtEncryptedV2
//   - _put_group_thought_encrypted_v2   → putGroupThoughtEncryptedV2
//   - _decrypt_v2_envelope_for_thought  → decryptV2EnvelopeForThought
//
// V2 thought 协议约定：
//   - 服务端依旧仅做内存级 KV，不持久化、不分配 seq、不 ack
//   - SDK 在 V2 ready 时多设备 wrap 出 e2ee.p2p_encrypted / e2ee.group_encrypted envelope
//     作为 payload 上传；客户端读取后再单设备解密
//   - 单条 thought 服务端只存一份 envelope，envelope 内含多个 device wrap

package aun

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelunion/aun-sdk-core/go/v2/e2ee"
)

// buildV2P2PEnvelope 构造 V2 P2P 多设备 wrap envelope（不发送）。
//
// thought.put 复用此函数构造与 message.send 相同的 V2 envelope。
func (c *AUNClient) buildV2P2PEnvelope(
	ctx context.Context,
	state *v2P2PState,
	to string,
	payload map[string]any,
	opts e2ee.EncryptOptions,
	useCache bool,
) (map[string]any, error) {
	peerDevices, auditRaw, err := c.v2ResolveBootstrap(ctx, state, to, useCache)
	if err != nil {
		return nil, err
	}
	if len(peerDevices) == 0 {
		return nil, fmt.Errorf("V2 bootstrap: no devices found for %s", to)
	}

	targets := make([]e2ee.Target, 0, len(peerDevices))
	for _, dev := range peerDevices {
		ikDER := v2DecodeBase64Field(dev, "ik_pk")
		if len(ikDER) == 0 {
			continue
		}
		spkDER := v2DecodeBase64Field(dev, "spk_pk")
		devID := v2AsString(dev["device_id"])
		state.session.CachePeerIK(to, devID, ikDER)
		targets = append(targets, e2ee.Target{
			AID:       to,
			DeviceID:  devID,
			Role:      "peer",
			KeySource: v2DefaultStr(v2AsString(dev["key_source"]), "peer_device_prekey"),
			IKPkDER:   ikDER,
			SPKPkDER:  spkDER,
			SPKID:     v2AsString(dev["spk_id"]),
		})
	}

	// audit recipients 也按 target 处理（与 Python _build_v2_p2p_envelope 对齐：
	// audit 直接进入 targets 列表，target_set.audit_recipients 留空）
	for _, dev := range auditRaw {
		ikDER := v2DecodeBase64Field(dev, "ik_pk")
		if len(ikDER) == 0 {
			continue
		}
		spkDER := v2DecodeBase64Field(dev, "spk_pk")
		targets = append(targets, e2ee.Target{
			AID:       v2AsString(dev["aid"]),
			DeviceID:  v2AsString(dev["device_id"]),
			Role:      "audit",
			KeySource: v2DefaultStr(v2AsString(dev["key_source"]), "peer_device_prekey"),
			IKPkDER:   ikDER,
			SPKPkDER:  spkDER,
			SPKID:     v2AsString(dev["spk_id"]),
		})
	}

	// self-sync：自己其它设备
	c.mu.RLock()
	myAID := c.aid
	myDeviceID := c.deviceID
	c.mu.RUnlock()
	if myAID != "" && myAID != to {
		selfDevices := c.v2FetchSelfDevices(ctx, state, myAID)
		for _, dev := range selfDevices {
			devID := v2AsString(dev["owner_device_id"])
			if devID == "" {
				devID = v2AsString(dev["device_id"])
			}
			if devID == "" || devID == myDeviceID {
				continue
			}
			ikDER := v2DecodeBase64Field(dev, "ik_pk")
			if len(ikDER) == 0 {
				continue
			}
			spkDER := v2DecodeBase64Field(dev, "spk_pk")
			targets = append(targets, e2ee.Target{
				AID:       myAID,
				DeviceID:  devID,
				Role:      "self_sync",
				KeySource: v2DefaultStr(v2AsString(dev["key_source"]), "peer_device_prekey"),
				IKPkDER:   ikDER,
				SPKPkDER:  spkDER,
				SPKID:     v2AsString(dev["spk_id"]),
			})
		}
	}

	sender, err := state.session.GetSenderIdentity()
	if err != nil {
		return nil, fmt.Errorf("buildV2P2PEnvelope: sender identity 失败: %w", err)
	}

	envelope, err := e2ee.EncryptP2PMessage(
		e2ee.Sender{
			AID:      sender.AID,
			DeviceID: sender.DeviceID,
			IKPriv:   sender.IKPriv,
			IKPubDER: sender.IKPubDER,
		},
		e2ee.TargetSet{Targets: targets},
		payload,
		opts,
	)
	if err != nil {
		return nil, fmt.Errorf("buildV2P2PEnvelope: 加密失败: %w", err)
	}
	return envelope, nil
}

// buildV2GroupEnvelope 构造 V2 Group 多设备 wrap envelope（不发送）。
func (c *AUNClient) buildV2GroupEnvelope(
	ctx context.Context,
	state *v2P2PState,
	groupID string,
	payload map[string]any,
	opts e2ee.EncryptOptions,
	useCache bool,
) (map[string]any, error) {
	allDevices, epoch, sc, auditRaw, err := c.v2ResolveGroupBootstrap(ctx, state, groupID, useCache)
	if err != nil {
		return nil, err
	}
	if len(allDevices) == 0 {
		return nil, fmt.Errorf("V2 group bootstrap: no devices for %s", groupID)
	}

	c.mu.RLock()
	myAID := c.aid
	myDeviceID := c.deviceID
	c.mu.RUnlock()

	targets := make([]e2ee.Target, 0, len(allDevices))
	for _, dev := range allDevices {
		devAID := v2AsString(dev["aid"])
		devID := v2AsString(dev["device_id"])
		if devAID == myAID && devID == myDeviceID {
			continue
		}
		ikDER := v2DecodeBase64Field(dev, "ik_pk")
		if len(ikDER) == 0 {
			continue
		}
		spkDER := v2DecodeBase64Field(dev, "spk_pk")
		role := "member"
		if devAID == myAID {
			role = "self_sync"
		}
		targets = append(targets, e2ee.Target{
			AID:       devAID,
			DeviceID:  devID,
			Role:      role,
			KeySource: v2DefaultStr(v2AsString(dev["key_source"]), "peer_device_prekey"),
			IKPkDER:   ikDER,
			SPKPkDER:  spkDER,
			SPKID:     v2AsString(dev["spk_id"]),
		})
	}

	// audit recipients
	for _, dev := range auditRaw {
		ikDER := v2DecodeBase64Field(dev, "ik_pk")
		if len(ikDER) == 0 {
			continue
		}
		spkDER := v2DecodeBase64Field(dev, "spk_pk")
		targets = append(targets, e2ee.Target{
			AID:       v2AsString(dev["aid"]),
			DeviceID:  v2AsString(dev["device_id"]),
			Role:      "audit",
			KeySource: v2DefaultStr(v2AsString(dev["key_source"]), "peer_device_prekey"),
			IKPkDER:   ikDER,
			SPKPkDER:  spkDER,
			SPKID:     v2AsString(dev["spk_id"]),
		})
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("V2 group: no target devices for %s", groupID)
	}

	sender, err := state.session.GetSenderIdentity()
	if err != nil {
		return nil, fmt.Errorf("buildV2GroupEnvelope: sender identity 失败: %w", err)
	}

	envelope, err := e2ee.EncryptGroupMessage(
		e2ee.Sender{
			AID:      sender.AID,
			DeviceID: sender.DeviceID,
			IKPriv:   sender.IKPriv,
			IKPubDER: sender.IKPubDER,
		},
		groupID,
		epoch,
		targets,
		payload,
		opts,
		sc,
	)
	if err != nil {
		return nil, fmt.Errorf("buildV2GroupEnvelope: 加密失败: %w", err)
	}
	return envelope, nil
}

// putMessageThoughtEncryptedV2 V2 P2P thought.put：使用 V2 多设备 wrap envelope。
//
// 服务端仍走 message.thought.put（内存 KV），envelope 透传，由接收端单设备解密。
func (c *AUNClient) putMessageThoughtEncryptedV2(ctx context.Context, params map[string]any) (any, error) {
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return nil, errors.New("V2 session not initialized (not connected?)")
	}

	toAID := strings.TrimSpace(getStr(params, "to", ""))
	if err := validateMessageRecipient(toAID); err != nil {
		return nil, err
	}
	if toAID == "" {
		return nil, NewValidationError("message.thought.put requires to")
	}
	payload, _ := params["payload"].(map[string]any)
	if payload == nil {
		return nil, NewValidationError("message.thought.put payload must be an object when encrypt=true")
	}

	thoughtID := strings.TrimSpace(getStr(params, "thought_id", ""))
	if thoughtID == "" {
		thoughtID = "mt-" + generateUUID4()
	}
	timestamp := toInt64(params["timestamp"])
	if timestamp == 0 {
		timestamp = time.Now().UnixMilli()
	}

	attempt := func(useCache bool) (any, error) {
		// context 传入 envelope HMAC（与 Python _put_message_thought_encrypted_v2 对齐）
		var ctxMeta map[string]any
		if cm, ok := params["context"].(map[string]any); ok && len(cm) > 0 {
			ctxMeta = cm
		}
		envelope, err := c.buildV2P2PEnvelope(ctx, state, toAID, payload, e2ee.EncryptOptions{
			MessageID: thoughtID,
			Timestamp: timestamp,
			Context:   ctxMeta,
		}, useCache)
		if err != nil {
			return nil, err
		}
		sendParams := map[string]any{
			"to":         toAID,
			"payload":    envelope,
			"encrypted":  true,
			"thought_id": thoughtID,
			"timestamp":  timestamp,
		}
		if value, ok := params["context"]; ok {
			sendParams["context"] = value
		}
		c.signClientOperation("message.thought.put", sendParams)
		return c.transport.Call(ctx, "message.thought.put", sendParams)
	}

	resp, err := attempt(true)
	if err == nil {
		return resp, nil
	}
	if isV2RetryableError(err) {
		c.logE2.Debug("V2 P2P thought put speculative rejected (code=%d), refreshing bootstrap", v2ErrorCode(err))
		state.bootstrapCacheM.Lock()
		delete(state.bootstrapCache, toAID)
		state.bootstrapCacheM.Unlock()
		return attempt(false)
	}
	return nil, err
}

// putGroupThoughtEncryptedV2 V2 Group thought.put：多设备 wrap envelope。
func (c *AUNClient) putGroupThoughtEncryptedV2(ctx context.Context, params map[string]any) (any, error) {
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return nil, errors.New("V2 session not initialized (not connected?)")
	}

	groupID := strings.TrimSpace(getStr(params, "group_id", ""))
	if groupID == "" {
		return nil, NewValidationError("group.thought.put requires 'group_id'")
	}
	payload, _ := params["payload"].(map[string]any)
	if payload == nil {
		return nil, NewValidationError("group.thought.put payload must be an object when encrypt=true")
	}

	thoughtID := strings.TrimSpace(getStr(params, "thought_id", ""))
	if thoughtID == "" {
		thoughtID = "gt-" + generateUUID4()
	}
	timestamp := toInt64(params["timestamp"])
	if timestamp == 0 {
		timestamp = time.Now().UnixMilli()
	}

	attempt := func(useCache bool) (any, error) {
		// context 传入 envelope HMAC（与 Python _put_group_thought_encrypted_v2 对齐）
		var ctxMeta map[string]any
		if cm, ok := params["context"].(map[string]any); ok && len(cm) > 0 {
			ctxMeta = cm
		}
		envelope, err := c.buildV2GroupEnvelope(ctx, state, groupID, payload, e2ee.EncryptOptions{
			MessageID: thoughtID,
			Timestamp: timestamp,
			Context:   ctxMeta,
		}, useCache)
		if err != nil {
			return nil, err
		}
		sendParams := map[string]any{
			"group_id":   groupID,
			"payload":    envelope,
			"encrypted":  true,
			"thought_id": thoughtID,
			"timestamp":  timestamp,
		}
		if value, ok := params["context"]; ok {
			sendParams["context"] = value
		}
		if c.deviceID != "" {
			sendParams["device_id"] = c.deviceID
		}
		if c.slotID != "" {
			sendParams["slot_id"] = c.slotID
		}
		c.signClientOperation("group.thought.put", sendParams)
		return c.transport.Call(ctx, "group.thought.put", sendParams)
	}

	resp, err := attempt(true)
	if err == nil {
		return resp, nil
	}
	if isV2RetryableError(err) {
		c.logE2.Debug("V2 group thought put speculative rejected (code=%d), refreshing bootstrap", v2ErrorCode(err))
		state.bootstrapCacheM.Lock()
		delete(state.groupBootstrapCache, groupID)
		state.bootstrapCacheM.Unlock()
		return attempt(false)
	}
	return nil, err
}

// decryptV2EnvelopeForThought 解密一个 V2 thought envelope（P2P 或 Group），返回 payload dict。
//
// 与 decryptV2Message 不同：
//   - 不依赖 msg.envelope_json 包装
//   - 失败返回 nil，不发布 message.undecryptable 事件
func (c *AUNClient) decryptV2EnvelopeForThought(ctx context.Context, envelope map[string]any, fromAID string) map[string]any {
	state := c.v2GetState()
	if state == nil || state.session == nil || envelope == nil {
		return nil
	}

	c.mu.RLock()
	selfAID := c.aid
	selfDeviceID := c.deviceID
	c.mu.RUnlock()

	// 在 envelope.recipients 中找到本设备 row，提取 spk_id
	spkID := ""
	if recipients, ok := envelope["recipients"].([]any); ok {
		for _, raw := range recipients {
			row, _ := raw.([]any)
			if len(row) < 6 {
				continue
			}
			rowAID, _ := row[0].(string)
			rowDevID, _ := row[1].(string)
			if rowAID == selfAID && rowDevID == selfDeviceID {
				if s, ok := row[5].(string); ok {
					spkID = s
				}
				break
			}
		}
	}

	ikPriv, spkPriv, err := state.session.GetDecryptKeys(spkID)
	if err != nil {
		c.logE2.Warn("V2 thought decrypt: GetDecryptKeys 失败 from=%s err=%v", fromAID, err)
		return nil
	}

	// sender 公钥（按 sender device_id 精确匹配）
	senderDeviceID := ""
	if aad, ok := envelope["aad"].(map[string]any); ok {
		senderDeviceID = v2AsString(aad["from_device"])
	}
	senderPubDER := state.session.GetPeerIK(fromAID, senderDeviceID)
	if len(senderPubDER) == 0 && fromAID != "" {
		raw, bsErr := c.Call(ctx, "message.v2.bootstrap", map[string]any{"peer_aid": fromAID})
		if bsErr == nil {
			bs, _ := raw.(map[string]any)
			for _, dev := range v2ToMapList(bs["peer_devices"]) {
				devID := v2AsString(dev["device_id"])
				if devID == "" {
					devID = v2AsString(dev["owner_device_id"])
				}
				ikDER := v2DecodeBase64Field(dev, "ik_pk")
				if len(ikDER) > 0 && devID != "" {
					state.session.CachePeerIK(fromAID, devID, ikDER)
				}
			}
			senderPubDER = state.session.GetPeerIK(fromAID, senderDeviceID)
		} else {
			c.logE2.Warn("V2 thought decrypt: bootstrap sender %s failed: %v", fromAID, bsErr)
		}
	}
	if len(senderPubDER) == 0 && fromAID != "" {
		certBytes, certErr := c.fetchPeerCert(ctx, fromAID, "")
		if certErr == nil && len(certBytes) > 0 {
			if block, _ := pem.Decode(certBytes); block != nil {
				if cert, parseErr := x509.ParseCertificate(block.Bytes); parseErr == nil {
					if der, marshalErr := x509.MarshalPKIXPublicKey(cert.PublicKey); marshalErr == nil {
						senderPubDER = der
						state.session.CachePeerIK(fromAID, senderDeviceID, der)
						c.logE2.Debug("V2 thought decrypt: sender IK fallback from CA cert for %s", fromAID)
					}
				}
			}
		} else if certErr != nil {
			c.logE2.Warn("V2 thought decrypt: CA fallback for %s failed: %v", fromAID, certErr)
		}
	}
	if len(senderPubDER) == 0 {
		c.logE2.Warn("V2 thought decrypt: no sender IK for %s device=%s", fromAID, senderDeviceID)
		return nil
	}

	plaintext, err := e2ee.DecryptMessage(envelope, selfAID, selfDeviceID, ikPriv, spkPriv, senderPubDER)
	if err != nil {
		c.logE2.Warn("V2 thought decrypt failed from=%s: %v", fromAID, err)
		return nil
	}
	return plaintext
}

func (c *AUNClient) decryptV2ThoughtGetResult(ctx context.Context, result any, fromAID string, group bool) {
	resultMap, ok := result.(map[string]any)
	if !ok || fromAID == "" {
		return
	}
	rawThoughts, ok := resultMap["thoughts"].([]any)
	if !ok || len(rawThoughts) == 0 {
		return
	}
	for _, raw := range rawThoughts {
		thought, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		payload, _ := thought["payload"].(map[string]any)
		if payload == nil {
			continue
		}
		if group {
			if !isV2GroupThoughtEnvelope(payload) {
				continue
			}
		} else if !isV2P2PThoughtEnvelope(payload) {
			continue
		}

		plaintext := c.decryptV2EnvelopeForThought(ctx, payload, fromAID)
		if plaintext == nil {
			thought["decrypt_failed"] = true
			thought["e2ee"] = v2ThoughtE2EEMetadata(payload)
			continue
		}
		thought["payload"] = plaintext
		thought["encrypted"] = true
		thought["e2ee"] = v2ThoughtE2EEMetadata(payload)
		delete(thought, "decrypt_failed")
	}
}

func v2ThoughtE2EEMetadata(envelope map[string]any) map[string]any {
	suite := v2AsString(envelope["suite"])
	encryptionMode := "v2_unknown"
	if suite != "" {
		encryptionMode = "v2_" + suite
	}
	meta := map[string]any{
		"version":         "v2",
		"suite":           suite,
		"encryption_mode": encryptionMode,
		"forward_secrecy": true,
	}
	if ph := v2MetadataWithoutAuth(envelope["protected_headers"]); len(ph) > 0 {
		meta["protected_headers"] = ph
	}
	if ctx := v2MetadataWithoutAuth(envelope["context"]); len(ctx) > 0 {
		meta["context"] = ctx
	}
	return meta
}

func v2MetadataWithoutAuth(value any) map[string]any {
	src, ok := value.(map[string]any)
	if !ok || len(src) == 0 {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		if k == "_auth" {
			continue
		}
		out[k] = v
	}
	return out
}

// isV2P2PThoughtEnvelope 识别 V2 P2P thought envelope。
func isV2P2PThoughtEnvelope(payload map[string]any) bool {
	if payload == nil {
		return false
	}
	t, _ := payload["type"].(string)
	return t == "e2ee.p2p_encrypted"
}

// isV2GroupThoughtEnvelope 识别 V2 Group thought envelope（version=v2 或含 recipients[]）。
func isV2GroupThoughtEnvelope(payload map[string]any) bool {
	if payload == nil {
		return false
	}
	t, _ := payload["type"].(string)
	if t != "e2ee.group_encrypted" {
		return false
	}
	if v, _ := payload["version"].(string); v == "v2" {
		return true
	}
	if _, ok := payload["recipients"]; ok {
		return true
	}
	return false
}

// envelopeJSONString 将 envelope 序列化为 JSON 字符串（仅用于 debug 日志，不参与 wire）
func envelopeJSONString(envelope map[string]any) string {
	b, err := json.Marshal(envelope)
	if err != nil {
		return ""
	}
	return string(b)
}
