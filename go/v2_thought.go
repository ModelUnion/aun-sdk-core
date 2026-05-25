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
	"encoding/json"
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
		devID := v2AsString(dev["device_id"])
		target, ok, err := c.v2BuildTargetFromDevice(ctx, state, dev, to, devID, "peer", "peer_device_prekey")
		if err != nil {
			return nil, err
		}
		if ok {
			targets = append(targets, target)
		}
	}

	// audit recipients 也按 target 处理（与 Python _build_v2_p2p_envelope 对齐：
	// audit 直接进入 targets 列表，target_set.audit_recipients 留空）
	for _, dev := range auditRaw {
		target, ok, err := c.v2BuildTargetFromDevice(ctx, state, dev, v2AsString(dev["aid"]), v2AsString(dev["device_id"]), "audit", "peer_device_prekey")
		if err != nil {
			return nil, err
		}
		if ok {
			targets = append(targets, target)
		}
	}

	// self-sync：自己其它设备
	c.mu.RLock()
	myAID := c.aid
	myDeviceID := c.deviceID
	c.mu.RUnlock()
	if myAID != "" && myAID != to {
		selfDevices := c.v2FetchSelfDevices(ctx, state, myAID)
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
	c.logMessageDebugWithPayload("thought-send-envelope", "message.thought.put.v2", "message.thought.put", map[string]any{
		"to":         to,
		"thought_id": opts.MessageID,
		"message_id": envelope["message_id"],
		"type":       envelope["type"],
		"version":    envelope["version"],
		"timestamp":  opts.Timestamp,
	}, envelope, map[string]any{
		"plaintext_payload": payload,
		"target_count":      len(targets),
		"audit_count":       len(auditRaw),
		"use_cache":         useCache,
	})
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
		devID, hasDeviceID := v2DeviceIDFromDevice(dev)
		if devAID == myAID && hasDeviceID && devID == myDeviceID {
			continue
		}
		role := "member"
		if devAID == myAID {
			role = "self_sync"
		}
		target, ok, err := c.v2BuildTargetFromDevice(ctx, state, dev, devAID, devID, role, "peer_device_prekey")
		if err != nil {
			return nil, err
		}
		if ok {
			targets = append(targets, target)
		}
	}

	// audit recipients
	for _, dev := range auditRaw {
		target, ok, err := c.v2BuildTargetFromDevice(ctx, state, dev, v2AsString(dev["aid"]), v2AsString(dev["device_id"]), "audit", "peer_device_prekey")
		if err != nil {
			return nil, err
		}
		if ok {
			targets = append(targets, target)
		}
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
	c.logMessageDebugWithPayload("thought-send-envelope", "group.thought.put.v2", "group.thought.put", map[string]any{
		"group_id":   groupID,
		"thought_id": opts.MessageID,
		"message_id": envelope["message_id"],
		"type":       envelope["type"],
		"version":    envelope["version"],
		"timestamp":  opts.Timestamp,
	}, envelope, map[string]any{
		"plaintext_payload": payload,
		"epoch":             epoch,
		"target_count":      len(targets),
		"audit_count":       len(auditRaw),
		"use_cache":         useCache,
	})
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
	c.logMessageDebugWithPayload("thought-send-plaintext", "message.thought.put.v2", "message.thought.put", map[string]any{
		"to":         toAID,
		"thought_id": thoughtID,
		"timestamp":  timestamp,
		"encrypted":  true,
		"context":    params["context"],
	}, payload, nil)

	attempt := func(useCache bool) (any, error) {
		c.log.Debug("message.thought.put v2 attempt: to=%s thought_id=%s use_cache=%v", toAID, thoughtID, useCache)
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
		c.logMessageDebugWithPayload("thought-send-call", "message.thought.put.v2", "message.thought.put", sendParams, envelope, map[string]any{
			"use_cache": useCache,
		})
		resp, err := c.transport.Call(ctx, "message.thought.put", sendParams)
		if err != nil {
			c.log.Debug("message.thought.put v2 failed: to=%s thought_id=%s use_cache=%v err=%v", toAID, thoughtID, useCache, err)
			return nil, err
		}
		c.log.Debug("message.thought.put v2 ok: to=%s thought_id=%s use_cache=%v result=%v", toAID, thoughtID, useCache, resp)
		c.logMessageDebugWithPayload("thought-send-ok", "message.thought.put.v2", "message.thought.put", sendParams, resp, map[string]any{
			"use_cache": useCache,
		})
		return resp, nil
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
	c.logMessageDebugWithPayload("thought-send-plaintext", "group.thought.put.v2", "group.thought.put", map[string]any{
		"group_id":   groupID,
		"thought_id": thoughtID,
		"timestamp":  timestamp,
		"encrypted":  true,
		"context":    params["context"],
	}, payload, nil)

	attempt := func(useCache bool) (any, error) {
		c.logEG.Debug("group.thought.put v2 attempt: group=%s thought_id=%s use_cache=%v", groupID, thoughtID, useCache)
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
		sendParams["device_id"] = c.deviceID
		if c.slotID != "" {
			sendParams["slot_id"] = c.slotID
		}
		c.signClientOperation("group.thought.put", sendParams)
		c.logMessageDebugWithPayload("thought-send-call", "group.thought.put.v2", "group.thought.put", sendParams, envelope, map[string]any{
			"use_cache": useCache,
		})
		resp, err := c.transport.Call(ctx, "group.thought.put", sendParams)
		if err != nil {
			c.logEG.Debug("group.thought.put v2 failed: group=%s thought_id=%s use_cache=%v err=%v", groupID, thoughtID, useCache, err)
			return nil, err
		}
		c.logEG.Debug("group.thought.put v2 ok: group=%s thought_id=%s use_cache=%v result=%v", groupID, thoughtID, useCache, resp)
		c.logMessageDebugWithPayload("thought-send-ok", "group.thought.put.v2", "group.thought.put", sendParams, resp, map[string]any{
			"use_cache": useCache,
		})
		return resp, nil
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
		c.log.Debug("V2 thought decrypt skipped: state_ready=%v envelope_nil=%v from=%s", state != nil && state.session != nil, envelope == nil, fromAID)
		return nil
	}

	c.mu.RLock()
	selfAID := c.aid
	selfDeviceID := c.deviceID
	c.mu.RUnlock()
	eventName := "message.thought.get"
	if isV2GroupThoughtEnvelope(envelope) {
		eventName = "group.thought.get"
	}
	c.observeAgentMDFromEnvelope(envelope)

	// 在 envelope.recipients 中找到本设备 row，提取 spk_id
	spkID := ""
	recipientKeySource := ""
	if recipients, ok := envelope["recipients"].([]any); ok {
		for _, raw := range recipients {
			row, _ := raw.([]any)
			if len(row) < 6 {
				continue
			}
			rowAID, _ := row[0].(string)
			rowDevID, _ := row[1].(string)
			if rowAID == selfAID && rowDevID == selfDeviceID {
				if s, ok := row[3].(string); ok {
					recipientKeySource = s
				}
				if s, ok := row[5].(string); ok {
					spkID = s
				}
				break
			}
		}
	}
	senderDeviceID := ""
	groupIDForKeys := ""
	if aad, ok := envelope["aad"].(map[string]any); ok {
		senderDeviceID = v2AsString(aad["from_device"])
		groupIDForKeys = strings.TrimSpace(v2AsString(aad["group_id"]))
	}
	c.logE2.Debug("V2 thought decrypt start: type=%s group=%s from=%s sender_device=%s self=%s device=%s spk_id=%s",
		v2AsString(envelope["type"]), valueOrDefault(groupIDForKeys, "<p2p>"), fromAID, valueOrDefault(senderDeviceID, "<empty>"), selfAID, selfDeviceID, valueOrDefault(spkID, "<empty>"))
	c.logMessageDebug("thought-decrypt-start", "v2.thought.decrypt", eventName, envelope, map[string]any{
		"from_aid":         fromAID,
		"self_aid":         selfAID,
		"self_device_id":   selfDeviceID,
		"sender_device_id": senderDeviceID,
		"group_id":         groupIDForKeys,
		"spk_id":           spkID,
		"key_source":       recipientKeySource,
	})

	var ikPriv, spkPriv []byte
	var err error
	if groupIDForKeys != "" {
		ikPriv, spkPriv, err = state.session.GetGroupDecryptKeys(groupIDForKeys, spkID)
	} else {
		ikPriv, spkPriv, err = state.session.GetDecryptKeys(spkID)
	}
	if err != nil {
		c.logE2.Warn("V2 thought decrypt: GetDecryptKeys 失败 from=%s err=%v", fromAID, err)
		c.logMessageDebugWithPayload("thought-decrypt-fail", "v2.thought.decrypt", eventName, map[string]any{
			"from":           fromAID,
			"_decrypt_error": err.Error(),
			"_decrypt_stage": "spk_lookup",
			"_envelope_type": v2AsString(envelope["type"]),
			"_suite":         v2AsString(envelope["suite"]),
			"_spk_id":        spkID,
			"_key_source":    recipientKeySource,
		}, envelope, nil)
		return nil
	}
	c.logE2.Debug("V2 thought decrypt key lookup ok: from=%s group=%s ik_len=%d spk_len=%d", fromAID, valueOrDefault(groupIDForKeys, "<p2p>"), len(ikPriv), len(spkPriv))

	// sender 公钥（按 sender device_id 精确匹配）；当前解密栈不走 bootstrap RPC，避免阻塞 RPC 回调线。
	senderPubDER := c.getV2SenderPubDER(ctx, state, fromAID, senderDeviceID)
	if len(senderPubDER) == 0 {
		c.logE2.Warn("V2 thought decrypt: no sender IK for %s device=%s", fromAID, senderDeviceID)
		c.scheduleV2SenderIKFetch(fromAID, senderDeviceID, groupIDForKeys)
		c.logMessageDebugWithPayload("thought-decrypt-fail", "v2.thought.decrypt", eventName, map[string]any{
			"from":              fromAID,
			"_decrypt_error":    "sender_ik_not_found",
			"_decrypt_stage":    "sender_ik",
			"_envelope_type":    v2AsString(envelope["type"]),
			"_suite":            v2AsString(envelope["suite"]),
			"_sender_device_id": senderDeviceID,
		}, envelope, nil)
		return nil
	}

	plaintext, err := e2ee.DecryptMessage(envelope, selfAID, selfDeviceID, ikPriv, spkPriv, senderPubDER)
	if err != nil {
		c.logE2.Warn("V2 thought decrypt failed from=%s: %v", fromAID, err)
		c.logMessageDebugWithPayload("thought-decrypt-fail", "v2.thought.decrypt", eventName, map[string]any{
			"from":              fromAID,
			"_decrypt_error":    err.Error(),
			"_decrypt_stage":    "decrypt",
			"_envelope_type":    v2AsString(envelope["type"]),
			"_suite":            v2AsString(envelope["suite"]),
			"_sender_device_id": senderDeviceID,
		}, envelope, nil)
		return nil
	}
	if plaintext == nil {
		c.logE2.Debug("V2 thought decrypt returned nil plaintext: from=%s group=%s", fromAID, valueOrDefault(groupIDForKeys, "<p2p>"))
		c.logMessageDebugWithPayload("thought-decrypt-null", "v2.thought.decrypt", eventName, map[string]any{
			"from":              fromAID,
			"_decrypt_stage":    "decrypt",
			"_envelope_type":    v2AsString(envelope["type"]),
			"_suite":            v2AsString(envelope["suite"]),
			"_sender_device_id": senderDeviceID,
		}, envelope, nil)
		return nil
	}
	c.logMessageDebugWithPayload("thought-decrypt-ok", "v2.thought.decrypt", eventName, map[string]any{
		"from":      fromAID,
		"to":        selfAID,
		"group_id":  groupIDForKeys,
		"encrypted": true,
		"payload":   plaintext,
	}, plaintext, map[string]any{
		"sender_device_id": senderDeviceID,
		"spk_id":           spkID,
	})
	return plaintext
}

func (c *AUNClient) decryptV2ThoughtGetResult(ctx context.Context, result any, fromAID string, group bool) {
	method := "message.thought.get"
	if group {
		method = "group.thought.get"
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		c.log.Debug("%s decrypt skipped: invalid result type=%T from=%s", method, result, fromAID)
		return
	}
	if fromAID == "" {
		c.log.Debug("%s decrypt skipped: empty sender_aid", method)
		return
	}
	rawThoughts, ok := resultMap["thoughts"].([]any)
	if !ok {
		c.log.Debug("%s decrypt skipped: thoughts field type=%T found=%v", method, resultMap["thoughts"], resultMap["found"])
		return
	}
	decryptedCount := 0
	failedCount := 0
	skippedCount := 0
	c.log.Debug("%s decrypt enter: from=%s raw_count=%d group=%v found=%v", method, fromAID, len(rawThoughts), group, resultMap["found"])
	defer func() {
		c.log.Debug("%s decrypt exit: from=%s raw_count=%d decrypted=%d failed=%d skipped=%d", method, fromAID, len(rawThoughts), decryptedCount, failedCount, skippedCount)
	}()
	if len(rawThoughts) == 0 {
		return
	}
	for index, raw := range rawThoughts {
		thought, ok := raw.(map[string]any)
		if !ok {
			skippedCount++
			c.log.Debug("%s thought[%d] skipped: invalid item type=%T", method, index, raw)
			continue
		}
		payload, _ := thought["payload"].(map[string]any)
		c.logMessageDebugWithPayload("thought-get-raw", "thought.get", method, thought, payload, map[string]any{
			"index":    index,
			"from_aid": fromAID,
			"group":    group,
		})
		if payload == nil {
			skippedCount++
			c.log.Debug("%s thought[%d] skipped: payload type=%T", method, index, thought["payload"])
			continue
		}
		if group {
			if !isV2GroupThoughtEnvelope(payload) {
				skippedCount++
				c.logMessageDebugWithPayload("thought-get-unsupported", "thought.get", method, thought, payload, map[string]any{
					"index":         index,
					"expected_type": "e2ee.group_encrypted",
					"actual_type":   v2AsString(payload["type"]),
				})
				continue
			}
		} else if !isV2P2PThoughtEnvelope(payload) {
			skippedCount++
			c.logMessageDebugWithPayload("thought-get-unsupported", "thought.get", method, thought, payload, map[string]any{
				"index":         index,
				"expected_type": "e2ee.p2p_encrypted",
				"actual_type":   v2AsString(payload["type"]),
			})
			continue
		}

		meta := v2ThoughtE2EEMetadata(payload)
		plaintext := c.decryptV2EnvelopeForThought(ctx, payload, fromAID)
		if plaintext == nil {
			failedCount++
			thought["decrypt_failed"] = true
			thought["e2ee"] = meta
			attachV2EnvelopeMetadata(thought, meta)
			c.logMessageDebugWithPayload("thought-decrypt-null", "thought.get", method, thought, payload, map[string]any{
				"index":    index,
				"from_aid": fromAID,
				"group":    group,
			})
			continue
		}
		thought["payload"] = plaintext
		thought["encrypted"] = true
		thought["e2ee"] = meta
		attachV2EnvelopeMetadata(thought, meta)
		delete(thought, "decrypt_failed")
		decryptedCount++
		c.logMessageDebug("thought-result", "thought.get", method, thought, map[string]any{
			"index":    index,
			"from_aid": fromAID,
			"group":    group,
		})
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
	ph := v2MetadataWithoutAuth(envelope["protected_headers"])
	if len(ph) > 0 {
		meta["protected_headers"] = ph
	}
	if payloadType := v2EnvelopePayloadType(envelope, ph); payloadType != "" {
		meta["payload_type"] = payloadType
	}
	if ctx := v2MetadataWithoutAuth(envelope["context"]); len(ctx) > 0 {
		meta["context"] = ctx
	}
	if agentMD := v2MetadataWithoutAuth(envelope["agent_md"]); len(agentMD) > 0 {
		meta["agent_md"] = agentMD
	}
	return meta
}

func attachV2EnvelopeMetadata(message map[string]any, meta map[string]any) {
	if message == nil || meta == nil {
		return
	}
	if payloadType := strings.TrimSpace(v2AsString(meta["payload_type"])); payloadType != "" {
		message["payload_type"] = payloadType
	}
	if headers, ok := meta["protected_headers"].(map[string]any); ok && len(headers) > 0 {
		copyHeaders := make(map[string]any, len(headers))
		for key, value := range headers {
			copyHeaders[key] = value
		}
		message["protected_headers"] = copyHeaders
	}
	if agentMD, ok := meta["agent_md"].(map[string]any); ok && len(agentMD) > 0 {
		copyAgentMD := make(map[string]any, len(agentMD))
		for key, value := range agentMD {
			copyAgentMD[key] = value
		}
		message["agent_md"] = copyAgentMD
	}
}

func v2EnvelopePayloadType(envelope map[string]any, protectedHeaders map[string]any) string {
	if envelope == nil {
		return ""
	}
	value := envelope["payload_type"]
	if value == nil && len(protectedHeaders) > 0 {
		value = protectedHeaders["payload_type"]
	}
	return strings.TrimSpace(v2AsString(value))
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
