package aun

import (
	"context"
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

func timeNowUnix() int64 { return time.Now().Unix() }

// signedMethods 需要附加客户端 ECDSA 签名的方法集合
var signedMethods = map[string]bool{
	"message.send":                     true,
	"message.v2.put_peer_pk":           true,
	"message.v2.bootstrap":             true,
	"message.v2.group_bootstrap":       true,
	"message.v2.pull":                  true,
	"message.v2.ack":                   true,
	"group.send":                       true,
	"group.v2.put_group_pk":            true,
	"group.v2.bootstrap":               true,
	"group.v2.send":                    true,
	"group.v2.pull":                    true,
	"group.v2.ack":                     true,
	"group.v2.propose_state":           true,
	"group.v2.confirm_state":           true,
	"group.v2.get_proposal":            true,
	"group.kick":                       true,
	"group.add_member":                 true,
	"group.leave":                      true,
	"group.remove_member":              true,
	"group.update_rules":               true,
	"group.update":                     true,
	"group.update_announcement":        true,
	"group.update_join_requirements":   true,
	"group.set_role":                   true,
	"group.transfer_owner":             true,
	"group.bind_group_aid":             true,
	"group.renew_group_aid":            true,
	"group.complete_transfer":          true,
	"group.review_join_request":        true,
	"group.batch_review_join_request":  true,
	"group.request_join":               true,
	"group.use_invite_code":            true,
	"group.thought.put":                true,
	"message.thought.put":              true,
	"group.set_settings":               true,
	"group.fs.mkdir":                   true,
	"group.fs.rm":                      true,
	"group.fs.cp":                      true,
	"group.fs.mv":                      true,
	"group.fs.set_acl":                 true,
	"group.fs.remove_acl":              true,
	"group.fs.mount":                   true,
	"group.fs.umount":                  true,
	"group.fs.check_upload":            true,
	"group.fs.create_upload_session":   true,
	"group.fs.complete_upload":         true,
	"group.fs.create_download_ticket":  true,
	"storage.put_object":               true,
	"storage.delete_object":            true,
	"storage.create_share_link":        true,
	"storage.revoke_share_link":        true,
	"storage.get_by_share":             true,
	"storage.create_upload_session":    true,
	"storage.complete_upload":          true,
	"storage.create_folder":            true,
	"storage.rename_folder":            true,
	"storage.move_folder":              true,
	"storage.delete_folder":            true,
	"storage.move_object":              true,
	"storage.copy_object":              true,
	"storage.batch_delete":             true,
	"storage.set_object_meta":          true,
	"storage.append_object":            true,
	"storage.set_acl":                  true,
	"storage.remove_acl":               true,
	"storage.set_visibility":           true,
	"storage.check_access":             true,
	"storage.issue_token":              true,
	"storage.revoke_token":             true,
	"storage.create_symlink":           true,
	"storage.atomic_repoint":           true,
	"storage.rename_symlink":           true,
	"storage.delete_symlink":           true,
	"storage.fs.mkdir":                 true,
	"storage.fs.remove":                true,
	"storage.fs.rename":                true,
	"storage.fs.copy":                  true,
	"storage.fs.mount":                 true,
	"storage.fs.approve":               true,
	"storage.fs.reject":                true,
	"storage.fs.unmount":               true,
	"storage.fs.invalidate_membership": true,
	"storage.volume.create":            true,
	"storage.volume.renew":             true,
	"storage.volume.expire_due":        true,
	"collab.create":                    true,
	"collab.commit":                    true,
	"collab.clone":                     true,
	"collab.prune":                     true,
	"collab.revert":                    true,
	"collab.unregister":                true,
	"collab.tag.create":                true,
	"collab.tag.restore":               true,
	"collab.tag.rm":                    true,
	"collab.tag.prune":                 true,
	"group.commit_state":               true,
	"group.ban":                        true,
	"group.unban":                      true,
	"group.dissolve":                   true,
	"group.suspend":                    true,
	"group.resume":                     true,
}

type rpcPipeline struct {
	runtime *clientRuntime
}

type rpcPreflightResult struct {
	params map[string]any
}

func newRpcPipeline(runtime *clientRuntime) *rpcPipeline {
	return &rpcPipeline{runtime: runtime}
}

func (p *rpcPipeline) call(ctx context.Context, method string, params map[string]any) (result any, err error) {
	c := p.runtime.client
	tStart := time.Now()
	c.log.Debug("Call enter: method=%s paramsSummary=%s", method, summarizeCallParams(method, params))
	defer func() {
		if err != nil {
			c.log.Debug("Call exit (error): method=%s elapsed=%dms err=%v", method, time.Since(tStart).Milliseconds(), err)
		} else {
			c.log.Debug("Call exit: method=%s elapsed=%dms", method, time.Since(tStart).Milliseconds())
		}
	}()

	preflight, err := p.preflight(method, params)
	if err != nil {
		return nil, err
	}
	params = preflight.params
	rpcBackground := truthyBool(params["_rpc_background"]) || rpcBackgroundFromContext(ctx)
	if rpcBackground {
		ctx = contextWithRPCBackground(ctx)
	}
	pullGateLocked := truthyBool(params["_pull_gate_locked"])
	delete(params, "_pull_gate_locked")
	skipSendResultEnvelope := truthyBool(params["_skip_send_result_envelope"])
	delete(params, "_skip_send_result_envelope")
	pullGateKey := p.pullGateKeyForCall(method, params)
	if pullGateKey != "" && !pullGateLocked {
		lockedParams := copyRpcParams(params)
		lockedParams["_pull_gate_locked"] = true
		if skipSendResultEnvelope {
			lockedParams["_skip_send_result_envelope"] = true
		}
		return p.runPullSerialized(ctx, pullGateKey, func() (any, error) {
			return p.call(ctx, method, lockedParams)
		})
	}

	if method == "message.send" {
		encrypt := true
		if enc, ok := params["encrypt"]; ok {
			if encBool, ok := enc.(bool); ok {
				encrypt = encBool
			}
			delete(params, "encrypt")
		}
		if encrypt {
			if c.v2GetState() != nil {
				c.log.Debug("call route: message.send → V2 send")
				return c.sendV2Internal(ctx, params)
			}
			return nil, NewStateError("V2 session not initialized, cannot send encrypted message")
		}
		c.maybeAppendEchoTraceSend(params)
	}

	if method == "group.send" {
		encrypt := true
		if enc, ok := params["encrypt"]; ok {
			if encBool, ok := enc.(bool); ok {
				encrypt = encBool
			}
			delete(params, "encrypt")
		}
		if encrypt {
			if c.v2GetState() != nil {
				c.logEG.Debug("call route: group.send → V2 send")
				return c.sendGroupV2Internal(ctx, params)
			}
			return nil, NewStateError("V2 session not initialized, cannot send encrypted group message")
		}
		c.maybeAppendEchoTraceSend(params)
	}

	if method == "message.pull" && c.v2GetState() != nil {
		c.log.Debug("call route: message.pull → V2 pull")
		return c.pullV2Internal(ctx, params)
	}
	if method == "message.ack" && c.v2GetState() != nil {
		c.log.Debug("call route: message.ack → V2 ack")
		return c.ackV2Internal(ctx, params)
	}
	if method == "group.pull" {
		gid, _ := params["group_id"].(string)
		if c.v2GetState() != nil && gid != "" {
			c.logEG.Debug("call route: group.pull → V2 pull group=%s", gid)
			return c.pullGroupV2Internal(ctx, params)
		}
	}
	if method == "group.ack_messages" {
		gid, _ := params["group_id"].(string)
		if c.v2GetState() != nil && gid != "" {
			if c.groupCursorTargetsCurrentInstance(params) {
				c.logEG.Debug("call route: group.ack_messages → V2 ack group=%s", gid)
				return c.ackGroupV2Internal(ctx, params)
			}
			c.logEG.Debug("call route: group.ack_messages external cursor → raw ack group=%s device_id=%s slot_id=%s", gid, stringFromAny(params["device_id"]), stringFromAny(params["slot_id"]))
		}
	}

	if method == "group.thought.put" {
		encrypt := true
		if enc, ok := params["encrypt"]; ok {
			if encBool, ok := enc.(bool); ok {
				encrypt = encBool
			}
			delete(params, "encrypt")
		}
		if encrypt {
			gid, _ := params["group_id"].(string)
			if c.v2GetState() != nil && gid != "" {
				c.logEG.Debug("call route: group.thought.put → V2 encrypted put group=%s", gid)
				return c.putGroupThoughtEncryptedV2(ctx, params)
			}
			return nil, NewStateError("V2 session not initialized, cannot encrypt group thought")
		}
	}
	if method == "message.thought.put" {
		encrypt := true
		if enc, ok := params["encrypt"]; ok {
			if encBool, ok := enc.(bool); ok {
				encrypt = encBool
			}
			delete(params, "encrypt")
		}
		if encrypt {
			toAID, _ := params["to"].(string)
			if c.v2GetState() != nil && toAID != "" {
				c.log.Debug("call route: message.thought.put → V2 encrypted put to=%s", toAID)
				return c.putMessageThoughtEncryptedV2(ctx, params)
			}
			return nil, NewStateError("V2 session not initialized, cannot encrypt message thought")
		}
	}

	if err := p.applyClientSignature(method, params); err != nil {
		return nil, err
	}

	callCtx := ctx
	if nonIdempotentMethods[method] {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, nonIdempotentTimeout)
		defer cancel()
	}

	if method == "message.thought.get" || method == "group.thought.get" {
		c.log.Debug("thought.get transport call start: method=%s params=%s", method, summarizeCallParams(method, params))
	}

	if pullGateKey != "" && !pullGateLocked {
		gatedResult, gatedErr := p.runPullSerialized(callCtx, pullGateKey, func() (any, error) {
			return c.transport.Call(callCtx, method, params)
		})
		if gatedErr != nil {
			return nil, gatedErr
		}
		result = gatedResult
	} else {
		result, err = c.transport.Call(callCtx, method, params)
		if err != nil {
			return nil, err
		}
	}

	result, err = p.postprocessResult(ctx, method, params, result)
	if err != nil {
		return nil, err
	}
	if !skipSendResultEnvelope {
		result = c.delivery().attachSendResultEnvelope(method, params, result, truthyBool(params["encrypted"]))
	}
	return result, nil
}

func (p *rpcPipeline) preflight(method string, params map[string]any) (*rpcPreflightResult, error) {
	c := p.runtime.client
	c.mu.RLock()
	state := c.state
	c.mu.RUnlock()

	if state != StateConnected {
		return nil, NewConnectionError("客户端未连接")
	}
	if internalOnlyMethods[method] {
		return nil, NewPermissionError(fmt.Sprintf("方法 %s 为内部专用", method))
	}

	nextParams := copyRpcParams(params)
	p.mergeInstanceProtectedHeaders(method, nextParams)

	if method == "message.send" || method == "group.send" {
		p.normalizeOutboundMessagePayload(nextParams, method)
	}
	if err := p.validateOutboundCall(method, nextParams); err != nil {
		return nil, err
	}
	if err := p.injectMessageCursorContext(method, nextParams); err != nil {
		return nil, err
	}
	normalizeGroupCallContext(c, method, nextParams)
	p.clampAckParams(method, nextParams)

	return &rpcPreflightResult{params: nextParams}, nil
}

func (p *rpcPipeline) normalizeOutboundMessagePayload(params map[string]any, method string) {
	if _, hasPayload := params["payload"]; !hasPayload {
		if content, hasContent := params["content"]; hasContent {
			params["payload"] = content
			delete(params, "content")
		}
	}
	payload, _ := params["payload"].(map[string]any)
	if payload != nil {
		if _, hasType := payload["type"]; !hasType {
			if _, ok := payload["text"].(string); ok {
				normalized := make(map[string]any, len(payload)+1)
				normalized["type"] = "text"
				for k, v := range payload {
					normalized[k] = v
				}
				params["payload"] = normalized
			}
		}
	}
}

func (p *rpcPipeline) validateOutboundCall(method string, params map[string]any) error {
	if method == "message.send" {
		if err := validateMessageRecipient(params["to"]); err != nil {
			return err
		}
		// 校验目标 AID 格式（拒绝 __system__ 等非法格式）
		if _, err := ValidateAIDFormat(params["to"], "message.send.to"); err != nil {
			return err
		}
		if _, ok := params["persist"]; ok {
			return NewValidationError("message.send no longer accepts 'persist'; configure delivery_mode during connect")
		}
		if _, ok := params["delivery_mode"]; ok {
			return NewValidationError("message.send does not accept delivery_mode; configure delivery_mode during connect")
		}
		if _, ok := params["queue_routing"]; ok {
			return NewValidationError("message.send does not accept delivery_mode; configure delivery_mode during connect")
		}
		if _, ok := params["affinity_ttl_ms"]; ok {
			return NewValidationError("message.send does not accept delivery_mode; configure delivery_mode during connect")
		}
		return nil
	}
	if method == "group.send" {
		// 校验目标 Group ID 格式
		if _, err := ValidateGroupIDFormat(params["group_id"], "group.send.group_id"); err != nil {
			return err
		}
		if _, ok := params["persist"]; ok {
			return NewValidationError("group.send does not accept 'persist'; group messages are always fanout")
		}
		if _, ok := params["delivery_mode"]; ok {
			return NewValidationError("group.send does not accept delivery_mode; group messages are always fanout")
		}
		if _, ok := params["queue_routing"]; ok {
			return NewValidationError("group.send does not accept delivery_mode; group messages are always fanout")
		}
		if _, ok := params["affinity_ttl_ms"]; ok {
			return NewValidationError("group.send does not accept delivery_mode; group messages are always fanout")
		}
	}
	if method == "group.thought.put" || method == "group.thought.get" || method == "message.thought.put" || method == "message.thought.get" {
		contextType := stringFieldFromObject(params["context"], "type")
		contextID := stringFieldFromObject(params["context"], "id")
		hasContext := contextType != "" && contextID != ""
		if !hasContext {
			return NewValidationError(method + " requires context.type + context.id")
		}
	}
	if method == "group.thought.put" {
		// 校验目标 Group ID 格式
		if _, err := ValidateGroupIDFormat(params["group_id"], "group.thought.put.group_id"); err != nil {
			return err
		}
	}
	if method == "group.thought.get" {
		senderAID, _ := params["sender_aid"].(string)
		if strings.TrimSpace(senderAID) == "" {
			return NewValidationError("group.thought.get requires sender_aid")
		}
		// 校验 sender_aid 格式
		if _, err := ValidateAIDFormat(params["sender_aid"], "group.thought.get.sender_aid"); err != nil {
			return err
		}
		// 校验目标 Group ID 格式
		if _, err := ValidateGroupIDFormat(params["group_id"], "group.thought.get.group_id"); err != nil {
			return err
		}
	}
	if method == "message.thought.put" {
		if err := validateMessageRecipient(params["to"]); err != nil {
			return err
		}
		if strings.TrimSpace(fmt.Sprint(params["to"])) == "" {
			return NewValidationError("message.thought.put requires to")
		}
		// 校验目标 AID 格式
		if _, err := ValidateAIDFormat(params["to"], "message.thought.put.to"); err != nil {
			return err
		}
	}
	if method == "message.thought.get" {
		senderAID, _ := params["sender_aid"].(string)
		if strings.TrimSpace(senderAID) == "" {
			return NewValidationError("message.thought.get requires sender_aid")
		}
		// 校验 sender_aid 格式
		if _, err := ValidateAIDFormat(params["sender_aid"], "message.thought.get.sender_aid"); err != nil {
			return err
		}
	}
	return nil
}

func (p *rpcPipeline) injectMessageCursorContext(method string, params map[string]any) error {
	c := p.runtime.client
	if method != "message.pull" && method != "message.ack" {
		return nil
	}
	if existing, ok := params["device_id"]; ok && strings.TrimSpace(fmt.Sprint(existing)) != c.deviceID {
		return NewValidationError("message.pull/message.ack device_id must match the current client instance")
	}
	slotSource := any(c.slotID)
	if existing, ok := params["slot_id"]; ok {
		slotSource = existing
	}
	slotID, err := NormalizeSlotID(slotSource, c.slotID)
	if err != nil {
		return NewValidationError(err.Error())
	}
	if SlotIsolationKey(slotID) != SlotIsolationKey(c.slotID) {
		return NewValidationError("message.pull/message.ack slot_id must match the current client instance")
	}
	params["device_id"] = c.deviceID
	params["slot_id"] = c.slotID
	return nil
}

func (p *rpcPipeline) clampAckParams(method string, params map[string]any) {
	c := p.runtime.client
	if params == nil {
		return
	}
	switch method {
	case "message.ack":
		c.mu.RLock()
		myAID := c.aid
		c.mu.RUnlock()
		if myAID != "" {
			params["seq"] = c.clampAckSeq(method, "seq", "p2p:"+myAID, toInt64(params["seq"]))
		}
	case "message.v2.ack":
		c.mu.RLock()
		myAID := c.aid
		c.mu.RUnlock()
		if myAID != "" {
			params["up_to_seq"] = c.clampAckSeq(method, "up_to_seq", "p2p:"+myAID, toInt64(params["up_to_seq"]))
		}
	case "group.ack_messages":
		groupID := strings.TrimSpace(stringFromAny(params["group_id"]))
		if groupID != "" {
			params["msg_seq"] = c.clampAckSeq(method, "msg_seq", "group:"+groupID, toInt64(params["msg_seq"]))
		}
	case "group.v2.ack":
		groupID := strings.TrimSpace(stringFromAny(params["group_id"]))
		if groupID != "" {
			params["up_to_seq"] = c.clampAckSeq(method, "up_to_seq", "group:"+groupID, toInt64(params["up_to_seq"]))
		}
	case "group.ack_events":
		groupID := strings.TrimSpace(stringFromAny(params["group_id"]))
		if groupID != "" {
			params["event_seq"] = c.clampAckSeq(method, "event_seq", "group_event:"+groupID, toInt64(params["event_seq"]))
		}
	}
}

func (p *rpcPipeline) mergeInstanceProtectedHeaders(method string, params map[string]any) {
	if !protectedHeadersMergeMethods[method] {
		return
	}
	instance := p.runtime.rpc.protectedHeaders()
	if len(instance) == 0 {
		return
	}

	merged := make(map[string]any)
	if existing := protectedHeadersFromParams(params); existing != nil {
		for k, v := range existing {
			merged[k] = v
		}
	}

	for k, v := range instance {
		if _, exists := merged[k]; !exists {
			merged[k] = v
		}
	}
	params["protected_headers"] = merged
}

func protectedHeadersFromParams(params map[string]any) map[string]any {
	if params == nil {
		return nil
	}
	if value, exists := params["protected_headers"]; exists {
		return protectedHeadersMap(value)
	}
	if value, exists := params["headers"]; exists {
		return protectedHeadersMap(value)
	}
	return nil
}

func protectedHeadersMap(value any) map[string]any {
	switch headers := value.(type) {
	case map[string]any:
		copied := make(map[string]any, len(headers))
		for k, v := range headers {
			copied[k] = v
		}
		return copied
	case map[string]string:
		copied := make(map[string]any, len(headers))
		for k, v := range headers {
			copied[k] = v
		}
		return copied
	case *ProtectedHeaders:
		return protectedHeadersMap(headers.ToMap())
	case ProtectedHeaders:
		return protectedHeadersMap(headers.ToMap())
	default:
		return nil
	}
}

// signClientOperation 为关键操作附加客户端 ECDSA 签名（_client_signature 字段）。
func (p *rpcPipeline) signClientOperation(method string, params map[string]any) error {
	c := p.runtime.client
	c.mu.RLock()
	currentAID := c.currentAIDObj
	c.mu.RUnlock()
	aidStr, privPEM, certPEM := clientSignatureIdentityFromParams(params, currentAID)
	if aidStr == "" || privPEM == "" {
		return nil
	}
	ts := fmt.Sprintf("%d", timeNowUnix())

	// 计算 params hash：签名覆盖所有非 _ 前缀且非 client_signature 的业务字段
	paramsForHash := make(map[string]any)
	for k, v := range params {
		if k != "client_signature" && !strings.HasPrefix(k, "_") {
			paramsForHash[k] = v
		}
	}
	paramsJSON := stableStringify(paramsForHash)
	paramsHash := fmt.Sprintf("%x", sha256.Sum256([]byte(paramsJSON)))
	signData := []byte(fmt.Sprintf("%s|%s|%s|%s", method, aidStr, ts, paramsHash))

	pk, err := parseECPrivateKeyPEM(privPEM)
	if err != nil {
		return NewClientSignatureError(fmt.Sprintf("客户端签名失败，拒绝发送无签名请求: %v", err))
	}
	hash := sha256.Sum256(signData)
	sig, err := ecdsa.SignASN1(cryptorand.Reader, pk, hash[:])
	if err != nil {
		return NewClientSignatureError(fmt.Sprintf("客户端签名失败，拒绝发送无签名请求: %v", err))
	}

	// 证书指纹：用于锁定签名时使用的证书版本
	certFingerprint := ""
	if certPEM != "" {
		block, _ := pem.Decode([]byte(certPEM))
		if block != nil {
			fp := sha256.Sum256(block.Bytes)
			certFingerprint = "sha256:" + fmt.Sprintf("%x", fp)
		}
	}

	params["client_signature"] = map[string]any{
		"aid":              aidStr,
		"cert_fingerprint": certFingerprint,
		"timestamp":        ts,
		"params_hash":      paramsHash,
		"signature":        base64.StdEncoding.EncodeToString(sig),
	}
	return nil
}

func clientSignatureIdentityFromParams(params map[string]any, fallback *AID) (string, string, string) {
	raw := params["_client_signature_identity"]
	switch identity := raw.(type) {
	case *AID:
		if identity != nil {
			return strings.TrimSpace(identity.Aid), identity.PrivateKeyPem, identity.CertPem
		}
	case AID:
		return strings.TrimSpace(identity.Aid), identity.PrivateKeyPem, identity.CertPem
	case map[string]any:
		aid := strings.TrimSpace(storageAnyToString(firstNonNil(identity["aid"], identity["Aid"])))
		privateKeyPEM := storageAnyToString(firstNonNil(
			identity["private_key_pem"],
			identity["privateKeyPem"],
			identity["PrivateKeyPem"],
		))
		certPEM := storageAnyToString(firstNonNil(
			identity["cert_pem"],
			identity["certPem"],
			identity["cert"],
			identity["CertPem"],
		))
		return aid, privateKeyPEM, certPEM
	}
	if fallback == nil {
		return "", "", ""
	}
	return strings.TrimSpace(fallback.Aid), fallback.PrivateKeyPem, fallback.CertPem
}

// applyClientSignature 统一执行 signed method 策略和 echo skip 规则。
func (p *rpcPipeline) applyClientSignature(method string, params map[string]any) error {
	if !signedMethods[method] {
		return nil
	}
	if p.shouldSkipClientSignature(method, params) {
		delete(params, "client_signature")
		return nil
	}
	return p.signClientOperation(method, params)
}

// isEchoMessageParams 判断是否为 echo 链路测试消息（明文 payload 且含 echo 关键字）。
func (p *rpcPipeline) isEchoMessageParams(params map[string]any) bool {
	if params == nil {
		return false
	}
	if truthyBool(params["encrypted"]) || truthyBool(params["encrypt"]) {
		return false
	}
	c := p.runtime.client
	_, _, ok := c.isEchoPayload(params["payload"])
	return ok
}

// shouldSkipClientSignature echo 消息不参与客户端操作签名（中间节点会追加 trace 行）。
func (p *rpcPipeline) shouldSkipClientSignature(method string, params map[string]any) bool {
	return (method == "message.send" || method == "group.send") && p.isEchoMessageParams(params)
}

// pullGateKeyForCall 根据 RPC method 和 params 返回 pull gate key。
// 空字符串表示该调用不需要 pull gate 保护。
func (p *rpcPipeline) pullGateKeyForCall(method string, params map[string]any) string {
	c := p.runtime.client
	switch method {
	case "message.pull", "message.v2.pull":
		c.mu.RLock()
		aid := c.aid
		c.mu.RUnlock()
		if aid != "" {
			return "p2p:" + aid
		}
		return ""
	case "group.pull", "group.v2.pull":
		gid := strings.TrimSpace(stringFromAny(params["group_id"]))
		if gid != "" {
			return "group:" + gid
		}
		return ""
	case "group.pull_events":
		gid := strings.TrimSpace(stringFromAny(params["group_id"]))
		if gid != "" {
			return "group_event:" + gid
		}
		return ""
	}
	return ""
}

// tryAcquirePullGate 尝试获取 pull gate。
// 返回 (token, true) 表示成功获取；(0, false) 表示当前有 inflight 且未过期。
func (p *rpcPipeline) tryAcquirePullGate(key string) (uint64, bool) {
	if key == "" {
		return 0, true
	}
	c := p.runtime.client
	now := time.Now().UnixMilli()
	staleMs := atomic.LoadInt64(&c.pullGateStaleMs)

	actual, _ := c.pullGates.LoadOrStore(key, &pullGateState{})
	gate := actual.(*pullGateState)

	if gate.inflight.Load() && now-gate.startedAt.Load() <= staleMs {
		return 0, false
	}
	if gate.inflight.Load() {
		c.log.Warn("pull in-flight stale reset: key=%s age=%dms", key, now-gate.startedAt.Load())
	}
	token := gate.token.Add(1)
	gate.inflight.Store(true)
	gate.startedAt.Store(now)
	return token, true
}

// releasePullGate 释放 pull gate（仅当 token 匹配时）。
func (p *rpcPipeline) releasePullGate(key string, token uint64) {
	if key == "" {
		return
	}
	actual, ok := p.runtime.client.pullGates.Load(key)
	if !ok {
		return
	}
	gate := actual.(*pullGateState)
	if gate.token.Load() != token {
		return
	}
	gate.inflight.Store(false)
	gate.startedAt.Store(0)
}

// runPullSerialized 获取 pull gate → 执行操作 → 释放。
func (p *rpcPipeline) runPullSerialized(ctx context.Context, key string, operation func() (any, error)) (any, error) {
	token, acquired := p.tryAcquirePullGate(key)
	if !acquired {
		staleMs := atomic.LoadInt64(&p.runtime.client.pullGateStaleMs)
		deadline := time.Now().Add(time.Duration(staleMs+100) * time.Millisecond)
		for !acquired && time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return nil, NewStateError(fmt.Sprintf("pull already in-flight for %s", key))
			case <-time.After(25 * time.Millisecond):
			}
			token, acquired = p.tryAcquirePullGate(key)
		}
		if !acquired {
			return nil, NewStateError(fmt.Sprintf("pull already in-flight for %s", key))
		}
	}
	defer p.releasePullGate(key, token)
	return operation()
}

// rawCall 内部裸 RPC 入口；默认执行客户端签名策略。
func (p *rpcPipeline) rawCall(ctx context.Context, method string, params map[string]any, signed bool) (any, error) {
	c := p.runtime.client
	payload := copyRpcParams(params)
	rpcBackground := truthyBool(payload["_rpc_background"]) || rpcBackgroundFromContext(ctx)
	if signed && signedMethods[method] {
		if p.shouldSkipClientSignature(method, payload) {
			delete(payload, "client_signature")
		} else {
			if err := p.signClientOperation(method, payload); err != nil {
				return nil, err
			}
		}
	}
	delete(payload, "_client_signature_identity")
	if rpcBackground {
		payload["_rpc_background"] = true
	}
	return c.transport.Call(ctx, method, payload)
}

// postprocessResult 按 RPC method 调度响应后处理。
func (p *rpcPipeline) postprocessResult(ctx context.Context, method string, params map[string]any, result any) (any, error) {
	p.postprocessThoughtGet(ctx, method, params, result)
	p.postprocessMessagePull(method, params, result)
	p.postprocessGroupPull(method, params, result)
	p.postprocessMembershipMutation(ctx, method, params, result)
	return result, nil
}

func (p *rpcPipeline) postprocessThoughtGet(ctx context.Context, method string, params map[string]any, result any) {
	c := p.runtime.client
	if method == "message.thought.get" && c.v2GetState() != nil {
		if m, ok := result.(map[string]any); ok {
			c.log.Debug("message.thought.get transport result: found=%v raw_count=%d", m["found"], len(anySlice(m["thoughts"])))
		}
		fromAID := strings.TrimSpace(getStr(params, "sender_aid", ""))
		c.decryptV2ThoughtGetResult(ctx, result, fromAID, false)
	}
	if method == "group.thought.get" && c.v2GetState() != nil {
		if m, ok := result.(map[string]any); ok {
			c.log.Debug("group.thought.get transport result: found=%v raw_count=%d", m["found"], len(anySlice(m["thoughts"])))
		}
		fromAID := strings.TrimSpace(getStr(params, "sender_aid", ""))
		c.decryptV2ThoughtGetResult(ctx, result, fromAID, true)
	}
}

func (p *rpcPipeline) postprocessMessagePull(method string, params map[string]any, result any) {
	if method != "message.pull" {
		return
	}
	c := p.runtime.client
	resultMap, ok := result.(map[string]any)
	if !ok {
		return
	}
	messages, _ := resultMap["messages"].([]any)
	c.log.Debug("message.pull returned %d messages", len(messages))
	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	if myAID == "" {
		return
	}
	ns := "p2p:" + myAID
	contigBefore := c.seqTracker.GetContiguousSeq(ns)
	var pullMsgs []map[string]any
	for _, raw := range messages {
		if m, ok := raw.(map[string]any); ok {
			pullMsgs = append(pullMsgs, m)
		}
	}
	if len(pullMsgs) > 0 {
		pullAfterSeq := int(toInt64(params["after_seq"]))
		c.seqTracker.OnPullResult(ns, pullMsgs, pullAfterSeq)
	}
	serverAck := int(toInt64(resultMap["server_ack_seq"]))
	if serverAck > 0 {
		contig := c.seqTracker.GetContiguousSeq(ns)
		if contig < serverAck {
			c.log.Info("message.pull retention-floor advanced: ns=%s contiguous=%d -> server_ack_seq=%d", ns, contig, serverAck)
			c.seqTracker.ForceContiguousSeq(ns, serverAck)
		}
	}
	if c.seqTracker.GetContiguousSeq(ns) != contigBefore {
		c.persistSeq(ns)
	}
	resultMap["_contig_before"] = contigBefore
}

func (p *rpcPipeline) postprocessGroupPull(method string, params map[string]any, result any) {
	if method != "group.pull" {
		return
	}
	c := p.runtime.client
	resultMap, ok := result.(map[string]any)
	if !ok {
		return
	}
	messages, _ := resultMap["messages"].([]any)
	gid := strings.TrimSpace(stringFromAny(params["group_id"]))
	c.logEG.Debug("group.pull returned %d messages: group=%s", len(messages), gid)
	if gid == "" {
		return
	}
	ns := "group:" + gid
	contigBefore := c.seqTracker.GetContiguousSeq(ns)
	var pullMsgs []map[string]any
	for _, raw := range messages {
		if m, ok := raw.(map[string]any); ok {
			pullMsgs = append(pullMsgs, m)
		}
	}
	if len(pullMsgs) > 0 {
		pullAfterSeq := int(toInt64(params["after_seq"]))
		if pullAfterSeq == 0 {
			pullAfterSeq = int(toInt64(params["after_message_seq"]))
		}
		c.seqTracker.OnPullResult(ns, pullMsgs, pullAfterSeq)
	}
	if cursor, ok := resultMap["cursor"].(map[string]any); ok {
		serverAck := int(toInt64(cursor["current_seq"]))
		if serverAck > 0 {
			contig := c.seqTracker.GetContiguousSeq(ns)
			if contig < serverAck {
				c.logEG.Info("group.pull retention-floor advanced: ns=%s contiguous=%d -> cursor.current_seq=%d", ns, contig, serverAck)
				c.seqTracker.ForceContiguousSeq(ns, serverAck)
			}
		}
	}
	if c.seqTracker.GetContiguousSeq(ns) != contigBefore {
		c.persistSeq(ns)
	}
	resultMap["_contig_before"] = contigBefore
}

func (p *rpcPipeline) postprocessMembershipMutation(ctx context.Context, method string, params map[string]any, result any) {
	p.runtime.client.getGroupStateCoordinator().postprocessResult(ctx, method, params, result)
}

func copyRpcParams(params map[string]any) map[string]any {
	if params == nil {
		return make(map[string]any)
	}
	copied := make(map[string]any, len(params))
	for k, v := range params {
		copied[k] = v
	}
	return copied
}

func normalizeGroupCallContext(c *AUNClient, method string, params map[string]any) {
	if !strings.HasPrefix(method, "group.") {
		return
	}
	if rawGid, ok := params["group_id"]; ok {
		if s, ok2 := rawGid.(string); ok2 && s != "" {
			params["group_id"] = NormalizeGroupID(s, "")
		}
	}
	if _, exists := params["device_id"]; !exists {
		params["device_id"] = c.deviceID
	}
	if _, exists := params["slot_id"]; !exists {
		params["slot_id"] = c.slotID
	}
}
