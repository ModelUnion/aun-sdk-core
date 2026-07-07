package aun

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
)

// messageDeliveryEngine 消息推送、拉取、有序投递、补洞与 ack 协调器。
//
// 行为基准 = Python _client/delivery.py 的 MessageDeliveryEngine。
// 组件持有 clientRuntime 引用，通过 d.runtime.client 访问主 client 的私有字段与方法。
// 主 client 中对应方法保留为 shim，委托到本组件，兼容测试 monkeypatch。
type messageDeliveryEngine struct {
	runtime *clientRuntime
}

func newMessageDeliveryEngine(runtime *clientRuntime) *messageDeliveryEngine {
	return &messageDeliveryEngine{runtime: runtime}
}

// delivery 返回主 client 的 delivery 组件（accessor，供 client.go shim 调用）。
func (c *AUNClient) delivery() *messageDeliveryEngine {
	if c.deliveryEngine != nil {
		return c.deliveryEngine
	}
	return newMessageDeliveryEngine(c.getClientRuntime())
}

// ── 应用层事件发布 ──────────────────────────────────────────

var appMessageEnvelopeKeys = []string{
	"module_id", "message_type", "type", "kind", "version",
	"from", "from_aid", "sender_aid", "to", "to_aid", "group_id",
	"timestamp", "created_at", "encrypted",
	"context", "protected_headers", "headers", "payload_type",
}

var recallPayloadKeys = []string{
	"message_ids", "target_message_seqs",
	"recalled_message_id", "target_message_id", "original_message_id",
	"target_seq", "original_seq",
	"notice_message_id", "notice_seq", "event_seq",
	"sender_aid", "recalled_by", "recalled_at", "reason",
}

var appSendEnvelopeMethods = map[string]bool{
	"message.send":        true,
	"group.send":          true,
	"message.thought.put": true,
	"group.thought.put":   true,
}

var appGroupEventEnvelopeKeys = []string{
	"module_id", "event_id", "event_seq", "seq", "event_type", "action", "group_id",
	"actor_aid", "sender_aid", "member_aid", "target_aid", "operator_aid",
	"created_at", "timestamp", "t_server", "status", "device_id", "slot_id",
}

func (d *messageDeliveryEngine) attachCurrentInstanceContext(payload any) any {
	c := d.runtime.client
	message, ok := payload.(map[string]any)
	if !ok {
		return payload
	}
	result := copyMapShallow(message)
	if _, exists := result["device_id"]; !exists {
		result["device_id"] = c.deviceID
	}
	if c.slotID != "" && strings.TrimSpace(stringFromAny(result["slot_id"])) == "" {
		result["slot_id"] = c.slotID
	}
	return result
}

func (d *messageDeliveryEngine) normalizePublishedMessagePayload(event string, payload any) any {
	if isInstanceScopedMessageEvent(event) {
		normalized := stripInternalSenderDeviceFields(d.runtime.client.attachCurrentInstanceContext(payload))
		return attachAppMessageEnvelope(normalized)
	}
	if isGroupScopedEvent(event) {
		normalized := d.runtime.client.attachCurrentInstanceContext(payload)
		return attachAppGroupEventEnvelope(normalized)
	}
	return payload
}

func appMessageEnvelope(payload any) map[string]any {
	message, ok := payload.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	body := map[string]any{}
	if rawBody, ok := message["payload"].(map[string]any); ok {
		body = rawBody
	}
	envelope := make(map[string]any)
	setEnvelopeValue(envelope, "from", firstEnvelopeValue(message["from"], message["from_aid"], message["sender_aid"]))
	setEnvelopeValue(envelope, "to", firstEnvelopeValue(message["to"], message["to_aid"]))
	setEnvelopeValue(envelope, "group_id", message["group_id"])
	setEnvelopeValue(envelope, "type", firstEnvelopeValue(body["type"], message["type"], message["message_type"], message["payload_type"]))
	setEnvelopeValue(envelope, "kind", firstEnvelopeValue(body["kind"], message["kind"]))
	setEnvelopeValue(envelope, "version", firstEnvelopeValue(body["version"], message["version"]))
	setEnvelopeValue(envelope, "timestamp", firstEnvelopeValue(message["timestamp"], message["created_at"], message["t_server"]))
	if value, exists := message["encrypted"]; exists {
		envelope["encrypted"] = truthyBool(value)
	}
	if value := envelopeMapValue(message["context"]); len(value) > 0 {
		envelope["context"] = value
	}
	protectedHeaders := envelopeMapValue(message["protected_headers"])
	if len(protectedHeaders) == 0 {
		protectedHeaders = envelopeMapValue(message["headers"])
	}
	if len(protectedHeaders) > 0 {
		envelope["protected_headers"] = protectedHeaders
	}
	setEnvelopeValue(envelope, "payload_type", firstEnvelopeValue(message["payload_type"], protectedHeaders["payload_type"]))
	return envelope
}

func isGroupScopedEvent(event string) bool {
	return event == "group.changed"
}

func appGroupEventEnvelope(payload any) map[string]any {
	event, ok := payload.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	envelope := make(map[string]any)
	for _, key := range appGroupEventEnvelopeKeys {
		if value, exists := event[key]; exists {
			envelope[key] = value
		}
	}
	return envelope
}

func attachAppMessageEnvelope(payload any) any {
	message, ok := payload.(map[string]any)
	if !ok {
		return payload
	}
	result := copyMapShallow(message)
	// 兼容期保留顶层信封字段；下一个大版本 0.5.* 将移除这些顶层别名，请通过 envelope.* 访问。
	result["envelope"] = appMessageEnvelope(result)
	return result
}

func (d *messageDeliveryEngine) sendResultEnvelope(method string, params map[string]any, result any, encrypted bool) map[string]any {
	if !appSendEnvelopeMethods[method] {
		return map[string]any{}
	}
	body := map[string]any{}
	if rawBody, ok := params["payload"].(map[string]any); ok {
		body = rawBody
	}
	resultMap, _ := result.(map[string]any)
	envelope := make(map[string]any)
	d.runtime.client.mu.RLock()
	selfAID := d.runtime.client.aid
	d.runtime.client.mu.RUnlock()
	setEnvelopeValue(envelope, "from", selfAID)
	if strings.HasPrefix(method, "message.") {
		setEnvelopeValue(envelope, "to", params["to"])
	} else {
		setEnvelopeValue(envelope, "group_id", params["group_id"])
	}
	setEnvelopeValue(envelope, "type", firstEnvelopeValue(body["type"], params["type"], params["message_type"], params["payload_type"]))
	setEnvelopeValue(envelope, "kind", firstEnvelopeValue(body["kind"], params["kind"]))
	setEnvelopeValue(envelope, "version", firstEnvelopeValue(body["version"], params["version"]))
	setEnvelopeValue(envelope, "timestamp", firstEnvelopeValue(
		params["timestamp"],
		resultMap["timestamp"],
		resultMap["created_at"],
		resultMap["t_server"],
		time.Now().UnixMilli(),
	))
	envelope["encrypted"] = encrypted
	if value := envelopeMapValue(params["context"]); len(value) > 0 {
		envelope["context"] = value
	}
	protectedHeaders := envelopeMapValue(params["protected_headers"])
	if len(protectedHeaders) == 0 {
		protectedHeaders = envelopeMapValue(params["headers"])
	}
	if len(protectedHeaders) > 0 {
		envelope["protected_headers"] = protectedHeaders
	}
	setEnvelopeValue(envelope, "payload_type", firstEnvelopeValue(params["payload_type"], protectedHeaders["payload_type"], body["type"]))
	return envelope
}

func (d *messageDeliveryEngine) attachSendResultEnvelope(method string, params map[string]any, result any, encrypted bool) any {
	if !appSendEnvelopeMethods[method] {
		return result
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		return result
	}
	out := copyMapShallow(resultMap)
	out["envelope"] = d.sendResultEnvelope(method, params, out, encrypted)
	if payload, exists := params["payload"]; exists {
		out["payload"] = payload
	} else if content, exists := params["content"]; exists {
		out["payload"] = content
	}
	return out
}

func attachAppGroupEventEnvelope(payload any) any {
	event, ok := payload.(map[string]any)
	if !ok {
		return payload
	}
	result := copyMapShallow(event)
	// 兼容期保留顶层群事件信封字段；下一个大版本 0.5.* 将移除这些顶层别名，请通过 envelope.* 访问。
	result["envelope"] = appGroupEventEnvelope(result)
	return result
}

func firstEnvelopeValue(values ...any) any {
	for _, value := range values {
		if value == nil {
			continue
		}
		if text, ok := value.(string); ok && strings.TrimSpace(text) == "" {
			continue
		}
		return value
	}
	return nil
}

func setEnvelopeValue(envelope map[string]any, key string, value any) {
	if value == nil {
		return
	}
	if text, ok := value.(string); ok && strings.TrimSpace(text) == "" {
		return
	}
	envelope[key] = value
}

func envelopeMapValue(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, v := range typed {
			if k != "_auth" {
				out[k] = v
			}
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(typed))
		for k, v := range typed {
			if k != "_auth" {
				out[k] = v
			}
		}
		return out
	case *ProtectedHeaders:
		return envelopeMapValue(typed.ToMap())
	case ProtectedHeaders:
		return envelopeMapValue(typed.ToMap())
	default:
		return nil
	}
}

func stripInternalSenderDeviceFields(payload any) any {
	message, ok := payload.(map[string]any)
	if !ok {
		return payload
	}
	result := copyMapShallow(message)
	for _, key := range []string{"sender_device_id", "_sender_device_id", "from_device_id", "from_device"} {
		delete(result, key)
	}
	return result
}

func firstNonEmptyDelivery(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func recallEventFromMessage(message any) (map[string]any, bool) {
	msg, ok := message.(map[string]any)
	if !ok {
		return nil, false
	}
	payloadMap := map[string]any{}
	if rawPayload, ok := msg["payload"].(map[string]any); ok {
		payloadMap = rawPayload
	}
	msgType := strings.TrimSpace(getStr(msg, "type", ""))
	payloadType := strings.TrimSpace(getStr(payloadMap, "type", ""))
	if payloadType == "" {
		payloadType = strings.TrimSpace(getStr(payloadMap, "kind", ""))
	}
	if msgType != "message.recalled" && payloadType != "message.recalled" {
		return nil, false
	}
	event := make(map[string]any, len(payloadMap)+8)
	for k, v := range payloadMap {
		event[k] = v
	}
	for _, key := range appMessageEnvelopeKeys {
		if _, exists := event[key]; !exists {
			if value, ok := msg[key]; ok {
				event[key] = value
			}
		}
	}
	for _, key := range recallPayloadKeys {
		if _, exists := event[key]; !exists {
			if value, ok := msg[key]; ok {
				event[key] = value
			}
		}
	}
	messageIDs := []any{}
	if rawIDs, ok := event["message_ids"].([]any); ok {
		for _, item := range rawIDs {
			value := strings.TrimSpace(stringFromAny(item))
			if value != "" {
				messageIDs = append(messageIDs, value)
			}
		}
	}
	if len(messageIDs) == 0 {
		for _, key := range []string{"recalled_message_id", "target_message_id", "original_message_id"} {
			value := strings.TrimSpace(getStr(event, key, ""))
			if value != "" {
				messageIDs = append(messageIDs, value)
				break
			}
		}
	}
	event["type"] = "message.recalled"
	event["kind"] = "message.recalled"
	event["message_ids"] = messageIDs
	if _, ok := event["from"]; !ok {
		event["from"] = firstNonEmptyDelivery(getStr(msg, "from", ""), getStr(msg, "from_aid", ""))
	}
	if _, ok := event["to"]; !ok {
		event["to"] = firstNonEmptyDelivery(getStr(msg, "to", ""), getStr(msg, "to_aid", ""))
	}
	if _, ok := event["timestamp"]; !ok {
		ts := msg["timestamp"]
		if ts == nil {
			ts = msg["t_server"]
		}
		if ts == nil {
			ts = event["recalled_at"]
		}
		if ts == nil {
			ts = int64(0)
		}
		event["timestamp"] = ts
	}
	if _, ok := event["seq"]; !ok {
		if seq, exists := msg["seq"]; exists {
			event["seq"] = seq
		}
	}
	if mid, exists := msg["message_id"]; exists {
		event["message_id"] = mid
		if _, ok := event["tombstone_message_id"]; !ok {
			event["tombstone_message_id"] = mid
		}
	}
	for _, key := range []string{"device_id", "slot_id"} {
		if _, ok := event[key]; !ok {
			if value, exists := msg[key]; exists {
				event[key] = value
			}
		}
	}
	return event, true
}

func p2pAppEventForMessage(message any) (string, any) {
	if recall, ok := recallEventFromMessage(message); ok {
		return "message.recalled", recall
	}
	return "message.received", message
}

func messageRecallDedupKey(payload map[string]any) string {
	idParts := []string{}
	if rawIDs, ok := payload["message_ids"].([]any); ok {
		for _, item := range rawIDs {
			v := strings.TrimSpace(stringFromAny(item))
			if v != "" {
				idParts = append(idParts, v)
			}
		}
	} else if v := strings.TrimSpace(stringFromAny(payload["message_ids"])); v != "" {
		idParts = append(idParts, v)
	}
	sort.Strings(idParts)
	if len(idParts) > 0 {
		return "p2p|id:" + strings.Join(idParts, ",")
	}
	for _, key := range []string{"recalled_message_id", "target_message_id", "original_message_id"} {
		value := strings.TrimSpace(getStr(payload, key, ""))
		if value != "" {
			return "p2p|id:" + value
		}
	}
	seqParts := []string{}
	if rawSeqs, ok := payload["target_message_seqs"].([]any); ok {
		for _, item := range rawSeqs {
			v := strings.TrimSpace(stringFromAny(item))
			if v != "" {
				seqParts = append(seqParts, v)
			}
		}
	} else {
		for _, key := range []string{"target_message_seqs", "target_seq", "original_seq"} {
			value := strings.TrimSpace(stringFromAny(payload[key]))
			if value != "" {
				seqParts = append(seqParts, value)
				break
			}
		}
	}
	sort.Strings(seqParts)
	if len(seqParts) > 0 {
		from := firstNonEmptyDelivery(getStr(payload, "from", ""), getStr(payload, "from_aid", ""), getStr(payload, "sender_aid", ""))
		to := firstNonEmptyDelivery(getStr(payload, "to", ""), getStr(payload, "to_aid", ""))
		return "p2p|from:" + from + "|to:" + to + "|seq:" + strings.Join(seqParts, ",")
	}
	tombstoneID := firstNonEmptyDelivery(getStr(payload, "tombstone_message_id", ""), getStr(payload, "message_id", ""))
	if tombstoneID != "" {
		return "p2p|tombstone:" + tombstoneID
	}
	return fmt.Sprintf("p2p|unknown:%p", payload)
}

func (d *messageDeliveryEngine) publishMessageRecallTombstone(seq int, message any) bool {
	c := d.runtime.client
	eventPayload, ok := recallEventFromMessage(message)
	if !ok {
		return false
	}
	dedupKey := messageRecallDedupKey(eventPayload)
	c.messageRecallSeenMu.Lock()
	if c.messageRecallSeen == nil {
		c.messageRecallSeen = make(map[string]int64)
	}
	if _, seen := c.messageRecallSeen[dedupKey]; seen {
		c.messageRecallSeenMu.Unlock()
		c.log.Debug("message.recalled dedup suppressed: seq=%d key=%s", seq, dedupKey)
		return false
	}
	c.messageRecallSeen[dedupKey] = time.Now().UnixMilli()
	if len(c.messageRecallSeen) > messageRecallSeenLimit {
		type kv struct {
			k string
			v int64
		}
		entries := make([]kv, 0, len(c.messageRecallSeen))
		for k, v := range c.messageRecallSeen {
			entries = append(entries, kv{k, v})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].v < entries[j].v })
		for i := 0; i < len(entries)-messageRecallSeenLimit; i++ {
			delete(c.messageRecallSeen, entries[i].k)
		}
	}
	c.messageRecallSeenMu.Unlock()
	c.publishAppEventSync("message.recalled", eventPayload)
	c.log.Debug("message.recalled published: seq=%d", seq)
	return true
}

// recallEventFromGroupMessage 把 pull / push 收到的群撤回 tombstone 归一化为
// group.message_recalled payload。占位 tombstone（原 seq）与通知 tombstone（新 seq）
// 都满足识别条件，统一归一化，由 publishGroupRecallTombstone 负责去重。
func recallEventFromGroupMessage(message any) (map[string]any, bool) {
	msg, ok := message.(map[string]any)
	if !ok {
		return nil, false
	}
	payloadMap := map[string]any{}
	if rawPayload, ok := msg["payload"].(map[string]any); ok {
		payloadMap = rawPayload
	}
	msgType := strings.TrimSpace(getStr(msg, "type", ""))
	if msgType == "" {
		msgType = strings.TrimSpace(getStr(msg, "kind", ""))
	}
	if msgType == "" {
		msgType = strings.TrimSpace(getStr(msg, "message_type", ""))
	}
	payloadType := strings.TrimSpace(getStr(payloadMap, "type", ""))
	if payloadType == "" {
		payloadType = strings.TrimSpace(getStr(payloadMap, "kind", ""))
	}
	if msgType != "group.message_recalled" && payloadType != "group.message_recalled" {
		return nil, false
	}
	event := make(map[string]any, len(payloadMap)+6)
	for k, v := range payloadMap {
		event[k] = v
	}
	for _, key := range appMessageEnvelopeKeys {
		if _, exists := event[key]; !exists {
			if value, ok := msg[key]; ok {
				event[key] = value
			}
		}
	}
	for _, key := range recallPayloadKeys {
		if _, exists := event[key]; !exists {
			if value, ok := msg[key]; ok {
				event[key] = value
			}
		}
	}
	messageIDs := []any{}
	if rawIDs, ok := event["message_ids"].([]any); ok {
		for _, item := range rawIDs {
			value := strings.TrimSpace(stringFromAny(item))
			if value != "" {
				messageIDs = append(messageIDs, value)
			}
		}
	}
	if len(messageIDs) == 0 {
		for _, key := range []string{"recalled_message_id", "target_message_id", "original_message_id"} {
			value := strings.TrimSpace(getStr(event, key, ""))
			if value != "" {
				messageIDs = append(messageIDs, value)
				break
			}
		}
	}
	event["type"] = "group.message_recalled"
	event["kind"] = "group.message_recalled"
	event["message_ids"] = messageIDs
	if _, ok := event["group_id"]; !ok {
		event["group_id"] = getStr(msg, "group_id", "")
	}
	if _, ok := event["timestamp"]; !ok {
		ts := msg["timestamp"]
		if ts == nil {
			ts = msg["t_server"]
		}
		if ts == nil {
			ts = event["recalled_at"]
		}
		if ts == nil {
			ts = int64(0)
		}
		event["timestamp"] = ts
	}
	if seq, exists := msg["seq"]; exists {
		event["seq"] = seq
	}
	if mid, exists := msg["message_id"]; exists {
		event["message_id"] = mid
		if _, ok := event["tombstone_message_id"]; !ok {
			event["tombstone_message_id"] = mid
		}
	}
	return event, true
}

// groupRecallDedupKey 群撤回去重键：group_id + 原始消息标识。
//
// 一条消息只能被撤回一次（服务端 group_message_recalls uk_recall_msg_id 唯一约束），
// (group_id, sorted message_ids) 已能唯一标识一次撤回；缺 message_ids 时按原消息 id/seq 兜底。
// 去重键不含 recalled_at：占位/通知 tombstone（pull）与在线 push 三条通道对同一次撤回
// 可能携带不同来源的时间戳（push 在事务后重取），纳入 recalled_at 会使去重失效、回调多次。
// 注意 Go map 无序，message_ids 拼接前必须 sort.Strings 保证键稳定。
func groupRecallDedupKey(groupID string, payload map[string]any) string {
	normalizedGroupID := NormalizeGroupID(strings.TrimSpace(groupID), "")
	idParts := []string{}
	if rawIDs, ok := payload["message_ids"].([]any); ok {
		for _, item := range rawIDs {
			v := strings.TrimSpace(stringFromAny(item))
			if v != "" {
				idParts = append(idParts, v)
			}
		}
	} else if v := strings.TrimSpace(stringFromAny(payload["message_ids"])); v != "" {
		idParts = append(idParts, v)
	}
	sort.Strings(idParts)
	if len(idParts) > 0 {
		return normalizedGroupID + "|id:" + strings.Join(idParts, ",")
	}
	for _, key := range []string{"recalled_message_id", "target_message_id", "original_message_id"} {
		value := strings.TrimSpace(getStr(payload, key, ""))
		if value != "" {
			return normalizedGroupID + "|id:" + value
		}
	}
	seqParts := []string{}
	if rawSeqs, ok := payload["target_message_seqs"].([]any); ok {
		for _, item := range rawSeqs {
			v := strings.TrimSpace(stringFromAny(item))
			if v != "" {
				seqParts = append(seqParts, v)
			}
		}
	} else {
		for _, key := range []string{"target_message_seqs", "original_seq"} {
			value := strings.TrimSpace(stringFromAny(payload[key]))
			if value != "" {
				seqParts = append(seqParts, value)
				break
			}
		}
	}
	sort.Strings(seqParts)
	if len(seqParts) > 0 {
		return normalizedGroupID + "|seq:" + strings.Join(seqParts, ",")
	}
	tombstoneID := firstNonEmptyDelivery(getStr(payload, "tombstone_message_id", ""), getStr(payload, "message_id", ""))
	if tombstoneID != "" {
		return normalizedGroupID + "|tombstone:" + tombstoneID
	}
	return fmt.Sprintf("%s|unknown:%p", normalizedGroupID, payload)
}

// publishGroupRecallTombstone 归一化并按去重键发布一次 group.message_recalled。
// 返回 true 表示本次实际发布；false 表示被去重抑制或不是撤回 tombstone。
func (d *messageDeliveryEngine) publishGroupRecallTombstone(groupID string, seq int, message any) bool {
	c := d.runtime.client
	eventPayload, ok := recallEventFromGroupMessage(message)
	if !ok {
		return false
	}
	rawGroupID := firstNonEmptyDelivery(getStr(eventPayload, "group_id", ""), groupID)
	dedupGroupID := NormalizeGroupID(strings.TrimSpace(rawGroupID), "")
	if dedupGroupID != "" {
		eventPayload["group_id"] = dedupGroupID
	}
	dedupKey := groupRecallDedupKey(dedupGroupID, eventPayload)
	c.groupRecallSeenMu.Lock()
	if c.groupRecallSeen == nil {
		c.groupRecallSeen = make(map[string]int64)
	}
	if _, seen := c.groupRecallSeen[dedupKey]; seen {
		c.groupRecallSeenMu.Unlock()
		c.logEG.Debug("group.message_recalled dedup suppressed: group=%s seq=%d key=%s", groupID, seq, dedupKey)
		return false
	}
	c.groupRecallSeen[dedupKey] = time.Now().UnixMilli()
	if len(c.groupRecallSeen) > groupRecallSeenLimit {
		type kv struct {
			k string
			v int64
		}
		entries := make([]kv, 0, len(c.groupRecallSeen))
		for k, v := range c.groupRecallSeen {
			entries = append(entries, kv{k, v})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].v < entries[j].v })
		for i := 0; i < len(entries)-groupRecallSeenLimit; i++ {
			delete(c.groupRecallSeen, entries[i].k)
		}
	}
	c.groupRecallSeenMu.Unlock()
	c.publishAppEventSync("group.message_recalled", eventPayload)
	c.logEG.Debug("group.message_recalled published: group=%s seq=%d", groupID, seq)
	return true
}

// onRawGroupMessageRecalled 处理 group.message_recalled 在线推送（与 pull 双 tombstone 兜底互补，去重）。
//
// 在线 push 是实时通道，与 pull 兜底的双 tombstone 互补。push 携带的 seq 是通知 tombstone 的
// notice_seq；必须像普通群消息 push 一样推进 seqTracker + markPushedSeq + auto-ack，否则该 seq
// 在本地 contiguous 序列留洞，后续 pull/reconnect 会重复拉到并重复处理。publishGroupRecallTombstone
// 内部再按 (group_id, message_ids) 去重，确保应用层只回调一次。
//
// 对齐 Python _apply_group_recall_push；Go 无 ns lock（单 goroutine 处理 + seqTracker 各方法自带
// mutex），且用 RepairContiguousSeq + persistRepairedSeq 取代 Python 的 repair_push_contiguous_bound +
// persist_seq，与同文件普通群消息 push 的 recall 分支保持一致。
func (c *AUNClient) onRawGroupMessageRecalled(data any) {
	dataMap, ok := data.(map[string]any)
	if !ok {
		return
	}
	groupID := getStr(dataMap, "group_id", "")
	wrapped := copyMapShallow(dataMap)
	if _, ok := wrapped["type"]; !ok {
		wrapped["type"] = "group.message_recalled"
	}
	if _, ok := wrapped["payload"]; !ok {
		wrapped["payload"] = map[string]any{
			"type":                "group.message_recalled",
			"message_ids":         dataMap["message_ids"],
			"target_message_seqs": dataMap["target_message_seqs"],
			"sender_aid":          dataMap["sender_aid"],
			"recalled_by":         dataMap["recalled_by"],
			"recalled_at":         dataMap["recalled_at"],
			"reason":              dataMap["reason"],
			"group_id":            groupID,
		}
	}
	seq := int(toInt64(dataMap["seq"]))
	// 无 group_id 或无 seq：无法推进序列，仅走去重发布兜底。
	if groupID == "" || seq <= 0 {
		c.delivery().publishGroupRecallTombstone(groupID, seq, wrapped)
		return
	}

	ns := "group:" + groupID
	c.seqTracker.UpdateMaxSeen(ns, seq)
	if c.seqTracker.GetContiguousSeq(ns) == seq {
		// 已被 pull 覆盖（pull 先到并推进过），仅走去重发布兜底，不重复推进 seq。
		c.delivery().publishGroupRecallTombstone(groupID, seq, wrapped)
		return
	}
	if c.seqTracker.GetContiguousSeq(ns) > seq {
		// contiguous 越界（脏数据）：倒退修复至 seq-1，与普通 push 路径一致。
		c.logEG.Warn("group recall push: contiguous_seq 越界（> push_seq=%d），脏数据修复倒退至 %d", seq, seq-1)
		c.seqTracker.RepairContiguousSeq(ns, seq-1)
		c.persistRepairedSeq(ns)
	}
	if c.isPushedSeq(ns, seq) || c.delivery().isPendingOrderedSeq(ns, seq) {
		// 该 notice_seq 已由 pull 路径处理过，去重发布兜底后返回。
		c.delivery().publishGroupRecallTombstone(groupID, seq, wrapped)
		return
	}
	c.seqTracker.OnMessageSeq(ns, seq)
	c.persistSeq(ns)
	c.delivery().publishGroupRecallTombstone(groupID, seq, wrapped)
	c.markPushedSeq(ns, seq)
	contig := c.seqTracker.GetContiguousSeq(ns)
	if contig > 0 {
		ackSeq := c.clampAckSeq("group.ack_messages", "msg_seq", ns, int64(contig))
		go func() {
			ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer ackCancel()
			if _, ackErr := c.transport.Call(ackCtx, "group.ack_messages", map[string]any{
				"group_id":        groupID,
				"msg_seq":         ackSeq,
				"device_id":       c.deviceID,
				"slot_id":         c.slotID,
				"_rpc_background": true,
			}); ackErr != nil {
				c.logEG.Warn("group recall push auto-ack failed: group=%s %v", groupID, ackErr)
			}
		}()
	}
}

func (d *messageDeliveryEngine) publishAppEvent(event string, payload any) {
	c := d.runtime.client
	if event == "message.received" || event == "group.message_created" {
		if msg, ok := payload.(map[string]any); ok {
			c.maybeAppendEchoTraceReceive(msg)
		}
	}
	if event == "message.received" || event == "message.undecryptable" ||
		event == "group.message_created" || event == "group.message_undecryptable" {
		c.logMessageDebug("publish", "direct", event, payload, nil)
	}
	c.injectAgentMDEtag(payload)
	c.events.Publish(event, c.normalizePublishedMessagePayload(event, payload))
}

func (d *messageDeliveryEngine) publishAppEventSync(event string, payload any) {
	c := d.runtime.client
	if event == "message.received" || event == "group.message_created" {
		if msg, ok := payload.(map[string]any); ok {
			c.maybeAppendEchoTraceReceive(msg)
		}
	}
	if event == "message.received" || event == "message.undecryptable" ||
		event == "group.message_created" || event == "group.message_undecryptable" {
		c.logMessageDebug("publish", "sync", event, payload, nil)
	}
	c.injectAgentMDEtag(payload)
	c.events.publishSync(event, c.normalizePublishedMessagePayload(event, payload))
}

func (d *messageDeliveryEngine) messageTargetsCurrentInstance(message any) bool {
	c := d.runtime.client
	msg, ok := message.(map[string]any)
	if !ok {
		return true
	}
	if _, exists := msg["device_id"]; exists {
		targetDeviceID := strings.TrimSpace(stringFromAny(msg["device_id"]))
		if targetDeviceID != c.deviceID {
			return false
		}
	}
	targetSlotID := strings.TrimSpace(stringFromAny(msg["slot_id"]))
	if targetSlotID != "" && c.slotID != "" && SlotIsolationKey(targetSlotID) != SlotIsolationKey(c.slotID) {
		return false
	}
	return true
}

// ── P2P 推送 ────────────────────────────────────────────────

func (d *messageDeliveryEngine) onRawMessageReceived(data any) {
	c := d.runtime.client
	tStart := time.Now()
	c.log.Debug("onRawMessageReceived enter")
	c.logMessageDebug("server-push", "_raw.message.received", "message.received", data, nil)
	defer func() {
		c.log.Debug("onRawMessageReceived exit: elapsed=%dms", time.Since(tStart).Milliseconds())
	}()
	go c.processAndPublishMessage(data)
}

func (c *AUNClient) onRawMessageRecalled(data any) {
	dataMap, ok := data.(map[string]any)
	if !ok {
		return
	}
	msg := copyMapShallow(dataMap)
	if _, ok := msg["type"]; !ok {
		msg["type"] = "message.recalled"
	}
	if !c.messageTargetsCurrentInstance(msg) {
		return
	}
	seq := int(toInt64(msg["seq"]))
	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	if seq <= 0 || myAID == "" {
		c.delivery().publishMessageRecallTombstone(seq, msg)
		return
	}
	ns := "p2p:" + myAID
	c.seqTracker.UpdateMaxSeen(ns, seq)
	contigBefore := c.seqTracker.GetContiguousSeq(ns)
	seqNeedsPull := c.seqTracker.OnMessageSeq(ns, seq)
	published := c.publishOrderedMessage("message.recalled", ns, seq, msg)
	contigAfter := c.seqTracker.GetContiguousSeq(ns)
	if seqNeedsPull && !published {
		go c.fillP2pGap()
	}
	contig := c.seqTracker.GetContiguousSeq(ns)
	if contig > 0 {
		ackSeq := c.clampAckSeq("message.v2.ack", "up_to_seq", ns, int64(contig))
		go func() {
			ackCtx, ackCancel := context.WithTimeout(contextWithRPCBackground(context.Background()), 5*time.Second)
			defer ackCancel()
			var ackErr error
			if c.v2GetState() != nil {
				_, ackErr = c.ackV2(ackCtx, ackSeq)
			} else {
				_, ackErr = c.transport.Call(ackCtx, "message.ack", map[string]any{
					"seq":             ackSeq,
					"device_id":       c.deviceID,
					"slot_id":         c.slotID,
					"_rpc_background": true,
				})
			}
			if ackErr != nil {
				c.log.Warn("P2P recall auto-ack failed: %v", ackErr)
			}
		}()
	}
	if contigAfter != contigBefore {
		c.persistSeq(ns)
	}
}

func (d *messageDeliveryEngine) processAndPublishMessage(data any) {
	c := d.runtime.client
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("processAndPublishMessage panic: %v", r)
		}
	}()

	dataMap, ok := data.(map[string]any)
	if !ok {
		c.publishAppEvent("message.received", data)
		return
	}

	msg := copyMapShallow(dataMap)
	if !c.messageTargetsCurrentInstance(msg) {
		c.log.Debug("P2P push filtered by instance: message_id=%s seq=%d target_device=%s target_slot=%s local_device=%s local_slot=%s",
			stringFromAny(msg["message_id"]), int(toInt64(msg["seq"])), stringFromAny(msg["device_id"]), stringFromAny(msg["slot_id"]), c.deviceID, c.slotID)
		return
	}

	// P2P 空洞检测
	seq := int(toInt64(msg["seq"]))
	fromAID, _ := msg["from"].(string)
	c.log.Debug("P2P message push: from=%s seq=%d", fromAID, seq)
	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	p2pNS := ""
	if seq > 0 && myAID != "" {
		p2pNS = "p2p:" + myAID
		c.seqTracker.UpdateMaxSeen(p2pNS, seq)
		needPull := c.seqTracker.OnMessageSeq(p2pNS, seq)
		if needPull {
			c.log.Debug("P2P seq gap detected, triggering gap fill: seq=%d", seq)
			go c.fillP2pGap()
		}
		// auto-ack contiguous_seq
		contig := c.seqTracker.GetContiguousSeq(p2pNS)
		if contig > 0 {
			ackSeq := c.clampAckSeq("message.v2.ack", "up_to_seq", p2pNS, int64(contig))
			c.log.Debug("P2P push auto-ack send: ns=%s seq=%d contiguous=%d", p2pNS, ackSeq, contig)
			go func() {
				ackCtx, ackCancel := context.WithTimeout(contextWithRPCBackground(context.Background()), 5*time.Second)
				defer ackCancel()
				var ackErr error
				if c.v2GetState() != nil {
					_, ackErr = c.ackV2(ackCtx, ackSeq)
				} else {
					_, ackErr = c.transport.Call(ackCtx, "message.ack", map[string]any{
						"seq":             ackSeq,
						"device_id":       c.deviceID,
						"slot_id":         c.slotID,
						"_rpc_background": true,
					})
				}
				if ackErr != nil {
					c.log.Warn("P2P auto-ack failed: %v", ackErr)
					return
				}
				c.log.Debug("P2P push auto-ack ok: ns=%s seq=%d", p2pNS, ackSeq)
			}()
		}
		c.persistSeq(p2pNS)
	}

	if isEncryptedPushMessage(msg) {
		c.log.Debug("encrypted P2P push attempting inline decrypt: from=%s seq=%d", fromAID, seq)
		c.publishEncryptedPushMessage("message.received", "message.undecryptable", p2pNS, seq, msg, false)
		return
	}

	// V2-only: V2 P2P 消息通过 V2 push 路径解密；明文/兼容消息在此处透传
	decrypted := msg
	if seq > 0 && myAID != "" {
		c.publishOrderedMessage("message.received", "p2p:"+myAID, seq, decrypted)
	} else {
		c.publishAppEvent("message.received", decrypted)
	}
}

// ── 群推送 ──────────────────────────────────────────────────

func (d *messageDeliveryEngine) onRawGroupMessageCreated(data any) {
	c := d.runtime.client
	tStart := time.Now()
	c.logEG.Debug("onRawGroupMessageCreated enter")
	c.logMessageDebug("server-push", "_raw.group.message_created", "group.message_created", data, nil)
	defer func() {
		c.logEG.Debug("onRawGroupMessageCreated exit: elapsed=%dms", time.Since(tStart).Milliseconds())
	}()
	go c.processAndPublishGroupMessage(data)
}

func (d *messageDeliveryEngine) processAndPublishGroupMessage(data any) {
	c := d.runtime.client
	defer func() {
		if r := recover(); r != nil {
			c.logEG.Error("processAndPublishGroupMessage panic: %v", r)
		}
	}()

	dataMap, ok := data.(map[string]any)
	if !ok {
		c.publishAppEvent("group.message_created", data)
		return
	}

	msg := copyMapShallow(dataMap)
	groupID, _ := msg["group_id"].(string)
	seq := int(toInt64(msg["seq"]))
	fromAID, _ := msg["from"].(string)
	c.logEG.Debug("group message push: group=%s from=%s seq=%d", groupID, fromAID, seq)

	if groupID != "" {
		c.groupSyncedMu.Lock()
		c.groupSynced[groupID] = true
		c.groupSyncedMu.Unlock()
	}

	// 检查是否带 payload
	payload := msg["payload"]
	hasPayload := false
	if payload != nil {
		if pm, ok := payload.(map[string]any); ok && len(pm) > 0 {
			hasPayload = true
		} else if _, ok := payload.(string); ok {
			hasPayload = true
		}
	}

	if !hasPayload {
		// 不带 payload 的通知不能先推进 seq，否则 auto-pull 会用推进后的 cursor 跳过该消息。
		if groupID != "" && seq > 0 {
			ns := "group:" + groupID
			c.seqTracker.UpdateMaxSeen(ns, seq)
			contigBefore := c.seqTracker.GetContiguousSeq(ns)
			if contigBefore == seq {
				c.logEG.Debug("group message notification: push seq=%d already covered by contiguous_seq=%d, ignore duplicate push",
					seq, contigBefore)
				return
			}
			if contigBefore > seq {
				c.logEG.Warn("group message notification: contiguous_seq=%d 越界（> push_seq=%d），脏数据修复倒退至 %d",
					contigBefore, seq, seq-1)
				c.seqTracker.RepairContiguousSeq(ns, seq-1)
				c.persistRepairedSeq(ns)
			}
		}
		c.autoPullGroupMessages(msg)
		return
	}

	encryptedPush := isEncryptedPushMessage(msg)

	// 群撤回 tombstone（占位 / 通知）：归一化为 group.message_recalled，仍占 seq 推进 contiguous/ack。
	if !encryptedPush {
		if _, isRecall := recallEventFromGroupMessage(msg); isRecall {
			if groupID != "" && seq > 0 {
				ns := "group:" + groupID
				c.seqTracker.UpdateMaxSeen(ns, seq)
				contigBefore := c.seqTracker.GetContiguousSeq(ns)
				if contigBefore == seq {
					c.logEG.Debug("group recall tombstone: push seq=%d already covered, ignore duplicate", seq)
					return
				}
				c.seqTracker.OnMessageSeq(ns, seq)
				c.delivery().publishGroupRecallTombstone(groupID, seq, msg)
				c.markPushedSeq(ns, seq)
				contig := c.seqTracker.GetContiguousSeq(ns)
				if contig > 0 {
					ackSeq := c.clampAckSeq("group.ack_messages", "msg_seq", ns, int64(contig))
					go func() {
						ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer ackCancel()
						if _, ackErr := c.transport.Call(ackCtx, "group.ack_messages", map[string]any{
							"group_id":        groupID,
							"msg_seq":         ackSeq,
							"device_id":       c.deviceID,
							"slot_id":         c.slotID,
							"_rpc_background": true,
						}); ackErr != nil {
							c.logEG.Warn("group recall auto-ack failed: group=%s %v", groupID, ackErr)
						}
					}()
				}
				c.persistSeq(ns)
			} else {
				c.delivery().publishGroupRecallTombstone(groupID, seq, msg)
			}
			return
		}
	}

	// V2-only: V2 群组消息通过 V2 push 路径解密；明文/兼容消息在此处透传
	decrypted := msg

	if decrypted != nil && groupID != "" && seq > 0 {
		ns := "group:" + groupID
		c.seqTracker.UpdateMaxSeen(ns, seq)
		contigBefore := c.seqTracker.GetContiguousSeq(ns)
		if contigBefore == seq {
			c.logEG.Debug("group message payload push: seq=%d already covered by contiguous_seq=%d, ignore duplicate push",
				seq, contigBefore)
			return
		}
		needPull := c.seqTracker.OnMessageSeq(ns, seq)
		if needPull {
			c.logEG.Debug("group message seq gap detected, triggering gap fill: group=%s seq=%d", groupID, seq)
			go c.fillGroupGap(groupID)
		}
		contig := c.seqTracker.GetContiguousSeq(ns)
		if contig > 0 {
			ackSeq := c.clampAckSeq("group.ack_messages", "msg_seq", ns, int64(contig))
			c.logEG.Debug("group push auto-ack send: group=%s ns=%s seq=%d contiguous=%d", groupID, ns, ackSeq, contig)
			go func() {
				ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer ackCancel()
				if _, ackErr := c.transport.Call(ackCtx, "group.ack_messages", map[string]any{
					"group_id":        groupID,
					"msg_seq":         ackSeq,
					"device_id":       c.deviceID,
					"slot_id":         c.slotID,
					"_rpc_background": true,
				}); ackErr != nil {
					c.logEG.Warn("group message auto-ack failed: group=%s %v", groupID, ackErr)
				} else {
					c.logEG.Debug("group push auto-ack ok: group=%s ns=%s seq=%d", groupID, ns, ackSeq)
				}
			}()
		}
		c.persistSeq(ns)
	}

	if encryptedPush {
		c.logEG.Debug("encrypted group push attempting inline decrypt: group=%s seq=%d", groupID, seq)
		ns := ""
		if groupID != "" && seq > 0 {
			ns = "group:" + groupID
		}
		c.publishEncryptedPushMessage("group.message_created", "group.message_undecryptable", ns, seq, msg, true)
		return
	}

	// V2-only: 不再有 pending decrypt 队列，decrypted 始终非 nil
	if groupID != "" && seq > 0 {
		c.publishOrderedMessage("group.message_created", "group:"+groupID, seq, decrypted)
	} else {
		c.publishAppEvent("group.message_created", decrypted)
	}
}

// autoPullGroupMessages 收到不带 payload 的通知后自动 pull 最新消息
func (d *messageDeliveryEngine) autoPullGroupMessages(notification map[string]any) {
	c := d.runtime.client
	groupID, _ := notification["group_id"].(string)
	if groupID == "" {
		c.publishAppEvent("group.message_created", notification)
		return
	}
	ns := "group:" + groupID
	afterSeq := c.seqTracker.GetContiguousSeq(ns)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// V2-only 模式：走 group.v2.pull（合并 V1 明文 + V2 密文并自动解密）
	v2State := c.v2GetState()
	if v2State != nil && v2State.session != nil {
		_, err := c.pullGroupV2Internal(ctx, map[string]any{
			"group_id":        groupID,
			"after_seq":       afterSeq,
			"limit":           50,
			"_rpc_background": true,
		})
		if err != nil {
			c.logEG.Warn("auto pull group messages (v2) failed: %v", err)
			c.publishAppEvent("group.message_created", notification)
		}
		return
	}

	result, err := c.Call(ctx, "group.pull", map[string]any{
		"group_id":        groupID,
		"after_seq":       afterSeq,
		"limit":           50,
		"_rpc_background": true,
	})
	if err != nil {
		c.logEG.Warn("auto pull group messages failed: %v", err)
		c.publishAppEvent("group.message_created", notification)
		return
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		c.publishAppEvent("group.message_created", notification)
		return
	}
	messages, ok := resultMap["messages"].([]any)
	if !ok || len(messages) == 0 {
		c.publishAppEvent("group.message_created", notification)
		return
	}
	// 更新 SeqTracker
	var pullMsgs []map[string]any
	for _, raw := range messages {
		if m, ok := raw.(map[string]any); ok {
			pullMsgs = append(pullMsgs, m)
		}
	}
	c.seqTracker.OnPullResult(ns, pullMsgs, afterSeq)
	// pushedSeqs 去重：使用 publishGapFillGroupMessages 安全发布，避免锁外读取竞态
	c.publishGapFillGroupMessages(ns, messages)
}

// ── P2P / 群补洞 ────────────────────────────────────────────

// fillGroupGap 后台补齐群消息空洞
func (d *messageDeliveryEngine) fillGroupGap(groupID string) {
	c := d.runtime.client
	groupID = NormalizeGroupID(strings.TrimSpace(groupID), "")
	if groupID == "" {
		return
	}
	ns := "group:" + groupID
	afterSeq := c.seqTracker.GetContiguousSeq(ns)
	c.logEG.Debug("fillGroupGap triggered: group=%s afterSeq=%d", groupID, afterSeq)
	// per-namespace 去重：同一 group namespace 只允许 1 个 in-flight pull
	dedupKey := "group_pull:" + ns
	c.gapFillDoneMu.Lock()
	if c.gapFillDone[dedupKey] {
		c.gapFillDoneMu.Unlock()
		return
	}
	c.gapFillDone[dedupKey] = true
	c.gapFillDoneMu.Unlock()
	// S1: 使用 defer 在所有出口（成功/异常/空返）清理 dedup 键，避免"成功但返回 0 条"永久污染。
	defer func() {
		c.gapFillDoneMu.Lock()
		delete(c.gapFillDone, dedupKey)
		c.gapFillDoneMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := c.Call(ctx, "group.pull", map[string]any{
		"group_id":        groupID,
		"after_seq":       afterSeq,
		"limit":           50,
		"_rpc_background": true,
	})
	if err != nil {
		c.logEG.Warn("background gap fill failed (fillGroupGap group=%s): %v", groupID, err)
		return
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		return
	}
	messages, ok := resultMap["messages"].([]any)
	if !ok {
		return
	}
	// seq_tracker 更新已在 Call() 拦截器中完成；auto-ack 在 publish 后执行
	nsKey := "group:" + groupID
	contigBefore := afterSeq
	if rawBefore, ok := resultMap["_contig_before"]; ok {
		contigBefore = int(toInt64(rawBefore))
	}
	c.logEG.Debug("fillGroupGap completed: group=%s recovered %d messages", groupID, len(messages))
	c.publishGapFillGroupMessages(nsKey, messages)
	// publish 完成后 auto-ack
	contig := c.seqTracker.GetContiguousSeq(nsKey)
	if contig > 0 && contig != contigBefore {
		ackSeq := c.clampAckSeq("group.ack_messages", "msg_seq", nsKey, int64(contig))
		go func() {
			ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer ackCancel()
			if _, ackErr := c.transport.Call(ackCtx, "group.ack_messages", map[string]any{
				"group_id":        groupID,
				"msg_seq":         ackSeq,
				"device_id":       c.deviceID,
				"slot_id":         c.slotID,
				"_rpc_background": true,
			}); ackErr != nil {
				c.logEG.Warn("fillGroupGap auto-ack failed: group=%s %v", groupID, ackErr)
			}
		}()
	}
}

// lazySyncGroup 惰性同步：首次激活群时 pull 最近消息，建立 seq 基线。
func (d *messageDeliveryEngine) lazySyncGroup(groupID string) {
	c := d.runtime.client
	c.logEG.Debug("lazySyncGroup entry: group=%s", groupID)
	c.groupSyncedMu.Lock()
	c.groupSynced[groupID] = true
	c.groupSyncedMu.Unlock()

	ns := "group:" + groupID
	afterSeq := c.seqTracker.GetContiguousSeq(ns)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := c.transport.Call(ctx, "group.pull", map[string]any{
		"group_id":          groupID,
		"after_message_seq": afterSeq,
		"limit":             200,
	})
	if err != nil {
		c.logEG.Warn("lazy sync group %s failed: %v", groupID, err)
		return
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		return
	}
	messages, ok := resultMap["messages"].([]any)
	if !ok {
		return
	}
	for _, raw := range messages {
		if msg, ok := raw.(map[string]any); ok {
			s := int(toInt64(msg["seq"]))
			if s > 0 {
				c.seqTracker.UpdateMaxSeen(ns, s)
				c.seqTracker.OnMessageSeq(ns, s)
			}
		}
	}
	if len(messages) > 0 {
		c.persistSeq(ns)
		c.logEG.Warn("lazy sync group %s: pulled %d messages, after_seq=%d", groupID, len(messages), afterSeq)
	}
}

// fillGroupEventGap 后台补齐群事件空洞
func (d *messageDeliveryEngine) fillGroupEventGap(groupID string) {
	c := d.runtime.client
	ns := "group_event:" + groupID
	afterSeq := c.seqTracker.GetContiguousSeq(ns)
	c.logEG.Debug("fillGroupEventGap triggered: group=%s afterSeq=%d", groupID, afterSeq)
	// per-namespace 去重：同一 group_event namespace 只允许 1 个 in-flight pull
	dedupKey := "group_event_pull:" + ns
	c.gapFillDoneMu.Lock()
	if c.gapFillDone[dedupKey] {
		c.gapFillDoneMu.Unlock()
		return
	}
	c.gapFillDone[dedupKey] = true
	c.gapFillDoneMu.Unlock()
	// S1: defer 清理 dedup 键
	defer func() {
		c.gapFillDoneMu.Lock()
		delete(c.gapFillDone, dedupKey)
		c.gapFillDoneMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nextAfterSeq := afterSeq
	const maxPages = 100
	pageCount := 0
	totalEvents := 0
	for pageCount < maxPages {
		pageCount++
		result, err := c.Call(ctx, "group.pull_events", map[string]any{
			"group_id":        groupID,
			"after_event_seq": nextAfterSeq,
			"device_id":       c.deviceID,
			"limit":           50,
			"_rpc_background": true,
		})
		if err != nil {
			c.logEG.Warn("background gap fill failed (fillGroupEventGap group=%s): %v", groupID, err)
			return
		}
		resultMap, ok := result.(map[string]any)
		if !ok {
			return
		}
		events, ok := resultMap["events"].([]any)
		if !ok {
			return
		}
		var pullEvts []map[string]any
		maxEventSeq := nextAfterSeq
		for _, raw := range events {
			if e, ok := raw.(map[string]any); ok {
				pullEvts = append(pullEvts, e)
				if es := int(toInt64(e["event_seq"])); es > maxEventSeq {
					maxEventSeq = es
				}
			}
		}
		pageContigBefore := c.seqTracker.GetContiguousSeq(ns)
		if len(pullEvts) > 0 {
			c.seqTracker.OnPullResult(ns, pullEvts, nextAfterSeq)
		}
		serverAck := 0
		if cursor, ok := resultMap["cursor"].(map[string]any); ok {
			serverAck = int(toInt64(cursor["current_seq"]))
			if serverAck > 0 {
				contigBeforeFloor := c.seqTracker.GetContiguousSeq(ns)
				if contigBeforeFloor < serverAck {
					c.logEG.Info("group.pull_events retention-floor advanced: ns=%s contiguous=%d -> cursor.current_seq=%d", ns, contigBeforeFloor, serverAck)
					c.seqTracker.ForceContiguousSeq(ns, serverAck)
				}
			}
		}
		hasDissolvedEvent := false
		for _, evt := range pullEvts {
			evt["_from_gap_fill"] = true
			if action, _ := evt["action"].(string); action == "dissolved" {
				hasDissolvedEvent = true
			}
			et, _ := evt["event_type"].(string)
			// 消息事件由 fillGroupGap 负责，事件补洞不重复投递
			if et == "group.message_created" {
				continue
			}
			// 验签：有 client_signature 就验（与实时事件路径对齐）
			if cs, ok := evt["client_signature"].(map[string]any); ok {
				if c.shouldSkipEventSignature(evt) {
					delete(evt, "client_signature")
				} else {
					evt["_verified"] = c.verifyEventSignature(cs)
				}
			}
			eventSeq := int(toInt64(evt["event_seq"]))
			if eventSeq > 0 && !c.isPushedSeq(ns, eventSeq) {
				c.enqueueOrderedMessage(ns, "group.changed", eventSeq, evt)
			}
		}
		ackContig := c.seqTracker.GetContiguousSeq(ns)
		d.drainOrderedMessages(ns)
		if ackContig != pageContigBefore && !hasDissolvedEvent {
			c.persistSeq(ns)
		}
		if len(pullEvts) > 0 && ackContig > 0 && ackContig != pageContigBefore {
			ackSeq := c.clampAckSeq("group.ack_events", "event_seq", ns, int64(ackContig))
			go func() {
				ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer ackCancel()
				if _, ackErr := c.transport.Call(ackCtx, "group.ack_events", map[string]any{
					"group_id":        groupID,
					"event_seq":       ackSeq,
					"device_id":       c.deviceID,
					"slot_id":         c.slotID,
					"_rpc_background": true,
				}); ackErr != nil {
					c.logEG.Warn("group event auto-ack failed: group=%s %v", groupID, ackErr)
				}
			}()
		}
		totalEvents += len(events)
		hasMore, _ := resultMap["has_more"].(bool)
		if len(pullEvts) == 0 || maxEventSeq <= nextAfterSeq || !hasMore {
			break
		}
		nextAfterSeq = maxEventSeq
	}
	if pageCount >= maxPages {
		c.logEG.Warn("fillGroupEventGap reached max_pages=%d group=%s afterSeq=%d", maxPages, groupID, nextAfterSeq)
	}
	c.logEG.Debug("fillGroupEventGap completed: group=%s recovered %d events", groupID, totalEvents)
}

func (d *messageDeliveryEngine) handleGroupChangedEventSeq(data map[string]any, groupID string) {
	c := d.runtime.client
	needPull := false
	es := int(toInt64(data["event_seq"]))
	if groupID == "" || es <= 0 {
		d.publishOrderedGroupChanged(data)
		return
	}

	ns := "group_event:" + groupID
	if d.isSelfJoinGroupChanged(data) {
		contig := c.seqTracker.GetContiguousSeq(ns)
		maxSeen := c.seqTracker.GetMaxSeenSeq(ns)
		if contig == 0 && maxSeen == 0 && es > 1 {
			c.logEG.Debug("group.changed self-join baseline: group=%s event_seq=%d baseline=%d", groupID, es, es-1)
			c.seqTracker.ForceContiguousSeq(ns, es-1)
		}
	}
	contigBefore := c.seqTracker.GetContiguousSeq(ns)
	if es <= contigBefore || c.isPushedSeq(ns, es) {
		c.logEG.Debug("group.changed skipped duplicate/stale: group=%s event_seq=%d contiguous=%d", groupID, es, contigBefore)
		d.ackCoveredGroupEvent(groupID, ns, es)
		return
	}

	c.enqueueOrderedMessage(ns, "group.changed", es, data)
	needPull = c.seqTracker.OnMessageSeq(ns, es)
	ackContig := c.seqTracker.GetContiguousSeq(ns)
	d.drainOrderedMessages(ns)
	if ackContig > 0 && ackContig != contigBefore {
		if data["action"] != "dissolved" {
			c.persistSeq(ns)
		}
		if c.transport != nil {
			ackSeq := c.clampAckSeq("group.ack_events", "event_seq", ns, int64(ackContig))
			go func() {
				ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer ackCancel()
				if _, ackErr := c.transport.Call(ackCtx, "group.ack_events", map[string]any{
					"group_id":        groupID,
					"event_seq":       ackSeq,
					"device_id":       c.deviceID,
					"slot_id":         c.slotID,
					"_rpc_background": true,
				}); ackErr != nil {
					c.logEG.Warn("group event push auto-ack failed: group=%s %v", groupID, ackErr)
				}
			}()
		}
	}

	if needPull && groupID != "" && data["_from_gap_fill"] == nil {
		c.logEG.Debug("group.changed event_seq gap detected, triggering gap fill: group=%s", groupID)
		go d.fillGroupEventGap(groupID)
	}
}

func (d *messageDeliveryEngine) ackCoveredGroupEvent(groupID, ns string, eventSeq int) {
	c := d.runtime.client
	if c.transport == nil || groupID == "" || eventSeq <= 0 {
		return
	}
	ackSeq := c.clampAckSeq("group.ack_events", "event_seq", ns, int64(eventSeq))
	if ackSeq <= 0 {
		return
	}
	go func() {
		ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer ackCancel()
		if _, ackErr := c.transport.Call(ackCtx, "group.ack_events", map[string]any{
			"group_id":        groupID,
			"event_seq":       ackSeq,
			"device_id":       c.deviceID,
			"slot_id":         c.slotID,
			"_rpc_background": true,
		}); ackErr != nil {
			c.logEG.Warn("group event covered push auto-ack failed: group=%s %v", groupID, ackErr)
		}
	}()
}

func (d *messageDeliveryEngine) isSelfJoinGroupChanged(data map[string]any) bool {
	action := strings.TrimSpace(stringFromAny(data["action"]))
	switch action {
	case "member_added", "joined", "join_approved", "invite_code_used":
	default:
		return false
	}
	c := d.runtime.client
	c.mu.RLock()
	selfAID := strings.TrimSpace(c.aid)
	c.mu.RUnlock()
	if selfAID == "" {
		return false
	}
	joinedAID := strings.TrimSpace(stringFromAny(data["joined_aid"]))
	if joinedAID == "" {
		joinedAID = strings.TrimSpace(stringFromAny(data["member_aid"]))
	}
	if joinedAID == "" {
		joinedAID = strings.TrimSpace(stringFromAny(data["aid"]))
	}
	if joinedAID == selfAID {
		return true
	}
	actorAID := strings.TrimSpace(stringFromAny(data["actor_aid"]))
	return joinedAID == "" && (action == "joined" || action == "invite_code_used") && actorAID == selfAID
}

func (d *messageDeliveryEngine) onV2PushNotification(data any) {
	c := d.runtime.client
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return
	}

	var pushSeq int64
	var pushFrom, pushMsgID, envelopeJSON string
	dataMap, _ := data.(map[string]any)
	if dataMap != nil {
		pushSeq = toInt64(dataMap["seq"])
		pushFrom = strings.TrimSpace(v2AsString(dataMap["from_aid"]))
		pushMsgID = strings.TrimSpace(v2AsString(dataMap["message_id"]))
		envelopeJSON = v2AsString(dataMap["envelope_json"])
	}

	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	ns := "p2p:" + myAID
	contigBefore := c.seqTracker.GetContiguousSeq(ns)

	c.logE2.Debug("onV2PushNotification executing: push_seq=%d push_from=%s push_msg_id=%s has_payload=%t contiguous_seq=%d",
		pushSeq, pushFrom, pushMsgID, envelopeJSON != "", contigBefore)

	if pushSeq > 0 {
		c.seqTracker.UpdateMaxSeen(ns, int(pushSeq))
		if contigBefore == int(pushSeq) {
			c.logE2.Debug("onV2PushNotification: push seq=%d already covered by contiguous_seq=%d, ignore duplicate push",
				pushSeq, contigBefore)
			return
		}
		if contigBefore > int(pushSeq) {
			c.logE2.Warn("onV2PushNotification: contiguous_seq=%d 越界（> push_seq=%d），脏数据修复倒退至 %d",
				contigBefore, pushSeq, pushSeq-1)
			c.seqTracker.RepairContiguousSeq(ns, int(pushSeq-1))
			c.persistRepairedSeq(ns)
			contigBefore = int(pushSeq - 1)
		}
	}

	if envelopeJSON != "" && pushSeq > 0 && ns != "" && dataMap != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		decrypted := c.decryptV2Message(ctx, state, dataMap)
		cancel()
		if decrypted != nil {
			needPull := c.seqTracker.OnMessageSeq(ns, int(pushSeq))
			published := c.publishOrderedMessage("message.received", ns, int(pushSeq), decrypted)
			newContig := c.seqTracker.GetContiguousSeq(ns)
			if newContig != contigBefore {
				c.persistSeq(ns)
			}
			if newContig > 0 && newContig != contigBefore {
				ackSeq := c.clampAckSeq("message.v2.ack", "up_to_seq", ns, int64(newContig))
				ackParams := map[string]any{"up_to_seq": ackSeq}
				go func() {
					ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer ackCancel()
					c.signClientOperation("message.v2.ack", ackParams)
					ackParams["_rpc_background"] = true
					if _, ackErr := c.transport.Call(ackCtx, "message.v2.ack", ackParams); ackErr != nil {
						c.logE2.Debug("V2 P2P push-ack failed: %v", ackErr)
					}
				}()
			}
			c.logE2.Debug("onV2PushNotification: push 带 payload 解密成功, contiguous_seq=%d->%d push_seq=%d",
				contigBefore, newContig, pushSeq)
			if !needPull && (published || newContig >= int(pushSeq) || int(pushSeq) <= contigBefore) {
				return
			}
			c.logE2.Debug("onV2PushNotification: payload push seq=%d 因空洞挂起，继续 pull 补齐 after_seq=%d",
				pushSeq, newContig)
		}
	}

	if pushSeq > 0 {
		c.logE2.Debug("onV2PushNotification: 纯通知 push_seq=%d > contiguous_seq=%d, 触发 pull(after_seq=%d)",
			pushSeq, contigBefore, contigBefore)
	}

	if !c.v2PushPullInflight.CompareAndSwap(false, true) {
		c.v2PushPullPending.Store(true)
		return
	}
	dedupKey := "p2p_pull:" + ns

	c.gapFillDoneMu.Lock()
	c.gapFillDone[dedupKey] = true
	c.gapFillDoneMu.Unlock()
	go func() {
		defer c.v2PushPullInflight.Store(false)
		defer func() {
			c.gapFillDoneMu.Lock()
			delete(c.gapFillDone, dedupKey)
			c.gapFillDoneMu.Unlock()
		}()
		defer func() {
			if r := recover(); r != nil {
				c.logE2.Warn("V2 push auto-pull panic: %v", r)
			}
		}()
		for {
			c.v2PushPullPending.Store(false)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, err := c.pullV2Internal(ctx, map[string]any{"_rpc_background": true})
			cancel()
			newContig := c.seqTracker.GetContiguousSeq(ns)
			if err != nil {
				c.logE2.Warn("V2 push auto-pull failed: contiguous_seq=%d->%d err=%v", contigBefore, newContig, err)
				return
			}
			c.logE2.Debug("onV2PushNotification pull done: contiguous_seq=%d->%d (push_seq=%d)", contigBefore, newContig, pushSeq)
			contigBefore = newContig
			if !c.v2PushPullPending.Load() {
				break
			}
		}
	}()
}

func (d *messageDeliveryEngine) onV2GroupPushNotification(data any) {
	c := d.runtime.client
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return
	}
	dataMap, ok := data.(map[string]any)
	if !ok {
		return
	}
	groupID := strings.TrimSpace(v2AsString(dataMap["group_id"]))
	if groupID == "" {
		return
	}
	seq := int(toInt64(dataMap["seq"]))
	if seq <= 0 {
		return
	}
	eventKind := strings.TrimSpace(v2AsString(dataMap["kind"]))
	if _, drained := dataMap["_online_hint_drained"]; eventKind == "group.online_unread_hint" && !drained {
		if !d.backgroundSyncEnabled() {
			c.logEG.Debug("onV2GroupPushNotification skipped online unread hint: group=%s background_sync=false", groupID)
			return
		}
		d.enqueueOnlineUnreadHint(dataMap)
		return
	}
	ns := "group:" + groupID
	c.seqTracker.UpdateMaxSeen(ns, seq)
	contigBefore := c.seqTracker.GetContiguousSeq(ns)
	if contigBefore == seq || (eventKind == "group.online_unread_hint" && contigBefore > seq) {
		c.logEG.Debug("onV2GroupPushNotification: push seq=%d already covered by contiguous_seq=%d, ignore duplicate push",
			seq, contigBefore)
		d.ackCoveredGroupV2(groupID, ns, seq)
		return
	}
	if contigBefore > seq {
		c.logEG.Warn("onV2GroupPushNotification: contiguous_seq=%d 越界（> push_seq=%d），脏数据修复倒退至 %d",
			contigBefore, seq, seq-1)
		c.seqTracker.RepairContiguousSeq(ns, seq-1)
		c.persistRepairedSeq(ns)
		contigBefore = seq - 1
	}
	if c.isPushedSeq(ns, seq) {
		return
	}
	afterSeq := contigBefore
	dedupKey := "group_pull:" + ns
	c.gapFillDoneMu.Lock()
	if c.gapFillDone[dedupKey] {
		c.gapFillDoneMu.Unlock()
		return
	}
	c.gapFillDone[dedupKey] = true
	c.gapFillDoneMu.Unlock()
	pull := func() {
		defer func() {
			c.gapFillDoneMu.Lock()
			delete(c.gapFillDone, dedupKey)
			c.gapFillDoneMu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := c.pullGroupV2Internal(ctx, map[string]any{
			"group_id":        groupID,
			"after_seq":       afterSeq,
			"limit":           50,
			"_rpc_background": true,
		})
		if err != nil {
			c.logEG.Warn("V2 group push auto-pull failed: group=%s err=%v", groupID, err)
		}
	}
	if _, drained := dataMap["_online_hint_drained"]; drained {
		pull()
	} else {
		go pull()
	}
}

func (d *messageDeliveryEngine) ackCoveredGroupV2(groupID, ns string, seq int) {
	c := d.runtime.client
	if c.transport == nil || groupID == "" || seq <= 0 {
		return
	}
	ackSeq := c.clampAckSeq("group.v2.ack", "up_to_seq", ns, int64(seq))
	if ackSeq <= 0 {
		return
	}
	ackParams := map[string]any{
		"group_id":  groupID,
		"up_to_seq": ackSeq,
	}
	go func() {
		ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer ackCancel()
		if err := c.signClientOperation("group.v2.ack", ackParams); err != nil {
			c.logEG.Debug("V2 group covered push ack sign failed: group=%s %v", groupID, err)
			return
		}
		ackParams["_rpc_background"] = true
		if _, ackErr := c.transport.Call(ackCtx, "group.v2.ack", ackParams); ackErr != nil {
			c.logEG.Debug("V2 group covered push auto-ack failed: group=%s %v", groupID, ackErr)
		}
	}()
}

func (d *messageDeliveryEngine) backgroundSyncEnabled() bool {
	c := d.runtime.client
	if c.sessionOptions == nil {
		return true
	}
	if enabled, ok := c.sessionOptions["background_sync"].(bool); ok {
		return enabled
	}
	return true
}

func (d *messageDeliveryEngine) enqueueOnlineUnreadHint(data map[string]any) {
	c := d.runtime.client
	groupID := strings.TrimSpace(v2AsString(data["group_id"]))
	if groupID == "" {
		return
	}
	c.onlineUnreadHintMu.Lock()
	queue := d.runtime.delivery.onlineUnreadHintQueueLocked()
	queue[groupID] = copyMapShallow(data)
	if c.onlineUnreadHintDraining {
		c.onlineUnreadHintMu.Unlock()
		return
	}
	d.runtime.delivery.setOnlineUnreadHintDrainingLocked(true)
	c.onlineUnreadHintMu.Unlock()
	go d.drainOnlineUnreadHints()
}

func (d *messageDeliveryEngine) drainOnlineUnreadHints() {
	c := d.runtime.client
	delay := c.onlineUnreadHintInitialDelay
	if delay < 0 {
		delay = 0
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	defer func() {
		c.onlineUnreadHintMu.Lock()
		d.runtime.delivery.setOnlineUnreadHintDrainingLocked(false)
		c.onlineUnreadHintMu.Unlock()
	}()
	for {
		c.mu.RLock()
		ready := clientStateIsReady(c.state)
		c.mu.RUnlock()
		if !ready || !d.backgroundSyncEnabled() {
			return
		}

		c.onlineUnreadHintMu.Lock()
		if len(c.onlineUnreadHintQueue) == 0 {
			c.onlineUnreadHintMu.Unlock()
			return
		}
		var groupID string
		var payload map[string]any
		for gid, queued := range c.onlineUnreadHintQueue {
			groupID = gid
			payload = copyMapShallow(queued)
			break
		}
		delete(c.onlineUnreadHintQueue, groupID)
		c.onlineUnreadHintMu.Unlock()
		if payload == nil {
			continue
		}
		payload["_online_hint_drained"] = true
		d.onV2GroupPushNotification(payload)

		interval := c.onlineUnreadHintInterval
		if interval < 0 {
			interval = 0
		}
		if interval > 0 {
			c.onlineUnreadHintMu.Lock()
			hasMore := len(c.onlineUnreadHintQueue) > 0
			c.onlineUnreadHintMu.Unlock()
			if hasMore {
				time.Sleep(interval)
			}
		}
	}
}

// fillP2pGap 后台补齐 P2P 消息空洞
func (d *messageDeliveryEngine) fillP2pGap() {
	c := d.runtime.client
	c.mu.RLock()
	myAID := c.aid
	state := c.state
	c.mu.RUnlock()
	if !clientStateIsReady(state) || c.closing.Load() {
		return
	}
	if myAID == "" {
		return
	}
	ns := "p2p:" + myAID
	afterSeq := c.seqTracker.GetContiguousSeq(ns)
	c.log.Debug("fillP2pGap triggered: afterSeq=%d", afterSeq)
	// per-namespace 去重：同一 p2p namespace 只允许 1 个 in-flight pull
	dedupKey := "p2p_pull:" + ns
	c.gapFillDoneMu.Lock()
	if c.gapFillDone[dedupKey] {
		c.gapFillDoneMu.Unlock()
		return
	}
	c.gapFillDone[dedupKey] = true
	c.gapFillDoneMu.Unlock()
	defer func() {
		c.gapFillDoneMu.Lock()
		delete(c.gapFillDone, dedupKey)
		c.gapFillDoneMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := c.Call(ctx, "message.pull", map[string]any{
		"after_seq":       afterSeq,
		"limit":           50,
		"_rpc_background": true,
	})
	if err != nil {
		c.log.Warn("P2P message gap fill failed: after_seq=%d error=%v", afterSeq, err)
		return
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		return
	}
	messages, ok := resultMap["messages"].([]any)
	if !ok {
		return
	}
	nsKey := "p2p:" + myAID
	contigBefore := afterSeq
	if rawBefore, ok := resultMap["_contig_before"]; ok {
		contigBefore = int(toInt64(rawBefore))
	}
	c.log.Debug("fillP2pGap completed: recovered %d messages", len(messages))
	c.publishGapFillMessages(nsKey, messages)
	// publish 完成后 auto-ack
	contig := c.seqTracker.GetContiguousSeq(nsKey)
	if contig > 0 && contig != contigBefore {
		ackSeq := c.clampAckSeq("message.ack", "seq", nsKey, int64(contig))
		go func() {
			ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer ackCancel()
			if _, ackErr := c.transport.Call(ackCtx, "message.ack", map[string]any{
				"seq":             ackSeq,
				"device_id":       c.deviceID,
				"slot_id":         c.slotID,
				"_rpc_background": true,
			}); ackErr != nil {
				c.log.Debug("P2P gap fill auto-ack failed: %v", ackErr)
			}
		}()
	}
}

// ── 已发布 seq 去重 ─────────────────────────────────────────

// prunePushedSeqs 只按硬上限裁剪 published guard。
// 不能按 contiguousSeq 清理：pull/补洞可能在 cursor 推进后再次拿到旧消息，
// 去重状态必须保留，否则会重复 publish。
func (d *messageDeliveryEngine) prunePushedSeqs(ns string) {
	c := d.runtime.client
	c.pushedSeqsMu.Lock()
	defer c.pushedSeqsMu.Unlock()
	pushed := c.pushedSeqs[ns]
	if pushed == nil {
		return
	}
	if len(pushed) > pushedSeqsLimit {
		seqs := make([]int, 0, len(pushed))
		for s := range pushed {
			seqs = append(seqs, s)
		}
		sort.Ints(seqs)
		keepStart := len(seqs) - pushedSeqsLimit
		next := make(map[int]bool, pushedSeqsLimit)
		for _, s := range seqs[keepStart:] {
			next[s] = true
		}
		c.pushedSeqs[ns] = next
	}
}

// markPushedSeq 在锁内安全标记指定 ns 的 seq 已发布到应用层。
func (d *messageDeliveryEngine) markPushedSeq(ns string, seq int) {
	c := d.runtime.client
	if seq <= 0 || ns == "" {
		return
	}
	c.pushedSeqsMu.Lock()
	if c.pushedSeqs[ns] == nil {
		c.pushedSeqs[ns] = make(map[int]bool)
	}
	c.pushedSeqs[ns][seq] = true
	if len(c.pushedSeqs[ns]) > pushedSeqsLimit {
		seqs := make([]int, 0, len(c.pushedSeqs[ns]))
		for s := range c.pushedSeqs[ns] {
			seqs = append(seqs, s)
		}
		sort.Ints(seqs)
		keepStart := len(seqs) - pushedSeqsLimit
		next := make(map[int]bool, pushedSeqsLimit)
		for _, s := range seqs[keepStart:] {
			next[s] = true
		}
		c.pushedSeqs[ns] = next
	}
	c.pushedSeqsMu.Unlock()
}

// isPushedSeq 在锁内安全查询指定 ns 的 seq 是否已通过推送路径分发。
// 不取出内层 map 引用，避免锁外读写竞态。
func (d *messageDeliveryEngine) isPushedSeq(ns string, seq int) bool {
	c := d.runtime.client
	if seq <= 0 || ns == "" {
		return false
	}
	c.pushedSeqsMu.Lock()
	defer c.pushedSeqsMu.Unlock()
	pushed := c.pushedSeqs[ns]
	if pushed == nil {
		return false
	}
	return pushed[seq]
}

// ── ack 参数 clamp ──────────────────────────────────────────

// clampAckSeq 在所有 ack 出口前做本地边界保护。
//
// 上界来自 push/pull 维护的 maxSeenSeq；这样本地脏 contiguousSeq 不会被回传给服务端。
// 下界固定为 0，避免负数/恶意值进入 RPC 参数。
func (d *messageDeliveryEngine) clampAckSeq(method, field, ns string, seq int64) int64 {
	c := d.runtime.client
	original := seq
	if seq < 0 {
		seq = 0
	}
	if ns != "" {
		maxSeen := c.seqTracker.GetMaxSeenSeq(ns)
		if maxSeen > 0 && seq > int64(maxSeen) {
			if strings.HasPrefix(method, "group.") {
				c.logEG.Warn("ack clamp: method=%s %s=%d > max_seen=%d, clamp", method, field, original, maxSeen)
			} else {
				c.log.Warn("ack clamp: method=%s %s=%d > max_seen=%d, clamp", method, field, original, maxSeen)
			}
			seq = int64(maxSeen)
		}
	}
	return seq
}

// ── 有序投递 ────────────────────────────────────────────────

func (d *messageDeliveryEngine) enqueueOrderedMessage(ns, event string, seq int, payload any) {
	c := d.runtime.client
	if ns == "" || seq <= 0 {
		return
	}
	c.pendingOrderedMsgsMu.Lock()
	defer c.pendingOrderedMsgsMu.Unlock()
	pending := d.runtime.delivery.pendingOrderedMsgsLocked()
	queue := pending[ns]
	if queue == nil {
		queue = make(map[int]pendingOrderedMessage)
		pending[ns] = queue
	}
	queue[seq] = pendingOrderedMessage{event: event, payload: payload}
	if len(queue) > pendingOrderedLimit {
		seqs := make([]int, 0, len(queue))
		for s := range queue {
			seqs = append(seqs, s)
		}
		sort.Ints(seqs)
		for _, s := range seqs[:len(queue)-pendingOrderedLimit] {
			delete(queue, s)
		}
	}
}

func (d *messageDeliveryEngine) popReadyOrderedMessages(ns string, beforeSeq int) []orderedReadyEntry {
	c := d.runtime.client
	c.pendingOrderedMsgsMu.Lock()
	defer c.pendingOrderedMsgsMu.Unlock()
	queue := c.pendingOrderedMsgs[ns]
	if len(queue) == 0 {
		return nil
	}
	contig := c.seqTracker.GetContiguousSeq(ns)
	seqs := make([]int, 0, len(queue))
	for seq := range queue {
		if seq <= contig && (beforeSeq <= 0 || seq < beforeSeq) {
			seqs = append(seqs, seq)
		}
	}
	sort.Ints(seqs)
	ready := make([]orderedReadyEntry, 0, len(seqs))
	for _, seq := range seqs {
		ready = append(ready, orderedReadyEntry{seq: seq, item: queue[seq]})
		delete(queue, seq)
	}
	if len(queue) == 0 {
		delete(c.pendingOrderedMsgs, ns)
	}
	return ready
}

func (d *messageDeliveryEngine) removePendingOrderedSeq(ns string, seq int) {
	c := d.runtime.client
	c.pendingOrderedMsgsMu.Lock()
	defer c.pendingOrderedMsgsMu.Unlock()
	queue := c.pendingOrderedMsgs[ns]
	if queue == nil {
		return
	}
	delete(queue, seq)
	if len(queue) == 0 {
		delete(c.pendingOrderedMsgs, ns)
	}
}

// isPendingOrderedSeq 查询 seq 是否已解密并挂在有序队列里等待放行
// （对齐 Python is_pending_ordered_seq）。撤回 push 用它判定 pull 是否已处理过该 seq。
func (d *messageDeliveryEngine) isPendingOrderedSeq(ns string, seq int) bool {
	c := d.runtime.client
	if ns == "" || seq <= 0 {
		return false
	}
	c.pendingOrderedMsgsMu.Lock()
	defer c.pendingOrderedMsgsMu.Unlock()
	queue := c.pendingOrderedMsgs[ns]
	if queue == nil {
		return false
	}
	_, ok := queue[seq]
	return ok
}

func (d *messageDeliveryEngine) pendingOrderedEmpty(ns string) bool {
	c := d.runtime.client
	c.pendingOrderedMsgsMu.Lock()
	defer c.pendingOrderedMsgsMu.Unlock()
	return len(c.pendingOrderedMsgs[ns]) == 0
}

func (d *messageDeliveryEngine) drainOrderedMessages(ns string, beforeSeq ...int) {
	c := d.runtime.client
	limit := 0
	if len(beforeSeq) > 0 {
		limit = beforeSeq[0]
	}
	delivered := false
	for _, ready := range c.popReadyOrderedMessages(ns, limit) {
		if c.isPushedSeq(ns, ready.seq) {
			c.log.Debug("publish ordered drain skipped duplicate: ns=%s seq=%d event=%s", ns, ready.seq, ready.item.event)
			continue
		}
		d.publishOrderedQueueItem(ns, ready.item.event, ready.seq, ready.item.payload)
		c.markPushedSeq(ns, ready.seq)
		delivered = true
		c.log.Debug("publish ordered drain delivered: ns=%s seq=%d event=%s", ns, ready.seq, ready.item.event)
	}
	if delivered && d.pendingOrderedEmpty(ns) {
		c.saveSeqTrackerState()
	}
}

func (d *messageDeliveryEngine) publishOrderedQueueItem(ns, event string, seq int, payload any) {
	c := d.runtime.client
	if event == "group.changed" && strings.HasPrefix(ns, "group_event:") {
		d.publishOrderedGroupChanged(payload)
		return
	}
	if event == "message.recalled" {
		d.publishMessageRecallTombstone(seq, payload)
		return
	}
	c.publishAppEventSync(event, payload)
}

func (d *messageDeliveryEngine) publishOrderedGroupChanged(payload any) {
	c := d.runtime.client
	if dataMap, ok := payload.(map[string]any); ok {
		groupID, _ := dataMap["group_id"].(string)
		action, _ := dataMap["action"].(string)
		c.onRawGroupChangedV2(groupID, action, dataMap)
		if action == "dissolved" && groupID != "" {
			c.cleanupDissolvedGroup(groupID)
		}
	}
	c.publishAppEventSync("group.changed", payload)
}

func (d *messageDeliveryEngine) publishOrderedMessage(event, ns string, seq int, payload any) bool {
	c := d.runtime.client
	if ns == "" || seq <= 0 {
		c.log.Debug("publish ordered direct(no-seq): event=%s ns=%s seq=%d", event, ns, seq)
		d.publishOrderedQueueItem(ns, event, seq, payload)
		return true
	}
	if c.isPushedSeq(ns, seq) {
		c.log.Debug("publish ordered skipped duplicate: event=%s ns=%s seq=%d", event, ns, seq)
		c.removePendingOrderedSeq(ns, seq)
		return false
	}
	contig := c.seqTracker.GetContiguousSeq(ns)
	if seq > contig {
		c.log.Debug("publish ordered enqueue(gap): event=%s ns=%s seq=%d contiguous=%d", event, ns, seq, contig)
		c.enqueueOrderedMessage(ns, event, seq, payload)
		return false
	}
	c.drainOrderedMessages(ns, seq)
	if c.isPushedSeq(ns, seq) {
		c.log.Debug("publish ordered skipped after-drain duplicate: event=%s ns=%s seq=%d", event, ns, seq)
		return false
	}
	c.removePendingOrderedSeq(ns, seq)
	d.publishOrderedQueueItem(ns, event, seq, payload)
	c.markPushedSeq(ns, seq)
	c.log.Debug("publish ordered delivered: event=%s ns=%s seq=%d", event, ns, seq)
	c.drainOrderedMessages(ns)
	if d.pendingOrderedEmpty(ns) {
		c.saveSeqTrackerState()
	}
	return true
}

// publishPulledMessage 发布 pull 批中的消息，只做 seq 级去重，不受 contiguous gate 限制。
// pull 返回的批内部空洞可能是永久空洞，不能因此阻塞批内后续消息投递。
func (d *messageDeliveryEngine) publishPulledMessage(event, ns string, seq int, payload any) bool {
	c := d.runtime.client
	if ns == "" || seq <= 0 {
		c.log.Debug("publish pulled direct(no-seq): event=%s ns=%s seq=%d", event, ns, seq)
		if event == "message.recalled" {
			return d.publishMessageRecallTombstone(seq, payload)
		}
		c.publishAppEventSync(event, payload)
		return true
	}
	if c.isPushedSeq(ns, seq) {
		c.log.Debug("publish pulled skipped duplicate: event=%s ns=%s seq=%d", event, ns, seq)
		c.removePendingOrderedSeq(ns, seq)
		return false
	}
	c.drainOrderedMessages(ns, seq)
	c.removePendingOrderedSeq(ns, seq)
	if event == "message.recalled" {
		published := d.publishMessageRecallTombstone(seq, payload)
		c.markPushedSeq(ns, seq)
		c.log.Debug("publish pulled delivered: event=%s ns=%s seq=%d", event, ns, seq)
		return published
	}
	c.publishAppEventSync(event, payload)
	c.markPushedSeq(ns, seq)
	c.log.Debug("publish pulled delivered: event=%s ns=%s seq=%d", event, ns, seq)
	return true
}

// publishGapFillMessages 补洞路径发布 P2P 消息，跳过已发布到应用层的 seq。
// 使用 isPushedSeq 逐条检查，避免取出内层 map 引用后在锁外读取的竞态。
func (d *messageDeliveryEngine) publishGapFillMessages(ns string, messages []any) {
	c := d.runtime.client
	for _, raw := range messages {
		if msg, ok := raw.(map[string]any); ok {
			s := int(toInt64(msg["seq"]))
			event, payload := p2pAppEventForMessage(msg)
			if s > 0 {
				c.publishPulledMessage(event, ns, s, payload)
			} else {
				c.publishPulledMessage(event, ns, s, payload)
			}
		}
	}
	c.prunePushedSeqs(ns)
}

// publishGapFillGroupMessages 补洞路径发布群消息，跳过已发布到应用层的 seq。
//
// legacy / 明文 pull 回退路径也可能拉回群撤回 tombstone（占位 / 通知）；发布前先用
// recallEventFromGroupMessage 识别，命中则走 publishGroupRecallTombstone（归一化为
// group.message_recalled 并去重 + markPushedSeq 占 seq），而非当作 group.message_created
// 泄漏给应用层。对齐 v2_routing pull 路径与 Python。
func (d *messageDeliveryEngine) publishGapFillGroupMessages(ns string, messages []any) {
	c := d.runtime.client
	for _, raw := range messages {
		if msg, ok := raw.(map[string]any); ok {
			s := int(toInt64(msg["seq"]))
			if _, isRecall := recallEventFromGroupMessage(msg); isRecall {
				groupID := strings.TrimPrefix(ns, "group:")
				c.delivery().publishGroupRecallTombstone(groupID, s, msg)
				if s > 0 {
					c.markPushedSeq(ns, s)
				}
				continue
			}
			c.publishPulledMessage("group.message_created", ns, s, msg)
		}
	}
	c.prunePushedSeqs(ns)
}

// ── seq tracker 持久化 ──────────────────────────────────────

const seqTrackerPersistFlushDelay = 200 * time.Millisecond

func (d *messageDeliveryEngine) currentSeqTrackerContext() string {
	c := d.runtime.client
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.aid == "" {
		return ""
	}
	return buildSeqTrackerContext(c.aid, c.deviceID, c.slotID)
}

func (d *messageDeliveryEngine) currentSeqTrackerIdentity() (string, string, string, string) {
	c := d.runtime.client
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.aid == "" {
		return "", "", "", ""
	}
	aid := c.aid
	deviceID := c.deviceID
	slotID := c.slotID
	return buildSeqTrackerContext(aid, deviceID, slotID), aid, deviceID, slotID
}

func (d *messageDeliveryEngine) writeSeqTrackerValues(aid, deviceID, slotID string, values map[string]int) {
	c := d.runtime.client
	if aid == "" || len(values) == 0 {
		return
	}
	store, ok := c.tokenStore.(keystore.SeqTrackerStore)
	if !ok {
		c.log.Warn("keystore does not support SeqTrackerStore, seq_tracker_state not persisted")
		return
	}
	for ns, seq := range values {
		if ns == "" || seq <= 0 {
			continue
		}
		_ = store.SaveSeq(aid, deviceID, slotID, ns, seq)
	}
}

func (d *messageDeliveryEngine) flushSeqTrackerPending() {
	c := d.runtime.client
	c.seqTrackerPersistMu.Lock()
	if c.seqTrackerFlushTimer != nil {
		c.seqTrackerFlushTimer.Stop()
		c.seqTrackerFlushTimer = nil
	}
	aid := c.seqTrackerPendingAid
	deviceID := c.seqTrackerPendingDevice
	slotID := c.seqTrackerPendingSlot
	values := make(map[string]int, len(c.seqTrackerPendingPersist))
	for ns, seq := range c.seqTrackerPendingPersist {
		values[ns] = seq
	}
	c.seqTrackerPendingPersist = make(map[string]int)
	c.seqTrackerPendingContext = ""
	c.seqTrackerPendingAid = ""
	c.seqTrackerPendingDevice = ""
	c.seqTrackerPendingSlot = ""
	c.seqTrackerPersistMu.Unlock()
	d.writeSeqTrackerValues(aid, deviceID, slotID, values)
}

func (d *messageDeliveryEngine) mergeSeqTrackerPending(context string, values map[string]int) {
	c := d.runtime.client
	c.seqTrackerPersistMu.Lock()
	if c.seqTrackerPendingPersist == nil {
		c.seqTrackerPendingPersist = make(map[string]int)
	}
	needFlush := c.seqTrackerPendingContext != "" && c.seqTrackerPendingContext != context && len(c.seqTrackerPendingPersist) > 0
	c.seqTrackerPersistMu.Unlock()
	if needFlush {
		d.flushSeqTrackerPending()
	}
	c.seqTrackerPersistMu.Lock()
	if c.seqTrackerPendingPersist == nil {
		c.seqTrackerPendingPersist = make(map[string]int)
	}
	_, aid, deviceID, slotID := d.currentSeqTrackerIdentity()
	c.seqTrackerPendingContext = context
	c.seqTrackerPendingAid = aid
	c.seqTrackerPendingDevice = deviceID
	c.seqTrackerPendingSlot = slotID
	for ns, seq := range values {
		if ns != "" && seq > 0 {
			c.seqTrackerPendingPersist[ns] = seq
		}
	}
	c.seqTrackerPersistMu.Unlock()
}

func (d *messageDeliveryEngine) scheduleSeqTrackerFlush() {
	c := d.runtime.client
	c.seqTrackerPersistMu.Lock()
	if len(c.seqTrackerPendingPersist) == 0 || c.seqTrackerFlushTimer != nil {
		c.seqTrackerPersistMu.Unlock()
		return
	}
	c.seqTrackerFlushTimer = time.AfterFunc(seqTrackerPersistFlushDelay, func() {
		d.flushSeqTrackerPending()
	})
	c.seqTrackerPersistMu.Unlock()
}

func (d *messageDeliveryEngine) dropSeqTrackerPending(ns string) {
	c := d.runtime.client
	c.seqTrackerPersistMu.Lock()
	delete(c.seqTrackerPendingPersist, ns)
	if len(c.seqTrackerPendingPersist) == 0 {
		c.seqTrackerPendingContext = ""
		c.seqTrackerPendingAid = ""
		c.seqTrackerPendingDevice = ""
		c.seqTrackerPendingSlot = ""
		if c.seqTrackerFlushTimer != nil {
			c.seqTrackerFlushTimer.Stop()
			c.seqTrackerFlushTimer = nil
		}
	}
	c.seqTrackerPersistMu.Unlock()
}

// restoreSeqTrackerState 从 keystore seq_tracker 表恢复 SeqTracker 状态
func (d *messageDeliveryEngine) restoreSeqTrackerState() {
	c := d.runtime.client
	c.mu.RLock()
	aid := c.aid
	deviceID := c.deviceID
	slotID := c.slotID
	c.mu.RUnlock()
	if aid == "" {
		return
	}
	if store, ok := c.tokenStore.(keystore.SeqTrackerStore); ok {
		seqs, err := store.LoadAllSeqs(aid, deviceID, slotID)
		if err != nil || len(seqs) == 0 {
			return
		}
		seqs = c.migrateSeqStateGroupIDs(aid, deviceID, slotID, seqs)
		c.seqTracker.RestoreState(seqs)
		return
	}
	// 降级：从 instance_state JSON 读取（兼容旧数据）
	if store, ok := c.tokenStore.(keystore.InstanceStateStore); ok {
		holder, _ := store.LoadInstanceState(aid, deviceID, slotID)
		if holder == nil {
			return
		}
		state, ok := holder["seq_tracker_state"].(map[string]any)
		if !ok {
			return
		}
		intState := make(map[string]int)
		for ns, v := range state {
			if seq, ok := v.(float64); ok && int(seq) > 0 {
				intState[ns] = int(seq)
			}
		}
		if len(intState) > 0 {
			intState = c.migrateSeqStateGroupIDs(aid, deviceID, slotID, intState)
			c.seqTracker.RestoreState(intState)
		}
	}
}

// migrateSeqStateGroupIDs 把 state 里 group_event:/group_msg: 前缀的老/污染 group_id 归一化。
// 冲突取 max；落盘删老 ns、写新 ns，避免下次启动重复迁移。
func (d *messageDeliveryEngine) migrateSeqStateGroupIDs(aid, deviceID, slotID string, state map[string]int) map[string]int {
	c := d.runtime.client
	if len(state) == 0 {
		return state
	}
	rename := make(map[string]string)
	for ns := range state {
		for _, prefix := range []string{"group_event:", "group_msg:"} {
			if strings.HasPrefix(ns, prefix) {
				oldGid := ns[len(prefix):]
				newGid := NormalizeGroupID(oldGid, "")
				if newGid != "" && newGid != oldGid {
					rename[ns] = prefix + newGid
				}
				break
			}
		}
	}
	if len(rename) == 0 {
		return state
	}
	newState := make(map[string]int, len(state))
	for k, v := range state {
		newState[k] = v
	}
	for oldNs, newNs := range rename {
		oldVal := newState[oldNs]
		curVal := newState[newNs]
		delete(newState, oldNs)
		if oldVal > curVal {
			newState[newNs] = oldVal
		} else {
			newState[newNs] = curVal
		}
	}
	c.logEG.Warn("SeqTracker group_id migration: %d namespaces rewritten", len(rename))
	if saver, ok := c.tokenStore.(keystore.SeqTrackerStore); ok {
		deleter, _ := c.tokenStore.(keystore.SeqTrackerDeleter)
		for oldNs, newNs := range rename {
			if deleter != nil {
				if err := deleter.DeleteSeq(aid, deviceID, slotID, oldNs); err != nil {
					c.log.Warn("failed to delete old seq ns: ns=%s err=%v", oldNs, err)
				}
			}
			if err := saver.SaveSeq(aid, deviceID, slotID, newNs, newState[newNs]); err != nil {
				c.log.Warn("failed to write new seq ns: ns=%s err=%v", newNs, err)
			}
		}
	}
	return newState
}

// saveSeqTrackerState 将 SeqTracker 状态保存到 keystore seq_tracker 表（每 namespace 一行）
func (d *messageDeliveryEngine) saveSeqTrackerState() {
	c := d.runtime.client
	context, _, _, _ := d.currentSeqTrackerIdentity()
	if context == "" {
		d.flushSeqTrackerPending()
		return
	}
	state := c.seqTracker.ExportState()
	c.seqTrackerPersistMu.Lock()
	if len(c.seqTrackerPendingPersist) > 0 && c.seqTrackerPendingContext == context {
		for ns := range c.seqTrackerPendingPersist {
			if _, ok := state[ns]; !ok {
				delete(c.seqTrackerPendingPersist, ns)
			}
		}
		if len(c.seqTrackerPendingPersist) == 0 {
			c.seqTrackerPendingContext = ""
		}
	}
	c.seqTrackerPersistMu.Unlock()
	if len(state) > 0 {
		d.mergeSeqTrackerPending(context, state)
	}
	d.flushSeqTrackerPending()
}

func (d *messageDeliveryEngine) persistSeq(ns string) {
	c := d.runtime.client
	context, _, _, _ := d.currentSeqTrackerIdentity()
	if context == "" {
		d.flushSeqTrackerPending()
		return
	}
	seq := c.seqTracker.GetContiguousSeq(ns)
	if ns == "" || seq <= 0 {
		return
	}
	d.mergeSeqTrackerPending(context, map[string]int{ns: seq})
	d.scheduleSeqTrackerFlush()
}

func (d *messageDeliveryEngine) persistRepairedSeq(ns string) {
	c := d.runtime.client
	if ns == "" {
		return
	}
	d.dropSeqTrackerPending(ns)
	seq := c.seqTracker.GetContiguousSeq(ns)
	context, aid, deviceID, slotID := d.currentSeqTrackerIdentity()
	if context == "" {
		return
	}
	if seq > 0 {
		d.writeSeqTrackerValues(aid, deviceID, slotID, map[string]int{ns: seq})
		return
	}
	if deleter, ok := c.tokenStore.(keystore.SeqTrackerDeleter); ok {
		_ = deleter.DeleteSeq(aid, deviceID, slotID, ns)
	}
}
