package aun

import (
	"context"
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
	if !isInstanceScopedMessageEvent(event) {
		return payload
	}
	return stripInternalSenderDeviceFields(d.runtime.client.attachCurrentInstanceContext(payload))
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
	if _, ok := event["tombstone_message_id"]; !ok {
		if mid, exists := msg["message_id"]; exists {
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
			ackSeq := c.clampAckSeq("message.ack", "seq", p2pNS, int64(contig))
			c.log.Debug("P2P push auto-ack send: ns=%s seq=%d contiguous=%d", p2pNS, ackSeq, contig)
			go func() {
				ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer ackCancel()
				if _, ackErr := c.transport.Call(ackCtx, "message.ack", map[string]any{
					"seq":       ackSeq,
					"device_id": c.deviceID,
					"slot_id":   c.slotID,
				}); ackErr != nil {
					c.log.Warn("P2P auto-ack failed: %v", ackErr)
				} else {
					c.log.Debug("P2P push auto-ack ok: ns=%s seq=%d", p2pNS, ackSeq)
				}
			}()
		}
		// 即时持久化 cursor，异常断连后不回退
		c.saveSeqTrackerState()
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
				c.saveSeqTrackerState()
			}
		}
		c.autoPullGroupMessages(msg)
		return
	}

	encryptedPush := isEncryptedPushMessage(msg)

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
					"group_id":  groupID,
					"msg_seq":   ackSeq,
					"device_id": c.deviceID,
					"slot_id":   c.slotID,
				}); ackErr != nil {
					c.logEG.Warn("group message auto-ack failed: group=%s %v", groupID, ackErr)
				} else {
					c.logEG.Debug("group push auto-ack ok: group=%s ns=%s seq=%d", groupID, ns, ackSeq)
				}
			}()
		}
		c.saveSeqTrackerState()
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
			"group_id":  groupID,
			"after_seq": afterSeq,
			"limit":     50,
		})
		if err != nil {
			c.logEG.Warn("auto pull group messages (v2) failed: %v", err)
			c.publishAppEvent("group.message_created", notification)
		}
		return
	}

	result, err := c.Call(ctx, "group.pull", map[string]any{
		"group_id":  groupID,
		"after_seq": afterSeq,
		"limit":     50,
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
		"group_id":  groupID,
		"after_seq": afterSeq,
		"limit":     50,
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
				"group_id":  groupID,
				"msg_seq":   ackSeq,
				"device_id": c.deviceID,
				"slot_id":   c.slotID,
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
		c.saveSeqTrackerState()
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
		for _, evt := range pullEvts {
			evt["_from_gap_fill"] = true
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
			// group.changed 或缺失/其他 → 发布到 group.changed（向后兼容）
			c.events.publishSync("group.changed", evt)
		}
		contig := c.seqTracker.GetContiguousSeq(ns)
		if contig != pageContigBefore {
			c.saveSeqTrackerState()
		}
		if len(pullEvts) > 0 && contig > 0 && contig != pageContigBefore {
			ackSeq := c.clampAckSeq("group.ack_events", "event_seq", ns, int64(contig))
			go func() {
				ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer ackCancel()
				if _, ackErr := c.transport.Call(ackCtx, "group.ack_events", map[string]any{
					"group_id":  groupID,
					"event_seq": ackSeq,
					"device_id": c.deviceID,
					"slot_id":   c.slotID,
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
	if rawES, ok := data["event_seq"]; ok && groupID != "" {
		if es := toInt64(rawES); es > 0 {
			ns := "group_event:" + groupID
			c.seqTracker.UpdateMaxSeen(ns, int(es))
			needPull = c.seqTracker.OnMessageSeq(ns, int(es))
		}
	}

	if needPull && groupID != "" && data["_from_gap_fill"] == nil {
		c.logEG.Debug("group.changed event_seq gap detected, triggering gap fill: group=%s", groupID)
		go d.fillGroupEventGap(groupID)
	}
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
			c.saveSeqTrackerState()
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
				c.saveSeqTrackerState()
			}
			if newContig > 0 && newContig != contigBefore {
				ackSeq := c.clampAckSeq("message.v2.ack", "up_to_seq", ns, int64(newContig))
				ackParams := map[string]any{"up_to_seq": ackSeq}
				go func() {
					ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer ackCancel()
					c.signClientOperation("message.v2.ack", ackParams)
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
			_, err := c.pullV2Internal(ctx, map[string]any{})
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
	if contigBefore == seq {
		c.logEG.Debug("onV2GroupPushNotification: push seq=%d already covered by contiguous_seq=%d, ignore duplicate push",
			seq, contigBefore)
		return
	}
	if contigBefore > seq {
		c.logEG.Warn("onV2GroupPushNotification: contiguous_seq=%d 越界（> push_seq=%d），脏数据修复倒退至 %d",
			contigBefore, seq, seq-1)
		c.seqTracker.RepairContiguousSeq(ns, seq-1)
		c.saveSeqTrackerState()
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
			"group_id":  groupID,
			"after_seq": afterSeq,
			"limit":     50,
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
		ready := c.state == StateConnected
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
	if state != StateConnected || c.closing.Load() {
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
		"after_seq": afterSeq,
		"limit":     50,
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
				"seq":       ackSeq,
				"device_id": c.deviceID,
				"slot_id":   c.slotID,
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

func (d *messageDeliveryEngine) drainOrderedMessages(ns string, beforeSeq ...int) {
	c := d.runtime.client
	limit := 0
	if len(beforeSeq) > 0 {
		limit = beforeSeq[0]
	}
	for _, ready := range c.popReadyOrderedMessages(ns, limit) {
		if c.isPushedSeq(ns, ready.seq) {
			c.log.Debug("publish ordered drain skipped duplicate: ns=%s seq=%d event=%s", ns, ready.seq, ready.item.event)
			continue
		}
		c.publishAppEventSync(ready.item.event, ready.item.payload)
		c.markPushedSeq(ns, ready.seq)
		c.log.Debug("publish ordered drain delivered: ns=%s seq=%d event=%s", ns, ready.seq, ready.item.event)
	}
}

func (d *messageDeliveryEngine) publishOrderedMessage(event, ns string, seq int, payload any) bool {
	c := d.runtime.client
	if ns == "" || seq <= 0 {
		c.log.Debug("publish ordered direct(no-seq): event=%s ns=%s seq=%d", event, ns, seq)
		c.publishAppEvent(event, payload)
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
	c.publishAppEventSync(event, payload)
	c.markPushedSeq(ns, seq)
	c.log.Debug("publish ordered delivered: event=%s ns=%s seq=%d", event, ns, seq)
	c.drainOrderedMessages(ns)
	return true
}

// publishPulledMessage 发布 pull 批中的消息，只做 seq 级去重，不受 contiguous gate 限制。
// pull 返回的批内部空洞可能是永久空洞，不能因此阻塞批内后续消息投递。
func (d *messageDeliveryEngine) publishPulledMessage(event, ns string, seq int, payload any) bool {
	c := d.runtime.client
	if ns == "" || seq <= 0 {
		c.log.Debug("publish pulled direct(no-seq): event=%s ns=%s seq=%d", event, ns, seq)
		c.publishAppEventSync(event, payload)
		return true
	}
	if c.isPushedSeq(ns, seq) {
		c.log.Debug("publish pulled skipped duplicate: event=%s ns=%s seq=%d", event, ns, seq)
		c.removePendingOrderedSeq(ns, seq)
		return false
	}
	c.removePendingOrderedSeq(ns, seq)
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
func (d *messageDeliveryEngine) publishGapFillGroupMessages(ns string, messages []any) {
	c := d.runtime.client
	for _, raw := range messages {
		if msg, ok := raw.(map[string]any); ok {
			s := int(toInt64(msg["seq"]))
			if s > 0 {
				c.publishPulledMessage("group.message_created", ns, s, msg)
			} else {
				c.publishPulledMessage("group.message_created", ns, s, msg)
			}
		}
	}
	c.prunePushedSeqs(ns)
}

// ── seq tracker 持久化 ──────────────────────────────────────

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
	c.mu.RLock()
	aid := c.aid
	deviceID := c.deviceID
	slotID := c.slotID
	c.mu.RUnlock()
	if aid == "" {
		return
	}
	state := c.seqTracker.ExportState()
	if len(state) == 0 {
		return
	}
	if store, ok := c.tokenStore.(keystore.SeqTrackerStore); ok {
		for ns, seq := range state {
			_ = store.SaveSeq(aid, deviceID, slotID, ns, seq)
		}
		return
	}
	c.log.Warn("keystore does not support SeqTrackerStore, seq_tracker_state not persisted")
}
