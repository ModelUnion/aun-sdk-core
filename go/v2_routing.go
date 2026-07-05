// v2_routing.go — V2 内部路由适配器。
//
// 把 client.Call(method, params) 的调用形式适配到公开的 V2 API（SendV2/PullV2/AckV2 等）。
// V2 路径内部方法签名保留参数 dict，与 Python `_send_encrypted_v2` / `_pull_v2_internal` 等对齐，
// 让 Call 路由可以直接传递业务侧的 params。
//
// 现有公开方法（SendV2/PullV2/AckV2/SendGroupV2/PullGroupV2/AckGroupV2）保留作为
// V2 测试与外部调用的便利入口；新业务代码建议统一通过 client.Call 进入。

package aun

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelunion/aun-sdk-core/go/v2/e2ee"
)

// sendV2Internal 适配 client.Call("message.send", params) → SendV2。
func (c *AUNClient) sendV2Internal(ctx context.Context, params map[string]any) (any, error) {
	to := strings.TrimSpace(getStr(params, "to", ""))
	if to == "" {
		return nil, NewValidationError("message.send requires 'to'")
	}
	payload, _ := params["payload"].(map[string]any)
	if payload == nil {
		return nil, NewValidationError("message.send payload must be a map for V2 encryption")
	}
	opts := e2ee.EncryptOptions{}
	if messageID := strings.TrimSpace(stringFromAny(params["message_id"])); messageID != "" {
		opts.MessageID = messageID
	}
	if timestamp := toInt64(params["timestamp"]); timestamp > 0 {
		opts.Timestamp = timestamp
	}
	if ph := protectedHeadersFromParams(params); len(ph) > 0 {
		opts.ProtectedHeaders = ph
	}
	if ctxMeta, ok := params["context"].(map[string]any); ok && len(ctxMeta) > 0 {
		opts.Context = ctxMeta
	}
	resp, err := c.SendV2WithOpts(ctx, to, payload, opts)
	if err != nil {
		return nil, err
	}
	// 发送成功后记录自己发的 P2P seq，保证 SeqTracker 连续；与 Python 对齐。
	if resp != nil {
		if seq := toInt64(resp["seq"]); seq > 0 {
			c.mu.RLock()
			myAID := c.aid
			c.mu.RUnlock()
			if myAID != "" {
				ns := "p2p:" + myAID
				c.seqTracker.OnMessageSeq(ns, int(seq))
				c.markPushedSeq(ns, int(seq))
				c.saveSeqTrackerState()
			}
		}
	}
	return resp, nil
}

// pullV2Internal 适配 client.Call("message.pull", params) → PullV2，并按
// {"messages": [...]} 形态返回。PullV2 内部会消费服务端 server_ack_seq，
// 即使空 pull 也会推进 SeqTracker 的 contiguous_seq。
func (c *AUNClient) pullV2Internal(ctx context.Context, params map[string]any) (any, error) {
	if truthyBool(params["_rpc_background"]) {
		ctx = contextWithRPCBackground(ctx)
	}
	afterSeq := toInt64(params["after_seq"])
	limit := int(toInt64(params["limit"]))
	if limit <= 0 {
		limit = 50
	}
	force := truthyBool(params["force"])
	c.mu.RLock()
	myAIDBefore := c.aid
	c.mu.RUnlock()
	nsBefore := ""
	if myAIDBefore != "" {
		nsBefore = "p2p:" + myAIDBefore
	}
	contigBefore := 0
	if nsBefore != "" {
		contigBefore = c.seqTracker.GetContiguousSeq(nsBefore)
	}
	out := make([]any, 0)
	nextAfterSeq := afterSeq
	if !force && nextAfterSeq == 0 && nsBefore != "" {
		nextAfterSeq = int64(c.seqTracker.GetContiguousSeq(nsBefore))
	}
	lastAutoAckSeq := int64(0)
	pendingAckSeq := int64(0)
	fireAck := func(ackSeq int64) {
		if ackSeq <= 0 {
			return
		}
		ackParams := map[string]any{
			"up_to_seq": ackSeq,
		}
		go func() {
			ackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c.signClientOperation("message.v2.ack", ackParams)
			ackParams["_rpc_background"] = true
			if _, ackErr := c.transport.Call(ackCtx, "message.v2.ack", ackParams); ackErr != nil {
				c.log.Debug("V2 P2P auto-ack failed: %v", ackErr)
			}
		}()
	}
	for pageCount := 0; pageCount < 100; pageCount++ {
		pageContigBefore := contigBefore
		if nsBefore != "" {
			pageContigBefore = c.seqTracker.GetContiguousSeq(nsBefore)
		}
		ackUpToSeq := pendingAckSeq
		msgs, pageMeta, err := c.pullV2WithForce(ctx, nextAfterSeq, limit, force, ackUpToSeq)
		if err != nil {
			return nil, err
		}
		if ackUpToSeq > 0 {
			pendingAckSeq = 0
			if ackUpToSeq > lastAutoAckSeq {
				lastAutoAckSeq = ackUpToSeq
			}
		}
		nextAfter := nextAfterSeq
		if pageMeta.latestSeq > nextAfter {
			nextAfter = pageMeta.latestSeq
		}
		if nextAfter > nextAfterSeq {
			for _, m := range msgs {
				out = append(out, m)
				seq := toInt64(m["seq"])
				event, payload := p2pAppEventForMessage(m)
				if seq <= 0 || nsBefore == "" {
					c.publishAppEvent(event, payload)
					continue
				}
				c.publishPulledMessage(event, nsBefore, int(seq), payload)
			}
		}
		if nsBefore != "" {
			contig := c.seqTracker.GetContiguousSeq(nsBefore)
			ackNeeded := contig > 0 &&
				int64(contig) > lastAutoAckSeq &&
				(contig != pageContigBefore || (pageMeta.hasServerAck && int64(contig) > pageMeta.serverAckSeq))
			if ackNeeded {
				ackSeq := c.clampAckSeq("message.v2.ack", "up_to_seq", nsBefore, int64(contig))
				if ackSeq > 0 {
					canContinuePage := pageMeta.latestSeq > nextAfterSeq
					if canContinuePage {
						if ackSeq > pendingAckSeq {
							pendingAckSeq = ackSeq
						}
						if ackSeq > lastAutoAckSeq {
							lastAutoAckSeq = ackSeq
						}
						c.log.Debug("message.v2.pull queued piggyback auto-ack: ns=%s ack_seq=%d raw_count=%d", nsBefore, pendingAckSeq, pageMeta.rawCount)
					} else {
						fireAck(ackSeq)
						if ackSeq > lastAutoAckSeq {
							lastAutoAckSeq = ackSeq
						}
					}
				}
			}
		}
		canContinuePage := pageMeta.rawCount > 0 && nextAfter > nextAfterSeq
		fullPage := canContinuePage && limit > 0 && pageMeta.rawCount >= limit
		shouldContinue := canContinuePage && (fullPage || pendingAckSeq > 0)
		if !shouldContinue {
			break
		}
		if delay := v2PullTailDelay(pageMeta.rawCount, limit); delay > 0 {
			sleepWithCancel(ctx, delay)
		}
		nextAfterSeq = nextAfter
	}
	if pendingAckSeq > 0 {
		fireAck(pendingAckSeq)
	}
	return map[string]any{"messages": out}, nil
}

// ackV2Internal 适配 client.Call("message.ack", params) → AckV2。
// 兼容 seq / up_to_seq 两种入参。
func (c *AUNClient) ackV2Internal(ctx context.Context, params map[string]any) (any, error) {
	if truthyBool(params["_rpc_background"]) {
		ctx = contextWithRPCBackground(ctx)
	}
	upTo := toInt64(params["seq"])
	if upTo == 0 {
		upTo = toInt64(params["up_to_seq"])
	}
	return c.ackV2(ctx, upTo)
}

// sendGroupV2Internal 适配 client.Call("group.send", params) → SendGroupV2。
func (c *AUNClient) sendGroupV2Internal(ctx context.Context, params map[string]any) (any, error) {
	_, groupAID := groupIdentifierPairFromParams(params)
	if groupAID == "" {
		return nil, NewValidationError("group.send requires 'group_id'")
	}
	payload, _ := params["payload"].(map[string]any)
	if payload == nil {
		return nil, NewValidationError("group.send payload must be a map for V2 encryption")
	}
	opts := e2ee.EncryptOptions{}
	if messageID := strings.TrimSpace(stringFromAny(params["message_id"])); messageID != "" {
		opts.MessageID = messageID
	}
	if timestamp := toInt64(params["timestamp"]); timestamp > 0 {
		opts.Timestamp = timestamp
	}
	if ph := protectedHeadersFromParams(params); len(ph) > 0 {
		opts.ProtectedHeaders = ph
	}
	if ctxMeta, ok := params["context"].(map[string]any); ok && len(ctxMeta) > 0 {
		opts.Context = ctxMeta
	}
	resp, err := c.SendGroupV2WithOpts(ctx, groupAID, payload, opts)
	if err != nil {
		return nil, err
	}
	// 发送成功后记录自己发的群消息 seq，保证 SeqTracker 连续；与 Python 对齐。
	if resp != nil {
		if seq := toInt64(resp["seq"]); seq > 0 {
			ns := "group:" + groupAID
			c.seqTracker.OnMessageSeq(ns, int(seq))
			c.markPushedSeq(ns, int(seq))
			c.saveSeqTrackerState()
		}
	}
	return resp, nil
}

// pullGroupV2Internal 适配 client.Call("group.pull", params) → PullGroupV2，按
// {"messages": [...]} 形态返回；同时 publish 到应用层 + auto-ack。
func (c *AUNClient) pullGroupV2Internal(ctx context.Context, params map[string]any) (any, error) {
	if truthyBool(params["_rpc_background"]) {
		ctx = contextWithRPCBackground(ctx)
	}
	wireGroupID, groupAID := groupIdentifierPairFromParams(params)
	if groupAID == "" {
		return nil, NewValidationError("group.pull requires 'group_id'")
	}
	afterSeq := int64(0)
	explicitAfterSeq := false
	if _, exists := params["after_seq"]; exists {
		afterSeq = toInt64(params["after_seq"])
		explicitAfterSeq = true
	} else if _, exists := params["after_message_seq"]; exists {
		afterSeq = toInt64(params["after_message_seq"])
		explicitAfterSeq = true
	}
	limit := int(toInt64(params["limit"]))
	if limit <= 0 {
		limit = 50
	}
	ns := "group:" + groupAID
	contigBefore := c.seqTracker.GetContiguousSeq(ns)
	ownsCursor := c.groupCursorTargetsCurrentInstance(params)
	cursorParams := groupCursorParams(params)
	out := make([]any, 0)
	nextAfterSeq := afterSeq
	if !explicitAfterSeq && nextAfterSeq == 0 {
		nextAfterSeq = int64(c.seqTracker.GetContiguousSeq(ns))
	}
	lastAutoAckSeq := int64(0)
	pendingAckSeq := int64(0)
	fireAck := func(ackSeq int64) {
		if ackSeq <= 0 {
			return
		}
		ackParams := map[string]any{
			"group_id":  groupAID,
			"group_aid": groupAID,
			"up_to_seq": ackSeq,
		}
		go func() {
			ackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c.signClientOperation("group.v2.ack", ackParams)
			ackParams["_rpc_background"] = true
			if _, ackErr := c.transport.Call(ackCtx, "group.v2.ack", ackParams); ackErr != nil {
				c.logEG.Debug("V2 group auto-ack failed: group=%s %v", groupAID, ackErr)
			}
		}()
	}
	for pageCount := 0; pageCount < 100; pageCount++ {
		pageContigBefore := contigBefore
		if ownsCursor {
			pageContigBefore = c.seqTracker.GetContiguousSeq(ns)
		}
		ackUpToSeq := int64(0)
		if ownsCursor {
			ackUpToSeq = pendingAckSeq
		}
		msgs, pageMeta, err := c.pullGroupV2WithOptions(ctx, groupAID, nextAfterSeq, limit, groupV2PullOptions{
			explicitAfterSeq: explicitAfterSeq,
			cursorParams:     cursorParams,
			wireGroupID:      wireGroupID,
			ackUpToSeq:       ackUpToSeq,
		})
		if err != nil {
			return nil, err
		}
		if ackUpToSeq > 0 {
			pendingAckSeq = 0
			if ackUpToSeq > lastAutoAckSeq {
				lastAutoAckSeq = ackUpToSeq
			}
		}
		nextAfter := nextAfterSeq
		if pageMeta.latestSeq > nextAfter {
			nextAfter = pageMeta.latestSeq
		}
		if nextAfter > nextAfterSeq {
			for _, m := range msgs {
				seq := toInt64(m["seq"])
				// 群撤回 tombstone（占位 / 通知 / legacy V1）：先识别再决定是否进列表。
				// 命中则归一化为 group.message_recalled 事件并占 seq，但绝不 append 进返回的 messages
				// 列表（否则撤回 tombstone 会作为"普通消息"泄漏给应用层）。对齐 Python/TS：识别后直接 continue。
				if _, isRecall := recallEventFromGroupMessage(m); isRecall {
					c.delivery().publishGroupRecallTombstone(groupAID, int(seq), m)
					if seq > 0 {
						c.markPushedSeq(ns, int(seq))
					}
					continue
				}
				out = append(out, m)
				if seq <= 0 {
					c.publishAppEvent("group.message_created", m)
					continue
				}
				c.publishPulledMessage("group.message_created", ns, int(seq), m)
			}
		}
		if ownsCursor {
			contig := c.seqTracker.GetContiguousSeq(ns)
			ackNeeded := contig > 0 &&
				int64(contig) > lastAutoAckSeq &&
				(contig != pageContigBefore || (pageMeta.hasServerAck && int64(contig) > pageMeta.serverAckSeq))
			if ackNeeded {
				ackSeq := c.clampAckSeq("group.v2.ack", "up_to_seq", ns, int64(contig))
				if ackSeq > 0 {
					canContinuePage := pageMeta.latestSeq > nextAfterSeq
					if canContinuePage {
						if ackSeq > pendingAckSeq {
							pendingAckSeq = ackSeq
						}
						if ackSeq > lastAutoAckSeq {
							lastAutoAckSeq = ackSeq
						}
						c.logEG.Debug("group.v2.pull queued piggyback auto-ack: group=%s ns=%s ack_seq=%d raw_count=%d", groupAID, ns, pendingAckSeq, pageMeta.rawCount)
					} else {
						fireAck(ackSeq)
						if ackSeq > lastAutoAckSeq {
							lastAutoAckSeq = ackSeq
						}
					}
				}
			}
		}
		if !ownsCursor {
			break
		}
		canContinuePage := pageMeta.rawCount > 0 && nextAfter > nextAfterSeq
		fullPage := canContinuePage && limit > 0 && pageMeta.rawCount >= limit
		shouldContinue := canContinuePage && (fullPage || pendingAckSeq > 0)
		if !shouldContinue {
			break
		}
		if delay := v2PullTailDelay(pageMeta.rawCount, limit); delay > 0 {
			sleepWithCancel(ctx, delay)
		}
		nextAfterSeq = nextAfter
	}
	if pendingAckSeq > 0 {
		fireAck(pendingAckSeq)
	}
	return map[string]any{"messages": out}, nil
}

func groupCursorParams(params map[string]any) map[string]any {
	out := make(map[string]any)
	for _, key := range []string{"device_id", "slot_id", "device_name", "device_type"} {
		if value, exists := params[key]; exists && value != nil {
			out[key] = value
		}
	}
	return out
}

func (c *AUNClient) groupCursorTargetsCurrentInstance(params map[string]any) bool {
	deviceID := strings.TrimSpace(stringFromAny(params["device_id"]))
	slotID := strings.TrimSpace(stringFromAny(params["slot_id"]))
	c.mu.RLock()
	currentDeviceID := c.deviceID
	currentSlotID := c.slotID
	c.mu.RUnlock()
	return (deviceID == "" || deviceID == currentDeviceID) &&
		(slotID == "" || slotID == currentSlotID)
}

// ackGroupV2Internal 适配 client.Call("group.ack_messages", params) → AckGroupV2。
func (c *AUNClient) ackGroupV2Internal(ctx context.Context, params map[string]any) (any, error) {
	if truthyBool(params["_rpc_background"]) {
		ctx = contextWithRPCBackground(ctx)
	}
	_, groupAID := groupIdentifierPairFromParams(params)
	if groupAID == "" {
		return nil, errors.New("group.ack_messages requires 'group_id'")
	}
	upTo := toInt64(params["msg_seq"])
	if upTo == 0 {
		upTo = toInt64(params["up_to_seq"])
	}
	return c.ackGroupV2(ctx, groupAID, upTo)
}

// 占位 import 防止 fmt 被去掉；实际使用见错误格式化扩展
var _ = fmt.Sprint
