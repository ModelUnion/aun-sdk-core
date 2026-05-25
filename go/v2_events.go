// v2_events.go — V2 事件订阅 + push 通知 + SPK rotation 触发。
//
// 与 Python aun_core.client 的对应方法对齐：
//   - _on_v2_push_notification → onV2PushNotification
//   - _on_v2_epoch_rotated     → onV2EpochRotated
//   - _on_raw_group_changed 中的 V2 逻辑 → 追加到 onRawGroupChanged

package aun

import (
	"context"
	"strings"
	"time"
)

// registerV2EventSubscriptions 在 client 构造时注册 V2 相关事件订阅。
// 在 NewClient 的事件订阅区块中调用。
func (c *AUNClient) registerV2EventSubscriptions() {
	// V2 P2P push 通知：自动 pull + decrypt + emit
	c.events.Subscribe("_raw.peer.v2.message_received", func(payload any) {
		c.onV2PushNotification(payload)
	})
	// V2 epoch 轮换事件：清除 bootstrap 缓存 + 触发 SPK rotation
	c.events.Subscribe("_raw.group.v2.epoch_rotated", func(payload any) {
		c.onV2EpochRotated(payload)
	})
	// V2 群消息推送：自动 pull + decrypt + emit
	c.events.Subscribe("_raw.group.v2.message_created", func(payload any) {
		c.onV2GroupPushNotification(payload)
	})
	// V2 state proposal 服务平面事件：owner/admin 负责确认或重新提案
	c.events.Subscribe("_raw.group.v2.state_proposed", func(payload any) {
		c.onV2StateProposed(payload)
	})
	c.events.Subscribe("_raw.group.v2.state_retry_needed", func(payload any) {
		c.onV2StateRetryNeeded(payload)
	})
	c.events.Subscribe("_raw.group.v2.state_confirmed", func(payload any) {
		c.onV2StateConfirmed(payload)
	})
}

// onV2PushNotification 处理 V2 push 通知：自动 pull + decrypt + emit。
//
// Push-Pull 双重修复机制：
//   - Push 确定上界：服务端至少有到 push_seq 的消息
//   - Pull 确定下界：server_ack_seq 以下的消息已被消费
//   - 修复窗口：[server_ack_seq+1, push_seq] 是需要关注的区间
func (c *AUNClient) onV2PushNotification(data any) {
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return
	}

	// 提取 push 通知中的元数据（用于诊断）
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
		// 越界修复必须先于 payload 分支，否则 payload 成功会提前返回，无法修正被污染的下界。
		if contigBefore > int(pushSeq) {
			c.logE2.Warn("onV2PushNotification: contiguous_seq=%d 越界（> push_seq=%d），脏数据修复倒退至 %d",
				contigBefore, pushSeq, pushSeq-1)
			c.seqTracker.RepairContiguousSeq(ns, int(pushSeq-1))
			c.saveSeqTrackerState()
			contigBefore = int(pushSeq - 1)
		}
	}

	// ── 带 payload 的 push：尝试就地解密 ──
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

	// ── 不带 payload 或解密失败：触发 pull ──
	// 关键：push 通知只表示“服务端有 seq=pushSeq 的新消息”，纯通知不能先推进 contiguousSeq。
	if pushSeq > 0 {
		c.logE2.Debug("onV2PushNotification: 纯通知 push_seq=%d > contiguous_seq=%d, 触发 pull(after_seq=%d)",
			pushSeq, contigBefore, contigBefore)
	}

	// only one in flight：CAS 抢占，失败则标记 pending
	if !c.v2PushPullInflight.CompareAndSwap(false, true) {
		c.v2PushPullPending.Store(true)
		return
	}
	// 同时标记 gapFillDone，阻止 fillP2pGap 并发
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

// onV2GroupPushNotification 处理 V2 群 push 通知：自动 pull + decrypt + emit。
func (c *AUNClient) onV2GroupPushNotification(data any) {
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
	// per-namespace 去重：同一 group namespace 只允许 1 个 in-flight pull
	dedupKey := "group_pull:" + ns
	c.gapFillDoneMu.Lock()
	if c.gapFillDone[dedupKey] {
		c.gapFillDoneMu.Unlock()
		return
	}
	c.gapFillDone[dedupKey] = true
	c.gapFillDoneMu.Unlock()
	go func() {
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
	}()
}

// onV2EpochRotated 处理 V2 epoch 轮换事件：清除 bootstrap 缓存 + 触发 SPK rotation。
func (c *AUNClient) onV2EpochRotated(data any) {
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

	// 清除 group bootstrap 缓存
	state := c.v2GetState()
	if state != nil {
		state.bootstrapCacheM.Lock()
		delete(state.groupBootstrapCache, groupID)
		state.bootstrapCacheM.Unlock()
	}

	// 触发 SPK rotation
	if state != nil && state.session != nil {
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
}

func (c *AUNClient) onV2StateProposed(data any) {
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
	c.events.Publish("group.v2.state_proposed", data)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c.v2ConfirmPendingProposal(ctx, groupID)
	}()
}

func (c *AUNClient) onV2StateRetryNeeded(data any) {
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
	c.events.Publish("group.v2.state_retry_needed", data)
	go c.v2AutoProposeStateFromEvent(context.Background(), groupID)
}

func (c *AUNClient) onV2StateConfirmed(data any) {
	dataMap, ok := data.(map[string]any)
	if !ok {
		return
	}
	groupID := strings.TrimSpace(v2AsString(dataMap["group_id"]))
	if groupID != "" {
		state := c.v2GetState()
		if state != nil {
			state.bootstrapCacheM.Lock()
			delete(state.groupBootstrapCache, groupID)
			state.bootstrapCacheM.Unlock()
		}
		c.v2AutoProposeLocksMu.Lock()
		delete(c.v2AutoProposeLastSnapshot, groupID)
		c.v2AutoProposeLocksMu.Unlock()
	}
	c.events.Publish("group.v2.state_confirmed", data)
}

// onRawGroupChangedV2 在 onRawGroupChanged 中追加的 V2 逻辑：
//   - 清 V2 group bootstrap 缓存
//   - owner/admin 时触发 auto_propose_state
//   - 成员变更触发 group SPK 注册/轮换
func (c *AUNClient) onRawGroupChangedV2(groupID string, action string, data map[string]any) {
	if groupID == "" {
		return
	}

	// 清除 V2 group bootstrap 缓存
	state := c.v2GetState()
	if state != nil {
		state.bootstrapCacheM.Lock()
		delete(state.groupBootstrapCache, groupID)
		state.bootstrapCacheM.Unlock()
	}

	membershipAction := action == "member_added" ||
		action == "member_left" ||
		action == "member_removed" ||
		action == "role_changed" ||
		action == "owner_transferred" ||
		action == "joined" ||
		action == "join_approved" ||
		action == "invite_code_used"

	// V2 自动 propose_state：owner/admin 在成员变更后自动提交 state proposal
	if (action == "upsert" || membershipAction) && state != nil && state.session != nil {
		go c.v2AutoProposeStateFromEvent(context.Background(), groupID)
	}

	// Group SPK 编排：成员变更触发注册/轮换
	if state != nil && state.session != nil {
		if membershipAction {
			joinedAID := strings.TrimSpace(stringFromAny(data["joined_aid"]))
			if joinedAID == "" {
				joinedAID = strings.TrimSpace(stringFromAny(data["member_aid"]))
			}
			if joinedAID == "" {
				joinedAID = strings.TrimSpace(stringFromAny(data["aid"]))
			}
			actorAID := strings.TrimSpace(stringFromAny(data["actor_aid"]))
			selfAID := strings.TrimSpace(c.GetAID())
			joinAction := action == "member_added" || action == "joined" || action == "join_approved" || action == "invite_code_used"
			isSelfJoin := joinAction && selfAID != "" &&
				(joinedAID == selfAID || (joinedAID == "" && (action == "joined" || action == "invite_code_used") && actorAID == selfAID))

			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if isSelfJoin {
					if err := state.session.EnsureGroupRegistered(ctx, groupID, c.v2CallFn()); err != nil {
						c.logE2.Debug("group SPK registration failed (non-fatal): group=%s action=%s err=%v", groupID, action, err)
					} else {
						c.logE2.Debug("group SPK registered: group=%s action=%s", groupID, action)
					}
				} else {
					if err := state.session.RotateGroupSPK(ctx, groupID, c.v2CallFn()); err != nil {
						c.logE2.Debug("group SPK rotation failed (non-fatal): group=%s action=%s err=%v", groupID, action, err)
					} else {
						c.logE2.Debug("group SPK rotated: group=%s action=%s", groupID, action)
					}
				}
			}()
		}
	}
}
