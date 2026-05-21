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
// per-namespace only one in flight + drain pending：如果已有 pull 在执行，标记 pending，
// pull 完成后会再拉一次（确保不丢消息）。
func (c *AUNClient) onV2PushNotification(data any) {
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return
	}
	// only one in flight：CAS 抢占，失败则标记 pending
	if !c.v2PushPullInflight.CompareAndSwap(false, true) {
		c.v2PushPullPending.Store(true)
		return
	}
	// 同时标记 gapFillDone，阻止 fillP2pGap 并发
	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	ns := "p2p:" + myAID
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
			if err != nil {
				c.logE2.Warn("V2 push auto-pull failed: %v", err)
				return
			}
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
	if c.isPushedSeq(ns, seq) {
		return
	}
	afterSeq := c.seqTracker.GetContiguousSeq(ns)
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
func (c *AUNClient) onRawGroupChangedV2(groupID string, action string) {
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

	// V2 自动 propose_state：owner/admin 在成员变更后自动提交 state proposal
	// 与 Python 对齐：仅 action == "upsert" 时触发
	if action == "upsert" && state != nil && state.session != nil {
		go c.v2AutoProposeStateFromEvent(context.Background(), groupID)
	}
}
