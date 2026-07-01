// v2_events.go — V2 事件订阅 + push 通知 + SPK rotation 触发。
//
// 与 Python aun_core.client 的对应方法对齐：
//   - _on_v2_push_notification → onV2PushNotification
//   - _on_raw_group_changed 中的 V2 逻辑 → 追加到 onRawGroupChanged

package aun

// registerV2EventSubscriptions 在 client 构造时注册 V2 相关事件订阅。
// 在 NewClient 的事件订阅区块中调用。
func (c *AUNClient) registerV2EventSubscriptions() {
	// V2 P2P push 通知：自动 pull + decrypt + emit
	c.events.Subscribe("_raw.peer.v2.message_received", func(payload any) {
		c.onV2PushNotification(payload)
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
	c.delivery().onV2PushNotification(data)
}

// onV2GroupPushNotification 处理 V2 群 push 通知：自动 pull + decrypt + emit。
func (c *AUNClient) onV2GroupPushNotification(data any) {
	c.delivery().onV2GroupPushNotification(data)
}

func (c *AUNClient) onV2StateProposed(data any) {
	c.getGroupStateCoordinator().onV2StateProposed(data)
}

func (c *AUNClient) onV2StateRetryNeeded(data any) {
	c.getGroupStateCoordinator().onV2StateRetryNeeded(data)
}

func (c *AUNClient) onV2StateConfirmed(data any) {
	c.getGroupStateCoordinator().onV2StateConfirmed(data)
}

// onRawGroupChangedV2 在 onRawGroupChanged 中追加的 V2 逻辑：
//   - 清 V2 group bootstrap 缓存
//   - owner/admin 时触发 auto_propose_state
//   - 成员变更触发 group SPK 注册/轮换
func (c *AUNClient) onRawGroupChangedV2(groupID string, action string, data map[string]any) {
	c.getGroupStateCoordinator().handleGroupChangedV2Membership(groupID, action, data)
}
