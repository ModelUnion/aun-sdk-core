package aun

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// pullGateKeyForCall 根据 RPC method 和 params 返回 pull gate key。
// 空字符串表示该调用不需要 pull gate 保护。
func (c *AUNClient) pullGateKeyForCall(method string, params map[string]any) string {
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
func (c *AUNClient) tryAcquirePullGate(key string) (uint64, bool) {
	if key == "" {
		return 0, true
	}
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
func (c *AUNClient) releasePullGate(key string, token uint64) {
	if key == "" {
		return
	}
	actual, ok := c.pullGates.Load(key)
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
// gate 被占时短等待后重试，超时则返回 StateError。
func (c *AUNClient) runPullSerialized(ctx context.Context, key string, operation func() (any, error)) (any, error) {
	token, acquired := c.tryAcquirePullGate(key)
	if !acquired {
		staleMs := atomic.LoadInt64(&c.pullGateStaleMs)
		deadline := time.Now().Add(time.Duration(staleMs+100) * time.Millisecond)
		for !acquired && time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return nil, NewStateError(fmt.Sprintf("pull already in-flight for %s", key))
			case <-time.After(25 * time.Millisecond):
			}
			token, acquired = c.tryAcquirePullGate(key)
		}
		if !acquired {
			return nil, NewStateError(fmt.Sprintf("pull already in-flight for %s", key))
		}
	}
	defer c.releasePullGate(key, token)
	return operation()
}
