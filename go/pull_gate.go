package aun

import (
	"context"
)

// pullGateKeyForCall 根据 RPC method 和 params 返回 pull gate key。
// 空字符串表示该调用不需要 pull gate 保护。
func (c *AUNClient) pullGateKeyForCall(method string, params map[string]any) string {
	return c.getRpcPipeline().pullGateKeyForCall(method, params)
}

// tryAcquirePullGate 尝试获取 pull gate。
// 返回 (token, true) 表示成功获取；(0, false) 表示当前有 inflight 且未过期。
func (c *AUNClient) tryAcquirePullGate(key string) (uint64, bool) {
	return c.getRpcPipeline().tryAcquirePullGate(key)
}

// releasePullGate 释放 pull gate（仅当 token 匹配时）。
func (c *AUNClient) releasePullGate(key string, token uint64) {
	c.getRpcPipeline().releasePullGate(key, token)
}

// runPullSerialized 获取 pull gate → 执行操作 → 释放。
// gate 被占时短等待后重试，超时则返回 StateError。
func (c *AUNClient) runPullSerialized(ctx context.Context, key string, operation func() (any, error)) (any, error) {
	return c.getRpcPipeline().runPullSerialized(ctx, key, operation)
}
