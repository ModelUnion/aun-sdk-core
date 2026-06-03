// v2_state.go — V2 State 安全增强层（验签 + fork 检测 + auto_propose）。
//
// 与 Python aun_core.client 的对应方法对齐：
//   - _v2_verify_state_signature → v2VerifyStateSignature
//   - _v2_check_fork             → v2CheckFork
//   - _v2_auto_propose_state     → v2AutoProposeState
//   - _v2_auto_confirm_pending_proposals → v2AutoConfirmPendingProposals

package aun

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	v2crypto "github.com/modelunion/aun-sdk-core/go/v2/crypto"
)

// ── 常量 ──────────────────────────────────────────────

const (
	v2SigCacheTTL = 3600  // 秒
	v2SigCacheMax = 16384 // 最大缓存条目
)

// ── 状态字段（嵌入 v2P2PState 或 client 级别） ──────────────────

// v2StateSecurityState 聚合 state 验签 + fork 检测的运行时状态。
type v2StateSecurityState struct {
	sigCache   map[[32]byte]int64 // sha256(actor+payload+sig) → expiry_unix
	sigCacheMu sync.Mutex

	stateChains   map[string]v2StateChainEntry // group_id → (state_version, state_chain)
	stateChainsMu sync.Mutex

	groupSecurityLevels   map[string]string
	groupSecurityLevelsMu sync.Mutex
}

type v2StateChainEntry struct {
	Version int
	Chain   string
}

func newV2StateSecurityState() *v2StateSecurityState {
	return &v2StateSecurityState{
		sigCache:            make(map[[32]byte]int64),
		stateChains:         make(map[string]v2StateChainEntry),
		groupSecurityLevels: make(map[string]string),
	}
}

// v2GetSecurityState 获取或懒初始化安全状态。
func (c *AUNClient) v2GetSecurityState() *v2StateSecurityState {
	c.mu.RLock()
	st := c.v2Security
	c.mu.RUnlock()
	if st != nil {
		return st
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.v2Security == nil {
		c.v2Security = newV2StateSecurityState()
	}
	return c.v2Security
}

// ── v2VerifyStateSignature ──────────────────────────────────────────────

// v2VerifyStateSignature 验证 owner/admin 对 state 的 ECDSA 签名（防服务端篡改 bootstrap 字段）。
//
//   - 无签名（state_version=0 或新建群）→ 跳过
//   - 签名验证失败 → 返回 error
//   - 验证通过 → 校验 bootstrap 返回的 member_aids 是否在签名快照中
func (c *AUNClient) v2VerifyStateSignature(ctx context.Context, groupID string, bootstrap map[string]any) error {
	return c.getGroupStateCoordinator().verifyStateSignature(ctx, groupID, bootstrap)
}

// ── v2CheckFork ──────────────────────────────────────────────

// v2CheckFork 分叉检测：比对服务端 state_chain 与本地存储。
func (c *AUNClient) v2CheckFork(ctx context.Context, groupID string, serverChain string) {
	c.getGroupStateCoordinator().checkFork(ctx, groupID, serverChain)
}

// ── v2AutoProposeState ──────────────────────────────────────────────

// v2AutoProposeState 成员变更后自动 propose state（仅 owner/admin 执行）。
func (c *AUNClient) v2AutoProposeState(ctx context.Context, groupID string) {
	c.getGroupStateCoordinator().autoProposeState(ctx, groupID)
}

// v2AutoProposeStateFromEvent 用于 group.changed 事件触发的兜底提案。
// 直接成员变更调用方同步提案；事件路径先做在线 owner/admin leader 选举，非 leader jitter 后再兜底。
func (c *AUNClient) v2AutoProposeStateFromEvent(ctx context.Context, groupID string) {
	c.getGroupStateCoordinator().autoProposeStateFromEvent(ctx, groupID)
}

func (c *AUNClient) v2AutoProposeLeaderDelay(ctx context.Context, groupID string) bool {
	return c.getGroupStateCoordinator().autoProposeLeaderDelay(ctx, groupID)
}

func (c *AUNClient) v2AutoProposeLock(groupID string) *sync.Mutex {
	c.v2AutoProposeLocksMu.Lock()
	defer c.v2AutoProposeLocksMu.Unlock()
	if c.v2AutoProposeLocks == nil {
		c.v2AutoProposeLocks = make(map[string]*sync.Mutex)
	}
	if c.v2AutoProposeLastSnapshot == nil {
		c.v2AutoProposeLastSnapshot = make(map[string]string)
	}
	lock := c.v2AutoProposeLocks[groupID]
	if lock == nil {
		lock = &sync.Mutex{}
		c.v2AutoProposeLocks[groupID] = lock
	}
	return lock
}

func (c *AUNClient) v2ConfirmPendingProposal(ctx context.Context, groupID string) bool {
	return c.getGroupStateCoordinator().confirmPendingProposal(ctx, groupID)
}

// ── v2AutoConfirmPendingProposals ──────────────────────────────────────────────

// v2AutoConfirmPendingProposals Owner 上线时自动检查并签名确认 pending state proposals。
func (c *AUNClient) v2AutoConfirmPendingProposals(ctx context.Context) {
	c.getGroupStateCoordinator().autoConfirmPendingProposals(ctx)
}

// v2MaybeTriggerAutoPropose lazy sync 路径：发现 pending members 时异步触发 auto propose（去重 10s）。
func (c *AUNClient) v2MaybeTriggerAutoPropose(groupID string) {
	c.getGroupStateCoordinator().maybeTriggerAutoPropose(groupID)
}

// ── 辅助函数 ──────────────────────────────────────────────

// marshalSortedCompactJSON 生成 key 排序的紧凑 JSON（无空格，无换行）。
func marshalSortedCompactJSON(v map[string]any) ([]byte, error) {
	// 与 Python json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False) 对齐，
	// 复用 V2 canonical serializer，避免 encoding/json 的 HTML 过度转义。
	return v2crypto.CanonicalJSON(v), nil
}

func v2DecodeMembershipSnapshot(snapshot string) (map[string]any, bool) {
	var payload map[string]any
	decoder := json.NewDecoder(strings.NewReader(snapshot))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, false
	}
	if payload == nil {
		return nil, false
	}
	return payload, true
}

// v2ToStringList 把 any → []string（支持 []any 和 []string）。
func v2ToStringList(v any) []string {
	switch arr := v.(type) {
	case []string:
		return arr
	case []any:
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// v2ToAnySlice 把 []string 转为 []any（用于 JSON 序列化兼容）。
func v2ToAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
