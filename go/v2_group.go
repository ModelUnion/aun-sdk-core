// v2_group.go — V2 Group E2EE 集成（send_group_v2 / pull_group_v2 / ack_group_v2）。
//
// 与 Python aun_core.client 的对应方法对齐：
//   - send_group_v2  → SendGroupV2
//   - pull_group_v2  → PullGroupV2
//   - ack_group_v2   → AckGroupV2
//
// 与 P2P 的关键差异：
//   - bootstrap RPC: group.v2.bootstrap（参数 group_id，返回 devices + epoch + state_*）
//   - 缓存 key: groupID（存储在 v2P2PState.groupBootstrapCache）
//   - 排除自己当前设备（dev.aid == self.aid && dev.device_id == self.deviceID）
//   - 同 AID 其它设备 role="self_sync"
//   - 发送 RPC: group.v2.send（参数 group_id + envelope）
//   - pull RPC: group.v2.pull（参数 group_id + after_seq + limit）
//   - ack RPC: group.v2.ack（参数 group_id + up_to_seq）
//   - pull 返回的消息加 group_id 字段
//   - 重试关键字多一个 "epoch"
//   - Group 不触发 PFS SPK 销毁

package aun

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelunion/aun-sdk-core/go/v2/e2ee"
)

// v2GroupBootstrapTTL 群 bootstrap 缓存有效期。
const v2GroupBootstrapTTL = time.Hour
const v2GroupSendIdempotencyTTL = 10 * time.Minute
const v2GroupSendIdempotencyMaxEntries = 512

type v2GroupSendIdempotencyEntry struct {
	Envelope  map[string]any
	Result    map[string]any
	UpdatedAt time.Time
}

// v2GroupBootstrapEntry 群 bootstrap 缓存项。
type v2GroupBootstrapEntry struct {
	Devices         []map[string]any
	AuditRecipients []map[string]any
	Epoch           int
	StateCommitment *e2ee.StateCommitmentAAD
	CachedAt        time.Time
	WrapPolicy      *v2WrapPolicy
}

func v2GroupSendIdempotencyKey(groupID, messageID string) string {
	groupID = strings.TrimSpace(groupID)
	messageID = strings.TrimSpace(messageID)
	if groupID == "" || messageID == "" {
		return ""
	}
	return groupID + "\x00" + messageID
}

func (v *v2E2EECoordinator) pruneGroupSendIdempotencyLocked(now time.Time) {
	if v.groupSendIdempotency == nil {
		v.groupSendIdempotency = make(map[string]v2GroupSendIdempotencyEntry)
		return
	}
	for key, entry := range v.groupSendIdempotency {
		if entry.UpdatedAt.IsZero() || now.Sub(entry.UpdatedAt) > v2GroupSendIdempotencyTTL {
			delete(v.groupSendIdempotency, key)
		}
	}
	if len(v.groupSendIdempotency) <= v2GroupSendIdempotencyMaxEntries {
		return
	}
	target := v2GroupSendIdempotencyMaxEntries / 2
	for key := range v.groupSendIdempotency {
		delete(v.groupSendIdempotency, key)
		if len(v.groupSendIdempotency) <= target {
			break
		}
	}
}

func (v *v2E2EECoordinator) getGroupSendCachedResult(key string) (map[string]any, bool) {
	if key == "" {
		return nil, false
	}
	v.groupSendIdempotencyMu.Lock()
	defer v.groupSendIdempotencyMu.Unlock()
	v.pruneGroupSendIdempotencyLocked(time.Now())
	entry, ok := v.groupSendIdempotency[key]
	if !ok || entry.Result == nil {
		return nil, false
	}
	return copyMapShallow(entry.Result), true
}

func (v *v2E2EECoordinator) getGroupSendCachedEnvelope(key string) (map[string]any, bool) {
	if key == "" {
		return nil, false
	}
	v.groupSendIdempotencyMu.Lock()
	defer v.groupSendIdempotencyMu.Unlock()
	v.pruneGroupSendIdempotencyLocked(time.Now())
	entry, ok := v.groupSendIdempotency[key]
	if !ok || entry.Envelope == nil {
		return nil, false
	}
	return copyMapShallow(entry.Envelope), true
}

func (v *v2E2EECoordinator) rememberGroupSendEnvelope(key string, envelope map[string]any) {
	if key == "" || envelope == nil {
		return
	}
	v.groupSendIdempotencyMu.Lock()
	defer v.groupSendIdempotencyMu.Unlock()
	now := time.Now()
	v.pruneGroupSendIdempotencyLocked(now)
	entry := v.groupSendIdempotency[key]
	entry.Envelope = copyMapShallow(envelope)
	entry.UpdatedAt = now
	v.groupSendIdempotency[key] = entry
}

func (v *v2E2EECoordinator) rememberGroupSendResult(key string, result map[string]any) {
	if key == "" || result == nil {
		return
	}
	v.groupSendIdempotencyMu.Lock()
	defer v.groupSendIdempotencyMu.Unlock()
	now := time.Now()
	v.pruneGroupSendIdempotencyLocked(now)
	entry := v.groupSendIdempotency[key]
	entry.Result = copyMapShallow(result)
	entry.UpdatedAt = now
	v.groupSendIdempotency[key] = entry
}

func (v *v2E2EECoordinator) dropGroupSendIdempotency(key string) {
	if key == "" {
		return
	}
	v.groupSendIdempotencyMu.Lock()
	delete(v.groupSendIdempotency, key)
	v.groupSendIdempotencyMu.Unlock()
}

// SendGroupV2 V2 Group 加密发送（推测性：用缓存 bootstrap 直接发，失败刷新重试一次）。
func (v *v2E2EECoordinator) sendGroupV2(ctx context.Context, groupID string, payload map[string]any) (map[string]any, error) {
	return v.SendGroupV2WithOpts(ctx, groupID, payload, e2ee.EncryptOptions{})
}

// SendGroupV2WithOpts 与 SendGroupV2 相同，但允许传入 EncryptOptions（含 ProtectedHeaders / Context）。
func (v *v2E2EECoordinator) SendGroupV2WithOpts(ctx context.Context, groupID string, payload map[string]any, opts e2ee.EncryptOptions) (map[string]any, error) {
	c := v.runtime.client
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return nil, errors.New("V2 session not initialized (not connected?)")
	}
	groupID = groupAIDOrRaw(groupID)
	if groupID == "" {
		return nil, errors.New("send_group_v2: group_id 不能为空")
	}
	c.logMessageDebugWithPayload("send-plaintext", "group.send.v2", "group.send", map[string]any{
		"group_id":  groupID,
		"group_aid": groupID,
		"payload":   payload,
	}, payload, nil)
	resultParams := map[string]any{
		"group_id":          groupID,
		"group_aid":         groupID,
		"payload":           payload,
		"protected_headers": opts.ProtectedHeaders,
		"context":           opts.Context,
	}
	if opts.Timestamp > 0 {
		resultParams["timestamp"] = opts.Timestamp
	}

	idempotencyKey := v2GroupSendIdempotencyKey(groupID, opts.MessageID)
	if cachedResult, ok := v.getGroupSendCachedResult(idempotencyKey); ok {
		c.logE2.Debug("group.v2.send cached result hit: group=%s message_id=%s", groupID, opts.MessageID)
		return c.delivery().attachSendResultEnvelope("group.send", resultParams, cachedResult, true).(map[string]any), nil
	}

	resp, err := v.v2GroupSendOnce(ctx, state, groupID, payload, true, opts)
	if err == nil {
		v.rememberGroupSendResult(idempotencyKey, resp)
		return c.delivery().attachSendResultEnvelope("group.send", resultParams, resp, true).(map[string]any), nil
	}
	if isV2RetryableError(err) {
		c.logE2.Debug("V2 Group speculative send rejected (code=%d), refreshing bootstrap", v2ErrorCode(err))
		v.deleteGroupBootstrapCache(groupID)
		v.dropGroupSendIdempotency(idempotencyKey)
		resp, retryErr := v.v2GroupSendOnce(ctx, state, groupID, payload, false, opts)
		if retryErr != nil {
			return nil, retryErr
		}
		v.rememberGroupSendResult(idempotencyKey, resp)
		return c.delivery().attachSendResultEnvelope("group.send", resultParams, resp, true).(map[string]any), nil
	}
	return nil, err
}

// v2GroupSendOnce 单次 group 发送尝试。
func (v *v2E2EECoordinator) v2GroupSendOnce(ctx context.Context, state *v2P2PState, groupID string, payload map[string]any, useCache bool, opts e2ee.EncryptOptions) (map[string]any, error) {
	c := v.runtime.client
	c.logE2.Debug("group.v2.send attempt: group=%s use_cache=%v", groupID, useCache)
	idempotencyKey := v2GroupSendIdempotencyKey(groupID, opts.MessageID)
	if cachedEnvelope, ok := v.getGroupSendCachedEnvelope(idempotencyKey); ok {
		c.logE2.Debug("group.v2.send reuse cached envelope: group=%s message_id=%s", groupID, opts.MessageID)
		raw, err := c.Call(ctx, "group.v2.send", map[string]any{
			"group_id":  groupID,
			"group_aid": groupID,
			"envelope":  cachedEnvelope,
		})
		if err != nil {
			return nil, err
		}
		if m, ok := raw.(map[string]any); ok {
			c.logE2.Debug("group.v2.send ok: group=%s cached_envelope=true seq=%d", groupID, toInt64(m["seq"]))
			return m, nil
		}
		c.logE2.Debug("group.v2.send ok: group=%s cached_envelope=true seq=<unknown>", groupID)
		return map[string]any{}, nil
	}

	allDevices, epoch, sc, auditRaw, wrapPolicy, usedCachedBootstrap, err := v.v2ResolveGroupBootstrap(ctx, state, groupID, useCache)
	if err != nil {
		return nil, err
	}
	if len(allDevices) == 0 {
		return nil, fmt.Errorf("V2 group bootstrap: no devices found for group %s", groupID)
	}

	targetSet, err := v.v2GroupTargetSet(ctx, state, groupID, allDevices, auditRaw, wrapPolicy, useCache)
	if err != nil {
		return nil, err
	}
	sendTargets := targetSet.Targets

	if len(sendTargets) == 0 {
		if usedCachedBootstrap {
			return nil, NewAUNError(
				fmt.Sprintf("V2 group: no target devices for group %s; bootstrap may be stale", groupID),
				WithCode(-33054),
				WithData(map[string]any{"expected_peer_aids": []string{}}),
			)
		}
		return nil, fmt.Errorf("V2 group: no target devices for group %s", groupID)
	}

	sender, err := state.session.GetSenderIdentity()
	if err != nil {
		return nil, fmt.Errorf("send_group_v2: 获取 sender identity 失败: %w", err)
	}

	envelope, err := e2ee.EncryptGroupMessage(
		e2ee.Sender{
			AID:      sender.AID,
			DeviceID: sender.DeviceID,
			IKPriv:   sender.IKPriv,
			IKPubDER: sender.IKPubDER,
		},
		groupID,
		epoch,
		sendTargets,
		payload,
		opts,
		sc,
	)
	if err != nil {
		return nil, fmt.Errorf("send_group_v2: 加密失败: %w", err)
	}
	c.logMessageDebugWithPayload("send-envelope", "group.send.v2", "group.send", map[string]any{
		"group_id":   groupID,
		"message_id": envelope["message_id"],
		"type":       envelope["type"],
		"version":    envelope["version"],
	}, envelope, map[string]any{
		"plaintext_payload": payload,
		"epoch":             epoch,
		"target_count":      len(sendTargets),
		"audit_count":       len(auditRaw),
		"use_cache":         useCache,
	})
	v.rememberGroupSendEnvelope(idempotencyKey, envelope)

	raw, err := c.Call(ctx, "group.v2.send", map[string]any{
		"group_id":  groupID,
		"group_aid": groupID,
		"envelope":  envelope,
	})
	if err != nil {
		return nil, err
	}
	if m, ok := raw.(map[string]any); ok {
		c.logE2.Debug("group.v2.send ok: group=%s use_cache=%v seq=%d", groupID, useCache, toInt64(m["seq"]))
		return m, nil
	}
	c.logE2.Debug("group.v2.send ok: group=%s use_cache=%v seq=<unknown>", groupID, useCache)
	return map[string]any{}, nil
}

// v2ResolveGroupBootstrap 解析群 bootstrap（缓存优先）。
// 返回 (devices, epoch, stateCommitment, auditRecipients, wrapPolicy, usedCachedBootstrap, error)。
func (v *v2E2EECoordinator) v2ResolveGroupBootstrap(ctx context.Context, state *v2P2PState, groupID string, useCache bool) ([]map[string]any, int, *e2ee.StateCommitmentAAD, []map[string]any, *v2WrapPolicy, bool, error) {
	c := v.runtime.client
	if useCache {
		entry, ok := v.getGroupBootstrapCache(state, groupID)
		if ok && time.Since(entry.CachedAt) < v2GroupBootstrapTTL {
			c.logE2.Debug("group.v2.bootstrap cache hit: group=%s devices=%d audit=%d epoch=%d", groupID, len(entry.Devices), len(entry.AuditRecipients), entry.Epoch)
			return entry.Devices, entry.Epoch, entry.StateCommitment, entry.AuditRecipients, entry.WrapPolicy, true, nil
		}
	}

	raw, err := c.Call(ctx, "group.v2.bootstrap", map[string]any{
		"group_id":               groupID,
		"group_aid":              groupID,
		"e2ee_wrap_capabilities": v2WrapCapabilities(),
	})
	if err != nil {
		return nil, 0, nil, nil, nil, false, fmt.Errorf("V2 group bootstrap: %w", err)
	}
	bs, _ := raw.(map[string]any)
	devices := v2ToMapList(bs["devices"])
	epoch := int(toInt64(bs["epoch"]))
	auditRecipients := v2ToMapList(bs["audit_recipients"])
	wrapPolicy := v2NormalizeWrapPolicy(bs["e2ee_wrap_policy"])
	c.logE2.Debug("group.v2.bootstrap fetched: group=%s devices=%d audit=%d epoch=%d members=%d", groupID, len(devices), len(auditRecipients), epoch, len(v2ToStringList(bs["member_aids"])))

	c.v2CheckFork(ctx, groupID, v2AsString(bs["state_chain"]))
	if err := c.v2VerifyStateSignature(ctx, groupID, bs); err != nil {
		return nil, 0, nil, nil, nil, false, err
	}
	c.getGroupStateCoordinator().publishGroupSecurityLevel(groupID, bs)

	// 提取 state_commitment
	sc := &e2ee.StateCommitmentAAD{
		StateVersion: int(toInt64(bs["state_version"])),
		StateHash:    v2AsString(bs["state_hash_signed"]),
		StateChain:   v2AsString(bs["state_chain"]),
	}
	if sc.StateHash == "" {
		sc.StateHash = v2AsString(bs["state_hash"])
	}

	if len(devices) > 0 {
		v.setGroupBootstrapCache(state, groupID, &v2GroupBootstrapEntry{
			Devices:         devices,
			AuditRecipients: auditRecipients,
			Epoch:           epoch,
			StateCommitment: sc,
			CachedAt:        time.Now(),
			WrapPolicy:      wrapPolicy,
		})
	}
	// lazy sync 触发：发现 pending members 时异步发起提案
	pendingAdds := v2ToStringList(bs["pending_adds"])
	if len(pendingAdds) > 0 {
		c.v2MaybeTriggerAutoPropose(groupID)
	}
	return devices, epoch, sc, auditRecipients, wrapPolicy, false, nil
}

type groupV2PullOptions struct {
	explicitAfterSeq bool
	cursorParams     map[string]any
	wireGroupID      string
	ackUpToSeq       int64
}

// PullGroupV2 拉取并解密 V2 Group 消息。
//
// afterSeq=0 时使用本地 SeqTracker 的 contiguous_seq（ns = "group:" + groupID）。
// limit<=0 时默认 50。
func (v *v2E2EECoordinator) pullGroupV2(ctx context.Context, groupID string, afterSeq int64, limit int) ([]map[string]any, error) {
	c := v.runtime.client
	rawGroupID := strings.TrimSpace(groupID)
	groupAID := groupAIDOrRaw(rawGroupID)
	if groupAID == "" {
		return nil, errors.New("pull_group_v2: group_id 不能为空")
	}
	if limit <= 0 {
		limit = 50
	}
	ns := "group:" + groupAID
	nextAfterSeq := afterSeq
	if nextAfterSeq == 0 {
		nextAfterSeq = int64(c.seqTracker.GetContiguousSeq(ns))
	}
	allMsgs := make([]map[string]any, 0)
	lastAutoAckSeq := int64(0)
	pendingAckSeq := int64(0)
	for pageCount := 0; pageCount < 100; pageCount++ {
		pageContigBefore := c.seqTracker.GetContiguousSeq(ns)
		ackUpToSeq := pendingAckSeq
		msgs, pageMeta, err := v.pullGroupV2WithOptions(ctx, groupAID, nextAfterSeq, limit, groupV2PullOptions{
			ackUpToSeq:  ackUpToSeq,
			wireGroupID: rawGroupID,
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
			allMsgs = append(allMsgs, msgs...)
		}
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
					c.logE2.Debug("group.v2.pull queued piggyback auto-ack: group=%s ns=%s ack_seq=%d raw_count=%d", groupAID, ns, pendingAckSeq, pageMeta.rawCount)
				} else {
					if _, err := v.ackGroupV2(ctx, groupAID, ackSeq); err != nil {
						return nil, err
					}
					if ackSeq > lastAutoAckSeq {
						lastAutoAckSeq = ackSeq
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
		if _, err := v.ackGroupV2(ctx, groupAID, pendingAckSeq); err != nil {
			return nil, err
		}
	}
	return allMsgs, nil
}

func (v *v2E2EECoordinator) pullGroupV2WithOptions(ctx context.Context, groupID string, afterSeq int64, limit int, opts groupV2PullOptions) ([]map[string]any, v2PullPageMeta, error) {
	c := v.runtime.client
	meta := v2PullPageMeta{}
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return nil, meta, errors.New("V2 session not initialized (not connected?)")
	}
	rawGroupID := strings.TrimSpace(groupID)
	groupID = groupAIDOrRaw(rawGroupID)
	if groupID == "" {
		return nil, meta, errors.New("pull_group_v2: group_id 不能为空")
	}
	wireGroupID := strings.TrimSpace(opts.wireGroupID)
	if wireGroupID == "" {
		wireGroupID = rawGroupID
	}
	if wireGroupID == "" {
		wireGroupID = groupID
	}
	if limit <= 0 {
		limit = 50
	}

	ns := "group:" + groupID
	effectiveAfterSeq := afterSeq
	if !opts.explicitAfterSeq && effectiveAfterSeq == 0 {
		effectiveAfterSeq = int64(c.seqTracker.GetContiguousSeq(ns))
	}

	c.logE2.Debug("group.v2.pull request: group=%s after_seq=%d limit=%d ack_up_to_seq=%d ns=%s", groupID, effectiveAfterSeq, limit, opts.ackUpToSeq, ns)
	raw, err := v.rawGroupV2Pull(ctx, wireGroupID, groupID, effectiveAfterSeq, limit, opts.cursorParams, opts.ackUpToSeq)
	if err != nil {
		return nil, meta, err
	}
	result, _ := raw.(map[string]any)
	pageMessages := v2ToMapList(result["messages"])
	messages := make([]map[string]any, 0, len(pageMessages))
	for _, msg := range pageMessages {
		if toInt64(msg["seq"]) > effectiveAfterSeq {
			messages = append(messages, msg)
		}
	}
	serverAckSeq := int64(0)
	hasServerAckSeq := false
	if cursor, ok := result["cursor"].(map[string]any); ok {
		_, hasServerAckSeq = cursor["current_seq"]
		serverAckSeq = toInt64(cursor["current_seq"])
	}
	meta = v2PullPageMeta{
		rawCount:     len(messages),
		serverAckSeq: serverAckSeq,
		hasServerAck: hasServerAckSeq,
	}
	c.logE2.Debug("group.v2.pull response: group=%s raw_count=%d stale_count=%d cursor_current=%d has_more=%v", groupID, len(messages), len(pageMessages)-len(messages), serverAckSeq, result["has_more"])
	for _, msg := range messages {
		c.logMessageDebug("pull-raw", "group.v2.pull", "group.message_created", msg, nil)
	}

	decrypted := make([]map[string]any, 0, len(messages))
	contigBefore := c.seqTracker.GetContiguousSeq(ns)
	maxSeq := int64(0)
	for _, msg := range messages {
		seq := toInt64(msg["seq"])
		if seq <= 0 {
			continue
		}
		if seq > maxSeq {
			maxSeq = seq
		}
	}
	meta.latestSeq = maxSeq

	if v.canParallelDecryptV2Page(messages, groupID, false) {
		for _, plaintext := range v.decryptV2PageParallel(ctx, state, messages, groupID, false) {
			if plaintext != nil {
				plaintext["group_id"] = groupID
				decrypted = append(decrypted, plaintext)
				c.logMessageDebug("decrypt-ok", "group.v2.pull", "group.message_created", plaintext, nil)
			}
		}
	} else {
		for _, msg := range messages {
			seq := toInt64(msg["seq"])
			if seq <= 0 {
				continue
			}

			if v2AsString(msg["version"]) == "v1" {
				if legacy, ok := v2BuildLegacyGroupMessage(msg, groupID); ok {
					decrypted = append(decrypted, legacy)
					c.logE2.Debug("group.v2.pull plaintext V1 decrypted: group=%s seq=%d", groupID, seq)
				} else {
					c.logE2.Debug("V2 group pull skipped legacy V1 encrypted/empty message: group=%s seq=%d", groupID, seq)
				}
				continue
			}

			plaintext := c.decryptV2Message(ctx, state, msg)
			if plaintext != nil {
				plaintext["group_id"] = groupID
				decrypted = append(decrypted, plaintext)
				c.logMessageDebug("decrypt-ok", "group.v2.pull", "group.message_created", plaintext, nil)
			} else {
				c.logE2.Debug("group.v2.pull decrypt returned nil: group=%s seq=%d", groupID, seq)
			}
			// Group 不跟踪旧 SPK（不触发 PFS 销毁）
		}
	}

	if maxSeq > 0 {
		currentContig := c.seqTracker.GetContiguousSeq(ns)
		if int(maxSeq) > currentContig {
			c.seqTracker.ForceContiguousSeq(ns, int(maxSeq))
			c.logE2.Debug("V2 group pull force-advanced contig: group=%s %d -> %d", groupID, currentContig, maxSeq)
			c.drainOrderedMessages(ns)
		}
	}
	if serverAckSeq > 0 {
		currentContig := c.seqTracker.GetContiguousSeq(ns)
		if int(serverAckSeq) > currentContig {
			c.seqTracker.ForceContiguousSeq(ns, int(serverAckSeq))
			c.logE2.Info("V2 group pull retention-floor advanced: ns=%s contiguous=%d -> cursor.current_seq=%d", ns, currentContig, serverAckSeq)
			c.drainOrderedMessages(ns)
		}
	}
	if c.seqTracker.GetContiguousSeq(ns) != contigBefore {
		c.persistSeq(ns)
	}

	c.logE2.Debug("group.v2.pull done: group=%s requested_after_seq=%d raw_count=%d decrypted=%d ns=%s", groupID, afterSeq, len(messages), len(decrypted), ns)
	return decrypted, meta, nil
}

func (v *v2E2EECoordinator) rawGroupV2Pull(ctx context.Context, wireGroupID string, groupID string, afterSeq int64, limit int, cursorParams map[string]any, ackUpToSeq int64) (any, error) {
	c := v.runtime.client
	wireGroupID = strings.TrimSpace(wireGroupID)
	groupID = groupAIDOrRaw(groupID)
	if wireGroupID == "" {
		wireGroupID = groupID
	}
	params := map[string]any{
		"group_id":  wireGroupID,
		"group_aid": groupID,
		"after_seq": afterSeq,
		"limit":     limit,
	}
	for k, v := range cursorParams {
		if v != nil {
			params[k] = v
		}
	}
	if ackUpToSeq > 0 {
		params["ack_up_to_seq"] = ackUpToSeq
	}
	if _, exists := params["device_id"]; !exists {
		params["device_id"] = c.deviceID
	}
	if _, exists := params["slot_id"]; !exists {
		params["slot_id"] = c.slotID
	}
	c.signClientOperation("group.v2.pull", params)
	if rpcBackgroundFromContext(ctx) {
		params["_rpc_background"] = true
	}
	return c.transport.Call(ctx, "group.v2.pull", params)
}

// AckGroupV2 确认 V2 群消息已消费。
//
// upToSeq=0 时使用本地 SeqTracker 的 contiguous_seq（ns = "group:" + groupID）。
// Group 不触发 PFS SPK 销毁。
func (v *v2E2EECoordinator) ackGroupV2(ctx context.Context, groupID string, upToSeq int64) (map[string]any, error) {
	c := v.runtime.client
	groupID = groupAIDOrRaw(groupID)
	if groupID == "" {
		return nil, errors.New("ack_group_v2: group_id 不能为空")
	}

	ns := "group:" + groupID
	seq := upToSeq
	if seq == 0 {
		seq = int64(c.seqTracker.GetContiguousSeq(ns))
	}
	if seq <= 0 {
		c.logE2.Debug("group.v2.ack skipped: group=%s ns=%s up_to_seq=%d", groupID, ns, upToSeq)
		return map[string]any{"acked": int64(0)}, nil
	}
	seq = c.clampAckSeq("group.v2.ack", "up_to_seq", ns, seq)
	if seq <= 0 {
		return map[string]any{"acked": int64(0)}, nil
	}

	c.logE2.Debug("group.v2.ack send: group=%s ns=%s up_to_seq=%d", groupID, ns, seq)
	ackParams := map[string]any{
		"group_id":  groupID,
		"group_aid": groupID,
		"up_to_seq": seq,
	}
	if rpcBackgroundFromContext(ctx) {
		ackParams["_rpc_background"] = true
	}
	raw, err := c.Call(ctx, "group.v2.ack", ackParams)
	if err != nil {
		return nil, err
	}
	result, _ := raw.(map[string]any)
	if result == nil {
		result = map[string]any{}
	}
	c.logE2.Debug("group.v2.ack ok: group=%s ns=%s requested=%d result=%v", groupID, ns, seq, result)
	return result, nil
}

// AUNClient 兼容门面：V2 Group 主体逻辑由 V2E2EECoordinator 承接。
func (c *AUNClient) sendGroupV2(ctx context.Context, groupID string, payload map[string]any) (map[string]any, error) {
	return c.getV2E2EECoordinator().sendGroupV2(ctx, groupID, payload)
}

func (c *AUNClient) SendGroupV2WithOpts(ctx context.Context, groupID string, payload map[string]any, opts e2ee.EncryptOptions) (map[string]any, error) {
	return c.getV2E2EECoordinator().SendGroupV2WithOpts(ctx, groupID, payload, opts)
}

func (c *AUNClient) v2ResolveGroupBootstrap(ctx context.Context, state *v2P2PState, groupID string, useCache bool) ([]map[string]any, int, *e2ee.StateCommitmentAAD, []map[string]any, *v2WrapPolicy, error) {
	devices, epoch, sc, audit, wrapPolicy, _, err := c.getV2E2EECoordinator().v2ResolveGroupBootstrap(ctx, state, groupID, useCache)
	return devices, epoch, sc, audit, wrapPolicy, err
}

func (c *AUNClient) pullGroupV2(ctx context.Context, groupID string, afterSeq int64, limit int) ([]map[string]any, error) {
	return c.getV2E2EECoordinator().pullGroupV2(ctx, groupID, afterSeq, limit)
}

func (c *AUNClient) pullGroupV2WithOptions(ctx context.Context, groupID string, afterSeq int64, limit int, opts groupV2PullOptions) ([]map[string]any, v2PullPageMeta, error) {
	return c.getV2E2EECoordinator().pullGroupV2WithOptions(ctx, groupID, afterSeq, limit, opts)
}

func (c *AUNClient) rawGroupV2Pull(ctx context.Context, groupID string, afterSeq int64, limit int, cursorParams map[string]any) (any, error) {
	return c.getV2E2EECoordinator().rawGroupV2Pull(ctx, groupID, groupAIDOrRaw(groupID), afterSeq, limit, cursorParams, 0)
}

func (c *AUNClient) ackGroupV2(ctx context.Context, groupID string, upToSeq int64) (map[string]any, error) {
	return c.getV2E2EECoordinator().ackGroupV2(ctx, groupID, upToSeq)
}
