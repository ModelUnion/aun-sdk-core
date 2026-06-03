package aun

import (
	"context"
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
	"github.com/modelunion/aun-sdk-core/go/v2/state"
)

type groupStateCoordinator struct {
	runtime *clientRuntime
}

func newGroupStateCoordinator(runtime *clientRuntime) *groupStateCoordinator {
	return &groupStateCoordinator{runtime: runtime}
}

func (g *groupStateCoordinator) postprocessResult(ctx context.Context, method string, params map[string]any, result any) {
	c := g.runtime.client
	if !isV2StateMembershipMethod(method) || c.v2GetState() == nil {
		return
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		return
	}
	if _, hasError := resultMap["error"]; hasError {
		return
	}
	groupID := extractGroupIDFromMutationResult(resultMap, params)
	if groupID == "" {
		return
	}
	c.v2AutoProposeState(ctx, groupID)
	if isV2StateSpkRegistrationMutationMethod(method) {
		c.getV2E2EECoordinator().scheduleGroupSpkRegistration(groupID, method)
	}
}

func (g *groupStateCoordinator) handleGroupChangedV2Membership(groupID string, action string, data map[string]any) {
	c := g.runtime.client
	groupID = NormalizeGroupID(strings.TrimSpace(groupID), "")
	if groupID == "" {
		return
	}

	state := c.v2GetState()
	c.getV2E2EECoordinator().deleteGroupBootstrapCache(groupID)
	membershipAction := isV2GroupMembershipAction(action)
	if (action == "upsert" || membershipAction) && state != nil && state.session != nil {
		go c.v2AutoProposeStateFromEvent(context.Background(), groupID)
	}
	c.getV2E2EECoordinator().handleGroupChangedSpk(groupID, action, data)
}

func (g *groupStateCoordinator) onV2StateProposed(data any) {
	c := g.runtime.client
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return
	}
	dataMap, ok := data.(map[string]any)
	if !ok {
		return
	}
	groupID := NormalizeGroupID(strings.TrimSpace(v2AsString(dataMap["group_id"])), "")
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

func (g *groupStateCoordinator) onV2StateRetryNeeded(data any) {
	c := g.runtime.client
	state := c.v2GetState()
	if state == nil || state.session == nil {
		return
	}
	dataMap, ok := data.(map[string]any)
	if !ok {
		return
	}
	groupID := NormalizeGroupID(strings.TrimSpace(v2AsString(dataMap["group_id"])), "")
	if groupID == "" {
		return
	}
	c.events.Publish("group.v2.state_retry_needed", data)
	go c.v2AutoProposeStateFromEvent(context.Background(), groupID)
}

func (g *groupStateCoordinator) onV2StateConfirmed(data any) {
	c := g.runtime.client
	dataMap, ok := data.(map[string]any)
	if !ok {
		return
	}
	groupID := NormalizeGroupID(strings.TrimSpace(v2AsString(dataMap["group_id"])), "")
	if groupID != "" {
		c.getV2E2EECoordinator().deleteGroupBootstrapCache(groupID)
		c.v2AutoProposeLocksMu.Lock()
		delete(c.v2AutoProposeLastSnapshot, groupID)
		c.v2AutoProposeLocksMu.Unlock()
	}
	c.events.Publish("group.v2.state_confirmed", data)
}

func (g *groupStateCoordinator) publishGroupSecurityLevel(groupID string, bootstrap map[string]any) {
	c := g.runtime.client
	groupID = NormalizeGroupID(strings.TrimSpace(groupID), "")
	if groupID == "" || bootstrap == nil {
		return
	}
	level := strings.TrimSpace(v2AsString(bootstrap["e2ee_security_level"]))
	if level == "" {
		level = "end_to_end"
	}
	sec := c.v2GetSecurityState()
	sec.groupSecurityLevelsMu.Lock()
	previous, exists := sec.groupSecurityLevels[groupID]
	if exists && previous == level {
		sec.groupSecurityLevelsMu.Unlock()
		return
	}
	sec.groupSecurityLevels[groupID] = level
	sec.groupSecurityLevelsMu.Unlock()
	prevValue := any(nil)
	if exists {
		prevValue = previous
	}
	c.events.Publish("group.v2.security_level", map[string]any{
		"group_id":       groupID,
		"level":          level,
		"warning":        v2AsString(bootstrap["e2ee_security_warning"]),
		"previous_level": prevValue,
	})
}

func (g *groupStateCoordinator) verifyStateSignature(ctx context.Context, groupID string, bootstrap map[string]any) error {
	c := g.runtime.client
	groupID = NormalizeGroupID(strings.TrimSpace(groupID), "")
	if groupID == "" || bootstrap == nil {
		return nil
	}
	stateSignature := strings.TrimSpace(v2AsString(bootstrap["state_signature"]))
	actorAID := strings.TrimSpace(v2AsString(bootstrap["state_actor_aid"]))
	stateHashSigned := strings.TrimSpace(v2AsString(bootstrap["state_hash_signed"]))
	membershipSnapshot := strings.TrimSpace(v2AsString(bootstrap["state_membership_snapshot"]))
	stateVersion := int(toInt64(bootstrap["state_version"]))
	if stateVersion == 0 || stateSignature == "" || actorAID == "" {
		return nil
	}

	signPayloadMap := map[string]any{
		"group_id":            groupID,
		"membership_snapshot": membershipSnapshot,
		"state_hash":          stateHashSigned,
		"state_version":       stateVersion,
	}
	signPayload, err := marshalSortedCompactJSON(signPayloadMap)
	if err != nil {
		return fmt.Errorf("V2 state verify: marshal sign_payload failed: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(stateSignature)
	if err != nil {
		return fmt.Errorf("V2 state verify: decode signature failed: %w", err)
	}

	cacheMaterial := buildLengthPrefixedBytesKey([]byte(actorAID), signPayload)
	cacheMaterial = append(cacheMaterial, sigBytes...)
	cacheKey := sha256.Sum256(cacheMaterial)
	sec := c.v2GetSecurityState()
	nowTS := time.Now().Unix()

	sec.sigCacheMu.Lock()
	if exp, ok := sec.sigCache[cacheKey]; ok && exp > nowTS {
		sec.sigCacheMu.Unlock()
		c.logE2.Debug("V2 state signature cache hit: group=%s sv=%d", groupID, stateVersion)
		g.checkMembershipTamper(ctx, groupID, bootstrap, membershipSnapshot)
		return nil
	}
	sec.sigCacheMu.Unlock()

	certBytes, err := c.fetchPeerCert(ctx, actorAID, "")
	if err != nil || len(certBytes) == 0 {
		c.logE2.Warn("V2 state verify: no cert for actor=%s, group=%s", actorAID, groupID)
		if err != nil {
			return fmt.Errorf("V2 state verify: cannot fetch actor cert for %s: %w", actorAID, err)
		}
		return fmt.Errorf("V2 state verify: cannot fetch actor cert for %s", actorAID)
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return fmt.Errorf("V2 state verify: invalid PEM cert for %s", actorAID)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("V2 state verify: parse cert failed for %s: %w", actorAID, err)
	}
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("V2 state verify: cert public key is not ECDSA for %s", actorAID)
	}

	payloadHash := sha256.Sum256(signPayload)
	if !ecdsa.VerifyASN1(pubKey, payloadHash[:], sigBytes) {
		return fmt.Errorf("V2 state signature verification failed: group=%s actor=%s", groupID, actorAID)
	}

	sec.sigCacheMu.Lock()
	sec.sigCache[cacheKey] = nowTS + v2SigCacheTTL
	if len(sec.sigCache) > v2SigCacheMax {
		stale := make([][32]byte, 0)
		for k, exp := range sec.sigCache {
			if exp <= nowTS {
				stale = append(stale, k)
			}
		}
		for _, k := range stale {
			delete(sec.sigCache, k)
		}
		if len(sec.sigCache) > v2SigCacheMax {
			type kv struct {
				key [32]byte
				exp int64
			}
			items := make([]kv, 0, len(sec.sigCache))
			for k, exp := range sec.sigCache {
				items = append(items, kv{k, exp})
			}
			sort.Slice(items, func(i, j int) bool { return items[i].exp < items[j].exp })
			evict := len(items) / 4
			for i := 0; i < evict; i++ {
				delete(sec.sigCache, items[i].key)
			}
		}
	}
	sec.sigCacheMu.Unlock()

	c.logE2.Debug("V2 state signature verified: group=%s sv=%d actor=%s", groupID, stateVersion, actorAID)
	g.checkMembershipTamper(ctx, groupID, bootstrap, membershipSnapshot)
	return nil
}

func (g *groupStateCoordinator) checkMembershipTamper(ctx context.Context, groupID string, bootstrap map[string]any, membershipSnapshot string) {
	c := g.runtime.client
	if membershipSnapshot == "" || !strings.HasPrefix(membershipSnapshot, "[") {
		return
	}
	var signedSnapshot []string
	if err := json.Unmarshal([]byte(membershipSnapshot), &signedSnapshot); err != nil {
		return
	}
	signedSet := make(map[string]bool, len(signedSnapshot))
	for _, aid := range signedSnapshot {
		signedSet[aid] = true
	}

	serverMembers := v2ToStringList(bootstrap["member_aids"])
	var extra []string
	for _, aid := range serverMembers {
		if !signedSet[aid] {
			extra = append(extra, aid)
		}
	}
	if len(extra) == 0 {
		return
	}

	mode := ""
	reqResp, err := c.Call(ctx, "group.get_join_requirements", map[string]any{"group_id": groupID})
	if err == nil {
		if reqMap, ok := reqResp.(map[string]any); ok {
			mode = strings.TrimSpace(v2AsString(reqMap["mode"]))
		}
	}
	if mode == "open" || mode == "invite_code" || mode == "invite_only" {
		return
	}

	sort.Strings(extra)
	c.logE2.Warn("V2 state tamper detected: group=%s pending_extra=%v mode=%s", groupID, extra, mode)
	c.events.Publish("group.v2.state_tampered", map[string]any{
		"group_id":      groupID,
		"pending_extra": extra,
		"mode":          mode,
	})
}

func (g *groupStateCoordinator) checkFork(ctx context.Context, groupID string, serverChain string) {
	c := g.runtime.client
	groupID = NormalizeGroupID(strings.TrimSpace(groupID), "")
	if groupID == "" || serverChain == "" {
		return
	}
	sec := c.v2GetSecurityState()

	sec.stateChainsMu.Lock()
	local, exists := sec.stateChains[groupID]
	if !exists {
		sec.stateChains[groupID] = v2StateChainEntry{Version: 0, Chain: serverChain}
		sec.stateChainsMu.Unlock()
		return
	}
	localChain := local.Chain
	localSV := local.Version
	sec.stateChainsMu.Unlock()
	if localChain == serverChain {
		return
	}

	stateResp, err := c.Call(ctx, "group.get_state", map[string]any{"group_id": groupID})
	if err == nil {
		if stateMap, ok := stateResp.(map[string]any); ok {
			serverSV := int(toInt64(stateMap["state_version"]))
			if serverSV > localSV {
				sec.stateChainsMu.Lock()
				sec.stateChains[groupID] = v2StateChainEntry{Version: serverSV, Chain: serverChain}
				sec.stateChainsMu.Unlock()
				return
			}
			if serverSV < localSV {
				c.logE2.Warn("V2 state chain rollback detected: group=%s server_sv=%d local_sv=%d", groupID, serverSV, localSV)
			}
		}
	}

	localPrefix := localChain
	if len(localPrefix) > 16 {
		localPrefix = localPrefix[:16]
	}
	serverPrefix := serverChain
	if len(serverPrefix) > 16 {
		serverPrefix = serverPrefix[:16]
	}
	c.logE2.Warn("V2 state chain fork detected: group=%s local_chain=%s... server_chain=%s...", groupID, localPrefix, serverPrefix)
	c.events.Publish("group.v2.fork_detected", map[string]any{
		"group_id":     groupID,
		"local_chain":  localChain,
		"server_chain": serverChain,
	})
}

func (g *groupStateCoordinator) maybeTriggerAutoPropose(groupID string) {
	c := g.runtime.client
	groupID = NormalizeGroupID(strings.TrimSpace(groupID), "")
	if groupID == "" {
		return
	}
	c.v2AutoProposeLocksMu.Lock()
	if c.v2LazyProposeTriggered == nil {
		c.v2LazyProposeTriggered = make(map[string]int64)
	}
	now := time.Now().Unix()
	last := c.v2LazyProposeTriggered[groupID]
	if now-last < 10 {
		c.v2AutoProposeLocksMu.Unlock()
		return
	}
	c.v2LazyProposeTriggered[groupID] = now
	c.v2AutoProposeLocksMu.Unlock()
	go c.v2AutoProposeStateFromEvent(context.Background(), groupID)
}

func (g *groupStateCoordinator) onRawGroupStateCommitted(data any) {
	c := g.runtime.client
	tStart := time.Now()
	c.logEG.Debug("onRawGroupStateCommitted enter")
	defer func() {
		c.logEG.Debug("onRawGroupStateCommitted exit: elapsed=%dms", time.Since(tStart).Milliseconds())
	}()
	dataMap, ok := data.(map[string]any)
	if !ok {
		return
	}
	groupID := strings.TrimSpace(stringFromAny(dataMap["group_id"]))
	if groupID == "" {
		return
	}

	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	if myAID == "" {
		return
	}

	if cs, ok := dataMap["client_signature"].(map[string]any); ok {
		if c.shouldSkipEventSignature(dataMap) {
			delete(dataMap, "client_signature")
		} else {
			verified := c.verifyEventSignature(cs)
			if verified == false {
				c.logEG.Error("state_committed actor signature verification failed group=%s actor=%s",
					groupID, stringFromAny(dataMap["actor_aid"]))
				return
			}
		}
	}

	structured, ok := c.tokenStore.(keystore.StructuredKeyStore)
	if !ok {
		c.logEG.Warn("keystore does not support StructuredKeyStore, skipping group state committed handling group=%s", groupID)
		return
	}

	stateVersion := toInt64(dataMap["state_version"])
	stateHash := strings.TrimSpace(stringFromAny(dataMap["state_hash"]))
	prevStateHash := strings.TrimSpace(stringFromAny(dataMap["prev_state_hash"]))
	keyEpoch := toInt64(dataMap["key_epoch"])
	membershipSnapshot := strings.TrimSpace(stringFromAny(dataMap["membership_snapshot"]))
	policySnapshot := strings.TrimSpace(stringFromAny(dataMap["policy_snapshot"]))

	localState, err := structured.LoadGroupState(myAID, groupID)
	if err != nil {
		c.logEG.Warn("failed to load group %s local state: %v", groupID, err)
	}
	if localState != nil && localState.StateHash != "" && localState.StateHash != prevStateHash {
		c.logEG.Error("state_hash chain discontinuous group=%s local_sv=%d event_sv=%d",
			groupID, localState.StateVersion, stateVersion)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		serverResult, callErr := c.transport.Call(ctx, "group.get_state", map[string]any{"group_id": groupID})
		if callErr != nil {
			c.logEG.Warn("state fetch from source failed group=%s: %v", groupID, callErr)
			return
		}
		serverState, _ := serverResult.(map[string]any)
		if serverState == nil || serverState["state_version"] == nil {
			c.logEG.Warn("state fetch from source returned empty group=%s", groupID)
			return
		}
		sv := toInt64(serverState["state_version"])
		sHash := strings.TrimSpace(stringFromAny(serverState["state_hash"]))
		sEpoch := toInt64(serverState["key_epoch"])
		sMembersJSON := strings.TrimSpace(stringFromAny(serverState["membership_snapshot"]))
		sPolicyJSON := strings.TrimSpace(stringFromAny(serverState["policy_snapshot"]))
		sPrev := strings.TrimSpace(stringFromAny(serverState["prev_state_hash"]))

		if sMembersJSON != "" && sHash != "" {
			sMembers := parseMemberRolesJSON(sMembersJSON)
			sPolicy := parseJSONObject(sPolicyJSON)
			computed := ComputeStateHash(groupID, sv, sEpoch, sMembers, sPolicy, sPrev)
			if computed != sHash {
				c.logEG.Error("fetched state_hash verification failed group=%s sv=%d expected=%s got=%s",
					groupID, sv, sHash, computed)
				return
			}
		}
		saveMembershipJSON := sMembersJSON
		if saveMembershipJSON == "" {
			saveMembershipJSON = membershipSnapshot
		}
		savePolicyJSON := sPolicyJSON
		if savePolicyJSON == "" {
			savePolicyJSON = policySnapshot
		}
		if saveErr := structured.SaveGroupState(myAID, groupID, sv, sHash, sEpoch, saveMembershipJSON, savePolicyJSON); saveErr != nil {
			c.logEG.Warn("failed to save group state after fetch group=%s: %v", groupID, saveErr)
		}
		return
	}

	members := parseMemberRolesJSON(membershipSnapshot)
	policy := parseJSONObject(policySnapshot)
	computed := ComputeStateHash(groupID, stateVersion, keyEpoch, members, policy, prevStateHash)
	if computed != stateHash {
		c.logEG.Error("state_hash recomputation mismatch group=%s sv=%d expected=%s got=%s",
			groupID, stateVersion, stateHash, computed)
		return
	}

	if saveErr := structured.SaveGroupState(myAID, groupID, stateVersion, stateHash, keyEpoch, membershipSnapshot, policySnapshot); saveErr != nil {
		c.logEG.Warn("failed to save group state group=%s: %v", groupID, saveErr)
	}
}

func (g *groupStateCoordinator) autoProposeState(ctx context.Context, groupID string) {
	c := g.runtime.client
	normalizedGroupID := NormalizeGroupID(strings.TrimSpace(groupID), "")
	if normalizedGroupID == "" {
		return
	}
	lock := c.v2AutoProposeLock(normalizedGroupID)
	lock.Lock()
	defer lock.Unlock()
	g.doAutoProposeState(ctx, normalizedGroupID)
}

func (g *groupStateCoordinator) autoProposeStateFromEvent(ctx context.Context, groupID string) {
	normalizedGroupID := NormalizeGroupID(strings.TrimSpace(groupID), "")
	if normalizedGroupID == "" {
		return
	}
	if !g.runtime.client.v2AutoProposeLeaderDelay(ctx, normalizedGroupID) {
		return
	}
	g.autoProposeState(ctx, normalizedGroupID)
}

func (g *groupStateCoordinator) autoProposeLeaderDelay(ctx context.Context, groupID string) bool {
	c := g.runtime.client
	membersResp, err := c.Call(ctx, "group.get_online_members", map[string]any{"group_id": groupID})
	if err != nil {
		c.logE2.Debug("V2 auto propose leader check failed, fallback immediate: group=%s err=%v", groupID, err)
		return true
	}
	membersMap, _ := membersResp.(map[string]any)
	membersList := v2ToMapList(membersMap["members"])
	if len(membersList) == 0 {
		membersList = v2ToMapList(membersMap["items"])
	}
	if len(membersList) == 0 {
		membersList = v2ToMapList(membersMap["online_members"])
	}

	c.mu.RLock()
	myAID := c.aid
	myDeviceID := c.deviceID
	c.mu.RUnlock()

	myRole := ""
	onlineAdminSet := make(map[string]bool)
	var onlineAdminAIDs []string
	for _, member := range membersList {
		aid := strings.TrimSpace(v2AsString(member["aid"]))
		role := strings.TrimSpace(v2AsString(member["role"]))
		if aid == "" {
			continue
		}
		if online, ok := member["online"].(bool); ok && !online {
			continue
		}
		if role == "owner" || role == "admin" {
			if !onlineAdminSet[aid] {
				onlineAdminSet[aid] = true
				onlineAdminAIDs = append(onlineAdminAIDs, aid)
			}
		}
		if aid == myAID {
			myRole = role
		}
	}
	if myRole != "owner" && myRole != "admin" {
		return false
	}

	bootstrapResp, err := c.Call(ctx, "group.v2.bootstrap", map[string]any{
		"group_id":               groupID,
		"e2ee_wrap_capabilities": v2WrapCapabilities(),
	})
	if err != nil {
		c.logE2.Debug("V2 auto propose leader bootstrap failed, fallback immediate: group=%s err=%v", groupID, err)
		return true
	}
	bootstrapMap, _ := bootstrapResp.(map[string]any)
	devices := v2ToMapList(bootstrapMap["devices"])
	candidates := make([]string, 0)
	for _, dev := range devices {
		aid := strings.TrimSpace(v2AsString(dev["aid"]))
		deviceID, hasDeviceID := v2DeviceIDFromDevice(dev)
		if aid != "" && hasDeviceID && onlineAdminSet[aid] {
			candidates = append(candidates, aid+"\x1f"+deviceID)
		}
	}
	if len(candidates) == 0 {
		sort.Strings(onlineAdminAIDs)
		for _, aid := range onlineAdminAIDs {
			candidates = append(candidates, aid+"\x1f")
		}
	}
	myKey := myAID + "\x1f" + myDeviceID
	foundSelf := false
	for _, candidate := range candidates {
		if candidate == myKey {
			foundSelf = true
			break
		}
	}
	if !foundSelf {
		candidates = append(candidates, myKey)
	}
	sort.Strings(candidates)
	leader := candidates[0]
	if leader == myKey {
		c.logE2.Debug("V2 auto propose leader elected: group=%s leader=%s", groupID, leader)
		return true
	}

	sum := sha256.Sum256([]byte(buildLengthPrefixedTextKey(groupID, myKey)))
	delayMs := 2000 + int(uint32(sum[0])<<24|uint32(sum[1])<<16|uint32(sum[2])<<8|uint32(sum[3]))%4000
	c.logE2.Debug("V2 auto propose non-leader delay: group=%s leader=%s self=%s delay_ms=%d", groupID, leader, myKey, delayMs)
	timer := time.NewTimer(time.Duration(delayMs) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (g *groupStateCoordinator) doAutoProposeState(ctx context.Context, groupID string) {
	c := g.runtime.client
	defer func() {
		if r := recover(); r != nil {
			c.logE2.Warn("v2AutoProposeState panic: group=%s err=%v", groupID, r)
		}
	}()

	membersResp, err := c.Call(ctx, "group.get_members", map[string]any{"group_id": groupID})
	if err != nil {
		c.logE2.Debug("V2 auto propose_state failed (non-fatal): group=%s err=%v", groupID, err)
		return
	}
	membersMap, _ := membersResp.(map[string]any)
	membersList := v2ToMapList(membersMap["members"])
	if len(membersList) == 0 {
		membersList = v2ToMapList(membersMap["items"])
	}

	c.mu.RLock()
	myAID := c.aid
	currentAID := c.currentAIDObj
	c.mu.RUnlock()

	myRole := ""
	var memberAIDs []string
	var adminAIDs []string
	for _, m := range membersList {
		aid := strings.TrimSpace(v2AsString(m["aid"]))
		role := strings.TrimSpace(v2AsString(m["role"]))
		if aid != "" {
			memberAIDs = append(memberAIDs, aid)
			if role == "owner" || role == "admin" {
				adminAIDs = append(adminAIDs, aid)
			}
		}
		if aid == myAID {
			myRole = role
		}
	}

	if myRole != "owner" && myRole != "admin" {
		return
	}

	proposalResp, err := c.Call(ctx, "group.v2.get_proposal", map[string]any{"group_id": groupID})
	if err == nil {
		if proposalMap, ok := proposalResp.(map[string]any); ok {
			if proposal, ok := proposalMap["proposal"].(map[string]any); ok && proposal != nil {
				if strings.TrimSpace(v2AsString(proposal["proposal_id"])) != "" {
					if c.v2ConfirmPendingProposal(ctx, groupID) {
						return
					}
					autoConfirmAt := toInt64(proposal["auto_confirm_at"])
					nowMs := time.Now().UnixMilli()
					if autoConfirmAt > nowMs {
						waitMs := autoConfirmAt - nowMs + 500
						if waitMs > 35000 {
							waitMs = 35000
						}
						c.logE2.Debug("V2 auto propose: pending proposal exists, waiting %dms group=%s", waitMs, groupID)
						timer := time.NewTimer(time.Duration(waitMs) * time.Millisecond)
						defer timer.Stop()
						select {
						case <-ctx.Done():
							return
						case <-timer.C:
						}
					}
				}
			}
		}
	}

	bootstrapResp, err := c.Call(ctx, "group.v2.bootstrap", map[string]any{
		"group_id":               groupID,
		"e2ee_wrap_capabilities": v2WrapCapabilities(),
	})
	if err != nil {
		c.logE2.Debug("V2 auto propose_state failed (non-fatal): group=%s err=%v", groupID, err)
		return
	}
	bsMap, _ := bootstrapResp.(map[string]any)
	allDevices := v2ToMapList(bsMap["devices"])
	auditRecipients := v2ToMapList(bsMap["audit_recipients"])

	auditAIDSet := make(map[string]bool)
	for _, r := range auditRecipients {
		aid := strings.TrimSpace(v2AsString(r["aid"]))
		if aid != "" {
			auditAIDSet[aid] = true
		}
	}
	auditAIDsList := make([]string, 0, len(auditAIDSet))
	for aid := range auditAIDSet {
		auditAIDsList = append(auditAIDsList, aid)
	}
	sort.Strings(auditAIDsList)

	membersWithDevices := make(map[string][]map[string]any)
	for _, aid := range memberAIDs {
		membersWithDevices[aid] = nil
	}
	for _, dev := range allDevices {
		devAID := strings.TrimSpace(v2AsString(dev["aid"]))
		if _, ok := membersWithDevices[devAID]; ok {
			membersWithDevices[devAID] = append(membersWithDevices[devAID], map[string]any{
				"device_id": v2AsString(dev["device_id"]),
				"ik_fp":     v2AsString(dev["ik_fp"]),
			})
		}
	}

	membersPayload := make([]any, 0, len(membersWithDevices))
	for _, aid := range memberAIDs {
		devices := membersWithDevices[aid]
		devList := make([]any, 0, len(devices))
		for _, d := range devices {
			devList = append(devList, d)
		}
		membersPayload = append(membersPayload, map[string]any{
			"aid":     aid,
			"devices": devList,
		})
	}

	sort.Strings(adminAIDs)
	statePayload := map[string]any{
		"members":          membersPayload,
		"audit_aids":       v2ToAnySlice(auditAIDsList),
		"admin_set":        map[string]any{"admin_aids": v2ToAnySlice(adminAIDs), "threshold": 1},
		"join_policy_hash": nil,
		"recovery_quorum":  nil,
		"history_policy":   "recent_7_days",
		"wrap_protocol":    "3DH",
	}

	stateResp, err := c.Call(ctx, "group.get_state", map[string]any{"group_id": groupID})
	if err != nil {
		c.logE2.Debug("V2 auto propose_state failed (non-fatal): group=%s err=%v", groupID, err)
		return
	}
	stateMap, ok := stateResp.(map[string]any)
	if !ok {
		return
	}
	if !g.verifyCommittedStateBase(groupID, stateMap) {
		return
	}
	currentSV := int(toInt64(stateMap["state_version"]))
	currentSH := v2AsString(stateMap["state_hash"])
	keyEpoch := int(toInt64(stateMap["key_epoch"]))

	stateHash := state.ComputeStateCommitment(groupID, uint32(currentSV+1), statePayload)
	membershipSnapshotBytes, _ := marshalSortedCompactJSON(statePayload)
	membershipSnapshot := string(membershipSnapshotBytes)
	c.v2AutoProposeLocksMu.Lock()
	lastMembershipSnapshot := c.v2AutoProposeLastSnapshot[groupID]
	c.v2AutoProposeLocksMu.Unlock()
	if lastMembershipSnapshot == membershipSnapshot {
		return
	}
	if currentMembership := strings.TrimSpace(v2AsString(stateMap["membership_snapshot"])); currentMembership != "" && currentMembership == membershipSnapshot {
		c.v2AutoProposeLocksMu.Lock()
		c.v2AutoProposeLastSnapshot[groupID] = membershipSnapshot
		c.v2AutoProposeLocksMu.Unlock()
		return
	}

	signature := ""
	privPEM := ""
	if currentAID != nil {
		privPEM = currentAID.PrivateKeyPem
	}
	if privPEM != "" {
		signPayloadMap := map[string]any{
			"group_id":            groupID,
			"membership_snapshot": membershipSnapshot,
			"state_hash":          stateHash,
			"state_version":       currentSV + 1,
		}
		signPayloadBytes, err := marshalSortedCompactJSON(signPayloadMap)
		if err == nil {
			pk, err := parseECPrivateKeyPEM(privPEM)
			if err == nil {
				payloadHash := sha256.Sum256(signPayloadBytes)
				sigDER, err := ecdsa.SignASN1(cryptorand.Reader, pk, payloadHash[:])
				if err == nil {
					signature = base64.StdEncoding.EncodeToString(sigDER)
				}
			}
		}
	}

	proposeResp, err := c.Call(ctx, "group.v2.propose_state", map[string]any{
		"group_id":             groupID,
		"state_version":        currentSV + 1,
		"key_epoch":            keyEpoch,
		"state_hash":           stateHash,
		"prev_state_hash":      currentSH,
		"membership_snapshot":  membershipSnapshot,
		"signature":            signature,
		"reason":               "membership_changed",
		"auto_confirm_seconds": 30,
	})
	if err != nil {
		c.logE2.Debug("V2 auto propose_state failed (non-fatal): group=%s err=%v", groupID, err)
		return
	}
	c.logE2.Debug("V2 auto propose_state: group=%s sv=%d", groupID, currentSV+1)
	if proposalMap, ok := proposeResp.(map[string]any); ok {
		proposalID := strings.TrimSpace(v2AsString(proposalMap["proposal_id"]))
		if proposalID != "" {
			if _, confirmErr := c.Call(ctx, "group.v2.confirm_state", map[string]any{"proposal_id": proposalID}); confirmErr != nil {
				c.logE2.Debug("V2 auto confirm_state failed (non-fatal): group=%s err=%v", groupID, confirmErr)
			} else {
				c.v2AutoProposeLocksMu.Lock()
				c.v2AutoProposeLastSnapshot[groupID] = membershipSnapshot
				c.v2AutoProposeLocksMu.Unlock()
				c.logE2.Debug("V2 auto confirm_state: group=%s proposal=%s", groupID, proposalID)
			}
		}
	}
}

func (g *groupStateCoordinator) verifyCommittedStateBase(groupID string, stateMap map[string]any) bool {
	c := g.runtime.client
	currentSV := int(toInt64(stateMap["state_version"]))
	if currentSV <= 0 {
		return true
	}
	currentSH := strings.TrimSpace(v2AsString(stateMap["state_hash"]))
	membershipSnapshot := strings.TrimSpace(v2AsString(stateMap["membership_snapshot"]))
	if currentSH == "" || membershipSnapshot == "" {
		c.logE2.Warn("V2 committed state base incomplete: group=%s sv=%d", groupID, currentSV)
		return false
	}
	payload, ok := v2DecodeMembershipSnapshot(membershipSnapshot)
	if !ok {
		c.logE2.Warn("V2 committed state base snapshot is not object: group=%s sv=%d", groupID, currentSV)
		return false
	}
	computed := state.ComputeStateCommitment(groupID, uint32(currentSV), payload)
	if computed != currentSH {
		c.logE2.Warn("V2 committed state base hash mismatch: group=%s sv=%d", groupID, currentSV)
		return false
	}
	return true
}

func (g *groupStateCoordinator) verifyPendingProposalAgainstBase(groupID string, proposal map[string]any, stateMap map[string]any) bool {
	c := g.runtime.client
	if !g.verifyCommittedStateBase(groupID, stateMap) {
		return false
	}
	currentSV := int(toInt64(stateMap["state_version"]))
	currentSH := strings.TrimSpace(v2AsString(stateMap["state_hash"]))
	proposalSV := int(toInt64(proposal["state_version"]))
	proposalHash := strings.TrimSpace(v2AsString(proposal["state_hash"]))
	proposalPrev := strings.TrimSpace(v2AsString(proposal["prev_state_hash"]))
	membershipSnapshot := strings.TrimSpace(v2AsString(proposal["membership_snapshot"]))
	if proposalSV != currentSV+1 || proposalPrev != currentSH || proposalHash == "" || membershipSnapshot == "" {
		c.logE2.Warn("V2 pending proposal base mismatch: group=%s current_sv=%d proposal_sv=%d", groupID, currentSV, proposalSV)
		return false
	}
	payload, ok := v2DecodeMembershipSnapshot(membershipSnapshot)
	if !ok {
		return false
	}
	computed := state.ComputeStateCommitment(groupID, uint32(proposalSV), payload)
	if computed != proposalHash {
		c.logE2.Warn("V2 pending proposal hash mismatch: group=%s proposal_sv=%d", groupID, proposalSV)
		return false
	}
	return true
}

func (g *groupStateCoordinator) confirmPendingProposal(ctx context.Context, groupID string) bool {
	c := g.runtime.client
	proposalResp, err := c.Call(ctx, "group.v2.get_proposal", map[string]any{"group_id": groupID})
	if err != nil {
		c.logE2.Debug("V2 auto confirm proposal failed (non-fatal): group=%s err=%v", groupID, err)
		return false
	}
	proposalMap, _ := proposalResp.(map[string]any)
	proposal, _ := proposalMap["proposal"].(map[string]any)
	if proposal == nil {
		return false
	}
	proposalID := strings.TrimSpace(v2AsString(proposal["proposal_id"]))
	if proposalID == "" {
		return false
	}

	stateResp, err := c.Call(ctx, "group.get_state", map[string]any{"group_id": groupID})
	if err != nil {
		c.logE2.Debug("V2 auto confirm proposal failed (non-fatal): group=%s err=%v", groupID, err)
		return false
	}
	stateMap, ok := stateResp.(map[string]any)
	if !ok {
		return false
	}
	currentSV := int(toInt64(stateMap["state_version"]))
	proposalSV := int(toInt64(proposal["state_version"]))
	if proposalSV <= currentSV {
		c.logE2.Debug("V2 pending proposal already settled: group=%s current_sv=%d proposal_sv=%d", groupID, currentSV, proposalSV)
		return false
	}
	if !g.verifyPendingProposalAgainstBase(groupID, proposal, stateMap) {
		return false
	}

	if _, err = c.Call(ctx, "group.v2.confirm_state", map[string]any{"proposal_id": proposalID}); err != nil {
		c.logE2.Debug("V2 auto confirm proposal failed (non-fatal): group=%s err=%v", groupID, err)
		return false
	}
	c.logE2.Info("V2 confirmed pending proposal: group=%s proposal=%s", groupID, proposalID)
	return true
}

func (g *groupStateCoordinator) autoConfirmPendingProposals(ctx context.Context) {
	c := g.runtime.client
	defer func() {
		if r := recover(); r != nil {
			c.logE2.Warn("v2AutoConfirmPendingProposals panic: %v", r)
		}
	}()

	c.mu.RLock()
	myAID := c.aid
	c.mu.RUnlock()
	if myAID == "" {
		return
	}

	groupsResp, err := c.Call(ctx, "group.list_my", map[string]any{})
	if err != nil {
		c.logE2.Debug("V2 auto confirm pending proposals failed (non-fatal): %v", err)
		return
	}
	groupsMap, _ := groupsResp.(map[string]any)
	groups := v2ToMapList(groupsMap["groups"])
	if len(groups) == 0 {
		groups = v2ToMapList(groupsMap["items"])
	}

	for _, group := range groups {
		groupID := strings.TrimSpace(v2AsString(group["group_id"]))
		myRole := strings.TrimSpace(v2AsString(group["role"]))
		if myRole == "" {
			myRole = strings.TrimSpace(v2AsString(group["my_role"]))
		}
		if groupID == "" || (myRole != "owner" && myRole != "admin") {
			continue
		}

		if !c.v2ConfirmPendingProposal(ctx, groupID) {
			c.v2AutoProposeState(ctx, groupID)
		}
	}
}

func isV2StateSpkRegistrationMutationMethod(method string) bool {
	switch method {
	case "group.create", "group.use_invite_code":
		return true
	default:
		return false
	}
}

func isV2StateMembershipMethod(method string) bool {
	switch method {
	case "group.create", "group.add_member", "group.kick", "group.remove_member", "group.leave",
		"group.review_join_request", "group.batch_review_join_request",
		"group.use_invite_code", "group.request_join":
		return true
	default:
		return false
	}
}

func extractGroupIDFromMutationResult(result any, params map[string]any) string {
	if resultMap, ok := result.(map[string]any); ok {
		if group, ok := resultMap["group"].(map[string]any); ok {
			if gid := strings.TrimSpace(stringFromAny(group["group_id"])); gid != "" {
				return NormalizeGroupID(gid, "")
			}
		}
		if gid := strings.TrimSpace(stringFromAny(resultMap["group_id"])); gid != "" {
			return NormalizeGroupID(gid, "")
		}
		if member, ok := resultMap["member"].(map[string]any); ok {
			if gid := strings.TrimSpace(stringFromAny(member["group_id"])); gid != "" {
				return NormalizeGroupID(gid, "")
			}
		}
	}
	if params != nil {
		if gid := strings.TrimSpace(stringFromAny(params["group_id"])); gid != "" {
			return NormalizeGroupID(gid, "")
		}
	}
	return ""
}
