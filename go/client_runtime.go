package aun

import (
	"context"
	"sync"
	"time"

	"github.com/modelunion/aun-sdk-core/go/keystore"
)

type clientRuntime struct {
	client     *AUNClient
	identity   *runtimeIdentityState
	lifecycle  *runtimeLifecycleState
	rpc        *runtimeRPCState
	delivery   *runtimeDeliveryState
	v2         *runtimeV2State
	groupState *runtimeGroupState
	services   *runtimeServices
}

func newClientRuntime(client *AUNClient) *clientRuntime {
	runtime := &clientRuntime{client: client}
	runtime.identity = &runtimeIdentityState{runtime: runtime}
	runtime.lifecycle = &runtimeLifecycleState{runtime: runtime}
	runtime.rpc = &runtimeRPCState{runtime: runtime}
	runtime.delivery = &runtimeDeliveryState{runtime: runtime}
	runtime.v2 = &runtimeV2State{runtime: runtime}
	runtime.groupState = &runtimeGroupState{runtime: runtime}
	runtime.services = &runtimeServices{runtime: runtime}
	return runtime
}

type runtimeIdentityState struct {
	runtime *clientRuntime
}

func (s *runtimeIdentityState) setLoadedIdentity(aid *AID, identity map[string]any) {
	c := s.runtime.client
	c.currentAIDObj = aid
	if aid != nil {
		c.aid = aid.Aid
	}
	c.identity = identity
	if c.auth != nil {
		if aid != nil {
			c.auth.aid = aid.Aid
		}
		if identity != nil {
			c.auth.SetIdentity(identity)
		}
	}
}

func (s *runtimeIdentityState) setIdentity(identity map[string]any) {
	s.runtime.client.identity = identity
}

func (s *runtimeIdentityState) setAid(aid string) {
	c := s.runtime.client
	c.aid = aid
	if c.logger != nil {
		c.logger.BindAID(aid)
	}
}

func (s *runtimeIdentityState) setInstanceContext(deviceID, slotID string) {
	c := s.runtime.client
	c.deviceID = deviceID
	c.slotID = slotID
	if c.auth != nil {
		c.auth.SetInstanceContext(deviceID, slotID)
	}
}

func (s *runtimeIdentityState) clear() {
	c := s.runtime.client
	c.currentAIDObj = nil
	c.aid = ""
	c.identity = nil
}

func (s *runtimeIdentityState) syncAfterConnect(accessToken string) {
	c := s.runtime.client
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.identity == nil {
		return
	}
	c.identity["access_token"] = accessToken
	if loadedAID, ok := c.identity["aid"].(string); ok && loadedAID != "" {
		s.setAid(loadedAID)
	}
	if _, ok := c.identity["aid"].(string); ok {
		if err := c.auth.persistIdentity(c.identity); err != nil {
			c.auth.lastPersistErr = err
		}
	}
}

type runtimeLifecycleState struct {
	runtime *clientRuntime
}

func (s *runtimeLifecycleState) setStateLocked(state ClientState) {
	s.runtime.client.state = state
}

func (s *runtimeLifecycleState) setState(state ClientState) {
	c := s.runtime.client
	c.mu.Lock()
	c.state = state
	c.mu.Unlock()
}

func (s *runtimeLifecycleState) setClosing(closing bool) {
	s.runtime.client.closing.Store(closing)
}

func (s *runtimeLifecycleState) setGatewayURLLocked(gatewayURL string) {
	s.runtime.client.gatewayURL = gatewayURL
}

func (s *runtimeLifecycleState) setConnectDeliveryModeLocked(deliveryMode map[string]any) {
	s.runtime.client.connectDeliveryMode = deliveryMode
}

func (s *runtimeLifecycleState) setSessionLocked(params map[string]any, options map[string]any) {
	c := s.runtime.client
	c.sessionParams = params
	c.sessionOptions = options
}

func (s *runtimeLifecycleState) setSessionAccessTokenLocked(token string) {
	c := s.runtime.client
	if c.sessionParams != nil && token != "" {
		c.sessionParams["access_token"] = token
	}
}

func (s *runtimeLifecycleState) setAuthenticatedLocked(authenticated bool) {
	s.runtime.client.authenticated = authenticated
}

func (s *runtimeLifecycleState) clearRetryStateLocked() {
	c := s.runtime.client
	c.nextRetryAt = time.Time{}
	c.retryAttempt = 0
	c.lastConnectError = nil
}

func (s *runtimeLifecycleState) setErrorLocked(err error) {
	s.runtime.client.lastConnectError = err
}

func (s *runtimeLifecycleState) setConnectedAtLocked(connectedAt time.Time) {
	s.runtime.client.connectedAt = connectedAt
}

func (s *runtimeLifecycleState) clearNextRetryAtLocked() {
	s.runtime.client.nextRetryAt = time.Time{}
}

func (s *runtimeLifecycleState) setRetryBackoffLocked(attempt int, nextRetryAt time.Time) {
	c := s.runtime.client
	c.state = StateReconnecting
	c.retryAttempt = attempt
	c.nextRetryAt = nextRetryAt
}

func (s *runtimeLifecycleState) setTerminalFailedLocked(err error) {
	c := s.runtime.client
	c.state = StateTerminalFailed
	c.nextRetryAt = time.Time{}
	c.lastConnectError = err
}

func (s *runtimeLifecycleState) setReconnectCancelLocked(cancel context.CancelFunc) {
	s.runtime.client.reconnectCancel = cancel
}

func (s *runtimeLifecycleState) clearReconnectCancelLocked() {
	s.runtime.client.reconnectCancel = nil
}

func (s *runtimeLifecycleState) setBackgroundContextLocked(ctx context.Context, cancel context.CancelFunc) {
	c := s.runtime.client
	c.ctx = ctx
	c.cancel = cancel
}

func (s *runtimeLifecycleState) setServerKicked(kicked bool) {
	s.runtime.client.serverKicked.Store(kicked)
}

func (s *runtimeLifecycleState) setLastDisconnectInfo(info map[string]any) {
	c := s.runtime.client
	c.lastDisconnectMu.Lock()
	c.lastDisconnectInfo = info
	c.lastDisconnectMu.Unlock()
}

func (s *runtimeLifecycleState) resetForDisconnectLocked(nextState ClientState) {
	c := s.runtime.client
	c.state = nextState
	c.authenticated = false
	c.nextRetryAt = time.Time{}
	c.retryAttempt = 0
	c.lastConnectError = nil
}

func (s *runtimeLifecycleState) resetForCloseLocked() {
	c := s.runtime.client
	c.state = StateClosed
	c.authenticated = false
	c.nextRetryAt = time.Time{}
	c.retryAttempt = 0
	c.lastConnectError = nil
	s.runtime.delivery.resetSeqTrackingStateLocked()
}

type runtimeRPCState struct {
	runtime *clientRuntime
}

func (s *runtimeRPCState) protectedHeaders() map[string]string {
	c := s.runtime.client
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.instanceProtectedHeaders) == 0 {
		return nil
	}
	out := make(map[string]string, len(c.instanceProtectedHeaders))
	for k, v := range c.instanceProtectedHeaders {
		out[k] = v
	}
	return out
}

type runtimeDeliveryState struct {
	runtime *clientRuntime
}

func (s *runtimeDeliveryState) seqTracker() *SeqTracker {
	return s.runtime.client.seqTracker
}

func (s *runtimeDeliveryState) resetSeqTrackingStateLocked() {
	c := s.runtime.client
	c.seqTracker = NewSeqTracker()
	c.seqTrackerContext = ""
	c.gapFillDoneMu.Lock()
	c.gapFillDone = make(map[string]bool)
	c.gapFillDoneMu.Unlock()
	c.pushedSeqsMu.Lock()
	c.pushedSeqs = make(map[string]map[int]bool)
	c.pushedSeqsMu.Unlock()
	c.pendingOrderedMsgsMu.Lock()
	c.pendingOrderedMsgs = make(map[string]map[int]pendingOrderedMessage)
	c.pendingOrderedMsgsMu.Unlock()
	c.groupSyncedMu.Lock()
	c.groupSynced = make(map[string]bool)
	c.groupSyncedMu.Unlock()
	c.onlineUnreadHintMu.Lock()
	c.onlineUnreadHintQueue = make(map[string]map[string]any)
	c.onlineUnreadHintDraining = false
	c.onlineUnreadHintMu.Unlock()
	c.v2SenderIKMu.Lock()
	c.v2SenderIKPending = make(map[string]v2SenderIKPendingEntry)
	c.v2SenderIKFetching = make(map[string]bool)
	c.v2SenderIKMu.Unlock()
}

func (s *runtimeDeliveryState) refreshSeqTrackerContextLocked() {
	c := s.runtime.client
	nextContext := buildSeqTrackerContext(c.aid, c.deviceID, c.slotID)
	if nextContext == c.seqTrackerContext {
		return
	}
	c.seqTracker = NewSeqTracker()
	c.seqTrackerContext = nextContext
	c.gapFillDoneMu.Lock()
	c.gapFillDone = make(map[string]bool)
	c.gapFillDoneMu.Unlock()
	c.pushedSeqsMu.Lock()
	c.pushedSeqs = make(map[string]map[int]bool)
	c.pushedSeqsMu.Unlock()
	c.pendingOrderedMsgsMu.Lock()
	c.pendingOrderedMsgs = make(map[string]map[int]pendingOrderedMessage)
	c.pendingOrderedMsgsMu.Unlock()
	c.groupSyncedMu.Lock()
	c.groupSynced = make(map[string]bool)
	c.groupSyncedMu.Unlock()
	c.onlineUnreadHintMu.Lock()
	c.onlineUnreadHintQueue = make(map[string]map[string]any)
	c.onlineUnreadHintDraining = false
	c.onlineUnreadHintMu.Unlock()
	c.v2SenderIKMu.Lock()
	c.v2SenderIKPending = make(map[string]v2SenderIKPendingEntry)
	c.v2SenderIKFetching = make(map[string]bool)
	c.v2SenderIKMu.Unlock()
}

func (s *runtimeDeliveryState) onlineUnreadHintQueueLocked() map[string]map[string]any {
	c := s.runtime.client
	if c.onlineUnreadHintQueue == nil {
		c.onlineUnreadHintQueue = make(map[string]map[string]any)
	}
	return c.onlineUnreadHintQueue
}

func (s *runtimeDeliveryState) setOnlineUnreadHintDrainingLocked(draining bool) {
	s.runtime.client.onlineUnreadHintDraining = draining
}

func (s *runtimeDeliveryState) pendingOrderedMsgsLocked() map[string]map[int]pendingOrderedMessage {
	c := s.runtime.client
	if c.pendingOrderedMsgs == nil {
		c.pendingOrderedMsgs = make(map[string]map[int]pendingOrderedMessage)
	}
	return c.pendingOrderedMsgs
}

type runtimeV2State struct {
	runtime *clientRuntime
}

func (s *runtimeV2State) state() *v2P2PState {
	return s.runtime.client.v2GetState()
}

func (s *runtimeV2State) setStateLocked(state *v2P2PState) {
	s.runtime.client.v2State = state
}

func (s *runtimeV2State) clearStateLocked() *v2P2PState {
	c := s.runtime.client
	old := c.v2State
	c.v2State = nil
	return old
}

func (s *runtimeV2State) resetForIdentityLocked() {
	c := s.runtime.client
	old := c.v2State
	c.v2State = nil
	c.v2Security = nil
	c.v2SenderIKPending = make(map[string]v2SenderIKPendingEntry)
	c.v2SenderIKFetching = make(map[string]bool)
	c.v2AutoProposeLastSnapshot = make(map[string]string)
	c.v2LazyProposeTriggered = make(map[string]int64)
	c.v2PushPullInflight.Store(false)
	c.v2PushPullPending.Store(false)
	if old != nil && old.keystore != nil {
		go func() { _ = old.keystore.Close() }()
	}
}

type runtimeGroupState struct {
	runtime *clientRuntime
}

func (s *runtimeGroupState) securityStateLocked() *v2StateSecurityState {
	c := s.runtime.client
	if c.v2Security == nil {
		c.v2Security = newV2StateSecurityState()
	}
	return c.v2Security
}

func (s *runtimeGroupState) autoProposeLocksLocked() map[string]*sync.Mutex {
	c := s.runtime.client
	if c.v2AutoProposeLocks == nil {
		c.v2AutoProposeLocks = make(map[string]*sync.Mutex)
	}
	if c.v2AutoProposeLastSnapshot == nil {
		c.v2AutoProposeLastSnapshot = make(map[string]string)
	}
	return c.v2AutoProposeLocks
}

func (s *runtimeGroupState) lazyProposeTriggeredLocked() map[string]int64 {
	c := s.runtime.client
	if c.v2LazyProposeTriggered == nil {
		c.v2LazyProposeTriggered = make(map[string]int64)
	}
	return c.v2LazyProposeTriggered
}

type runtimeServices struct {
	runtime *clientRuntime
}

func (s *runtimeServices) context() context.Context { return s.runtime.client.ctx }
func (s *runtimeServices) tokenStore() keystore.TokenStore {
	return s.runtime.client.tokenStore
}

func (c *AUNClient) getClientRuntime() *clientRuntime {
	if c.clientRuntime != nil {
		return c.clientRuntime
	}
	return newClientRuntime(c)
}

func (c *AUNClient) getIdentityRuntime() *identityRuntimeManager {
	if c.identityRuntime != nil {
		return c.identityRuntime
	}
	return newIdentityRuntimeManager(c.getClientRuntime())
}

func (c *AUNClient) getPeerDirectory() *peerDirectory {
	if c.peerDirectory != nil {
		return c.peerDirectory
	}
	return newPeerDirectory(c.getClientRuntime())
}

func (c *AUNClient) getLifecycleController() *lifecycleController {
	if c.lifecycle != nil {
		return c.lifecycle
	}
	return newLifecycleController(c.getClientRuntime())
}

func (c *AUNClient) getRpcPipeline() *rpcPipeline {
	if c.rpcPipeline != nil {
		return c.rpcPipeline
	}
	return newRpcPipeline(c.getClientRuntime())
}

func (c *AUNClient) getV2E2EECoordinator() *v2E2EECoordinator {
	if c.v2E2EE != nil {
		return c.v2E2EE
	}
	return newV2E2EECoordinator(c.getClientRuntime())
}

func (c *AUNClient) getGroupStateCoordinator() *groupStateCoordinator {
	if c.groupState != nil {
		return c.groupState
	}
	return newGroupStateCoordinator(c.getClientRuntime())
}
