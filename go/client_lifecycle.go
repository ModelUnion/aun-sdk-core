package aun

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type lifecycleController struct {
	runtime *clientRuntime
}

func newLifecycleController(runtime *clientRuntime) *lifecycleController {
	return &lifecycleController{runtime: runtime}
}

func (l *lifecycleController) authenticate(ctx context.Context, opts ...ConnectOptions) (map[string]any, error) {
	c := l.runtime.client
	if len(opts) > 1 {
		return nil, NewValidationError("Authenticate accepts at most one options object")
	}
	pubState := c.State()
	if pubState != ConnStateStandby {
		return nil, NewStateError(fmt.Sprintf("authenticate not allowed in state %s", pubState))
	}
	c.mu.RLock()
	current := c.currentAIDObj
	gatewayURL := c.gatewayURL
	c.mu.RUnlock()
	if current == nil || !current.IsPrivateKeyValid() {
		return nil, NewStateError("Authenticate requires a loaded AID with a valid private key")
	}
	if gatewayURL == "" {
		resolved, err := c.resolveGatewayForAID(ctx, current.Aid)
		if err != nil {
			return nil, fmt.Errorf("authenticate gateway discovery failed: %w", err)
		}
		gatewayURL = resolved
	}
	result, err := c.auth.Authenticate(ctx, gatewayURL, current.Aid)
	if err != nil {
		c.mu.Lock()
		l.runtime.lifecycle.setErrorLocked(err)
		l.runtime.lifecycle.setAuthenticatedLocked(false)
		c.mu.Unlock()
		return nil, err
	}
	c.mu.Lock()
	l.runtime.identity.setIdentity(c.auth.LoadIdentityOrNil(current.Aid))
	l.runtime.identity.setAid(current.Aid)
	l.runtime.lifecycle.setGatewayURLLocked(gatewayURL)
	l.runtime.lifecycle.setAuthenticatedLocked(true)
	if c.state == StateIdle {
		l.runtime.lifecycle.setStateLocked(StateDisconnected)
	}
	l.runtime.lifecycle.setErrorLocked(nil)
	c.mu.Unlock()
	return result, nil
}

func (l *lifecycleController) connect(ctx context.Context, opts ...ConnectionOptions) error {
	c := l.runtime.client
	c.mu.RLock()
	current := c.currentAIDObj
	authenticated := c.authenticated
	c.mu.RUnlock()
	if current == nil || !current.IsPrivateKeyValid() {
		return NewStateError("Connect requires a loaded AID with a valid private key")
	}
	if !authenticated {
		if _, err := c.Authenticate(ctx); err != nil {
			return fmt.Errorf("connect: authenticate failed: %w", err)
		}
	}
	var connOpt *ConnectionOptions
	if len(opts) > 0 {
		connOpt = &opts[0]
	}
	return l.connectWithLoadedIdentity(ctx, connectionOptionsToConnectOptions(connOpt, c))
}

func (l *lifecycleController) connectWithLoadedIdentity(ctx context.Context, opts *ConnectOptions) error {
	c := l.runtime.client
	c.mu.RLock()
	current := c.currentAIDObj
	gatewayURL := c.gatewayURL
	c.mu.RUnlock()
	if current == nil || !current.IsPrivateKeyValid() {
		return NewStateError("Connect requires a loaded AID with a valid private key")
	}
	if gatewayURL == "" {
		resolved, err := c.resolveGatewayForAID(ctx, current.Aid)
		if err != nil {
			return fmt.Errorf("connect gateway discovery failed: %w", err)
		}
		gatewayURL = resolved
	}
	params := map[string]any{
		"gateway": gatewayURL,
	}
	return l.connectWithParams(ctx, params, opts, true, false)
}

func (l *lifecycleController) connectWithParams(ctx context.Context, params map[string]any, opts *ConnectOptions, allowReauth bool, requireAccessToken bool) (err error) {
	c := l.runtime.client
	tStart := time.Now()
	gatewayURL := ""
	if params != nil {
		gatewayURL, _ = params["gateway"].(string)
		if gatewayURL == "" {
			gatewayURL, _ = params["gateway_url"].(string)
		}
	}
	c.log.Debug("Connect enter: gateway=%s", gatewayURL)
	defer func() {
		if err != nil {
			c.log.Debug("Connect exit (error): gateway=%s elapsed=%dms err=%v", gatewayURL, time.Since(tStart).Milliseconds(), err)
		} else {
			c.log.Debug("Connect exit: gateway=%s elapsed=%dms", gatewayURL, time.Since(tStart).Milliseconds())
		}
	}()

	c.mu.Lock()
	switch c.state {
	case StateIdle, StateClosed, StateDisconnected, StateReconnecting, StateTerminalFailed:
	default:
		st := c.state
		c.mu.Unlock()
		return NewStateError(fmt.Sprintf("connect 不允许在状态 %s 下调用", st))
	}
	if c.state == StateReconnecting && c.reconnectCancel != nil {
		cancel := c.reconnectCancel
		l.runtime.lifecycle.clearReconnectCancelLocked()
		c.mu.Unlock()
		cancel()
		for i := 0; i < 200 && c.reconnecting.Load(); i++ {
			time.Sleep(5 * time.Millisecond)
		}
		c.mu.Lock()
	}
	if c.state == StateTerminalFailed {
		l.runtime.lifecycle.clearRetryStateLocked()
	}
	l.runtime.lifecycle.clearNextRetryAtLocked()
	l.runtime.lifecycle.setStateLocked(StateConnecting)
	c.mu.Unlock()

	merged := make(map[string]any)
	for k, v := range params {
		merged[k] = v
	}
	if opts != nil {
		if opts.ConnectionKind != "" {
			merged["connection_kind"] = opts.ConnectionKind
		}
		if opts.ShortTtlMs > 0 {
			merged["short_ttl_ms"] = opts.ShortTtlMs
		}
		if len(opts.ExtraInfo) > 0 {
			merged["extra_info"] = opts.ExtraInfo
		}
		if len(opts.DeliveryMode) > 0 {
			merged["delivery_mode"] = copyMapShallow(opts.DeliveryMode)
		}
	}

	normalized, normErr := c.normalizeConnectParamsWithTokenPolicy(merged, requireAccessToken)
	if normErr != nil {
		c.mu.Lock()
		l.runtime.lifecycle.setStateLocked(StateDisconnected)
		c.mu.Unlock()
		err = normErr
		return err
	}

	c.mu.Lock()
	l.runtime.lifecycle.setSessionLocked(normalized, c.buildSessionOptions(normalized, opts))
	l.runtime.lifecycle.setClosing(false)
	c.mu.Unlock()

	c.mu.RLock()
	if timeouts, ok := c.sessionOptions["timeouts"].(map[string]any); ok {
		if callTimeout, ok := timeouts["call"].(float64); ok {
			c.transport.SetTimeout(time.Duration(callTimeout * float64(time.Second)))
		}
	}
	c.mu.RUnlock()

	gateways := c.resolveGateways(normalized)
	var lastErr error
	for _, gw := range gateways {
		gwParams := make(map[string]any)
		for k, v := range normalized {
			gwParams[k] = v
		}
		gwParams["gateway"] = gw
		lastErr = l.connectOnce(ctx, gwParams, allowReauth)
		if lastErr == nil {
			c.mu.Lock()
			l.runtime.lifecycle.setAuthenticatedLocked(true)
			l.runtime.lifecycle.setErrorLocked(nil)
			c.mu.Unlock()
			return nil
		}
		if len(gateways) > 1 {
			c.log.Warn("Connect: gateway %s failed, trying next: %v", gw, lastErr)
		}
		c.mu.Lock()
		if c.state == StateConnecting || c.state == StateAuthenticating {
			l.runtime.lifecycle.setStateLocked(StateConnecting)
		}
		c.mu.Unlock()
	}
	err = lastErr
	if err != nil {
		c.log.Error("Connect failed: err=%v", err)
		c.mu.Lock()
		l.runtime.lifecycle.setErrorLocked(err)
		if c.state == StateConnecting || c.state == StateAuthenticating {
			l.runtime.lifecycle.setStateLocked(StateDisconnected)
		}
		c.mu.Unlock()
	}
	return err
}

func (l *lifecycleController) connectOnce(ctx context.Context, params map[string]any, allowReauth bool) (err error) {
	c := l.runtime.client
	tStart := time.Now()
	gatewayURL := c.resolveGateway(params)
	c.log.Debug("connectOnce enter: gateway=%s allowReauth=%v", gatewayURL, allowReauth)
	defer func() {
		if err != nil {
			c.log.Debug("connectOnce exit (error): gateway=%s elapsed=%dms err=%v", gatewayURL, time.Since(tStart).Milliseconds(), err)
		} else {
			c.log.Debug("connectOnce exit: gateway=%s elapsed=%dms", gatewayURL, time.Since(tStart).Milliseconds())
		}
	}()

	c.mu.Lock()
	l.runtime.lifecycle.setGatewayURLLocked(gatewayURL)
	l.runtime.identity.setInstanceContext(c.deviceID, strings.TrimSpace(fmt.Sprint(params["slot_id"])))
	if deliveryMode, ok := params["delivery_mode"].(map[string]any); ok {
		l.runtime.lifecycle.setConnectDeliveryModeLocked(copyMapShallow(deliveryMode))
	}
	c.auth.SetDeliveryMode(c.connectDeliveryMode)
	l.runtime.lifecycle.setStateLocked(StateConnecting)
	l.runtime.delivery.refreshSeqTrackerContextLocked()
	c.mu.Unlock()
	c.restoreSeqTrackerState()

	c.log.Debug("WebSocket connecting: gateway=%s", gatewayURL)
	challenge, connErr := c.transport.Connect(ctx, gatewayURL)
	if connErr != nil {
		c.log.Error("WebSocket connection failed: gateway=%s err=%v", gatewayURL, connErr)
		err = connErr
		return err
	}
	if c.dnsNet != nil {
		c.dnsNet.refreshDNSCacheAfterSuccess(gatewayURL)
	}
	c.log.Debug("WebSocket connected, starting auth: gateway=%s", gatewayURL)

	c.mu.Lock()
	l.runtime.lifecycle.setStateLocked(StateAuthenticating)
	c.mu.Unlock()

	connectionKind, _ := params["connection_kind"].(string)
	if connectionKind == "" {
		connectionKind = "long"
	}
	shortTtlMs := 0
	if v, ok := params["short_ttl_ms"].(int); ok {
		shortTtlMs = v
	}
	var extraInfo map[string]any
	if ei, ok := params["extra_info"].(map[string]any); ok && len(ei) > 0 {
		extraInfo = ei
	}

	if allowReauth {
		accessToken, _ := params["access_token"].(string)
		authContext, authErr := c.auth.ConnectSession(ctx, c.transport, challenge, gatewayURL, accessToken, connectionKind, shortTtlMs, extraInfo)
		if authErr != nil {
			c.log.Error("auth failed (ConnectSession): gateway=%s err=%v", gatewayURL, authErr)
			err = authErr
			return err
		}
		if authContext != nil {
			identity, _ := authContext["identity"].(map[string]any)
			if identity != nil {
				c.mu.Lock()
				l.runtime.identity.setIdentity(identity)
				if aidStr, ok := identity["aid"].(string); ok {
					l.runtime.identity.setAid(aidStr)
				}
				if token, ok := authContext["token"].(string); ok && token != "" {
					l.runtime.lifecycle.setSessionAccessTokenLocked(token)
				}
				c.mu.Unlock()
			}
			if hello, ok := authContext["hello"].(map[string]any); ok && hello != nil {
				if raw, exists := hello["heartbeat_interval"]; exists {
					c.applyServerHeartbeatInterval(raw, "auth")
				}
			}
		}
	} else {
		accessToken, _ := params["access_token"].(string)
		hello, initErr := c.auth.InitializeWithToken(ctx, c.transport, challenge, accessToken, connectionKind, shortTtlMs, extraInfo)
		if initErr != nil {
			c.log.Error("auth failed (InitializeWithToken): gateway=%s err=%v", gatewayURL, initErr)
			err = initErr
			return err
		}
		l.runtime.identity.syncAfterConnect(accessToken)
		if hello != nil {
			if raw, exists := hello["heartbeat_interval"]; exists {
				c.applyServerHeartbeatInterval(raw, "auth")
			}
		}
	}

	c.mu.Lock()
	l.runtime.lifecycle.setStateLocked(StateConnected)
	l.runtime.lifecycle.setConnectedAtLocked(time.Now())
	l.runtime.lifecycle.clearNextRetryAtLocked()
	prevContext := c.seqTrackerContext
	l.runtime.delivery.refreshSeqTrackerContextLocked()
	contextChanged := c.seqTrackerContext != prevContext
	c.mu.Unlock()

	c.log.Debug("connection auth completed, state switched to connected: gateway=%s aid=%s", gatewayURL, c.AID())
	c.events.Publish("state_change", map[string]any{"state": string(c.ConnectionState()), "gateway": gatewayURL})

	if contextChanged {
		c.restoreSeqTrackerState()
	}
	l.startBackgroundTasks(ctx)

	bgSync := true
	if v, ok := c.sessionOptions["background_sync"].(bool); ok {
		bgSync = v
	}
	c.getV2E2EECoordinator().onConnected(ctx, bgSync)

	if bgSync {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					c.log.Warn("post-connect P2P gap fill panic: %v", r)
				}
			}()
			c.fillP2pGap()
		}()
	}

	return nil
}

func (l *lifecycleController) disconnect() (err error) {
	c := l.runtime.client
	tStart := time.Now()
	c.log.Debug("Disconnect enter")
	defer func() {
		if err != nil {
			c.log.Debug("Disconnect exit (error): elapsed=%dms err=%v", time.Since(tStart).Milliseconds(), err)
		} else {
			c.log.Debug("Disconnect exit: elapsed=%dms", time.Since(tStart).Milliseconds())
		}
	}()
	c.mu.Lock()
	state := c.state
	if state != StateConnected && state != StateReconnecting {
		c.mu.Unlock()
		return nil
	}
	cancelFn := c.cancel
	c.mu.Unlock()

	c.saveSeqTrackerState()
	if cancelFn != nil {
		cancelFn()
	}
	if err := c.transport.Close(); err != nil {
		c.log.Warn("Disconnect failed to close transport: %v", err)
	}

	c.mu.Lock()
	l.runtime.lifecycle.setStateLocked(StateDisconnected)
	l.runtime.lifecycle.setAuthenticatedLocked(false)
	c.mu.Unlock()

	c.events.Publish("state_change", map[string]any{"state": string(c.ConnectionState())})
	return nil
}

func (l *lifecycleController) close() (err error) {
	c := l.runtime.client
	tStart := time.Now()
	c.log.Debug("Close enter")
	defer func() {
		if err != nil {
			c.log.Debug("Close exit (error): elapsed=%dms err=%v", time.Since(tStart).Milliseconds(), err)
		} else {
			c.log.Debug("Close exit: elapsed=%dms", time.Since(tStart).Milliseconds())
		}
	}()
	c.mu.Lock()
	l.runtime.lifecycle.setClosing(true)
	state := c.state
	cancelFn := c.cancel
	c.mu.Unlock()

	c.saveSeqTrackerState()
	if cancelFn != nil {
		cancelFn()
	}

	if state == StateIdle || state == StateClosed {
		if closer, ok := c.tokenStore.(interface{ Close() }); ok {
			closer.Close()
		}
		if c.dnsNet != nil {
			c.dnsNet.Close()
		}
		c.releaseV2State()
		c.mu.Lock()
		l.runtime.lifecycle.resetForCloseLocked()
		c.mu.Unlock()
		return nil
	}

	if err := c.transport.Close(); err != nil {
		c.log.Warn("failed to close transport: %v", err)
	}
	if closer, ok := c.tokenStore.(interface{ Close() }); ok {
		closer.Close()
	}
	if c.dnsNet != nil {
		c.dnsNet.Close()
	}
	c.releaseV2State()

	c.mu.Lock()
	l.runtime.lifecycle.resetForCloseLocked()
	c.mu.Unlock()

	c.events.Publish("state_change", map[string]any{"state": string(c.ConnectionState())})
	return nil
}

func (l *lifecycleController) startBackgroundTasks(_ context.Context) {
	c := l.runtime.client
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	l.runtime.lifecycle.setBackgroundContextLocked(ctx, cancel)
	connectionKind := ""
	if opts := c.sessionOptions; opts != nil {
		connectionKind, _ = opts["connection_kind"].(string)
	}
	c.mu.Unlock()

	if connectionKind != "short" {
		go c.heartbeatLoop(ctx)
		go c.tokenRefreshLoop(ctx)
	}
	c.startCacheCleanupTask(ctx)
}

func (l *lifecycleController) onGatewayDisconnect(payload any) {
	c := l.runtime.client
	data, _ := payload.(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	code := data["code"]
	reason := data["reason"]
	detail, _ := data["detail"].(map[string]any)
	if detail == nil {
		detail = map[string]any{}
	}
	c.log.Warn("server initiated disconnect: code=%v, reason=%v, detail=%v", code, reason, detail)
	l.runtime.lifecycle.setServerKicked(true)
	l.runtime.lifecycle.setLastDisconnectInfo(map[string]any{
		"code":   code,
		"reason": reason,
		"detail": detail,
	})
	c.events.Publish("gateway.disconnect", map[string]any{
		"code":   code,
		"reason": reason,
		"detail": detail,
	})
}

func (l *lifecycleController) handleTransportDisconnect(err error, closeCode int) {
	c := l.runtime.client
	c.log.Warn("transport disconnected: closeCode=%d err=%v", closeCode, err)
	c.mu.Lock()
	isClosing := c.closing.Load()
	state := c.state
	if isClosing || state == StateClosed {
		c.mu.Unlock()
		return
	}
	l.runtime.lifecycle.resetForDisconnectLocked(StateDisconnected)
	c.mu.Unlock()

	c.events.Publish("state_change", map[string]any{
		"state": string(c.ConnectionState()),
		"error": err,
	})

	c.mu.RLock()
	autoReconnect := false
	if opts := c.sessionOptions; opts != nil {
		if v, ok := opts["auto_reconnect"].(bool); ok {
			autoReconnect = v
		}
	}
	c.mu.RUnlock()

	if !autoReconnect {
		return
	}

	if c.serverKicked.Load() || noReconnectCodes[closeCode] {
		c.mu.Lock()
		l.runtime.lifecycle.setTerminalFailedLocked(err)
		c.mu.Unlock()
		reason := "server kicked"
		if !c.serverKicked.Load() {
			reason = fmt.Sprintf("close code %d", closeCode)
		}
		c.log.Warn("suppressing auto-reconnect: %s", reason)
		eventPayload := map[string]any{
			"state":  string(c.ConnectionState()),
			"error":  err,
			"reason": reason,
		}
		c.lastDisconnectMu.Lock()
		info := c.lastDisconnectInfo
		c.lastDisconnectMu.Unlock()
		if info != nil {
			if detail, ok := info["detail"].(map[string]any); ok && len(detail) > 0 {
				eventPayload["detail"] = detail
			}
			if code, ok := info["code"]; ok && code != nil {
				eventPayload["code"] = code
			}
		}
		c.events.Publish("state_change", eventPayload)
		return
	}

	if c.reconnecting.CompareAndSwap(false, true) {
		serverInitiated := closeCode != -1
		c.log.Info("triggering auto-reconnect: serverInitiated=%v closeCode=%d", serverInitiated, closeCode)
		reconnCtx, reconnCancel := context.WithCancel(context.Background())
		c.mu.Lock()
		l.runtime.lifecycle.setReconnectCancelLocked(reconnCancel)
		c.mu.Unlock()
		go l.reconnectLoop(reconnCtx, serverInitiated)
	}
}

func (l *lifecycleController) reconnectLoop(ctx context.Context, serverInitiated bool) {
	c := l.runtime.client
	c.mu.RLock()
	opts := c.sessionOptions
	c.mu.RUnlock()

	retryConfig, _ := opts["retry"].(map[string]any)
	initialDelay := 1.0
	maxBaseDelay := 64.0
	maxAttempts := 0
	if retryConfig != nil {
		if v, ok := retryConfig["initial_delay"].(float64); ok {
			initialDelay = v
		}
		if v, ok := retryConfig["max_delay"].(float64); ok {
			maxBaseDelay = v
		}
		if v, ok := retryConfig["max_attempts"].(float64); ok && v > 0 {
			maxAttempts = int(v)
		}
	}
	maxBaseDelay = clampReconnectDelaySeconds(maxBaseDelay, reconnectMaxBaseDelaySeconds, reconnectMaxBaseDelaySeconds)

	delay := initialDelay
	delayFallback := 1.0
	if serverInitiated {
		delay = 16.0
		delayFallback = 16.0
	}
	delay = clampReconnectDelaySeconds(delay, delayFallback, maxBaseDelay)
	for attempt := 1; !c.closing.Load() && ctx.Err() == nil; attempt++ {
		if maxAttempts > 0 && attempt > maxAttempts {
			c.log.Warn("reconnect exceeded max attempts %d, stopping retry", maxAttempts)
			maxErr := fmt.Errorf("超过最大重连次数 %d", maxAttempts)
			c.mu.Lock()
			l.runtime.lifecycle.setTerminalFailedLocked(maxErr)
			c.mu.Unlock()
			c.events.Publish("state_change", map[string]any{
				"state":   string(c.ConnectionState()),
				"error":   maxErr,
				"attempt": attempt - 1,
			})
			c.reconnecting.Store(false)
			return
		}

		jitteredDelay := reconnectSleepDelaySeconds(delay, maxBaseDelay)
		sleepDuration := time.Duration(jitteredDelay * float64(time.Second))
		nextRetryAt := time.Now().Add(sleepDuration)
		c.mu.Lock()
		l.runtime.lifecycle.setRetryBackoffLocked(attempt, nextRetryAt)
		c.mu.Unlock()

		c.events.Publish("state_change", map[string]any{
			"state":         string(c.ConnectionState()),
			"attempt":       attempt,
			"next_retry_at": nextRetryAt,
		})

		select {
		case <-time.After(sleepDuration):
		case <-ctx.Done():
			c.reconnecting.Store(false)
			return
		}

		if c.closing.Load() || ctx.Err() != nil {
			c.reconnecting.Store(false)
			return
		}
		c.mu.Lock()
		l.runtime.lifecycle.clearNextRetryAtLocked()
		l.runtime.lifecycle.setStateLocked(StateReconnecting)
		c.mu.Unlock()
		c.events.Publish("state_change", map[string]any{
			"state":   string(c.ConnectionState()),
			"attempt": attempt,
		})

		c.mu.RLock()
		gw := c.gatewayURL
		c.mu.RUnlock()
		if gw != "" {
			healthy := c.discovery.CheckHealth(context.Background(), gw, 5*time.Second)
			if !healthy {
				delay = delay * 2
				if delay > maxBaseDelay {
					delay = maxBaseDelay
				}
				continue
			}
		}

		_ = c.transport.Close()

		c.mu.RLock()
		params := c.sessionParams
		identity := c.identity
		c.mu.RUnlock()
		if params == nil {
			c.mu.Lock()
			l.runtime.lifecycle.setTerminalFailedLocked(nil)
			c.mu.Unlock()
			c.events.Publish("state_change", map[string]any{"state": string(c.ConnectionState())})
			c.reconnecting.Store(false)
			return
		}

		// 重连前同步 identity 里的 token 状态到 params，防止用过期 token 死循环 4001
		if identity != nil {
			cachedToken, _ := identity["access_token"].(string)
			expiresAt := c.auth.GetAccessTokenExpiry(identity)
			if cachedToken != "" && (expiresAt == 0 || expiresAt > float64(time.Now().Unix())+30) {
				params["access_token"] = cachedToken
			} else {
				c.log.Debug("reconnect: cached token expired or missing for aid=%s, clearing to trigger re-login", c.aid)
				params["access_token"] = ""
			}
		} else {
			params["access_token"] = ""
		}

		err := l.connectOnce(context.Background(), params, true)
		if err == nil {
			c.log.Info("reconnect succeeded: attempt=%d", attempt)
			c.reconnecting.Store(false)
			return
		}

		c.log.Warn("reconnect failed: attempt=%d err=%v", attempt, err)
		c.events.Publish("connection.error", map[string]any{
			"error":   err,
			"attempt": attempt,
		})

		if !shouldRetryReconnect(err) {
			c.mu.Lock()
			l.runtime.lifecycle.setTerminalFailedLocked(err)
			c.mu.Unlock()
			c.events.Publish("state_change", map[string]any{
				"state":   string(c.ConnectionState()),
				"error":   err,
				"attempt": attempt,
			})
			c.reconnecting.Store(false)
			return
		}

		delay = delay * 2
		if delay > maxBaseDelay {
			delay = maxBaseDelay
		}
	}
	c.reconnecting.Store(false)
}
