package aun

import (
	"context"
	"fmt"
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
		c.lastConnectError = err
		c.authenticated = false
		c.mu.Unlock()
		return nil, err
	}
	c.mu.Lock()
	c.identity = c.auth.LoadIdentityOrNil(current.Aid)
	c.aid = current.Aid
	c.gatewayURL = gatewayURL
	c.authenticated = true
	if c.state == StateIdle {
		c.state = StateDisconnected
	}
	c.lastConnectError = nil
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
		c.reconnectCancel = nil
		c.mu.Unlock()
		cancel()
		for i := 0; i < 200 && c.reconnecting.Load(); i++ {
			time.Sleep(5 * time.Millisecond)
		}
		c.mu.Lock()
	}
	if c.state == StateTerminalFailed {
		c.retryAttempt = 0
		c.lastConnectError = nil
	}
	c.nextRetryAt = time.Time{}
	c.state = StateConnecting
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
		c.state = StateDisconnected
		c.mu.Unlock()
		err = normErr
		return err
	}

	c.mu.Lock()
	c.sessionParams = normalized
	c.sessionOptions = c.buildSessionOptions(normalized, opts)
	c.closing.Store(false)
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
		lastErr = c.connectOnce(ctx, gwParams, allowReauth)
		if lastErr == nil {
			c.mu.Lock()
			c.authenticated = true
			c.lastConnectError = nil
			c.mu.Unlock()
			return nil
		}
		if len(gateways) > 1 {
			c.log.Warn("Connect: gateway %s failed, trying next: %v", gw, lastErr)
		}
		c.mu.Lock()
		if c.state == StateConnecting || c.state == StateAuthenticating {
			c.state = StateConnecting
		}
		c.mu.Unlock()
	}
	err = lastErr
	if err != nil {
		c.log.Error("Connect failed: err=%v", err)
		c.mu.Lock()
		c.lastConnectError = err
		if c.state == StateConnecting || c.state == StateAuthenticating {
			c.state = StateDisconnected
		}
		c.mu.Unlock()
	}
	return err
}
