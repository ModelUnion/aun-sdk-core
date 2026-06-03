package aun

import (
	"fmt"
	"time"
)

type identityRuntimeManager struct {
	runtime *clientRuntime
}

func newIdentityRuntimeManager(runtime *clientRuntime) *identityRuntimeManager {
	return &identityRuntimeManager{runtime: runtime}
}

func (m *identityRuntimeManager) loadIdentity(aid *AID) error {
	c := m.runtime.client
	if aid == nil || !aid.IsPrivateKeyValid() {
		return NewStateError("LoadIdentity requires an AID with a valid private key")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != StateIdle && c.state != StateClosed {
		return NewStateError(fmt.Sprintf("LoadIdentity not allowed in state %s", c.state))
	}
	c.rebuildRuntimeForIdentity(aid)
	c.currentAIDObj = aid
	c.aid = aid.Aid
	if aid.DeviceID != "" {
		c.deviceID = aid.DeviceID
	}
	if aid.SlotID != "" {
		c.slotID = aid.SlotID
	}
	if c.auth != nil {
		c.auth.aid = aid.Aid
		c.auth.SetInstanceContext(c.deviceID, c.slotID)
		c.auth.SetIdentity(map[string]any{
			"aid":                aid.Aid,
			"private_key_pem":    aid.PrivateKeyPem,
			"public_key_der_b64": aid.PublicKey,
			"cert":               aid.CertPem,
		})
	}
	c.identity = map[string]any{
		"aid":                aid.Aid,
		"private_key_pem":    aid.PrivateKeyPem,
		"public_key_der_b64": aid.PublicKey,
		"cert":               aid.CertPem,
	}
	c.authenticated = false
	c.lastConnectError = nil
	c.retryAttempt = 0
	c.nextRetryAt = time.Time{}
	c.state = StateIdle
	return nil
}
