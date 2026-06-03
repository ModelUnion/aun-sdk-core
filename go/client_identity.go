package aun

import (
	"fmt"
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
	deviceID := c.deviceID
	if aid.DeviceID != "" {
		deviceID = aid.DeviceID
	}
	slotID := c.slotID
	if aid.SlotID != "" {
		slotID = aid.SlotID
	}
	m.runtime.identity.setInstanceContext(deviceID, slotID)
	identity := map[string]any{
		"aid":                aid.Aid,
		"private_key_pem":    aid.PrivateKeyPem,
		"public_key_der_b64": aid.PublicKey,
		"cert":               aid.CertPem,
	}
	m.runtime.identity.setLoadedIdentity(aid, identity)
	m.runtime.v2.resetForIdentityLocked()
	m.runtime.lifecycle.setAuthenticatedLocked(false)
	m.runtime.lifecycle.clearRetryStateLocked()
	m.runtime.lifecycle.setStateLocked(StateIdle)
	return nil
}
