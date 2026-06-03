package aun

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

type peerDirectory struct {
	runtime *clientRuntime
}

func newPeerDirectory(runtime *clientRuntime) *peerDirectory {
	return &peerDirectory{runtime: runtime}
}

func (d *peerDirectory) cachePeer(aid *AID) (*AID, error) {
	c := d.runtime.client
	if !c.HasIdentity() {
		return nil, NewStateError("CachePeer requires a loaded identity")
	}
	if aid == nil || !aid.IsCertValid() {
		return nil, NewValidationError("CachePeer requires an AID with a valid certificate")
	}
	c.peerCacheMu.Lock()
	c.peerCache[aid.Aid] = aid
	c.peerCacheMu.Unlock()
	return aid, nil
}

func (d *peerDirectory) getPeer(aid string) *AID {
	c := d.runtime.client
	if !c.HasIdentity() {
		return nil
	}
	c.peerCacheMu.RLock()
	defer c.peerCacheMu.RUnlock()
	return c.peerCache[strings.TrimSpace(aid)]
}

func (d *peerDirectory) lookupPeer(ctx context.Context, aid string) (*AID, error) {
	c := d.runtime.client
	if !c.HasIdentity() {
		return nil, NewStateError("LookupPeer requires a loaded identity")
	}
	target := strings.TrimSpace(aid)
	if target == "" {
		return nil, NewValidationError("LookupPeer requires non-empty aid")
	}
	if cached := d.getPeer(target); cached != nil {
		return cached, nil
	}
	certBytes, fetchErr := c.fetchPeerCert(ctx, target, "")
	if fetchErr != nil {
		return nil, fetchErr
	}
	certPEM := string(certBytes)
	peer, err := d.publicAIDFromCert(target, certPEM)
	if err != nil {
		return nil, err
	}
	if !peer.IsCertValid() {
		return nil, NewAUNError(fmt.Sprintf("resolved peer certificate is invalid: %s", target))
	}
	c.peerCacheMu.Lock()
	c.peerCache[peer.Aid] = peer
	c.peerCacheMu.Unlock()
	return peer, nil
}

func (d *peerDirectory) publicAIDFromCert(aid, certPEM string) (*AID, error) {
	c := d.runtime.client
	target := strings.TrimSpace(aid)
	cert, err := parsePEMCertificate(certPEM)
	if err != nil {
		return nil, NewAUNError(fmt.Sprintf("peer certificate parse failed: %s", target))
	}
	if tErr := certTimeError(cert); tErr != "" {
		return nil, NewAUNError(fmt.Sprintf("peer certificate is %s: %s", tErr, target))
	}
	if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" && cn != target {
		return nil, NewAUNError(fmt.Sprintf("peer certificate CN mismatch: expected %s, got %s", target, cn))
	}
	debug := false
	if c.logger != nil {
		debug = c.logger.Debug()
	}
	return newAID(
		target,
		c.configModel.AUNPath,
		certPEM,
		cert,
		nil,
		true,
		false,
		c.deviceID,
		c.slotID,
		c.configModel.VerifySSL,
		c.configModel.RootCAPath,
		debug,
		"",
	), nil
}

func (d *peerDirectory) peers() []*AID {
	c := d.runtime.client
	c.peerCacheMu.RLock()
	defer c.peerCacheMu.RUnlock()
	result := make([]*AID, 0, len(c.peerCache))
	for _, v := range c.peerCache {
		result = append(result, v)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Aid < result[j].Aid })
	return result
}
