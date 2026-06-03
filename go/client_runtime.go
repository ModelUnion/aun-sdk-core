package aun

type clientRuntime struct {
	client *AUNClient
}

func newClientRuntime(client *AUNClient) *clientRuntime {
	return &clientRuntime{client: client}
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
