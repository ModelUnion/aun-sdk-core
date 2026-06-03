package aun

import (
	"context"
	"errors"
	"testing"
	"time"
)

func componentTestAID(aid string, certValid, privateKeyValid bool) *AID {
	a := newAID(
		aid,
		"",
		"cert:"+aid,
		nil,
		nil,
		certValid,
		privateKeyValid,
		"dev-"+aid,
		"slot-"+aid,
		false,
		"",
		false,
		"priv:"+aid,
	)
	a.PublicKey = "pub:" + aid
	return a
}

func TestIdentityRuntimeManagerLoadIdentityResetsRuntime(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()
	c.authenticated = true
	c.lastConnectError = errors.New("old")
	c.retryAttempt = 3
	c.nextRetryAt = time.Now().Add(time.Minute)
	aid := componentTestAID("alice.aid.com", true, true)

	if err := c.getIdentityRuntime().loadIdentity(aid); err != nil {
		t.Fatalf("loadIdentity failed: %v", err)
	}

	if c.currentAIDObj != aid {
		t.Fatal("loadIdentity 应保存 currentAIDObj")
	}
	if c.aid != "alice.aid.com" {
		t.Fatalf("aid mismatch: %s", c.aid)
	}
	if c.identity["private_key_pem"] != "priv:alice.aid.com" || c.identity["public_key_der_b64"] != "pub:alice.aid.com" {
		t.Fatalf("identity 写入不完整: %#v", c.identity)
	}
	if c.state != StateIdle {
		t.Fatalf("state 应回到 idle，实际: %s", c.state)
	}
	if c.authenticated {
		t.Fatal("loadIdentity 后 authenticated 应清零")
	}
	if c.lastConnectError != nil || c.retryAttempt != 0 || !c.nextRetryAt.IsZero() {
		t.Fatalf("重连错误状态未清理: err=%v retry=%d next=%v", c.lastConnectError, c.retryAttempt, c.nextRetryAt)
	}
	if c.ConnectionState() != ConnStateStandby {
		t.Fatalf("公开状态应为 standby，实际: %s", c.ConnectionState())
	}
}

func TestIdentityRuntimeManagerRejectsInvalidAIDAndState(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()

	if err := c.getIdentityRuntime().loadIdentity(componentTestAID("alice.aid.com", true, false)); err == nil {
		t.Fatal("无有效私钥 AID 应被拒绝")
	} else if _, ok := err.(*StateError); !ok {
		t.Fatalf("期望 StateError，实际: %T %v", err, err)
	}

	c.state = StateConnecting
	if err := c.getIdentityRuntime().loadIdentity(componentTestAID("alice.aid.com", true, true)); err == nil {
		t.Fatal("connecting 状态 loadIdentity 应被拒绝")
	} else if _, ok := err.(*StateError); !ok {
		t.Fatalf("期望 StateError，实际: %T %v", err, err)
	}
}

func TestPeerDirectoryCacheGetLookupAndSort(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()
	c.currentAIDObj = componentTestAID("self.aid.com", true, true)
	c.state = StateIdle
	d := c.getPeerDirectory()
	bob := componentTestAID("bob.aid.com", true, false)
	alice := componentTestAID("alice.aid.com", true, false)

	if got, err := d.cachePeer(bob); err != nil || got != bob {
		t.Fatalf("cachePeer bob failed: got=%v err=%v", got, err)
	}
	if _, err := d.cachePeer(alice); err != nil {
		t.Fatalf("cachePeer alice failed: %v", err)
	}
	if got := d.getPeer(" bob.aid.com "); got != bob {
		t.Fatalf("getPeer 应 trim 后命中 bob，实际: %v", got)
	}
	if got, err := d.lookupPeer(context.Background(), "bob.aid.com"); err != nil || got != bob {
		t.Fatalf("lookupPeer cached failed: got=%v err=%v", got, err)
	}
	peers := d.peers()
	if len(peers) != 2 || peers[0] != alice || peers[1] != bob {
		t.Fatalf("peers 应按 aid 排序，实际: %#v", peers)
	}
}

func TestPeerDirectoryRejectsMissingIdentityInvalidCertAndEmptyLookup(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()
	d := c.getPeerDirectory()

	if _, err := d.cachePeer(componentTestAID("bob.aid.com", true, false)); err == nil {
		t.Fatal("无身份 cachePeer 应被拒绝")
	} else if _, ok := err.(*StateError); !ok {
		t.Fatalf("期望 StateError，实际: %T %v", err, err)
	}

	c.currentAIDObj = componentTestAID("self.aid.com", true, true)
	c.state = StateIdle
	if _, err := d.cachePeer(componentTestAID("bob.aid.com", false, false)); err == nil {
		t.Fatal("无有效证书 peer 应被拒绝")
	} else if _, ok := err.(*ValidationError); !ok {
		t.Fatalf("期望 ValidationError，实际: %T %v", err, err)
	}
	if _, err := d.lookupPeer(context.Background(), "   "); err == nil {
		t.Fatal("空 aid lookupPeer 应被拒绝")
	} else if _, ok := err.(*ValidationError); !ok {
		t.Fatalf("期望 ValidationError，实际: %T %v", err, err)
	}
}

func TestGroupStateCoordinatorPublishesSecurityLevelOnlyOnChange(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()
	g := c.getGroupStateCoordinator()
	events := []map[string]any{}
	c.events.Subscribe("group.v2.security_level", func(payload any) {
		if m, ok := payload.(map[string]any); ok {
			events = append(events, m)
		}
	})

	g.publishGroupSecurityLevel("group.agentid.pub/12345", map[string]any{
		"e2ee_security_level":   "degraded",
		"e2ee_security_warning": "missing devices",
	})
	g.publishGroupSecurityLevel("group.agentid.pub/12345", map[string]any{
		"e2ee_security_level":   "degraded",
		"e2ee_security_warning": "same",
	})
	g.publishGroupSecurityLevel("group.agentid.pub/12345", map[string]any{
		"e2ee_security_level": "end_to_end",
	})

	if len(events) != 2 {
		t.Fatalf("security_level 应仅在等级变化时发布 2 次，实际: %#v", events)
	}
	if events[0]["level"] != "degraded" || events[0]["previous_level"] != nil || events[0]["warning"] != "missing devices" {
		t.Fatalf("首次 security_level payload 不正确: %#v", events[0])
	}
	if events[1]["level"] != "end_to_end" || events[1]["previous_level"] != "degraded" {
		t.Fatalf("第二次 security_level payload 不正确: %#v", events[1])
	}
}

func TestGroupStateCoordinatorStateConfirmedClearsCacheAndSnapshot(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()
	groupID := "group.agentid.pub/12345"
	c.v2State = &v2P2PState{
		bootstrapCache:      make(map[string]v2BootstrapEntry),
		groupBootstrapCache: map[string]*v2GroupBootstrapEntry{groupID: {CachedAt: time.Now()}},
	}
	c.v2AutoProposeLastSnapshot[groupID] = "snapshot"
	events := []map[string]any{}
	c.events.Subscribe("group.v2.state_confirmed", func(payload any) {
		if m, ok := payload.(map[string]any); ok {
			events = append(events, m)
		}
	})

	c.getGroupStateCoordinator().onV2StateConfirmed(map[string]any{"group_id": groupID})

	c.v2State.bootstrapCacheM.Lock()
	_, cached := c.v2State.groupBootstrapCache[groupID]
	c.v2State.bootstrapCacheM.Unlock()
	if cached {
		t.Fatal("state_confirmed 应清理 group bootstrap cache")
	}
	if _, ok := c.v2AutoProposeLastSnapshot[groupID]; ok {
		t.Fatal("state_confirmed 应清理 auto propose snapshot")
	}
	if len(events) != 1 || events[0]["group_id"] != groupID {
		t.Fatalf("state_confirmed 事件发布不正确: %#v", events)
	}
}

func TestMessageDeliveryEngineClampAckAndPulledDedup(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()
	d := c.delivery()
	ns := "p2p:alice.agentid.pub"
	c.seqTracker.UpdateMaxSeen(ns, 5)

	if got := d.clampAckSeq("message.ack", "seq", ns, 9); got != 5 {
		t.Fatalf("ack 应按 max_seen clamp 到 5，实际: %d", got)
	}
	if got := d.clampAckSeq("message.ack", "seq", ns, -2); got != 0 {
		t.Fatalf("负数 ack 应 clamp 到 0，实际: %d", got)
	}

	received := []int{}
	c.events.Subscribe("message.received", func(payload any) {
		if msg, ok := payload.(map[string]any); ok {
			received = append(received, int(toInt64(msg["seq"])))
		}
	})
	if !d.publishPulledMessage("message.received", ns, 2, map[string]any{"seq": 2}) {
		t.Fatal("pull 批 seq=2 应发布")
	}
	if !d.publishPulledMessage("message.received", ns, 4, map[string]any{"seq": 4}) {
		t.Fatal("pull 批内部空洞 seq=4 应发布")
	}
	if d.publishPulledMessage("message.received", ns, 4, map[string]any{"seq": 4}) {
		t.Fatal("重复 pulled seq=4 应被去重")
	}
	if len(received) != 2 || received[0] != 2 || received[1] != 4 {
		t.Fatalf("pull 批内部空洞不应阻塞发布，实际: %#v", received)
	}
	if !d.isPushedSeq(ns, 2) || !d.isPushedSeq(ns, 4) {
		t.Fatal("pulled 已发布 seq 应进入去重 guard")
	}
}

func TestMessageDeliveryEngineMigratesPersistsAndRestoresSeqState(t *testing.T) {
	c := newClient(map[string]any{"aun_path": t.TempDir()})
	defer c.Close()
	c.aid = "alice.agentid.pub"
	c.deviceID = "device-a"
	c.slotID = "slot-a"
	d := c.delivery()
	seqStore, ok := c.tokenStore.(interface {
		LoadAllSeqs(aid, deviceID, slotID string) (map[string]int, error)
	})
	if !ok {
		t.Fatal("测试 token store 应支持 LoadAllSeqs")
	}

	migrated := d.migrateSeqStateGroupIDs(c.aid, c.deviceID, c.slotID, map[string]int{
		"group_msg:g1.agentid.pub":       3,
		"group_msg:group.agentid.pub/g1": 5,
		"group_event:g2@agentid.pub":     6,
		"p2p:alice.agentid.pub":          9,
	})
	if migrated["group_msg:group.agentid.pub/g1"] != 5 || migrated["group_event:group.agentid.pub/g2"] != 6 || migrated["p2p:alice.agentid.pub"] != 9 {
		t.Fatalf("迁移结果不正确: %#v", migrated)
	}
	if _, exists := migrated["group_msg:g1.agentid.pub"]; exists {
		t.Fatalf("旧 group namespace 应被删除: %#v", migrated)
	}
	persisted, err := seqStore.LoadAllSeqs(c.aid, c.deviceID, c.slotID)
	if err != nil {
		t.Fatalf("读取迁移落盘 seq 失败: %v", err)
	}
	if persisted["group_event:group.agentid.pub/g2"] != 6 {
		t.Fatalf("迁移后的 group_event namespace 应落盘: %#v", persisted)
	}

	c.seqTracker.ForceContiguousSeq("p2p:alice.agentid.pub", 11)
	d.saveSeqTrackerState()
	persisted, err = seqStore.LoadAllSeqs(c.aid, c.deviceID, c.slotID)
	if err != nil {
		t.Fatalf("读取保存后的 seq 失败: %v", err)
	}
	if persisted["p2p:alice.agentid.pub"] != 11 {
		t.Fatalf("saveSeqTrackerState 应按 namespace 保存，实际: %#v", persisted)
	}

	c.seqTracker = NewSeqTracker()
	d.restoreSeqTrackerState()
	if got := c.seqTracker.GetContiguousSeq("p2p:alice.agentid.pub"); got != 11 {
		t.Fatalf("restoreSeqTrackerState 未恢复 p2p seq: %d", got)
	}
	if got := c.seqTracker.GetContiguousSeq("group_event:group.agentid.pub/g2"); got != 6 {
		t.Fatalf("restoreSeqTrackerState 未恢复迁移后的 group_event seq: %d", got)
	}
}
