package aun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	v2crypto "github.com/modelunion/aun-sdk-core/go/v2/crypto"
	v2e2ee "github.com/modelunion/aun-sdk-core/go/v2/e2ee"
	v2session "github.com/modelunion/aun-sdk-core/go/v2/session"
	v2state "github.com/modelunion/aun-sdk-core/go/v2/state"
)

func waitForParityCondition(timeout time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fn()
}

func TestV2BuildTargetAllowsExplicitEmptyDeviceID(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ikDER := []byte{1, 2, 3}
	state := &v2P2PState{
		session: v2session.NewV2Session(nil, "", "alice.example.com", nil, nil),
	}
	target, ok, err := c.v2BuildTargetFromDevice(
		context.Background(),
		state,
		map[string]any{"device_id": "", "ik_pk": base64.StdEncoding.EncodeToString(ikDER)},
		"bob.example.com",
		"",
		"peer",
		"peer_device_prekey",
	)
	if err != nil {
		t.Fatalf("v2BuildTargetFromDevice 返回错误: %v", err)
	}
	if !ok {
		t.Fatal("显式空 device_id 应被当作有效设备值")
	}
	if target.DeviceID != "" || target.AID != "bob.example.com" || target.Role != "peer" {
		t.Fatalf("target 不正确: %#v", target)
	}
	cached := state.session.GetPeerIK("bob.example.com", "")
	if string(cached) != string(ikDER) {
		t.Fatalf("显式空 device_id 的 IK 未缓存: %#v", cached)
	}
}

func TestCacheV2PeerIKFromDeviceAllowsExplicitEmptyDeviceID(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ikDER := []byte{1, 2, 3}
	state := &v2P2PState{
		session: v2session.NewV2Session(nil, "", "alice.example.com", nil, nil),
	}

	c.cacheV2PeerIKFromDevice(state, map[string]any{
		"device_id": "",
		"ik_pk":     base64.StdEncoding.EncodeToString(ikDER),
	}, "bob.example.com")

	cached := state.session.GetPeerIK("bob.example.com", "")
	if !bytes.Equal(cached, ikDER) {
		t.Fatalf("显式空 device_id 的 bootstrap IK 未缓存: %#v", cached)
	}
}

func TestV2BuildTargetAllowsIKInSPKFields(t *testing.T) {
	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()

	ikPriv, ikDER, err := v2crypto.GenerateP256Keypair()
	if err != nil {
		t.Fatal(err)
	}
	ikSum := sha256.Sum256(ikDER)
	ikID := "sha256:" + hex.EncodeToString(ikSum[:])[:16]
	c.mu.Lock()
	c.aid = "bob.example.com"
	c.mu.Unlock()
	ks, err := openV2Keystore(t.TempDir(), "bob.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()
	state := &v2P2PState{
		session: v2session.NewV2Session(ks.store, "", "bob.example.com", ikPriv, ikDER),
	}

	target, ok, err := c.v2BuildTargetFromDevice(
		context.Background(),
		state,
		map[string]any{
			"device_id":  "",
			"ik_pk":      base64.StdEncoding.EncodeToString(ikDER),
			"spk_pk":     base64.StdEncoding.EncodeToString(ikDER),
			"spk_id":     ikID,
			"key_source": "peer_device_prekey",
		},
		"bob.example.com",
		"",
		"peer",
		"peer_device_prekey",
	)
	if err != nil {
		t.Fatalf("IK-as-SPK bootstrap target should be accepted: %v", err)
	}
	if !ok || target.SPKID != ikID || !bytes.Equal(target.SPKPkDER, ikDER) {
		t.Fatalf("target 不正确: ok=%v target=%#v", ok, target)
	}
}
func TestV2AutoProposeLeaderDelayTreatsEmptyDeviceIDAsCandidate(t *testing.T) {
	wsURL, _, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "group.get_online_members":
			return map[string]any{"members": []any{
				map[string]any{"aid": "a-owner.example.com", "role": "owner", "online": true},
				map[string]any{"aid": "b-owner.example.com", "role": "owner", "online": true},
			}}
		case "group.v2.bootstrap":
			return map[string]any{"devices": []any{
				map[string]any{"aid": "a-owner.example.com", "device_id": "", "ik_fp": "ik-empty"},
				map[string]any{"aid": "b-owner.example.com", "device_id": "dev-b", "ik_fp": "ik-b"},
			}, "audit_recipients": []any{}}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.aid = "b-owner.example.com"
	c.deviceID = "dev-b"
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if c.v2AutoProposeLeaderDelay(ctx, "group.example.com/g1") {
		t.Fatal("空 device_id 候选应排在当前设备前，等待超时后应返回 false")
	}
}
func TestMarshalSortedCompactJSONMatchesPythonStyle(t *testing.T) {
	got, err := marshalSortedCompactJSON(map[string]any{
		"z": map[string]any{
			"b": 2,
			"a": 1,
		},
		"m": "中文",
		"a": "x<y&z>",
	})
	if err != nil {
		t.Fatalf("marshalSortedCompactJSON 失败: %v", err)
	}
	want := `{"a":"x<y&z>","m":"中文","z":{"a":1,"b":2}}`
	if string(got) != want {
		t.Fatalf("compact JSON 未对齐 Python ensure_ascii=False/no HTML escape\nwant=%s\ngot =%s", want, string(got))
	}
}

func TestV2GroupPushNotificationPullsAndPublishes(t *testing.T) {
	groupID := "group.example.com/g1"
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "group.v2.pull" {
			return map[string]any{"messages": []any{
				map[string]any{
					"version":    "v1",
					"seq":        1,
					"message_id": "gm-v2-push",
					"from_aid":   "alice.example.com",
					"t_server":   int64(123),
					"payload":    map[string]any{"type": "text", "text": "pulled by v2 group push"},
				},
			}}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()

	received := make(chan map[string]any, 1)
	c.On("group.message_created", func(payload any) {
		if m, ok := payload.(map[string]any); ok {
			received <- m
		}
	})

	c.events.Publish("_raw.group.v2.message_created", map[string]any{
		"group_id":   groupID,
		"seq":        1,
		"message_id": "gm-v2-push",
		"sender_aid": "alice.example.com",
	})

	select {
	case msg := <-received:
		payload, _ := msg["payload"].(map[string]any)
		if payload["text"] != "pulled by v2 group push" {
			t.Fatalf("群 V2 push 后发布的消息不正确: %#v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("群 V2 push 未触发 group.v2.pull 并发布 group.message_created")
	}

	if !waitForParityCondition(time.Second, func() bool {
		for _, call := range getCalls() {
			if call.Method == "group.v2.pull" {
				return int(toInt64(call.Params["after_seq"])) == 0
			}
		}
		return false
	}) {
		t.Fatalf("未观察到 group.v2.pull 调用: %#v", getCalls())
	}
}

func TestV2P2PPurePushNotificationPullsFromCurrentContiguousSeq(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "message.v2.pull":
			if toInt64(params["after_seq"]) != 0 {
				return map[string]any{"messages": []any{}}
			}
			return map[string]any{"messages": []any{
				map[string]any{
					"version":    "v1",
					"seq":        1,
					"message_id": "m-v2-pure-push",
					"from_aid":   "bob.example.com",
					"t_server":   int64(123),
					"legacy_v1": map[string]any{
						"to":      "alice.example.com",
						"payload": map[string]any{"type": "text", "text": "pulled by v2 pure push"},
					},
				},
			}}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()

	received := make(chan map[string]any, 1)
	c.On("message.received", func(payload any) {
		if m, ok := payload.(map[string]any); ok {
			received <- m
		}
	})

	c.events.Publish("_raw.peer.v2.message_received", map[string]any{
		"seq":        1,
		"message_id": "m-v2-pure-push",
		"from_aid":   "bob.example.com",
	})

	select {
	case msg := <-received:
		payload, _ := msg["payload"].(map[string]any)
		if payload["text"] != "pulled by v2 pure push" {
			t.Fatalf("V2 P2P pure push 后发布的消息不正确: %#v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("V2 P2P pure push 未从当前 contiguous_seq 拉取并发布消息，calls=%#v", getCalls())
	}

	if !waitForParityCondition(time.Second, func() bool {
		for _, call := range getCalls() {
			if call.Method == "message.v2.pull" {
				return int(toInt64(call.Params["after_seq"])) == 0
			}
		}
		return false
	}) {
		t.Fatalf("message.v2.pull 应使用 after_seq=0，calls=%#v", getCalls())
	}
}
func TestV2P2PPayloadPushWithGapPullsFromCurrentContiguousSeq(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "message.v2.pull" {
			return map[string]any{"messages": []any{}}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()
	ns := "p2p:alice.example.com"
	c.seqTracker.OnMessageSeq(ns, 1)

	c.events.Publish("_raw.peer.v2.message_received", map[string]any{
		"seq":           int64(3),
		"message_id":    "m-push-3",
		"from_aid":      "bob.example.com",
		"envelope_json": "{}",
	})

	if !waitForParityCondition(time.Second, func() bool {
		for _, call := range getCalls() {
			if call.Method == "message.v2.pull" {
				return toInt64(call.Params["after_seq"]) == 1
			}
		}
		return false
	}) {
		t.Fatalf("payload push 发现空洞后应从当前 contiguous_seq=1 pull，calls=%#v", getCalls())
	}
	if got := c.seqTracker.GetContiguousSeq(ns); got != 1 {
		t.Fatalf("payload push 只有上界消息时不应推进下界，contiguous=%d", got)
	}
	if got := c.seqTracker.GetMaxSeenSeq(ns); got != 3 {
		t.Fatalf("payload push 应更新 max_seen_seq=3，got=%d", got)
	}
}

func TestV2P2PPurePushEqualContiguousIsIdempotent(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "message.v2.pull" {
			return map[string]any{"messages": []any{}}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()
	ns := "p2p:alice.example.com"
	c.seqTracker.ForceContiguousSeq(ns, 3)

	c.events.Publish("_raw.peer.v2.message_received", map[string]any{
		"seq":        int64(3),
		"message_id": "m-pure-duplicate",
		"from_aid":   "bob.example.com",
	})

	time.Sleep(150 * time.Millisecond)
	for _, call := range getCalls() {
		if call.Method == "message.v2.pull" {
			t.Fatalf("contiguous_seq == push_seq 的纯通知 push 应幂等忽略，不应 pull，calls=%#v", getCalls())
		}
	}
	if got := c.seqTracker.GetContiguousSeq(ns); got != 3 {
		t.Fatalf("纯通知重复 push 不应回退 contiguous_seq，got=%d", got)
	}
	if got := c.seqTracker.GetMaxSeenSeq(ns); got != 3 {
		t.Fatalf("纯通知重复 push 应保持 max_seen_seq=3，got=%d", got)
	}
}

func TestV2GroupPurePushEqualContiguousIsIdempotent(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "group.v2.pull" {
			return map[string]any{"messages": []any{}}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()
	groupID := "group.example.com/g1"
	ns := "group:" + groupID
	c.seqTracker.ForceContiguousSeq(ns, 3)

	c.events.Publish("_raw.group.v2.message_created", map[string]any{
		"group_id":   groupID,
		"seq":        int64(3),
		"message_id": "gm-pure-duplicate",
		"sender_aid": "bob.example.com",
	})

	time.Sleep(150 * time.Millisecond)
	for _, call := range getCalls() {
		if call.Method == "group.v2.pull" {
			t.Fatalf("contiguous_seq == push_seq 的 group 纯通知 push 应幂等忽略，不应 pull，calls=%#v", getCalls())
		}
	}
	if got := c.seqTracker.GetContiguousSeq(ns); got != 3 {
		t.Fatalf("group 纯通知重复 push 不应回退 contiguous_seq，got=%d", got)
	}
	if got := c.seqTracker.GetMaxSeenSeq(ns); got != 3 {
		t.Fatalf("group 纯通知重复 push 应保持 max_seen_seq=3，got=%d", got)
	}
}

func TestDecryptV2MessageFallsBackToCACert(t *testing.T) {
	aliceKey, _, alicePubB64 := testGenerateECKeypair(t)
	bobKey, _, bobPubB64 := testGenerateECKeypair(t)
	aliceAID := "alice.example.com"
	bobAID := "bob.example.com"
	aliceCert := testMakeSelfSignedCert(t, aliceKey, aliceAID)

	alicePriv := aliceKey.D.FillBytes(make([]byte, 32))
	bobPriv := bobKey.D.FillBytes(make([]byte, 32))
	alicePubDER := mustDecodeB64ForParity(t, alicePubB64)
	bobPubDER := mustDecodeB64ForParity(t, bobPubB64)
	bobSPKPriv, bobSPKPubDER, err := v2crypto.GenerateP256Keypair()
	if err != nil {
		t.Fatalf("生成 SPK 失败: %v", err)
	}
	spkHash := sha256.Sum256(bobSPKPubDER)
	bobSPKID := "sha256:" + hex.EncodeToString(spkHash[:])[:16]

	envelope, err := v2e2ee.EncryptP2PMessage(
		v2e2ee.Sender{AID: aliceAID, DeviceID: "dev-alice", IKPriv: alicePriv, IKPubDER: alicePubDER},
		v2e2ee.TargetSet{Targets: []v2e2ee.Target{{
			AID:       bobAID,
			DeviceID:  "dev-bob",
			Role:      "peer",
			KeySource: "peer_device_prekey",
			IKPkDER:   bobPubDER,
			SPKPkDER:  bobSPKPubDER,
			SPKID:     bobSPKID,
		}}},
		map[string]any{"type": "text", "text": "ca fallback decrypt"},
		v2e2ee.EncryptOptions{MessageID: "m-ca-fallback", Timestamp: 1710504000000},
	)
	if err != nil {
		t.Fatalf("构造 V2 envelope 失败: %v", err)
	}
	envJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("序列化 envelope 失败: %v", err)
	}

	store, err := openV2Keystore(t.TempDir(), bobAID)
	if err != nil {
		t.Fatalf("打开 V2 keystore 失败: %v", err)
	}
	defer store.Close()
	if err := store.store.SaveSPK("dev-bob", bobSPKID, bobSPKPriv, bobSPKPubDER); err != nil {
		t.Fatalf("保存测试 SPK 失败: %v", err)
	}
	sess := v2session.NewV2Session(store.store, "dev-bob", bobAID, bobPriv, bobPubDER)
	if err := sess.EnsureKeys(); err != nil {
		t.Fatalf("初始化测试 V2 session 失败: %v", err)
	}

	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.aid = bobAID
	c.deviceID = "dev-bob"
	c.gatewayURL = "ws://gateway.example.com"
	c.v2State = &v2P2PState{
		session:             sess,
		keystore:            store,
		bootstrapCache:      make(map[string]v2BootstrapEntry),
		groupBootstrapCache: make(map[string]*v2GroupBootstrapEntry),
	}
	c.mu.Unlock()
	c.certCacheMu.Lock()
	c.certCache[certCacheKey(aliceAID, "")] = &cachedPeerCert{
		certBytes:    []byte(aliceCert),
		validatedAt:  float64(time.Now().Unix()),
		refreshAfter: float64(time.Now().Add(time.Hour).Unix()),
	}
	c.certCacheMu.Unlock()

	msg := map[string]any{
		"message_id":    "m-ca-fallback",
		"from_aid":      aliceAID,
		"seq":           int64(1),
		"spk_id":        bobSPKID,
		"envelope_json": string(envJSON),
	}
	plaintext := c.decryptV2Message(context.Background(), c.v2GetState(), msg)
	if plaintext == nil {
		t.Fatal("sender IK 缓存缺失时应通过 CA 证书 fallback 解密成功")
	}
	payload, _ := plaintext["payload"].(map[string]any)
	if payload["text"] != "ca fallback decrypt" {
		t.Fatalf("CA fallback 解密 payload 不正确: %#v", plaintext)
	}
	if plaintext["payload_type"] != "text" {
		t.Fatalf("应用层消息顶层 payload_type 应透传原始 payload.type，实际: %#v", plaintext)
	}
	if !reflect.DeepEqual(plaintext["protected_headers"], map[string]any{"payload_type": "text", "sdk_lang": "go", "sdk_version": "0.3.4"}) {
		t.Fatalf("应用层消息顶层 protected_headers 应去 _auth 后透传，实际: %#v", plaintext["protected_headers"])
	}
	e2eeMeta, _ := plaintext["e2ee"].(map[string]any)
	if e2eeMeta["payload_type"] != "text" {
		t.Fatalf("应用层 e2ee.payload_type 应透传原始 payload.type，实际: %#v", e2eeMeta)
	}
}

func TestDecryptV2MessageUndecryptableEventPreservesMetadata(t *testing.T) {
	bobAID := "bob.example.com"
	bobPriv, bobPubDER, err := v2crypto.GenerateP256Keypair()
	if err != nil {
		t.Fatalf("生成 IK 失败: %v", err)
	}
	store, err := openV2Keystore(t.TempDir(), bobAID)
	if err != nil {
		t.Fatalf("打开 V2 keystore 失败: %v", err)
	}
	defer store.Close()
	sess := v2session.NewV2Session(store.store, "dev-bob", bobAID, bobPriv, bobPubDER)
	if err := sess.EnsureKeys(); err != nil {
		t.Fatalf("初始化测试 V2 session 失败: %v", err)
	}

	c := NewClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.aid = bobAID
	c.deviceID = "dev-bob"
	c.v2State = &v2P2PState{session: sess, keystore: store}
	c.mu.Unlock()

	published := make(chan map[string]any, 1)
	c.On("message.undecryptable", func(payload any) {
		if event, ok := payload.(map[string]any); ok {
			published <- event
		}
	})
	envelope := map[string]any{
		"type":         "e2ee.p2p_encrypted",
		"version":      "v2",
		"suite":        "P256_HKDF_SHA256_AES_256_GCM",
		"payload_type": "text",
		"aad":          map[string]any{"from": "alice.example.com", "from_device": "dev-alice"},
		"recipients": []any{[]any{
			bobAID, "dev-bob", "peer", "peer_device_prekey", "fp", "missing-spk", "n", "w",
		}},
		"protected_headers": map[string]any{"payload_type": "text", "trace_id": "trace-1", "sdk_lang": "python", "sdk_version": "0.3.4", "_auth": "secret"},
	}
	envJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("序列化 envelope 失败: %v", err)
	}

	result := c.decryptV2Message(context.Background(), c.v2GetState(), map[string]any{
		"message_id":    "m-undecryptable",
		"from_aid":      "alice.example.com",
		"seq":           int64(1),
		"spk_id":        "missing-spk",
		"envelope_json": string(envJSON),
	})
	if result != nil {
		t.Fatalf("SPK 缺失时应返回 nil，实际: %#v", result)
	}

	select {
	case event := <-published:
		if event["payload_type"] != "text" {
			t.Fatalf("失败事件顶层 payload_type 不正确: %#v", event)
		}
		wantHeaders := map[string]any{"payload_type": "text", "trace_id": "trace-1", "sdk_lang": "python", "sdk_version": "0.3.4"}
		if !reflect.DeepEqual(event["protected_headers"], wantHeaders) {
			t.Fatalf("失败事件 protected_headers 应去 _auth 后透传: %#v", event["protected_headers"])
		}
	case <-time.After(time.Second):
		t.Fatal("未收到 message.undecryptable 事件")
	}
}

func TestV2P2PPullBatchAutoAckOnceWithFinalContiguousSeq(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "message.v2.pull":
			return map[string]any{"messages": []any{
				map[string]any{"version": "v1", "seq": 1, "message_id": "m-1", "from_aid": "bob.example.com", "t_server": int64(1), "legacy_v1": map[string]any{"to": "alice.example.com", "payload": map[string]any{"type": "text", "text": "m-1"}}},
				map[string]any{"version": "v1", "seq": 2, "message_id": "m-2", "from_aid": "bob.example.com", "t_server": int64(2), "legacy_v1": map[string]any{"to": "alice.example.com", "payload": map[string]any{"type": "text", "text": "m-2"}}},
				map[string]any{"version": "v1", "seq": 3, "message_id": "m-3", "from_aid": "bob.example.com", "t_server": int64(3), "legacy_v1": map[string]any{"to": "alice.example.com", "payload": map[string]any{"type": "text", "text": "m-3"}}},
			}}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := c.Call(ctx, "message.pull", map[string]any{"after_seq": 0, "limit": 10})
	if err != nil {
		t.Fatalf("message.pull 失败: %v", err)
	}
	resultMap, _ := result.(map[string]any)
	messages, _ := resultMap["messages"].([]any)
	if len(messages) != 3 {
		t.Fatalf("message.pull 应返回 3 条消息: %#v", result)
	}

	if !waitForParityCondition(time.Second, func() bool {
		count := 0
		for _, call := range getCalls() {
			if call.Method == "message.v2.ack" {
				count++
			}
		}
		return count == 1
	}) {
		t.Fatalf("message.v2.pull 批量消息应只 ack 一次，calls=%#v", getCalls())
	}
	var ackCalls []testRPCCall
	for _, call := range getCalls() {
		if call.Method == "message.v2.ack" {
			ackCalls = append(ackCalls, call)
		}
	}
	if len(ackCalls) != 1 || toInt64(ackCalls[0].Params["up_to_seq"]) != 3 {
		t.Fatalf("message.v2.pull 应 ack 最终 contiguous_seq=3，ackCalls=%#v", ackCalls)
	}
}

func TestV2P2PPullPublishesAfterContiguousAdvanceAndAcksOnce(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "message.v2.pull":
			return map[string]any{"messages": []any{
				map[string]any{"version": "v1", "seq": 1, "message_id": "m-event-1", "from_aid": "bob.example.com", "t_server": int64(1), "legacy_v1": map[string]any{"to": "alice.example.com", "payload": map[string]any{"type": "text", "text": "m-event-1"}}},
				map[string]any{"version": "v1", "seq": 2, "message_id": "m-event-2", "from_aid": "bob.example.com", "t_server": int64(2), "legacy_v1": map[string]any{"to": "alice.example.com", "payload": map[string]any{"type": "text", "text": "m-event-2"}}},
				map[string]any{"version": "v1", "seq": 3, "message_id": "m-event-3", "from_aid": "bob.example.com", "t_server": int64(3), "legacy_v1": map[string]any{"to": "alice.example.com", "payload": map[string]any{"type": "text", "text": "m-event-3"}}},
			}}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()

	ns := "p2p:" + c.aid
	var observed []int
	c.On("message.received", func(payload any) {
		observed = append(observed, c.seqTracker.GetContiguousSeq(ns))
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := c.Call(ctx, "message.pull", map[string]any{"after_seq": 0, "limit": 10}); err != nil {
		t.Fatalf("message.pull 失败: %v", err)
	}

	if !waitForParityCondition(time.Second, func() bool {
		return len(observed) == 3
	}) {
		t.Fatalf("message.received 应发布 3 次，observed=%#v", observed)
	}
	if len(observed) != 3 || observed[0] != 3 || observed[1] != 3 || observed[2] != 3 {
		t.Fatalf("message.received 发布时 contiguous_seq 应已推进到 3，observed=%#v", observed)
	}
	if !waitForParityCondition(time.Second, func() bool {
		ackCount := 0
		ackOK := false
		for _, call := range getCalls() {
			if call.Method == "message.v2.ack" {
				ackCount++
				ackOK = toInt64(call.Params["up_to_seq"]) == 3
			}
		}
		return ackCount == 1 && ackOK
	}) {
		t.Fatalf("message.v2.pull 本页应只 ack 一次，calls=%#v", getCalls())
	}
	ackCount := 0
	for _, call := range getCalls() {
		if call.Method == "message.v2.ack" {
			ackCount++
			if toInt64(call.Params["up_to_seq"]) != 3 {
				t.Fatalf("message.v2.ack 应使用最终 contiguous_seq=3，call=%#v", call)
			}
		}
	}
	if ackCount != 1 {
		t.Fatalf("message.v2.pull 本页应只 ack 一次，calls=%#v", getCalls())
	}
}

func TestV2P2PPullEmptyResultConsumesServerAckFloor(t *testing.T) {
	wsURL, _, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "message.v2.pull":
			return map[string]any{"messages": []any{}, "server_ack_seq": int64(7)}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	msgs, err := c.PullV2(ctx, 0, 10)
	if err != nil {
		t.Fatalf("PullV2 失败: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("空 pull 不应返回消息: %#v", msgs)
	}
	if got := c.seqTracker.GetContiguousSeq("p2p:alice.example.com"); got != 7 {
		t.Fatalf("空 message.v2.pull 应按 server_ack_seq 推进 contiguous_seq=7，got=%d", got)
	}
}

func TestV2GroupPullBatchAutoAckOnceWithFinalContiguousSeq(t *testing.T) {
	groupID := "group.example.com/g1"
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "group.v2.pull":
			return map[string]any{"messages": []any{
				map[string]any{"version": "v1", "seq": 1, "message_id": "gm-1", "from_aid": "bob.example.com", "t_server": int64(1), "type": "message", "payload": map[string]any{"type": "text", "text": "gm-1"}},
				map[string]any{"version": "v1", "seq": 2, "message_id": "gm-2", "from_aid": "bob.example.com", "t_server": int64(2), "type": "message", "payload": map[string]any{"type": "text", "text": "gm-2"}},
				map[string]any{"version": "v1", "seq": 3, "message_id": "gm-3", "from_aid": "bob.example.com", "t_server": int64(3), "type": "message", "payload": map[string]any{"type": "text", "text": "gm-3"}},
			}}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := c.Call(ctx, "group.pull", map[string]any{"group_id": groupID, "after_seq": 0, "limit": 10})
	if err != nil {
		t.Fatalf("group.pull 失败: %v", err)
	}
	resultMap, _ := result.(map[string]any)
	messages, _ := resultMap["messages"].([]any)
	if len(messages) != 3 {
		t.Fatalf("group.pull 应返回 3 条消息: %#v", result)
	}

	if !waitForParityCondition(time.Second, func() bool {
		count := 0
		for _, call := range getCalls() {
			if call.Method == "group.v2.ack" {
				count++
			}
		}
		return count == 1
	}) {
		t.Fatalf("group.v2.pull 批量消息应只 ack 一次，calls=%#v", getCalls())
	}
	var ackCalls []testRPCCall
	for _, call := range getCalls() {
		if call.Method == "group.v2.ack" {
			ackCalls = append(ackCalls, call)
		}
	}
	if len(ackCalls) != 1 || strings.TrimSpace(v2AsString(ackCalls[0].Params["group_id"])) != groupID || toInt64(ackCalls[0].Params["up_to_seq"]) != 3 {
		t.Fatalf("group.v2.pull 应 ack 最终 contiguous_seq=3，ackCalls=%#v", ackCalls)
	}
}

func TestV2GroupPullPublishesAfterContiguousAdvanceAndAcksOnce(t *testing.T) {
	groupID := "group.example.com/g1"
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "group.v2.pull":
			return map[string]any{"messages": []any{
				map[string]any{"version": "v1", "seq": 1, "message_id": "gm-event-1", "from_aid": "bob.example.com", "t_server": int64(1), "type": "message", "payload": map[string]any{"type": "text", "text": "gm-event-1"}},
				map[string]any{"version": "v1", "seq": 2, "message_id": "gm-event-2", "from_aid": "bob.example.com", "t_server": int64(2), "type": "message", "payload": map[string]any{"type": "text", "text": "gm-event-2"}},
				map[string]any{"version": "v1", "seq": 3, "message_id": "gm-event-3", "from_aid": "bob.example.com", "t_server": int64(3), "type": "message", "payload": map[string]any{"type": "text", "text": "gm-event-3"}},
			}}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()

	ns := "group:" + groupID
	var observed []int
	c.On("group.message_created", func(payload any) {
		observed = append(observed, c.seqTracker.GetContiguousSeq(ns))
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := c.Call(ctx, "group.pull", map[string]any{"group_id": groupID, "after_seq": 0, "limit": 10}); err != nil {
		t.Fatalf("group.pull 失败: %v", err)
	}

	if !waitForParityCondition(time.Second, func() bool {
		return len(observed) == 3
	}) {
		t.Fatalf("group.message_created 应发布 3 次，observed=%#v", observed)
	}
	if len(observed) != 3 || observed[0] != 3 || observed[1] != 3 || observed[2] != 3 {
		t.Fatalf("group.message_created 发布时 contiguous_seq 应已推进到 3，observed=%#v", observed)
	}
	if !waitForParityCondition(time.Second, func() bool {
		ackCount := 0
		ackOK := false
		for _, call := range getCalls() {
			if call.Method == "group.v2.ack" {
				ackCount++
				ackOK = strings.TrimSpace(v2AsString(call.Params["group_id"])) == groupID && toInt64(call.Params["up_to_seq"]) == 3
			}
		}
		return ackCount == 1 && ackOK
	}) {
		t.Fatalf("group.v2.pull 本页应只 ack 一次，calls=%#v", getCalls())
	}
	ackCount := 0
	for _, call := range getCalls() {
		if call.Method == "group.v2.ack" {
			ackCount++
			if strings.TrimSpace(v2AsString(call.Params["group_id"])) != groupID || toInt64(call.Params["up_to_seq"]) != 3 {
				t.Fatalf("group.v2.ack 应使用最终 contiguous_seq=3，call=%#v", call)
			}
		}
	}
	if ackCount != 1 {
		t.Fatalf("group.v2.pull 本页应只 ack 一次，calls=%#v", getCalls())
	}
}

func TestV2GroupPullEmptyResultConsumesCursorFloor(t *testing.T) {
	groupID := "group.example.com/g1"
	wsURL, _, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "group.v2.pull":
			return map[string]any{
				"messages": []any{},
				"cursor":   map[string]any{"current_seq": int64(9)},
			}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	msgs, err := c.PullGroupV2(ctx, groupID, 0, 10)
	if err != nil {
		t.Fatalf("PullGroupV2 失败: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("空 group pull 不应返回消息: %#v", msgs)
	}
	if got := c.seqTracker.GetContiguousSeq("group:" + groupID); got != 9 {
		t.Fatalf("空 group.v2.pull 应按 cursor.current_seq 推进 contiguous_seq=9，got=%d", got)
	}
}
func TestV2GroupBootstrapStateSignatureFailureIsFatal(t *testing.T) {
	wsURL, _, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "group.v2.bootstrap" {
			return map[string]any{
				"devices": []any{map[string]any{
					"aid":       "bob.example.com",
					"device_id": "dev-bob",
					"ik_pk":     "AA==",
				}},
				"epoch":                     1,
				"state_version":             2,
				"state_signature":           "not-base64",
				"state_actor_aid":           "alice.example.com",
				"state_hash_signed":         "state-hash",
				"state_membership_snapshot": "[]",
			}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()
	state := c.v2GetState()
	if _, _, _, _, _, err := c.v2ResolveGroupBootstrap(context.Background(), state, "group.example.com/g1", false); err == nil {
		t.Fatal("state_signature 无效时 group.v2.bootstrap 必须失败，不能继续信任 bootstrap")
	}
}

func TestAckV2AddsPythonCompatibilityFields(t *testing.T) {
	wsURL, _, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "message.v2.ack" {
			return map[string]any{"acked": int64(0)}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.v2State = nil
	c.mu.Unlock()
	result, err := c.AckV2(context.Background(), 7)
	if err != nil {
		t.Fatalf("AckV2 失败: %v", err)
	}
	if result["success"] != true || toInt64(result["ack_seq"]) != 7 || toInt64(result["acked"]) != 7 {
		t.Fatalf("AckV2 兼容字段未对齐 Python: %#v", result)
	}
}

func TestV2AutoProposeStateConfirmsReturnedProposal(t *testing.T) {
	_, privPEM, _ := testGenerateECKeypair(t)
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "group.get_members":
			return map[string]any{"members": []any{
				map[string]any{"aid": "alice.example.com", "role": "owner"},
				map[string]any{"aid": "bob.example.com", "role": "member"},
			}}
		case "group.v2.bootstrap":
			return map[string]any{"devices": []any{}, "audit_recipients": []any{}}
		case "group.get_state":
			return map[string]any{"state_version": int64(0), "state_hash": "", "key_epoch": int64(3), "membership_snapshot": ""}
		case "group.v2.propose_state":
			return map[string]any{"proposal_id": "proposal-1"}
		case "group.v2.confirm_state":
			return map[string]any{"ok": true}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.aid = "alice.example.com"
	c.identity = map[string]any{"aid": "alice.example.com", "private_key_pem": privPEM}
	c.mu.Unlock()

	c.v2AutoProposeState(context.Background(), "group.example.com/g1")
	if !waitForParityCondition(time.Second, func() bool {
		for _, call := range getCalls() {
			if call.Method == "group.v2.confirm_state" && strings.TrimSpace(v2AsString(call.Params["proposal_id"])) == "proposal-1" {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("propose_state 返回 proposal_id 后未立即 confirm，calls=%#v", getCalls())
	}
}

func TestV2AutoProposeLeaderDelayUsesOnlyOnlineOwnerAdmin(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "group.get_online_members":
			return map[string]any{"members": []any{
				map[string]any{"aid": "z-owner.example.com", "role": "owner", "online": true},
				map[string]any{"aid": "m-member.example.com", "role": "member", "online": true},
			}}
		case "group.get_members":
			return map[string]any{"members": []any{
				map[string]any{"aid": "a-offline-admin.example.com", "role": "admin"},
				map[string]any{"aid": "z-owner.example.com", "role": "owner"},
			}}
		case "group.v2.bootstrap":
			return map[string]any{"devices": []any{
				map[string]any{"aid": "a-offline-admin.example.com", "device_id": "dev-offline", "ik_fp": "ik-a"},
				map[string]any{"aid": "z-owner.example.com", "device_id": "dev-owner", "ik_fp": "ik-z"},
			}, "audit_recipients": []any{}}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.aid = "z-owner.example.com"
	c.deviceID = "dev-owner"
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if !c.v2AutoProposeLeaderDelay(ctx, "group.example.com/g1") {
		t.Fatal("online owner/admin 选举不应因离线 admin 进入候选集而退化为等待超时")
	}

	methods := make([]string, 0, len(getCalls()))
	for _, call := range getCalls() {
		methods = append(methods, call.Method)
	}
	want := []string{"group.get_online_members", "group.v2.bootstrap"}
	if len(methods) != len(want) || methods[0] != want[0] || methods[1] != want[1] {
		t.Fatalf("leader delay 应只读取在线成员并再读 bootstrap, got=%v want=%v", methods, want)
	}
	for _, method := range methods {
		if method == "group.get_members" {
			t.Fatalf("leader delay 不应再读取 group.get_members, calls=%#v", methods)
		}
	}
}

func TestV2AutoProposeStateVerifiesCommittedBaseBeforePropose(t *testing.T) {
	committedPayload := map[string]any{
		"members": []any{
			map[string]any{"aid": "alice.example.com", "devices": []any{}},
		},
		"audit_aids":       []any{},
		"admin_set":        map[string]any{"admin_aids": []any{"alice.example.com"}, "threshold": 1},
		"join_policy_hash": nil,
		"recovery_quorum":  nil,
		"history_policy":   "recent_7_days",
		"wrap_protocol":    "3DH",
	}
	snapshot, _ := marshalSortedCompactJSON(committedPayload)
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "group.get_members":
			return map[string]any{"members": []any{
				map[string]any{"aid": "alice.example.com", "role": "owner"},
				map[string]any{"aid": "bob.example.com", "role": "member"},
			}}
		case "group.v2.bootstrap":
			return map[string]any{"devices": []any{}, "audit_recipients": []any{}}
		case "group.get_state":
			return map[string]any{
				"state_version":       int64(1),
				"state_hash":          "not-a-valid-committed-hash",
				"key_epoch":           int64(0),
				"membership_snapshot": string(snapshot),
			}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.aid = "alice.example.com"
	c.mu.Unlock()

	c.v2AutoProposeState(context.Background(), "group.example.com/g1")
	for _, call := range getCalls() {
		if call.Method == "group.v2.propose_state" || call.Method == "group.v2.confirm_state" {
			t.Fatalf("committed base 校验失败时不应继续提交 proposal，calls=%#v", getCalls())
		}
	}
}

func TestV2ConfirmPendingProposalVerifiesCommittedBaseAndHash(t *testing.T) {
	groupID := "group.example.com/g1"
	basePayload := map[string]any{
		"members": []any{
			map[string]any{"aid": "alice.example.com", "devices": []any{}},
		},
		"audit_aids":       []any{},
		"admin_set":        map[string]any{"admin_aids": []any{"alice.example.com"}, "threshold": 1},
		"join_policy_hash": nil,
		"recovery_quorum":  nil,
		"history_policy":   "recent_7_days",
		"wrap_protocol":    "3DH",
	}
	nextPayload := map[string]any{
		"members": []any{
			map[string]any{"aid": "alice.example.com", "devices": []any{}},
			map[string]any{"aid": "bob.example.com", "devices": []any{}},
		},
		"audit_aids":       []any{},
		"admin_set":        map[string]any{"admin_aids": []any{"alice.example.com"}, "threshold": 1},
		"join_policy_hash": nil,
		"recovery_quorum":  nil,
		"history_policy":   "recent_7_days",
		"wrap_protocol":    "3DH",
	}
	baseSnapshot, _ := marshalSortedCompactJSON(basePayload)
	nextSnapshot, _ := marshalSortedCompactJSON(nextPayload)
	baseHash := v2state.ComputeStateCommitment(groupID, 1, basePayload)
	nextHash := v2state.ComputeStateCommitment(groupID, 2, nextPayload)
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "group.v2.get_proposal":
			return map[string]any{"proposal": map[string]any{
				"proposal_id":         "sp-1",
				"state_version":       int64(2),
				"state_hash":          nextHash,
				"prev_state_hash":     baseHash,
				"membership_snapshot": string(nextSnapshot),
			}}
		case "group.get_state":
			return map[string]any{
				"state_version":       int64(1),
				"state_hash":          baseHash,
				"key_epoch":           int64(0),
				"membership_snapshot": string(baseSnapshot),
			}
		case "group.v2.confirm_state":
			return map[string]any{"ok": true}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()

	if !c.v2ConfirmPendingProposal(context.Background(), groupID) {
		t.Fatalf("pending proposal 校验通过后应确认")
	}
	methods := make([]string, 0, len(getCalls()))
	for _, call := range getCalls() {
		methods = append(methods, call.Method)
	}
	want := []string{"group.v2.get_proposal", "group.get_state", "group.v2.confirm_state"}
	if strings.Join(methods, ",") != strings.Join(want, ",") {
		t.Fatalf("pending confirm 调用顺序不一致: got=%v want=%v", methods, want)
	}
}

func TestV2StateRetryNeededTriggersLeaderDelayReproposal(t *testing.T) {
	groupID := "group.example.com/g1"
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "group.get_online_members":
			return map[string]any{"members": []any{
				map[string]any{"aid": "alice.example.com", "role": "owner", "online": true},
			}}
		case "group.get_members":
			return map[string]any{"members": []any{
				map[string]any{"aid": "alice.example.com", "role": "owner"},
			}}
		case "group.v2.bootstrap":
			return map[string]any{"devices": []any{
				map[string]any{"aid": "alice.example.com", "device_id": "dev-1", "ik_fp": "ik-a"},
			}, "audit_recipients": []any{}}
		case "group.get_state":
			return map[string]any{"state_version": int64(0), "state_hash": "", "key_epoch": int64(0), "membership_snapshot": ""}
		case "group.v2.propose_state":
			return map[string]any{"proposal_id": "retry-proposal"}
		case "group.v2.confirm_state":
			return map[string]any{"ok": true}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.aid = "alice.example.com"
	c.deviceID = "dev-1"
	c.mu.Unlock()

	c.events.Publish("_raw.group.v2.state_retry_needed", map[string]any{"group_id": groupID})
	if !waitForParityCondition(2*time.Second, func() bool {
		for _, call := range getCalls() {
			if call.Method == "group.v2.confirm_state" && strings.TrimSpace(v2AsString(call.Params["proposal_id"])) == "retry-proposal" {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("state_retry_needed 未触发 leader-delay 重提案并确认，calls=%#v", getCalls())
	}
}

func TestGroupCreateBlocksUntilV2StateConfirmed(t *testing.T) {
	_, privPEM, _ := testGenerateECKeypair(t)
	groupID := "group.example.com/g-create"
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		switch method {
		case "group.create":
			return map[string]any{"group": map[string]any{"group_id": groupID}}
		case "group.get_members":
			return map[string]any{"members": []any{
				map[string]any{"aid": "alice.example.com", "role": "owner"},
			}}
		case "group.v2.bootstrap":
			return map[string]any{"devices": []any{
				map[string]any{"aid": "alice.example.com", "device_id": "dev-1", "ik_fp": "ik-a"},
			}, "audit_recipients": []any{}}
		case "group.get_state":
			return map[string]any{"state_version": int64(0), "state_hash": "", "key_epoch": int64(0), "membership_snapshot": ""}
		case "group.v2.propose_state":
			return map[string]any{"proposal_id": "proposal-create"}
		case "group.v2.confirm_state":
			return map[string]any{"ok": true}
		default:
			return map[string]any{"ok": true}
		}
	})
	defer closeServer()

	c := newConnectedV2PullClientForTest(t, wsURL)
	defer func() { _ = c.Close() }()
	c.mu.Lock()
	c.aid = "alice.example.com"
	c.identity = map[string]any{"aid": "alice.example.com", "private_key_pem": privPEM}
	c.mu.Unlock()

	if _, err := c.Call(context.Background(), "group.create", map[string]any{"name": "v2-create"}); err != nil {
		t.Fatalf("group.create 失败: %v", err)
	}

	calls := getCalls()
	var createIdx, proposeIdx, confirmIdx = -1, -1, -1
	for i, call := range calls {
		switch call.Method {
		case "group.create":
			createIdx = i
		case "group.v2.propose_state":
			proposeIdx = i
		case "group.v2.confirm_state":
			confirmIdx = i
		}
	}
	if createIdx < 0 || proposeIdx < 0 || confirmIdx < 0 || !(createIdx < proposeIdx && proposeIdx < confirmIdx) {
		t.Fatalf("group.create 未在返回前完成 V2 propose+confirm，calls=%#v", calls)
	}
}

func mustDecodeB64ForParity(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("base64 解析失败: %v", err)
	}
	return decoded
}
