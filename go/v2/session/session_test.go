package session

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelunion/aun-sdk-core/go/v2/crypto"
	_ "modernc.org/sqlite"
)

// mockRPC 收集所有 callFn 调用。
type mockRPC struct {
	mu    sync.Mutex
	calls []rpcCall
	// returnErr 让某次调用返回错误（指定 method）
	returnErr error
}

type rpcCall struct {
	Method string
	Params map[string]any
}

func (m *mockRPC) call(ctx context.Context, method string, params map[string]any) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, rpcCall{Method: method, Params: params})
	if m.returnErr != nil {
		return nil, m.returnErr
	}
	return map[string]any{}, nil
}

func (m *mockRPC) Calls() []rpcCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]rpcCall, len(m.calls))
	copy(out, m.calls)
	return out
}

// newSessionForTest 为测试构造一个 session（含真实 P-256 IK + 内存 store）。
func newSessionForTest(t *testing.T) (*V2Session, *V2KeyStore) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewV2KeyStore(db)
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err := crypto.GenerateP256Keypair()
	if err != nil {
		t.Fatal(err)
	}
	sess := NewV2Session(store, "dev-1", "alice.aid.com", priv, pub)
	return sess, store
}

func TestEnsureKeys_GeneratesSPK_WhenNoneExists(t *testing.T) {
	sess, store := newSessionForTest(t)

	if err := sess.EnsureKeys(); err != nil {
		t.Fatal(err)
	}
	id := sess.CurrentSPKID()
	if !strings.HasPrefix(id, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %s", id)
	}
	// 已写入 store
	idStored, _, _, err := store.LoadCurrentSPK("dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if idStored != id {
		t.Fatalf("store id %s != memory id %s", idStored, id)
	}
}

func TestEnsureKeys_ReuseExistingSPK(t *testing.T) {
	sess, store := newSessionForTest(t)
	// 预先写入一个 SPK
	preID := "sha256:preexistingid01"
	if err := store.SaveSPK("dev-1", preID, bytes.Repeat([]byte{1}, 32), []byte("pub-pre")); err != nil {
		t.Fatal(err)
	}
	if err := sess.EnsureKeys(); err != nil {
		t.Fatal(err)
	}
	if got := sess.CurrentSPKID(); got != preID {
		t.Fatalf("expected reuse %s, got %s", preID, got)
	}
}

func TestEnsureKeys_RequiresIK(t *testing.T) {
	db, _ := sql.Open("sqlite", ":memory:")
	defer db.Close()
	store, err := NewV2KeyStore(db)
	if err != nil {
		t.Fatal(err)
	}
	// 注入空 IK
	sess := NewV2Session(store, "dev-1", "alice.aid.com", nil, nil)
	err = sess.EnsureKeys()
	if err == nil {
		t.Fatal("expected error when IK missing")
	}
}

func TestEnsureRegistered_CallsRPC(t *testing.T) {
	sess, _ := newSessionForTest(t)
	rpc := &mockRPC{}
	if err := sess.EnsureRegistered(context.Background(), rpc.call); err != nil {
		t.Fatal(err)
	}
	calls := rpc.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0].Method != "message.v2.put_peer_pk" {
		t.Fatalf("wrong method %s", calls[0].Method)
	}
	p := calls[0].Params
	if p["peer_aid"] != "alice.aid.com" {
		t.Fatalf("wrong peer_aid: %v", p["peer_aid"])
	}
	if p["key_source"] != "peer_device_prekey" {
		t.Fatalf("wrong key_source: %v", p["key_source"])
	}
	if id, _ := p["spk_id"].(string); !strings.HasPrefix(id, "sha256:") {
		t.Fatalf("wrong spk_id: %v", p["spk_id"])
	}
	// 验证 spk_pk 是 base64
	pk, _ := p["spk_pk"].(string)
	if _, err := base64.StdEncoding.DecodeString(pk); err != nil {
		t.Fatalf("spk_pk not valid base64: %v", err)
	}
	// 验证 spk_signature 是 base64 + 64 字节 RAW
	sig, _ := p["spk_signature"].(string)
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("spk_signature not valid base64: %v", err)
	}
	if len(sigBytes) != 64 {
		t.Fatalf("expected 64-byte raw sig, got %d", len(sigBytes))
	}
	// 验证签名可被 IK 公钥验证
	pkBytes, _ := base64.StdEncoding.DecodeString(pk)
	tsRaw := p["spk_timestamp"]
	ts, ok := tsRaw.(int64)
	if !ok {
		t.Fatalf("spk_timestamp not int64: %T", tsRaw)
	}
	signData := append([]byte{}, pkBytes...)
	signData = append(signData, []byte(p["spk_id"].(string))...)
	signData = append(signData, []byte(fmt.Sprintf("%d", ts))...)
	ikPubDER, err := sess.IKPubDER()
	if err != nil {
		t.Fatal(err)
	}
	if !crypto.ECDSAVerifyRaw(ikPubDER, sigBytes, signData) {
		t.Fatal("SPK signature verify failed")
	}
}

func TestEnsureRegistered_Idempotent(t *testing.T) {
	sess, _ := newSessionForTest(t)
	rpc := &mockRPC{}
	for i := 0; i < 3; i++ {
		if err := sess.EnsureRegistered(context.Background(), rpc.call); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(rpc.Calls()); got != 1 {
		t.Fatalf("expected 1 call (idempotent), got %d", got)
	}
}

func TestEnsureRegistered_RPCError_NotMarked(t *testing.T) {
	sess, _ := newSessionForTest(t)
	rpc := &mockRPC{returnErr: fmt.Errorf("boom")}
	if err := sess.EnsureRegistered(context.Background(), rpc.call); err == nil {
		t.Fatal("expected error from rpc")
	}
	// 重置错误并再次调用，应该真正发起 RPC
	rpc.returnErr = nil
	if err := sess.EnsureRegistered(context.Background(), rpc.call); err != nil {
		t.Fatal(err)
	}
	if got := len(rpc.Calls()); got != 2 {
		t.Fatalf("expected 2 calls (first failed not marked registered), got %d", got)
	}
}

func TestRotateSPK_NewKeyAndRegister(t *testing.T) {
	sess, _ := newSessionForTest(t)
	rpc := &mockRPC{}
	if err := sess.EnsureRegistered(context.Background(), rpc.call); err != nil {
		t.Fatal(err)
	}
	oldID := sess.CurrentSPKID()
	if err := sess.RotateSPK(context.Background(), rpc.call); err != nil {
		t.Fatal(err)
	}
	newID := sess.CurrentSPKID()
	if newID == oldID {
		t.Fatal("rotate should produce new spk id")
	}
	calls := rpc.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}
	if calls[1].Params["spk_id"].(string) != newID {
		t.Fatal("rotate call should carry new spk id")
	}
}

func TestGetDecryptKeys_Cases(t *testing.T) {
	sess, store := newSessionForTest(t)
	if err := sess.EnsureKeys(); err != nil {
		t.Fatal(err)
	}
	currentID := sess.CurrentSPKID()

	// 1) spk_id == "" → spk priv 为 nil
	ik, spk, err := sess.GetDecryptKeys("")
	if err != nil {
		t.Fatal(err)
	}
	if spk != nil {
		t.Fatal("empty spk_id should return nil spk priv")
	}
	if len(ik) != 32 {
		t.Fatalf("expected 32-byte IK priv, got %d", len(ik))
	}

	// 2) spk_id == 当前 SPK → 返回当前 spk priv
	_, spk, err = sess.GetDecryptKeys(currentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(spk) != 32 {
		t.Fatalf("expected 32-byte current SPK priv, got %d", len(spk))
	}

	// 3) 旧 SPK 从 store 加载
	oldPriv := bytes.Repeat([]byte{0x77}, 32)
	if err := store.SaveSPK("dev-1", "sha256:old0123456789ab", oldPriv, []byte("oldpub")); err != nil {
		t.Fatal(err)
	}
	_, spk, err = sess.GetDecryptKeys("sha256:old0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(spk, oldPriv) {
		t.Fatal("old SPK priv mismatch")
	}

	// 4) 不存在的 spk_id → spk priv 为 nil（不 error）
	_, spk, err = sess.GetDecryptKeys("sha256:nonexistent00000")
	if err != nil {
		t.Fatal(err)
	}
	if spk != nil {
		t.Fatal("missing spk should return nil")
	}
}

func TestIsCurrentSPK(t *testing.T) {
	sess, _ := newSessionForTest(t)
	if err := sess.EnsureKeys(); err != nil {
		t.Fatal(err)
	}
	cur := sess.CurrentSPKID()
	if !sess.IsCurrentSPK(cur) {
		t.Fatal("should match current")
	}
	if sess.IsCurrentSPK("") {
		t.Fatal("empty should not match")
	}
	if sess.IsCurrentSPK("sha256:other") {
		t.Fatal("other should not match")
	}
}

func TestTrackOldSPKMaxSeq_OnlyTracksNonCurrent(t *testing.T) {
	sess, _ := newSessionForTest(t)
	if err := sess.EnsureKeys(); err != nil {
		t.Fatal(err)
	}
	cur := sess.CurrentSPKID()
	// 当前 SPK 不被跟踪
	sess.TrackOldSPKMaxSeq(cur, 100)
	// 空字符串忽略
	sess.TrackOldSPKMaxSeq("", 50)
	// 非当前的会被记录
	sess.TrackOldSPKMaxSeq("sha256:old1234567890ab", 5)
	sess.TrackOldSPKMaxSeq("sha256:old1234567890ab", 10) // 升高
	sess.TrackOldSPKMaxSeq("sha256:old1234567890ab", 8)  // 不降低

	// MaybeDestroyOldSPKs 在 contig=20、时间已超过 7h 时应包含此 spk
	sess.SetNowFnForTest(func() time.Time { return time.Now().Add(8 * time.Hour) })
	destroyed := sess.MaybeDestroyOldSPKs(20)
	// 但旧 SPK 不在 store（未保存），DeleteSPK 不会失败但跟踪 map 应清理
	// 检查：destroyed 包含此 id
	found := false
	for _, id := range destroyed {
		if id == "sha256:old1234567890ab" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected destroyed to include old spk, got %v", destroyed)
	}
}

func TestMaybeDestroyOldSPKs_TripleCondition(t *testing.T) {
	sess, store := newSessionForTest(t)
	if err := sess.EnsureKeys(); err != nil {
		t.Fatal(err)
	}

	// 使用 t0 附近的 created_at，避免被 180 天硬上限路径独立扫到。
	// 条件 1/2/3 验证的是引用计数 + 时间 + 7 代窗口三重判定，不该被硬上限干扰。
	t0 := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	baseCreatedAt := t0.Unix()

	// 准备一个旧 SPK（保存到 store，不在最近 7 代窗口内 → 我们下面再加 8 个比它新的）
	oldID := "sha256:tobedestroy01ab"
	if err := store.SaveSPKWithCreatedAt("dev-1", oldID, bytes.Repeat([]byte{1}, 32), []byte("pub"), baseCreatedAt); err != nil {
		t.Fatal(err)
	}
	// 加 8 个更新的 SPK，将 oldID 排出最近 7 代窗口
	for i := 0; i < 8; i++ {
		spkID := fmt.Sprintf("sha256:newer%011d", i)
		if err := store.SaveSPKWithCreatedAt("dev-1", spkID, bytes.Repeat([]byte{2}, 32), []byte("p"), baseCreatedAt+int64(i+1)); err != nil {
			t.Fatal(err)
		}
	}

	// 注入虚拟时间：先在原始时刻
	sess.SetNowFnForTest(func() time.Time { return t0 })
	// 跟踪 max_seq=10，last_seen=t0
	sess.TrackOldSPKMaxSeq(oldID, 10)

	// 条件 1：contig_seq < max_seq → 不销毁
	dest := sess.MaybeDestroyOldSPKs(5)
	if len(dest) != 0 {
		t.Fatalf("contig<max should not destroy, got %v", dest)
	}

	// 条件 2：contig 满足，但时间不到 7h → 不销毁
	sess.SetNowFnForTest(func() time.Time { return t0.Add(2 * time.Hour) })
	dest = sess.MaybeDestroyOldSPKs(20)
	if len(dest) != 0 {
		t.Fatalf("time<7h should not destroy, got %v", dest)
	}

	// 条件 3：contig 满足、时间满足，但仍在最近 7 代窗口内 → 不销毁
	// 把所有 8 个 newer 删掉，让 oldID 进入 recent 7 窗口
	for i := 0; i < 8; i++ {
		spkID := fmt.Sprintf("sha256:newer%011d", i)
		_ = store.DeleteSPK("dev-1", spkID)
	}
	// 现在 oldID 是唯一的 SPK，必然在最近 7 代里
	sess.SetNowFnForTest(func() time.Time { return t0.Add(8 * time.Hour) })
	dest = sess.MaybeDestroyOldSPKs(20)
	if len(dest) != 0 {
		t.Fatalf("recent-7 keep window should not destroy, got %v", dest)
	}
	// store 里 oldID 仍存在
	priv, _ := store.LoadSPK("dev-1", oldID)
	if priv == nil {
		t.Fatal("oldID should still be in store (recent-7 keep)")
	}

	// 三条件全满足：把 oldID 排出 recent-7 + contig 满足 + 时间满足
	// 新 SPK 的 created_at 必须 > oldID（baseCreatedAt），同时仍在 180 天窗口内不触发硬上限
	for i := 0; i < 8; i++ {
		spkID := fmt.Sprintf("sha256:newer%011d", i)
		if err := store.SaveSPKWithCreatedAt("dev-1", spkID, bytes.Repeat([]byte{2}, 32), []byte("p"), baseCreatedAt+int64(100+i)); err != nil {
			t.Fatal(err)
		}
	}
	dest = sess.MaybeDestroyOldSPKs(20)
	found := false
	for _, id := range dest {
		if id == oldID {
			found = true
		}
	}
	if !found {
		t.Fatalf("triple condition met, expected destroy, got %v", dest)
	}
	priv, _ = store.LoadSPK("dev-1", oldID)
	if priv != nil {
		t.Fatal("oldID should be destroyed in store")
	}
}

func TestMaybeDestroyOldSPKs_CurrentSPKNeverDestroyed(t *testing.T) {
	sess, _ := newSessionForTest(t)
	if err := sess.EnsureKeys(); err != nil {
		t.Fatal(err)
	}
	cur := sess.CurrentSPKID()
	// 直接构造 oldSPKMaxSeq 让 cur 出现（虽然 TrackOldSPKMaxSeq 会忽略 cur）
	sess.mu.Lock()
	sess.oldSPKMaxSeq[cur] = oldSPKSeq{seq: 1, lastSeenAt: time.Now().Add(-100 * time.Hour)}
	sess.mu.Unlock()
	dest := sess.MaybeDestroyOldSPKs(1000)
	for _, id := range dest {
		if id == cur {
			t.Fatal("current SPK must not be destroyed")
		}
	}
}

func TestPeerIKCache_TTL(t *testing.T) {
	sess, _ := newSessionForTest(t)
	t0 := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	sess.SetNowFnForTest(func() time.Time { return t0 })

	pub := []byte("peer-ik-pub-der")
	sess.CachePeerIK("bob.aid.com", "bob-dev", pub)

	got := sess.GetPeerIK("bob.aid.com", "bob-dev")
	if !bytes.Equal(got, pub) {
		t.Fatal("expected immediate cache hit")
	}

	// 30 分钟内仍命中
	sess.SetNowFnForTest(func() time.Time { return t0.Add(30 * time.Minute) })
	if got := sess.GetPeerIK("bob.aid.com", "bob-dev"); !bytes.Equal(got, pub) {
		t.Fatal("expected hit at 30min")
	}

	// 1 小时后过期
	sess.SetNowFnForTest(func() time.Time { return t0.Add(1*time.Hour + time.Second) })
	if got := sess.GetPeerIK("bob.aid.com", "bob-dev"); got != nil {
		t.Fatal("expected expired")
	}

	// miss key
	if got := sess.GetPeerIK("never.aid.com", "any"); got != nil {
		t.Fatal("expected nil for missing")
	}
}

func TestVerifiedSPKs(t *testing.T) {
	sess, _ := newSessionForTest(t)
	if sess.IsPeerSPKVerified("a", "d", "s1") {
		t.Fatal("not yet marked")
	}
	sess.MarkPeerSPKVerified("a", "d", "s1")
	if !sess.IsPeerSPKVerified("a", "d", "s1") {
		t.Fatal("should be verified")
	}
	if sess.IsPeerSPKVerified("a", "d", "s2") {
		t.Fatal("different spk should not match")
	}
	if sess.IsPeerSPKVerified("a", "d2", "s1") {
		t.Fatal("different device should not match")
	}
}

func TestGetSenderIdentity(t *testing.T) {
	sess, _ := newSessionForTest(t)
	id, err := sess.GetSenderIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if id.AID != "alice.aid.com" || id.DeviceID != "dev-1" {
		t.Fatalf("identity wrong: %+v", id)
	}
	if len(id.IKPriv) != 32 || len(id.IKPubDER) == 0 {
		t.Fatalf("ik fields wrong: priv-len=%d pub-len=%d", len(id.IKPriv), len(id.IKPubDER))
	}
}

func TestConcurrentSafety(t *testing.T) {
	sess, _ := newSessionForTest(t)
	if err := sess.EnsureKeys(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sess.CachePeerIK(fmt.Sprintf("peer%d.aid.com", i), "d", []byte("pub"))
			_ = sess.GetPeerIK(fmt.Sprintf("peer%d.aid.com", i), "d")
			sess.MarkPeerSPKVerified("a", "d", fmt.Sprintf("s-%d", i))
			sess.TrackOldSPKMaxSeq(fmt.Sprintf("sha256:old-%012d", i), int64(i))
			_ = sess.IsPeerSPKVerified("a", "d", fmt.Sprintf("s-%d", i))
			_, _, _ = sess.GetDecryptKeys("")
		}(i)
	}
	wg.Wait()
}
