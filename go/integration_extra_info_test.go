//go:build integration

package aun

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════
// ExtraInfo 集成测试 — 验证 connect 时传入的 extra_info 在踢人时透传
//
// 运行方法:
//   MSYS_NO_PATHCONV=1 docker exec kite-go-tester sh -lc \
//     "cd /workspace/go && /usr/local/go/bin/go test -tags integration . \
//      -run TestExtraInfo -count=1 -v"
//
// 前置条件:
//   - Docker 环境运行中（docker compose up -d）
//   - 运行环境能解析 gateway.agentid.pub
// ═══════════════════════════════════════════════════════════════════════════

// TestExtraInfo_KickCarriesBothInfos 验证：
// c1 connect(ExtraInfo={pid:1111})，c2 同槽位 connect(ExtraInfo={pid:2222})
// → c1 收到 gateway.disconnect 含 self_extra_info.pid=1111 + new_extra_info.pid=2222
func TestExtraInfo_KickCarriesBothInfos(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("go-ei-%s.%s", rid, testIssuer())

	sharedPath := t.TempDir()
	createAIDInPath(t, sharedPath, aid)

	// c1: connect with ExtraInfo={pid: "1111"}
	c1 := quotaTestClient(t, sharedPath)
	defer closeQuiet(c1)

	c1Disconnect, c1Cancel := captureDisconnect(c1)
	defer c1Cancel()

	ctx1, cancel1 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel1()
	authResult1, err := c1.Auth.Authenticate(ctx1, map[string]any{"aid": aid})
	if err != nil {
		t.Skipf("无法认证（Docker 环境可能未运行）: %v", err)
	}
	authResult1["slot_id"] = "extra-slot"
	authResult1["connection_kind"] = "long"
	if err := c1.Connect(ctx1, authResult1, &ConnectOptions{
		AutoReconnect:     false,
		HeartbeatInterval: 30,
		ConnectionKind:    "long",
		ExtraInfo:         map[string]any{"pid": "1111"},
	}); err != nil {
		t.Fatalf("c1 连接失败: %v", err)
	}
	t.Logf("[OK] c1 已连接 (ExtraInfo={pid:1111})")

	// 短暂等待确保 c1 注册完成
	time.Sleep(200 * time.Millisecond)

	// c2: 同 aid + 同 slot → 挤掉 c1
	c2 := quotaTestClient(t, sharedPath)
	defer closeQuiet(c2)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()
	authResult2, err := c2.Auth.Authenticate(ctx2, map[string]any{"aid": aid})
	if err != nil {
		t.Fatalf("c2 认证失败: %v", err)
	}
	authResult2["slot_id"] = "extra-slot"
	authResult2["connection_kind"] = "long"
	if err := c2.Connect(ctx2, authResult2, &ConnectOptions{
		AutoReconnect:     false,
		HeartbeatInterval: 30,
		ConnectionKind:    "long",
		ExtraInfo:         map[string]any{"pid": "2222"},
	}); err != nil {
		t.Fatalf("c2 连接失败: %v", err)
	}
	t.Logf("[OK] c2 已连接 (ExtraInfo={pid:2222})，应踢掉 c1")

	// 等待 c1 收到 gateway.disconnect
	var info quotaDisconnectInfo
	select {
	case info = <-c1Disconnect:
	case <-time.After(10 * time.Second):
		t.Fatalf("超时未收到 c1 的 gateway.disconnect 事件")
	}

	t.Logf("c1 收到 disconnect: code=%d reason=%s detail=%v", info.code, info.reason, info.detail)

	// 验证 code 为 4009（slot 替换）
	if info.code != 4009 {
		t.Errorf("期望 code=4009，实际 code=%d", info.code)
	}

	// 验证 detail 中包含 self_extra_info 和 new_extra_info
	if info.detail == nil {
		t.Fatalf("detail 为 nil，无法验证 extra_info")
	}

	selfExtra, _ := info.detail["self_extra_info"].(map[string]any)
	if selfExtra == nil {
		t.Fatalf("detail.self_extra_info 为 nil")
	}
	if pid, _ := selfExtra["pid"].(string); pid != "1111" {
		t.Errorf("期望 self_extra_info.pid=1111，实际=%v", selfExtra["pid"])
	}

	newExtra, _ := info.detail["new_extra_info"].(map[string]any)
	if newExtra == nil {
		t.Fatalf("detail.new_extra_info 为 nil")
	}
	if pid, _ := newExtra["pid"].(string); pid != "2222" {
		t.Errorf("期望 new_extra_info.pid=2222，实际=%v", newExtra["pid"])
	}

	t.Logf("[OK] extra_info 踢人透传验证通过")
}

// TestExtraInfo_EmptyWhenNotProvided 验证：
// 不传 ExtraInfo 时 detail 里无 extra_info 字段（或为 nil）
func TestExtraInfo_EmptyWhenNotProvided(t *testing.T) {
	rid := runID()
	aid := fmt.Sprintf("go-ei0-%s.%s", rid, testIssuer())

	sharedPath := t.TempDir()
	createAIDInPath(t, sharedPath, aid)

	// c1: connect 不传 ExtraInfo
	c1 := quotaTestClient(t, sharedPath)
	defer closeQuiet(c1)

	c1Disconnect, c1Cancel := captureDisconnect(c1)
	defer c1Cancel()

	ctx1, cancel1 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel1()
	authResult1, err := c1.Auth.Authenticate(ctx1, map[string]any{"aid": aid})
	if err != nil {
		t.Skipf("无法认证（Docker 环境可能未运行）: %v", err)
	}
	authResult1["slot_id"] = "no-extra-slot"
	authResult1["connection_kind"] = "long"
	if err := c1.Connect(ctx1, authResult1, &ConnectOptions{
		AutoReconnect:     false,
		HeartbeatInterval: 30,
		ConnectionKind:    "long",
	}); err != nil {
		t.Fatalf("c1 连接失败: %v", err)
	}
	t.Logf("[OK] c1 已连接 (无 ExtraInfo)")

	time.Sleep(200 * time.Millisecond)

	// c2: 同 slot 挤掉 c1，也不传 ExtraInfo
	c2 := quotaTestClient(t, sharedPath)
	defer closeQuiet(c2)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()
	authResult2, err := c2.Auth.Authenticate(ctx2, map[string]any{"aid": aid})
	if err != nil {
		t.Fatalf("c2 认证失败: %v", err)
	}
	authResult2["slot_id"] = "no-extra-slot"
	authResult2["connection_kind"] = "long"
	if err := c2.Connect(ctx2, authResult2, &ConnectOptions{
		AutoReconnect:     false,
		HeartbeatInterval: 30,
		ConnectionKind:    "long",
	}); err != nil {
		t.Fatalf("c2 连接失败: %v", err)
	}
	t.Logf("[OK] c2 已连接 (无 ExtraInfo)，应踢掉 c1")

	// 等待 c1 收到 gateway.disconnect
	var info quotaDisconnectInfo
	select {
	case info = <-c1Disconnect:
	case <-time.After(10 * time.Second):
		t.Fatalf("超时未收到 c1 的 gateway.disconnect 事件")
	}

	t.Logf("c1 收到 disconnect: code=%d reason=%s detail=%v", info.code, info.reason, info.detail)

	// 验证 code 为 4009
	if info.code != 4009 {
		t.Errorf("期望 code=4009，实际 code=%d", info.code)
	}

	// detail 中不应有 self_extra_info / new_extra_info，或为 nil
	if info.detail != nil {
		if selfExtra, ok := info.detail["self_extra_info"]; ok && selfExtra != nil {
			// 如果存在但为空 map 也可接受
			if m, ok := selfExtra.(map[string]any); ok && len(m) > 0 {
				t.Errorf("不传 ExtraInfo 时不应有非空 self_extra_info，实际=%v", selfExtra)
			}
		}
		if newExtra, ok := info.detail["new_extra_info"]; ok && newExtra != nil {
			if m, ok := newExtra.(map[string]any); ok && len(m) > 0 {
				t.Errorf("不传 ExtraInfo 时不应有非空 new_extra_info，实际=%v", newExtra)
			}
		}
	}

	t.Logf("[OK] 无 ExtraInfo 时踢人验证通过")
}
