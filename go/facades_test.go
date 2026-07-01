package aun

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestClientFacadeGettersAreCached(t *testing.T) {
	client := NewAUNClientEmpty()
	defer func() { _ = client.Close() }()

	if first, second := client.Message(), client.Message(); first == nil || first != second {
		t.Fatal("Message getter 应惰性缓存同一实例")
	}
	if first, second := client.Group(), client.Group(); first == nil || first != second {
		t.Fatal("Group getter 应惰性缓存同一实例")
	}
	if first, second := client.Stream(), client.Stream(); first == nil || first != second {
		t.Fatal("Stream getter 应惰性缓存同一实例")
	}
	if first, second := client.Message().Thought(), client.Message().Thought(); first == nil || first != second {
		t.Fatal("Message().Thought getter 应惰性缓存同一实例")
	}
	if first, second := client.Group().Thought(), client.Group().Thought(); first == nil || first != second {
		t.Fatal("Group().Thought getter 应惰性缓存同一实例")
	}
	if first, second := client.Group().FS(), client.Group().FS(); first == nil || first != second {
		t.Fatal("Group().FS getter 应惰性缓存同一实例")
	}
}

func TestMessageFacadeRPCMappingsAndNilFiltering(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	message := newMessageFacade(client)
	var nilSlice []string

	cases := []struct {
		name   string
		call   func() error
		method string
	}{
		{"send", func() error {
			_, err := message.Send(ctx, map[string]any{"to": "bob1.agentid.pub", "payload": map[string]any{"text": "hi"}, "drop": nil})
			return err
		}, "message.send"},
		{"pull", func() error {
			_, err := message.Pull(ctx, map[string]any{"after_seq": 7, "limit": 20, "nil_slice": nilSlice})
			return err
		}, "message.pull"},
		{"ack", func() error {
			_, err := message.Ack(ctx, map[string]any{"seq": 9})
			return err
		}, "message.ack"},
		{"recall", func() error {
			_, err := message.Recall(ctx, map[string]any{"message_ids": []string{"m1"}})
			return err
		}, "message.recall"},
		{"query_online", func() error {
			_, err := message.QueryOnline(ctx, map[string]any{"aid": "bob1.agentid.pub"})
			return err
		}, "message.query_online"},
		{"thought_put", func() error {
			_, err := message.Thought().Put(ctx, map[string]any{"to": "bob1.agentid.pub", "context": map[string]any{"type": "chat", "id": "c1"}, "payload": map[string]any{"text": "t"}})
			return err
		}, "message.thought.put"},
		{"thought_get", func() error {
			_, err := message.Thought().Get(ctx, map[string]any{"sender_aid": "bob1.agentid.pub", "context": map[string]any{"type": "chat", "id": "c1"}})
			return err
		}, "message.thought.get"},
	}

	for _, tc := range cases {
		if err := tc.call(); err != nil {
			t.Fatalf("%s 调用失败: %v", tc.name, err)
		}
	}
	if len(client.calls) != len(cases) {
		t.Fatalf("调用次数不正确: got=%d want=%d calls=%#v", len(client.calls), len(cases), client.calls)
	}
	for i, tc := range cases {
		if client.calls[i].method != tc.method {
			t.Fatalf("第 %d 次调用方法不正确: got=%s want=%s", i, client.calls[i].method, tc.method)
		}
	}
	if _, exists := client.calls[0].params["drop"]; exists {
		t.Fatalf("nil 参数未过滤: %#v", client.calls[0].params)
	}
	if _, exists := client.calls[1].params["nil_slice"]; exists {
		t.Fatalf("nil slice 参数未过滤: %#v", client.calls[1].params)
	}
}

func TestGroupFacadeRPCMappings(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	group := newGroupFacade(client)

	cases := []struct {
		name   string
		call   func() error
		method string
	}{
		{"create", func() error { _, err := group.Create(ctx, map[string]any{"name": "team"}); return err }, "group.create"},
		{"bind_aid", func() error {
			_, err := group.BindAID(ctx, map[string]any{"group_id": "g1", "aid": "team.agentid.pub"})
			return err
		}, "group.bind_aid"},
		{"get_info", func() error { _, err := group.GetInfo(ctx, map[string]any{"group_id": "g1"}); return err }, "group.get_info"},
		{"update", func() error { _, err := group.Update(ctx, map[string]any{"group_id": "g1", "name": "new"}); return err }, "group.update"},
		{"list", func() error { _, err := group.List(ctx, nil); return err }, "group.list"},
		{"list_my", func() error { _, err := group.ListMy(ctx, nil); return err }, "group.list_my"},
		{"search", func() error { _, err := group.Search(ctx, map[string]any{"q": "team"}); return err }, "group.search"},
		{"suspend", func() error { _, err := group.Suspend(ctx, map[string]any{"group_id": "g1"}); return err }, "group.suspend"},
		{"resume", func() error { _, err := group.Resume(ctx, map[string]any{"group_id": "g1"}); return err }, "group.resume"},
		{"dissolve", func() error { _, err := group.Dissolve(ctx, map[string]any{"group_id": "g1"}); return err }, "group.dissolve"},
		{"add_member", func() error {
			_, err := group.AddMember(ctx, map[string]any{"group_id": "g1", "aid": "bob1.agentid.pub"})
			return err
		}, "group.add_member"},
		{"get_members", func() error { _, err := group.GetMembers(ctx, map[string]any{"group_id": "g1"}); return err }, "group.get_members"},
		{"get_online_members", func() error { _, err := group.GetOnlineMembers(ctx, map[string]any{"group_id": "g1"}); return err }, "group.get_online_members"},
		{"kick", func() error {
			_, err := group.Kick(ctx, map[string]any{"group_id": "g1", "aid": "bob1.agentid.pub"})
			return err
		}, "group.kick"},
		{"leave", func() error { _, err := group.Leave(ctx, map[string]any{"group_id": "g1"}); return err }, "group.leave"},
		{"set_role", func() error {
			_, err := group.SetRole(ctx, map[string]any{"group_id": "g1", "aid": "bob1.agentid.pub", "role": "admin"})
			return err
		}, "group.set_role"},
		{"transfer_owner", func() error {
			_, err := group.TransferOwner(ctx, map[string]any{"group_id": "g1", "aid": "bob1.agentid.pub"})
			return err
		}, "group.transfer_owner"},
		{"complete_transfer", func() error {
			_, err := group.CompleteTransfer(ctx, map[string]any{"group_id": "g1", "public_key": "PUB"})
			return err
		}, "group.complete_transfer"},
		{"ban", func() error {
			_, err := group.Ban(ctx, map[string]any{"group_id": "g1", "aid": "bob1.agentid.pub"})
			return err
		}, "group.ban"},
		{"unban", func() error {
			_, err := group.Unban(ctx, map[string]any{"group_id": "g1", "aid": "bob1.agentid.pub"})
			return err
		}, "group.unban"},
		{"get_banlist", func() error { _, err := group.GetBanlist(ctx, map[string]any{"group_id": "g1"}); return err }, "group.get_banlist"},
		{"request_join", func() error { _, err := group.RequestJoin(ctx, map[string]any{"group_id": "g1"}); return err }, "group.request_join"},
		{"list_join_requests", func() error { _, err := group.ListJoinRequests(ctx, map[string]any{"group_id": "g1"}); return err }, "group.list_join_requests"},
		{"review_join_request", func() error {
			_, err := group.ReviewJoinRequest(ctx, map[string]any{"request_id": "r1", "action": "approve"})
			return err
		}, "group.review_join_request"},
		{"batch_review_join_request", func() error {
			_, err := group.BatchReviewJoinRequest(ctx, map[string]any{"request_ids": []string{"r1"}, "action": "approve"})
			return err
		}, "group.batch_review_join_request"},
		{"create_invite_code", func() error { _, err := group.CreateInviteCode(ctx, map[string]any{"group_id": "g1"}); return err }, "group.create_invite_code"},
		{"list_invite_codes", func() error { _, err := group.ListInviteCodes(ctx, map[string]any{"group_id": "g1"}); return err }, "group.list_invite_codes"},
		{"use_invite_code", func() error { _, err := group.UseInviteCode(ctx, map[string]any{"code": "ic1"}); return err }, "group.use_invite_code"},
		{"revoke_invite_code", func() error { _, err := group.RevokeInviteCode(ctx, map[string]any{"code": "ic1"}); return err }, "group.revoke_invite_code"},
		{"set_settings", func() error {
			_, err := group.SetSettings(ctx, map[string]any{"group_id": "g1", "dispatch_mode": "broadcast"})
			return err
		}, "group.set_settings"},
		{"get_settings", func() error { _, err := group.GetSettings(ctx, map[string]any{"group_id": "g1"}); return err }, "group.get_settings"},
		{"send", func() error {
			_, err := group.Send(ctx, map[string]any{"group_id": "g-test", "payload": map[string]any{"text": "hi"}})
			return err
		}, "group.send"},
		{"recall", func() error {
			_, err := group.Recall(ctx, map[string]any{"group_id": "g1", "message_ids": []string{"m1"}})
			return err
		}, "group.recall"},
		{"pull", func() error {
			_, err := group.Pull(ctx, map[string]any{"group_id": "g-test", "after_message_seq": 1})
			return err
		}, "group.pull"},
		{"pull_events", func() error {
			_, err := group.PullEvents(ctx, map[string]any{"group_id": "g1", "after_event_seq": 1})
			return err
		}, "group.pull_events"},
		{"ack_messages", func() error {
			_, err := group.AckMessages(ctx, map[string]any{"group_id": "g1", "msg_seq": 2})
			return err
		}, "group.ack_messages"},
		{"ack_events", func() error {
			_, err := group.AckEvents(ctx, map[string]any{"group_id": "g1", "event_seq": 3})
			return err
		}, "group.ack_events"},
		{"thought_put", func() error {
			_, err := group.Thought().Put(ctx, map[string]any{"group_id": "g1", "context": map[string]any{"type": "chat", "id": "c1"}, "payload": map[string]any{"text": "t"}})
			return err
		}, "group.thought.put"},
		{"thought_get", func() error {
			_, err := group.Thought().Get(ctx, map[string]any{"group_id": "g1", "sender_aid": "alice.agentid.pub", "context": map[string]any{"type": "chat", "id": "c1"}})
			return err
		}, "group.thought.get"},
	}

	for _, tc := range cases {
		if err := tc.call(); err != nil {
			t.Fatalf("%s 调用失败: %v", tc.name, err)
		}
	}
	if len(client.calls) != len(cases) {
		t.Fatalf("调用次数不正确: got=%d want=%d calls=%#v", len(client.calls), len(cases), client.calls)
	}
	for i, tc := range cases {
		if client.calls[i].method != tc.method {
			t.Fatalf("第 %d 次调用方法不正确: got=%s want=%s", i, client.calls[i].method, tc.method)
		}
	}
	var listParams map[string]any
	for i, tc := range cases {
		if tc.name == "list" {
			listParams = client.calls[i].params
			break
		}
	}
	if !reflect.DeepEqual(listParams, map[string]any{}) {
		t.Fatalf("nil params 应转换为空 map: %#v", listParams)
	}
}

func TestGroupFacadeSendPullRequireGroupIDBeforeRPC(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	group := newGroupFacade(client)

	if _, err := group.Send(ctx, map[string]any{"payload": map[string]any{"text": "hi"}}); err == nil {
		t.Fatal("group.Send 缺少 group_id 应直接返回 ValidationError")
	} else if _, ok := err.(*ValidationError); !ok {
		t.Fatalf("group.Send 错误类型应为 ValidationError: %T %v", err, err)
	}
	if _, err := group.Pull(ctx, map[string]any{"group_id": "   ", "limit": 10}); err == nil {
		t.Fatal("group.Pull 空 group_id 应直接返回 ValidationError")
	} else if _, ok := err.(*ValidationError); !ok {
		t.Fatalf("group.Pull 错误类型应为 ValidationError: %T %v", err, err)
	}
	if len(client.calls) != 0 {
		t.Fatalf("缺少 group_id 时不应发起 RPC: %#v", client.calls)
	}
}

func TestGroupFacadeDoesNotExposeInternalRPCs(t *testing.T) {
	groupType := reflect.TypeOf((*GroupFacade)(nil))
	for _, method := range []string{
		"RemoveMember",
		"GetDispatchLog",
		"UpdateName",
		"UpdateAvatar",
		"UpdateSettings",
		"Invite",
		"Ack",
		"ListDevices",
		"UnregisterDevice",
		"GetAdmins",
		"GetMaster",
		"RefreshMemberTypes",
		"GetSummary",
		"GetMetrics",
		"GetPublicInfo",
		"GetStats",
		"GetState",
		"CommitState",
		"GetCursor",
	} {
		if _, exists := groupType.MethodByName(method); exists {
			t.Fatalf("GroupFacade 不应暴露内部/低层 RPC 方法 %s", method)
		}
	}
}

func TestLowLevelGroupRPCsRemainAccessibleThroughCall(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}

	if _, err := client.Call(ctx, "group.get_state", map[string]any{"group_id": "g1"}); err != nil {
		t.Fatalf("group.get_state 低层调用失败: %v", err)
	}
	if _, err := client.Call(ctx, "group.commit_state", map[string]any{"group_id": "g1", "state_version": 1}); err != nil {
		t.Fatalf("group.commit_state 低层调用失败: %v", err)
	}

	want := []string{"group.get_state", "group.commit_state"}
	if len(client.calls) != len(want) {
		t.Fatalf("调用次数不正确: got=%d want=%d calls=%#v", len(client.calls), len(want), client.calls)
	}
	for i, method := range want {
		if client.calls[i].method != method {
			t.Fatalf("第 %d 次调用方法不正确: got=%s want=%s", i, client.calls[i].method, method)
		}
	}
}

func TestStreamFacadeRPCMappingsAndNilFiltering(t *testing.T) {
	ctx := context.Background()
	client := &fakeStorageClient{aid: "alice.agentid.pub"}
	stream := newStreamFacade(client)

	if _, err := stream.Create(ctx, map[string]any{"content_type": "text/plain", "nil": nil}); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	if _, err := stream.Close(ctx, map[string]any{"stream_id": "s1"}); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if _, err := stream.GetInfo(ctx, map[string]any{"stream_id": "s1"}); err != nil {
		t.Fatalf("GetInfo 失败: %v", err)
	}
	if _, err := stream.ListActive(ctx, map[string]any{"limit": 10}); err != nil {
		t.Fatalf("ListActive 失败: %v", err)
	}

	want := []string{"stream.create", "stream.close", "stream.get_info", "stream.list_active"}
	if len(client.calls) != len(want) {
		t.Fatalf("调用次数不正确: got=%d want=%d calls=%#v", len(client.calls), len(want), client.calls)
	}
	for i, method := range want {
		if client.calls[i].method != method {
			t.Fatalf("第 %d 次调用方法不正确: got=%s want=%s", i, client.calls[i].method, method)
		}
	}
	if _, exists := client.calls[0].params["nil"]; exists {
		t.Fatalf("nil 参数未过滤: %#v", client.calls[0].params)
	}
}

func TestMessageFacadeSendUsesClientCallPipeline(t *testing.T) {
	wsURL, getCalls, closeServer := startTestRPCServer(t, func(method string, params map[string]any) any {
		if method == "auth.connect" {
			return map[string]any{"status": "ok"}
		}
		return map[string]any{"ok": true}
	})
	defer closeServer()

	client := newClient(map[string]any{"aun_path": t.TempDir()})
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := connectWithTestAuth(t, client, ctx, map[string]any{"access_token": "tok", "gateway": wsURL}, nil); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}

	if _, err := client.Message().Send(ctx, map[string]any{
		"to":      "bob1.example.com",
		"content": map[string]any{"text": "hello"},
		"encrypt": false,
		"drop":    nil,
	}); err != nil {
		t.Fatalf("Message().Send 失败: %v", err)
	}

	var sendCall *testRPCCall
	for _, call := range getCalls() {
		if call.Method == "message.send" {
			copied := call
			sendCall = &copied
		}
	}
	if sendCall == nil {
		t.Fatalf("未捕获 message.send: %#v", getCalls())
	}
	if _, exists := sendCall.Params["content"]; exists {
		t.Fatalf("Message().Send 应走 Client.Call pipeline 并移除 content: %#v", sendCall.Params)
	}
	if _, exists := sendCall.Params["encrypt"]; exists {
		t.Fatalf("Message().Send 应走 Client.Call pipeline 并消费 encrypt: %#v", sendCall.Params)
	}
	if _, exists := sendCall.Params["drop"]; exists {
		t.Fatalf("facade 应过滤 nil 参数: %#v", sendCall.Params)
	}
	payload, _ := sendCall.Params["payload"].(map[string]any)
	if payload["type"] != "text" || payload["text"] != "hello" {
		t.Fatalf("Message().Send 未走 payload 归一化: %#v", sendCall.Params)
	}
}
