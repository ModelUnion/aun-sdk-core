package aun

import (
	"context"
	"fmt"
	"sync"
)

type rpcFacade struct {
	client StorageRPCClient
	prefix string
}

func newRPCFacade(client StorageRPCClient, prefix string) rpcFacade {
	return rpcFacade{client: client, prefix: prefix}
}

func facadeParams(params map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range params {
		if !isNilStorageParam(value) {
			out[key] = value
		}
	}
	return out
}

func (f *rpcFacade) call(ctx context.Context, name string, params map[string]any) (any, error) {
	return f.client.Call(ctx, f.prefix+"."+name, facadeParams(params))
}

type ThoughtFacade struct {
	rpcFacade
}

func newThoughtFacade(client StorageRPCClient, prefix string) *ThoughtFacade {
	return &ThoughtFacade{rpcFacade: newRPCFacade(client, prefix)}
}

func (f *ThoughtFacade) Put(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "put", params)
}

func (f *ThoughtFacade) Get(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "get", params)
}

type MessageFacade struct {
	rpcFacade
	mu      sync.Mutex
	thought *ThoughtFacade
}

func newMessageFacade(client StorageRPCClient) *MessageFacade {
	return &MessageFacade{rpcFacade: newRPCFacade(client, "message")}
}

func (f *MessageFacade) Thought() *ThoughtFacade {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.thought == nil {
		f.thought = newThoughtFacade(f.client, "message.thought")
	}
	return f.thought
}

func (f *MessageFacade) Send(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "send", params)
}

func (f *MessageFacade) Pull(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "pull", params)
}

func (f *MessageFacade) Ack(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "ack", params)
}

func (f *MessageFacade) Recall(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "recall", params)
}

func (f *MessageFacade) QueryOnline(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "query_online", params)
}

type GroupFacade struct {
	rpcFacade
	mu      sync.Mutex
	fs      *GroupFSVFS
	thought *ThoughtFacade
}

func newGroupFacade(client StorageRPCClient) *GroupFacade {
	return &GroupFacade{rpcFacade: newRPCFacade(client, "group")}
}

func (f *GroupFacade) FS() *GroupFSVFS {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fs == nil {
		f.fs = NewGroupFSVFS(f.client)
	}
	return f.fs
}

func (f *GroupFacade) Thought() *ThoughtFacade {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.thought == nil {
		f.thought = newThoughtFacade(f.client, "group.thought")
	}
	return f.thought
}

func (f *GroupFacade) Create(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "create", params)
}

func (f *GroupFacade) BindAID(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "bind_aid", params)
}

func (f *GroupFacade) BindGroupAID(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "bind_group_aid", params)
}

func (f *GroupFacade) RenewGroupAID(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "renew_group_aid", params)
}

func (f *GroupFacade) GetInfo(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "get_info", params)
}

func (f *GroupFacade) Update(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "update", params)
}

func (f *GroupFacade) List(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "list", params)
}

func (f *GroupFacade) ListMy(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "list_my", params)
}

func (f *GroupFacade) Search(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "search", params)
}

func (f *GroupFacade) Suspend(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "suspend", params)
}

func (f *GroupFacade) Resume(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "resume", params)
}

func (f *GroupFacade) Dissolve(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "dissolve", params)
}

func (f *GroupFacade) AddMember(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "add_member", params)
}

func (f *GroupFacade) GetMembers(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "get_members", params)
}

func (f *GroupFacade) GetOnlineMembers(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "get_online_members", params)
}

func (f *GroupFacade) Kick(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "kick", params)
}

func (f *GroupFacade) Leave(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "leave", params)
}

func (f *GroupFacade) SetRole(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "set_role", params)
}

func (f *GroupFacade) TransferOwner(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "transfer_owner", params)
}

func (f *GroupFacade) CompleteTransfer(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "complete_transfer", params)
}

func (f *GroupFacade) Ban(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "ban", params)
}

func (f *GroupFacade) Unban(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "unban", params)
}

func (f *GroupFacade) GetBanlist(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "get_banlist", params)
}

func (f *GroupFacade) RequestJoin(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "request_join", params)
}

func (f *GroupFacade) ListJoinRequests(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "list_join_requests", params)
}

func (f *GroupFacade) ReviewJoinRequest(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "review_join_request", params)
}

func (f *GroupFacade) BatchReviewJoinRequest(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "batch_review_join_request", params)
}

func (f *GroupFacade) CreateInviteCode(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "create_invite_code", params)
}

func (f *GroupFacade) ListInviteCodes(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "list_invite_codes", params)
}

func (f *GroupFacade) UseInviteCode(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "use_invite_code", params)
}

func (f *GroupFacade) RevokeInviteCode(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "revoke_invite_code", params)
}

func (f *GroupFacade) SetSettings(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "set_settings", params)
}

func (f *GroupFacade) GetSettings(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "get_settings", params)
}

// groupSettingsToMap 将 GetSettings 返回的 settings 数组转为 {key: value} 映射
func groupSettingsToMap(resultMap map[string]any) map[string]any {
	settings := make(map[string]any)
	if settingsList, ok := resultMap["settings"].([]any); ok {
		for _, s := range settingsList {
			if sm, ok := s.(map[string]any); ok {
				if key, ok := sm["key"].(string); ok {
					settings[key] = sm["value"]
				}
			}
		}
	}
	return settings
}

func (f *GroupFacade) UpdateAnnouncement(ctx context.Context, params map[string]any) (any, error) {
	// 便利方法：基于 SetSettings
	groupID, ok := params["group_id"].(string)
	if !ok || groupID == "" {
		return nil, fmt.Errorf("group_id is required")
	}
	content, ok := params["content"]
	if !ok {
		return nil, fmt.Errorf("content is required")
	}

	settingsUpdate := map[string]any{"announcement.content": content}
	if attachments, exists := params["attachments"]; exists {
		settingsUpdate["announcement.attachments"] = attachments
	}

	result, err := f.SetSettings(ctx, map[string]any{
		"group_id": groupID,
		"settings": settingsUpdate,
	})
	if err != nil {
		return nil, err
	}

	resultMap, _ := result.(map[string]any)
	attachmentsList := params["attachments"]
	if attachmentsList == nil {
		attachmentsList = []any{}
	}
	return map[string]any{
		"group_id": resultMap["group_id"],
		"announcement": map[string]any{
			"group_id":    resultMap["group_id"],
			"content":     content,
			"attachments": attachmentsList,
		},
	}, nil
}

func (f *GroupFacade) Send(ctx context.Context, params map[string]any) (any, error) {
	if _, err := ValidateGroupIDFormat(params["group_id"], "group_id"); err != nil {
		return nil, err
	}
	return f.call(ctx, "send", params)
}

func (f *GroupFacade) Recall(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "recall", params)
}

func (f *GroupFacade) Pull(ctx context.Context, params map[string]any) (any, error) {
	if _, err := ValidateGroupIDFormat(params["group_id"], "group_id"); err != nil {
		return nil, err
	}
	return f.call(ctx, "pull", params)
}

func (f *GroupFacade) PullEvents(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "pull_events", params)
}

func (f *GroupFacade) AckMessages(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "ack_messages", params)
}

func (f *GroupFacade) AckEvents(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "ack_events", params)
}

func (f *GroupFacade) GetAnnouncement(ctx context.Context, params map[string]any) (any, error) {
	// 便利方法：基于 GetSettings
	groupID, ok := params["group_id"].(string)
	if !ok || groupID == "" {
		return nil, fmt.Errorf("group_id is required")
	}

	result, err := f.GetSettings(ctx, map[string]any{
		"group_id": groupID,
		"keys":     []string{"announcement.content", "announcement.attachments"},
	})
	if err != nil {
		return nil, err
	}

	resultMap, _ := result.(map[string]any)
	settings := groupSettingsToMap(resultMap)

	content := ""
	if v, ok := settings["announcement.content"].(string); ok {
		content = v
	}
	attachments := []any{}
	if v, ok := settings["announcement.attachments"].([]any); ok {
		attachments = v
	}

	return map[string]any{
		"group_id": resultMap["group_id"],
		"announcement": map[string]any{
			"group_id":    resultMap["group_id"],
			"content":     content,
			"attachments": attachments,
		},
	}, nil
}

func (f *GroupFacade) GetRules(ctx context.Context, params map[string]any) (any, error) {
	// 便利方法：基于 GetSettings
	groupID, ok := params["group_id"].(string)
	if !ok || groupID == "" {
		return nil, fmt.Errorf("group_id is required")
	}

	result, err := f.GetSettings(ctx, map[string]any{
		"group_id": groupID,
		"keys":     []string{"rules.content", "rules.attachments"},
	})
	if err != nil {
		return nil, err
	}

	resultMap, _ := result.(map[string]any)
	settings := groupSettingsToMap(resultMap)

	content := ""
	if v, ok := settings["rules.content"].(string); ok {
		content = v
	}
	attachments := []any{}
	if v, ok := settings["rules.attachments"].([]any); ok {
		attachments = v
	}

	return map[string]any{
		"group_id": resultMap["group_id"],
		"rules": map[string]any{
			"group_id":    resultMap["group_id"],
			"content":     content,
			"attachments": attachments,
		},
	}, nil
}

func (f *GroupFacade) UpdateRules(ctx context.Context, params map[string]any) (any, error) {
	// 便利方法：基于 SetSettings
	groupID, ok := params["group_id"].(string)
	if !ok || groupID == "" {
		return nil, fmt.Errorf("group_id is required")
	}
	content, ok := params["content"]
	if !ok {
		return nil, fmt.Errorf("content is required")
	}

	settingsUpdate := map[string]any{"rules.content": content}
	if attachments, exists := params["attachments"]; exists {
		settingsUpdate["rules.attachments"] = attachments
	}

	result, err := f.SetSettings(ctx, map[string]any{
		"group_id": groupID,
		"settings": settingsUpdate,
	})
	if err != nil {
		return nil, err
	}

	resultMap, _ := result.(map[string]any)
	attachmentsList := params["attachments"]
	if attachmentsList == nil {
		attachmentsList = []any{}
	}
	return map[string]any{
		"group_id": resultMap["group_id"],
		"rules": map[string]any{
			"group_id":    resultMap["group_id"],
			"content":     content,
			"attachments": attachmentsList,
		},
	}, nil
}

func (f *GroupFacade) GetJoinRequirements(ctx context.Context, params map[string]any) (any, error) {
	// 便利方法：基于 GetSettings
	groupID, ok := params["group_id"].(string)
	if !ok || groupID == "" {
		return nil, fmt.Errorf("group_id is required")
	}

	result, err := f.GetSettings(ctx, map[string]any{
		"group_id": groupID,
		"keys":     []string{"join.mode", "join.question", "join.auto_approve_patterns", "join.max_pending"},
	})
	if err != nil {
		return nil, err
	}

	resultMap, _ := result.(map[string]any)
	settings := groupSettingsToMap(resultMap)

	mode := "open"
	if v, ok := settings["join.mode"].(string); ok {
		mode = v
	}
	question := ""
	if v, ok := settings["join.question"].(string); ok {
		question = v
	}
	patterns := []any{}
	if v, ok := settings["join.auto_approve_patterns"].([]any); ok {
		patterns = v
	}
	maxPending := 100
	if v, ok := settings["join.max_pending"].(float64); ok {
		maxPending = int(v)
	}

	return map[string]any{
		"group_id": resultMap["group_id"],
		"join_requirements": map[string]any{
			"group_id":              resultMap["group_id"],
			"mode":                  mode,
			"question":              question,
			"auto_approve_patterns": patterns,
			"max_pending":           maxPending,
		},
	}, nil
}

func (f *GroupFacade) UpdateJoinRequirements(ctx context.Context, params map[string]any) (any, error) {
	// 便利方法：基于 SetSettings
	groupID, ok := params["group_id"].(string)
	if !ok || groupID == "" {
		return nil, fmt.Errorf("group_id is required")
	}

	settingsUpdate := make(map[string]any)
	if mode, exists := params["mode"]; exists {
		settingsUpdate["join.mode"] = mode
	}
	if question, exists := params["question"]; exists {
		settingsUpdate["join.question"] = question
	}
	if patterns, exists := params["auto_approve_patterns"]; exists {
		settingsUpdate["join.auto_approve_patterns"] = patterns
	}
	if maxPending, exists := params["max_pending"]; exists {
		settingsUpdate["join.max_pending"] = maxPending
	}

	if len(settingsUpdate) == 0 {
		return nil, fmt.Errorf("at least one field to update is required")
	}

	result, err := f.SetSettings(ctx, map[string]any{
		"group_id": groupID,
		"settings": settingsUpdate,
	})
	if err != nil {
		return nil, err
	}

	resultMap, _ := result.(map[string]any)
	return map[string]any{
		"group_id": resultMap["group_id"],
		"join_requirements": map[string]any{
			"group_id":              resultMap["group_id"],
			"mode":                  params["mode"],
			"question":              params["question"],
			"auto_approve_patterns": params["auto_approve_patterns"],
			"max_pending":           params["max_pending"],
		},
	}, nil
}

type StreamFacade struct {
	rpcFacade
}

func newStreamFacade(client StorageRPCClient) *StreamFacade {
	return &StreamFacade{rpcFacade: newRPCFacade(client, "stream")}
}

func (f *StreamFacade) Create(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "create", params)
}

func (f *StreamFacade) Close(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "close", params)
}

func (f *StreamFacade) GetInfo(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "get_info", params)
}

func (f *StreamFacade) ListActive(ctx context.Context, params map[string]any) (any, error) {
	return f.call(ctx, "list_active", params)
}
