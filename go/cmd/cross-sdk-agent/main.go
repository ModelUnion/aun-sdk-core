package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	aun "github.com/modelunion/aun-sdk-core/go"
)

type CrossSdkGoAgent struct {
	language     string
	sdkVersion   string
	aid          string
	issuer       string
	gatewayAid   string
	slotID       string
	aunPath      string
	debug        bool
	client       *aun.AUNClient
	ready        bool
	startupError string
	inbox        []map[string]any
	groupInbox   []map[string]any
	traces       map[string][]map[string]any
	sendResults  map[string]map[string]any
	mu           sync.Mutex
}

func NewCrossSdkGoAgent() *CrossSdkGoAgent {
	issuer := strings.TrimSpace(envString("AUN_TEST_ISSUER", "agentid.pub"))
	if issuer == "" {
		issuer = "agentid.pub"
	}
	aid := strings.TrimSpace(envString("AUN_TEST_AID", "cross-go.agentid.pub"))
	slotID := strings.TrimSpace(envString("AUN_TEST_SLOT_ID", "cross-sdk-go-"+uuid.NewString()[:8]))
	aunPath := strings.TrimSpace(envString("AUN_TEST_AUN_PATH", envString("AUN_DATA_ROOT", "/data/aun")))
	debug := envBool("AUN_TEST_DEBUG", false)
	client := aun.NewAUNClientEmpty()
	agent := &CrossSdkGoAgent{
		language:    "go",
		sdkVersion:  aun.Version,
		aid:         aid,
		issuer:      issuer,
		gatewayAid:  strings.TrimSpace(envString("AUN_GATEWAY_AID", "gateway."+issuer)),
		slotID:      slotID,
		aunPath:     aunPath,
		debug:       debug,
		client:      client,
		inbox:       []map[string]any{},
		groupInbox:  []map[string]any{},
		traces:      map[string][]map[string]any{},
		sendResults: map[string]map[string]any{},
	}
	return agent
}

func (a *CrossSdkGoAgent) Start(ctx context.Context) error {
	a.client.On("message.received", func(payload any) {
		a.storeInboxItem(a.normalizeMessage(payload, true, ""))
	})
	a.client.On("message.undecryptable", func(payload any) {
		a.storeInboxItem(a.normalizeMessage(payload, false, "undecryptable"))
	})
	a.client.On("group.message_created", func(payload any) {
		a.storeGroupInboxItem(a.normalizeGroupMessage(payload, true, ""))
	})
	a.client.On("group.message_undecryptable", func(payload any) {
		a.storeGroupInboxItem(a.normalizeGroupMessage(payload, false, "undecryptable"))
	})
	if err := a.ensureConnected(ctx); err != nil {
		return err
	}
	a.mu.Lock()
	a.ready = true
	a.mu.Unlock()
	return nil
}

func (a *CrossSdkGoAgent) Close() {
	_ = a.client.Close()
}

func (a *CrossSdkGoAgent) ensureConnected(ctx context.Context) error {
	store := aun.NewAIDStore(a.aunPath, "")
	defer store.Close()
	if rr := store.Register(ctx, a.aid); !rr.Ok {
		if lr := store.Load(a.aid); !lr.Ok {
			return fmt.Errorf("register_aid failed and no local identity exists: %s", rr.Error.Message)
		}
	}
	lr := store.Load(a.aid)
	if !lr.Ok {
		return fmt.Errorf("%s: %s", lr.Error.Code, lr.Error.Message)
	}
	if err := a.client.LoadIdentity(lr.Data.AID); err != nil {
		return err
	}
	return a.client.Connect(ctx)
}

func (a *CrossSdkGoAgent) recordTrace(traceID string, item map[string]any) {
	if traceID == "" {
		return
	}
	entry := map[string]any{
		"ts":       time.Now().UnixMilli(),
		"language": a.language,
		"aid":      a.aid,
	}
	for k, v := range item {
		entry[k] = v
	}
	a.mu.Lock()
	a.traces[traceID] = append(a.traces[traceID], entry)
	a.mu.Unlock()
}

func (a *CrossSdkGoAgent) storeInboxItem(item map[string]any) {
	a.mu.Lock()
	a.inbox = append(a.inbox, item)
	if len(a.inbox) > 1000 {
		a.inbox = a.inbox[len(a.inbox)-1000:]
	}
	a.mu.Unlock()
	a.recordTrace(stringValue(item["trace_id"]), map[string]any{"stage": "receive", "message": item})
}

func (a *CrossSdkGoAgent) storeGroupInboxItem(item map[string]any) {
	a.mu.Lock()
	a.groupInbox = append(a.groupInbox, item)
	if len(a.groupInbox) > 1000 {
		a.groupInbox = a.groupInbox[len(a.groupInbox)-1000:]
	}
	a.mu.Unlock()
	a.recordTrace(stringValue(item["trace_id"]), map[string]any{"stage": "group_receive", "message": item})
}

func (a *CrossSdkGoAgent) normalizeMessage(msg any, decrypted bool, errorCode string) map[string]any {
	data := asMap(msg)
	if data == nil {
		data = map[string]any{"raw": msg}
	}
	payload := asMap(data["payload"])
	traceID := firstNonEmpty(stringValue(payload["trace_id"]), stringValue(data["trace_id"]))
	text := firstNonEmpty(stringValue(payload["text"]), stringValue(data["text"]))
	item := map[string]any{
		"trace_id":   traceID,
		"message_id": firstNonEmpty(stringValue(data["message_id"]), stringValue(data["id"])),
		"from":       firstNonEmpty(stringValue(data["from"]), stringValue(data["from_aid"])),
		"to":         firstNonEmpty(stringValue(data["to"]), stringValue(data["to_aid"]), a.aid),
		"text":       text,
		"decrypted":  decrypted,
		"encrypted":  boolValue(data["e2ee"], false) || boolValue(data["encrypted"], false),
		"seq":        intValue(firstNonNil(data["seq"], data["message_seq"])),
		"ack_seq":    intValue(data["ack_seq"]),
		"error_code": errorCode,
		"raw_sha256": sha256JSON(data),
	}
	for key, value := range extractEnvelopeMetadata(data) {
		item[key] = value
	}
	return item
}

func (a *CrossSdkGoAgent) normalizeGroupMessage(msg any, decrypted bool, errorCode string) map[string]any {
	data := asMap(msg)
	if data == nil {
		data = map[string]any{"raw": msg}
	}
	payload := asMap(data["payload"])
	traceID := firstNonEmpty(stringValue(payload["trace_id"]), stringValue(data["trace_id"]))
	text := firstNonEmpty(stringValue(payload["text"]), stringValue(data["text"]))
	item := map[string]any{
		"trace_id":   traceID,
		"group_id":   stringValue(data["group_id"]),
		"message_id": firstNonEmpty(stringValue(data["message_id"]), stringValue(data["id"])),
		"from":       firstNonEmpty(stringValue(data["from"]), stringValue(data["from_aid"]), stringValue(data["sender_aid"])),
		"text":       text,
		"decrypted":  decrypted,
		"encrypted":  boolValue(data["e2ee"], false) || boolValue(data["encrypted"], false),
		"seq":        intValue(firstNonNil(data["seq"], data["message_seq"], data["msg_seq"])),
		"error_code": errorCode,
		"raw_sha256": sha256JSON(data),
	}
	for key, value := range extractEnvelopeMetadata(data) {
		item[key] = value
	}
	return item
}

func extractEnvelopeMetadata(data map[string]any) map[string]any {
	e2ee := objectMap(data["e2ee"])
	protectedHeaders := objectMap(data["protected_headers"])
	if protectedHeaders == nil && e2ee != nil {
		protectedHeaders = objectMap(e2ee["protected_headers"])
	}
	protectedPayloadType := ""
	if protectedHeaders != nil {
		protectedPayloadType = stringValue(protectedHeaders["payload_type"])
	}
	e2eePayloadType := ""
	if e2ee != nil {
		e2eePayloadType = stringValue(e2ee["payload_type"])
	}
	payloadType := strings.TrimSpace(firstNonEmpty(stringValue(data["payload_type"]), protectedPayloadType, e2eePayloadType))
	out := map[string]any{}
	if payloadType != "" {
		out["payload_type"] = payloadType
	}
	if protectedHeaders != nil {
		out["protected_headers"] = jsonSafe(protectedHeaders)
	}
	return out
}

func objectMap(value any) map[string]any {
	if out, ok := value.(map[string]any); ok {
		return out
	}
	return nil
}

func (a *CrossSdkGoAgent) identity() map[string]any {
	identity := a.client.GetIdentity()
	if identity == nil {
		identity = a.client.AuthLoadIdentityOrNil(a.aid)
	}
	return map[string]any{
		"aid":                    a.aid,
		"device_id":              "",
		"slot_id":                a.slotID,
		"issuer":                 a.issuer,
		"public_key_fingerprint": publicKeyFingerprint(firstNonEmpty(stringValue(identity["cert"]), stringValue(identity["cert_pem"]))),
	}
}

func (a *CrossSdkGoAgent) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			writeJSON(res, http.StatusInternalServerError, map[string]any{
				"ok":            false,
				"error_code":    "panic",
				"error_message": fmt.Sprint(recovered),
			})
		}
	}()
	path := req.URL.Path
	switch {
	case req.Method == http.MethodGet && path == "/health":
		a.handleHealth(res)
	case req.Method == http.MethodPost && path == "/reset":
		a.handleReset(res, req)
	case req.Method == http.MethodGet && path == "/identity":
		writeJSON(res, http.StatusOK, a.identity())
	case req.Method == http.MethodPost && path == "/send":
		a.handleSend(res, req)
	case req.Method == http.MethodPost && path == "/ack":
		a.handleAck(res, req)
	case req.Method == http.MethodPost && path == "/pull":
		a.handlePull(res, req)
	case req.Method == http.MethodGet && path == "/inbox":
		a.handleInbox(res, req)
	case req.Method == http.MethodPost && path == "/group/create":
		a.handleGroupCreate(res, req)
	case req.Method == http.MethodPost && path == "/group/call":
		a.handleGroupCall(res, req)
	case req.Method == http.MethodGet && path == "/group/ready":
		a.handleGroupReady(res, req)
	case req.Method == http.MethodPost && path == "/group/send":
		a.handleGroupSend(res, req)
	case req.Method == http.MethodPost && path == "/group/pull":
		a.handleGroupPull(res, req)
	case req.Method == http.MethodPost && path == "/group/ack":
		a.handleGroupAck(res, req)
	case req.Method == http.MethodPost && path == "/group/fs/call":
		a.handleGroupFSCall(res, req)
	case req.Method == http.MethodPost && path == "/collab/call":
		a.handleCollabCall(res, req)
	case req.Method == http.MethodPost && path == "/storage/call":
		a.handleStorageCall(res, req)
	case req.Method == http.MethodGet && path == "/group/inbox":
		a.handleGroupInbox(res, req)
	case req.Method == http.MethodGet && strings.HasPrefix(path, "/traces/"):
		traceID := strings.TrimPrefix(path, "/traces/")
		a.mu.Lock()
		items := append([]map[string]any(nil), a.traces[traceID]...)
		a.mu.Unlock()
		writeJSON(res, http.StatusOK, map[string]any{"trace_id": traceID, "items": items})
	case req.Method == http.MethodGet && path == "/logs":
		writeJSON(res, http.StatusOK, map[string]any{"log_files": logFiles(), "tail": []any{}})
	default:
		writeJSON(res, http.StatusNotFound, map[string]any{"ok": false, "error_code": "not_found", "error_message": path})
	}
}

func (a *CrossSdkGoAgent) handleHealth(res http.ResponseWriter) {
	a.mu.Lock()
	ready := a.ready
	startupError := a.startupError
	a.mu.Unlock()
	status := http.StatusOK
	if startupError != "" {
		status = http.StatusServiceUnavailable
	}
	state := string(a.client.ConnectionState())
	writeJSON(res, status, map[string]any{
		"ok":            startupError == "",
		"agent_ready":   ready && (state == string(aun.ConnStateReady) || state == string(aun.StateConnected)),
		"state":         state,
		"aid":           a.aid,
		"language":      a.language,
		"sdk_version":   a.sdkVersion,
		"gateway_url":   a.client.GetGatewayURL(),
		"startup_error": startupError,
	})
}

func (a *CrossSdkGoAgent) handleReset(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	traceID := stringValue(body["trace_id"])
	a.mu.Lock()
	if traceID != "" {
		a.inbox = filterByTrace(a.inbox, traceID, false)
		a.groupInbox = filterByTrace(a.groupInbox, traceID, false)
		delete(a.traces, traceID)
		delete(a.sendResults, traceID)
	} else {
		a.inbox = []map[string]any{}
		a.groupInbox = []map[string]any{}
		a.traces = map[string][]map[string]any{}
		a.sendResults = map[string]map[string]any{}
	}
	a.mu.Unlock()
	writeJSON(res, http.StatusOK, map[string]any{"ok": true})
}

func (a *CrossSdkGoAgent) handleSend(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	traceID := firstNonEmpty(stringValue(body["trace_id"]), compactUUID())
	messageID := firstNonEmpty(stringValue(body["message_id"]), traceID+"-"+uuid.NewString()[:8])
	target := strings.TrimSpace(stringValue(body["to"]))
	text := stringValue(body["text"])
	e2ee := true
	if raw, ok := body["e2ee"]; ok {
		e2ee = boolValue(raw, true)
	}
	if target == "" {
		writeJSON(res, http.StatusBadRequest, map[string]any{"ok": false, "error_code": "bad_request", "error_message": "to is required"})
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), time.Duration(intValueDefault(body["timeout_ms"], 30000))*time.Millisecond)
	defer cancel()
	payload := map[string]any{
		"type":     "text",
		"text":     text,
		"trace_id": traceID,
		"case_id":  firstNonEmpty(stringValue(body["case_id"]), traceID),
	}
	result, err := a.client.Call(ctx, "message.send", map[string]any{
		"to":         target,
		"payload":    payload,
		"encrypt":    e2ee,
		"message_id": messageID,
	})
	if err != nil {
		out := map[string]any{
			"ok":            false,
			"trace_id":      traceID,
			"message_id":    messageID,
			"encrypted":     e2ee,
			"error_code":    errorCode(err),
			"error_message": err.Error(),
		}
		a.mu.Lock()
		a.sendResults[traceID] = out
		a.mu.Unlock()
		a.recordTrace(traceID, map[string]any{"stage": "send_error", "target": target, "message_id": messageID, "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	resultMap := asMap(result)
	out := map[string]any{
		"ok":         true,
		"trace_id":   traceID,
		"message_id": messageID,
		"seq":        intValue(firstNonNil(resultMap["seq"], resultMap["message_seq"])),
		"encrypted":  e2ee,
		"result":     jsonSafe(result),
	}
	a.mu.Lock()
	a.sendResults[traceID] = out
	a.mu.Unlock()
	a.recordTrace(traceID, map[string]any{"stage": "send", "target": target, "message_id": messageID, "result": out})
	writeJSON(res, http.StatusOK, out)
}

func (a *CrossSdkGoAgent) handleAck(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	seq := intValue(firstNonNil(body["seq"], body["up_to_seq"]))
	params := map[string]any{}
	if seq > 0 {
		params["seq"] = seq
	}
	ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
	defer cancel()
	result, err := a.client.Call(ctx, "message.ack", params)
	if err != nil {
		writeJSON(res, http.StatusInternalServerError, map[string]any{"ok": false, "seq": seq, "error_code": errorCode(err), "error_message": err.Error()})
		return
	}
	writeJSON(res, http.StatusOK, map[string]any{"ok": true, "seq": seq, "result": jsonSafe(result)})
}

func (a *CrossSdkGoAgent) handlePull(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	afterSeq := intValue(body["after_seq"])
	limit := intValueDefault(body["limit"], 50)
	ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
	defer cancel()
	result, err := a.client.Call(ctx, "message.pull", map[string]any{"after_seq": afterSeq, "limit": limit})
	if err != nil {
		writeJSON(res, http.StatusInternalServerError, map[string]any{"ok": false, "error_code": errorCode(err), "error_message": err.Error()})
		return
	}
	for _, msg := range mapList(asMap(result)["messages"]) {
		a.storeInboxItem(a.normalizeMessage(msg, true, ""))
	}
	writeJSON(res, http.StatusOK, map[string]any{"ok": true, "result": jsonSafe(result)})
}

func (a *CrossSdkGoAgent) handleInbox(res http.ResponseWriter, req *http.Request) {
	traceID := stringValue(req.URL.Query().Get("trace_id"))
	fromAID := stringValue(req.URL.Query().Get("from"))
	limit := intValueDefault(req.URL.Query().Get("limit"), 20)
	a.mu.Lock()
	items := append([]map[string]any(nil), a.inbox...)
	a.mu.Unlock()
	items = filterInbox(items, traceID, "", fromAID, limit)
	writeJSON(res, http.StatusOK, map[string]any{"received": len(items) > 0, "items": items})
}

func (a *CrossSdkGoAgent) handleGroupCreate(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	traceID := firstNonEmpty(stringValue(body["trace_id"]), compactUUID())
	name := firstNonEmpty(stringValue(body["name"]), "cross-sdk-"+traceID[:min(8, len(traceID))])
	members := stringList(body["members"])
	params := map[string]any{
		"name":       name,
		"visibility": firstNonEmpty(stringValue(body["visibility"]), "private"),
	}
	groupName := strings.TrimSpace(firstNonEmpty(stringValue(body["group_name"]), stringValue(body["groupName"])))
	if groupName != "" {
		params["group_name"] = groupName
	}
	if joinMode := strings.TrimSpace(stringValue(body["join_mode"])); joinMode != "" {
		params["join_mode"] = joinMode
	}
	ctx, cancel := context.WithTimeout(req.Context(), 35*time.Second)
	defer cancel()
	var createResult any
	var err error
	if groupName != "" {
		createResult, err = a.client.CreateGroup(ctx, params)
	} else {
		createResult, err = a.client.Call(ctx, "group.create", params)
	}
	if err != nil {
		out := map[string]any{"ok": false, "trace_id": traceID, "error_code": errorCode(err), "error_message": err.Error()}
		a.recordTrace(traceID, map[string]any{"stage": "group_create_error", "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	groupID := extractGroupID(createResult)
	if groupID == "" {
		err := fmt.Errorf("group.create did not return group_id: %v", jsonSafe(createResult))
		out := map[string]any{"ok": false, "trace_id": traceID, "error_code": errorCode(err), "error_message": err.Error()}
		a.recordTrace(traceID, map[string]any{"stage": "group_create_error", "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	addResults := []any{}
	for _, member := range members {
		aid := strings.TrimSpace(member)
		if aid == "" || aid == a.aid {
			continue
		}
		addResult, addErr := a.client.Call(ctx, "group.add_member", map[string]any{"group_id": groupID, "aid": aid, "role": "member"})
		if addErr != nil {
			out := map[string]any{"ok": false, "trace_id": traceID, "group_id": groupID, "error_code": errorCode(addErr), "error_message": addErr.Error()}
			a.recordTrace(traceID, map[string]any{"stage": "group_create_error", "error": out})
			writeJSON(res, http.StatusInternalServerError, out)
			return
		}
		addResults = append(addResults, jsonSafe(addResult))
	}
	out := map[string]any{"ok": true, "trace_id": traceID, "group_id": groupID, "group_aid": extractGroupAID(createResult), "create_result": jsonSafe(createResult), "add_results": addResults}
	a.recordTrace(traceID, map[string]any{"stage": "group_create", "group_id": groupID, "result": out})
	writeJSON(res, http.StatusOK, out)
}

func (a *CrossSdkGoAgent) handleCollabCall(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	traceID := firstNonEmpty(stringValue(body["trace_id"]), compactUUID())
	action := strings.TrimSpace(stringValue(body["action"]))
	params := asMap(body["params"])
	if params == nil {
		params = map[string]any{}
	}
	ctx, cancel := context.WithTimeout(req.Context(), 60*time.Second)
	defer cancel()
	result, err := a.callCollabAction(ctx, action, params)
	if err != nil {
		out := map[string]any{"ok": false, "trace_id": traceID, "action": action, "error_code": errorCode(err), "error_message": err.Error()}
		a.recordTrace(traceID, map[string]any{"stage": "collab_call_error", "action": action, "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	out := map[string]any{"ok": true, "trace_id": traceID, "action": action, "result": jsonSafe(result)}
	a.recordTrace(traceID, map[string]any{"stage": "collab_call", "action": action, "result": out})
	writeJSON(res, http.StatusOK, out)
}

func (a *CrossSdkGoAgent) handleStorageCall(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	traceID := firstNonEmpty(stringValue(body["trace_id"]), compactUUID())
	action := strings.TrimSpace(stringValue(body["action"]))
	params := asMap(body["params"])
	if params == nil {
		params = map[string]any{}
	}
	ctx, cancel := context.WithTimeout(req.Context(), 60*time.Second)
	defer cancel()
	result, err := a.callStorageAction(ctx, action, params)
	if err != nil {
		out := map[string]any{"ok": false, "trace_id": traceID, "action": action, "error_code": errorCode(err), "error_message": err.Error()}
		a.recordTrace(traceID, map[string]any{"stage": "storage_call_error", "action": action, "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	out := map[string]any{"ok": true, "trace_id": traceID, "action": action, "result": jsonSafe(result)}
	a.recordTrace(traceID, map[string]any{"stage": "storage_call", "action": action, "result": out})
	writeJSON(res, http.StatusOK, out)
}

func (a *CrossSdkGoAgent) handleGroupCall(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	traceID := firstNonEmpty(stringValue(body["trace_id"]), compactUUID())
	method := strings.TrimSpace(stringValue(body["method"]))
	action := strings.TrimSpace(stringValue(body["action"]))
	if method == "" && action != "" {
		if strings.HasPrefix(action, "group.") {
			method = action
		} else {
			method = "group." + action
		}
	}
	if method == "" {
		writeJSON(res, http.StatusBadRequest, map[string]any{"ok": false, "trace_id": traceID, "error_code": "bad_request", "error_message": "method is required"})
		return
	}
	params := asMap(body["params"])
	if params == nil {
		params = map[string]any{}
	}
	ctx, cancel := context.WithTimeout(req.Context(), 60*time.Second)
	defer cancel()
	result, err := a.client.Call(ctx, method, params)
	if err != nil {
		out := map[string]any{"ok": false, "trace_id": traceID, "method": method, "error_code": errorCode(err), "error_message": err.Error()}
		a.recordTrace(traceID, map[string]any{"stage": "group_call_error", "method": method, "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	out := map[string]any{"ok": true, "trace_id": traceID, "method": method, "result": jsonSafe(result)}
	a.recordTrace(traceID, map[string]any{"stage": "group_call", "method": method, "result": out})
	writeJSON(res, http.StatusOK, out)
}

func (a *CrossSdkGoAgent) handleGroupFSCall(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	traceID := firstNonEmpty(stringValue(body["trace_id"]), compactUUID())
	action := strings.TrimSpace(stringValue(body["action"]))
	params := asMap(body["params"])
	if params == nil {
		params = map[string]any{}
	}
	asGroupAID := strings.TrimSpace(firstNonEmpty(
		stringValue(body["as_group_aid"]),
		stringValue(body["asGroupAid"]),
		stringValue(params["as_group_aid"]),
		stringValue(params["asGroupAid"]),
	))
	delete(params, "as_group_aid")
	delete(params, "asGroupAid")
	ctx, cancel := context.WithTimeout(req.Context(), 60*time.Second)
	defer cancel()
	result, err := a.callGroupFSAction(ctx, action, params, asGroupAID)
	if err != nil {
		out := map[string]any{"ok": false, "trace_id": traceID, "action": action, "error_code": errorCode(err), "error_message": err.Error()}
		a.recordTrace(traceID, map[string]any{"stage": "group_fs_call_error", "action": action, "as_group_aid": asGroupAID, "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	out := map[string]any{"ok": true, "trace_id": traceID, "action": action, "result": jsonSafe(result)}
	a.recordTrace(traceID, map[string]any{"stage": "group_fs_call", "action": action, "as_group_aid": asGroupAID, "result": out})
	writeJSON(res, http.StatusOK, out)
}

func (a *CrossSdkGoAgent) callCollabAction(ctx context.Context, action string, params map[string]any) (any, error) {
	collab := a.client.Collab()
	root := firstNonEmpty(stringValue(params["collab_root"]), stringValue(params["collabRoot"]))
	doc := stringValue(params["doc"])
	source := stringValue(params["source"])
	switch action {
	case "ls":
		return collab.LsFiles(ctx, root)
	case "ls-files":
		return collab.LsFiles(ctx, root)
	case "read":
		return collab.Show(ctx, root, doc, nil)
	case "show":
		rev := optionalInt(firstNonNil(params["rev"]))
		return collab.Show(ctx, root, doc, rev)
	case "submit":
		onto := intValue(firstNonNil(params["onto"], params["base_version"], params["baseVersion"]))
		return collab.Commit(ctx, root, doc, source, onto, stringValue(params["message"]))
	case "commit":
		onto := intValue(firstNonNil(params["onto"], params["base_version"], params["baseVersion"]))
		return collab.Commit(ctx, root, doc, source, onto, stringValue(params["message"]))
	case "history":
		return collab.Log(ctx, root, doc)
	case "log":
		return collab.Log(ctx, root, doc)
	case "get":
		rev := intValue(params["version"])
		return collab.Show(ctx, root, doc, &rev)
	case "export":
		return collab.Clone(ctx, root, stringValue(params["dest"]), false)
	case "adopt":
		return collab.Clone(ctx, stringValue(params["src"]), firstNonEmpty(stringValue(params["new_root"]), stringValue(params["newRoot"])), true)
	case "clone":
		return collab.Clone(ctx, stringValue(params["src"]), stringValue(params["dest"]), boolValue(params["reroot"], false))
	case "revert":
		rev := intValue(firstNonNil(params["rev"], params["version"]))
		return collab.Revert(ctx, root, doc, rev, stringValue(params["message"]))
	case "reset":
		return collab.Revert(ctx, root, doc, intValue(params["version"]), stringValue(params["message"]))
	case "discover":
		return collab.LsRemote(ctx, firstNonEmpty(stringValue(params["group_aid"]), stringValue(params["groupAid"])))
	case "ls-remote":
		return collab.LsRemote(ctx, firstNonEmpty(stringValue(params["group_aid"]), stringValue(params["groupAid"])))
	case "unregister":
		return collab.Unregister(ctx, firstNonEmpty(stringValue(params["group_aid"]), stringValue(params["groupAid"])), root)
	case "set_acl":
		return collab.SetACL(ctx, root, firstNonEmpty(stringValue(params["grantee_aid"]), stringValue(params["granteeAID"])), firstNonEmpty(stringValue(params["perms"]), "w"))
	case "remove_acl":
		return collab.RemoveACL(ctx, root, firstNonEmpty(stringValue(params["grantee_aid"]), stringValue(params["granteeAID"])))
	case "tag.create":
		return collab.Tag().Create(ctx, root, stringValue(params["message"]), boolValue(params["major"], false))
	case "snapshot.create":
		return collab.Tag().Create(ctx, root, stringValue(params["message"]), boolValue(params["major"], false))
	case "tag.list":
		return collab.Tag().List(ctx, root)
	case "snapshot.list":
		return collab.Tag().List(ctx, root)
	case "tag.show":
		return collab.Tag().Show(ctx, root, stringValue(params["version"]))
	case "snapshot.show":
		return collab.Tag().Show(ctx, root, stringValue(params["version"]))
	case "tag.diff":
		return collab.Tag().Diff(ctx, root, firstNonEmpty(stringValue(params["version_a"]), stringValue(params["versionA"])), firstNonEmpty(stringValue(params["version_b"]), stringValue(params["versionB"])))
	case "snapshot.diff":
		return collab.Tag().Diff(ctx, root, firstNonEmpty(stringValue(params["version_a"]), stringValue(params["versionA"])), firstNonEmpty(stringValue(params["version_b"]), stringValue(params["versionB"])))
	case "tag.restore":
		return collab.Tag().Restore(ctx, root, stringValue(params["version"]), stringValue(params["message"]))
	case "snapshot.restore":
		return collab.Tag().Restore(ctx, root, stringValue(params["version"]), stringValue(params["message"]))
	case "tag.rm":
		return collab.Tag().Rm(ctx, root, stringValue(params["version"]))
	case "snapshot.rm":
		return collab.Tag().Rm(ctx, root, stringValue(params["version"]))
	case "tag.prune":
		before := firstNonNil(params["before"])
		keepLast := optionalInt(firstNonNil(params["keep_last"], params["keepLast"]))
		return collab.Tag().Prune(ctx, root, before, keepLast)
	case "snapshot.prune":
		before := firstNonNil(params["before"])
		keepLast := optionalInt(firstNonNil(params["keep_last"], params["keepLast"]))
		return collab.Tag().Prune(ctx, root, before, keepLast)
	case "create":
		return collab.Create(ctx, root, doc, source)
	case "merge":
		onto := intValue(firstNonNil(params["onto"], params["base_version"], params["baseVersion"]))
		return collab.Merge(ctx, root, doc, source, onto)
	case "diff":
		return collab.Diff(ctx, root, doc, intValue(params["from"]), intValue(params["to"]))
	case "prune":
		return collab.Prune(ctx, root, doc)
	case "gc":
		dryRun := true
		if params["dry_run"] != nil {
			dryRun = boolValue(params["dry_run"], true)
		} else if params["dryRun"] != nil {
			dryRun = boolValue(params["dryRun"], true)
		}
		return collab.GC(ctx, root, dryRun)
	case "reflog":
		limit := intValue(params["limit"])
		if limit <= 0 {
			limit = 100
		}
		return collab.Reflog(ctx, root, doc, limit)
	default:
		return nil, fmt.Errorf("unsupported collab action: %s", action)
	}
}

func (a *CrossSdkGoAgent) callGroupFSAction(ctx context.Context, action string, params map[string]any, asGroupAID string) (any, error) {
	fs := a.client.Group().FS()
	pathValue := strings.TrimSpace(stringValue(params["path"]))
	var signingStore *aun.AIDStore
	if strings.TrimSpace(asGroupAID) != "" {
		signingStore = a.aidStore()
		defer signingStore.Close()
	}
	switch action {
	case "ls":
		return fs.Ls(ctx, pathValue, &aun.GroupFSListOptions{
			Page:      intValue(params["page"]),
			Size:      intValue(params["size"]),
			Marker:    stringValue(params["marker"]),
			Token:     stringValue(params["token"]),
			Long:      boolValue(params["long"], false),
			Recursive: boolValue(params["recursive"], false),
			SignAs:    asGroupAID,
			AidStore:  signingStore,
			Extra:     params,
		})
	case "find":
		return fs.Find(ctx, pathValue, &aun.GroupFSFindOptions{
			Pattern:  stringValue(params["pattern"]),
			Name:     stringValue(params["name"]),
			NodeType: firstNonEmpty(stringValue(params["type"]), stringValue(params["node_type"]), stringValue(params["nodeType"])),
			Size:     stringValue(params["size"]),
			MTime:    firstNonEmpty(stringValue(params["mtime"]), stringValue(params["m_time"]), stringValue(params["mTime"])),
			Page:     intValue(params["page"]),
			PageSize: intValue(firstNonNil(params["page_size"], params["pageSize"])),
			Token:    stringValue(params["token"]),
			SignAs:   asGroupAID,
			AidStore: signingStore,
			Extra:    params,
		})
	case "stat":
		return fs.Stat(ctx, pathValue, &aun.GroupFSStatOptions{Token: stringValue(params["token"]), SignAs: asGroupAID, AidStore: signingStore, Extra: params})
	case "lstat":
		return fs.Lstat(ctx, pathValue, &aun.GroupFSStatOptions{Token: stringValue(params["token"]), SignAs: asGroupAID, AidStore: signingStore, Extra: params})
	case "mkdir":
		return fs.Mkdir(ctx, pathValue, &aun.GroupFSMkdirOptions{Parents: boolValue(params["parents"], false), SignAs: asGroupAID, AidStore: signingStore, Extra: params})
	case "set_acl":
		return fs.SetACL(ctx, pathValue, &aun.GroupFSAclOptions{
			GranteeAID: firstNonEmpty(stringValue(params["grantee_aid"]), stringValue(params["granteeAid"]), "role:admin"),
			Perms:      firstNonEmpty(stringValue(params["perms"]), "rwx"),
			SignAs:     asGroupAID,
			AidStore:   signingStore,
			Extra:      params,
		})
	case "remove_acl":
		return fs.RemoveACL(ctx, pathValue, &aun.GroupFSAclOptions{
			GranteeAID: firstNonEmpty(stringValue(params["grantee_aid"]), stringValue(params["granteeAid"]), "role:admin"),
			SignAs:     asGroupAID,
			AidStore:   signingStore,
			Extra:      params,
		})
	case "get_acl":
		return fs.GetACL(ctx, pathValue, &aun.GroupFSAclOptions{SignAs: asGroupAID, AidStore: signingStore, Extra: params})
	case "list_acl":
		return fs.ListACL(ctx, pathValue, &aun.GroupFSAclOptions{SignAs: asGroupAID, AidStore: signingStore, Extra: params})
	case "rm":
		return fs.Rm(ctx, pathValue, &aun.GroupFSRmOptions{
			Recursive: boolValue(params["recursive"], false),
			Force:     boolValue(params["force"], false),
			SignAs:    asGroupAID,
			AidStore:  signingStore,
			Extra:     params,
		})
	case "cp":
		src := stringValue(params["src"])
		dst := stringValue(params["dst"])
		cpExtra := copyMap(params)
		delete(cpExtra, "src")
		delete(cpExtra, "dst")
		delete(cpExtra, "src_text")
		delete(cpExtra, "dst_text")
		if params["src_text"] != nil {
			path, err := writeTempText(stringValue(params["src_text"]), ".txt")
			if err != nil {
				return nil, err
			}
			src = path
		}
		var parentsSet *bool
		if rawParents, ok := params["parents"]; ok && rawParents != nil {
			value := boolValue(rawParents, true)
			parentsSet = &value
		}
		result, err := fs.Cp(ctx, src, dst, &aun.GroupFSCpOptions{
			Force:      boolValue(params["force"], false),
			Recursive:  boolValue(params["recursive"], false),
			Parents:    boolValue(params["parents"], true),
			ParentsSet: parentsSet,
			GroupID:    stringValue(params["group_id"]),
			SrcGroupID: stringValue(params["src_group_id"]),
			DstGroupID: stringValue(params["dst_group_id"]),
			SignAs:     asGroupAID,
			AidStore:   signingStore,
			Extra:      cpExtra,
		})
		if err != nil {
			return nil, err
		}
		return groupFSCpResponse(result, dst), nil
	case "mv":
		mvExtra := copyMap(params)
		delete(mvExtra, "src")
		delete(mvExtra, "dst")
		return fs.Mv(ctx, stringValue(params["src"]), stringValue(params["dst"]), &aun.GroupFSMvOptions{
			Force:      boolValue(params["force"], false),
			GroupID:    stringValue(params["group_id"]),
			SrcGroupID: stringValue(params["src_group_id"]),
			DstGroupID: stringValue(params["dst_group_id"]),
			SignAs:     asGroupAID,
			AidStore:   signingStore,
			Extra:      mvExtra,
		})
	case "df":
		return fs.Df(ctx, pathValue, &aun.GroupFSDfOptions{
			GroupID:  stringValue(params["group_id"]),
			Bucket:   stringValue(params["bucket"]),
			SignAs:   asGroupAID,
			AidStore: signingStore,
			Extra:    params,
		})
	case "mount":
		readonly := optionalBool(params["readonly"])
		return fs.Mount(ctx, pathValue, &aun.GroupFSMountOptions{
			Readonly:        readonly,
			RequireApproval: boolValue(firstNonNil(params["require_approval"], params["requireApproval"]), false),
			SourceBucket:    stringValue(params["source_bucket"]),
			ExpiresAt:       optionalInt64(params["expires_at"]),
			VolumeID:        stringValue(params["volume_id"]),
			SignAs:          asGroupAID,
			AidStore:        signingStore,
			Extra:           params,
		})
	case "umount":
		return fs.Umount(ctx, pathValue, &aun.GroupFSUmountOptions{SignAs: asGroupAID, AidStore: signingStore, Extra: params})
	case "raw":
		rawParams := copyMap(params)
		method := stringValue(rawParams["method"])
		delete(rawParams, "method")
		return a.rawGroupFSCall(ctx, method, rawParams, asGroupAID, signingStore)
	case "check_upload":
		return a.rawGroupFSCall(ctx, "group.fs.check_upload", params, asGroupAID, signingStore)
	case "create_upload_session":
		return a.rawGroupFSCall(ctx, "group.fs.create_upload_session", params, asGroupAID, signingStore)
	case "complete_upload":
		return a.rawGroupFSCall(ctx, "group.fs.complete_upload", params, asGroupAID, signingStore)
	case "create_download_ticket":
		return a.rawGroupFSCall(ctx, "group.fs.create_download_ticket", params, asGroupAID, signingStore)
	default:
		return nil, fmt.Errorf("unsupported group fs action: %s", action)
	}
}

func (a *CrossSdkGoAgent) rawGroupFSCall(ctx context.Context, method string, params map[string]any, asGroupAID string, signingStore *aun.AIDStore) (any, error) {
	if strings.TrimSpace(method) == "" {
		return nil, fmt.Errorf("raw group fs action requires method")
	}
	payload := copyMap(params)
	if strings.TrimSpace(asGroupAID) != "" {
		if signingStore == nil {
			return nil, fmt.Errorf("group fs signing store is not initialized")
		}
		loaded := signingStore.Load(asGroupAID)
		if !loaded.Ok || loaded.Data.AID == nil {
			message := fmt.Sprintf("signer identity not found: %s", asGroupAID)
			if loaded.Error != nil && strings.TrimSpace(loaded.Error.Message) != "" {
				message = loaded.Error.Message
			}
			return nil, fmt.Errorf("%s", message)
		}
		if !loaded.Data.AID.IsPrivateKeyValid() || strings.TrimSpace(loaded.Data.AID.PrivateKeyPem) == "" {
			return nil, fmt.Errorf("signer identity missing private key: %s", asGroupAID)
		}
		payload["_client_signature_identity"] = loaded.Data.AID
	}
	return a.client.Call(ctx, method, payload)
}

func (a *CrossSdkGoAgent) callStorageAction(ctx context.Context, action string, params map[string]any) (any, error) {
	storage := a.client.Storage()
	low := aun.NewStorageLowLevel(a.client)
	path := strings.TrimSpace(stringValue(params["path"]))
	owner := strings.TrimSpace(firstNonEmpty(stringValue(params["owner_aid"]), stringValue(params["ownerAID"])))
	bucket := strings.TrimSpace(stringValue(params["bucket"]))
	if bucket == "" {
		bucket = "default"
	}
	token := strings.TrimSpace(stringValue(params["token"]))
	src := strings.TrimSpace(stringValue(params["src"]))
	dst := strings.TrimSpace(stringValue(params["dst"]))
	objectKey := strings.TrimLeft(firstNonEmpty(stringValue(params["object_key"]), stringValue(params["objectKey"]), path), "/")
	switch action {
	case "write_bytes":
		contentText := stringValue(params["content"])
		data := []byte(contentText)
		if boolValue(firstNonNil(params["content_base64"], params["contentBase64"]), false) {
			decoded, err := base64.StdEncoding.DecodeString(contentText)
			if err != nil {
				return nil, err
			}
			data = decoded
		}
		overwrite := boolValue(params["overwrite"], false)
		return storage.WriteBytes(ctx, path, data, &aun.WriteBytesOptions{
			Owner:       owner,
			Bucket:      bucket,
			ContentType: firstNonEmpty(stringValue(params["content_type"]), stringValue(params["contentType"]), "text/plain"),
			Public:      boolValue(params["public"], false),
			Overwrite:   &overwrite,
		})
	case "read_bytes":
		data, err := storage.ReadBytes(ctx, path, &aun.ReadOptions{Owner: owner, Bucket: bucket, Token: token})
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"content":        string(data),
			"content_base64": base64.StdEncoding.EncodeToString(data),
			"size_bytes":     len(data),
		}, nil
	case "create_download_ticket":
		return low.CreateDownloadTicket(ctx, owner, bucket, objectKey, token)
	case "download_text":
		url := strings.TrimSpace(firstNonEmpty(stringValue(params["url"]), stringValue(params["download_url"]), stringValue(params["downloadUrl"])))
		if url == "" {
			return nil, fmt.Errorf("download_text requires url")
		}
		content, err := downloadText(ctx, url, a.accessToken())
		if err != nil {
			return nil, err
		}
		return map[string]any{"content": content}, nil
	case "set_acl":
		return storage.SetACL(ctx, path, aun.SetACLOptions{
			Owner:      owner,
			Bucket:     bucket,
			GranteeAID: strings.TrimSpace(firstNonEmpty(stringValue(params["grantee_aid"]), stringValue(params["granteeAID"]))),
			Perms:      strings.TrimSpace(stringValue(params["perms"])),
			ExpiresAt:  optionalInt64(firstNonNil(params["expires_at"], params["expiresAt"])),
			MaxUses:    optionalInt(firstNonNil(params["max_uses"], params["maxUses"])),
		})
	case "remove_acl":
		return storage.RemoveACL(ctx, path, aun.RemoveACLOptions{
			Owner:      owner,
			Bucket:     bucket,
			GranteeAID: strings.TrimSpace(firstNonEmpty(stringValue(params["grantee_aid"]), stringValue(params["granteeAID"]))),
		})
	case "list":
		return storage.List(ctx, path, &aun.ListOptions{
			Owner:     owner,
			Bucket:    bucket,
			Page:      intValueDefault(params["page"], 1),
			Size:      intValueDefault(params["size"], 100),
			Marker:    stringValue(params["marker"]),
			Long:      boolValue(params["long"], false),
			Recursive: boolValue(params["recursive"], false),
			Token:     token,
		})
	case "find":
		return storage.Find(ctx, path, &aun.FindOptions{
			Owner:    owner,
			Bucket:   bucket,
			Name:     stringValue(params["name"]),
			NodeType: firstNonEmpty(stringValue(params["node_type"]), stringValue(params["nodeType"])),
			Size:     firstNonEmpty(stringValue(params["size_expr"]), stringValue(params["sizeExpr"])),
			MTime:    stringValue(params["mtime"]),
			Page:     intValueDefault(params["page"], 1),
			PageSize: intValueDefault(firstNonNil(params["page_size"], params["pageSize"]), 1000),
			Token:    token,
		})
	case "stat":
		return storage.Stat(ctx, path, &aun.StatOptions{Owner: owner, Bucket: bucket, Token: token})
	case "lstat":
		return storage.Lstat(ctx, path, &aun.StatOptions{Owner: owner, Bucket: bucket, Token: token})
	case "mkdir":
		return storage.Mkdir(ctx, path, &aun.MkdirOptions{Owner: owner, Bucket: bucket, Parents: boolValue(params["parents"], false)})
	case "touch":
		return storage.Touch(ctx, path, &aun.TouchOptions{
			Owner:          owner,
			Bucket:         bucket,
			Parents:        boolValue(params["parents"], false),
			NoCreate:       boolValue(firstNonNil(params["no_create"], params["noCreate"]), false),
			MTime:          optionalInt64(params["mtime"]),
			FollowSymlinks: boolValue(firstNonNil(params["follow_symlinks"], params["followSymlinks"]), false),
		})
	case "remove":
		return storage.Remove(ctx, path, &aun.RemoveOptions{Owner: owner, Bucket: bucket, Recursive: boolValue(params["recursive"], false)})
	case "rename":
		return storage.Rename(ctx, src, dst, &aun.RenameOptions{
			Owner:           owner,
			Bucket:          bucket,
			Overwrite:       boolValue(params["overwrite"], false),
			ExpectedVersion: optionalInt(firstNonNil(params["expected_version"], params["expectedVersion"])),
		})
	case "copy":
		return storage.Copy(ctx, src, dst, &aun.CopyOptions{
			Owner:          owner,
			Bucket:         bucket,
			DstOwner:       firstNonEmpty(stringValue(params["dst_owner_aid"]), stringValue(params["dstOwnerAID"]), stringValue(params["dstOwner"])),
			DstBucket:      firstNonEmpty(stringValue(params["dst_bucket"]), stringValue(params["dstBucket"])),
			Overwrite:      boolValue(params["overwrite"], false),
			FollowSymlinks: boolValue(firstNonNil(params["follow_symlinks"], params["followSymlinks"]), false),
			Recursive:      boolValue(params["recursive"], false),
		})
	case "df":
		return storage.DF(ctx, &aun.UsageOptions{Owner: owner, Bucket: bucket})
	case "du":
		return storage.Du(ctx, path, &aun.DuOptions{
			Owner:    owner,
			Bucket:   bucket,
			MaxDepth: optionalInt(firstNonNil(params["max_depth"], params["maxDepth"])),
			PageSize: intValueDefault(firstNonNil(params["page_size"], params["pageSize"]), 1000),
			Token:    token,
		})
	case "symlink":
		return storage.Symlink(ctx, stringValue(params["target"]), path, &aun.SymlinkOptions{
			Owner:     owner,
			Bucket:    bucket,
			Overwrite: boolValue(params["overwrite"], false),
		})
	case "readlink":
		return storage.Readlink(ctx, path, &aun.ReadlinkOptions{Owner: owner, Bucket: bucket})
	case "repoint":
		return storage.Repoint(ctx, path, firstNonEmpty(stringValue(params["new_target"]), stringValue(params["newTarget"])), &aun.RepointOptions{
			Owner:           owner,
			Bucket:          bucket,
			ExpectedVersion: optionalInt(firstNonNil(params["expected_version"], params["expectedVersion"])),
		})
	case "rename_symlink":
		return storage.RenameSymlink(ctx, src, dst, &aun.RenameSymlinkOptions{
			Owner:           owner,
			Bucket:          bucket,
			Overwrite:       boolValue(params["overwrite"], false),
			ExpectedVersion: optionalInt(firstNonNil(params["expected_version"], params["expectedVersion"])),
		})
	case "delete_symlink":
		return low.DeleteSymlink(ctx, owner, bucket, objectKey)
	case "list_acl":
		return storage.ListACL(ctx, path, &aun.UsageOptions{Owner: owner, Bucket: bucket})
	case "check_access":
		follow := boolValue(firstNonNil(params["follow_symlinks"], params["followSymlinks"]), true)
		return storage.CheckAccess(ctx, path, &aun.CheckAccessOptions{
			Owner:          owner,
			Bucket:         bucket,
			Operation:      firstNonEmpty(stringValue(params["operation"]), "read"),
			Token:          token,
			FollowSymlinks: &follow,
		})
	case "issue_token":
		return storage.IssueToken(ctx, path, aun.IssueTokenOptions{
			Owner:     owner,
			Bucket:    bucket,
			ExpiresAt: optionalInt64(firstNonNil(params["expires_at"], params["expiresAt"])),
			MaxReads:  optionalInt(firstNonNil(params["max_reads"], params["maxReads"])),
		})
	case "revoke_token":
		return storage.RevokeToken(ctx, path, aun.RevokeTokenOptions{Owner: owner, Bucket: bucket, Token: token})
	case "list_tokens":
		return storage.ListTokens(ctx, path, &aun.UsageOptions{Owner: owner, Bucket: bucket})
	case "set_visibility":
		return storage.SetVisibility(ctx, path, aun.VisibilityOptions{
			Owner:      owner,
			Bucket:     bucket,
			Visibility: firstNonEmpty(stringValue(params["visibility"]), "private"),
			AllowRoles: stringList(firstNonNil(params["allow_roles"], params["allowRoles"])),
		})
	case "create_share_link":
		return low.CreateShareLink(
			ctx,
			owner,
			bucket,
			objectKey,
			stringList(firstNonNil(params["allowed_aids"], params["allowedAids"])),
			optionalInt(firstNonNil(params["expire_in_seconds"], params["expireInSeconds"])),
			optionalInt(firstNonNil(params["max_uses"], params["maxUses"])),
		)
	case "list_share_links":
		return low.ListShareLinks(ctx, owner, bucket, objectKey)
	case "revoke_share_link":
		return low.RevokeShareLink(ctx, firstNonEmpty(stringValue(params["share_id"]), stringValue(params["shareId"])))
	case "get_by_share":
		result, err := low.GetByShare(ctx, firstNonEmpty(stringValue(params["share_id"]), stringValue(params["shareId"])))
		if err != nil {
			return nil, err
		}
		if content := stringValue(result["content"]); content != "" {
			if decoded, err := base64.StdEncoding.DecodeString(content); err == nil {
				result["content_text"] = string(decoded)
				result["content_base64"] = base64.StdEncoding.EncodeToString(decoded)
			}
		}
		return result, nil
	case "head_object":
		return low.HeadObject(ctx, owner, bucket, objectKey, token)
	case "list_objects":
		return low.ListObjects(
			ctx,
			owner,
			bucket,
			stringValue(params["prefix"]),
			intValueDefault(params["page"], 1),
			intValueDefault(params["size"], 100),
			stringValue(params["marker"]),
		)
	case "list_prefixes":
		return low.ListPrefixes(ctx, owner, bucket, stringValue(params["prefix"]), intValueDefault(params["size"], 100))
	case "delete_object":
		return low.DeleteObject(ctx, owner, bucket, objectKey)
	case "set_object_meta":
		return low.SetObjectMeta(
			ctx,
			owner,
			bucket,
			objectKey,
			asMapOrEmpty(params["metadata"]),
			firstNonEmpty(stringValue(params["content_type"]), stringValue(params["contentType"])),
			boolValue(params["merge"], true),
			optionalInt(firstNonNil(params["expected_version"], params["expectedVersion"])),
		)
	case "append_object":
		contentText := stringValue(params["content"])
		data := []byte(contentText)
		if boolValue(firstNonNil(params["content_base64"], params["contentBase64"]), false) {
			decoded, err := base64.StdEncoding.DecodeString(contentText)
			if err != nil {
				return nil, err
			}
			data = decoded
		}
		return low.AppendObject(ctx, aun.AppendObjectOptions{
			Owner:           owner,
			Bucket:          bucket,
			ObjectKey:       objectKey,
			Content:         data,
			ContentType:     firstNonEmpty(stringValue(params["content_type"]), stringValue(params["contentType"])),
			Metadata:        asMapOrEmpty(params["metadata"]),
			ExpectedVersion: optionalInt(firstNonNil(params["expected_version"], params["expectedVersion"])),
			IsPublic:        boolValue(firstNonNil(params["public"], params["isPublic"]), false),
		})
	case "create_folder":
		return low.CreateFolder(ctx, owner, bucket, objectKey, boolValue(firstNonNil(params["parents"], params["mkdirs"]), false))
	case "list_children":
		return low.ListChildren(ctx, aun.ListChildrenOptions{
			Owner:           owner,
			Bucket:          bucket,
			Path:            objectKey,
			NodeType:        firstNonEmpty(stringValue(params["node_type"]), stringValue(params["nodeType"]), stringValue(params["type"])),
			Page:            intValueDefault(params["page"], 1),
			Size:            intValueDefault(params["size"], 50),
			OrderBy:         firstNonEmpty(stringValue(params["order_by"]), stringValue(params["orderBy"])),
			Order:           stringValue(params["order"]),
			IncludeMetadata: optionalBool(firstNonNil(params["include_metadata"], params["includeMetadata"])),
			IncludeURLs:     optionalBool(firstNonNil(params["include_urls"], params["includeUrls"])),
		})
	case "copy_object":
		return low.CopyObject(ctx, aun.CopyObjectOptions{
			Owner:     owner,
			Bucket:    bucket,
			SrcPath:   strings.TrimLeft(firstNonEmpty(stringValue(params["src_path"]), stringValue(params["srcPath"]), src), "/"),
			DstPath:   strings.TrimLeft(firstNonEmpty(stringValue(params["dst_path"]), stringValue(params["dstPath"]), dst), "/"),
			Overwrite: boolValue(params["overwrite"], false),
		})
	case "move_object":
		return low.MoveObject(ctx, aun.MoveObjectOptions{
			Owner:           owner,
			Bucket:          bucket,
			Path:            strings.TrimLeft(firstNonEmpty(stringValue(params["src_path"]), stringValue(params["srcPath"]), src, objectKey), "/"),
			DstParentPath:   strings.Trim(strings.TrimLeft(firstNonEmpty(stringValue(params["dst_parent_path"]), stringValue(params["dstParentPath"])), "/"), "/"),
			NewName:         firstNonEmpty(stringValue(params["new_name"]), stringValue(params["newName"])),
			Overwrite:       boolValue(params["overwrite"], false),
			ExpectedVersion: optionalInt(firstNonNil(params["expected_version"], params["expectedVersion"])),
		})
	case "batch_delete":
		return low.BatchDelete(ctx, owner, bucket, mapItems(params["items"]), boolValue(params["recursive"], false))
	default:
		return nil, fmt.Errorf("unsupported storage action: %s", action)
	}
}

func (a *CrossSdkGoAgent) accessToken() string {
	if a == nil || a.client == nil {
		return ""
	}
	identity := a.client.GetIdentity()
	if identity == nil {
		identity = a.client.AuthLoadIdentityOrNil(a.aid)
	}
	return strings.TrimSpace(stringValue(identity["access_token"]))
}

func (a *CrossSdkGoAgent) handleGroupReady(res http.ResponseWriter, req *http.Request) {
	groupID := strings.TrimSpace(req.URL.Query().Get("group_id"))
	expected := splitCSV(req.URL.Query().Get("members"))
	if len(expected) == 0 {
		expected = []string{a.aid}
	}
	if groupID == "" {
		writeJSON(res, http.StatusBadRequest, map[string]any{"ok": false, "ready": false, "error_code": "bad_request", "error_message": "group_id is required"})
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
	defer cancel()
	raw, err := a.client.Call(ctx, "group.v2.bootstrap", map[string]any{"group_id": groupID})
	if err != nil {
		writeJSON(res, http.StatusInternalServerError, map[string]any{"ok": false, "ready": false, "error_code": errorCode(err), "error_message": err.Error()})
		return
	}
	bootstrap := asMap(raw)
	committed := stringSet(firstNonNil(bootstrap["committed_member_aids"], bootstrap["member_aids"]))
	deviceAIDs := map[string]bool{}
	for _, device := range mapList(bootstrap["devices"]) {
		if aid := stringValue(device["aid"]); aid != "" {
			deviceAIDs[aid] = true
		}
	}
	membershipOK := allInSet(expected, committed)
	devicesOK := !envBool("CROSS_SDK_GROUP_READY_REQUIRE_DEVICES", true) || allInSet(expected, deviceAIDs)
	writeJSON(res, http.StatusOK, map[string]any{
		"ok":                    true,
		"ready":                 membershipOK && devicesOK,
		"group_id":              groupID,
		"expected":              expected,
		"committed_member_aids": sortedKeys(committed),
		"device_aids":           sortedKeys(deviceAIDs),
		"pending_adds":          jsonSafe(bootstrap["pending_adds"]),
		"bootstrap":             jsonSafe(bootstrap),
	})
}

func (a *CrossSdkGoAgent) handleGroupSend(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	traceID := firstNonEmpty(stringValue(body["trace_id"]), compactUUID())
	messageID := firstNonEmpty(stringValue(body["message_id"]), traceID+"-"+uuid.NewString()[:8])
	groupID := strings.TrimSpace(stringValue(body["group_id"]))
	text := stringValue(body["text"])
	e2ee := true
	if raw, ok := body["e2ee"]; ok {
		e2ee = boolValue(raw, true)
	}
	if groupID == "" {
		writeJSON(res, http.StatusBadRequest, map[string]any{"ok": false, "error_code": "bad_request", "error_message": "group_id is required"})
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), time.Duration(intValueDefault(body["timeout_ms"], 30000))*time.Millisecond)
	defer cancel()
	payload := map[string]any{
		"type":     "text",
		"text":     text,
		"trace_id": traceID,
		"case_id":  firstNonEmpty(stringValue(body["case_id"]), traceID),
	}
	result, err := a.client.Call(ctx, "group.send", map[string]any{
		"group_id":   groupID,
		"payload":    payload,
		"encrypt":    e2ee,
		"message_id": messageID,
	})
	if err != nil {
		out := map[string]any{"ok": false, "trace_id": traceID, "group_id": groupID, "message_id": messageID, "encrypted": e2ee, "error_code": errorCode(err), "error_message": err.Error()}
		a.recordTrace(traceID, map[string]any{"stage": "group_send_error", "group_id": groupID, "message_id": messageID, "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	resultMap := asMap(result)
	out := map[string]any{
		"ok":         true,
		"trace_id":   traceID,
		"group_id":   groupID,
		"message_id": messageID,
		"seq":        intValue(firstNonNil(resultMap["seq"], resultMap["message_seq"])),
		"encrypted":  e2ee,
		"result":     jsonSafe(result),
	}
	a.recordTrace(traceID, map[string]any{"stage": "group_send", "group_id": groupID, "message_id": messageID, "result": out})
	writeJSON(res, http.StatusOK, out)
}

func (a *CrossSdkGoAgent) handleGroupPull(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	groupID := strings.TrimSpace(stringValue(body["group_id"]))
	afterSeq := intValue(body["after_seq"])
	limit := intValueDefault(body["limit"], 50)
	if groupID == "" {
		writeJSON(res, http.StatusBadRequest, map[string]any{"ok": false, "error_code": "bad_request", "error_message": "group_id is required"})
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
	defer cancel()
	result, err := a.client.Call(ctx, "group.pull", map[string]any{"group_id": groupID, "after_seq": afterSeq, "limit": limit})
	if err != nil {
		writeJSON(res, http.StatusInternalServerError, map[string]any{"ok": false, "group_id": groupID, "error_code": errorCode(err), "error_message": err.Error()})
		return
	}
	for _, msg := range mapList(asMap(result)["messages"]) {
		a.storeGroupInboxItem(a.normalizeGroupMessage(msg, true, ""))
	}
	writeJSON(res, http.StatusOK, map[string]any{"ok": true, "group_id": groupID, "result": jsonSafe(result)})
}

func (a *CrossSdkGoAgent) handleGroupAck(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	groupID := strings.TrimSpace(stringValue(body["group_id"]))
	seq := intValue(firstNonNil(body["seq"], body["msg_seq"], body["up_to_seq"]))
	if groupID == "" {
		writeJSON(res, http.StatusBadRequest, map[string]any{"ok": false, "error_code": "bad_request", "error_message": "group_id is required"})
		return
	}
	params := map[string]any{"group_id": groupID}
	if seq > 0 {
		params["msg_seq"] = seq
		params["up_to_seq"] = seq
	}
	ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
	defer cancel()
	result, err := a.client.Call(ctx, "group.ack_messages", params)
	if err != nil {
		writeJSON(res, http.StatusInternalServerError, map[string]any{"ok": false, "group_id": groupID, "seq": seq, "error_code": errorCode(err), "error_message": err.Error()})
		return
	}
	writeJSON(res, http.StatusOK, map[string]any{"ok": true, "group_id": groupID, "seq": seq, "result": jsonSafe(result)})
}

func (a *CrossSdkGoAgent) handleGroupInbox(res http.ResponseWriter, req *http.Request) {
	traceID := stringValue(req.URL.Query().Get("trace_id"))
	groupID := stringValue(req.URL.Query().Get("group_id"))
	fromAID := stringValue(req.URL.Query().Get("from"))
	limit := intValueDefault(req.URL.Query().Get("limit"), 20)
	a.mu.Lock()
	items := append([]map[string]any(nil), a.groupInbox...)
	a.mu.Unlock()
	items = filterInbox(items, traceID, groupID, fromAID, limit)
	writeJSON(res, http.StatusOK, map[string]any{"received": len(items) > 0, "items": items})
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	agent := NewCrossSdkGoAgent()
	go func() {
		startCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		if err := agent.Start(startCtx); err != nil {
			agent.mu.Lock()
			agent.startupError = fmt.Sprintf("%T: %v", err, err)
			agent.mu.Unlock()
			fmt.Fprintln(os.Stderr, agent.startupError)
		}
	}()
	host := envString("AUN_CONTROL_HOST", "0.0.0.0")
	port := envString("AUN_CONTROL_PORT", "9001")
	server := &http.Server{
		Addr:              host + ":" + port,
		Handler:           agent,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		fmt.Printf("cross-sdk go agent listening on %s:%s\n", host, port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	agent.Close()
}

func envString(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func readJSON(req *http.Request) map[string]any {
	defer req.Body.Close()
	decoder := json.NewDecoder(req.Body)
	decoder.UseNumber()
	var out map[string]any
	if err := decoder.Decode(&out); err != nil || out == nil {
		return map[string]any{}
	}
	return out
}

func writeJSON(res http.ResponseWriter, status int, data map[string]any) {
	body, err := json.Marshal(jsonSafe(data))
	if err != nil {
		body = []byte(`{"ok":false,"error_code":"json_error"}`)
		status = http.StatusInternalServerError
	}
	res.Header().Set("content-type", "application/json; charset=utf-8")
	res.WriteHeader(status)
	_, _ = res.Write(body)
}

func jsonSafe(value any) any {
	if _, err := json.Marshal(value); err == nil {
		return value
	}
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, item := range v {
			out[key] = jsonSafe(item)
		}
		return out
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, jsonSafe(item))
		}
		return out
	default:
		return fmt.Sprint(value)
	}
}

func asMap(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if out, ok := value.(map[string]any); ok {
		return out
	}
	return nil
}

func mapList(value any) []map[string]any {
	switch v := value.(type) {
	case []map[string]any:
		return v
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, item := range v {
			if m := asMap(item); m != nil {
				out = append(out, m)
			}
		}
		return out
	default:
		return []map[string]any{}
	}
}

func pendingOpsLen(value any) int {
	switch v := value.(type) {
	case []any:
		return len(v)
	case []map[string]any:
		return len(v)
	default:
		return 0
	}
}

func stringValue(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case json.Number:
		return v.String()
	default:
		return fmt.Sprint(value)
	}
}

func intValue(value any) int {
	switch v := value.(type) {
	case nil:
		return 0
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		i, err := v.Int64()
		if err == nil {
			return int(i)
		}
		f, _ := v.Float64()
		return int(f)
	case string:
		var i int
		_, _ = fmt.Sscanf(v, "%d", &i)
		return i
	default:
		return 0
	}
}

func intValueDefault(value any, fallback int) int {
	if value == nil {
		return fallback
	}
	out := intValue(value)
	if out == 0 {
		return fallback
	}
	return out
}

func optionalInt(value any) *int {
	if value == nil {
		return nil
	}
	n := intValue(value)
	return &n
}

func optionalInt64(value any) *int64 {
	if value == nil {
		return nil
	}
	n := int64(intValue(value))
	return &n
}

func optionalBool(value any) *bool {
	if value == nil {
		return nil
	}
	v := boolValue(value, false)
	return &v
}

func boolValue(value any, fallback bool) bool {
	switch v := value.(type) {
	case nil:
		return fallback
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		default:
			return fallback
		}
	default:
		return fallback
	}
}

func firstNonNil(values ...any) any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func sha256JSON(value any) string {
	body, err := json.Marshal(jsonSafe(value))
	if err != nil {
		body = []byte(fmt.Sprint(value))
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func publicKeyFingerprint(certPEM string) string {
	block, _ := pem.Decode([]byte(strings.TrimSpace(certPEM)))
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || len(cert.RawSubjectPublicKeyInfo) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (a *CrossSdkGoAgent) aidStore() *aun.AIDStore {
	return aun.NewAIDStore(a.aunPath, "", aun.AIDStoreOptions{SlotID: a.slotID, Debug: a.debug})
}

func errorCode(err error) string {
	if err == nil {
		return ""
	}
	name := fmt.Sprintf("%T", err)
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		return name[idx+1:]
	}
	return name
}

func compactUUID() string {
	return strings.ReplaceAll(uuid.NewString(), "-", "")
}

func stringList(value any) []string {
	items, ok := value.([]any)
	if !ok {
		if strings.TrimSpace(stringValue(value)) != "" {
			return []string{strings.TrimSpace(stringValue(value))}
		}
		return []string{}
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s := strings.TrimSpace(stringValue(item)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func mapItems(value any) []map[string]any {
	items, ok := value.([]any)
	if !ok {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if m := asMap(item); m != nil {
			out = append(out, m)
		}
	}
	return out
}

func asMapOrEmpty(value any) map[string]any {
	if m := asMap(value); m != nil {
		return m
	}
	return map[string]any{}
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func stringSet(value any) map[string]bool {
	out := map[string]bool{}
	for _, item := range stringList(value) {
		out[item] = true
	}
	return out
}

func copyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func allInSet(items []string, set map[string]bool) bool {
	for _, item := range items {
		if !set[item] {
			return false
		}
	}
	return true
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func extractGroupID(result any) string {
	obj := asMap(result)
	if obj == nil {
		return ""
	}
	if groupID := stringValue(obj["group_id"]); groupID != "" {
		return groupID
	}
	if group := asMap(obj["group"]); group != nil {
		if groupID := stringValue(group["group_id"]); groupID != "" {
			return groupID
		}
	}
	if member := asMap(obj["member"]); member != nil {
		if groupID := stringValue(member["group_id"]); groupID != "" {
			return groupID
		}
	}
	return ""
}

func extractGroupAID(result any) string {
	obj := asMap(result)
	if obj == nil {
		return ""
	}
	if group := asMap(obj["group"]); group != nil {
		if groupAID := stringValue(group["group_aid"]); groupAID != "" {
			return groupAID
		}
	}
	return stringValue(obj["group_aid"])
}

func shouldForwardBearerOnRedirect(current *url.URL, next *url.URL) bool {
	if current == nil || next == nil {
		return false
	}
	if current.Scheme == next.Scheme && current.Host == next.Host {
		return true
	}
	currentHost := strings.ToLower(current.Hostname())
	nextHost := strings.ToLower(next.Hostname())
	if !strings.HasPrefix(nextHost, "storage.") {
		return false
	}
	issuer := strings.TrimPrefix(nextHost, "storage.")
	return issuer != "" && (currentHost == issuer || strings.HasSuffix(currentHost, "."+issuer))
}

func downloadText(ctx context.Context, rawURL string, bearerToken string) (string, error) {
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	trimmedToken := strings.TrimSpace(bearerToken)
	client := &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if trimmedToken == "" || len(via) == 0 {
				return nil
			}
			prev := via[len(via)-1]
			if shouldForwardBearerOnRedirect(prev.URL, req.URL) {
				req.Header.Set("Authorization", "Bearer "+trimmedToken)
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	if trimmedToken != "" {
		req.Header.Set("Authorization", "Bearer "+trimmedToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("download failed status=%d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func filterByTrace(items []map[string]any, traceID string, keepMatch bool) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		matched := stringValue(item["trace_id"]) == traceID
		if matched == keepMatch {
			out = append(out, item)
		}
	}
	return out
}

func filterInbox(items []map[string]any, traceID, groupID, fromAID string, limit int) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if traceID != "" && stringValue(item["trace_id"]) != traceID {
			continue
		}
		if groupID != "" && stringValue(item["group_id"]) != groupID {
			continue
		}
		if fromAID != "" && stringValue(item["from"]) != fromAID {
			continue
		}
		out = append(out, item)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

func logFiles() []string {
	logDir := envString("AUN_LOG_DIR", "/root/.aun/logs")
	files := []string{}
	_ = filepath.WalkDir(logDir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d != nil && !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	if len(files) > 20 {
		files = files[len(files)-20:]
	}
	return files
}

func writeTempText(content, suffix string) (string, error) {
	root := envString("AUN_CROSS_SDK_TMP", "/tmp/aun-cross-sdk")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(root, "*"+suffix)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := file.WriteString(content); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func groupFSCpResponse(result aun.GroupFSCpResult, dst string) map[string]any {
	out := map[string]any{"raw": jsonSafe(result)}
	candidates := []string{result.Download.LocalPath, dst}
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		data, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		out["local_path"] = candidate
		out["content"] = string(data)
		out["content_base64"] = base64.StdEncoding.EncodeToString(data)
		out["size_bytes"] = len(data)
		break
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
