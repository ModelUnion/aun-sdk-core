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
	case req.Method == http.MethodGet && path == "/group/ready":
		a.handleGroupReady(res, req)
	case req.Method == http.MethodPost && path == "/group/send":
		a.handleGroupSend(res, req)
	case req.Method == http.MethodPost && path == "/group/pull":
		a.handleGroupPull(res, req)
	case req.Method == http.MethodPost && path == "/group/ack":
		a.handleGroupAck(res, req)
	case req.Method == http.MethodPost && path == "/group/resources/init":
		a.handleGroupResourcesInit(res, req)
	case req.Method == http.MethodPost && path == "/group/resources/put":
		a.handleGroupResourcesPut(res, req)
	case req.Method == http.MethodPost && path == "/group/resources/mkdir":
		a.handleGroupResourcesMkdir(res, req)
	case req.Method == http.MethodPost && path == "/group/resources/mount":
		a.handleGroupResourcesMount(res, req)
	case req.Method == http.MethodPost && path == "/group/resources/read":
		a.handleGroupResourcesRead(res, req)
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

func (a *CrossSdkGoAgent) handleGroupResourcesInit(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	traceID := firstNonEmpty(stringValue(body["trace_id"]), compactUUID())
	ctx, cancel := context.WithTimeout(req.Context(), 60*time.Second)
	defer cancel()
	store := a.aidStore()
	defer store.Close()
	body["aid_store"] = store
	result, err := a.client.Group().Resources().InitializeNamespace(ctx, body)
	if err != nil {
		out := map[string]any{"ok": false, "trace_id": traceID, "error_code": errorCode(err), "error_message": err.Error()}
		a.recordTrace(traceID, map[string]any{"stage": "group_resources_init_error", "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	out := map[string]any{"ok": true, "trace_id": traceID, "result": jsonSafe(result)}
	a.recordTrace(traceID, map[string]any{"stage": "group_resources_init", "result": out})
	writeJSON(res, http.StatusOK, out)
}

func (a *CrossSdkGoAgent) handleGroupResourcesPut(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	traceID := firstNonEmpty(stringValue(body["trace_id"]), compactUUID())
	ctx, cancel := context.WithTimeout(req.Context(), 60*time.Second)
	defer cancel()
	pending, err := a.client.Group().Resources().Put(ctx, body)
	if err != nil {
		out := map[string]any{"ok": false, "trace_id": traceID, "error_code": errorCode(err), "error_message": err.Error()}
		a.recordTrace(traceID, map[string]any{"stage": "group_resources_put_error", "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	plan := asMap(pending)
	var confirmed any
	if plan != nil && pendingOpsLen(plan["pending_ops"]) > 0 {
		store := a.aidStore()
		defer store.Close()
		plan["aid_store"] = store
		confirmed, err = a.client.Group().Resources().ExecutePendingOps(ctx, plan)
		if err != nil {
			out := map[string]any{"ok": false, "trace_id": traceID, "error_code": errorCode(err), "error_message": err.Error(), "pending": jsonSafe(pending)}
			a.recordTrace(traceID, map[string]any{"stage": "group_resources_put_error", "error": out})
			writeJSON(res, http.StatusInternalServerError, out)
			return
		}
	}
	out := map[string]any{"ok": true, "trace_id": traceID, "pending": jsonSafe(pending), "confirmed": jsonSafe(confirmed)}
	a.recordTrace(traceID, map[string]any{"stage": "group_resources_put", "result": out})
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

func (a *CrossSdkGoAgent) callCollabAction(ctx context.Context, action string, params map[string]any) (any, error) {
	collab := a.client.Collab()
	root := firstNonEmpty(stringValue(params["collab_root"]), stringValue(params["collabRoot"]))
	doc := stringValue(params["doc"])
	source := stringValue(params["source"])
	switch action {
	case "ls":
		return collab.LS(ctx, root)
	case "create":
		return collab.Create(ctx, root, doc, source)
	case "read":
		return collab.Read(ctx, root, doc)
	case "submit":
		return collab.Submit(ctx, root, doc, source, intValue(firstNonNil(params["base_version"], params["baseVersion"])), stringValue(params["message"]))
	case "merge":
		return collab.Merge(ctx, root, doc, source, intValue(firstNonNil(params["base_version"], params["baseVersion"])))
	case "history":
		return collab.History(ctx, root, doc)
	case "get":
		return collab.Get(ctx, root, doc, intValue(params["version"]))
	case "diff":
		return collab.Diff(ctx, root, doc, intValue(params["from"]), intValue(params["to"]))
	case "export":
		return collab.Export(ctx, root, stringValue(params["dest"]))
	case "adopt":
		return collab.Adopt(ctx, stringValue(params["src"]), firstNonEmpty(stringValue(params["new_root"]), stringValue(params["newRoot"])))
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
	case "reset":
		return collab.Reset(ctx, root, doc, intValue(params["version"]), stringValue(params["message"]))
	case "discover":
		return collab.Discover(ctx, firstNonEmpty(stringValue(params["group_aid"]), stringValue(params["groupAid"])))
	case "unregister":
		return collab.Unregister(ctx, firstNonEmpty(stringValue(params["group_aid"]), stringValue(params["groupAid"])), root)
	case "snapshot.create":
		return collab.Snapshot().Create(ctx, root, stringValue(params["message"]), boolValue(params["major"], false))
	case "snapshot.list":
		return collab.Snapshot().List(ctx, root)
	case "snapshot.show":
		return collab.Snapshot().Show(ctx, root, stringValue(params["version"]))
	case "snapshot.diff":
		return collab.Snapshot().Diff(ctx, root, firstNonEmpty(stringValue(params["version_a"]), stringValue(params["versionA"])), firstNonEmpty(stringValue(params["version_b"]), stringValue(params["versionB"])))
	case "snapshot.restore":
		return collab.Snapshot().Restore(ctx, root, stringValue(params["version"]), stringValue(params["message"]))
	case "snapshot.rm":
		return collab.Snapshot().Remove(ctx, root, stringValue(params["version"]))
	case "snapshot.prune":
		before := optionalInt(firstNonNil(params["before"]))
		keepLast := optionalInt(firstNonNil(params["keep_last"], params["keepLast"]))
		return collab.Snapshot().Prune(ctx, root, before, keepLast)
	default:
		return nil, fmt.Errorf("unsupported collab action: %s", action)
	}
}

func (a *CrossSdkGoAgent) callStorageAction(ctx context.Context, action string, params map[string]any) (any, error) {
	storage := a.client.Storage()
	path := strings.TrimSpace(stringValue(params["path"]))
	owner := strings.TrimSpace(firstNonEmpty(stringValue(params["owner_aid"]), stringValue(params["ownerAID"])))
	bucket := strings.TrimSpace(stringValue(params["bucket"]))
	if bucket == "" {
		bucket = "default"
	}
	token := strings.TrimSpace(stringValue(params["token"]))
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
		overwrite := boolValue(params["overwrite"], true)
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
		objectKey := strings.TrimLeft(firstNonEmpty(stringValue(params["object_key"]), stringValue(params["objectKey"]), path), "/")
		callParams := map[string]any{
			"owner_aid":  owner,
			"bucket":     bucket,
			"object_key": objectKey,
		}
		if token != "" {
			callParams["token"] = token
		}
		return a.client.Call(ctx, "storage.create_download_ticket", callParams)
	case "download_text":
		url := strings.TrimSpace(firstNonEmpty(stringValue(params["url"]), stringValue(params["download_url"]), stringValue(params["downloadUrl"])))
		if url == "" {
			return nil, fmt.Errorf("download_text requires url")
		}
		content, err := downloadText(ctx, url)
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
	default:
		return nil, fmt.Errorf("unsupported storage action: %s", action)
	}
}

func (a *CrossSdkGoAgent) handleGroupResourcesMkdir(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	traceID := firstNonEmpty(stringValue(body["trace_id"]), compactUUID())
	ctx, cancel := context.WithTimeout(req.Context(), 60*time.Second)
	defer cancel()
	result, err := a.client.Group().Resources().CreateFolder(ctx, body)
	if err != nil {
		out := map[string]any{"ok": false, "trace_id": traceID, "error_code": errorCode(err), "error_message": err.Error()}
		a.recordTrace(traceID, map[string]any{"stage": "group_resources_mkdir_error", "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	out := map[string]any{"ok": true, "trace_id": traceID, "result": jsonSafe(result)}
	a.recordTrace(traceID, map[string]any{"stage": "group_resources_mkdir", "result": out})
	writeJSON(res, http.StatusOK, out)
}

func (a *CrossSdkGoAgent) handleGroupResourcesMount(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	traceID := firstNonEmpty(stringValue(body["trace_id"]), compactUUID())
	ctx, cancel := context.WithTimeout(req.Context(), 60*time.Second)
	defer cancel()
	pending, err := a.client.Group().Resources().MountObject(ctx, body)
	if err != nil {
		out := map[string]any{"ok": false, "trace_id": traceID, "error_code": errorCode(err), "error_message": err.Error()}
		a.recordTrace(traceID, map[string]any{"stage": "group_resources_mount_error", "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	plan := asMap(pending)
	if plan == nil || pendingOpsLen(plan["pending_ops"]) == 0 {
		out := map[string]any{"ok": false, "trace_id": traceID, "error_code": "bad_pending", "error_message": fmt.Sprintf("group.resources.mount_object returned non-pending result: %v", jsonSafe(pending))}
		a.recordTrace(traceID, map[string]any{"stage": "group_resources_mount_error", "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	store := a.aidStore()
	defer store.Close()
	plan["aid_store"] = store
	confirmed, err := a.client.Group().Resources().ExecutePendingOps(ctx, plan)
	if err != nil {
		out := map[string]any{"ok": false, "trace_id": traceID, "error_code": errorCode(err), "error_message": err.Error(), "pending": jsonSafe(pending)}
		a.recordTrace(traceID, map[string]any{"stage": "group_resources_mount_error", "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	out := map[string]any{"ok": true, "trace_id": traceID, "pending": jsonSafe(pending), "confirmed": jsonSafe(confirmed)}
	a.recordTrace(traceID, map[string]any{"stage": "group_resources_mount", "result": out})
	writeJSON(res, http.StatusOK, out)
}

func (a *CrossSdkGoAgent) handleGroupResourcesRead(res http.ResponseWriter, req *http.Request) {
	body := readJSON(req)
	traceID := firstNonEmpty(stringValue(body["trace_id"]), compactUUID())
	ctx, cancel := context.WithTimeout(req.Context(), 45*time.Second)
	defer cancel()
	access, err := a.client.Group().Resources().GetAccess(ctx, body)
	if err != nil {
		out := map[string]any{"ok": false, "trace_id": traceID, "error_code": errorCode(err), "error_message": err.Error()}
		a.recordTrace(traceID, map[string]any{"stage": "group_resources_read_error", "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	download := asMap(asMap(access)["download"])
	downloadURL := strings.TrimSpace(firstNonEmpty(stringValue(download["download_url"]), stringValue(download["downloadUrl"])))
	if downloadURL == "" {
		out := map[string]any{"ok": false, "trace_id": traceID, "error_code": "missing_download_url", "error_message": fmt.Sprintf("group.resources.get_access did not return download_url: %v", jsonSafe(access))}
		a.recordTrace(traceID, map[string]any{"stage": "group_resources_read_error", "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	content, err := downloadText(ctx, downloadURL)
	if err != nil {
		out := map[string]any{"ok": false, "trace_id": traceID, "error_code": errorCode(err), "error_message": err.Error()}
		a.recordTrace(traceID, map[string]any{"stage": "group_resources_read_error", "error": out})
		writeJSON(res, http.StatusInternalServerError, out)
		return
	}
	out := map[string]any{"ok": true, "trace_id": traceID, "content": content, "access": jsonSafe(access)}
	a.recordTrace(traceID, map[string]any{"stage": "group_resources_read", "result": map[string]any{"ok": true, "content_len": len(content)}})
	writeJSON(res, http.StatusOK, out)
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

func downloadText(ctx context.Context, url string) (string, error) {
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
