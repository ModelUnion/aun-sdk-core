package aun

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"
)

const MaxWSPayloadSize = 1_000_000

// eventNameMap 协议事件名到 SDK 事件名的映射
var eventNameMap = map[string]string{
	"message.received":       "message.received",
	"message.recalled":       "message.recalled",
	"message.ack":            "message.ack",
	"group.changed":          "group.changed",
	"group.message_created":  "group.message_created", // ISSUE-SDK-GO-001: 补充群消息事件映射
	"storage.object_changed": "storage.object_changed",
}

// 提取诊断字段时使用的字段白名单（按 RPC method 前缀匹配）
// 仅打印元数据/路由字段，绝不打印 payload 明文、token、私钥、密钥材料
var diagParamFields = []string{
	"to", "to_aid", "from", "from_aid", "group_id", "message_id", "mid",
	"method", "device_id", "slot_id", "epoch", "epoch_id", "rotation_id",
	"after_seq", "after_event_seq", "seq", "event_seq", "limit", "cursor",
	"aid", "session_id", "type", "encrypt", "encryption_mode", "suite",
	"prekey_id", "trust_root_version", "version", "ok", "request_id",
	"owner_aid", "rotated_by", "action",
}

var diagResultFields = append(append([]string{}, diagParamFields...),
	"members", "messages", "events", "count", "imported", "skipped",
	"next_cursor", "current_seq", "committed_epoch",
)

// summarizeDict 提取 map 中的关键诊断字段，序列化为简短字符串。
// 敏感字段（payload/content/text/cert/private_key/token/secret/ciphertext 等）一律不打印。
// list/map 类型只打长度或键名。
func summarizeDict(payload any, fields []string) string {
	m, ok := payload.(map[string]any)
	if !ok {
		if arr, ok := payload.([]any); ok {
			return fmt.Sprintf("[list len=%d]", len(arr))
		}
		if payload == nil {
			return "<empty>"
		}
		return fmt.Sprintf("<%T>", payload)
	}
	var parts []string
	for _, key := range fields {
		v, exists := m[key]
		if !exists || v == nil || v == "" {
			continue
		}
		switch vv := v.(type) {
		case []any:
			parts = append(parts, fmt.Sprintf("%s=[len=%d]", key, len(vv)))
		case map[string]any:
			parts = append(parts, fmt.Sprintf("%s={keys=%d}", key, len(vv)))
		case bool, int, int64, float64, uint, uint64:
			parts = append(parts, fmt.Sprintf("%s=%v", key, vv))
		default:
			s := fmt.Sprintf("%v", vv)
			if len(s) > 64 {
				s = s[:61] + "..."
			}
			parts = append(parts, fmt.Sprintf("%s=%s", key, s))
		}
	}
	if len(parts) == 0 {
		return "<no diag fields>"
	}
	return strings.Join(parts, " ")
}

// RPCTransport WebSocket JSON-RPC 2.0 传输层
// 与 Python SDK transport.py 对应。
type RPCTransport struct {
	dispatcher   *EventDispatcher
	timeout      atomic.Int64 // 纳秒，使用 atomic 保证跨 goroutine 安全
	onDisconnect func(error, int)
	verifySSL    bool
	ws           *websocket.Conn
	pending      map[string]chan map[string]any
	pendingMu    sync.Mutex
	closed       bool
	closedMu     sync.RWMutex
	challenge    map[string]any
	challengeMu  sync.RWMutex
	cancelReader context.CancelFunc
	readerDone   chan struct{}

	// Gateway 在 RPC envelope 注入 _meta 字段（与 result 同级），由 client 层 observer 接收。
	// 注入失败 / 字段缺失时 observer 不会被调用，不影响业务路径。
	metaObserver   func(map[string]any)
	metaObserverMu sync.RWMutex
}

// NewRPCTransport 创建 RPC 传输层
func NewRPCTransport(dispatcher *EventDispatcher, timeout time.Duration, onDisconnect func(error, int), verifySSL bool) *RPCTransport {
	if timeout == 0 {
		timeout = 35 * time.Second
	}
	t := &RPCTransport{
		dispatcher:   dispatcher,
		onDisconnect: onDisconnect,
		verifySSL:    verifySSL,
		pending:      make(map[string]chan map[string]any),
		closed:       true,
	}
	t.timeout.Store(int64(timeout))
	return t
}

// SetTimeout 设置 RPC 调用超时时间（线程安全）
func (t *RPCTransport) SetTimeout(timeout time.Duration) {
	t.timeout.Store(int64(timeout))
}

// SetMetaObserver 注册 RPC envelope _meta 字段观察者；observer(meta) 在每次成功 RPC 时调用。
//
// Gateway 注入的 _meta 与业务无关（如 agent_md_etag），observer panic 会被 recover 吞掉，
// 不影响 RPC result 返回。传入 nil 表示移除观察者。
func (t *RPCTransport) SetMetaObserver(observer func(map[string]any)) {
	t.metaObserverMu.Lock()
	t.metaObserver = observer
	t.metaObserverMu.Unlock()
}

// invokeMetaObserver 安全调用 metaObserver；observer panic 被 recover 吞掉。
func (t *RPCTransport) invokeMetaObserver(meta map[string]any) {
	t.metaObserverMu.RLock()
	observer := t.metaObserver
	t.metaObserverMu.RUnlock()
	if observer == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			pkgLogTransport().Debug("metaObserver panic: %v", r)
		}
	}()
	observer(meta)
}

// getTimeout 获取当前超时设置（线程安全）
func (t *RPCTransport) getTimeout() time.Duration {
	return time.Duration(t.timeout.Load())
}

// Challenge 返回连接时收到的 challenge 消息（线程安全）
func (t *RPCTransport) Challenge() map[string]any {
	t.challengeMu.RLock()
	defer t.challengeMu.RUnlock()
	return t.challenge
}

// setChallenge 线程安全地设置 challenge
func (t *RPCTransport) setChallenge(c map[string]any) {
	t.challengeMu.Lock()
	t.challenge = c
	t.challengeMu.Unlock()
}

// Connect 连接到 WebSocket 服务端，返回 challenge 消息
func (t *RPCTransport) Connect(ctx context.Context, url string) (challenge map[string]any, err error) {
	tStart := time.Now()
	pkgLogTransport().Debug("Connect enter: url=%s", url)
	defer func() {
		if err != nil {
			pkgLogTransport().Debug("Connect exit (error): elapsed=%dms err=%v", time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogTransport().Debug("Connect exit: elapsed=%dms", time.Since(tStart).Milliseconds())
		}
	}()
	opts := &websocket.DialOptions{}
	if !t.verifySSL {
		opts.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	conn, dialErr := func() (*websocket.Conn, error) {
		c, _, e := websocket.Dial(ctx, url, opts)
		return c, e
	}()
	if dialErr != nil {
		err = NewConnectionError(fmt.Sprintf("WebSocket connection failed: %v", dialErr))
		pkgLogTransport().Error("WebSocket connection failed: url=%s err=%v", url, dialErr)
		return nil, err
	}
	pkgLogTransport().Debug("WebSocket connection established: url=%s", url)

	t.closedMu.Lock()
	t.ws = conn
	t.closed = false
	t.closedMu.Unlock()

	// 接收初始消息（challenge）
	challenge, recvErr := t.recvInitialMessage(ctx)
	if recvErr != nil {
		pkgLogTransport().Error("failed to receive challenge: url=%s err=%v", url, recvErr)
		_ = conn.Close(websocket.StatusNormalClosure, "")
		t.closedMu.Lock()
		if t.ws == conn {
			t.ws = nil
		}
		t.closed = true
		t.closedMu.Unlock()
		err = recvErr
		return nil, err
	}
	t.setChallenge(challenge)
	pkgLogTransport().Debug("challenge received, starting reader loop: url=%s", url)

	// 启动读取循环 — cancelReader/readerDone 在 closedMu 保护下写入，与 Close() 的读取保持一致
	readerCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.closedMu.Lock()
	t.cancelReader = cancel
	t.readerDone = done
	t.closedMu.Unlock()
	go t.readerLoop(readerCtx)

	return challenge, nil
}

// Close 关闭传输层
func (t *RPCTransport) Close() (err error) {
	tStart := time.Now()
	pkgLogTransport().Debug("Close enter")
	defer func() {
		if err != nil {
			pkgLogTransport().Debug("Close exit (error): elapsed=%dms err=%v", time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogTransport().Debug("Close exit: elapsed=%dms", time.Since(tStart).Milliseconds())
		}
	}()
	t.closedMu.Lock()
	t.closed = true
	ws := t.ws
	t.ws = nil
	cancelFn := t.cancelReader
	doneCh := t.readerDone
	t.closedMu.Unlock()

	// 取消读取循环 — cancelFn/doneCh 在锁内快照，避免与 Connect() 写入竞争
	if cancelFn != nil {
		cancelFn()
		// 等待读取循环退出
		if doneCh != nil {
			<-doneCh
		}
	}

	// H25: 在锁外关闭 ws，避免持锁做网络 I/O；先把 t.ws 置 nil 保证其他 goroutine 看到一致状态
	if ws != nil {
		_ = ws.Close(websocket.StatusNormalClosure, "")
	}

	// 通知所有等待中的 RPC 调用
	t.pendingMu.Lock()
	pendingCount := len(t.pending)
	for id, ch := range t.pending {
		close(ch)
		delete(t.pending, id)
	}
	t.pendingMu.Unlock()
	pkgLogTransport().Debug("Close cancelled pending RPC calls: count=%d", pendingCount)

	return nil
}

// Call 发起 JSON-RPC 调用
func (t *RPCTransport) Call(ctx context.Context, method string, params map[string]any) (result any, err error) {
	tStart := time.Now()
	pkgLogTransport().Debug("Call enter: method=%s", method)
	defer func() {
		if err != nil {
			pkgLogTransport().Debug("Call exit (error): method=%s elapsed=%dms err=%v", method, time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogTransport().Debug("Call exit: method=%s elapsed=%dms", method, time.Since(tStart).Milliseconds())
		}
	}()
	t.closedMu.RLock()
	ws := t.ws
	if t.closed || ws == nil {
		t.closedMu.RUnlock()
		pkgLogTransport().Error("RPC call failed, transport not connected: method=%s", method)
		return nil, NewConnectionError("transport not connected")
	}
	t.closedMu.RUnlock()

	// 生成请求 ID
	rpcID := generateRPCID()
	resultCh := make(chan map[string]any, 1)

	t.pendingMu.Lock()
	t.pending[rpcID] = resultCh
	t.pendingMu.Unlock()

	// 构造 JSON-RPC 请求
	if params == nil {
		params = make(map[string]any)
	}
	request := map[string]any{
		"jsonrpc": "2.0",
		"id":      rpcID,
		"method":  method,
		"params":  params,
	}

	data, err := json.Marshal(request)
	if err != nil {
		t.pendingMu.Lock()
		delete(t.pending, rpcID)
		t.pendingMu.Unlock()
		pkgLogTransport().Error("failed to serialize RPC request: method=%s err=%v", method, err)
		return nil, NewSerializationError(fmt.Sprintf("failed to serialize RPC request: %v", err))
	}

	if len(data) > MaxWSPayloadSize {
		t.pendingMu.Lock()
		delete(t.pending, rpcID)
		t.pendingMu.Unlock()
		return nil, fmt.Errorf("payload is too large")
	}

	pkgLogTransport().Debug("sending RPC request: method=%s id=%s %s", method, rpcID, summarizeDict(params, diagParamFields))

	// 发送请求：write 超时跟随整体 timeout（不超过 30s 作为兜底上限），
	// 避免慢网络下 5s 硬编码导致 RPC 还没等响应就先 fail。
	currentTimeout := t.getTimeout()
	writeTimeout := currentTimeout
	if writeTimeout <= 0 || writeTimeout > 30*time.Second {
		writeTimeout = 30 * time.Second
	}
	writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	if err := ws.Write(writeCtx, websocket.MessageText, data); err != nil {
		t.pendingMu.Lock()
		delete(t.pending, rpcID)
		t.pendingMu.Unlock()
		pkgLogTransport().Error("failed to send RPC request: method=%s id=%s err=%v", method, rpcID, err)
		return nil, NewConnectionError(fmt.Sprintf("failed to send RPC %s: %v", method, err))
	}

	// 等待响应（带超时）
	timer := time.NewTimer(currentTimeout)
	defer timer.Stop()

	select {
	case response, ok := <-resultCh:
		if !ok {
			pkgLogTransport().Error("RPC response channel closed (transport disconnected): method=%s id=%s", method, rpcID)
			return nil, NewConnectionError("transport closed")
		}
		// 检查错误
		if errData, ok := response["error"]; ok {
			if errMap, ok := errData.(map[string]any); ok {
				pkgLogTransport().Warn("RPC response error: method=%s id=%s elapsed=%dms error=%v", method, rpcID, time.Since(tStart).Milliseconds(), errMap)
				return nil, MapRemoteError(errMap)
			}
		}
		pkgLogTransport().Debug("RPC response ok: method=%s id=%s elapsed=%dms %s", method, rpcID, time.Since(tStart).Milliseconds(), summarizeDict(response["result"], diagResultFields))
		// 透传 envelope._meta 给 observer（与业务无关，注入失败被吞，不影响 result 返回）。
		if meta, ok := response["_meta"].(map[string]any); ok {
			t.invokeMetaObserver(meta)
		}
		return response["result"], nil

	case <-timer.C:
		t.pendingMu.Lock()
		delete(t.pending, rpcID)
		t.pendingMu.Unlock()
		pkgLogTransport().Error("RPC timeout: method=%s id=%s elapsed=%dms timeout=%v", method, rpcID, time.Since(tStart).Milliseconds(), currentTimeout)
		return nil, NewTimeoutError(fmt.Sprintf("RPC timeout: %s", method))

	case <-ctx.Done():
		t.pendingMu.Lock()
		delete(t.pending, rpcID)
		t.pendingMu.Unlock()
		pkgLogTransport().Warn("RPC context cancelled: method=%s id=%s elapsed=%dms", method, rpcID, time.Since(tStart).Milliseconds())
		return nil, NewTimeoutError(fmt.Sprintf("RPC context cancelled: %s", method))
	}
}

// recvInitialMessage 接收初始消息（通常为 challenge）
// GO-015: 循环等待 challenge 消息，非 challenge 消息路由后继续等待，直到超时
func (t *RPCTransport) recvInitialMessage(ctx context.Context) (map[string]any, error) {
	readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// H25: 通过锁读取 t.ws，避免与 Close/Connect 的写入竞争
	t.closedMu.RLock()
	ws := t.ws
	t.closedMu.RUnlock()
	if ws == nil {
		return nil, NewConnectionError("failed to receive initial message: connection closed")
	}

	for {
		_, data, err := ws.Read(readCtx)
		if err != nil {
			return nil, NewConnectionError(fmt.Sprintf("waiting for challenge timed out or connection failed: %v", err))
		}

		message, err := decodeMessage(data)
		if err != nil {
			return nil, err
		}

		if method, ok := message["method"].(string); ok && method == "challenge" {
			return message, nil
		}

		// 非 challenge 消息，路由到事件处理后继续等待
		t.routeMessage(message)
	}
}

// readerLoop 后台读取循环
func (t *RPCTransport) readerLoop(ctx context.Context) {
	defer close(t.readerDone)
	var disconnectErr error
	unexpectedDisconnect := false

	defer func() {
		t.closedMu.Lock()
		wasClosed := t.closed
		t.closed = true
		t.closedMu.Unlock()

		if unexpectedDisconnect && !wasClosed && t.onDisconnect != nil {
			pkgLogTransport().Warn("unexpected disconnect: err=%v", disconnectErr)
			// 从 nhooyr.io/websocket 错误中提取 close code（-1 表示无 close frame）
			closeCode := int(websocket.CloseStatus(disconnectErr))
			t.onDisconnect(disconnectErr, closeCode)
		}
	}()

	for {
		t.closedMu.RLock()
		isClosed := t.closed
		t.closedMu.RUnlock()
		if isClosed {
			return
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		// H25: 通过锁读 t.ws，避免与 Connect/Close 竞争；重连窗口中 ws 被置 nil 时安全退出
		t.closedMu.RLock()
		ws := t.ws
		t.closedMu.RUnlock()
		if ws == nil {
			return
		}
		_, data, err := ws.Read(ctx)
		if err != nil {
			t.closedMu.RLock()
			wasClosed := t.closed
			t.closedMu.RUnlock()
			if !wasClosed {
				disconnectErr = err
				unexpectedDisconnect = true
				t.dispatcher.Publish("connection.error", map[string]any{"error": err})
			}
			return
		}

		message, err := decodeMessage(data)
		if err != nil {
			pkgLogTransport().Warn("failed to decode message: %v", err)
			continue
		}
		t.routeMessage(message)
	}
}

// routeMessage 路由消息到对应的处理器
func (t *RPCTransport) routeMessage(message map[string]any) {
	pkgLogTransport().Debug("routeMessage entry")
	defer pkgLogTransport().Debug("routeMessage exit")
	// 有 id 的是 RPC 响应
	if id, ok := message["id"]; ok {
		rpcID := fmt.Sprintf("%v", id)
		t.pendingMu.Lock()
		ch, exists := t.pending[rpcID]
		if exists {
			delete(t.pending, rpcID)
		}
		t.pendingMu.Unlock()

		if exists {
			ch <- message
		} else {
			pkgLogTransport().Warn("orphan RPC response: no pending call matches id=%s", rpcID)
		}
		return
	}

	// challenge 消息
	method, _ := message["method"].(string)
	if method == "challenge" {
		t.setChallenge(message)
		params, _ := message["params"].(map[string]any)
		pkgLogTransport().Debug("challenge received")
		t.dispatcher.Publish("connection.challenge", params)
		return
	}

	// 事件消息 — 异步发布，避免慢 handler 阻塞 readerLoop
	if len(method) > 6 && method[:6] == "event/" {
		protocolEvent := method[6:]
		sdkEvent := protocolEvent
		if mapped, ok := eventNameMap[protocolEvent]; ok {
			sdkEvent = mapped
		}
		params, _ := message["params"].(map[string]any)
		pkgLogTransport().Debug("event recv: event=%s %s", sdkEvent, summarizeDict(params, diagResultFields))
		go t.dispatcher.Publish("_raw."+sdkEvent, params)
		return
	}

	// 其他通知
	pkgLogTransport().Debug("notification recv: method=%s", methodOrPlaceholder(method))
	go t.dispatcher.Publish("notification", message)
}

func methodOrPlaceholder(s string) string {
	if s == "" {
		return "<no-method>"
	}
	return s
}

// decodeMessage 解码 WebSocket 消息为 map
func decodeMessage(data []byte) (map[string]any, error) {
	var message map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&message); err != nil {
		return nil, NewSerializationError("invalid JSON payload")
	}
	return normalizeDecodedJSONNumbers(message).(map[string]any), nil
}

func normalizeDecodedJSONNumbers(v any) any {
	switch value := v.(type) {
	case map[string]any:
		for k, item := range value {
			value[k] = normalizeDecodedJSONNumbers(item)
		}
		return value
	case []any:
		for i, item := range value {
			value[i] = normalizeDecodedJSONNumbers(item)
		}
		return value
	case json.Number:
		if i, err := value.Int64(); err == nil {
			return i
		}
		if f, err := value.Float64(); err == nil {
			return f
		}
		return value.String()
	default:
		return value
	}
}

// generateRPCID 生成随机的 RPC 请求 ID
func generateRPCID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "rpc-" + hex.EncodeToString(b)
}
