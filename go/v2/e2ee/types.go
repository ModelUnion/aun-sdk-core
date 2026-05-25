// Package e2ee 提供 AUN E2EE V2 端到端加解密引擎（P2P / Group）。
//
// 本包为纯计算实现，不涉及 IO；输入输出与 Python `aun_core.v2.e2ee` 模块字节级互通。
//
// 规范引用 §4 / §5 / §6。
package e2ee

// SuiteName V2 默认密码套件标识。
const SuiteName = "P256_HKDF_SHA256_AES_256_GCM"

// Sender 表示发送方身份。
//
//   - AID:      发送方 AID（如 "alice.aid.com"）
//   - DeviceID: 发送方设备 ID
//   - IKPriv:   AID 主私钥标量（32B big-endian P-256 scalar）
//   - IKPubDER: AID 主公钥 SubjectPublicKeyInfo DER 编码
type Sender struct {
	AID      string
	DeviceID string
	IKPriv   []byte
	IKPubDER []byte
}

// Target 表示单个接收方设备。
//
// 只有 SPKID、SPKPkDER 同时非空，且 KeySource 属于
// {"peer_device_prekey", "group_device_prekey"} 时才走 3DH 路径；
// 其它情况统一走 1DH，信封行会写 key_source=aid_master 且 spk_id=""。
//
// Role 取值通常为 "peer" / "member" / "self_sync" / "audit"。
// KeySource 取值通常为 "peer_device_prekey" / "group_device_prekey" / "aid_master"。
type Target struct {
	AID       string
	DeviceID  string
	Role      string
	KeySource string
	IKPkDER   []byte
	SPKPkDER  []byte // nil = 1DH
	SPKID     string
}

// TargetSet 表示 P2P 加密的接收方集合。
//
// Targets 是常规接收方（peer + 多设备 self_sync），
// AuditRecipients 是监管方（role = "audit"）。
type TargetSet struct {
	Targets         []Target
	AuditRecipients []Target
}

// EncryptOptions 控制加密时的可选参数。
//
// MessageID 为空时自动生成 "m-{uuid4 hex}"。
// Timestamp 为 0 时使用当前毫秒时间戳。
// ProtectedHeaders / Context 为 nil 或空 map 时不写入 envelope。
type EncryptOptions struct {
	MessageID        string
	Timestamp        int64
	ProtectedHeaders map[string]any
	Context          map[string]any
}

// StateCommitmentAAD 群消息 AAD 中的 state_commitment 块。
//
// 与 Python 实现对齐，缺省（全部零值）等价于 sv=0 的占位（兼容未启用 state 的群）。
type StateCommitmentAAD struct {
	StateVersion int    `json:"state_version"`
	StateHash    string `json:"state_hash"`
	StateChain   string `json:"state_chain"`
}
