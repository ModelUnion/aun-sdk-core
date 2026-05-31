package keystore

import "time"

// TokenStore 不含私钥操作的存储接口，AuthFlow / AUNClient 持有此类型。
// 包含：证书、token/实例状态、seq、群组状态、E2EE prekey、group secret、
// metadata、agent.md 缓存、信任根等所有非私钥操作。
type TokenStore interface {
	// LoadCert 加载证书（PEM 字符串）
	LoadCert(aid string) (string, error)

	// SaveCert 保存证书（PEM 字符串）
	SaveCert(aid string, certPEM string) error
}

// KeyStore 私钥/完整身份存储接口，仅 AIDStore / RegisterFlow 持有。
// 定义了身份密钥、证书、元数据的增删查改操作。
type KeyStore interface {
	// LoadKeyPair 加载指定 AID 的密钥对
	LoadKeyPair(aid string) (map[string]any, error)

	// SaveKeyPair 保存密钥对
	SaveKeyPair(aid string, keyPair map[string]any) error

	// LoadIdentity 加载完整身份信息（密钥对 + 证书 + 元数据合并）
	LoadIdentity(aid string) (map[string]any, error)

	// SaveIdentity 保存完整身份信息（允许写入私钥字段）
	SaveIdentity(aid string, identity map[string]any) error

	// ListIdentities 列出所有具有有效私钥的 AID
	ListIdentities() ([]string, error)
}

// FullKeyStore 物理 keystore 通常同时实现 TokenStore 与 KeyStore；
// 注册流程显式使用组合类型。
type FullKeyStore interface {
	TokenStore
	KeyStore
}

// PendingIdentityKeyStore 提供 RegisterAID pending 身份的崩溃恢复能力。
// pending key.json 必须使用加密私钥字段，不能落盘 private_key_pem 明文。
type PendingIdentityKeyStore interface {
	PendingIdentityDir(aid string) (string, error)
	ListPendingIdentityDirs(aid string) ([]string, error)
	SavePendingKeyPair(pendingDir, aid string, keyPair map[string]any) error
	LoadPendingKeyPair(pendingDir, aid string) (map[string]any, error)
	SavePendingCert(pendingDir, certPEM string) error
	PromotePendingIdentity(pendingDir, aid string) (string, error)
	DiscardPendingIdentity(pendingDir string) error
	CleanupPendingDirs(maxAge time.Duration) int
}

// AgentMDCacheRecord 是单个 owner AID 本地缓存的某个 target AID 的 agent.md 状态。
// local_etag 是本地 content 的内容 ETag，remote_etag 是云端 HEAD/RPC/envelope 观察到的 ETag。
type AgentMDCacheRecord struct {
	AID          string `json:"aid"`
	Content      string `json:"content"`
	LocalEtag    string `json:"local_etag"`
	RemoteEtag   string `json:"remote_etag"`
	LastModified string `json:"last_modified"`
	FetchedAt    int64  `json:"fetched_at"`
	ObservedAt   int64  `json:"observed_at"`
	CheckedAt    int64  `json:"checked_at"`
	RemoteStatus string `json:"remote_status"`
	VerifyStatus string `json:"verify_status"`
	VerifyError  string `json:"verify_error"`
	LastError    string `json:"last_error"`
	UpdatedAt    int64  `json:"updated_at"`
}

// AgentMDCacheUpsert 表示 agent.md 缓存的局部更新；nil 字段保持原值，非 nil 字段可写入空串。
type AgentMDCacheUpsert struct {
	Content      *string
	LocalEtag    *string
	RemoteEtag   *string
	LastModified *string
	FetchedAt    *int64
	ObservedAt   *int64
	CheckedAt    *int64
	RemoteStatus *string
	VerifyStatus *string
	VerifyError  *string
	LastError    *string
}

// GroupState represents the current state_hash state for a group.
type GroupState struct {
	GroupID        string `json:"group_id"`
	StateVersion   int64  `json:"state_version"`
	StateHash      string `json:"state_hash"`
	KeyEpoch       int64  `json:"key_epoch"`
	MembershipJSON string `json:"membership_json"`
	PolicyJSON     string `json:"policy_json"`
	UpdatedAt      int64  `json:"updated_at"`
}

// StructuredKeyStore 提供结构化主存能力。
// 与 Python FileKeyStore 的 prekeys / group secret state 语义对齐。
//
// 说明：
// - KeyStore 仍保持向后兼容，不强制所有实现立刻支持这些方法。
// - 业务层（E2EE / group）会优先探测并使用该扩展接口，避免继续依赖整块 metadata 的读改写。
type StructuredKeyStore interface {
	// LoadE2EEPrekeys 加载某个 AID 指定设备的全部 prekey 私钥状态；deviceID 为空时加载默认设备
	LoadE2EEPrekeys(aid, deviceID string) (map[string]map[string]any, error)

	// LoadE2EEPrekeyByID 按 prekey_id 单点查询（O(1) 数据库行级查询）。
	// 解密入站消息时优先走该路径，避免 LoadE2EEPrekeys 的全量扫描。
	// 与 Python SDK keystore.base.KeyStore.load_e2ee_prekey_by_id 对应。未命中返回 (nil, nil)。
	LoadE2EEPrekeyByID(aid, prekeyID string) (map[string]any, error)

	// SaveE2EEPrekey 保存单个 prekey 私钥状态；deviceID 为空时写入默认设备
	SaveE2EEPrekey(aid, prekeyID, deviceID string, prekeyData map[string]any) error

	// CleanupE2EEPrekeys 清理”早于 cutoffMs 且不在最新 keepLatest 个里”的 prekey 私钥状态；deviceID 为空时清理默认设备
	CleanupE2EEPrekeys(aid, deviceID string, cutoffMs int64, keepLatest int) ([]string, error)

	// ListGroupSecretIDs 列出本地已存储群组密钥的 group_id
	ListGroupSecretIDs(aid string) ([]string, error)

	// CleanupGroupOldEpochsState 清理单个群组过期的旧 epoch 状态
	CleanupGroupOldEpochsState(aid, groupID string, cutoffMs int64) (int, error)

	// LoadGroupSecretEpoch 按 row 加载当前或指定 epoch 的群组密钥
	LoadGroupSecretEpoch(aid, groupID string, epoch *int) (map[string]any, error)

	// LoadGroupSecretEpochs 按 row 加载某个群组的当前和历史 epoch 密钥
	LoadGroupSecretEpochs(aid, groupID string) ([]map[string]any, error)

	// StoreGroupSecretTransition 事务化保存群组密钥状态转移
	StoreGroupSecretTransition(aid, groupID string, opts GroupSecretTransitionOptions) (bool, error)

	// StoreGroupSecretEpoch 事务化保存指定 epoch 密钥；低于 current 时写入 old epoch row
	StoreGroupSecretEpoch(aid, groupID string, opts GroupSecretTransitionOptions) (bool, error)

	// DiscardPendingGroupSecretState 事务化丢弃指定 pending rotation
	DiscardPendingGroupSecretState(aid, groupID string, epoch int, rotationID string) (bool, error)

	// DeleteGroupSecretState 删除单个群组的所有密钥状态
	DeleteGroupSecretState(aid, groupID string) error

	// SaveGroupState 保存群组 state_hash 状态
	SaveGroupState(aid, groupID string, stateVersion int64, stateHash string, keyEpoch int64, membershipJSON, policyJSON string) error

	// LoadGroupState 加载群组 state_hash 状态
	LoadGroupState(aid, groupID string) (*GroupState, error)
}

type GroupSecretTransitionOptions struct {
	Epoch                      int
	Secret                     string
	Commitment                 string
	MemberAIDs                 []string
	EpochChain                 string
	PendingRotationID          string
	EpochChainUnverified       bool
	EpochChainUnverifiedSet    bool
	EpochChainUnverifiedReason string
	OldEpochRetentionMillis    int64
}

// VersionedCertKeyStore 提供按证书指纹加载/保存版本化证书的能力。
type VersionedCertKeyStore interface {
	// LoadCertVersion 按 cert_fingerprint 加载证书版本
	LoadCertVersion(aid, certFingerprint string) (string, error)

	// SaveCertVersion 保存版本化证书；makeActive=true 时同时更新 active_signing 证书
	SaveCertVersion(aid, certPEM, certFingerprint string, makeActive bool) error
}

// InstanceStateStore 提供 device_id / slot_id 维度的实例态持久化能力。
type InstanceStateStore interface {
	// LoadInstanceState 加载实例级状态
	LoadInstanceState(aid, deviceID, slotID string) (map[string]any, error)

	// SaveInstanceState 保存实例级状态
	SaveInstanceState(aid, deviceID, slotID string, state map[string]any) error

	// UpdateInstanceState 原子更新实例级状态
	UpdateInstanceState(
		aid, deviceID, slotID string,
		updater func(map[string]any) (map[string]any, error),
	) (map[string]any, error)
}

// SessionKeyStore 提供 E2EE session 独立存储能力（对标 Python AIDDatabase.e2ee_sessions 表）。
type SessionKeyStore interface {
	// LoadE2EESessions 加载某个 AID 的全部 E2EE session
	LoadE2EESessions(aid string) ([]map[string]any, error)

	// SaveE2EESession 保存单个 E2EE session
	SaveE2EESession(aid, sessionID string, data map[string]any) error
}

// SeqTrackerStore 提供 seq tracker 结构化存储能力（对标 Python AIDDatabase.seq_tracker 表）。
type SeqTrackerStore interface {
	// SaveSeq 保存单个 namespace 的 contiguous_seq
	SaveSeq(aid, deviceID, slotID, namespace string, contiguousSeq int) error

	// LoadSeq 加载单个 namespace 的 contiguous_seq
	LoadSeq(aid, deviceID, slotID, namespace string) (int, error)

	// LoadAllSeqs 加载某 device+slot 下所有 namespace 的 contiguous_seq
	LoadAllSeqs(aid, deviceID, slotID string) (map[string]int, error)
}

// SeqTrackerDeleter 是 SeqTrackerStore 的可选扩展，提供按 namespace 删除单行的能力。
// 用于历史格式 group_id 的迁移：删除老 ns，写入 canonical ns。
type SeqTrackerDeleter interface {
	DeleteSeq(aid, deviceID, slotID, namespace string) error
}

// MetadataKeyStore 提供按 AID 隔离的轻量级 KV 元数据读写能力。
// 用于缓存非身份核心字段（如 gateway_url 等）以跨进程复用。
//
// 与 Python SDK keystore.file.FileKeyStore._get_db(aid).get_metadata/set_metadata 对应。
type MetadataKeyStore interface {
	// GetMetadataValue 读取指定 AID 下 key 对应的字符串值；不存在或读取失败返回空字符串。
	GetMetadataValue(aid, key string) string

	// SetMetadataValue 写入指定 AID 下 key 对应的字符串值。
	// value 为空字符串时按写入空字符串处理（不删除行）。
	SetMetadataValue(aid, key, value string) error
}

// TrustRootStore 提供信任根证书存储能力。
// 与 Python SDK TrustRootStore 对应。
type TrustRootStore interface {
	// TrustRootDir 返回信任根存储目录路径
	TrustRootDir() string

	// SaveTrustRoots 保存信任根列表。
	// trustList 为 trust-roots.json 的完整内容；imported 为已验证并导入的根证书摘要列表。
	// 返回 (bundlePath, error)。
	SaveTrustRoots(trustList map[string]any, imported []map[string]string) (string, error)

	// SaveIssuerRootCert 保存 Issuer 根证书。
	// 返回 (certPath, fingerprint, error)。
	SaveIssuerRootCert(issuer, certPEM, fingerprint string) (string, string, error)
}
