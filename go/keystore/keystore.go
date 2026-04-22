package keystore

// KeyStore 密钥存储接口
// 定义了身份密钥、证书、元数据的增删查改操作。
// 与 Python SDK keystore/base.py 的 KeyStore 抽象基类对应。
type KeyStore interface {
	// LoadKeyPair 加载指定 AID 的密钥对
	LoadKeyPair(aid string) (map[string]any, error)

	// SaveKeyPair 保存密钥对
	SaveKeyPair(aid string, keyPair map[string]any) error

	// LoadCert 加载证书（PEM 字符串）
	LoadCert(aid string) (string, error)

	// SaveCert 保存证书（PEM 字符串）
	SaveCert(aid string, certPEM string) error

	// LoadIdentity 加载完整身份信息（密钥对 + 证书 + 元数据合并）
	LoadIdentity(aid string) (map[string]any, error)

	// SaveIdentity 保存完整身份信息（自动拆分到密钥对、证书、元数据）
	SaveIdentity(aid string, identity map[string]any) error

	// ListIdentities 列出所有具有有效私钥的 AID
	ListIdentities() ([]string, error)
}

// StructuredKeyStore 提供结构化主存能力。
// 与 Python FileKeyStore 的 prekeys / group secret state 语义对齐。
//
// 说明：
// - KeyStore 仍保持向后兼容，不强制所有实现立刻支持这些方法。
// - 业务层（E2EE / group）会优先探测并使用该扩展接口，避免继续依赖整块 metadata 的读改写。
type StructuredKeyStore interface {
	KeyStore

	// LoadE2EEPrekeys 加载某个 AID 的全部 prekey 私钥状态
	LoadE2EEPrekeys(aid string) (map[string]map[string]any, error)

	// SaveE2EEPrekey 保存单个 prekey 私钥状态
	SaveE2EEPrekey(aid, prekeyID string, prekeyData map[string]any) error

	// CleanupE2EEPrekeys 清理“早于 cutoffMs 且不在最新 keepLatest 个里”的 prekey 私钥状态
	CleanupE2EEPrekeys(aid string, cutoffMs int64, keepLatest int) ([]string, error)

	// LoadGroupSecretState 加载单个群组的结构化密钥状态
	LoadGroupSecretState(aid, groupID string) (map[string]any, error)

	// LoadAllGroupSecretStates 加载某个 AID 的全部群组结构化密钥状态
	LoadAllGroupSecretStates(aid string) (map[string]map[string]any, error)

	// SaveGroupSecretState 保存单个群组结构化密钥状态
	SaveGroupSecretState(aid, groupID string, entry map[string]any) error

	// CleanupGroupOldEpochsState 清理单个群组过期的旧 epoch 状态
	CleanupGroupOldEpochsState(aid, groupID string, cutoffMs int64) (int, error)
}

// VersionedCertKeyStore 提供按证书指纹加载/保存版本化证书的能力。
type VersionedCertKeyStore interface {
	KeyStore

	// LoadCertVersion 按 cert_fingerprint 加载证书版本
	LoadCertVersion(aid, certFingerprint string) (string, error)

	// SaveCertVersion 保存版本化证书；makeActive=true 时同时更新 active_signing 证书
	SaveCertVersion(aid, certPEM, certFingerprint string, makeActive bool) error
}

// InstanceStateStore 提供 device_id / slot_id 维度的实例态持久化能力。
type InstanceStateStore interface {
	KeyStore

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
	KeyStore

	// LoadE2EESessions 加载某个 AID 的全部 E2EE session
	LoadE2EESessions(aid string) ([]map[string]any, error)

	// SaveE2EESession 保存单个 E2EE session
	SaveE2EESession(aid, sessionID string, data map[string]any) error
}

// SeqTrackerStore 提供 seq tracker 结构化存储能力（对标 Python AIDDatabase.seq_tracker 表）。
type SeqTrackerStore interface {
	KeyStore

	// SaveSeq 保存单个 namespace 的 contiguous_seq
	SaveSeq(aid, deviceID, slotID, namespace string, contiguousSeq int) error

	// LoadSeq 加载单个 namespace 的 contiguous_seq
	LoadSeq(aid, deviceID, slotID, namespace string) (int, error)

	// LoadAllSeqs 加载某 device+slot 下所有 namespace 的 contiguous_seq
	LoadAllSeqs(aid, deviceID, slotID string) (map[string]int, error)
}
