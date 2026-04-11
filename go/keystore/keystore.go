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

	// LoadMetadata 加载元数据（tokens、prekeys 等）
	LoadMetadata(aid string) (map[string]any, error)

	// SaveMetadata 保存元数据
	SaveMetadata(aid string, metadata map[string]any) error

	// UpdateMetadata 在同一把锁内完成 load -> mutate -> save（原子更新）
	UpdateMetadata(aid string, updater func(map[string]any) (map[string]any, error)) (map[string]any, error)

	// LoadIdentity 加载完整身份信息（密钥对 + 证书 + 元数据合并）
	LoadIdentity(aid string) (map[string]any, error)

	// SaveIdentity 保存完整身份信息（自动拆分到密钥对、证书、元数据）
	SaveIdentity(aid string, identity map[string]any) error
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
