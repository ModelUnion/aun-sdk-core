package aun

// 错误码常量，与 Python SDK error_codes.py 对齐；Go SDK 可补充本地实现需要的细分错误码。

// 加载阶段（AIDStore.Load）
const (
	ErrCodeCertNotFound         = "CERT_NOT_FOUND"
	ErrCodeCertParseError       = "CERT_PARSE_ERROR"
	ErrCodeCertExpired          = "CERT_EXPIRED"
	ErrCodeCertNotYetValid      = "CERT_NOT_YET_VALID"
	ErrCodeCertChainBroken      = "CERT_CHAIN_BROKEN"
	ErrCodeKeypairMismatch      = "KEYPAIR_MISMATCH"
	ErrCodePrivateKeyParseError = "PRIVATE_KEY_PARSE_ERROR"
	ErrCodeSaveIdentityFailed   = "SAVE_IDENTITY_FAILED"
)

// 注册阶段（AIDStore.Register）
const (
	ErrCodeIdentityConflict = "IDENTITY_CONFLICT"
	ErrCodeInvalidAIDFormat = "INVALID_AID_FORMAT"
	ErrCodeNetworkError     = "NETWORK_ERROR"
	ErrCodeServerError      = "SERVER_ERROR"
)

// agent.md / 证书下载阶段
const (
	ErrCodeAgentMdNotFound         = "AGENTMD_NOT_FOUND"
	ErrCodeAgentMdParseError       = "AGENTMD_PARSE_ERROR"
	ErrCodeSignatureNotFound       = "SIGNATURE_NOT_FOUND"
	ErrCodeSignatureInvalid        = "SIGNATURE_INVALID"
	ErrCodeCertFingerprintMismatch = "CERT_FINGERPRINT_MISMATCH"
)

// 证书运维阶段（AIDStore.RenewCert / Rekey）
const (
	ErrCodeCertRenewalFailed  = "CERT_RENEWAL_FAILED"
	ErrCodeRekeyFailed        = "REKEY_FAILED"
	ErrCodePrivateKeyRequired = "PRIVATE_KEY_REQUIRED"
)

// 密码学操作（AID.Sign / Verify / SignAgentMd / VerifyAgentMd）
const (
	ErrCodeSignatureOperationError    = "SIGNATURE_OPERATION_ERROR"
	ErrCodeVerificationOperationError = "VERIFICATION_OPERATION_ERROR"
	ErrCodeCertNotValid               = "CERT_NOT_VALID"
	ErrCodePrivateKeyNotValid         = "PRIVATE_KEY_NOT_VALID"
)

// 其他
const (
	ErrCodeTrustRootsInvalid = "TRUST_ROOTS_INVALID"
)
