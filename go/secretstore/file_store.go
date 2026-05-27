package secretstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

var hexSecretPartPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

func decodeSecretPart(value string) ([]byte, error) {
	if len(value)%2 == 0 && hexSecretPartPattern.MatchString(value) {
		return hex.DecodeString(value)
	}
	return base64.StdEncoding.DecodeString(value)
}

// SeedBackup seed 备份接口，避免循环依赖 keystore 包
type SeedBackup interface {
	BackupSeed(seed []byte)
	RestoreSeed() []byte
}

// FileSecretStore 基于文件的 SecretStore（AES-256-GCM 加密）
//
// 密钥派生：
//   - 传入 encryptionSeed → 从 seed 字符串派生
//   - 未传 → 从空字符串派生；旧 .seed 只作为迁移源使用
//
// 与 Python SDK file_store.py 完全对应。
type FileSecretStore struct {
	root      string
	masterKey []byte // 32 字节 AES-256 主密钥
}

// NewFileSecretStore 创建基于文件的密钥存储
// seedBackup 可为 nil（不启用 seed 备份）。
func NewFileSecretStore(root string, encryptionSeed string, seedBackup ...SeedBackup) (*FileSecretStore, error) {
	// 确保目录存在
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("创建密钥存储目录失败: %w", err)
	}

	var sb SeedBackup
	if len(seedBackup) > 0 && !isNilSeedBackup(seedBackup[0]) {
		sb = seedBackup[0]
	}
	_ = sb

	seedBytes := []byte(encryptionSeed)

	// PBKDF2-SHA256 派生主密钥
	masterKey := pbkdf2.Key(seedBytes, []byte("aun_file_secret_store_v1"), 100000, 32, sha256.New)

	return &FileSecretStore{
		root:      root,
		masterKey: masterKey,
	}, nil
}

func isNilSeedBackup(backup SeedBackup) bool {
	if backup == nil {
		return true
	}
	value := reflect.ValueOf(backup)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// Protect 保护明文数据（AES-256-GCM 加密）
func (f *FileSecretStore) Protect(scope, name string, plaintext []byte) (record map[string]any, err error) {
	tStart := time.Now()
	pkgLogSecretStore().Debug("Protect enter: scope=%s name=%s len=%d", scope, name, len(plaintext))
	defer func() {
		if err != nil {
			pkgLogSecretStore().Debug("Protect exit (error): scope=%s name=%s elapsed=%dms err=%v", scope, name, time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogSecretStore().Debug("Protect exit: scope=%s name=%s elapsed=%dms", scope, name, time.Since(tStart).Milliseconds())
		}
	}()
	key := f.deriveKey(scope, name)

	// 生成 12 字节随机 nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("生成随机 nonce 失败: %w", err)
	}

	// AES-256-GCM 加密
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("创建 AES 密码器失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建 GCM 模式失败: %w", err)
	}

	// GCM Seal 输出 = 密文 + 16 字节 tag
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	ctLen := len(sealed) - 16
	ciphertext := sealed[:ctLen]
	tag := sealed[ctLen:]

	return map[string]any{
		"scheme":     "file_aes",
		"name":       name,
		"persisted":  true,
		"nonce":      base64.StdEncoding.EncodeToString(nonce),
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
		"tag":        base64.StdEncoding.EncodeToString(tag),
	}, nil
}

// Reveal 还原被保护的数据（AES-256-GCM 解密）
func (f *FileSecretStore) Reveal(scope, name string, record map[string]any) (plaintext []byte, err error) {
	tStart := time.Now()
	pkgLogSecretStore().Debug("Reveal enter: scope=%s name=%s", scope, name)
	defer func() {
		if err != nil {
			pkgLogSecretStore().Debug("Reveal exit (error): scope=%s name=%s elapsed=%dms err=%v", scope, name, time.Since(tStart).Milliseconds(), err)
		} else {
			pkgLogSecretStore().Debug("Reveal exit: scope=%s name=%s len=%d elapsed=%dms", scope, name, len(plaintext), time.Since(tStart).Milliseconds())
		}
	}()
	// 验证 scheme 和 name — 不匹配返回 nil,nil（表示"不是我的 record"）
	if scheme, ok := record["scheme"].(string); !ok || scheme != "file_aes" {
		return nil, nil
	}
	recordName, _ := record["name"].(string)
	if recordName != name {
		return nil, nil
	}

	nonceB64, _ := record["nonce"].(string)
	ctB64, _ := record["ciphertext"].(string)
	tagB64, _ := record["tag"].(string)
	if nonceB64 == "" || ctB64 == "" || tagB64 == "" {
		return nil, fmt.Errorf("secretstore.Reveal: record 缺少必要字段 (nonce/ciphertext/tag)")
	}

	key := f.deriveKey(scope, name)

	// 解码
	nonce, err := decodeSecretPart(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("secretstore.Reveal: nonce base64 解码失败: %w", err)
	}
	ciphertext, err := decodeSecretPart(ctB64)
	if err != nil {
		return nil, fmt.Errorf("secretstore.Reveal: ciphertext base64 解码失败: %w", err)
	}
	tag, err := decodeSecretPart(tagB64)
	if err != nil {
		return nil, fmt.Errorf("secretstore.Reveal: tag base64 解码失败: %w", err)
	}

	// AES-256-GCM 解密
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secretstore.Reveal: AES cipher 创建失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretstore.Reveal: GCM 创建失败: %w", err)
	}

	// 拼接 ciphertext + tag（GCM Open 期望的格式）
	sealed := append(ciphertext, tag...)
	plaintext, err = aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("secretstore.Reveal: GCM 解密失败（数据可能损坏）: %w", err)
	}

	return plaintext, nil
}

// deriveKey 从主密钥派生子密钥
// 使用 HMAC-SHA256: key = HMAC(masterKey, "aun:{scope}:{name}\x01")
func (f *FileSecretStore) deriveKey(scope, name string) []byte {
	mac := hmac.New(sha256.New, f.masterKey)
	mac.Write([]byte(fmt.Sprintf("aun:%s:%s", scope, name)))
	mac.Write([]byte{0x01})
	return mac.Sum(nil)
}
