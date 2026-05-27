package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/modelunion/aun-sdk-core/go/secretstore"
	"golang.org/x/crypto/pbkdf2"
)

var seedMigrationHexPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

type SeedChangeResult struct {
	PrivateKeysMigrated int
	Migrated            int
	Skipped             int
	Errors              int
	SeedFileRenamed     bool
}

type privateKeyMigration struct {
	aid       string
	path      string
	plaintext []byte
}

func ChangeSeed(root, oldSeed, newSeed string) (SeedChangeResult, error) {
	var result SeedChangeResult
	oldSeedBytes, renameSeedFile, err := resolveOldSeed(root, oldSeed)
	if err != nil {
		return result, err
	}
	oldMaster := deriveSeedMasterKey(oldSeedBytes)
	newSeedBytes := []byte(newSeed)
	newMaster := deriveSeedMasterKey(newSeedBytes)

	privateKeys, err := verifyPrivateKeysForSeedChange(root, oldMaster)
	if err != nil {
		return result, err
	}
	if len(privateKeys) == 0 {
		return result, fmt.Errorf("seed migration refused: no encrypted private key verified with old seed")
	}
	if hmac.Equal(oldMaster, newMaster) {
		if renameSeedFile {
			result.SeedFileRenamed = renameSeedPath(filepath.Join(root, ".seed"))
		}
		return result, nil
	}

	for _, item := range privateKeys {
		if err := rewriteKeyJSONPrivateKey(item.path, item.aid, item.plaintext, newSeedBytes, newMaster); err != nil {
			result.Errors++
			return result, err
		}
		result.PrivateKeysMigrated++
		result.Migrated++
	}

	migrated, skipped, errors := migrateAIDDBEncryptedFields(root, oldMaster, newSeedBytes)
	result.Migrated += migrated
	result.Skipped += skipped
	result.Errors += errors
	if errors > 0 {
		return result, fmt.Errorf("seed migration failed while migrating database fields: errors=%d", errors)
	}

	if renameSeedFile {
		result.SeedFileRenamed = renameSeedPath(filepath.Join(root, ".seed"))
	}
	return result, nil
}

func resolveActiveEncryptionSeed(root, encryptionSeed string) string {
	seedPath := filepath.Join(root, ".seed")
	if _, err := os.Stat(seedPath); err != nil {
		return encryptionSeed
	}
	if _, err := ChangeSeed(root, ".seed", encryptionSeed); err == nil {
		return encryptionSeed
	}
	data, readErr := os.ReadFile(seedPath)
	if readErr != nil || len(data) == 0 {
		return encryptionSeed
	}
	pkgLogKeystore().Warn("seed migration failed; continuing with legacy .seed")
	return string(data)
}

func (f *FileKeyStore) ChangeSeed(oldSeed, newSeed string) (SeedChangeResult, error) {
	f.Close()
	result, err := ChangeSeed(f.root, oldSeed, newSeed)
	if err != nil {
		return result, err
	}
	ss, err := secretstore.NewFileSecretStore(f.root, newSeed)
	if err != nil {
		return result, err
	}
	f.secretStore = ss
	return result, nil
}

func resolveOldSeed(root, oldSeed string) ([]byte, bool, error) {
	if oldSeed != ".seed" {
		return []byte(oldSeed), false, nil
	}
	seedPath := filepath.Join(root, ".seed")
	data, err := os.ReadFile(seedPath)
	if err != nil {
		return nil, false, fmt.Errorf("read .seed failed: %w", err)
	}
	if len(data) == 0 {
		return nil, false, fmt.Errorf("seed migration refused: .seed is empty")
	}
	return data, true, nil
}

func verifyPrivateKeysForSeedChange(root string, oldMaster []byte) ([]privateKeyMigration, error) {
	aidsRoot := filepath.Join(root, "AIDs")
	entries, err := os.ReadDir(aidsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("seed migration refused: AIDs directory not found")
		}
		return nil, err
	}
	var out []privateKeyMigration
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), "_") {
			continue
		}
		aid := entry.Name()
		keyPath := filepath.Join(aidsRoot, aid, "private", "key.json")
		data, err := os.ReadFile(keyPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("seed migration refused: invalid key.json for %s: %w", aid, err)
		}
		record, ok := raw["private_key_protection"].(map[string]any)
		if !ok {
			continue
		}
		plaintext, ok := decryptSeedRecord(oldMaster, aid, "identity/private_key", record)
		if !ok {
			return nil, fmt.Errorf("seed migration refused: private key not encrypted by old seed: aid=%s", aid)
		}
		out = append(out, privateKeyMigration{aid: aid, path: keyPath, plaintext: plaintext})
	}
	return out, nil
}

func rewriteKeyJSONPrivateKey(path, aid string, plaintext []byte, newSeed, newMaster []byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	record, err := encryptSeedRecordWithMaster(newMaster, aid, "identity/private_key", plaintext)
	if err != nil {
		return err
	}
	if verified, ok := decryptSeedRecord(deriveSeedMasterKey(newSeed), aid, "identity/private_key", record); !ok || string(verified) != string(plaintext) {
		return fmt.Errorf("seed migration refused: new seed verification failed for %s", aid)
	}
	raw["private_key_protection"] = record
	encoded, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0o600)
}

func migrateAIDDBEncryptedFields(root string, oldMaster, newSeed []byte) (int, int, int) {
	aidsRoot := filepath.Join(root, "AIDs")
	entries, err := os.ReadDir(aidsRoot)
	if err != nil {
		return 0, 0, 1
	}
	totalMigrated, totalSkipped, totalErrors := 0, 0, 0
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), "_") {
			continue
		}
		dbPath := filepath.Join(aidsRoot, entry.Name(), "aun.db")
		if _, err := os.Stat(dbPath); err != nil {
			continue
		}
		m, s, e := migrateOneAIDDB(dbPath, entry.Name(), oldMaster, newSeed)
		totalMigrated += m
		totalSkipped += s
		totalErrors += e
	}
	return totalMigrated, totalSkipped, totalErrors
}

func migrateOneAIDDB(dbPath, scope string, oldMaster, newSeed []byte) (int, int, int) {
	specs := []struct {
		table   string
		keyCols string
		encCol  string
		nameFn  func([]any) string
	}{
		{"prekeys", "prekey_id, device_id", "private_key_enc", func(row []any) string { return "prekey/" + fmt.Sprint(row[0]) }},
		{"group_current", "group_id", "secret_enc", func(row []any) string { return "group/" + fmt.Sprint(row[0]) + "/current" }},
		{"group_old_epochs", "group_id, epoch", "secret_enc", func(row []any) string { return "group/" + fmt.Sprint(row[0]) + "/epoch/" + fmt.Sprint(row[1]) }},
		{"e2ee_sessions", "session_id", "data_enc", func(row []any) string { return "session/" + fmt.Sprint(row[0]) }},
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, 0, 1
	}
	defer db.Close()
	_, _ = db.Exec("PRAGMA busy_timeout = 5000")
	migrated, skipped, errors := 0, 0, 0
	for _, spec := range specs {
		rows, err := db.Query(fmt.Sprintf("SELECT %s, %s FROM %s", spec.keyCols, spec.encCol, spec.table))
		if err != nil {
			continue
		}
		keyCols := splitColumnList(spec.keyCols)
		for rows.Next() {
			values := make([]any, len(keyCols)+1)
			scan := make([]any, len(values))
			for i := range values {
				scan[i] = &values[i]
			}
			if err := rows.Scan(scan...); err != nil {
				errors++
				continue
			}
			keyValues := values[:len(values)-1]
			stored := stringFromDBValue(values[len(values)-1])
			if stored == "" {
				skipped++
				continue
			}
			var record map[string]any
			if err := json.Unmarshal([]byte(stored), &record); err != nil {
				skipped++
				continue
			}
			name := spec.nameFn(keyValues)
			plaintext, ok := decryptSeedRecord(oldMaster, scope, name, record)
			if !ok {
				skipped++
				continue
			}
			newRecord, err := encryptSeedRecord(newSeed, scope, name, plaintext)
			if err != nil {
				errors++
				continue
			}
			encoded, _ := json.Marshal(newRecord)
			whereParts := make([]string, len(keyCols))
			for i, col := range keyCols {
				whereParts[i] = col + " = ?"
			}
			args := append([]any{string(encoded)}, keyValues...)
			if _, err := db.Exec(fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s", spec.table, spec.encCol, strings.Join(whereParts, " AND ")), args...); err != nil {
				errors++
				continue
			}
			migrated++
		}
		_ = rows.Close()
	}
	return migrated, skipped, errors
}

func deriveSeedMasterKey(seed []byte) []byte {
	return pbkdf2.Key(seed, []byte("aun_file_secret_store_v1"), 100000, 32, sha256.New)
}

func deriveSeedFieldKey(master []byte, scope, name string) []byte {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte("aun:" + scope + ":" + name))
	mac.Write([]byte{0x01})
	return mac.Sum(nil)
}

func decryptSeedRecord(master []byte, scope, name string, record map[string]any) ([]byte, bool) {
	if scheme, _ := record["scheme"].(string); scheme != "file_aes" {
		return nil, false
	}
	if recordName, ok := record["name"].(string); ok && recordName != name {
		return nil, false
	}
	nonce, err := decodeSeedPart(fmt.Sprint(record["nonce"]))
	if err != nil {
		return nil, false
	}
	ciphertext, err := decodeSeedPart(fmt.Sprint(record["ciphertext"]))
	if err != nil {
		return nil, false
	}
	tag, err := decodeSeedPart(fmt.Sprint(record["tag"]))
	if err != nil {
		return nil, false
	}
	block, err := aes.NewCipher(deriveSeedFieldKey(master, scope, name))
	if err != nil {
		return nil, false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	plaintext, err := aead.Open(nil, nonce, append(ciphertext, tag...), nil)
	if err != nil {
		return nil, false
	}
	return plaintext, true
}

func encryptSeedRecord(seed []byte, scope, name string, plaintext []byte) (map[string]any, error) {
	return encryptSeedRecordWithMaster(deriveSeedMasterKey(seed), scope, name, plaintext)
}

func encryptSeedRecordWithMaster(master []byte, scope, name string, plaintext []byte) (map[string]any, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(deriveSeedFieldKey(master, scope, name))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	return map[string]any{
		"scheme":     "file_aes",
		"name":       name,
		"persisted":  true,
		"nonce":      base64.StdEncoding.EncodeToString(nonce),
		"ciphertext": base64.StdEncoding.EncodeToString(sealed[:len(sealed)-16]),
		"tag":        base64.StdEncoding.EncodeToString(sealed[len(sealed)-16:]),
	}, nil
}

func decodeSeedPart(value string) ([]byte, error) {
	if len(value)%2 == 0 && value != "" && seedMigrationHexPattern.MatchString(value) {
		return hex.DecodeString(value)
	}
	return base64.StdEncoding.DecodeString(value)
}

func splitColumnList(cols string) []string {
	parts := strings.Split(cols, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, strings.TrimSpace(part))
	}
	return out
}

func stringFromDBValue(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return fmt.Sprint(v)
	}
}

func renameSeedPath(seedPath string) bool {
	ts := time.Now().Unix()
	target := fmt.Sprintf("%s.migrated.%d", seedPath, ts)
	for index := 1; ; index++ {
		if _, err := os.Stat(target); os.IsNotExist(err) {
			break
		}
		target = fmt.Sprintf("%s.migrated.%d.%d", seedPath, ts, index)
	}
	return os.Rename(seedPath, target) == nil
}
