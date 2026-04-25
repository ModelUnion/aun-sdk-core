package keystore

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSQLiteInteropDriver(t *testing.T) {
	if os.Getenv("AUN_SQLITE_INTEROP_DRIVER") != "1" {
		t.Skip("interop driver only")
	}
	root := os.Getenv("AUN_SQLITE_INTEROP_ROOT")
	aid := os.Getenv("AUN_SQLITE_INTEROP_AID")
	action := os.Getenv("AUN_SQLITE_INTEROP_ACTION")
	if root == "" || aid == "" || action == "" {
		t.Fatal("missing interop env")
	}
	ks, err := NewFileKeyStore(root, nil, "interop-seed")
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}
	defer ks.Close()
	switch action {
	case "write-go":
		if err := ks.SaveE2EEPrekey(aid, "go-prekey", "", map[string]any{"private_key_pem": "GO-PREKEY-SECRET", "created_at": int64(1)}); err != nil {
			t.Fatalf("SaveE2EEPrekey: %v", err)
		}
		if err := ks.SaveGroupSecretState(aid, "go-group", map[string]any{"epoch": int64(1), "secret": "GO-GROUP-SECRET"}); err != nil {
			t.Fatalf("SaveGroupSecretState: %v", err)
		}
		if err := ks.SaveE2EESession(aid, "go-session", map[string]any{"secret": "GO-SESSION-SECRET"}); err != nil {
			t.Fatalf("SaveE2EESession: %v", err)
		}
	case "read-all":
		prekeys, err := ks.LoadE2EEPrekeys(aid, "")
		if err != nil {
			t.Fatalf("LoadE2EEPrekeys: %v", err)
		}
		groups, err := ks.LoadAllGroupSecretStates(aid)
		if err != nil {
			t.Fatalf("LoadAllGroupSecretStates: %v", err)
		}
		sessions, err := ks.LoadE2EESessions(aid)
		if err != nil {
			t.Fatalf("LoadE2EESessions: %v", err)
		}
		payload := map[string]any{"prekeys": prekeys, "groups": groups, "sessions": sessions}
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		_, _ = os.Stdout.Write(encoded)
		_, _ = os.Stdout.Write([]byte("\n"))
	default:
		t.Fatalf("unknown action %q", action)
	}
}
