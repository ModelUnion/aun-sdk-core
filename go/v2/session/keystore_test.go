package session

import (
	"bytes"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestStore(t *testing.T) *V2KeyStore {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := NewV2KeyStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSaveLoadIK(t *testing.T) {
	s := newTestStore(t)
	priv := bytes.Repeat([]byte{0xAB}, 32)
	pubDER := []byte("pub-der-bytes")

	if err := s.SaveIK("dev1", priv, pubDER); err != nil {
		t.Fatal(err)
	}
	p, pd, err := s.LoadIK("dev1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, priv) || !bytes.Equal(pd, pubDER) {
		t.Fatalf("ik mismatch: priv=%x pub=%x", p, pd)
	}
}

func TestLoadIK_NotFound(t *testing.T) {
	s := newTestStore(t)
	p, pd, err := s.LoadIK("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if p != nil || pd != nil {
		t.Fatalf("expected nil, got priv=%v pub=%v", p, pd)
	}
}

func TestSaveLoadSPK_AndCurrent(t *testing.T) {
	s := newTestStore(t)
	if err := s.SaveSPK("dev1", "spk-1", []byte("priv1"), []byte("pub1")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond) // 确保 created_at 不同
	if err := s.SaveSPK("dev1", "spk-2", []byte("priv2"), []byte("pub2")); err != nil {
		t.Fatal(err)
	}

	id, priv, pub, err := s.LoadCurrentSPK("dev1")
	if err != nil {
		t.Fatal(err)
	}
	if id != "spk-2" {
		t.Fatalf("LoadCurrentSPK got %s, want spk-2", id)
	}
	if !bytes.Equal(priv, []byte("priv2")) || !bytes.Equal(pub, []byte("pub2")) {
		t.Fatal("current spk content mismatch")
	}

	// 加载具体 spk_id
	p1, err := s.LoadSPK("dev1", "spk-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p1, []byte("priv1")) {
		t.Fatalf("spk-1 mismatch: %x", p1)
	}

	// 不存在的 spk_id
	p3, err := s.LoadSPK("dev1", "spk-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	if p3 != nil {
		t.Fatal("expected nil for missing spk")
	}
}

func TestLoadCurrentSPK_NoSPK(t *testing.T) {
	s := newTestStore(t)
	id, priv, pub, err := s.LoadCurrentSPK("dev-empty")
	if err != nil {
		t.Fatal(err)
	}
	if id != "" || priv != nil || pub != nil {
		t.Fatalf("expected empty, got id=%s priv=%v pub=%v", id, priv, pub)
	}
}

func TestDeleteSPK_PFS(t *testing.T) {
	s := newTestStore(t)
	if err := s.SaveSPK("dev1", "spk-old", []byte("priv-old"), []byte("pub-old")); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSPK("dev1", "spk-old"); err != nil {
		t.Fatal(err)
	}
	p, err := s.LoadSPK("dev1", "spk-old")
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Fatal("SPK should be destroyed")
	}
}

func TestDeleteSPK_Missing_NoError(t *testing.T) {
	s := newTestStore(t)
	if err := s.DeleteSPK("dev1", "never-saved"); err != nil {
		t.Fatalf("delete missing should not error: %v", err)
	}
}

func TestListRecentSPKIDs(t *testing.T) {
	s := newTestStore(t)
	for i := 0; i < 10; i++ {
		spkID := fmt.Sprintf("spk-%d", i)
		// 用显式 created_at 确保顺序稳定
		if err := s.SaveSPKWithCreatedAt("dev1", spkID, []byte("priv"), []byte("pub"), int64(1000+i)); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := s.ListRecentSPKIDs("dev1", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 {
		t.Fatalf("expected 3, got %d", len(ids))
	}
	// 最新 3 个：spk-9, spk-8, spk-7
	want := []string{"spk-9", "spk-8", "spk-7"}
	for i, id := range ids {
		if id != want[i] {
			t.Fatalf("idx %d: got %s want %s", i, id, want[i])
		}
	}
}

func TestListRecentSPKIDs_NonPositiveN(t *testing.T) {
	s := newTestStore(t)
	if err := s.SaveSPK("dev1", "spk-a", []byte("p"), []byte("pub")); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, -1} {
		ids, err := s.ListRecentSPKIDs("dev1", n)
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) != 0 {
			t.Fatalf("n=%d expected empty, got %v", n, ids)
		}
	}
}

func TestListRecentSPKIDs_Empty(t *testing.T) {
	s := newTestStore(t)
	ids, err := s.ListRecentSPKIDs("no-such-dev", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected empty, got %v", ids)
	}
}

func TestSaveSPK_PrimaryKeyReplace(t *testing.T) {
	// 同 (device_id, key_type, key_id) 重复保存应覆盖
	s := newTestStore(t)
	if err := s.SaveSPK("dev1", "spk-1", []byte("v1"), []byte("p1")); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSPK("dev1", "spk-1", []byte("v2"), []byte("p2")); err != nil {
		t.Fatal(err)
	}
	priv, err := s.LoadSPK("dev1", "spk-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv, []byte("v2")) {
		t.Fatalf("expected replaced value v2, got %s", priv)
	}
}

func TestSaveLoadSPK_MultiDevice(t *testing.T) {
	s := newTestStore(t)
	if err := s.SaveSPK("devA", "spk-1", []byte("A1"), []byte("Apub")); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSPK("devB", "spk-1", []byte("B1"), []byte("Bpub")); err != nil {
		t.Fatal(err)
	}
	pa, _ := s.LoadSPK("devA", "spk-1")
	pb, _ := s.LoadSPK("devB", "spk-1")
	if !bytes.Equal(pa, []byte("A1")) || !bytes.Equal(pb, []byte("B1")) {
		t.Fatal("device-scoped lookup failed")
	}
}

func TestMigrateLegacyDeviceKeysAllowsNullUploadedMarkers(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec(`CREATE TABLE v2_device_keys (
		device_id TEXT NOT NULL,
		key_type TEXT NOT NULL,
		key_id TEXT NOT NULL DEFAULT '',
		private_key BLOB,
		public_key BLOB,
		created_at INTEGER NOT NULL,
		PRIMARY KEY (device_id, key_type, key_id)
	)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO v2_device_keys (device_id, key_type, key_id, private_key, public_key, created_at) VALUES
		('dev1', 'spk', 'spk-1', x'01', x'02', 1),
		('dev1', 'spk_uploaded', 'spk-1', NULL, NULL, 2),
		('dev1', 'group_spk', 'group-1' || char(0) || 'gspk-1', x'03', x'04', 3),
		('dev1', 'group_spk_uploaded', 'group-1' || char(0) || 'gspk-1', NULL, NULL, 4)
	`)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewV2KeyStore(db)
	if err != nil {
		t.Fatalf("legacy migration should tolerate NULL uploaded markers: %v", err)
	}
	spkID, err := store.LoadLatestUploadedSPKID("dev1")
	if err != nil {
		t.Fatal(err)
	}
	if spkID != "spk-1" {
		t.Fatalf("uploaded SPK marker mismatch: got %q", spkID)
	}
	groupSPKID, err := store.LoadLatestUploadedGroupSPKID("dev1", "group-1")
	if err != nil {
		t.Fatal(err)
	}
	if groupSPKID != "gspk-1" {
		t.Fatalf("uploaded group SPK marker mismatch: got %q", groupSPKID)
	}
}

func TestGroupSPKNewRecordsDoNotUseLegacyCompositeKey(t *testing.T) {
	s := newTestStore(t)
	if err := s.SaveGroupSPK("dev1", "group-1", "gspk-1", []byte("gpriv"), []byte("gpub")); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkGroupSPKUploaded("dev1", "group-1", "gspk-1"); err != nil {
		t.Fatal(err)
	}

	rows, err := s.db.Query(`SELECT group_id, key_id FROM v2_device_keys WHERE device_id='dev1' AND key_type IN ('group_spk', 'group_spk_uploaded')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		var groupID, keyID string
		if err := rows.Scan(&groupID, &keyID); err != nil {
			t.Fatal(err)
		}
		if groupID != "group-1" || keyID != "gspk-1" {
			t.Fatalf("new group SPK record should use group_id/key_id columns, got group_id=%q key_id=%q", groupID, keyID)
		}
		if strings.Contains(keyID, "\x00") {
			t.Fatalf("new group SPK key_id must not contain NUL: %q", keyID)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected group key + uploaded marker, got %d rows", count)
	}
}
