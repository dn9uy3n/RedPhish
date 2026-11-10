package core

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/kgretzky/evilginx2/database"
)

func newSessionTestServer(t *testing.T) (*apiServer, *database.Database) {
	t.Helper()
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatalf("db: %v", err)
	}

	a, c := newApiTestServer(t)
	t.Cleanup(func() { _ = db.Close() })
	a.db = db
	_ = c
	return a, db
}

func listSessions(a *apiServer, target string) []map[string]interface{} {
	rec := httptest.NewRecorder()
	a.handleSessions(rec, httptest.NewRequest("GET", target, nil))
	var rows []map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &rows)
	return rows
}

func TestSessionCompletedDefaultsFalseAndPersists(t *testing.T) {
	_, db := newSessionTestServer(t)
	if err := db.CreateSession("s1", "edds", "", "https://e/1", "UA", "203.0.113.1"); err != nil {
		t.Fatalf("create: %v", err)
	}
	s, err := db.GetSessionById(1)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if s.Completed {
		t.Fatal("new session must not be completed")
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

func TestSessionFinishWritesCompleted(t *testing.T) {
	_, db := newSessionTestServer(t)
	s, err := NewSession("edds", db)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	if err := db.CreateSession(s.Id, "edds", "", "https://e/1", "UA", "203.0.113.1"); err != nil {
		t.Fatalf("create: %v", err)
	}
	s.Finish(false)
	got, err := db.GetSessionById(1)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Completed {
		t.Fatal("Finish did not persist completed")
	}
}

func TestSessionsCarryLureAndFilter(t *testing.T) {
	a, db := newSessionTestServer(t)
	if err := db.CreateSession("s1", "edds", "lure-1", "https://e/1", "UA", "203.0.113.1"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.CreateSession("s2", "edds", "lure-2", "https://e/2", "UA", "203.0.113.2"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.CreateSession("s3", "armgs", "lure-1", "https://a/1", "UA", "203.0.113.3"); err != nil {
		t.Fatalf("create: %v", err)
	}

	all := listSessions(a, "/sessions")
	if len(all) != 3 {
		t.Fatalf("unfiltered: %d", len(all))
	}
	if all[0]["lure_id"] != "lure-1" {
		t.Fatalf("lure_id not serialized: %v", all[0])
	}

	byLure := listSessions(a, "/sessions?lure=lure-1")
	if len(byLure) != 2 {
		t.Fatalf("lure filter: %d", len(byLure))
	}
	byPhishlet := listSessions(a, "/sessions?phishlet=armgs&lure=lure-1")
	if len(byPhishlet) != 1 || byPhishlet[0]["session_id"] != "s3" {
		t.Fatalf("combined filter: %v", byPhishlet)
	}
	limited := listSessions(a, "/sessions?limit=1")
	if len(limited) != 1 {
		t.Fatalf("limit: %d", len(limited))
	}
	since := listSessions(a, "/sessions?since=1")
	if len(since) != 2 {
		t.Fatalf("since cursor: %d", len(since))
	}
}
