package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"capability-broker/internal/audit"
	"capability-broker/internal/capability"

	_ "modernc.org/sqlite"
)

// SQLite persists grants, call history, and the hash-chained audit log.
type SQLite struct {
	DB  *sql.DB
	Mem *Memory
}

func Open(path string) (*SQLite, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &SQLite{DB: db, Mem: NewMemory()}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS audit_log (
  seq INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  kind TEXT,
  task_id TEXT,
  decision TEXT,
  control TEXT,
  reason TEXT,
  tool TEXT,
  operation TEXT,
  resource TEXT,
  grant_id TEXT,
  detail TEXT,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
`)
	return err
}

func (s *SQLite) CreateTask(t Task) error                     { return s.Mem.CreateTask(t) }
func (s *SQLite) GetTask(id string) (Task, bool)              { return s.Mem.GetTask(id) }
func (s *SQLite) PutGrant(g capability.Grant) error           { return s.Mem.PutGrant(g) }
func (s *SQLite) GrantsFor(taskID string) []capability.Grant  { return s.Mem.GrantsFor(taskID) }
func (s *SQLite) GetGrant(id string) (capability.Grant, bool) { return s.Mem.GetGrant(id) }
func (s *SQLite) MarkRevoked(grantID string) error            { return s.Mem.MarkRevoked(grantID) }
func (s *SQLite) RecordCall(c CallRecord) error               { return s.Mem.RecordCall(c) }
func (s *SQLite) History(taskID string) []CallRecord          { return s.Mem.History(taskID) }

func (s *SQLite) PersistAudit(e audit.Entry) error {
	var detail string
	if len(e.Detail) > 0 {
		detail = string(e.Detail)
	}
	_, err := s.DB.Exec(`INSERT INTO audit_log(seq,ts,kind,task_id,decision,control,reason,tool,operation,resource,grant_id,detail,prev_hash,hash)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.Seq, e.Timestamp.Format(time.RFC3339Nano), e.Kind, e.TaskID, e.Decision, e.Control, e.Reason,
		e.Tool, e.Operation, e.Resource, e.GrantID, detail, e.PrevHash, e.Hash)
	return err
}

func (s *SQLite) LoadAudit() ([]audit.Entry, error) {
	rows, err := s.DB.Query(`SELECT seq,ts,kind,task_id,decision,control,reason,tool,operation,resource,grant_id,detail,prev_hash,hash FROM audit_log ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []audit.Entry
	for rows.Next() {
		var e audit.Entry
		var ts, detail string
		if err := rows.Scan(&e.Seq, &ts, &e.Kind, &e.TaskID, &e.Decision, &e.Control, &e.Reason,
			&e.Tool, &e.Operation, &e.Resource, &e.GrantID, &detail, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		if detail != "" {
			e.Detail = json.RawMessage(detail)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLite) Close() error {
	if s.DB != nil {
		return s.DB.Close()
	}
	return nil
}

func MustOpen(path string) *SQLite {
	s, err := Open(path)
	if err != nil {
		panic(fmt.Errorf("sqlite: %w", err))
	}
	return s
}
