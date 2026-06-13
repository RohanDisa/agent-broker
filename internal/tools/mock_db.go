package tools

import (
	"fmt"
	"strings"
	"sync"

	"capability-broker/internal/injection"
)

type record struct {
	ID         string
	Body       string
	Sensitive  bool
	Provenance injection.Provenance
}

type DB struct {
	mu   sync.Mutex
	rows map[string]record
}

func NewDB() *DB {
	d := &DB{rows: make(map[string]record)}
	d.rows["db://customers/123/profile"] = record{
		ID:         "123",
		Body:       "customer_record id=123 name=Ada Lovelace ssn=123-45-6789 home_address=12 Market St",
		Sensitive:  true,
		Provenance: injection.Provenance{Source: injection.Tool, Origin: "db://customers/123/profile"},
	}
	d.rows["db://customers/124/profile"] = record{
		ID:         "124",
		Body:       "customer_record id=124 name=Grace Hopper ssn=987-65-4321 home_address=9 Navy Way",
		Sensitive:  true,
		Provenance: injection.Provenance{Source: injection.Tool, Origin: "db://customers/124/profile"},
	}
	return d
}

func (d *DB) Name() string { return "db" }

func (d *DB) Exec(req Request) Result {
	switch req.Operation {
	case "read":
		d.mu.Lock()
		rec, ok := d.rows[req.Resource]
		d.mu.Unlock()
		if !ok {
			return Result{Error: "db: not found"}
		}
		p := rec.Provenance
		if req.Provenance.Source != "" {
			p = rec.Provenance
			p.Source = injection.Worst(rec.Provenance.Effective(), req.Provenance.Effective())
			p.TaintChain = append(append([]injection.Source{}, rec.Provenance.TaintChain...), req.Provenance.Effective())
		}
		return Result{OK: true, Output: rec.Body, Provenance: p, Sensitive: rec.Sensitive, Records: 1}
	case "write":
		body := arg(req.Arguments, "body")
		if body == "" {
			body = arg(req.Arguments, "value")
		}
		d.mu.Lock()
		prev, ok := d.rows[req.Resource]
		rec := record{
			ID:         req.Resource,
			Body:       body,
			Sensitive:  true,
			Provenance: req.Provenance.Inherit(injection.Tool, req.Resource),
		}
		if ok {
			rec.Provenance.Source = injection.Worst(prev.Provenance.Effective(), rec.Provenance.Effective())
			rec.Provenance.TaintChain = append(prev.Provenance.TaintChain, rec.Provenance.Effective())
			if prev.Sensitive {
				rec.Sensitive = true
			}
		}
		if injection.LooksSensitive(body) {
			rec.Sensitive = true
		}
		d.rows[req.Resource] = rec
		d.mu.Unlock()
		return Result{OK: true, Output: "wrote " + req.Resource, Provenance: rec.Provenance, Sensitive: rec.Sensitive}
	case "delete":
		d.mu.Lock()
		delete(d.rows, req.Resource)
		d.mu.Unlock()
		return Result{OK: true, Output: "deleted " + req.Resource, Provenance: injection.Provenance{Source: injection.Tool}}
	default:
		return Result{Error: fmt.Sprintf("db: unknown operation %s", req.Operation)}
	}
}

func (d *DB) Get(resource string) (record, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.rows[resource]
	return r, ok
}

func (d *DB) SeedNote(resource, body string, p injection.Provenance) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rows[resource] = record{ID: resource, Body: body, Sensitive: strings.Contains(body, "customer_record") || injection.LooksSensitive(body), Provenance: p}
}
