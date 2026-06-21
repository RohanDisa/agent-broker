package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"capability-broker/internal/broker"
	"capability-broker/internal/capability"
	"capability-broker/internal/server"
)

func TestHTTPAllowedTaskAndAudit(t *testing.T) {
	svc, err := broker.New(broker.Config{TTL: capability.DefaultTTL})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.New(svc).Handler())
	defer ts.Close()

	task := post(t, ts.URL+"/v1/tasks", map[string]any{
		"name": "integ",
		"grants": []map[string]any{{
			"tool": "db", "operation": "read", "resource_pattern": "db://customers/123/*",
		}},
	})
	id, _ := task["task_id"].(string)
	if id == "" {
		t.Fatalf("no task: %v", task)
	}
	call := post(t, ts.URL+"/v1/call", map[string]any{
		"task_id": id, "tool": "db", "operation": "read",
		"resource":   "db://customers/123/profile",
		"provenance": map[string]string{"source": "user"},
	})
	dec := call["decision"].(map[string]any)
	if dec["action"] != "allow" {
		t.Fatalf("want allow: %v", dec)
	}
	var verify map[string]any
	resp, err := http.Post(ts.URL+"/v1/audit/verify", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&verify); err != nil {
		t.Fatal(err)
	}
	if verify["ok"] != true {
		t.Fatalf("audit: %v", verify)
	}
}

func TestHTTPElevationDenyPath(t *testing.T) {
	svc, _ := broker.New(broker.Config{TTL: capability.DefaultTTL})
	ts := httptest.NewServer(server.New(svc).Handler())
	defer ts.Close()
	task := post(t, ts.URL+"/v1/tasks", map[string]any{
		"name": "pay",
		"grants": []map[string]any{{
			"tool": "payments", "operation": "charge", "resource_pattern": "payments://acct/1",
		}},
	})
	id := task["task_id"].(string)
	call := post(t, ts.URL+"/v1/call", map[string]any{
		"task_id": id, "tool": "payments", "operation": "charge",
		"resource": "payments://acct/1", "arguments": map[string]string{"amount": "1"},
	})
	dec := call["decision"].(map[string]any)
	if dec["action"] != "require_elevation" {
		t.Fatalf("%v", dec)
	}
	eid := call["elevation_id"].(string)
	post(t, ts.URL+"/v1/elevate/deny", map[string]any{"id": eid})
	again := post(t, ts.URL+"/v1/call", map[string]any{
		"task_id": id, "tool": "payments", "operation": "charge",
		"resource": "payments://acct/1", "elevation_id": eid,
		"arguments": map[string]string{"amount": "1"},
	})
	if again["decision"].(map[string]any)["action"] != "deny" {
		t.Fatalf("denied elevation must not proceed: %v", again)
	}
}

func post(t *testing.T, url string, body any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}
