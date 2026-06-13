package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"capability-broker/internal/broker"
	"capability-broker/internal/capability"
)

func TestHealthAndTaskCallMetrics(t *testing.T) {
	svc, err := broker.New(broker.Config{TTL: capability.DefaultTTL})
	if err != nil {
		t.Fatal(err)
	}
	h := New(svc).Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rr.Code != 200 {
		t.Fatal(rr.Code)
	}

	body, _ := json.Marshal(map[string]any{
		"name": "s",
		"grants": []map[string]any{{
			"tool": "db", "operation": "read", "resource_pattern": "db://customers/123/*",
		}},
	})
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/tasks", bytes.NewReader(body)))
	if rr.Code != 200 {
		t.Fatalf("tasks %d %s", rr.Code, rr.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	id := created["task_id"].(string)

	call, _ := json.Marshal(map[string]any{
		"task_id": id, "tool": "db", "operation": "read",
		"resource": "db://customers/123/profile",
	})
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/call", bytes.NewReader(call)))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/metrics", nil))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/audit", nil))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/audit/verify", bytes.NewReader([]byte("{}"))))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
}

func TestRevokeAndElevationHTTP(t *testing.T) {
	svc, _ := broker.New(broker.Config{TTL: capability.DefaultTTL})
	h := New(svc).Handler()
	body, _ := json.Marshal(map[string]any{
		"name": "p",
		"grants": []map[string]any{{
			"tool": "payments", "operation": "charge", "resource_pattern": "payments://acct/1",
		}},
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/tasks", bytes.NewReader(body)))
	var created struct {
		TaskID string              `json:"task_id"`
		Grants []capability.Grant  `json:"grants"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &created)

	call, _ := json.Marshal(map[string]any{
		"task_id": created.TaskID, "tool": "payments", "operation": "charge",
		"resource": "payments://acct/1", "arguments": map[string]string{"amount": "1"},
	})
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/tools/call", bytes.NewReader(call)))
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	eid := resp["elevation_id"].(string)

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/elevate/pending", nil))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	approve, _ := json.Marshal(map[string]string{"id": eid})
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/elevate/approve", bytes.NewReader(approve)))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}

	rev, _ := json.Marshal(map[string]string{"grant_id": created.Grants[0].ID})
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/revoke", bytes.NewReader(rev)))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
}

func TestBadJSON(t *testing.T) {
	svc, _ := broker.New(broker.Config{TTL: capability.DefaultTTL})
	h := New(svc).Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/tasks", bytes.NewReader([]byte("{"))))
	if rr.Code != 400 {
		t.Fatal(rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/call", bytes.NewReader([]byte("{"))))
	if rr.Code != 400 {
		t.Fatal(rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/elevate/approve", bytes.NewReader([]byte("{"))))
	if rr.Code != 400 {
		t.Fatal(rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/elevate/deny", bytes.NewReader([]byte(`{"id":"nope"}`))))
	if rr.Code != 400 {
		t.Fatal(rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/revoke", bytes.NewReader([]byte("{"))))
	if rr.Code != 400 {
		t.Fatal(rr.Code)
	}
}
