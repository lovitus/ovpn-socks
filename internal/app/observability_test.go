package app

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMetricsBoundaryAndRuntime(t *testing.T) {
	s, ovpn := fixture(t)
	for _, path := range []string{"/api/metrics", "/api/metrics?profile=unknown", "/api/profiles/unknown/status"} {
		if w := request(s, "GET", path, nil, false, false); w.Code != 401 {
			t.Fatalf("%s leaked unauthenticated: %d", path, w.Code)
		}
	}
	w := request(s, "GET", "/api/metrics", nil, true, false)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var data struct {
		Current  any          `json:"current"`
		History  []any        `json:"history"`
		Runtime  runtimeStats `json:"runtime"`
		Capacity int          `json:"capacity"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if data.Current != nil || len(data.History) != 0 || data.Capacity != 450 || data.Runtime.HeapAllocBytes == 0 || data.Runtime.Goroutines == 0 || data.Runtime.HeapSysBytes < data.Runtime.HeapAllocBytes {
		t.Fatalf("invalid metrics: %s", w.Body.String())
	}
	if w := request(s, "POST", "/api/metrics", nil, true, true); w.Code != 405 {
		t.Fatal(w.Code)
	}
	if w := request(s, "GET", "/api/metrics?profile=unknown", nil, true, false); w.Code != 404 {
		t.Fatal(w.Code)
	}
	created := request(s, "POST", "/api/profiles", map[string]any{"name": "test", "ovpn": ovpn, "listen": "127.0.0.1:1080"}, true, true)
	if created.Code != 200 {
		t.Fatal(created.Code, created.Body.String())
	}
	var p view
	if err := json.Unmarshal(created.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/profiles?summary=1", "/api/profiles/" + p.ID + "/status", "/api/metrics?profile=" + p.ID} {
		w := request(s, "GET", path, nil, true, false)
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") {
			t.Fatal("configuration leaked into observability")
		}
	}
	if w := request(s, "POST", "/api/profiles/"+p.ID+"/export", map[string]string{"format": "mihomo", "host": "127.0.0.1"}, true, true); w.Code != 400 {
		t.Fatal("empty routes should not export broad rules", w.Code, w.Body.String())
	}
	if w := request(s, "GET", "/api/profiles/"+p.ID+"/export", nil, true, false); w.Code != 405 {
		t.Fatal(w.Code)
	}
	if w := request(s, "POST", "/api/profiles/"+p.ID+"/status", nil, true, true); w.Code != 405 {
		t.Fatal(w.Code)
	}
}

func TestRuntimeSamplingIsCached(t *testing.T) {
	s, _ := fixture(t)
	first := s.runtimeSnapshot()
	at := s.runtimeAt
	second := s.runtimeSnapshot()
	if !at.Equal(s.runtimeAt) || first.GCCycles != second.GCCycles || first.HeapAllocBytes != second.HeapAllocBytes {
		t.Fatal("runtime counters sampled more often than budget")
	}
}
