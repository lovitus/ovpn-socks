package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEngineInventoryAndExternalInspectionBoundary(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OVPN_SOCKS_ENGINE_DIR", root)
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	if err := os.WriteFile(filepath.Join(root, "flyssh"+suffix), []byte("not executed by inventory"), 0600); err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("a", 40)
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(`{"sources":{"flyssh":{"commit":"`+sha+`"},"gust":{"commit":"secret-not-a-commit"}},"secret":"never-export"}`), 0600); err != nil {
		t.Fatal(err)
	}
	s, _ := fixture(t)
	if w := request(s, "GET", "/api/engines", nil, false, false); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := request(s, "GET", "/api/engines", nil, true, false)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rows []engineBuild
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || !rows[0].Available || !rows[1].Available || rows[1].Commit != sha || rows[2].Available || rows[2].Commit != "" {
		t.Fatal(rows)
	}
	if strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), root) {
		t.Fatal("inventory leaked unexpected manifest fields or path")
	}
	if w := request(s, "GET", "/api/engines/inspect", nil, true, false); w.Code != 405 {
		t.Fatal(w.Code)
	}
	if w := request(s, "POST", "/api/engines/inspect", map[string]string{"engine": "gust", "arguments": "-L :1234"}, true, false); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request(s, "POST", "/api/profiles", map[string]string{"engine": "gust", "name": "missing binary", "arguments": "-L :1234"}, true, true); w.Code != 400 {
		t.Fatal(w.Code, w.Body.String())
	}
	if len(s.store.List()) != 0 {
		t.Fatal("invalid native profile persisted")
	}
}
