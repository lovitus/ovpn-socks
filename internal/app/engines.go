package app

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/lovitus/ovpn-socks/internal/config"
	"github.com/lovitus/ovpn-socks/internal/engine"
)

type engineBuild struct {
	Engine           string `json:"engine"`
	Available        bool   `json:"available"`
	Commit           string `json:"commit,omitempty"`
	DependencyCommit string `json:"dependency_commit,omitempty"`
}

func (s *Server) engines(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, 405, errors.New("method not allowed"))
		return
	}
	root := os.Getenv("OVPN_SOCKS_ENGINE_DIR")
	if root == "" {
		if exe, err := os.Executable(); err == nil {
			root = filepath.Join(filepath.Dir(exe), "engines")
		}
	}
	var manifest struct {
		Sources map[string]struct {
			Commit string `json:"commit"`
		} `json:"sources"`
	}
	if filepath.IsAbs(root) {
		if f, err := os.Open(filepath.Join(root, "manifest.json")); err == nil {
			_ = json.NewDecoder(io.LimitReader(f, 64*1024)).Decode(&manifest)
			_ = f.Close()
		}
	}
	out := []engineBuild{{Engine: "openvpn", Available: true}}
	for _, name := range []string{"flyssh", "gust"} {
		item := engineBuild{Engine: name}
		file := name
		if runtime.GOOS == "windows" {
			file += ".exe"
		}
		if filepath.IsAbs(root) {
			if st, err := os.Stat(filepath.Join(root, file)); err == nil && st.Mode().IsRegular() {
				item.Available = true
			}
		}
		if sha := manifest.Sources[name].Commit; validCommit(sha) {
			item.Commit = sha
		}
		if name == "gust" {
			if sha := manifest.Sources["gust-x"].Commit; validCommit(sha) {
				item.DependencyCommit = sha
			}
		}
		out = append(out, item)
	}
	writeJSON(w, out)
}
func validCommit(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func engineOptions(p config.Profile) engine.Options {
	return engine.Options{ID: p.ID, Name: p.Name, Engine: p.EngineName(), Arguments: p.Arguments, ConfigText: p.EngineConfig, ConfigFormat: p.ConfigFormat, WorkingDirectory: p.WorkingDirectory, AutoReconnect: p.AutoReconnect}
}
func listenerDeclarations(list []engine.Listener) []config.Listener {
	out := make([]config.Listener, 0, len(list))
	for _, l := range list {
		out = append(out, config.Listener{ID: l.ID, Network: l.Network, Address: l.Address, Scope: l.Scope, Kind: l.Kind})
	}
	return out
}
func (s *Server) inspectEngine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, 405, errors.New("method not allowed"))
		return
	}
	var p config.Profile
	if err := decode(w, r, &p); err != nil {
		fail(w, 400, err)
		return
	}
	if p.EngineName() == "openvpn" {
		fail(w, 400, errors.New("请选择 flyssh 或 gust 引擎"))
		return
	}
	result, err := engine.Inspect(r.Context(), engineOptions(p))
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, result)
}
