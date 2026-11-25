package app

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lovitus/ovpn-socks/internal/config"
	"github.com/lovitus/ovpn-socks/internal/engine"
	"github.com/lovitus/ovpn-socks/internal/ovpnconfig"
	"github.com/lovitus/ovpn-socks/internal/vpn"
)

//go:embed web/*
var assets embed.FS

// managedSession keeps profile lifecycle independent of its network engine.
// Implementations return bounded snapshots and stop all owned resources.
type managedSession interface {
	Snapshot() vpn.Snapshot
	Summary() vpn.Snapshot
	Metrics() vpn.MetricsSnapshot
	Stop()
}

type Server struct {
	store        *config.Store
	openvpn      string
	authMu       sync.Mutex
	logins       map[string]time.Time
	authTokens   float64
	authLast     time.Time
	mu           sync.Mutex
	sessions     map[string]managedSession
	ctx          context.Context
	cancel       context.CancelFunc
	startedAt    time.Time
	runtimeMu    sync.Mutex
	runtimeAt    time.Time
	runtimeStats runtimeStats
}

func New(store *config.Store, openvpn string) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{startedAt: time.Now(), store: store, openvpn: openvpn, logins: map[string]time.Time{}, authTokens: 10, authLast: time.Now(), sessions: map[string]managedSession{}, ctx: ctx, cancel: cancel}, nil
}
func (s *Server) URL(addr string) string {
	return "http://" + addr + "/"
}
func (s *Server) Close() {
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, session := range s.sessions {
		session.Stop()
	}
}
func (s *Server) AutoStart() []error {
	var errs []error
	for _, p := range s.store.List() {
		if p.AutoConnect {
			if err := s.start(p); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", p.Name, err))
			}
		}
	}
	return errs
}
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serve) }
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if r.Header.Get("X-OVPN-Socks") != "1" {
			http.Error(w, "missing request header", http.StatusForbidden)
			return
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != scheme+"://"+r.Host {
			http.Error(w, "invalid origin", http.StatusForbidden)
			return
		}
	}
	if s.authRoute(w, r) {
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") && !s.authenticated(r) {
		fail(w, http.StatusUnauthorized, errors.New("请先登录"))
		return
	}
	switch {
	case r.URL.Path == "/api/engines":
		s.engines(w, r)
	case r.URL.Path == "/api/engines/inspect":
		s.inspectEngine(w, r)
	case r.URL.Path == "/api/metrics":
		s.metrics(w, r)
	case r.URL.Path == "/api/profiles":
		s.profiles(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/profiles/"):
		s.profile(w, r)
	case r.URL.Path == "/api/info":
		if r.Method != http.MethodGet {
			fail(w, 405, errors.New("method not allowed"))
			return
		}
		writeJSON(w, map[string]any{"openvpn": s.openvpn, "default_socks": "0.0.0.0:1080", "udp_associate": false})
	case r.URL.Path == "/" || r.URL.Path == "/app.js" || r.URL.Path == "/style.css":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		b, err := assets.ReadFile("web/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		ct := map[string]string{"index.html": "text/html; charset=utf-8", "app.js": "application/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8"}
		w.Header().Set("Content-Type", ct[name])
		_, _ = w.Write(b)
	default:
		http.NotFound(w, r)
	}
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("expected one JSON object")
	}
	return nil
}

type view struct {
	ID            string               `json:"id"`
	Name          string               `json:"name"`
	Username      string               `json:"username"`
	Listen        string               `json:"listen"`
	AutoConnect   bool                 `json:"auto_connect"`
	AutoReconnect bool                 `json:"auto_reconnect"`
	TOTPMode      string               `json:"totp_mode"`
	HasPassword   bool                 `json:"has_password"`
	HasTOTP       bool                 `json:"has_totp"`
	Status        vpn.Snapshot         `json:"status"`
	Engine        string               `json:"engine"`
	Listeners     []config.Listener    `json:"listeners,omitempty"`
	EngineStatus  *engine.EngineStatus `json:"engine_status,omitempty"`
}

func (s *Server) describe(p config.Profile) view {
	return s.describeSummary(p, false)
}
func (s *Server) describeSummary(p config.Profile, summary bool) view {
	v := view{ID: p.ID, Name: p.Name, Username: p.Username, Listen: p.Listen, AutoConnect: p.AutoConnect, AutoReconnect: p.AutoReconnect, TOTPMode: p.TOTPMode, HasPassword: p.Password != "", HasTOTP: p.TOTPSeed != "", Status: vpn.Snapshot{ID: p.ID, State: "stopped", Listen: p.Listen}}
	v.Engine = p.EngineName()
	v.Listeners = p.Listeners
	s.mu.Lock()
	defer s.mu.Unlock()
	if session := s.sessions[p.ID]; session != nil {
		if external, ok := session.(interface{ EngineStatus() engine.EngineStatus }); ok {
			state := external.EngineStatus()
			v.EngineStatus = &state
		}
		if summary {
			v.Status = session.Summary()
		} else {
			v.Status = session.Snapshot()
		}
	}
	return v
}
func (s *Server) profiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		result := []view{}
		for _, p := range s.store.List() {
			result = append(result, s.describeSummary(p, r.URL.Query().Get("summary") == "1"))
		}
		writeJSON(w, result)
	case http.MethodPost:
		var input struct {
			config.Profile
			ClearPassword bool `json:"clear_password"`
			ClearTOTP     bool `json:"clear_totp"`
		}
		if err := decode(w, r, &input); err != nil {
			fail(w, 400, err)
			return
		}
		if input.ID != "" {
			old, ok := s.store.Get(input.ID)
			if !ok {
				fail(w, 404, errors.New("配置不存在"))
				return
			}
			s.mu.Lock()
			session := s.sessions[input.ID]
			s.mu.Unlock()
			if session != nil {
				fail(w, 409, errors.New("请先停止连接再编辑配置"))
				return
			}
			if input.Password == "" && !input.ClearPassword {
				input.Password = old.Password
			}
			if input.TOTPSeed == "" && !input.ClearTOTP {
				input.TOTPSeed = old.TOTPSeed
			}
		}
		if input.ClearPassword {
			input.Password = ""
		}
		if input.ClearTOTP {
			input.TOTPSeed = ""
			input.TOTPMode = ""
		}
		if input.EngineName() == "openvpn" {
			input.Listeners = nil
			if _, err := ovpnconfig.Parse(input.OVPN); err != nil {
				fail(w, 400, err)
				return
			}
		} else {
			result, err := engine.Inspect(r.Context(), engineOptions(input.Profile))
			if err != nil {
				fail(w, 400, err)
				return
			}
			input.Listeners = listenerDeclarations(result.Listeners)
		}
		s.mu.Lock()
		if input.ID != "" {
			if _, exists := s.store.Get(input.ID); !exists {
				s.mu.Unlock()
				fail(w, 404, errors.New("配置已删除"))
				return
			}
		}
		if input.ID != "" && s.sessions[input.ID] != nil {
			s.mu.Unlock()
			fail(w, 409, errors.New("连接已启动，请先停止连接再编辑配置"))
			return
		}
		p, err := s.store.Save(input.Profile)
		s.mu.Unlock()
		if err != nil {
			fail(w, 400, err)
			return
		}
		writeJSON(w, s.describe(p))
	default:
		fail(w, 405, errors.New("method not allowed"))
	}
}
func (s *Server) profile(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/profiles/"), "/")
	if len(parts) > 2 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	p, ok := s.store.Get(id)
	if !ok {
		fail(w, 404, errors.New("配置不存在"))
		return
	}
	if len(parts) == 2 {
		if parts[1] == "status" {
			if r.Method != http.MethodGet {
				fail(w, 405, errors.New("method not allowed"))
				return
			}
			writeJSON(w, s.describe(p).Status)
			return
		}
		if r.Method != http.MethodPost {
			fail(w, 405, errors.New("method not allowed"))
			return
		}
		switch parts[1] {
		case "export":
			s.exportRoutes(w, r, p)
			return
		case "start":
			if err := s.start(p); err != nil {
				fail(w, 400, err)
				return
			}
		case "stop":
			s.mu.Lock()
			if session := s.sessions[id]; session != nil {
				session.Stop()
				delete(s.sessions, id)
			}
			s.mu.Unlock()
		default:
			http.NotFound(w, r)
			return
		}
		writeJSON(w, s.describe(p))
		return
	}
	switch r.Method {
	case http.MethodGet:
		p.Password = ""
		p.TOTPSeed = ""
		writeJSON(w, p)
	case http.MethodDelete:
		s.mu.Lock()
		if session := s.sessions[id]; session != nil {
			session.Stop()
			delete(s.sessions, id)
		}
		err := s.store.Delete(id)
		s.mu.Unlock()
		if err != nil {
			fail(w, 500, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	default:
		fail(w, 405, errors.New("method not allowed"))
	}
}
func (s *Server) start(p config.Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	latest, ok := s.store.Get(p.ID)
	if !ok {
		return errors.New("配置不存在")
	}
	p = latest
	if s.sessions[p.ID] != nil {
		return errors.New("连接已启动，请先停止再重启")
	}
	if p.EngineName() != "openvpn" {
		session, err := engine.Start(s.ctx, engineOptions(p))
		if err != nil {
			return err
		}
		s.sessions[p.ID] = session
		return nil
	}
	session, err := vpn.Start(s.ctx, vpn.Options{ID: p.ID, Name: p.Name, Config: p.OVPN, Username: p.Username, Listen: p.Listen, OpenVPNPath: s.openvpn, AutoReconnect: p.AutoReconnect, Password: func() (string, error) { return p.AuthPassword(time.Now()) }})
	if err != nil {
		return err
	}
	s.sessions[p.ID] = session
	return nil
}

func ValidateListen(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if host != "" && ip == nil {
		return errors.New("管理地址必须是 IP，例如 0.0.0.0:2080 或 [::]:2080")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return errors.New("invalid port")
	}
	return nil
}
