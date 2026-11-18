package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/lovitus/ovpn-socks/internal/config"
)

const sessionLifetime = 12 * time.Hour

func (s *Server) authenticatedLocked(r *http.Request) bool {
	cookie, err := r.Cookie("ovpn_session")
	if err != nil {
		return false
	}
	expiry, ok := s.logins[cookie.Value]
	if !ok {
		return false
	}
	if !time.Now().Before(expiry) {
		delete(s.logins, cookie.Value)
		return false
	}
	return true
}

func (s *Server) authenticated(r *http.Request) bool {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	return s.authenticatedLocked(r)
}

// Bound password hashing work across all source addresses, including parallel requests.
// A burst of ten attempts refills at one attempt every three seconds.
func (s *Server) allowPasswordLocked(w http.ResponseWriter) bool {
	now := time.Now()
	s.authTokens += now.Sub(s.authLast).Seconds() / 3
	if s.authTokens > 10 {
		s.authTokens = 10
	}
	s.authLast = now
	if s.authTokens < 1 {
		w.Header().Set("Retry-After", "3")
		fail(w, http.StatusTooManyRequests, errors.New("尝试过于频繁，请稍后重试"))
		return false
	}
	s.authTokens--
	return true
}

func sessionCookie(r *http.Request, value string, expires time.Time, maxAge int) *http.Cookie {
	return &http.Cookie{Name: "ovpn_session", Value: value, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: maxAge}
}

func (s *Server) authRoute(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/api/auth", "/api/login", "/api/logout", "/api/account":
	default:
		return false
	}
	if (r.URL.Path == "/api/auth" && r.Method != http.MethodGet) || (r.URL.Path != "/api/auth" && r.Method != http.MethodPost) {
		fail(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return true
	}
	s.authMu.Lock()
	defer s.authMu.Unlock()
	switch r.URL.Path {
	case "/api/auth":
		authenticated := s.authenticatedLocked(r)
		username := ""
		if authenticated {
			username = s.store.AccountUsername()
		}
		writeJSON(w, map[string]any{"authenticated": authenticated, "username": username})
	case "/api/login":
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := decode(w, r, &input); err != nil {
			fail(w, 400, errors.New("无效的登录请求"))
			return true
		}
		if !s.allowPasswordLocked(w) {
			return true
		}
		if !s.store.Authenticate(input.Username, input.Password) {
			fail(w, http.StatusUnauthorized, config.ErrCredentials)
			return true
		}
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			fail(w, 500, errors.New("无法创建登录会话"))
			return true
		}
		now := time.Now()
		// Replacing a browser's session and pruning keeps the session table bounded.
		if old, err := r.Cookie("ovpn_session"); err == nil {
			delete(s.logins, old.Value)
		}
		for key, expiry := range s.logins {
			if !now.Before(expiry) {
				delete(s.logins, key)
			}
		}
		if len(s.logins) >= 256 {
			var oldest string
			var earliest time.Time
			for key, expiry := range s.logins {
				if oldest == "" || expiry.Before(earliest) {
					oldest, earliest = key, expiry
				}
			}
			delete(s.logins, oldest)
		}
		token := hex.EncodeToString(random[:])
		expiry := now.Add(sessionLifetime)
		s.logins[token] = expiry
		http.SetCookie(w, sessionCookie(r, token, expiry, int(sessionLifetime.Seconds())))
		writeJSON(w, map[string]bool{"ok": true})
	case "/api/logout":
		if !s.authenticatedLocked(r) {
			fail(w, 401, errors.New("请先登录"))
			return true
		}
		cookie, _ := r.Cookie("ovpn_session")
		delete(s.logins, cookie.Value)
		http.SetCookie(w, sessionCookie(r, "", time.Unix(1, 0), -1))
		writeJSON(w, map[string]bool{"ok": true})
	case "/api/account":
		if !s.authenticatedLocked(r) {
			fail(w, 401, errors.New("请先登录"))
			return true
		}
		var input struct {
			CurrentPassword string `json:"current_password"`
			Username        string `json:"username"`
			Password        string `json:"password"`
		}
		if err := decode(w, r, &input); err != nil {
			fail(w, 400, errors.New("无效的账户请求"))
			return true
		}
		if !s.allowPasswordLocked(w) {
			return true
		}
		if err := s.store.ChangeAccount(input.CurrentPassword, input.Username, input.Password); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, config.ErrCredentials) {
				status = http.StatusUnauthorized
			}
			fail(w, status, err)
			return true
		}
		clear(s.logins)
		http.SetCookie(w, sessionCookie(r, "", time.Unix(1, 0), -1))
		writeJSON(w, map[string]bool{"ok": true})
	}
	return true
}
