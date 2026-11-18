package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lovitus/ovpn-socks/internal/config"
)

func authRequest(s *Server, method, path string, body any, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, "http://192.168.1.10:2080"+path, &buf)
	r.Header.Set("X-OVPN-Socks", "1")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func login(t *testing.T, s *Server, username, password string) *http.Cookie {
	t.Helper()
	w := authRequest(s, "POST", "/api/login", map[string]string{"username": username, "password": password}, nil, "http://192.168.1.10:2080")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing cookie")
	}
	c := cookies[0]
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.MaxAge != 43200 || c.Path != "/" || time.Until(c.Expires) < 11*time.Hour {
		t.Fatal("invalid cookie", c)
	}
	return c
}

func TestAccountChangeInvalidatesAndPersists(t *testing.T) {
	dir := t.TempDir()
	store, err := config.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(store, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c1 := login(t, s, "admin", "admin")
	c2 := login(t, s, "admin", "admin")
	if c1.Value == c2.Value {
		t.Fatal("sessions are not independent")
	}
	input := map[string]string{"current_password": "incorrect", "username": "new-admin", "password": "new-secret"}
	if w := authRequest(s, "POST", "/api/account", input, nil, ""); w.Code != 401 {
		t.Fatal("unauthenticated account update", w.Code)
	}
	if w := authRequest(s, "POST", "/api/account", input, c1, ""); w.Code != 401 {
		t.Fatal("wrong current password accepted", w.Code)
	}
	input["current_password"] = "admin"
	if w := authRequest(s, "POST", "/api/account", input, c1, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, cookie := range []*http.Cookie{c1, c2} {
		if w := authRequest(s, "GET", "/api/profiles", nil, cookie, ""); w.Code != 401 {
			t.Fatal("old session accepted")
		}
	}
	for _, credentials := range [][2]string{{"admin", "admin"}, {"new-admin", "admin"}, {"admin", "new-secret"}} {
		if w := authRequest(s, "POST", "/api/login", map[string]string{"username": credentials[0], "password": credentials[1]}, nil, ""); w.Code != 401 {
			t.Fatal("old credentials accepted", w.Code)
		}
	}
	c3 := login(t, s, "new-admin", "new-secret")
	data, err := os.ReadFile(filepath.Join(dir, "admin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("new-secret")) || bytes.Contains(data, []byte(`"password"`)) || !bytes.Contains(data, []byte(`"salt"`)) || !bytes.Contains(data, []byte(`"hash"`)) {
		t.Fatal("account hash storage failed", string(data))
	}
	reopened, err := config.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := New(reopened, "")
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if w := authRequest(restarted, "GET", "/api/profiles", nil, c3, ""); w.Code != 401 {
		t.Fatal("session survived restart")
	}
	c4 := login(t, restarted, "new-admin", "new-secret")
	if w := authRequest(restarted, "POST", "/api/login", map[string]string{"username": "admin", "password": "admin"}, nil, ""); w.Code != 401 {
		t.Fatal("default account returned after restart")
	}
	if w := authRequest(restarted, "POST", "/api/account", map[string]string{"current_password": "new-secret", "username": "renamed", "password": ""}, c4, ""); w.Code != 200 {
		t.Fatal("username-only update", w.Code, w.Body.String())
	}
	login(t, restarted, "renamed", "new-secret")
}

func TestOriginAndSessionExpiry(t *testing.T) {
	s, _ := fixture(t)
	input := map[string]string{"username": "admin", "password": "admin"}
	for _, origin := range []string{"http://evil.test", "https://192.168.1.10:2080", "null", "http://192.168.1.10:2081"} {
		if w := authRequest(s, "POST", "/api/login", input, nil, origin); w.Code != 403 {
			t.Fatal("cross-origin login accepted", origin, w.Code)
		}
	}
	cookie := login(t, s, "admin", "admin")
	for _, path := range []string{"/api/account", "/api/logout", "/api/profiles"} {
		if w := authRequest(s, "POST", path, map[string]string{}, cookie, "http://evil.test"); w.Code != 403 {
			t.Fatal("cross-origin mutation accepted", path, w.Code)
		}
	}
	s.authMu.Lock()
	s.logins[cookie.Value] = time.Now().Add(-time.Second)
	s.authMu.Unlock()
	if w := authRequest(s, "GET", "/api/profiles", nil, cookie, ""); w.Code != 401 {
		t.Fatal("expired session accepted")
	}
	cookie = login(t, s, "admin", "admin")
	if w := authRequest(s, "POST", "/api/logout", nil, cookie, ""); w.Code != 200 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout failed")
	}
	if w := authRequest(s, "GET", "/api/profiles", nil, cookie, ""); w.Code != 401 {
		t.Fatal("logged-out session accepted")
	}
}

func TestPasswordRateLimit(t *testing.T) {
	s, _ := fixture(t)
	// Exercise the exhausted bucket without spending CPU on ten password hashes.
	s.authMu.Lock()
	s.authTokens = 0
	s.authLast = time.Now()
	s.authMu.Unlock()
	w := authRequest(s, "POST", "/api/login", map[string]string{"username": "admin", "password": "admin"}, nil, "")
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("no rate limit", w.Code)
	}
}

func TestValidateListen(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:2080", "192.168.1.1:2080", "[::]:2080", "[2001:db8::1]:2080", ":2080", "127.0.0.1:0"} {
		if err := ValidateListen(addr); err != nil {
			t.Fatal(addr, err)
		}
	}
	for _, addr := range []string{"localhost:2080", "example.com:2080", "0.0.0.0:65536", "0.0.0.0:-1", "::2080"} {
		if err := ValidateListen(addr); err == nil {
			t.Fatal("accepted", addr)
		}
	}
	s, _ := fixture(t)
	if u := s.URL("192.168.1.10:2080"); u != "http://192.168.1.10:2080/" {
		t.Fatal(u)
	}
}
