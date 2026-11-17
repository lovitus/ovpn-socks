package app

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lovitus/ovpn-socks/internal/config"
)

func fixture(t *testing.T) (*Server, string) {
	t.Helper()
	store, err := config.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(store, "")
	if err != nil {
		t.Fatal(err)
	}
	s.URL("127.0.0.1:2080")
	t.Cleanup(s.Close)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ovpn := "client\ndev tun\nremote 127.0.0.1 1194\n<ca>\n" + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + "</ca>\n"
	return s, ovpn
}
func request(s *Server, method, path string, v any, auth, header bool) *httptest.ResponseRecorder {
	var b bytes.Buffer
	if v != nil {
		_ = json.NewEncoder(&b).Encode(v)
	}
	r := httptest.NewRequest(method, "http://127.0.0.1:2080"+path, &b)
	if auth {
		r.AddCookie(&http.Cookie{Name: "ovpn_session", Value: s.token})
	}
	if header {
		r.Header.Set("X-OVPN-Socks", "1")
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func TestAuthenticationAndRequestBoundary(t *testing.T) {
	s, _ := fixture(t)
	if w := request(s, "GET", "/api/profiles", nil, false, false); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request(s, "GET", "/?token="+s.token, nil, false, false); w.Code != 303 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("token exchange %d", w.Code)
	}
	if w := request(s, "POST", "/api/profiles", map[string]string{}, true, false); w.Code != 403 {
		t.Fatal(w.Code)
	}
	r := httptest.NewRequest("GET", "http://attacker.invalid/api/profiles", nil)
	r.AddCookie(&http.Cookie{Name: "ovpn_session", Value: s.token})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("DNS rebinding host accepted")
	}
}
func TestSecretsStayPrivateAndBlankEditsPreserve(t *testing.T) {
	s, ovpn := fixture(t)
	input := config.Profile{Name: "test", OVPN: ovpn, Username: "fixture-user", Password: "secret-fixture-password", TOTPSeed: "JBSWY3DPEHPK3PXP", TOTPMode: "append", AutoReconnect: true}
	w := request(s, "POST", "/api/profiles", input, true, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result view
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	id := result.ID
	for _, path := range []string{"/api/profiles", "/api/profiles/" + id} {
		w = request(s, "GET", path, nil, true, false)
		for _, secret := range []string{input.Password, input.TOTPSeed} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("secret returned by API")
			}
		}
	}
	input.ID = id
	input.Password = ""
	input.TOTPSeed = ""
	input.Name = "edited"
	w = request(s, "POST", "/api/profiles", input, true, true)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	saved, _ := s.store.Get(id)
	if saved.Password != "secret-fixture-password" || saved.TOTPSeed != "JBSWY3DPEHPK3PXP" {
		t.Fatal("empty edit lost stored secrets")
	}
	clear := map[string]any{"id": id, "name": "edited", "ovpn": ovpn, "username": "fixture-user", "totp_mode": "append", "clear_password": true, "clear_totp": true}
	w = request(s, "POST", "/api/profiles", clear, true, true)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	saved, _ = s.store.Get(id)
	if saved.Password != "" || saved.TOTPSeed != "" || saved.TOTPMode != "" {
		t.Fatal("clear flags failed")
	}
	if w := request(s, "DELETE", "/api/profiles/"+id, nil, true, true); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
}
func TestRejectMalformedAndUnsafeConfig(t *testing.T) {
	s, _ := fixture(t)
	w := request(s, "POST", "/api/profiles", map[string]any{"name": "unsafe", "ovpn": "client\nplugin malicious.dll\n"}, true, true)
	if w.Code != 400 {
		t.Fatal("unsafe profile saved")
	}
	w = request(s, "POST", "/api/profiles", map[string]any{"unexpected": true}, true, true)
	if w.Code != 400 {
		t.Fatal("unknown field accepted")
	}
}
