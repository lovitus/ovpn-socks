package config

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRFC6238(t *testing.T) {
	vectors := []struct {
		timestamp            int64
		sha1, sha256, sha512 string
	}{
		{59, "94287082", "46119246", "90693936"}, {1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"}, {1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"}, {20000000000, "65353130", "77737706", "47863826"},
	}
	for _, algorithm := range []struct{ name, secret string }{{"SHA1", "12345678901234567890"}, {"SHA256", "12345678901234567890123456789012"}, {"SHA512", "1234567890123456789012345678901234567890123456789012345678901234"}} {
		for _, v := range vectors {
			t.Run(fmt.Sprintf("%s/%d", algorithm.name, v.timestamp), func(t *testing.T) {
				seed := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(algorithm.secret))
				p := Profile{TOTPMode: "code", TOTPSeed: "otpauth://totp/test?secret=" + seed + "&algorithm=" + algorithm.name + "&digits=8"}
				got, err := p.AuthPassword(time.Unix(v.timestamp, 0))
				if err != nil {
					t.Fatal(err)
				}
				want := v.sha1
				if algorithm.name == "SHA256" {
					want = v.sha256
				}
				if algorithm.name == "SHA512" {
					want = v.sha512
				}
				if got != want {
					t.Fatalf("got %s, want %s", got, want)
				}
			})
		}
	}
}

func TestAuthModesAndPeriod(t *testing.T) {
	p := Profile{Password: "secret", TOTPSeed: "gezd gnbv gy3t qojq gezd gnbv gy3t qojq", TOTPMode: "append"}
	got, err := p.AuthPassword(time.Unix(59, 0))
	if err != nil || got != "secret287082" {
		t.Fatalf("got %q, %v", got, err)
	}
	p.TOTPMode = "code"
	p.TOTPSeed = "otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=60"
	got, err = p.AuthPassword(time.Unix(119, 0))
	if err != nil || got != "94287082" {
		t.Fatalf("period: %q, %v", got, err)
	}
	p.TOTPMode = ""
	got, err = p.AuthPassword(time.Time{})
	if err != nil || got != "secret" {
		t.Fatal(got, err)
	}
	for _, seed := range []string{"", "not!base32", "otpauth://hotp/a?secret=AA", "otpauth://totp/a?secret=AA&digits=7", "otpauth://totp/a?secret=AA&algorithm=MD5", "otpauth://totp/a?secret=AA&period=0", "otpauth://totp/a?secret=AA&period=-1", "otpauth://totp/a?secret=AA&secret=BB"} {
		p.TOTPSeed, p.TOTPMode = seed, "code"
		if _, err := p.AuthPassword(time.Now()); err == nil {
			t.Errorf("accepted %q", seed)
		}
	}
}

func sampleProfile() Profile {
	return Profile{Name: "private-profile-name", OVPN: "client\n<key>super-private-openvpn-key</key>", Username: "private-username", Password: "private-password", TOTPSeed: "JBSWY3DPEHPK3PXP", TOTPMode: "append", AutoConnect: true, AutoReconnect: true}
}

func TestEncryptedCRUD(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Save(sampleProfile())
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == "" || p.Listen != "0.0.0.0:1080" {
		t.Fatal(p)
	}
	p2, err := s.Save(sampleProfile())
	if err != nil || p2.Listen != "0.0.0.0:1081" {
		t.Fatal(p2, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, dataFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{p.Name, p.OVPN, p.Username, p.Password, p.TOTPSeed, p.ID, p.Listen} {
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("ciphertext contains %q", secret)
		}
	}
	copy := s.List()
	copy[0].Name = "mutated"
	got, _ := s.Get(p.ID)
	if got.Name != p.Name {
		t.Fatal("List aliased storage")
	}
	p.Name = "renamed"
	if _, err = s.Save(p); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.Get(p.ID)
	if !ok || got != p {
		t.Fatalf("roundtrip: %+v vs %+v", got, p)
	}
	if err = reopened.Delete(p.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok = reopened.Get(p.ID); ok {
		t.Fatal("delete retained profile")
	}
	reopened, err = Open(dir)
	if err != nil || len(reopened.List()) != 1 {
		t.Fatal(reopened, err)
	}
	if err = reopened.Delete(p2.ID); err != nil {
		t.Fatal(err)
	}
	reopened, err = Open(dir)
	if err != nil || len(reopened.List()) != 0 {
		t.Fatal(reopened, err)
	}
}

func TestValidation(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Profile){
		func(p *Profile) { p.ID = "../escape" }, func(p *Profile) { p.Name = " " }, func(p *Profile) { p.OVPN = " " }, func(p *Profile) { p.TOTPSeed = "bad!" }, func(p *Profile) { p.TOTPMode = "other" },
		func(p *Profile) { p.Listen = "example.com:1080" }, func(p *Profile) { p.Listen = "127.0.0.1:0" }, func(p *Profile) { p.Listen = "127.0.0.1:65536" },
	} {
		p := sampleProfile()
		change(&p)
		if _, err := s.Save(p); err == nil {
			t.Errorf("accepted invalid profile %+v", p)
		}
	}
	p := sampleProfile()
	p.Listen = "[::1]:1080"
	if _, err = s.Save(p); err != nil {
		t.Fatal(err)
	}
	p.ID = "second"
	p.Listen = "0.0.0.0:1080"
	if _, err = s.Save(p); err == nil {
		t.Fatal("accepted duplicate port")
	}
	if err = s.Delete("../../escape"); err == nil {
		t.Fatal("accepted unsafe ID")
	}
}

func TestExplicitListenAddressesRemainUnchanged(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:1080", "0.0.0.0:1080", "192.168.1.15:1080", "[::]:1080", "[2001:db8::15]:1080", ":1080"} {
		t.Run(addr, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			p := sampleProfile()
			p.Listen = addr
			p, err = s.Save(p)
			if err != nil {
				t.Fatal(err)
			}
			s, err = Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := s.Get(p.ID)
			if !ok || got.Listen != addr {
				t.Fatal("explicit listen changed", got.Listen)
			}
		})
	}
}

func TestMissingKeyAndTampering(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Save(sampleProfile())
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, keyFile)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(dir); err == nil {
		t.Fatal("silently replaced missing key")
	}
	if _, err = os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("key regenerated")
	}
	p.Name = "changed"
	if _, err = s.Save(p); err == nil {
		t.Fatal("saved without key")
	}
	got, _ := s.Get(p.ID)
	if got.Name == p.Name {
		t.Fatal("failed Save changed memory")
	}
	if err = os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	changedKey := bytes.Repeat([]byte{0x42}, 32)
	if err = os.WriteFile(keyPath, changedKey, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(dir); err == nil {
		t.Fatal("accepted replaced key")
	}
	if _, err = s.Save(p); err == nil {
		t.Fatal("saved with replaced key")
	}
	if err = os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	dataPath := filepath.Join(dir, dataFile)
	data, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err = os.WriteFile(dataPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(dir); err == nil {
		t.Fatal("accepted tampered ciphertext")
	}
}

func TestFailedWritePreservesMemory(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Save(sampleProfile())
	if err != nil {
		t.Fatal(err)
	}
	// A directory at the destination reliably makes atomic replacement fail,
	// including when tests are running as a privileged user.
	target := filepath.Join(dir, dataFile)
	if err = os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	p.Name = "failed-update"
	if _, err = s.Save(p); err == nil {
		t.Fatal("expected write failure")
	}
	got, _ := s.Get(p.ID)
	if got.Name == p.Name {
		t.Fatal("failed write updated memory")
	}
	if err = s.Delete(p.ID); err == nil {
		t.Fatal("expected delete failure")
	}
	if _, ok := s.Get(p.ID); !ok {
		t.Fatal("failed delete updated memory")
	}
}

func TestConcurrentCRUD(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := s.Save(sampleProfile())
			if err != nil {
				t.Error(err)
				return
			}
			if _, ok := s.Get(p.ID); !ok {
				t.Error("missing profile")
			}
			_ = s.List()
			p.Name += "-updated"
			if _, err = s.Save(p); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if len(s.List()) != 12 {
		t.Fatal("lost concurrent save")
	}
	for _, p := range s.List() {
		if !strings.HasSuffix(p.Name, "-updated") {
			t.Fatal("lost update")
		}
	}
}
