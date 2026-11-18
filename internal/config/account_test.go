package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAccountAtomicFailureAndHash(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	initialSalt := append([]byte{}, s.account.Salt...)
	if !s.Authenticate("admin", "admin") {
		t.Fatal("default account missing")
	}
	if err := s.ChangeAccount("wrong", "renamed", "secret"); err != ErrCredentials {
		t.Fatal(err)
	}
	if err := s.ChangeAccount("admin", "renamed", ""); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(initialSalt, s.account.Salt) || !s.Authenticate("renamed", "admin") {
		t.Fatal("username-only update changed password")
	}
	if err := s.ChangeAccount("admin", "renamed", "secret"); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(initialSalt, s.account.Salt) || s.Authenticate("renamed", "admin") || !s.Authenticate("renamed", "secret") {
		t.Fatal("password/salt update failed")
	}
	target := filepath.Join(dir, accountFile)
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangeAccount("secret", "failed", "failed"); err == nil {
		t.Fatal("expected persistence failure")
	}
	if s.AccountUsername() != "renamed" || !s.Authenticate("renamed", "secret") {
		t.Fatal("failed write changed account in memory")
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("account directory silently reset")
	}
}

func TestCorruptAccountDoesNotReset(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, accountFile), []byte(`{"username":"admin","salt":"AA==","hash":"AA==","iterations":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("corrupt account silently reset")
	}
}
