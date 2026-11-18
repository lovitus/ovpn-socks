package config

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const accountFile = "admin.json"
const passwordIterations = 600000

var ErrCredentials = errors.New("用户名或密码错误")

type account struct {
	Username   string `json:"username"`
	Salt       []byte `json:"salt"`
	Hash       []byte `json:"hash"`
	Iterations int    `json:"iterations"`
}

func (s *Store) loadAccount() error {
	path := filepath.Join(s.dir, accountFile)
	data, err := readRegular(path)
	if errors.Is(err, os.ErrNotExist) {
		a, err := newAccount("admin", "admin")
		if err != nil {
			return err
		}
		if err = s.persistAccount(a); err != nil {
			return err
		}
		s.account = a
		return nil
	}
	if err != nil {
		return err
	}
	if err = securePath(path, false); err != nil {
		return err
	}
	var a account
	if err = json.Unmarshal(data, &a); err != nil {
		return fmt.Errorf("decode admin account: %w", err)
	}
	if strings.TrimSpace(a.Username) == "" || len(a.Username) > 128 || len(a.Salt) != 32 || len(a.Hash) != 32 || a.Iterations != passwordIterations {
		return errors.New("invalid admin account file")
	}
	s.account = a
	return nil
}

func newAccount(username, password string) (account, error) {
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 128 || password == "" || len(password) > 1024 {
		return account{}, errors.New("用户名需为 1 至 128 字节，密码需为 1 至 1024 字节")
	}
	a := account{Username: username, Salt: make([]byte, 32), Iterations: passwordIterations}
	if _, err := rand.Read(a.Salt); err != nil {
		return account{}, err
	}
	a.Hash = pbkdf2.Key([]byte(password), a.Salt, a.Iterations, 32, sha256.New)
	return a, nil
}

func (a account) check(password string) bool {
	if len(password) > 1024 {
		return false
	}
	hash := pbkdf2.Key([]byte(password), a.Salt, a.Iterations, 32, sha256.New)
	return subtle.ConstantTimeCompare(hash, a.Hash) == 1
}

func (s *Store) AccountUsername() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.account.Username
}

func (s *Store) Authenticate(username, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	valid := s.account.check(password)
	return subtle.ConstantTimeCompare([]byte(username), []byte(s.account.Username)) == 1 && valid
}

// ChangeAccount verifies the old password and changes memory only after persistence.
func (s *Store) ChangeAccount(currentPassword, username, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.account.check(currentPassword) {
		return ErrCredentials
	}
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 128 {
		return errors.New("用户名需为 1 至 128 字节")
	}
	next := s.account
	next.Username = username
	if password != "" {
		var err error
		next, err = newAccount(username, password)
		if err != nil {
			return err
		}
	}
	if err := s.persistAccount(next); err != nil {
		return err
	}
	s.account = next
	return nil
}

func (s *Store) persistAccount(a account) error {
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".admin-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	err = securePath(temp, false)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(temp, filepath.Join(s.dir, accountFile)); err != nil {
		return err
	}
	return syncDirectory(s.dir)
}
