// Package config stores all profile contents in a locally encrypted file.
package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const keyFile = "master.key"
const dataFile = "profiles.enc"
const fileHeader = "OVPNSOCKS\x01"

// Profile contains connection settings. Every field is encrypted at rest.
type Profile struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	OVPN          string `json:"ovpn"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	TOTPSeed      string `json:"totp_seed"`
	TOTPMode      string `json:"totp_mode"`
	Listen        string `json:"listen"`
	AutoConnect   bool   `json:"auto_connect"`
	AutoReconnect bool   `json:"auto_reconnect"`
}

type Store struct {
	mu       sync.RWMutex
	dir      string
	aead     cipher.AEAD
	profiles []Profile
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Open opens an encrypted store, creating a local key only for a new store.
// A missing or invalid key for existing data is always an error.
func Open(dir string) (*Store, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("configuration directory must be a real directory")
	}
	if err = securePath(dir, true); err != nil {
		return nil, fmt.Errorf("secure configuration directory: %w", err)
	}
	dataPath := filepath.Join(dir, dataFile)
	dataInfo, dataErr := os.Lstat(dataPath)
	if dataErr == nil && !dataInfo.Mode().IsRegular() {
		return nil, errors.New("configuration file must be a regular file")
	}
	if dataErr != nil && !errors.Is(dataErr, os.ErrNotExist) {
		return nil, dataErr
	}
	keyPath := filepath.Join(dir, keyFile)
	key, err := readRegular(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		if dataErr == nil {
			return nil, errors.New("configuration key is missing; restore master.key to decrypt existing profiles")
		}
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		f, createErr := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(createErr, os.ErrExist) {
			key, err = readRegular(keyPath)
		} else if createErr != nil {
			return nil, createErr
		} else {
			err = securePath(keyPath, false)
			if err == nil {
				_, err = f.Write(key)
			}
			if err == nil {
				err = f.Sync()
			}
			closeErr := f.Close()
			if err == nil {
				err = closeErr
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read/create configuration key: %w", err)
	}
	if len(key) != 32 {
		return nil, errors.New("configuration key must contain exactly 32 bytes")
	}
	if err = securePath(keyPath, false); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, aead: aead, profiles: []Profile{}}
	if dataErr == nil {
		if err = securePath(dataPath, false); err != nil {
			return nil, err
		}
		data, err := readRegular(dataPath)
		if err != nil {
			return nil, err
		}
		n := len(fileHeader)
		if len(data) < n+aead.NonceSize()+aead.Overhead() || string(data[:n]) != fileHeader {
			return nil, errors.New("invalid encrypted configuration format")
		}
		plain, err := aead.Open(nil, data[n:n+aead.NonceSize()], data[n+aead.NonceSize():], []byte(fileHeader))
		if err != nil {
			return nil, errors.New("cannot decrypt configuration: key mismatch or damaged data")
		}
		if err = json.Unmarshal(plain, &s.profiles); err != nil {
			return nil, fmt.Errorf("decode configuration: %w", err)
		}
		ids, ports := map[string]bool{}, map[string]bool{}
		for i, p := range s.profiles {
			if !safeID.MatchString(p.ID) || ids[p.ID] || p.Listen == "" {
				return nil, errors.New("invalid or duplicate saved profile ID/listen address")
			}
			p, err = validate(p)
			if err != nil {
				return nil, fmt.Errorf("invalid saved profile: %w", err)
			}
			_, port, _ := net.SplitHostPort(p.Listen)
			if ports[port] {
				return nil, errors.New("duplicate saved profile port")
			}
			ids[p.ID], ports[port] = true, true
			s.profiles[i] = p
		}
	}
	return s, nil
}

func readRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("configuration file must be a regular file")
	}
	return os.ReadFile(path)
}

// List returns a copy, including secrets; callers must redact HTTP responses.
func (s *Store) List() []Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Profile{}, s.profiles...)
}
func (s *Store) Get(id string) (Profile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.profiles {
		if p.ID == id {
			return p, true
		}
	}
	return Profile{}, false
}

func validate(p Profile) (Profile, error) {
	if p.ID != "" && !safeID.MatchString(p.ID) {
		return p, errors.New("invalid profile ID")
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 256 {
		return p, errors.New("profile name must contain 1 to 256 bytes")
	}
	if strings.TrimSpace(p.OVPN) == "" {
		return p, errors.New("OpenVPN configuration is required")
	}
	if p.TOTPMode != "" && p.TOTPMode != "append" && p.TOTPMode != "code" {
		return p, errors.New("TOTP mode must be empty, append or code")
	}
	if p.TOTPSeed != "" || p.TOTPMode != "" {
		if _, err := parseTOTP(p.TOTPSeed); err != nil {
			return p, err
		}
	}
	if p.Listen != "" {
		host, port, err := net.SplitHostPort(p.Listen)
		if err != nil {
			return p, errors.New("listen must be a loopback host:port")
		}
		if strings.EqualFold(host, "localhost") {
			host = "127.0.0.1"
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return p, errors.New("SOCKS listen address must be loopback")
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return p, errors.New("listen port must be 1 to 65535")
		}
		p.Listen = net.JoinHostPort(ip.String(), strconv.Itoa(number))
	}
	return p, nil
}

// Save inserts or replaces a profile. Memory changes only after atomic disk persistence.
func (s *Store) Save(p Profile) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := validate(p)
	if err != nil {
		return Profile{}, err
	}
	if p.ID == "" {
		for {
			var id [12]byte
			if _, err = rand.Read(id[:]); err != nil {
				return Profile{}, err
			}
			p.ID = hex.EncodeToString(id[:])
			found := false
			for _, old := range s.profiles {
				if old.ID == p.ID {
					found = true
				}
			}
			if !found {
				break
			}
		}
	}
	used := map[string]bool{}
	for _, old := range s.profiles {
		if old.ID != p.ID {
			_, port, _ := net.SplitHostPort(old.Listen)
			used[port] = true
		}
	}
	if p.Listen == "" {
		for port := 1080; port <= 65535; port++ {
			if !used[strconv.Itoa(port)] {
				p.Listen = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
				break
			}
		}
		if p.Listen == "" {
			return Profile{}, errors.New("no available profile port")
		}
	}
	_, port, _ := net.SplitHostPort(p.Listen)
	if used[port] {
		return Profile{}, errors.New("listen port is already assigned to another profile")
	}
	next := append([]Profile{}, s.profiles...)
	replaced := false
	for i := range next {
		if next[i].ID == p.ID {
			next[i] = p
			replaced = true
			break
		}
	}
	if !replaced {
		next = append(next, p)
	}
	if err = s.persist(next); err != nil {
		return Profile{}, err
	}
	s.profiles = next
	return p, nil
}

func (s *Store) Delete(id string) error {
	if !safeID.MatchString(id) {
		return errors.New("invalid profile ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make([]Profile, 0, len(s.profiles))
	found := false
	for _, p := range s.profiles {
		if p.ID == id {
			found = true
		} else {
			next = append(next, p)
		}
	}
	if !found {
		return nil
	}
	if err := s.persist(next); err != nil {
		return err
	}
	s.profiles = next
	return nil
}

func (s *Store) persist(profiles []Profile) error {
	// Refuse to create ciphertext if the persisted key has disappeared or changed.
	key, err := readRegular(filepath.Join(s.dir, keyFile))
	if err != nil {
		return fmt.Errorf("configuration key unavailable: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return errors.New("configuration key is invalid")
	}
	check, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(profiles)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	data := append([]byte(fileHeader), nonce...)
	data = s.aead.Seal(data, nonce, plain, []byte(fileHeader))
	if _, err = check.Open(nil, nonce, data[len(fileHeader)+len(nonce):], []byte(fileHeader)); err != nil {
		return errors.New("configuration key has changed")
	}
	f, err := os.CreateTemp(s.dir, ".profiles-*")
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
	if err = os.Rename(temp, filepath.Join(s.dir, dataFile)); err != nil {
		return err
	}
	return syncDirectory(s.dir)
}
