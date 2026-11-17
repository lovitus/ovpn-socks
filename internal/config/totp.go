package config

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type totpSpec struct {
	key       []byte
	algorithm func() hash.Hash
	digits    int
	period    int64
}

func parseTOTP(seed string) (totpSpec, error) {
	spec := totpSpec{algorithm: sha1.New, digits: 6, period: 30}
	secret := strings.TrimSpace(seed)
	if strings.HasPrefix(strings.ToLower(secret), "otpauth:") {
		u, err := url.Parse(secret)
		if err != nil || u.Scheme != "otpauth" || u.Host != "totp" || u.Fragment != "" {
			return spec, errors.New("invalid TOTP otpauth URI")
		}
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return spec, errors.New("invalid TOTP URI parameters")
		}
		for _, k := range []string{"secret", "algorithm", "digits", "period"} {
			if len(q[k]) > 1 {
				return spec, fmt.Errorf("duplicate TOTP %s", k)
			}
		}
		secret = q.Get("secret")
		switch strings.ToUpper(q.Get("algorithm")) {
		case "", "SHA1":
		case "SHA256":
			spec.algorithm = sha256.New
		case "SHA512":
			spec.algorithm = sha512.New
		default:
			return spec, errors.New("TOTP algorithm must be SHA1, SHA256 or SHA512")
		}
		if d := q.Get("digits"); d != "" {
			spec.digits, err = strconv.Atoi(d)
			if err != nil || (spec.digits != 6 && spec.digits != 8) {
				return spec, errors.New("TOTP digits must be 6 or 8")
			}
		}
		if p := q.Get("period"); p != "" {
			spec.period, err = strconv.ParseInt(p, 10, 64)
			if err != nil || spec.period <= 0 {
				return spec, errors.New("TOTP period must be positive")
			}
		}
	}
	secret = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToUpper(r)
	}, secret)
	secret = strings.TrimRight(secret, "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) == 0 {
		return spec, errors.New("invalid TOTP base32 secret")
	}
	spec.key = key
	return spec, nil
}

// AuthPassword computes a fresh TOTP when enabled. An empty mode uses Password unchanged.
func (p Profile) AuthPassword(now time.Time) (string, error) {
	if p.TOTPMode == "" {
		return p.Password, nil
	}
	if p.TOTPMode != "append" && p.TOTPMode != "code" {
		return "", errors.New("TOTP mode must be empty, append or code")
	}
	spec, err := parseTOTP(p.TOTPSeed)
	if err != nil {
		return "", err
	}
	if now.Unix() < 0 {
		return "", errors.New("TOTP time precedes Unix epoch")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/spec.period))
	mac := hmac.New(spec.algorithm, spec.key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 15)
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulo := uint32(1000000)
	if spec.digits == 8 {
		modulo = 100000000
	}
	code := fmt.Sprintf("%0*d", spec.digits, value%modulo)
	if p.TOTPMode == "append" {
		return p.Password + code, nil
	}
	return code, nil
}
