// Package ovpnconfig parses self-contained OpenVPN client profiles. It never
// reads files, executes commands, creates network devices, or changes routes.
package ovpnconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	openvpn "github.com/sagernet/sing-openvpn"
)

const maxProfileSize = 4 << 20

// Parse converts an OpenVPN profile to userspace client options. Authentication
// credentials are deliberately left empty: the caller supplies the UI values.
// Tunnel options describe protocol metadata only; Parse performs no system I/O.
func Parse(text string) (openvpn.ClientOptions, error) {
	var zero openvpn.ClientOptions
	if len(text) > maxProfileSize {
		return zero, fmt.Errorf("OVPN profile exceeds 4 MiB")
	}
	if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		return zero, fmt.Errorf("OVPN profile must be UTF-8 text without NUL bytes")
	}
	p := parser{seen: make(map[string]bool), port: 1194}
	p.o.Mode = openvpn.ModeTLS
	p.o.KeyDirection = -1
	p.o.Transport.Protocol = "udp"
	p.o.Tunnel.DevType = "tun"
	p.o.TLS.VersionMin = "1.2"
	lines := strings.Split(strings.TrimPrefix(text, "\ufeff"), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSuffix(lines[i], "\r")
		words, err := tokenize(line)
		if err != nil {
			return zero, fmt.Errorf("line %d: %w", i+1, err)
		}
		if len(words) == 0 {
			continue
		}
		name := strings.TrimPrefix(words[0], "--")
		if strings.HasPrefix(name, "<") {
			if len(words) != 1 || !strings.HasSuffix(name, ">") || strings.HasPrefix(name, "</") {
				return zero, fmt.Errorf("line %d: malformed inline block", i+1)
			}
			tag := name[1 : len(name)-1]
			m := p.material(tag)
			if m == nil {
				return zero, fmt.Errorf("line %d: unsupported inline block <%s>", i+1, tag)
			}
			if m.IsSet() {
				return zero, fmt.Errorf("line %d: duplicate <%s> material", i+1, tag)
			}
			start := i + 1
			var body []string
			for i++; i < len(lines); i++ {
				raw := strings.TrimSuffix(lines[i], "\r")
				if strings.TrimSpace(raw) == "</"+tag+">" {
					break
				}
				if strings.HasPrefix(strings.TrimSpace(raw), "<") {
					return zero, fmt.Errorf("line %d: unexpected inline tag inside <%s>", i+1, tag)
				}
				body = append(body, raw)
			}
			if i == len(lines) {
				return zero, fmt.Errorf("line %d: missing </%s>", start, tag)
			}
			content := strings.Join(body, "\n") + "\n"
			if strings.TrimSpace(content) == "" {
				return zero, fmt.Errorf("line %d: empty <%s>", start, tag)
			}
			m.Content = []byte(content)
			continue
		}
		if err := p.directive(name, words[1:]); err != nil {
			return zero, fmt.Errorf("line %d (%s): %w", i+1, name, err)
		}
	}
	for _, name := range []string{"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"} {
		if p.seen[name] && !p.material(name).IsSet() {
			return zero, fmt.Errorf("%s [inline] requires <%s> material", name, name)
		}
	}
	if len(p.o.Transport.Remotes) == 0 {
		return zero, fmt.Errorf("at least one remote is required")
	}
	for i := range p.o.Transport.Remotes {
		r := &p.o.Transport.Remotes[i]
		if r.Port == 0 {
			r.Port = p.port
		}
		if r.Protocol == "" {
			r.Protocol = p.o.Transport.Protocol
		}
	}
	if !p.o.TLS.CertificateAuthority.IsSet() {
		return zero, fmt.Errorf("inline <ca> is required; external CA paths and system trust are not used")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(p.o.TLS.CertificateAuthority.Content) {
		return zero, fmt.Errorf("<ca> must contain valid PEM certificates")
	}
	if p.o.TLS.Certificate.IsSet() != p.o.TLS.Key.IsSet() {
		return zero, fmt.Errorf("inline <cert> and <key> must both be supplied or both omitted")
	}
	if p.o.TLS.Certificate.IsSet() {
		if _, err := tls.X509KeyPair(p.o.TLS.Certificate.Content, p.o.TLS.Key.Content); err != nil {
			return zero, fmt.Errorf("invalid inline client certificate/key (encrypted keys are unsupported): %w", err)
		}
	}
	if p.ifconfigLocal.IsValid() {
		bits := 32
		if p.o.Tunnel.Topology == "subnet" {
			var err error
			bits, err = maskBits(p.ifconfigOther.String())
			if err != nil {
				return zero, fmt.Errorf("ifconfig subnet: %w", err)
			}
		} else {
			p.o.Tunnel.VPNGateway = p.ifconfigOther
		}
		p.o.Tunnel.LocalAddress = append(p.o.Tunnel.LocalAddress, netip.PrefixFrom(p.ifconfigLocal, bits))
	}
	if p.o.TLS.RemoteCertificateTLS == "" && p.o.TLS.NSCertificateType == "" {
		p.o.TLS.RemoteCertificateTLS = "server"
	}
	// NewClient validates cipher names, TLS constraints, compression, filters, and
	// cross-option conflicts without starting a connection or loading files.
	client, err := openvpn.NewClient(p.o)
	if err != nil {
		return zero, fmt.Errorf("invalid OVPN options: %w", err)
	}
	_ = client.Close()
	return p.o, nil
}

type parser struct {
	o                            openvpn.ClientOptions
	seen                         map[string]bool
	port                         uint16
	ifconfigLocal, ifconfigOther netip.Addr
}

func (p *parser) material(name string) *openvpn.Material {
	switch name {
	case "ca":
		return &p.o.TLS.CertificateAuthority
	case "cert":
		return &p.o.TLS.Certificate
	case "key":
		return &p.o.TLS.Key
	case "tls-auth":
		return &p.o.TLS.Auth
	case "tls-crypt":
		return &p.o.TLS.Crypt
	case "tls-crypt-v2":
		return &p.o.TLS.CryptV2
	}
	return nil
}

func (p *parser) directive(name string, a []string) error {
	count := func(min, max int) error {
		if len(a) < min || len(a) > max {
			return fmt.Errorf("expected %d..%d arguments, got %d", min, max, len(a))
		}
		return nil
	}
	one := func(dst *string) error {
		if err := count(1, 1); err != nil {
			return err
		}
		if a[0] == "" {
			return fmt.Errorf("empty argument")
		}
		*dst = a[0]
		return nil
	}
	flag := func(dst *bool) error {
		if err := count(0, 0); err != nil {
			return err
		}
		*dst = true
		return nil
	}
	num := func(dst *uint32, min, max uint64) error {
		if err := count(1, 1); err != nil {
			return err
		}
		v, err := number(a[0], min, max)
		if err == nil {
			*dst = uint32(v)
		}
		return err
	}
	duration := func(dst *time.Duration, disabled *bool) error {
		if err := count(1, 1); err != nil {
			return err
		}
		v, err := number(a[0], 0, uint64((1<<63-1)/int64(time.Second)))
		if err != nil {
			return err
		}
		*dst = time.Duration(v) * time.Second
		if disabled != nil {
			*disabled = v == 0
		}
		return nil
	}
	// Repeated security directives are ambiguous and are rejected, rather than
	// letting an appended directive silently replace an earlier security policy.
	repeat := name == "remote" || name == "pull-filter" || name == "dhcp-option" || name == "route" || name == "route-ipv6"
	if p.seen[name] && !repeat {
		return fmt.Errorf("duplicate directive")
	}
	p.seen[name] = true
	if m := p.material(name); m != nil {
		max := 1
		if name == "tls-auth" {
			max = 2
		}
		if err := count(1, max); err != nil {
			return err
		}
		if a[0] != "[inline]" {
			return fmt.Errorf("external file paths are forbidden; embed material in <%s>...</%s>", name, name)
		}
		if len(a) == 2 {
			return p.direction(a[1])
		}
		return nil
	}
	switch name {
	case "client":
		if err := count(0, 0); err != nil {
			return err
		}
		p.o.Pull.Enabled = true
	case "tls-client":
		return count(0, 0)
	case "pull":
		return flag(&p.o.Pull.Enabled)
	case "dev":
		if err := count(1, 1); err != nil {
			return err
		}
		if a[0] != "tun" && !(strings.HasPrefix(a[0], "tun") && digits(a[0][3:])) {
			return fmt.Errorf("only IP-layer dev tun is supported; TAP/system devices are not supported")
		}
	case "dev-type":
		if err := count(1, 1); err != nil {
			return err
		}
		if a[0] != "tun" {
			return fmt.Errorf("only dev-type tun is supported")
		}
	case "proto":
		if err := count(1, 1); err != nil {
			return err
		}
		v, err := protocol(a[0])
		if err != nil {
			return err
		}
		p.o.Transport.Protocol = v
	case "port", "rport":
		if err := count(1, 1); err != nil {
			return err
		}
		v, err := number(a[0], 1, 65535)
		if err != nil {
			return err
		}
		p.port = uint16(v)
	case "remote":
		if err := count(1, 3); err != nil {
			return err
		}
		if a[0] == "" || strings.ContainsAny(a[0], " \t\r\n/\\") {
			return fmt.Errorf("invalid remote host")
		}
		r := openvpn.Remote{Host: a[0]}
		if len(a) > 1 {
			v, err := number(a[1], 1, 65535)
			if err != nil {
				return err
			}
			r.Port = uint16(v)
		}
		if len(a) > 2 {
			v, err := protocol(a[2])
			if err != nil {
				return err
			}
			r.Protocol = v
		}
		p.o.Transport.Remotes = append(p.o.Transport.Remotes, r)
	case "remote-random":
		return flag(&p.o.Transport.RemoteRandom)
	case "auth-user-pass":
		if len(a) != 0 {
			return fmt.Errorf("auth-user-pass file paths are forbidden; supply username/password in the UI")
		}
	case "auth-retry":
		return one(&p.o.Authentication.AuthRetry)
	case "static-challenge":
		if err := count(2, 2); err != nil {
			return err
		}
		if a[0] == "" || (a[1] != "0" && a[1] != "1") {
			return fmt.Errorf("expected prompt and echo 0 or 1")
		}
		p.o.Authentication.StaticChallenge = a[0]
		p.o.Authentication.StaticChallengeEcho = a[1] == "1"
	case "cipher":
		return one(&p.o.DataChannel.Cipher)
	case "auth":
		return one(&p.o.DataChannel.Auth)
	case "data-ciphers", "ncp-ciphers":
		if p.seen["data-ciphers"] && p.seen["ncp-ciphers"] {
			return fmt.Errorf("data-ciphers conflicts with ncp-ciphers")
		}
		if err := count(1, 1); err != nil {
			return err
		}
		p.o.DataChannel.Ciphers = strings.Split(a[0], ":")
	case "data-ciphers-fallback":
		return one(&p.o.DataChannel.FallbackCipher)
	case "key-direction":
		if err := count(1, 1); err != nil {
			return err
		}
		return p.direction(a[0])
	case "remote-cert-tls":
		if err := count(1, 1); err != nil {
			return err
		}
		if a[0] != "server" {
			return fmt.Errorf("remote-cert-tls must be server for a client")
		}
		p.o.TLS.RemoteCertificateTLS = "server"
	case "ns-cert-type":
		if err := count(1, 1); err != nil {
			return err
		}
		if a[0] != "server" {
			return fmt.Errorf("ns-cert-type must be server for a client")
		}
		p.o.TLS.NSCertificateType = "server"
	case "verify-x509-name":
		if err := count(1, 2); err != nil {
			return err
		}
		if a[0] == "" {
			return fmt.Errorf("empty certificate identity")
		}
		p.o.TLS.VerifyX509Name = a[0]
		p.o.TLS.VerifyX509Type = "subject"
		if len(a) == 2 {
			p.o.TLS.VerifyX509Type = a[1]
		}
	case "remote-cert-ku":
		if err := count(1, 16); err != nil {
			return err
		}
		p.o.TLS.RemoteCertificateKU = append([]string(nil), a...)
	case "remote-cert-eku":
		return one(&p.o.TLS.RemoteCertificateEKU)
	case "tls-version-min":
		return one(&p.o.TLS.VersionMin)
	case "tls-version-max":
		return one(&p.o.TLS.VersionMax)
	case "tls-cipher":
		return one(&p.o.TLS.Cipher)
	case "tls-groups":
		return one(&p.o.TLS.Groups)
	case "tls-cert-profile":
		return one(&p.o.TLS.CertificateProfile)
	case "reneg-sec":
		return duration(&p.o.Timing.RenegotiationInterval, &p.o.Timing.RenegotiationDisabled)
	case "reneg-bytes", "reneg-pkts":
		if err := count(1, 1); err != nil {
			return err
		}
		v, err := number(a[0], 0, ^uint64(0))
		if err != nil {
			return err
		}
		if name == "reneg-bytes" {
			p.o.Timing.RenegotiationBytes = v
		} else {
			p.o.Timing.RenegotiationPackets = v
		}
	case "ping":
		if p.seen["keepalive"] {
			return fmt.Errorf("ping conflicts with keepalive")
		}
		return duration(&p.o.Timing.PingInterval, nil)
	case "ping-restart":
		if p.seen["keepalive"] {
			return fmt.Errorf("ping-restart conflicts with keepalive")
		}
		return duration(&p.o.Timing.PingRestart, &p.o.Timing.PingRestartDisabled)
	case "keepalive":
		if err := count(2, 2); err != nil {
			return err
		}
		if p.seen["ping"] || p.seen["ping-restart"] {
			return fmt.Errorf("keepalive conflicts with explicit ping options")
		}
		v, err := number(a[0], 1, 2147483647)
		if err != nil {
			return err
		}
		w, err := number(a[1], 1, 2147483647)
		if err != nil {
			return err
		}
		p.o.Timing.PingInterval = time.Duration(v) * time.Second
		p.o.Timing.PingRestart = time.Duration(w) * time.Second
	case "tls-timeout":
		return duration(&p.o.Timing.TLSTimeout, nil)
	case "hand-window":
		return duration(&p.o.Timing.HandWindow, nil)
	case "tun-mtu":
		return num(&p.o.DataChannel.MTU, 68, 65535)
	case "fragment":
		return num(&p.o.DataChannel.Fragment, 68, 65535)
	case "mssfix":
		if err := count(0, 2); err != nil {
			return err
		}
		p.o.DataChannel.MSSFix = 1492
		p.o.DataChannel.MSSFixMode = "mtu"
		if len(a) == 0 {
			return nil
		}
		v, err := number(a[0], 0, 65535)
		if err != nil {
			return err
		}
		p.o.DataChannel.MSSFix = uint32(v)
		p.o.DataChannel.MSSFixMode = "fixed"
		if len(a) == 2 {
			if a[1] != "mtu" {
				return fmt.Errorf("expected mtu modifier")
			}
			p.o.DataChannel.MSSFixMode = "mtu"
		}
		if v == 0 {
			if len(a) == 2 {
				return fmt.Errorf("mssfix 0 cannot have mtu modifier")
			}
			p.o.DataChannel.MSSFixDisabled = true
			p.o.DataChannel.MSSFixMode = ""
		}
	case "explicit-exit-notify":
		if len(a) == 0 {
			p.o.Transport.ExplicitExitNotify = 1
			return nil
		}
		return num(&p.o.Transport.ExplicitExitNotify, 0, 255)
	case "pull-filter":
		if err := count(2, 2); err != nil {
			return err
		}
		p.o.Pull.Filters = append(p.o.Pull.Filters, openvpn.PullFilter{Action: a[0], Text: a[1]})
	case "route-nopull":
		return flag(&p.o.Pull.RouteNoPull)
	case "topology":
		return one(&p.o.Tunnel.Topology)
	case "redirect-gateway", "redirect-private", "route", "route-ipv6", "route-gateway", "route-metric", "dhcp-option", "ifconfig", "ifconfig-ipv6", "block-ipv6", "block-outside-dns":
		return p.tunnelDirective(name, a)
	case "compress":
		if p.seen["comp-lzo"] {
			return fmt.Errorf("mixed compress and comp-lzo policies are unsupported")
		}
		if len(a) == 1 && a[0] == "" {
			return fmt.Errorf("empty compression algorithm")
		}
		if err := count(0, 1); err != nil {
			return err
		}
		p.o.DataChannel.Compression = "stub"
		if len(a) == 1 {
			p.o.DataChannel.Compression = a[0]
		}
		p.o.DataChannel.CompressionLZO = ""
	case "comp-lzo":
		if p.seen["compress"] {
			return fmt.Errorf("mixed compress and comp-lzo policies are unsupported")
		}
		if len(a) == 1 && a[0] == "" {
			return fmt.Errorf("empty compression algorithm")
		}
		if err := count(0, 1); err != nil {
			return err
		}
		p.o.DataChannel.CompressionLZO = "adaptive"
		if len(a) == 1 {
			p.o.DataChannel.CompressionLZO = a[0]
		}
		p.o.DataChannel.Compression = ""
	case "allow-compression":
		return one(&p.o.DataChannel.AllowCompression)
	// These options affect only the external OpenVPN executable's logging,
	// persistence, local bind, retries, or credential cache. This parser uses
	// an in-process transport and never creates a TUN device or credential cache.
	case "persist-key", "persist-tun", "nobind", "auth-nocache", "mute-replay-warnings":
		return count(0, 0)
	case "verb", "mute":
		if err := count(1, 1); err != nil {
			return err
		}
		_, err := number(a[0], 0, 999)
		return err
	case "resolv-retry":
		if err := count(1, 1); err != nil {
			return err
		}
		if a[0] == "infinite" {
			return nil
		}
		_, err := number(a[0], 0, 2147483647)
		return err
	case "up", "down", "route-up", "route-pre-down", "ipchange", "tls-verify", "auth-user-pass-verify", "client-connect", "client-disconnect", "learn-address", "plugin", "script-security", "config", "cd", "chroot", "daemon", "log", "log-append", "status", "writepid", "management", "management-client", "setenv", "setenv-safe":
		return fmt.Errorf("unsafe directive is forbidden in imported profiles")
	default:
		return fmt.Errorf("unsupported directive; it cannot be safely ignored")
	}
	return nil
}
func (p *parser) direction(s string) error {
	v, err := strconv.Atoi(s)
	if err != nil || (v != 0 && v != 1) {
		return fmt.Errorf("key-direction must be 0 or 1")
	}
	if p.o.KeyDirection != -1 && p.o.KeyDirection != v {
		return fmt.Errorf("conflicting key-direction")
	}
	p.o.KeyDirection = v
	return nil
}
func number(s string, min, max uint64) (uint64, error) {
	if !digits(s) {
		return 0, fmt.Errorf("expected unsigned decimal integer")
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v < min || v > max {
		return 0, fmt.Errorf("integer must be between %d and %d", min, max)
	}
	return v, nil
}
func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func protocol(s string) (string, error) {
	switch s {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
		return s, nil
	case "tcp-client":
		return "tcp", nil
	case "tcp4-client":
		return "tcp4", nil
	case "tcp6-client":
		return "tcp6", nil
	}
	return "", fmt.Errorf("unsupported client protocol %q", s)
}

// tokenize follows OpenVPN's line grammar: comments begin at a token boundary,
// single quotes are literal, double quotes and bare words permit backslash
// escaping, and quoted tokens must be separated by whitespace.
func tokenize(line string) ([]string, error) {
	var out []string
	for i := 0; i < len(line); {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r') {
			i++
		}
		if i == len(line) || line[i] == '#' || line[i] == ';' {
			break
		}
		var b strings.Builder
		quote := byte(0)
		if line[i] == '\'' || line[i] == '"' {
			quote = line[i]
			i++
		}
		closed := quote == 0
		for i < len(line) {
			c := line[i]
			if quote != 0 && c == quote {
				i++
				closed = true
				break
			}
			if quote == 0 && (c == ' ' || c == '\t' || c == '\r') {
				break
			}
			if quote == 0 && (c == '\'' || c == '"') {
				return nil, fmt.Errorf("quote must start a token")
			}
			if c == '\\' && quote != '\'' {
				i++
				if i == len(line) {
					return nil, fmt.Errorf("unfinished escape")
				}
				c = line[i]
				if c != '\\' && c != '"' && c != ' ' && c != '\t' {
					return nil, fmt.Errorf("invalid backslash escape")
				}
			}
			b.WriteByte(c)
			i++
		}
		if !closed {
			return nil, fmt.Errorf("unterminated quote")
		}
		if quote != 0 && i < len(line) && line[i] != ' ' && line[i] != '\t' && line[i] != '\r' {
			return nil, fmt.Errorf("quoted token must be followed by whitespace")
		}
		out = append(out, b.String())
	}
	return out, nil
}
