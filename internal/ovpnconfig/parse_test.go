package ovpnconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func caPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
func profile(ca, extra string) string {
	return "client\ndev tun\nremote vpn.example 1194\n" + extra + "\n<ca>\n" + ca + "</ca>\n"
}

func TestOpenVPN234Profile(t *testing.T) {
	text := profile(caPEM(t), `proto udp
resolv-retry infinite
nobind
persist-key
persist-tun
ns-cert-type server
cipher AES-128-CBC
auth SHA1
comp-lzo
verb 3
mute 20
auth-user-pass
auth-nocache
reneg-sec 0
ping 10
ping-restart 0
tun-mtu 1400`)
	o, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if o.Mode != "tls" || o.KeyDirection != -1 || o.Tunnel.DevType != "tun" || !o.Pull.Enabled {
		t.Fatalf("invalid defaults: %+v", o)
	}
	if o.TLS.NSCertificateType != "server" || o.TLS.RemoteCertificateTLS != "" || o.TLS.CertificateAuthority.Path != "" {
		t.Fatalf("legacy verification policy lost: %+v", o.TLS)
	}
	if o.DataChannel.Cipher != "AES-128-CBC" || o.DataChannel.Auth != "SHA1" || o.DataChannel.CompressionLZO != "adaptive" {
		t.Fatalf("legacy data policy lost: %+v", o.DataChannel)
	}
	if !o.Timing.RenegotiationDisabled || !o.Timing.PingRestartDisabled || o.Timing.PingInterval != 10*time.Second {
		t.Fatalf("timing policy lost: %+v", o.Timing)
	}
	if o.Authentication.Username != "" || o.Authentication.Password != "" {
		t.Fatal("parser must leave UI credentials unset")
	}
}
func TestRemotesAndQuotedSecurityPolicy(t *testing.T) {
	text := "\ufeff" + profile(caPEM(t), `proto tcp-client
port 443
remote "second.example" 8443 tcp4-client ; comment
remote third.example
verify-x509-name "VPN Server" name
pull-filter ignore "redirect-gateway"
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-128-CBC
key-direction 1
tls-version-min 1.2
tls-version-max 1.3`)
	o, err := Parse(strings.ReplaceAll(text, "\n", "\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Transport.Remotes) != 3 || o.Transport.Remotes[0].Protocol != "tcp" || o.Transport.Remotes[1].Protocol != "tcp4" || o.Transport.Remotes[2].Port != 443 {
		t.Fatalf("incorrect remote inheritance: %+v", o.Transport)
	}
	if o.TLS.RemoteCertificateTLS != "server" || o.TLS.VerifyX509Name != "VPN Server" || o.TLS.VerifyX509Type != "name" || o.KeyDirection != 1 {
		t.Fatalf("identity policy lost: %+v", o)
	}
	if len(o.Pull.Filters) != 1 || len(o.DataChannel.Ciphers) != 2 {
		t.Fatal("list options lost")
	}
}
func TestInlineControlKeys(t *testing.T) {
	ca := caPEM(t)
	for _, tag := range []string{"tls-auth", "tls-crypt", "tls-crypt-v2"} {
		t.Run(tag, func(t *testing.T) {
			o, err := Parse(profile(ca, tag+" [inline]\n<"+tag+">\nopaque key material\n</"+tag+">"))
			if err != nil {
				t.Fatal(err)
			}
			p := parser{o: o}
			m := p.material(tag)
			if m.Path != "" || string(m.Content) != "opaque key material\n" {
				t.Fatalf("inline material changed: %+v", m)
			}
		})
	}
}
func TestRejectUnsafeOrUnsupported(t *testing.T) {
	ca := caPEM(t)
	cases := []string{
		"ca C:\\\\secrets\\\\ca.crt", "cert client.crt", "key client.key", "tls-auth ta.key 1", "tls-crypt secret.key", "auth-user-pass credentials.txt",
		"up run.exe", "down run.exe", "plugin evil.dll", "script-security 2", "management localhost 1234", "config other.ovpn", "include other.ovpn", "log trace.txt", "status stats.txt", "crl-verify crl.pem", "pkcs12 identity.p12", "tls-verify verify.cmd", "setenv opt tls-cert-profile insecure",
		"dev tap", "dev-type tap", "remote-cert-tls client", "ns-cert-type client", "unknown-security-policy yes", "tls-version-min 9.0", "tls-version-min 1.3\ntls-version-max 1.2", "verify-x509-name server invalid", "cipher TYPO", "auth TYPO", "data-ciphers AES-256-GCM:", "pull-filter ignore \"\"", "auth-user-pass \"\"",
		"reneg-sec -1", "ping 18446744073709551615", "tun-mtu 0", "remote bad.example 65536", "proto tcp-server", "key-direction 2", "key-direction 0\nkey-direction 1", "keepalive 10 60\nping 5", "ping 5\nkeepalive 10 60",
		"<ca>\nx\n</ca>", "<tls-auth>\n<key>\nx\n</key>\n</tls-auth>", "<tls-auth>\nx", "<connection>\nremote example\n</connection>", "<tls-auth>\n\n</tls-auth>", "tls-auth [inline]", "tls-crypt [inline]\n<tls-crypt>\nx\n</tls-crypt>\n<tls-auth>\ny\n</tls-auth>",
		"remote \"unterminated", "verb 3 extra", "persist-tun yes", "verify-x509-name \"a\"suffix name", "ca [inline]\nca [inline]",
		"compress \"\"", "comp-lzo \"\"", "compress stub-v2\ncomp-lzo", "comp-lzo\ncompress stub-v2", "float",
	}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			if _, err := Parse(profile(ca, s)); err == nil {
				t.Fatalf("accepted forbidden or malformed input %q", s)
			}
		})
	}
}
func TestMissingTrustOrBrokenMaterial(t *testing.T) {
	cases := []string{"client\nremote example", profile("not a certificate\n", ""), profile(caPEM(t), "<cert>\ninvalid\n</cert>"), profile(caPEM(t), "<cert>\ninvalid\n</cert>\n<key>\ninvalid\n</key>"), profile(caPEM(t), "\x00"), strings.Repeat("x", maxProfileSize+1)}
	for i, text := range cases {
		if _, err := Parse(text); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
func TestTokenizer(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{` ; comment`, nil}, {`remote vpn#one 1194 # comment`, []string{"remote", "vpn#one", "1194"}},
		{`verify-x509-name "VPN \"Server\"" name`, []string{"verify-x509-name", `VPN "Server"`, "name"}},
		{`pull-filter ignore 'route ; # literal'`, []string{"pull-filter", "ignore", "route ; # literal"}},
		{`verify-x509-name VPN\ Server name`, []string{"verify-x509-name", "VPN Server", "name"}},
	}
	for _, c := range cases {
		got, err := tokenize(c.line)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("tokenize(%q) = %#v, %v; want %#v", c.line, got, err, c.want)
		}
	}
	for _, s := range []string{`x "bad`, `x 'bad`, `x bad\`, `x bad\q`, `x "x"tail`} {
		if _, err := tokenize(s); err == nil {
			t.Errorf("accepted malformed %q", s)
		}
	}
}

// Optional local compatibility check; no real profile or credential is copied
// into the repository and the test never starts a VPN connection.
func TestLocalProfile(t *testing.T) {
	path := os.Getenv("OVPN_TEST_PROFILE")
	if path == "" {
		t.Skip("set OVPN_TEST_PROFILE to check a local self-contained profile")
	}
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	o, err := Parse(string(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Transport.Remotes) == 0 || len(o.TLS.CertificateAuthority.Content) == 0 {
		t.Fatal("profile produced no remote or trust material")
	}
}

func TestTunnelMetadata(t *testing.T) {
	o, err := Parse(profile(caPEM(t), `topology subnet
ifconfig 10.8.0.2 255.255.255.0
route 10.10.0.0 255.255.0.0 10.8.0.1 5
route-ipv6 fd00::/64 fd01::1
redirect-gateway def1
dhcp-option DNS 10.8.0.1
block-ipv6`))
	if err != nil {
		t.Fatal(err)
	}
	if o.Tunnel.LocalAddress[0].String() != "10.8.0.2/24" || len(o.Tunnel.Routes) != 2 || !o.Tunnel.RedirectGateway || !o.Tunnel.BlockIPv6 {
		t.Fatalf("metadata lost: %+v", o.Tunnel)
	}
}
