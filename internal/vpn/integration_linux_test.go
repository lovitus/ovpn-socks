//go:build linux

package vpn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestOfficialOpenVPNInterop is intentionally opt-in: the official SERVER fixture
// needs CAP_NET_ADMIN and /dev/net/tun in an isolated Linux CI runner. The client
// under test remains entirely userspace and never opens that device.
// Run: sudo -E env OVPN_INTEGRATION=1 go test -v ./internal/vpn -run TestOfficialOpenVPNInterop
func TestOfficialOpenVPNInterop(t *testing.T) {
	if os.Getenv("OVPN_INTEGRATION") != "1" {
		t.Skip("set OVPN_INTEGRATION=1 in an isolated Linux runner with OpenVPN and CAP_NET_ADMIN")
	}
	binary, err := exec.LookPath("openvpn")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"tls-auth", "tls-crypt"} {
		t.Run(mode, func(t *testing.T) { testOfficialOpenVPN(t, binary, mode) })
	}
}

type lockedOutput struct {
	sync.Mutex
	data []byte
}

func (b *lockedOutput) Write(data []byte) (int, error) {
	b.Lock()
	b.data = append(b.data, data...)
	b.Unlock()
	return len(data), nil
}
func (b *lockedOutput) String() string {
	b.Lock()
	defer b.Unlock()
	return string(append([]byte(nil), b.data...))
}
func testOfficialOpenVPN(t *testing.T, binary, mode string) {
	dir := t.TempDir()
	ca, serverCert, serverKey, clientCert, clientKey := testCertificates(t)
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	caPath := write("ca.pem", ca)
	serverCertPath := write("server.pem", serverCert)
	serverKeyPath := write("server.key", serverKey)
	static := make([]byte, 256)
	if _, err := rand.Read(static); err != nil {
		t.Fatal(err)
	}
	staticHex := hex.EncodeToString(static)
	var key strings.Builder
	key.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(staticHex); i += 32 {
		key.WriteString(staticHex[i:i+32] + "\n")
	}
	key.WriteString("-----END OpenVPN Static key V1-----\n")
	staticPath := write("control.key", key.String())
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := socket.LocalAddr().(*net.UDPAddr).Port
	socket.Close()
	unique := make([]byte, 4)
	rand.Read(unique)
	dev := "ovs" + hex.EncodeToString(unique)
	controlServer := mode + " " + staticPath
	if mode == "tls-auth" {
		controlServer += " 0"
	}
	config := fmt.Sprintf("local 127.0.0.1\nport %d\nproto udp\ndev %s\ndev-type tun\ntopology subnet\nserver 10.203.77.0 255.255.255.0\nca %s\ncert %s\nkey %s\ndh none\n%s\ndata-ciphers AES-256-GCM\ncipher AES-256-GCM\nauth SHA256\ntls-version-min 1.2\nkeepalive 2 10\npush \"route 10.42.0.0 255.255.0.0\"\npush \"route-ipv6 2001:db8:42::/64\"\npush \"dhcp-option DNS 10.203.77.1\"\nverb 3\n", port, dev, caPath, serverCertPath, serverKeyPath, controlServer)
	confPath := write("server.ovpn", config)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--config", confPath)
	output := &lockedOutput{}
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- cmd.Wait() }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
		}
	})
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for !strings.Contains(output.String(), "Initialization Sequence Completed") {
		select {
		case err := <-serverDone:
			t.Fatalf("server exited: %v\n%s", err, output.String())
		case <-deadline.C:
			t.Fatalf("server did not initialize: %s", output.String())
		case <-tick.C:
		}
	}
	listener, err := net.Listen("tcp4", "10.203.77.1:0")
	if err != nil {
		t.Fatalf("server tunnel not configured: %v\n%s", err, output.String())
	}
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.RemoteAddr, "10.203.77.") {
			t.Errorf("HTTP arrived outside VPN: %s", r.RemoteAddr)
		}
		io.WriteString(w, "official-openvpn-userspace-ok")
	}), ReadHeaderTimeout: 3 * time.Second}
	go httpServer.Serve(listener)
	defer httpServer.Close()
	clientConfig := fmt.Sprintf("client\ndev tun\nproto udp\nremote 127.0.0.1 %d\nremote-cert-tls server\nverify-x509-name ovpn-test-server name\ndata-ciphers AES-256-GCM\ncipher AES-256-GCM\nauth SHA256\n<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n<%s>\n%s</%s>\n", port, ca, clientCert, clientKey, mode, key.String(), mode)
	if mode == "tls-auth" {
		clientConfig += "key-direction 1\n"
	}
	session, err := Start(ctx, Options{ID: "integration-" + mode, Config: clientConfig, AutoReconnect: true})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Stop()
	until := time.NewTimer(20 * time.Second)
	defer until.Stop()
	for session.Snapshot().State != "connected" {
		select {
		case <-ctx.Done():
			t.Fatalf("timeout: %+v\n%s", session.Snapshot(), output.String())
		case <-until.C:
			t.Fatalf("client did not connect: %+v\n%s", session.Snapshot(), output.String())
		case <-tick.C:
		}
	}
	snapshot := session.Snapshot()
	if !strings.Contains(strings.Join(snapshot.Routes, "\n"), "10.42.0.0/16") || !strings.Contains(strings.Join(snapshot.Routes, "\n"), "2001:db8:42::/64") {
		t.Fatalf("pushed routes missing: %+v", snapshot)
	}
	if len(snapshot.DNS) != 1 || snapshot.DNS[0] != "10.203.77.1" {
		t.Fatalf("DNS: %v", snapshot.DNS)
	}
	address := listener.Addr().(*net.TCPAddr)
	conn, err := net.DialTimeout("tcp", snapshot.Listen, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte{5, 1, 0})
	reply := make([]byte, 2)
	if _, err = io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
		t.Fatalf("SOCKS greeting: %x %v", reply, err)
	}
	request := []byte{5, 1, 0, 1, 10, 203, 77, 1, byte(address.Port >> 8), byte(address.Port)}
	conn.Write(request)
	reply = make([]byte, 10)
	if _, err = io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
		t.Fatalf("SOCKS CONNECT: %x %v %+v", reply, err, session.Snapshot())
	}
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: vpn-fixture\r\n\r\n")
	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(response), "official-openvpn-userspace-ok") {
		t.Fatalf("HTTP over VPN failed: %q", response)
	}
	session.Stop()
	if got := session.Snapshot().State; got != "stopped" {
		t.Fatal("Stop state:", got)
	}
	t.Log("official OpenVPN " + mode + " TCP via userspace stack verified, SOCKS port " + strconv.Itoa(address.Port))
}
func testCertificates(t *testing.T) (ca, serverCert, serverKey, clientCert, clientKey string) {
	t.Helper()
	makeKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	caKey := makeKey()
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ovpn-test-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	issue := func(serial int64, name string, usage x509.ExtKeyUsage) (string, string) {
		key := makeKey()
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{usage}, BasicConstraintsValid: true}
		der, err := x509.CreateCertificate(rand.Reader, template, caTemplate, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	}
	serverCert, serverKey = issue(2, "ovpn-test-server", x509.ExtKeyUsageServerAuth)
	clientCert, clientKey = issue(3, "ovpn-test-client", x509.ExtKeyUsageClientAuth)
	return
}
