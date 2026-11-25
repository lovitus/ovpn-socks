package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flyssh/flyssh/internal/testkit"
	"github.com/flyssh/flyssh/pkg/managed"
)

// This subprocess test checks the wire contract and actual forwarded payloads.
// Set OVPN_FLYSSH_TEST_BINARY to the instrumented native executable.
func TestManagedObservationWire(t *testing.T) {
	binary := os.Getenv("OVPN_FLYSSH_TEST_BINARY")
	if binary == "" {
		t.Skip("set OVPN_FLYSSH_TEST_BINARY")
	}
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	echo := echoListener.Addr().String()
	closeEcho := make(chan struct{})
	var once sync.Once
	stopEcho := func() { once.Do(func() { close(closeEcho) }) }
	defer stopEcho()
	go func() {
		for {
			c, e := echoListener.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); go func() { <-closeEcho; _ = c.Close() }(); _, _ = io.Copy(c, c) }()
		}
	}()
	sshServer := testkit.StartSSHServer(t, map[string]string{"u": "test-password"})
	host, port, _ := net.SplitHostPort(sshServer.Addr)
	const token = "0123456789abcdef0123456789abcdef"
	args := []string{"-N", "--no-reconnect", "--relay=disable", "--password", "test-password", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=" + t.TempDir() + "/known_hosts", "-p", port, "-L", "127.0.0.1:0:" + echo, "-L", "127.0.0.1:0:" + echo, "-R", "127.0.0.1:0:" + echo, "-D", "127.0.0.1:0", "u@" + host}
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), "OVPN_SOCKS_TELEMETRY_TOKEN="+token)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	events := make(chan managed.Envelope, 64)
	go func() {
		defer close(events)
		s := bufio.NewScanner(stdout)
		s.Buffer(make([]byte, 4096), 256*1024)
		for s.Scan() {
			line := s.Text()
			if !strings.HasPrefix(line, "OVPN_ENGINE_"+token+" ") {
				continue
			}
			if strings.Contains(line, "test-password") {
				return
			}
			var e managed.Envelope
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "OVPN_ENGINE_"+token+" ")), &e) == nil {
				events <- e
			}
		}
	}()
	await := func(predicate func(managed.Envelope) bool) managed.Envelope {
		deadline := time.NewTimer(15 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case e, ok := <-events:
				if !ok {
					t.Fatalf("telemetry closed: %s", stderr.String())
				}
				t.Logf("snapshot state=%s active=%d total=%d upload=%d download=%d listeners=%+v", e.State, e.Active, e.Total, e.Upload, e.Download, e.Listeners)
				if predicate(e) {
					return e
				}
			case <-deadline.C:
				t.Fatalf("telemetry condition timed out: %s", stderr.String())
			}
		}
	}
	ready := await(func(e managed.Envelope) bool {
		if e.State != "connected" || len(e.Listeners) != 4 {
			return false
		}
		for _, l := range e.Listeners {
			if l.State != "listening" || l.ActualAddress == "" || strings.HasSuffix(l.ActualAddress, ":0") {
				return false
			}
		}
		return true
	})
	payload := bytes.Repeat([]byte("payload"), 8192)
	conns := make([]net.Conn, 0, 4)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for _, l := range ready.Listeners {
		c, err := net.DialTimeout("tcp", l.ActualAddress, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if l.Kind == "socks5" {
			_, _ = c.Write([]byte{5, 1, 0})
			greeting := make([]byte, 2)
			if _, err = io.ReadFull(c, greeting); err != nil {
				t.Fatal(err)
			}
			eh, ep, _ := net.SplitHostPort(echo)
			var pn int
			_, _ = fmt.Sscan(ep, &pn)
			ip := net.ParseIP(eh).To4()
			request := append([]byte{5, 1, 0, 1}, ip...)
			request = append(request, byte(pn>>8), byte(pn))
			_, _ = c.Write(request)
			reply := make([]byte, 10)
			if _, err = io.ReadFull(c, reply); err != nil || reply[1] != 0 {
				t.Fatalf("SOCKS: %v %v", reply, err)
			}
		}
		if _, err = c.Write(payload); err != nil {
			t.Fatal(err)
		}
		received := make([]byte, len(payload))
		if _, err = io.ReadFull(c, received); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(payload, received) {
			t.Fatal("payload mismatch")
		}
	}
	measured := await(func(e managed.Envelope) bool {
		if e.Active != 4 {
			return false
		}
		for _, l := range e.Listeners {
			if !l.Metrics || l.Upload != uint64(len(payload)) || l.Download != uint64(len(payload)) || l.Active != 1 || l.Total != 1 {
				return false
			}
		}
		return true
	})
	if measured.Upload != uint64(4*len(payload)) || measured.Download != measured.Upload {
		t.Fatalf("bad aggregate: %+v", measured)
	}
	for _, c := range conns {
		_ = c.Close()
	}
	// Upstream testkit relay waits for both directions without half-closing;
	// close the echo endpoint too so the mock SSH server can finish its copies.
	stopEcho()
	await(func(e managed.Envelope) bool { return e.Active == 0 && e.Total == 4 && e.Upload == measured.Upload })
}
