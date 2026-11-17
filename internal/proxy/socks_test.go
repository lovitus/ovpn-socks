package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func request(t *testing.T, s *Server, command byte, host string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var response [2]byte
	if _, err = io.ReadFull(c, response[:]); err != nil || response != [2]byte{5, 0} {
		t.Fatalf("greeting: %v %v", response, err)
	}
	message := append([]byte{5, command, 0, 3, byte(len(host))}, []byte(host)...)
	message = append(message, 0, 80)
	if _, err = c.Write(message); err != nil {
		t.Fatal(err)
	}
	return c
}
func TestSOCKSDomainPassedToIsolatedDialer(t *testing.T) {
	got := make(chan string, 1)
	s, err := Listen("127.0.0.1:0", func(_ context.Context, address string) (net.Conn, error) {
		got <- address
		a, b := net.Pipe()
		go func() { defer b.Close(); buffer := make([]byte, 4); io.ReadFull(b, buffer); b.Write(buffer) }()
		return a, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := request(t, s, 1, "must-never-use-host-dns.invalid")
	defer c.Close()
	var response [10]byte
	if _, err = io.ReadFull(c, response[:]); err != nil || response[1] != 0 {
		t.Fatalf("reply: %v %v", response, err)
	}
	if address := <-got; address != "must-never-use-host-dns.invalid:80" {
		t.Fatal(address)
	}
	c.Write([]byte("ping"))
	var echo [4]byte
	if _, err = io.ReadFull(c, echo[:]); err != nil || string(echo[:]) != "ping" {
		t.Fatalf("echo %q %v", echo, err)
	}
}
func TestSOCKSOfflineFailsClosedAndUDPUnsupported(t *testing.T) {
	var count atomic.Int32
	s, err := Listen("127.0.0.1:0", func(context.Context, string) (net.Conn, error) { count.Add(1); return nil, errors.New("offline") })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, tc := range []struct{ command, status byte }{{1, 4}, {3, 7}, {2, 7}} {
		c := request(t, s, tc.command, "example.invalid")
		var response [10]byte
		_, err := io.ReadFull(c, response[:])
		c.Close()
		if err != nil || response[1] != tc.status {
			t.Fatalf("command %d response %v: %v", tc.command, response, err)
		}
	}
	if count.Load() != 1 {
		t.Fatalf("unsupported commands dialed: %d", count.Load())
	}
}
func TestSOCKSRejectsPublicListeners(t *testing.T) {
	for _, address := range []string{"0.0.0.0:0", ":0", "localhost:0", "[::]:0"} {
		if s, err := Listen(address, func(context.Context, string) (net.Conn, error) { return nil, errors.New("offline") }); err == nil {
			s.Close()
			t.Errorf("accepted %s", address)
		}
	}
}
