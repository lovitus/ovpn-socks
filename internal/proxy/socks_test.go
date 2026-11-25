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

// net.Pipe makes the regression deterministic: the client cannot finish its
// request write unless the server consumes all address and port bytes before
// writing the rejection. TCP buffering otherwise makes this failure intermittent.
func TestSOCKSUnsupportedCommandConsumesRequest(t *testing.T) {
	for _, command := range []byte{2, 3} {
		for _, address := range [][]byte{
			{1, 127, 0, 0, 1},
			{3, 3, 'v', 'p', 'n'},
			append([]byte{4}, make([]byte, 16)...),
		} {
			func() {
				client, server := net.Pipe()
				defer client.Close()
				client.SetDeadline(time.Now().Add(2 * time.Second))
				s := &Server{ctx: context.Background(), dial: func(context.Context, string) (net.Conn, error) {
					t.Error("unsupported command reached dialer")
					return nil, errors.New("unexpected dial")
				}}
				done := make(chan struct{})
				go func() { defer close(done); defer server.Close(); s.serve(server) }()
				defer func() { client.Close(); <-done }()
				if _, err := client.Write([]byte{5, 1, 0}); err != nil {
					t.Fatal(err)
				}
				var greeting [2]byte
				if _, err := io.ReadFull(client, greeting[:]); err != nil {
					t.Fatal(err)
				}
				message := append([]byte{5, command, 0}, address...)
				message = append(message, 0, 0) // UDP commonly requests a zero port.
				if _, err := client.Write(message); err != nil {
					t.Fatalf("command %d request not consumed: %v", command, err)
				}
				var response [10]byte
				if _, err := io.ReadFull(client, response[:]); err != nil || response[1] != 7 {
					t.Fatalf("command %d reply %v: %v", command, response, err)
				}
				<-done
				if m := s.Metrics(); m.RequestsFailed != 1 || m.DialCount != 0 {
					t.Fatalf("rejected request metrics: %+v", m)
				}
			}()
		}
	}
}

func TestSOCKSInterfaceListeners(t *testing.T) {
	for _, address := range []string{"0.0.0.0:0", ":0", "127.0.0.1:0"} {
		s, err := Listen(address, func(context.Context, string) (net.Conn, error) { return nil, errors.New("offline") })
		if err != nil {
			t.Fatalf("listen %s: %v", address, err)
		}
		_, port, _ := net.SplitHostPort(s.Addr())
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second)
		if err != nil {
			s.Close()
			t.Fatal(err)
		}
		c.Close()
		s.Close()
	}
	if s, err := Listen("invalid.example:0", func(context.Context, string) (net.Conn, error) { return nil, errors.New("offline") }); err == nil {
		s.Close()
		t.Fatal("accepted non-IP listener")
	}
}
