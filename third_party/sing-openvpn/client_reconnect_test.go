package openvpn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func reconnectTestOptions(ctx context.Context) ClientOptions {
	return ClientOptions{Context: ctx, Mode: ModeStaticKey,
		StaticKey:   Material{Content: bytes.Repeat([]byte{0x42}, 256)},
		DataChannel: ClientDataChannelOptions{Cipher: "AES-256-CBC", Auth: "SHA256"},
		Transport:   ClientTransportOptions{Protocol: "tcp", Remotes: []Remote{{Host: "127.0.0.1", Port: 1194, Protocol: "tcp"}}},
	}
}

func waitSupervisor(t *testing.T, c *Client) {
	t.Helper()
	select {
	case <-c.lifecycle.supervisorDone:
	case <-time.After(4 * time.Second):
		t.Fatal("supervisor did not stop")
	}
}

func TestDisableReconnectInitialFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sentinel := errors.New("example dial failure")
	options := reconnectTestOptions(ctx)
	options.DisableReconnect = true
	var calls atomic.Int32
	options.Transport.DialContext = func(context.Context, string, string) (net.Conn, error) { calls.Add(1); return nil, sentinel }
	c, err := NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = c.WaitReady(ctx); !errors.Is(err, sentinel) {
		t.Fatalf("initial failure not reported: %v", err)
	}
	waitSupervisor(t, c)
	if calls.Load() != 1 {
		t.Fatalf("dial calls=%d, want 1", calls.Load())
	}
}

func TestDisableReconnectAfterEstablishedSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	options := reconnectTestOptions(ctx)
	options.DisableReconnect = true
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	var calls atomic.Int32
	options.Transport.DialContext = func(context.Context, string, string) (net.Conn, error) { calls.Add(1); return clientConn, nil }
	c, err := NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = c.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err = serverConn.Close(); err != nil {
		t.Fatal(err)
	}
	waitSupervisor(t, c)
	if calls.Load() != 1 {
		t.Fatalf("dial calls=%d, want 1", calls.Load())
	}
	if err = c.currentDataReadError(); err == nil {
		t.Fatal("ended session did not expose error")
	}
	if c.Ready() {
		t.Fatal("ended session remained ready")
	}
}

func TestReconnectDefaultRetriesInitialFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	options := reconnectTestOptions(ctx)
	var calls atomic.Int32
	retried := make(chan struct{})
	options.Transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		if calls.Add(1) == 2 {
			close(retried)
			cancel()
		}
		return nil, io.EOF
	}
	c, err := NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-retried:
	case <-ctx.Done():
		t.Fatal("default reconnect did not retry")
	}
	waitSupervisor(t, c)
	if calls.Load() != 2 {
		t.Fatalf("dial calls=%d, want 2", calls.Load())
	}
}
