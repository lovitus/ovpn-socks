package openvpn

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestReconnectStabilityAndJitter(t *testing.T) {
	for _, d := range []time.Duration{0, time.Second, 59 * time.Second} {
		if got := clientReconnectBackoffAfterSession(32*time.Second, d); got != 32*time.Second {
			t.Fatalf("short session %v reset backoff to %v", d, got)
		}
	}
	if got := clientReconnectBackoffAfterSession(32*time.Second, time.Minute); got != time.Second {
		t.Fatalf("stable session backoff: %v", got)
	}
	for _, base := range []time.Duration{time.Second, 2 * time.Second, 32 * time.Second, time.Minute} {
		for _, sample := range []float64{0, .25, .5, .75, 1} {
			got := clientReconnectDelayWithJitter(nil, base, sample)
			if got < base*8/10 || got > min(base*12/10, time.Minute) {
				t.Fatalf("base %v sample %v delay %v", base, sample, got)
			}
			got = clientReconnectDelayWithJitter(&AuthFailedTemporaryError{BackoffSeconds: 120}, base, sample)
			if got != 120*time.Second {
				t.Fatalf("server minimum truncated: %v", got)
			}
		}
	}
}

func awaitReconnectStatus(t *testing.T, c *Client, check func(ReconnectStatus) bool) ReconnectStatus {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		s := c.ReconnectStatus()
		if check(s) {
			return s
		}
		select {
		case <-deadline.C:
			t.Fatalf("status never reached: %+v", s)
		case <-ticker.C:
		}
	}
}

func TestReconnectFlappingPreservesBackoffAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	options := reconnectTestOptions(ctx)
	peers := make(chan net.Conn, 4)
	options.Transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		client, peer := net.Pipe()
		peers <- peer
		return client, nil
	}
	c, err := NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer func() {
		for {
			select {
			case peer := <-peers:
				peer.Close()
			default:
				return
			}
		}
	}()
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	for i := uint64(1); i <= 3; i++ {
		s := awaitReconnectStatus(t, c, func(s ReconnectStatus) bool { return s.State == "connected" && s.Attempts == i })
		if s.Retries != i-1 || s.Reconnects != i-1 {
			t.Fatalf("incorrect counters: %+v", s)
		}
		peer := <-peers
		peer.Close()
		s = awaitReconnectStatus(t, c, func(s ReconnectStatus) bool { return s.State == "backoff" && s.Attempts == i })
		base := time.Second * time.Duration(1<<(i-1))
		if s.Backoff < base*8/10 || s.Backoff > base*12/10 || s.NextAttempt.IsZero() || s.ConsecutiveFailures != i {
			t.Fatalf("flap reset backoff or lost failure: %+v", s)
		}
	}
	cancel()
	waitSupervisor(t, c)
	s := c.ReconnectStatus()
	if s.State != "closed" || s.Attempts != 3 || s.Backoff != 0 || !s.NextAttempt.IsZero() {
		t.Fatalf("cancellation state: %+v", s)
	}
}

func TestReconnectTerminalFailureDoesNotRetry(t *testing.T) {
	options := reconnectTestOptions(context.Background())
	options.Transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, &AuthFailedTerminalError{Reason: "sensitive-server-detail"}
	}
	c, err := NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	waitSupervisor(t, c)
	s := c.ReconnectStatus()
	if s.State != "terminal" || s.Attempts != 1 || s.Retries != 0 || s.LastError != "terminal session failure" {
		t.Fatalf("terminal status: %+v", s)
	}
	if !errors.Is(c.currentDataReadError(), ErrAuthenticationFailed) {
		t.Fatalf("lost terminal auth failure: %v", c.currentDataReadError())
	}
}

func TestReconnectSnapshotStabilityAndIsolation(t *testing.T) {
	c := &Client{}
	if c.ReconnectStatus().State != "idle" {
		t.Fatal("new client is not idle")
	}
	c.noteReconnectAttempt(time.Now())
	c.noteReconnectFailure(errors.New("private detail"), false)
	c.noteReconnectConnected(time.Now().Add(-clientReconnectStableDuration), true)
	s := c.ReconnectStatus()
	if s.ConsecutiveFailures != 0 || s.State != "connected" || s.ConnectedSince.IsZero() {
		t.Fatalf("stable status: %+v", s)
	}
	s.Attempts = 999
	if c.ReconnectStatus().Attempts != 1 {
		t.Fatal("snapshot mutated client")
	}
	c.noteReconnectFailure(errors.New("private detail"), true)
	if s = c.ReconnectStatus(); s.ConsecutiveFailures != 1 || s.LastError != "retryable session failure" {
		t.Fatalf("stable reset failed: %+v", s)
	}
}

func TestReconnectWaitCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitClientReconnectBackoff(ctx, 24*time.Hour) {
		t.Fatal("canceled backoff retried")
	}
}
