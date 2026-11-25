package openvpn

import "time"

// ReconnectStatus is a read-only snapshot of the client supervisor. Attempts
// includes the first attempt; Retries counts subsequent attempts, successful or
// not. Reconnects counts successful connections after the first success.
// Backoff and NextAttempt describe only a currently scheduled retry.
// LastError is deliberately a fixed category, not a server-provided string,
// because authentication errors can contain sensitive challenge material.
type ReconnectStatus struct {
	State               string
	Attempts            uint64
	Retries             uint64
	Reconnects          uint64
	ConsecutiveFailures uint64
	LastAttempt         time.Time
	ConnectedSince      time.Time
	NextAttempt         time.Time
	Backoff             time.Duration
	LastError           string
}

// ReconnectStatus returns a consistent value copy safe for concurrent polling.
// State is idle, connecting, connected, backoff, suspended, terminal, or closed.
func (c *Client) ReconnectStatus() ReconnectStatus {
	c.lifecycle.access.Lock()
	defer c.lifecycle.access.Unlock()
	status := c.lifecycle.reconnect
	if status.State == "" {
		status.State = "idle"
	}
	switch {
	case c.lifecycle.closed:
		status.State = "closed"
	case c.lifecycle.terminalError != nil:
		status.State = "terminal"
	case c.lifecycle.suspended.Load():
		status.State = "suspended"
	}
	if status.State != "backoff" {
		status.Backoff = 0
		status.NextAttempt = time.Time{}
	}
	if status.State != "connected" {
		status.ConnectedSince = time.Time{}
	}
	if status.State == "connected" && time.Since(status.ConnectedSince) >= clientReconnectStableDuration {
		status.ConsecutiveFailures = 0
	}
	return status
}

func (c *Client) noteReconnectAttempt(now time.Time) {
	c.lifecycle.access.Lock()
	defer c.lifecycle.access.Unlock()
	s := &c.lifecycle.reconnect
	s.Attempts++
	s.Retries = s.Attempts - 1
	s.State = "connecting"
	s.LastAttempt = now
	s.Backoff = 0
	s.NextAttempt = time.Time{}
	s.ConnectedSince = time.Time{}
}

func (c *Client) noteReconnectConnected(now time.Time, first bool) {
	c.lifecycle.access.Lock()
	defer c.lifecycle.access.Unlock()
	s := &c.lifecycle.reconnect
	s.State = "connected"
	s.ConnectedSince = now
	s.LastError = ""
	if !first {
		s.Reconnects++
	}
}

func (c *Client) noteReconnectFailure(err error, stable bool) {
	c.lifecycle.access.Lock()
	defer c.lifecycle.access.Unlock()
	s := &c.lifecycle.reconnect
	if stable {
		s.ConsecutiveFailures = 0
	}
	s.ConsecutiveFailures++
	s.ConnectedSince = time.Time{}
	s.State = "connecting"
	if classifyClientSessionError(err) == clientSessionErrorTerminal {
		s.LastError = "terminal session failure"
	} else {
		s.LastError = "retryable session failure"
	}
}

func (c *Client) noteReconnectBackoff(delay time.Duration) {
	c.lifecycle.access.Lock()
	defer c.lifecycle.access.Unlock()
	s := &c.lifecycle.reconnect
	s.State = "backoff"
	s.Backoff = delay
	s.NextAttempt = time.Now().Add(delay)
}
