package openvpn

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCredentialsCallbackFreshPerExchange(t *testing.T) {
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "test-context")
	c := &Client{mode: ModeTLS}
	calls := 0
	c.options.Authentication.Credentials = func(got context.Context) (string, string, error) {
		if got.Value(contextKey{}) != "test-context" {
			t.Error("callback did not receive session context")
		}
		calls++
		return "example-user", fmt.Sprintf("example-password-%d", calls), nil
	}
	for i, useToken := range []bool{false, true, true} {
		// The supervisor runs this once per full connection; the exchange itself
		// is also used directly for TLS renegotiation without acquisition here.
		if i < 2 {
			if err := c.acquireSessionCredentials(ctx, useToken); err != nil {
				t.Fatal(err)
			}
		}
		if calls != i {
			t.Fatal("callback ran before key-method exchange")
		}
		username, password, err := c.sessionCredentials(ctx, useToken)
		if err != nil || username != "example-user" || password != fmt.Sprintf("example-password-%d", i+1) {
			t.Fatalf("exchange %d: unexpected credentials or error %v", i, err)
		}
	}
	if calls != 3 {
		t.Fatalf("calls=%d, want 3", calls)
	}
	if c.loadStagedCredentials().password != "" {
		t.Fatal("callback password was cached")
	}
}

func TestCredentialsCallbackTokenPriorityAndRejectedFallback(t *testing.T) {
	c := &Client{mode: ModeTLS}
	calls := 0
	c.options.Authentication.Credentials = func(context.Context) (string, string, error) {
		calls++
		return "example-user", fmt.Sprintf("example-password-%d", calls), nil
	}
	ctx := context.Background()
	if _, _, err := c.sessionCredentials(ctx, false); err != nil {
		t.Fatal(err)
	}
	c.tunnel.authToken = "example-server-token"
	if err := c.acquireSessionCredentials(ctx, true); err != nil {
		t.Fatal(err)
	}
	username, password, err := c.sessionCredentials(ctx, true)
	if err != nil || username != "example-user" || password != "example-server-token" || calls != 1 {
		t.Fatalf("token did not take priority: callback calls=%d, err=%v", calls, err)
	}
	c.tunnel.authTokenUser = base64.StdEncoding.EncodeToString([]byte("example-token-user"))
	username, password, err = c.sessionCredentials(ctx, true)
	if err != nil || username != "example-token-user" || password != "example-server-token" || calls != 1 {
		t.Fatal("auth-token-user was not honored")
	}
	// Exercise the upstream AUTH_FAILED handler rather than clearing the token
	// manually: the next connection must acquire fresh application credentials.
	session := &tlsClient{parent: c}
	var rejected *AuthTokenAuthenticationFailedError
	if !errors.As(session.authFailedError([]byte("AUTH_FAILED,example rejection")), &rejected) {
		t.Fatal("token rejection did not propagate")
	}
	username, password, err = c.sessionCredentials(ctx, true)
	if err != nil || username != "example-user" || password != "example-password-2" || calls != 2 {
		t.Fatalf("no fresh fallback after rejected token: calls=%d err=%v", calls, err)
	}
	c.tunnel.authToken = "example-server-token"
	c.tunnel.authTokenUser = "invalid-base64!"
	if _, _, err = c.sessionCredentials(ctx, true); err != nil || calls != 3 {
		t.Fatal("invalid token username did not fall back to callback")
	}
}

func TestCredentialsCallbackErrorNeverUsesOldPassword(t *testing.T) {
	sentinel := errors.New("example credential source failure")
	c := &Client{mode: ModeTLS}
	c.options.Authentication.Username = "example-old-user"
	c.options.Authentication.Password = "example-old-password"
	c.stageCredentials("example-staged-user", "example-staged-password", false)
	c.options.Authentication.Credentials = func(context.Context) (string, string, error) { return "partial-user", "partial-password", sentinel }
	ctx := context.Background()
	username, password, err := c.sessionCredentials(ctx, true)
	if !errors.Is(err, sentinel) || username != "" || password != "" {
		t.Fatal("callback error fell back to cached or partial credentials")
	}
	// The actual initial key-method caller must return the callback error before
	// trying to write a TLS record (tlsConnection is deliberately nil).
	session := &tlsClient{parent: c, sessionContext: ctx}
	if err = session.exchangeKeyMethod(time.Now().Add(time.Second)); !errors.Is(err, sentinel) {
		t.Fatalf("key-method caller lost callback error: %v", err)
	}
}

func TestCredentialsCallbackCancellation(t *testing.T) {
	c := &Client{mode: ModeTLS}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	c.options.Authentication.Credentials = func(context.Context) (string, string, error) {
		calls++
		cancel()
		return "example-user", "example-password", nil
	}
	username, password, err := c.sessionCredentials(ctx, false)
	if !errors.Is(err, context.Canceled) || username != "" || password != "" {
		t.Fatal("canceled callback returned usable credentials")
	}
	if _, _, err = c.sessionCredentials(ctx, false); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("called credential source after cancellation")
	}
}

func TestCredentialsCallbackPreservesInteractiveAnswers(t *testing.T) {
	c := &Client{mode: ModeTLS}
	calls := 0
	c.options.Authentication.Credentials = func(context.Context) (string, string, error) { calls++; return "example-user", "example-password", nil }
	ctx := context.Background()
	for _, answer := range []string{"SCRV1:ZXhhbXBsZQ==:YW5zd2Vy", "CRV1::example-state::example-answer"} {
		c.stageCredentials("example-interactive-user", answer, true)
		if err := c.acquireSessionCredentials(ctx, true); err != nil {
			t.Fatal(err)
		}
		username, password, err := c.sessionCredentials(ctx, true)
		if err != nil || username != "example-interactive-user" || password != answer || calls != 0 || !c.lastSentCredentialsInteractive() {
			t.Fatal("callback replaced an interactive challenge answer")
		}
	}
	c.tunnel.authToken = "example-server-token"
	_, password, err := c.sessionCredentials(ctx, true)
	if err != nil || password != "example-server-token" || calls != 0 || c.lastSentCredentialsInteractive() {
		t.Fatal("token did not take priority over interactive answer")
	}
}

func TestCredentialsCallbackSerialized(t *testing.T) {
	c := &Client{mode: ModeTLS}
	var active, calls atomic.Int32
	c.options.Authentication.Credentials = func(context.Context) (string, string, error) {
		if active.Add(1) != 1 {
			t.Error("credential callbacks ran concurrently")
		}
		defer active.Add(-1)
		// Callback may inspect authentication state without holding access itself.
		_ = c.loadStagedCredentials()
		runtime.Gosched()
		n := calls.Add(1)
		return "example-user", fmt.Sprintf("example-password-%d", n), nil
	}
	var wg sync.WaitGroup
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := c.sessionCredentials(context.Background(), true); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 24 {
		t.Fatalf("callback calls=%d", calls.Load())
	}
}

func TestCredentialsWithoutCallbackPreserveStagedBehavior(t *testing.T) {
	c := &Client{mode: ModeTLS}
	c.options.Authentication.Username = "example-original-user"
	c.options.Authentication.Password = "example-original-password"
	ctx := context.Background()
	if err := c.acquireSessionCredentials(ctx, false); err != nil {
		t.Fatal(err)
	}
	c.options.Authentication.Password = "example-changed-options-password"
	if err := c.acquireSessionCredentials(ctx, true); err != nil {
		t.Fatal(err)
	}
	for _, useToken := range []bool{false, true} {
		username, password, err := c.sessionCredentials(ctx, useToken)
		if err != nil || username != "example-original-user" || password != "example-original-password" {
			t.Fatal("legacy staged credential behavior changed")
		}
	}
	c.stageCredentials("example-interactive-user", "example-interactive-answer", true)
	if _, _, err := c.sessionCredentials(ctx, false); err != nil || !c.lastSentCredentialsInteractive() {
		t.Fatal("legacy interactive marker changed")
	}
	c.tunnel.authToken = "example-server-token"
	_, password, err := c.sessionCredentials(ctx, true)
	if err != nil || password != "example-server-token" || c.lastSentCredentialsInteractive() {
		t.Fatal("legacy token behavior changed")
	}
}
