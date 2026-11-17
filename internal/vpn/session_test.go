package vpn

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSnapshotCopiesMutableSlices(t *testing.T) {
	s := &Session{snapshot: Snapshot{Routes: []string{"route 10.0.0.0/8"}, DNS: []string{"10.0.0.1"}, Logs: []string{"connected"}}}
	v := s.Snapshot()
	v.Routes[0] = "changed"
	v.DNS[0] = "changed"
	v.Logs[0] = "changed"
	fresh := s.Snapshot()
	if fresh.Routes[0] == "changed" || fresh.DNS[0] == "changed" || fresh.Logs[0] == "changed" {
		t.Fatal("Snapshot exposed internal mutable state")
	}
}
func TestOfflineSessionCannotDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Session{ctx: ctx, snapshot: Snapshot{State: "reconnecting"}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err = s.dial(ctx, listener.Addr().String()); err == nil {
		t.Fatal("offline session dialed host")
	}
}
func TestPrivateLogsAreRedacted(t *testing.T) {
	for _, secret := range []string{"PUSH_REPLY,auth-token TOP-SECRET,route 10.0.0.0", "password=TOP-SECRET", "-----BEGIN PRIVATE KEY-----"} {
		got := redactLog(secret)
		if strings.Contains(got, "TOP-SECRET") || got == secret {
			t.Fatalf("private log leaked: %s", got)
		}
	}
}
func TestBadConfigurationDoesNotStartListener(t *testing.T) {
	_, err := Start(context.Background(), Options{Config: "client\nup /tmp/unsafe.sh\n"})
	if err == nil {
		t.Fatal("unsafe config started")
	}
}
func TestOfflineDialContextUnchanged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s := &Session{ctx: ctx}
	_, err := s.dial(ctx, "example.invalid:80")
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("offline rejection should be immediate: %v", err)
	}
}
