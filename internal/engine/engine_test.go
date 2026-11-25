package engine

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var helperConfig = flag.String("F", "", "test helper native config flag")

// This is executed in a separate OS process copied under the trusted engine
// directory. It exercises argv, pipes, cancellation, containment and cleanup.
func TestEngineHelper(t *testing.T) {
	token := os.Getenv("OVPN_SOCKS_TELEMETRY_TOKEN")
	if token == "" {
		return
	}
	mode := "live"
	for i, a := range os.Args {
		if a == "--" && i+1 < len(os.Args) {
			mode = os.Args[i+1]
		}
	}
	if mode == "descendant" {
		for {
			_ = os.WriteFile(os.Getenv("ENGINE_TEST_HEARTBEAT"), []byte(time.Now().String()), 0600)
			time.Sleep(20 * time.Millisecond)
		}
	}
	for i, a := range os.Args {
		if a == "-F" && i+1 < len(os.Args) && os.Getenv("ENGINE_TEST_CONFIG_PATH") != "" {
			_ = os.WriteFile(os.Getenv("ENGINE_TEST_CONFIG_PATH"), []byte(os.Args[i+1]), 0600)
		}
	}
	if mode == "diagnostic" {
		fmt.Printf("OVPN_ENGINE_%s {\"version\":1,\"engine\":\"flyssh\",\"type\":\"error\",\"error_code\":\"invalid_config\",\"error_line\":12,\"message\":\"secret-native-error\"}\n", token)
		os.Exit(3)
	}
	if mode == "invalid" {
		fmt.Println("secret-native-error")
		os.Exit(3)
	}
	emit := func() {
		r := record{Version: 1, Type: "snapshot", Engine: "flyssh", State: "connected", TimestampMS: time.Now().UnixMilli(), UploadBytes: 42, DownloadBytes: 84, TotalConnections: 3, MetricsAvailable: true, Listeners: []Listener{{ID: "local-0", Network: "tcp", Address: "127.0.0.1:1234", Scope: "local", Kind: "tcp", State: "listening", Error: "secret-native-error", UploadBytes: 21, TotalConnections: 2, MetricsAvailable: true}}}
		if os.Getenv("OVPN_SOCKS_INSPECT") == "1" {
			r.Type = "inspect"
			r.State = "configured"
			r.Listeners[0].State = "configured"
		}
		b, _ := json.Marshal(r)
		fmt.Printf("OVPN_ENGINE_%s %s\n", token, b)
	}
	fmt.Println("native-password=secret-native-error")
	fmt.Printf("OVPN_ENGINE_%s %s\n", token, strings.Repeat("x", maxRecord+100))
	fmt.Printf("OVPN_ENGINE_%s {bad-json}\n", token)
	if mode == "tree" {
		exe, _ := os.Executable()
		cmd := exec.Command(exe, "-test.run=^TestEngineHelper$", "--", "descendant")
		cmd.Env = os.Environ()
		if cmd.Start() != nil {
			os.Exit(5)
		}
	}
	if mode == "hang" {
		for {
			time.Sleep(time.Second)
		}
	}
	emit()
	if os.Getenv("OVPN_SOCKS_INSPECT") == "1" {
		os.Exit(0)
	}
	if mode == "exit" {
		time.Sleep(100 * time.Millisecond)
		os.Exit(2)
	}
	for {
		time.Sleep(100 * time.Millisecond)
		if mode != "stale" {
			emit()
		}
	}
}
func setupEngine(t *testing.T) Options {
	t.Helper()
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	name := "flyssh"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err = os.WriteFile(filepath.Join(dir, name), data, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OVPN_SOCKS_ENGINE_DIR", dir)
	return Options{ID: "test", Engine: "flyssh", Arguments: "-test.run=^TestEngineHelper$ -- live"}
}
func await(t *testing.T, limit time.Duration, f func() bool) {
	t.Helper()
	until := time.Now().Add(limit)
	for time.Now().Before(until) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not reached before timeout")
}
func TestInspectRealProcess(t *testing.T) {
	o := setupEngine(t)
	o.ConfigText = "Host test\n HostName example.invalid\n"
	marker := filepath.Join(t.TempDir(), "path")
	t.Setenv("ENGINE_TEST_CONFIG_PATH", marker)
	r, err := Inspect(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Listeners) != 1 || r.Listeners[0].State != "configured" {
		t.Fatalf("unexpected inspect: %+v", r)
	}
	path, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(string(path)); !os.IsNotExist(err) {
		t.Fatalf("temporary config still exists: %v", err)
	}
	o.Arguments = "-test.run=^TestEngineHelper$ -- invalid"
	_, err = Inspect(context.Background(), o)
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe inspect error: %v", err)
	}
}
func TestLiveStopTreeAndConfigCleanup(t *testing.T) {
	o := setupEngine(t)
	o.Arguments = "-test.run=^TestEngineHelper$ -- tree"
	o.ConfigText = "Host x\n HostName example.invalid"
	dir := t.TempDir()
	marker := filepath.Join(dir, "config-path")
	heartbeat := filepath.Join(dir, "heartbeat")
	t.Setenv("ENGINE_TEST_CONFIG_PATH", marker)
	t.Setenv("ENGINE_TEST_HEARTBEAT", heartbeat)
	s, err := Start(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	await(t, 5*time.Second, func() bool { _, err := os.Stat(heartbeat); return s.EngineStatus().Fresh && err == nil })
	if s.Snapshot().State != "connected" || s.Metrics().Current.UploadBytes != 42 {
		t.Fatal("valid telemetry not consumed")
	}
	status := s.EngineStatus()
	status.Listeners[0].Address = "mutated"
	if s.EngineStatus().Listeners[0].Address == "mutated" {
		t.Fatal("status exposes shared slices")
	}
	b, _ := json.Marshal(s.Snapshot())
	b2, _ := json.Marshal(s.EngineStatus())
	if strings.Contains(string(b)+string(b2), "secret-native-error") {
		t.Fatal("secret native log leaked")
	}
	path, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(string(path)); err != nil {
		t.Fatal("config missing while child alive")
	}
	begin := time.Now()
	s.Stop()
	if time.Since(begin) > 3*time.Second {
		t.Fatal("stop was not prompt")
	}
	if _, err = os.Stat(string(path)); !os.IsNotExist(err) {
		t.Fatalf("config leaked after stop: %v", err)
	}
	first, _ := os.ReadFile(heartbeat)
	time.Sleep(150 * time.Millisecond)
	second, _ := os.ReadFile(heartbeat)
	if string(first) != string(second) {
		t.Fatal("descendant survived stop")
	}
	if s.EngineStatus().ProcessRunning || s.Snapshot().State != "stopped" {
		t.Fatal("stop state incorrect")
	}
}
func TestStaleAndRestartRealProcesses(t *testing.T) {
	o := setupEngine(t)
	o.Arguments = "-test.run=^TestEngineHelper$ -- stale"
	s, err := Start(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	await(t, 5*time.Second, func() bool { return s.EngineStatus().Fresh })
	await(t, 10*time.Second, func() bool { return !s.EngineStatus().Fresh })
	if s.Snapshot().State == "connected" || s.EngineStatus().Listeners[0].State == "listening" {
		t.Fatal("stale engine reported healthy")
	}
	s.Stop()
	o.Arguments = "-test.run=^TestEngineHelper$ -- exit"
	o.AutoReconnect = true
	s2, err := Start(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Stop()
	await(t, 5*time.Second, func() bool { return s2.Metrics().Current.UploadBytes >= 84 })
	if s2.EngineStatus().Listeners[0].UploadBytes < 42 || s2.EngineStatus().Listeners[0].TotalConnections < 4 {
		t.Fatal("listener counters reset across restart")
	}
	if s2.EngineStatus().Restarts < 1 {
		t.Fatal("restart not counted")
	}
	s2.Stop()
}
func TestInspectCancellationAndAmbiguity(t *testing.T) {
	o := setupEngine(t)
	o.Arguments = "-test.run=^TestEngineHelper$ -- hang"
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	begin := time.Now()
	if _, err := Inspect(ctx, o); err == nil {
		t.Fatal("inspection did not cancel")
	}
	if time.Since(begin) > 3*time.Second {
		t.Fatal("slow cancel")
	}
	o.ConfigText = "private"
	o.Arguments = "-F elsewhere"
	if _, err := Start(context.Background(), o); err == nil {
		t.Fatal("ambiguous config accepted")
	}
}
func TestSafeDiagnosticAndRestartCleanup(t *testing.T) {
	o := setupEngine(t)
	o.Arguments = "-test.run=^TestEngineHelper$ -- diagnostic"
	_, err := Inspect(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "第 12 行") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("missing safe diagnostic: %v", err)
	}
	o.Arguments = "-test.run=^TestEngineHelper$ -- exit"
	o.ConfigText = "Host x"
	o.AutoReconnect = true
	marker := filepath.Join(t.TempDir(), "config-path")
	t.Setenv("ENGINE_TEST_CONFIG_PATH", marker)
	s, err := Start(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	await(t, 3*time.Second, func() bool { return s.Snapshot().State == "reconnecting" })
	first, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(string(first)); !os.IsNotExist(err) {
		t.Fatal("config retained during restart backoff")
	}
	await(t, 5*time.Second, func() bool { path, _ := os.ReadFile(marker); return len(path) > 0 && string(path) != string(first) })
	s.Stop()
	last, _ := os.ReadFile(marker)
	if _, err = os.Stat(string(last)); !os.IsNotExist(err) {
		t.Fatal("recreated config leaked after stop")
	}
}

func TestBoundedTelemetryAndHistory(t *testing.T) {
	accepted := 0
	w := lineSink{prefix: "OVPN_ENGINE_token ", engine: "flyssh", kind: "snapshot", accept: func(record) { accepted++ }}
	r := record{Version: 1, Type: "snapshot", Engine: "flyssh", State: "running"}
	b, _ := json.Marshal(r)
	_, _ = w.Write([]byte(strings.Repeat("x", maxRecord*2) + "\nOVPN_ENGINE_token " + string(b) + "\n"))
	if accepted != 1 || cap(w.line) > 2*(maxRecord+len(w.prefix)) {
		t.Fatal("oversize record broke bounded parser")
	}
	r.Listeners = make([]Listener, 257)
	b, _ = json.Marshal(r)
	_, _ = w.Write([]byte("OVPN_ENGINE_token " + string(b) + "\n"))
	if accepted != 1 {
		t.Fatal("listener limit not enforced")
	}
	s := &Session{started: time.Now().Add(-time.Hour), state: "connected", status: EngineStatus{ProcessRunning: true, MetricsAvailable: true}}
	for i := 0; i < 1000; i++ {
		now := time.Now().Add(time.Duration(i-1000) * 2 * time.Second)
		s.last = now
		s.sample(now)
	}
	before := s.count
	s.last = time.Now().Add(-time.Minute)
	s.sample(time.Now())
	if s.count != before {
		t.Fatal("stale telemetry created a false zero sample")
	}
	m := s.Metrics()
	if len(m.History) > 450 || len(m.History) == 0 {
		t.Fatal("bad bounded history")
	}
}
