package engine

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Opt-in compatibility checks against the real instrumented upstream binaries.
// Both binaries are copied into a private trusted directory under canonical names.
func TestNativeEngineProtocol(t *testing.T) {
	for _, name := range []string{"gust", "flyssh"} {
		t.Run(name, func(t *testing.T) {
			key := "OVPN_ENGINE_TEST_GUST"
			args := "-L socks5://127.0.0.1:0"
			if name == "flyssh" {
				key = "OVPN_ENGINE_TEST_FLYSSH"
				args = "-N -D 127.0.0.1:0 example.invalid"
			}
			source := os.Getenv(key)
			if source == "" {
				t.Skip("set " + key + " to an instrumented native binary")
			}
			data, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			binary := name
			if runtime.GOOS == "windows" {
				binary += ".exe"
			}
			if err = os.WriteFile(filepath.Join(dir, binary), data, 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("OVPN_SOCKS_ENGINE_DIR", dir)
			o := Options{ID: "native-" + name, Engine: name, Arguments: args}
			inspected, err := Inspect(context.Background(), o)
			if err != nil {
				t.Fatal(err)
			}
			if len(inspected.Listeners) != 1 || inspected.Listeners[0].State != "configured" || inspected.Listeners[0].Scope != "local" {
				t.Fatalf("unexpected native inspection: %+v", inspected)
			}
			if name == "gust" {
				s, err := Start(context.Background(), o)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Stop()
				await(t, 10*time.Second, func() bool {
					status := s.EngineStatus()
					return status.Fresh && status.State == "ready" && len(status.Listeners) == 1 && status.Listeners[0].State == "listening"
				})
				if s.EngineStatus().Listeners[0].ActualAddress == "" {
					t.Fatal("native gust omitted actual bound listener")
				}
			}
		})
	}
}
