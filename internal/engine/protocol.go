// Package engine supervises instrumented native engines without a shell.
package engine

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

const maxRecord = 256 * 1024
const freshness = 8 * time.Second

type Options struct {
	ID, Name, Engine, Arguments, ConfigText, ConfigFormat, WorkingDirectory string
	AutoReconnect                                                           bool
}
type Listener struct {
	CounterScope      string `json:"counter_scope,omitempty"`
	ConnectionScope   string `json:"connection_scope,omitempty"`
	ID                string `json:"id"`
	Network           string `json:"network"`
	Address           string `json:"address"`
	ActualAddress     string `json:"actual_address"`
	Scope             string `json:"scope"`
	Kind              string `json:"kind"`
	State             string `json:"state"`
	Error             string `json:"error"`
	UploadBytes       uint64 `json:"upload_bytes"`
	DownloadBytes     uint64 `json:"download_bytes"`
	ActiveConnections int64  `json:"active_connections"`
	TotalConnections  uint64 `json:"total_connections"`
	FailedConnections uint64 `json:"failed_connections"`
	MetricsAvailable  bool   `json:"metrics_available"`
}
type InspectResult struct {
	Listeners []Listener `json:"listeners"`
}
type EngineStatus struct {
	CounterScope      string     `json:"counter_scope,omitempty"`
	ConnectionScope   string     `json:"connection_scope,omitempty"`
	Engine            string     `json:"engine"`
	State             string     `json:"state"`
	ProcessRunning    bool       `json:"process_running"`
	Fresh             bool       `json:"fresh"`
	LastTelemetryMS   int64      `json:"last_telemetry_ms"`
	MetricsAvailable  bool       `json:"metrics_available"`
	Listeners         []Listener `json:"listeners"`
	TotalConnections  uint64     `json:"total_connections"`
	FailedConnections uint64     `json:"failed_connections"`
	Restarts          uint64     `json:"restarts"`
}
type record struct {
	CounterScope      string     `json:"counter_scope,omitempty"`
	ConnectionScope   string     `json:"connection_scope,omitempty"`
	ErrorCode         string     `json:"error_code"`
	ErrorLine         int        `json:"error_line"`
	Version           int        `json:"version"`
	Type              string     `json:"type"`
	Engine            string     `json:"engine"`
	State             string     `json:"state"`
	TimestampMS       int64      `json:"timestamp_ms"`
	Listeners         []Listener `json:"listeners"`
	UploadBytes       uint64     `json:"upload_bytes"`
	DownloadBytes     uint64     `json:"download_bytes"`
	ActiveConnections int64      `json:"active_connections"`
	TotalConnections  uint64     `json:"total_connections"`
	FailedConnections uint64     `json:"failed_connections"`
	MetricsAvailable  bool       `json:"metrics_available"`
}

// lineSink keeps at most one bounded record. Oversize/native output is discarded,
// but draining continues so an engine cannot deadlock on a full stdout pipe.
type lineSink struct {
	mu                   sync.Mutex
	prefix, engine, kind string
	line                 []byte
	dropping             bool
	accept               func(record)
}

func (w *lineSink) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, b := range p {
		if b == '\n' {
			if !w.dropping {
				w.parse()
			}
			w.line = w.line[:0]
			w.dropping = false
		} else if !w.dropping {
			if len(w.line) >= maxRecord+len(w.prefix) {
				w.line = w.line[:0]
				w.dropping = true
			} else {
				w.line = append(w.line, b)
			}
		}
	}
	return len(p), nil
}
func (w *lineSink) parse() {
	if !strings.HasPrefix(string(w.line), w.prefix) {
		return
	}
	var r record
	if json.Unmarshal(w.line[len(w.prefix):], &r) != nil || r.Version != 1 || (r.Type != w.kind && r.Type != "error") || r.Engine != w.engine || len(r.CounterScope) > 512 || len(r.ConnectionScope) > 512 || len(r.Listeners) > 256 || r.ActiveConnections < 0 {
		return
	}
	if r.Type == "error" {
		if safeDiagnostic(r) != "" {
			w.accept(r)
		}
		return
	}
	switch r.State {
	case "configured":
		if r.Type != "inspect" {
			return
		}
	case "starting", "connecting", "connected", "running", "ready", "degraded", "failed", "stopped", "":
	default:
		return
	}
	for i := range r.Listeners {
		l := &r.Listeners[i]
		if len(l.CounterScope) > 512 || len(l.ConnectionScope) > 512 || len(l.ID) > 256 || len(l.Network) > 32 || len(l.Address) > 1024 || len(l.ActualAddress) > 1024 || len(l.Kind) > 64 || l.ActiveConnections < 0 {
			return
		}
		switch l.State {
		case "configured", "starting", "listening", "failed", "closed", "unknown":
		default:
			return
		}
		if l.Scope != "local" && l.Scope != "remote" {
			return
		}
		// Native error text can embed credentials or destination URLs.
		if l.Error != "" {
			l.Error = "engine listener error"
		}
	}
	w.accept(r)
}

func safeDiagnostic(r record) string {
	var message string
	switch r.ErrorCode {
	case "invalid_arguments":
		message = "引擎参数无效，请检查命令行参数"
	case "invalid_config":
		message = "引擎配置无效，请检查配置语法"
	case "unsupported_mode":
		message = "当前模式不支持受管引擎运行"
	case "config_not_found":
		message = "引擎配置文件不存在或无法读取"
	case "too_many_listeners":
		message = "监听项超过 256 个上限"
	default:
		return ""
	}
	if r.ErrorLine > 0 && r.ErrorLine <= 10000000 {
		message += fmt.Sprintf("（第 %d 行）", r.ErrorLine)
	}
	return message
}
