// Package managed is an optional ovpn-socks observation overlay, not upstream FlySSH.
package managed

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flyssh/flyssh/pkg/cli"
	"github.com/flyssh/flyssh/pkg/config"
)

type Listener struct {
	ID              string `json:"id"`
	Network         string `json:"network"`
	Address         string `json:"address"`
	ActualAddress   string `json:"actual_address,omitempty"`
	Scope           string `json:"scope"`
	Kind            string `json:"kind"`
	State           string `json:"state"`
	Error           string `json:"error,omitempty"`
	Upload          uint64 `json:"upload_bytes"`
	Download        uint64 `json:"download_bytes"`
	Active          int64  `json:"active_connections"`
	Total           uint64 `json:"total_connections"`
	Failed          uint64 `json:"failed_connections"`
	Metrics         bool   `json:"metrics_available"`
	CounterScope    string `json:"counter_scope"`
	ConnectionScope string `json:"connection_scope"`
	epoch           uint64
}
type Envelope struct {
	Version         int        `json:"version"`
	Type            string     `json:"type"`
	Engine          string     `json:"engine"`
	State           string     `json:"state"`
	Timestamp       int64      `json:"timestamp_ms"`
	Listeners       []Listener `json:"listeners"`
	Upload          uint64     `json:"upload_bytes"`
	Download        uint64     `json:"download_bytes"`
	Active          int64      `json:"active_connections"`
	Total           uint64     `json:"total_connections"`
	Failed          uint64     `json:"failed_connections"`
	Metrics         bool       `json:"metrics_available"`
	CounterScope    string     `json:"counter_scope"`
	ConnectionScope string     `json:"connection_scope"`
}

const counterScope = "成功写入的转发有效载荷；不含 SSH 与 SOCKS 握手"
const connectionScope = "已接受的 TCP 连接；含尚在拨号或 SOCKS 握手的连接，双向转发结束后移除"

var mu sync.Mutex
var entries []Listener
var state = "starting"
var prefix string
var output chan []byte
var enabled bool

// Diagnostic emits only a finite safe error code, never native error text.
func Diagnostic(code string) {
	if !Requested() {
		return
	}
	token := os.Getenv("OVPN_SOCKS_TELEMETRY_TOKEN")
	if len(token) != 32 || strings.Trim(token, "0123456789abcdefABCDEF") != "" {
		return
	}
	switch code {
	case "invalid_arguments", "invalid_config", "unsupported_mode", "config_not_found", "too_many_listeners":
	default:
		code = "invalid_arguments"
	}
	b, _ := json.Marshal(struct {
		Version int    `json:"version"`
		Type    string `json:"type"`
		Engine  string `json:"engine"`
		Code    string `json:"error_code"`
	}{1, "error", "flyssh", code})
	_, _ = fmt.Fprintf(os.Stdout, "OVPN_ENGINE_%s %s\n", token, b)
}
func ReportError(err error) {
	code := "invalid_arguments"
	switch s := err.Error(); {
	case strings.Contains(s, "cannot read -F"):
		code = "config_not_found"
	case strings.Contains(s, "resolved SSH"):
		code = "invalid_config"
	case strings.Contains(s, "at most 256"):
		code = "too_many_listeners"
	case strings.Contains(s, "managed mode supports") || strings.Contains(s, "requires -N") || strings.Contains(s, "does not support"):
		code = "unsupported_mode"
	}
	Diagnostic(code)
}
func Requested() bool {
	return os.Getenv("OVPN_SOCKS_TELEMETRY_TOKEN") != "" || os.Getenv("OVPN_SOCKS_INSPECT") == "1"
}

// Configure uses native parsed options and native SSH configuration resolution.
// It never connects, binds, opens authentication keys, or executes commands.
func Configure(o *cli.Options) (bool, error) {
	if !Requested() {
		return false, nil
	}
	token := os.Getenv("OVPN_SOCKS_TELEMETRY_TOKEN")
	if len(token) != 32 || strings.Trim(token, "0123456789abcdefABCDEF") != "" {
		return false, fmt.Errorf("managed mode requires a 32 hexadecimal character telemetry token")
	}
	if o.Host == "" || o.ShowVersion {
		return false, fmt.Errorf("managed mode requires an SSH host and forwarding options")
	}
	if o.Command != "" || o.StdioForward != "" || o.HasTransferMode() || o.Wingui || o.HasGUIInternalMode() || o.Mosh || o.ExitOnForward || o.ForceTTY || o.Subsystem || o.ForwardX11 || o.ForwardX11Trusted {
		return false, fmt.Errorf("managed mode supports foreground -N port forwarding or --ssh-gateway only; remove interactive, command, transfer, GUI, mosh, stdio and -f options")
	}
	if o.SSHGateway == "" && !o.NoCommand {
		return false, fmt.Errorf("managed port forwarding requires -N")
	}
	if o.ConfigFile != "" {
		if _, err := os.ReadFile(o.ConfigFile); err != nil {
			return false, fmt.Errorf("cannot read -F configuration")
		}
	}
	cfg := config.LoadSSHConfig(o)
	if cfg.Hostname == "" || cfg.Port < 1 || cfg.Port > 65535 {
		return false, fmt.Errorf("invalid resolved SSH host or port")
	}
	if cfg.ProxyCommand != "" {
		return false, fmt.Errorf("managed mode does not support ProxyCommand subprocesses; use --socks or -J")
	}
	var rows []Listener
	add := func(id, addr, scope, kind string, metrics bool) error {
		if len(rows) >= 256 {
			return fmt.Errorf("managed mode supports at most 256 listeners")
		}
		if err := validateAddress(addr); err != nil {
			return fmt.Errorf("%s: invalid listener address (numeric port 0..65535 required)", id)
		}
		rows = append(rows, Listener{ID: id, Network: "tcp", Address: addr, Scope: scope, Kind: kind, State: "configured", Metrics: metrics, CounterScope: counterScope, ConnectionScope: connectionScope})
		if !metrics {
			rows[len(rows)-1].CounterScope = "SSH gateway 未观测流量，仅观测监听生命周期"
			rows[len(rows)-1].ConnectionScope = "SSH gateway 未观测连接计数"
		}
		return nil
	}
	for _, group := range []struct {
		name, scope string
		forwards    []cli.ForwardSpec
	}{{"local", "local", o.LocalForwards}, {"remote", "remote", o.RemoteForwards}} {
		for i, f := range group.forwards {
			addr, target, err := ParseForward(f.Spec)
			if err != nil {
				return false, fmt.Errorf("%s-%d: use [bind:]port:host:port or standalone -ltcp:// syntax; IPv6 -L/-R and URL -L specs are unsupported by upstream", group.name, i)
			}
			if err = validateAddress(target); err != nil {
				return false, fmt.Errorf("%s-%d: invalid destination port", group.name, i)
			}
			if err = add(fmt.Sprintf("%s-%d", group.name, i), addr, group.scope, "tcp", true); err != nil {
				return false, err
			}
		}
	}
	for i, f := range o.DynamicForwards {
		addr := f.Spec
		if !strings.Contains(addr, ":") {
			addr = "127.0.0.1:" + addr
		}
		if err := add(fmt.Sprintf("dynamic-%d", i), addr, "local", "socks5", true); err != nil {
			return false, err
		}
	}
	if o.SSHGateway != "" {
		at := strings.LastIndex(o.SSHGateway, "@")
		if at < 0 {
			return false, fmt.Errorf("gateway requires user:password@bind:port")
		}
		up := strings.SplitN(o.SSHGateway[:at], ":", 2)
		if len(up) != 2 || up[0] == "" || up[1] == "" {
			return false, fmt.Errorf("gateway requires nonempty user and password")
		}
		if err := add("gateway-0", o.SSHGateway[at+1:], "local", "ssh-gateway", false); err != nil {
			return false, err
		}
	}
	if len(rows) == 0 {
		return false, fmt.Errorf("managed mode requires at least one -L/-R/-D/easy forward or --ssh-gateway")
	}
	mu.Lock()
	entries = rows
	prefix = "OVPN_ENGINE_" + token + " "
	enabled = true
	mu.Unlock()
	if os.Getenv("OVPN_SOCKS_INSPECT") == "1" {
		b := snapshot("inspect")
		_, err := os.Stdout.Write(append(b, '\n'))
		return true, err
	}
	// The parent supervisor owns reconnect policy and per-process accounting.
	o.NoReconnect = true
	output = make(chan []byte, 1)
	go func() {
		for b := range output {
			_, _ = os.Stdout.Write(append(b, '\n'))
		}
	}()
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for range t.C {
			emit()
		}
	}()
	State("connecting")
	return false, nil
}
func validateAddress(addr string) error {
	h, p, e := net.SplitHostPort(addr)
	if e != nil {
		return e
	}
	if strings.ContainsAny(h, "/@?#\r\n\t ") || len(h) > 253 {
		return fmt.Errorf("invalid host")
	}
	n, e := strconv.Atoi(p)
	if e != nil || n < 0 || n > 65535 {
		return fmt.Errorf("invalid port")
	}
	return nil
}

// ParseForward deliberately mirrors upstream's colon splitter, including its IPv6 limitation.
func ParseForward(spec string) (string, string, error) {
	p := strings.Split(spec, ":")
	switch len(p) {
	case 3:
		return "127.0.0.1:" + p[0], net.JoinHostPort(p[1], p[2]), nil
	case 4:
		return net.JoinHostPort(p[0], p[1]), net.JoinHostPort(p[2], p[3]), nil
	}
	return "", "", fmt.Errorf("invalid forward")
}
func snapshot(kind string) []byte {
	mu.Lock()
	defer mu.Unlock()
	e := Envelope{Version: 1, Type: kind, Engine: "flyssh", State: state, Timestamp: time.Now().UnixMilli(), Listeners: append([]Listener(nil), entries...), Metrics: true, CounterScope: counterScope, ConnectionScope: connectionScope}
	for _, l := range entries {
		e.Upload += l.Upload
		e.Download += l.Download
		e.Active += l.Active
		e.Total += l.Total
		e.Failed += l.Failed
		e.Metrics = e.Metrics && l.Metrics
	}
	if !e.Metrics {
		e.CounterScope = "SSH gateway 未观测流量，仅观测监听生命周期"
		e.ConnectionScope = "SSH gateway 未观测连接计数"
	}
	b, _ := json.Marshal(e)
	return append([]byte(prefix), b...)
}
func emit() {
	if !enabled || output == nil {
		return
	}
	b := snapshot("snapshot")
	select {
	case output <- b:
	default:
	}
}
func State(s string) {
	if !enabled {
		return
	}
	mu.Lock()
	if s == "connecting" && state == "connected" {
		for i := range entries {
			entries[i].epoch++
			entries[i].State = "closed"
			entries[i].ActualAddress = ""
		}
	}
	state = s
	mu.Unlock()
	emit()
}
func find(id string) *Listener {
	for i := range entries {
		if entries[i].ID == id {
			return &entries[i]
		}
	}
	return nil
}
func ID(ids []string) string {
	if len(ids) > 0 {
		return ids[0]
	}
	return ""
}
func Start(id string) uint64 {
	if !enabled || id == "" {
		return 0
	}
	mu.Lock()
	l := find(id)
	var epoch uint64
	if l != nil {
		l.epoch++
		epoch = l.epoch
		l.State = "starting"
		l.Error = ""
		l.ActualAddress = ""
	}
	mu.Unlock()
	emit()
	return epoch
}
func Bound(id string, epoch uint64, addr string) {
	if !enabled || id == "" {
		return
	}
	mu.Lock()
	if l := find(id); l != nil && l.epoch == epoch {
		l.State = "listening"
		l.ActualAddress = addr
		l.Error = ""
	}
	mu.Unlock()
	emit()
}
func End(id string, epoch uint64, err error) {
	if !enabled || id == "" {
		return
	}
	mu.Lock()
	if l := find(id); l != nil && l.epoch == epoch {
		l.State = "closed"
		l.ActualAddress = ""
		if err != nil {
			l.State = "failed"
			l.Error = "listener unavailable; see engine log"
		}
	}
	mu.Unlock()
	emit()
}
func Accept(id string) func() {
	if !enabled || id == "" {
		return func() {}
	}
	mu.Lock()
	if l := find(id); l != nil {
		l.Active++
		l.Total++
	}
	mu.Unlock()
	return func() {
		mu.Lock()
		if l := find(id); l != nil {
			l.Active--
		}
		mu.Unlock()
	}
}
func Fail(id string) {
	if !enabled || id == "" {
		return
	}
	mu.Lock()
	if l := find(id); l != nil {
		l.Failed++
	}
	mu.Unlock()
}

// Writer counts successfully delivered payload bytes on every Write, including long-lived flows.
type countWriter struct {
	io.Writer
	id     string
	upload bool
}

func (w countWriter) Write(p []byte) (int, error) {
	n, e := w.Writer.Write(p)
	if n > 0 {
		mu.Lock()
		if l := find(w.id); l != nil {
			if w.upload {
				l.Upload += uint64(n)
			} else {
				l.Download += uint64(n)
			}
		}
		mu.Unlock()
	}
	return n, e
}
func Writer(w io.Writer, id string, upload bool) io.Writer {
	if !enabled || id == "" {
		return w
	}
	return countWriter{w, id, upload}
}
