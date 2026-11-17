// Package vpn connects a pure Go OpenVPN protocol engine to an isolated gVisor
// network stack. It never opens a TUN/TAP device or changes host routes/DNS.
package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/lovitus/ovpn-socks/internal/ovpnconfig"
	"github.com/lovitus/ovpn-socks/internal/proxy"
	openvpn "github.com/sagernet/sing-openvpn"
)

type Options struct {
	ID, Name, Config, Username, Listen, OpenVPNPath string
	AutoReconnect                                   bool
	Password                                        func() (string, error)
}
type Snapshot struct {
	ID       string   `json:"id"`
	State    string   `json:"state"`
	Listen   string   `json:"listen"`
	Routes   []string `json:"routes"`
	DNS      []string `json:"dns"`
	Logs     []string `json:"logs"`
	Error    string   `json:"error"`
	TunnelIP string   `json:"tunnel_ip"`
}
type Session struct {
	opts       Options
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.RWMutex
	snapshot   Snapshot
	client     *openvpn.Client
	network    *proxy.Network
	networkKey string
	server     *proxy.Server
	once       sync.Once
	done       chan struct{}
}

func Start(ctx context.Context, opts Options) (*Session, error) {
	parsed, err := ovpnconfig.Parse(opts.Config)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Session{opts: opts, ctx: ctx, cancel: cancel, done: make(chan struct{}), snapshot: Snapshot{ID: opts.ID, State: "connecting", Routes: []string{}, DNS: []string{}, Logs: []string{}}}
	parsed.Context = ctx
	parsed.DisableReconnect = !opts.AutoReconnect
	parsed.Authentication.Username = opts.Username
	parsed.Authentication.Password = ""
	parsed.Authentication.AuthRetry = "none"
	if opts.Username != "" || opts.Password != nil {
		if opts.Password == nil {
			cancel()
			return nil, errors.New("username/password authentication requires a password callback")
		}
		parsed.Authentication.Credentials = func(authCtx context.Context) (string, string, error) {
			if err := authCtx.Err(); err != nil {
				return "", "", err
			}
			password, e := opts.Password()
			if e != nil {
				return "", "", fmt.Errorf("generate authentication password: %w", e)
			}
			if strings.ContainsRune(password, 0) || strings.ContainsRune(opts.Username, 0) {
				return "", "", errors.New("credentials contain NUL")
			}
			return opts.Username, password, nil
		}
	}
	parsed.Logger = sessionLogger{s}
	parsed.OnTunnelConfiguration = s.configure
	s.client, err = openvpn.NewClient(parsed)
	if err != nil {
		cancel()
		return nil, err
	}
	s.server, err = proxy.Listen(opts.Listen, s.dial)
	if err != nil {
		s.client.Close()
		cancel()
		return nil, err
	}
	s.snapshot.Listen = s.server.Addr()
	if err = s.client.Start(); err != nil {
		s.server.Close()
		s.client.Close()
		cancel()
		return nil, err
	}
	s.addLog("userspace OpenVPN started; system adapters, routes and DNS are unchanged")
	go s.monitor()
	return s, nil
}
func (s *Session) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.snapshot
	v.Routes = append([]string{}, v.Routes...)
	v.DNS = append([]string{}, v.DNS...)
	v.Logs = append([]string{}, v.Logs...)
	return v
}
func (s *Session) Stop() {
	s.once.Do(func() {
		s.cancel()
		s.dropNetwork()
		s.client.Close()
		s.server.Close()
		<-s.done
		s.mu.Lock()
		s.snapshot.State = "stopped"
		s.snapshot.TunnelIP = ""
		s.mu.Unlock()
		s.addLog("stopped")
	})
}
func (s *Session) dial(ctx context.Context, address string) (net.Conn, error) {
	s.mu.RLock()
	n := s.network
	state := s.snapshot.State
	s.mu.RUnlock()
	if s.ctx.Err() != nil || n == nil || state != "connected" || !s.client.Ready() {
		return nil, errors.New("VPN is offline; SOCKS connection refused")
	}
	return n.Dial(ctx, address)
}
func (s *Session) configure(event openvpn.TunnelConfigurationEvent) error {
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	cfg := event.Configuration
	if cfg.DevType != "" && cfg.DevType != "tun" {
		return errors.New("userspace IP stack supports dev tun only; TAP/Ethernet is unsupported")
	}
	var ips []netip.Addr
	for _, prefix := range cfg.LocalIPv4 {
		ips = append(ips, prefix.Addr())
	}
	if !cfg.BlockIPv6 {
		for _, prefix := range cfg.LocalIPv6 {
			ips = append(ips, prefix.Addr())
		}
	}
	var dns []netip.AddrPort
	var dnsText []string
	for _, ip := range cfg.DNS {
		if !ip.IsValid() {
			continue
		}
		dns = append(dns, netip.AddrPortFrom(ip, 53))
		dnsText = appendUnique(dnsText, ip.String())
	}
	for _, server := range cfg.DNSServers {
		if server.Transport != "" && server.Transport != "plain" && server.Transport != "udp" && server.Transport != "tcp" {
			return fmt.Errorf("pushed DNS transport %q is unsupported (plain VPN DNS only)", server.Transport)
		}
		for _, address := range server.Addresses {
			if !address.IsValid() {
				continue
			}
			if address.Port() == 0 {
				address = netip.AddrPortFrom(address.Addr(), 53)
			}
			dns = append(dns, address)
			dnsText = appendUnique(dnsText, address.String())
		}
	}
	var routes []string
	for _, route := range cfg.IPv4Routes {
		routes = appendUnique(routes, renderRoute("route", route))
	}
	for _, route := range cfg.IPv6Routes {
		routes = appendUnique(routes, renderRoute("route-ipv6", route))
	}
	if cfg.RedirectGateway {
		routes = appendUnique(routes, "redirect-gateway "+strings.Join(cfg.RedirectGatewayFlags, " "))
	}
	key := fmt.Sprint(ips, dns, cfg.TunMTU)
	s.mu.Lock()
	preserve := event.Reason == openvpn.TunnelConfigurationEventRenegotiation && s.network != nil && s.networkKey == key && s.network.Err() == nil
	old := s.network
	if !preserve {
		s.network = nil
		s.snapshot.State = "connecting"
	}
	s.mu.Unlock()
	if !preserve {
		// Stop the only raw-packet reader before attaching a replacement.
		if old != nil {
			old.Close()
		}
		n, err := proxy.NewNetwork(s.client, ips, dns, cfg.TunMTU)
		if err != nil {
			return err
		}
		s.mu.Lock()
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			n.Close()
			return s.ctx.Err()
		}
		s.network, s.networkKey = n, key
		s.mu.Unlock()
	}
	s.mu.Lock()
	s.snapshot.Routes = routes
	s.snapshot.DNS = dnsText
	s.snapshot.TunnelIP = joinIPs(ips)
	s.snapshot.Error = ""
	s.mu.Unlock()
	for _, route := range routes {
		s.addLog("PUSH_REPLY " + route)
	}
	for _, address := range dnsText {
		s.addLog("PUSH_REPLY DNS " + address)
	}
	s.addLog("userspace tunnel configured: " + joinIPs(ips))
	return nil
}
func renderRoute(kind string, route openvpn.TunnelRoute) string {
	result := kind + " " + route.Prefix.String()
	if route.Gateway.IsValid() {
		result += " via " + route.Gateway.String()
	}
	if route.Metric != 0 {
		result += fmt.Sprintf(" metric %d", route.Metric)
	}
	return result
}
func joinIPs(ips []netip.Addr) string {
	values := make([]string, len(ips))
	for i, ip := range ips {
		values[i] = ip.String()
	}
	return strings.Join(values, ", ")
}
func appendUnique(values []string, v string) []string {
	for _, old := range values {
		if old == v {
			return values
		}
	}
	return append(values, v)
}
func (s *Session) dropNetwork() {
	s.mu.Lock()
	old := s.network
	s.network = nil
	s.snapshot.TunnelIP = ""
	s.mu.Unlock()
	if old != nil {
		old.Close()
	}
}
func (s *Session) monitor() {
	defer close(s.done)
	defer func() {
		s.dropNetwork()
		s.client.Close()
		s.server.Close()
		if s.ctx.Err() != nil {
			s.mu.Lock()
			s.snapshot.State = "stopped"
			s.mu.Unlock()
		}
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	wasReady := false
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
		ready := s.client.Ready()
		s.mu.RLock()
		n := s.network
		s.mu.RUnlock()
		if ready && n != nil && n.Err() == nil {
			s.mu.Lock()
			s.snapshot.State = "connected"
			s.snapshot.Error = ""
			s.mu.Unlock()
			wasReady = true
			continue
		}
		if ready && n == nil {
			// Configuration callback is replacing a stack; readiness alone does
			// not grant SOCKS access until the replacement is fully installed.
			continue
		}
		if wasReady {
			wasReady = false
			s.dropNetwork()
			s.mu.Lock()
			s.snapshot.State = "reconnecting"
			s.mu.Unlock()
			s.addLog("VPN disconnected; existing SOCKS connections closed")
			if !s.opts.AutoReconnect {
				s.client.Close()
				s.mu.Lock()
				s.snapshot.State = "disconnected"
				s.mu.Unlock()
				return
			}
		}
		if n != nil && n.Err() != nil {
			s.addLog(n.Err().Error())
			s.dropNetwork()
			if !s.opts.AutoReconnect {
				s.mu.Lock()
				s.snapshot.State, s.snapshot.Error = "error", n.Err().Error()
				s.mu.Unlock()
				return
			}
			s.client.RestartSession()
		}
		probe, cancel := context.WithTimeout(s.ctx, time.Millisecond)
		err := s.client.WaitReady(probe)
		cancel()
		if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			s.mu.Lock()
			s.snapshot.State = "error"
			s.snapshot.Error = err.Error()
			s.mu.Unlock()
			s.dropNetwork()
			s.addLog("OpenVPN error: " + err.Error())
			return
		}
	}
}
func (s *Session) addLog(message string) {
	message = redactLog(message)
	if message == "" {
		return
	}
	if len(message) > 2048 {
		message = message[:2048] + "…"
	}
	line := time.Now().Format("15:04:05") + " " + message
	s.mu.Lock()
	s.snapshot.Logs = append(s.snapshot.Logs, line)
	if len(s.snapshot.Logs) > 200 {
		s.snapshot.Logs = append([]string(nil), s.snapshot.Logs[len(s.snapshot.Logs)-200:]...)
	}
	s.mu.Unlock()
	log.Printf("vpn[%s] %s", s.opts.ID, message)
}
func redactLog(message string) string {
	// A protocol implementation may log pushed auth-tokens. Never send those to
	// the UI or host logger. Drop entire records instead of guessing delimiters.
	lower := strings.ToLower(message)
	for _, secret := range []string{"auth-token", "password=", "password:", "-----begin private key", "-----begin rsa private key", "-----begin ec private key"} {
		if strings.Contains(lower, secret) {
			return "[authentication/private-key log redacted]"
		}
	}
	return strings.TrimSpace(message)
}
