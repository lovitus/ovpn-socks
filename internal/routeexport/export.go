// Package routeexport converts the destination routes printed in vpn.Snapshot
// into proxy-client rules. It does not reproduce OS routing, DNS, or exclusions.
package routeexport

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

// Options describes the SOCKS endpoint reachable by the importing client.
type Options struct {
	ListenAddress string
	// ProxyHost overrides the listener host, without a port. Required for wildcard listeners.
	ProxyHost string
	ProxyName string
	// IncludeRedirectGateway explicitly permits default routes. False is the safe default.
	IncludeRedirectGateway bool
}

// Result contains a mihomo YAML fragment and Proxifier Target Hosts field text.
// ProxifierHosts is NOT an importable profile; never create a rule with an empty
// Target Hosts field, since Proxifier treats it as Any.
type Result struct {
	MihomoYAML     string
	ProxifierHosts string
	Prefixes       []string
	Warnings       []string
	ProxyHost      string
	ProxyPort      int
	ProxyName      string
}

// Convert accepts Snapshot.Routes strings such as "route 10.29.0.0/16 via
// 10.0.0.1 metric 2", "route-ipv6 fd00::/64", and "redirect-gateway def1".
// Invalid input returns no partial export. Destination CIDRs are masked and
// deduplicated; distinct overlapping routes are preserved without aggregation.
func Convert(routes []string, opts Options) (Result, error) {
	host, port, err := endpoint(opts)
	if err != nil {
		return Result{}, err
	}
	name := opts.ProxyName
	if name == "" {
		name = "ovpn-socks"
	}
	// Rule entries use comma-separated fields even when the whole YAML scalar is quoted.
	if strings.ContainsAny(name, ",\r\n") || strings.TrimSpace(name) != name || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return Result{}, fmt.Errorf("proxy name must not contain commas, control characters, or surrounding whitespace")
	}
	r := Result{ProxyHost: host, ProxyPort: port, ProxyName: name, Prefixes: []string{}, Warnings: []string{}}
	var prefixes []netip.Prefix
	seen := make(map[netip.Prefix]bool)
	add := func(p netip.Prefix) {
		p = p.Masked()
		if !seen[p] {
			seen[p] = true
			prefixes = append(prefixes, p)
			r.Prefixes = append(r.Prefixes, p.String())
		}
	}
	for i, line := range routes {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "route", "route-ipv6":
			if len(f) < 2 {
				return Result{}, fmt.Errorf("route %d: missing CIDR", i+1)
			}
			p, err := netip.ParsePrefix(f[1])
			if err != nil || p.Addr().Is4In6() || (f[0] == "route") != p.Addr().Is4() {
				return Result{}, fmt.Errorf("route %d: invalid %s CIDR %q", i+1, f[0], f[1])
			}
			// Only the suffix emitted by Snapshot.renderRoute is accepted.
			next := 2
			if next < len(f) && f[next] == "via" {
				if next+1 >= len(f) {
					return Result{}, fmt.Errorf("route %d: missing gateway", i+1)
				}
				gateway, e := netip.ParseAddr(f[next+1])
				if e != nil || gateway.Zone() != "" || gateway.Is4() != p.Addr().Is4() {
					return Result{}, fmt.Errorf("route %d: invalid gateway", i+1)
				}
				next += 2
			}
			if next < len(f) && f[next] == "metric" {
				if next+1 >= len(f) {
					return Result{}, fmt.Errorf("route %d: missing metric", i+1)
				}
				if _, e := strconv.ParseUint(f[next+1], 10, 32); e != nil {
					return Result{}, fmt.Errorf("route %d: invalid metric", i+1)
				}
				next += 2
			}
			if next != len(f) {
				return Result{}, fmt.Errorf("route %d: unsupported suffix", i+1)
			}
			add(p)
		case "redirect-gateway":
			if !opts.IncludeRedirectGateway {
				r.Warnings = append(r.Warnings, "Skipped "+strings.Join(f, " ")+": default-route export requires explicit opt-in; only explicit destination routes are exported.")
				continue
			}
			v4, v6 := true, false
			for _, flag := range f[1:] {
				switch flag {
				case "def1", "local", "autolocal":
				case "ipv6":
					v6 = true
				case "!ipv4":
					v4 = false
				default:
					return Result{}, fmt.Errorf("redirect-gateway flag %q cannot be faithfully exported (routing exclusions are unavailable)", flag)
				}
			}
			if v4 {
				add(netip.MustParsePrefix("0.0.0.0/0"))
			}
			if v6 {
				add(netip.MustParsePrefix("2000::/4"))
				add(netip.MustParsePrefix("3000::/4"))
			}
			r.Warnings = append(r.Warnings, "redirect-gateway export explicitly enabled: broad destination rules do not reproduce VPN-server, LAN, or OS routing exceptions; keep proxy/VPN transport connections direct to avoid loops.")
		default:
			return Result{}, fmt.Errorf("route %d: unsupported directive %q", i+1, f[0])
		}
	}
	var yaml strings.Builder
	fmt.Fprintf(&yaml, "proxies:\n  - name: %s\n    type: socks5\n    server: %s\n    port: %d\n", quote(name), quote(host), port)
	if len(prefixes) == 0 {
		yaml.WriteString("rules: []\n")
		r.Warnings = append(r.Warnings, "No destination routes to export. Do not create an empty Proxifier Target Hosts rule: an empty field matches Any.")
	} else {
		yaml.WriteString("rules:\n")
		targets := make([]string, 0, len(prefixes))
		for _, p := range prefixes {
			kind := "IP-CIDR6"
			if p.Addr().Is4() {
				kind = "IP-CIDR"
			}
			fmt.Fprintf(&yaml, "  - %s\n", quote(kind+","+p.String()+","+name+",no-resolve"))
			targets = append(targets, addressRange(p))
		}
		r.ProxifierHosts = strings.Join(targets, "; ")
	}
	r.MihomoYAML = yaml.String()
	r.Warnings = append(r.Warnings, "Proxifier output is Target Hosts text, not a .ppx profile. Add a SOCKS5 proxy, paste the text into a rule above Default, select that proxy, and keep Default Direct. Preserve direct rules for the proxy endpoint and ovpn-socks/VPN transport to prevent loops.", "Rules match destination IPs only; gateways, metrics and VPN DNS settings are not imported. mihomo no-resolve does not resolve domain-only requests for these rules.")
	return r, nil
}

func endpoint(opts Options) (string, int, error) {
	host, portText, err := net.SplitHostPort(opts.ListenAddress)
	if err != nil {
		return "", 0, fmt.Errorf("invalid SOCKS listen address: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("SOCKS port must be between 1 and 65535")
	}
	if opts.ProxyHost != "" {
		host = opts.ProxyHost
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.IsUnspecified() || ip.Unmap().IsUnspecified() {
			return "", 0, fmt.Errorf("wildcard SOCKS listener requires an explicit reachable proxy host")
		}
		if ip.Zone() != "" {
			return "", 0, fmt.Errorf("scoped IPv6 proxy hosts are not supported")
		}
		return ip.String(), port, nil
	}
	if host == "" {
		return "", 0, fmt.Errorf("wildcard SOCKS listener requires an explicit reachable proxy host")
	}
	if len(host) > 253 {
		return "", 0, fmt.Errorf("invalid proxy hostname")
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", 0, fmt.Errorf("invalid proxy hostname")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return "", 0, fmt.Errorf("proxy host must be an IP or ASCII DNS hostname without a port")
			}
		}
	}
	return host, port, nil
}

// JSON double-quoted strings are also YAML double-quoted scalars. In particular,
// this avoids strconv.Quote's Go-only \\x and \\U escape forms.
func quote(s string) string { b, _ := json.Marshal(s); return string(b) }

func addressRange(p netip.Prefix) string {
	p = p.Masked()
	first := p.Addr()
	if p.Bits() == first.BitLen() {
		return first.String()
	}
	var last netip.Addr
	if first.Is4() {
		bytes := first.As4()
		for bit := p.Bits(); bit < 32; bit++ {
			bytes[bit/8] |= 1 << (7 - uint(bit%8))
		}
		last = netip.AddrFrom4(bytes)
	} else {
		bytes := first.As16()
		for bit := p.Bits(); bit < 128; bit++ {
			bytes[bit/8] |= 1 << (7 - uint(bit%8))
		}
		last = netip.AddrFrom16(bytes)
	}
	return first.String() + "-" + last.String()
}
