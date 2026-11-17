package ovpnconfig

import (
	"fmt"
	"net/netip"
	"strings"

	openvpn "github.com/sagernet/sing-openvpn"
)

// These values populate only the library's tunnel configuration metadata.
// There is deliberately no operating-system device or routing implementation.
func (p *parser) tunnelDirective(name string, a []string) error {
	count := func(min, max int) error {
		if len(a) < min || len(a) > max {
			return fmt.Errorf("expected %d..%d arguments", min, max)
		}
		return nil
	}
	addr := func(s string, v4 bool) (netip.Addr, error) {
		v, err := netip.ParseAddr(s)
		if err != nil || v.Is4() != v4 {
			return netip.Addr{}, fmt.Errorf("expected literal IP address of the appropriate family")
		}
		return v, nil
	}
	metric := func(s string) (int, error) { v, err := number(s, 0, 2147483647); return int(v), err }
	switch name {
	case "block-ipv6", "block-outside-dns":
		if err := count(0, 0); err != nil {
			return err
		}
		if name == "block-ipv6" {
			p.o.Tunnel.BlockIPv6 = true
		} else {
			p.o.Tunnel.BlockOutsideDNS = true
		}
	case "redirect-gateway", "redirect-private":
		for _, s := range a {
			switch s {
			case "local", "autolocal", "def1", "bypass-dhcp", "bypass-dns", "block-local", "ipv6", "!ipv4":
			default:
				return fmt.Errorf("unsupported redirect flag %q", s)
			}
		}
		if name == "redirect-gateway" {
			p.o.Tunnel.RedirectGateway = true
		} else {
			p.o.Tunnel.RedirectPrivate = true
		}
		p.o.Tunnel.RedirectGatewayFlags = append(p.o.Tunnel.RedirectGatewayFlags, a...)
	case "route-metric":
		if err := count(1, 1); err != nil {
			return err
		}
		v, err := metric(a[0])
		if err != nil {
			return err
		}
		p.o.Tunnel.RouteMetric = v
	case "route-gateway":
		if err := count(1, 1); err != nil {
			return err
		}
		v, err := addr(a[0], true)
		if err != nil {
			return err
		}
		p.o.Tunnel.RouteGateway = v
	case "route", "route-ipv6":
		var prefix netip.Prefix
		var err error
		gatewayIndex := 1
		if name == "route" {
			if err = count(1, 4); err != nil {
				return err
			}
			ip, e := addr(a[0], true)
			if e != nil {
				return e
			}
			bits := 32
			if len(a) > 1 {
				bits, err = maskBits(a[1])
				if err != nil {
					return err
				}
			}
			prefix = netip.PrefixFrom(ip, bits)
			gatewayIndex = 2
		} else {
			if err = count(1, 3); err != nil {
				return err
			}
			prefix, err = netip.ParsePrefix(a[0])
			if err != nil || !prefix.Addr().Is6() {
				return fmt.Errorf("route-ipv6 requires IPv6 prefix")
			}
		}
		route := openvpn.TunnelRoute{Prefix: prefix.Masked()}
		if len(a) > gatewayIndex {
			route.Gateway, err = addr(a[gatewayIndex], name == "route")
			if err != nil {
				return fmt.Errorf("only literal route gateways are supported: %w", err)
			}
		}
		if len(a) > gatewayIndex+1 {
			route.Metric, err = metric(a[gatewayIndex+1])
			if err != nil {
				return err
			}
		}
		p.o.Tunnel.Routes = append(p.o.Tunnel.Routes, route)
	case "dhcp-option":
		if err := count(2, 2); err != nil {
			return err
		}
		switch a[0] {
		case "DNS", "DNS6":
			if _, err := netip.ParseAddr(a[1]); err != nil {
				return fmt.Errorf("DHCP DNS must be a literal IP")
			}
		case "DOMAIN", "DOMAIN-SEARCH", "DOMAIN-ROUTE":
			if a[1] == "" || strings.ContainsAny(a[1], " \t\r\n") {
				return fmt.Errorf("invalid DHCP domain")
			}
		default:
			return fmt.Errorf("unsupported dhcp-option %q", a[0])
		}
		p.o.Tunnel.DHCPOptions = append(p.o.Tunnel.DHCPOptions, strings.Join(a, " "))
	case "ifconfig":
		if err := count(2, 2); err != nil {
			return err
		}
		local, err := addr(a[0], true)
		if err != nil {
			return err
		}
		other, err := addr(a[1], true)
		if err != nil {
			return err
		}
		// ifconfig has topology-dependent meaning, resolved after all directives.
		p.ifconfigLocal = local
		p.ifconfigOther = other
	case "ifconfig-ipv6":
		if err := count(2, 2); err != nil {
			return err
		}
		local, err := netip.ParsePrefix(a[0])
		if err != nil || !local.Addr().Is6() {
			return fmt.Errorf("ifconfig-ipv6 requires IPv6 prefix")
		}
		gateway, err := addr(a[1], false)
		if err != nil {
			return err
		}
		p.o.Tunnel.LocalAddress = append(p.o.Tunnel.LocalAddress, local)
		p.o.Tunnel.VPNGatewayIPv6 = gateway
	}
	return nil
}

func maskBits(s string) (int, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return 0, fmt.Errorf("invalid IPv4 netmask")
	}
	b := a.As4()
	bits := 0
	zero := false
	for _, v := range b {
		for n := 7; n >= 0; n-- {
			if v&(1<<n) != 0 {
				if zero {
					return 0, fmt.Errorf("non-contiguous IPv4 netmask")
				}
				bits++
			} else {
				zero = true
			}
		}
	}
	return bits, nil
}
