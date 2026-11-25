package routeexport

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestConvertRoutes(t *testing.T) {
	r, err := Convert([]string{"route 10.29.1.4/16 via 10.0.0.1 metric 10", "route 10.29.0.0/16", "route-ipv6 fd00::1/64 via fd00::2", "route 192.0.2.1/32"}, Options{ListenAddress: "127.0.0.1:1080"})
	if err != nil {
		t.Fatal(err)
	}
	want := "10.29.0.0-10.29.255.255; fd00::-fd00::ffff:ffff:ffff:ffff; 192.0.2.1"
	if r.ProxifierHosts != want {
		t.Fatalf("got %q want %q", r.ProxifierHosts, want)
	}
	if len(r.Prefixes) != 3 {
		t.Fatal(r.Prefixes)
	}
	for _, line := range []string{"IP-CIDR,10.29.0.0/16,ovpn-socks,no-resolve", "IP-CIDR6,fd00::/64,ovpn-socks,no-resolve"} {
		if !strings.Contains(r.MihomoYAML, line) {
			t.Fatal(r.MihomoYAML)
		}
	}
}

func TestRangeBoundaries(t *testing.T) {
	tests := map[string]string{
		"0.0.0.0/0":       "0.0.0.0-255.255.255.255",
		"192.0.2.3/31":    "192.0.2.2-192.0.2.3",
		"192.0.2.3/32":    "192.0.2.3",
		"::/0":            "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"2001:db8::3/127": "2001:db8::2-2001:db8::3",
		"2001:db8::3/128": "2001:db8::3",
		"fd00::/65":       "fd00::-fd00::7fff:ffff:ffff:ffff",
	}
	for prefix, want := range tests {
		t.Run(prefix, func(t *testing.T) {
			if got := addressRange(netip.MustParsePrefix(prefix)); got != want {
				t.Fatalf("%s != %s", got, want)
			}
		})
	}
}

func TestRedirectGatewayOptIn(t *testing.T) {
	opts := Options{ListenAddress: "127.0.0.1:1080"}
	r, e := Convert([]string{"redirect-gateway def1 ipv6"}, opts)
	if e != nil || len(r.Prefixes) != 0 || r.ProxifierHosts != "" || !strings.Contains(r.MihomoYAML, "rules: []") {
		t.Fatalf("%+v %v", r, e)
	}
	opts.IncludeRedirectGateway = true
	for _, tc := range []struct{ line, want string }{
		{"redirect-gateway def1", "0.0.0.0/0"},
		{"redirect-gateway ipv6 !ipv4", "2000::/4,3000::/4"},
		{"redirect-gateway ipv6", "0.0.0.0/0,2000::/4,3000::/4"},
		{"redirect-gateway !ipv4", ""},
	} {
		r, e = Convert([]string{tc.line}, opts)
		if e != nil || strings.Join(r.Prefixes, ",") != tc.want {
			t.Fatalf("%s: %+v %v", tc.line, r, e)
		}
	}
	for _, flag := range []string{"bypass-dhcp", "bypass-dns", "block-local", "unknown"} {
		if _, e = Convert([]string{"redirect-gateway " + flag}, opts); e == nil {
			t.Fatal("accepted", flag)
		}
	}
}

func TestEmptyDoesNotExportAny(t *testing.T) {
	r, e := Convert(nil, Options{ListenAddress: "127.0.0.1:1080"})
	if e != nil || r.ProxifierHosts != "" || len(r.Prefixes) != 0 || !strings.Contains(r.MihomoYAML, "rules: []") || strings.Contains(r.MihomoYAML, "MATCH") {
		t.Fatalf("%+v %v", r, e)
	}
}

func TestEndpointValidation(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:1080", "[::]:1080", ":1080", "[::ffff:0.0.0.0]:1080", "localhost:0", "localhost:65536", "bad"} {
		if _, e := Convert(nil, Options{ListenAddress: addr}); e == nil {
			t.Fatal("accepted", addr)
		}
	}
	for _, host := range []string{"0.0.0.0", "::", "evil\nserver", "example.com:80", "https://example.com", "a,b", "[::1]:1080", "fe80::1%eth0"} {
		if _, e := Convert(nil, Options{ListenAddress: "0.0.0.0:1080", ProxyHost: host}); e == nil {
			t.Fatal("accepted", host)
		}
	}
	for _, host := range []string{"vpn.example.com", "192.0.2.1", "[2001:db8::1]"} {
		r, e := Convert(nil, Options{ListenAddress: "[::]:1080", ProxyHost: host})
		if e != nil || r.ProxyPort != 1080 {
			t.Fatalf("%+v %v", r, e)
		}
	}
}

func TestMalformedRoutesAreNotPartiallyExported(t *testing.T) {
	for _, line := range []string{"route", "route *", "route 10.0.0.0/33", "route ::/0", "route-ipv6 10.0.0.0/8", "route-ipv6 ::ffff:192.0.2.0/120", "route 10.0.0.0/8 via", "route 10.0.0.0/8 via bad", "route 10.0.0.0/8 metric -1", "route 10.0.0.0/8 extra", "something 0.0.0.0/0"} {
		r, e := Convert([]string{"route 192.0.2.0/24", line}, Options{ListenAddress: "localhost:1080"})
		if e == nil || r.MihomoYAML != "" {
			t.Fatalf("accepted %q: %+v %v", line, r, e)
		}
	}
}

func TestYAMLQuotingAndRuleNameInjection(t *testing.T) {
	name := "代理: \"vpn\" \\ # [name] & <test>"
	r, e := Convert([]string{"route 10.0.0.0/8"}, Options{ListenAddress: "localhost:1080", ProxyName: name})
	if e != nil {
		t.Fatal(e)
	}
	for _, line := range strings.Split(r.MihomoYAML, "\n") {
		var quoted string
		if strings.HasPrefix(line, "  - name: ") {
			quoted = strings.TrimPrefix(line, "  - name: ")
		} else if strings.HasPrefix(line, "  - \"") {
			quoted = strings.TrimPrefix(line, "  - ")
		} else {
			continue
		}
		var decoded string
		if e := json.Unmarshal([]byte(quoted), &decoded); e != nil {
			t.Fatal(e)
		}
		if decoded != name && decoded != "IP-CIDR,10.0.0.0/8,"+name+",no-resolve" {
			t.Fatal(decoded)
		}
	}
	for _, name := range []string{"x,DIRECT", "x\ny", "\tx", " x", "x\x01"} {
		if _, e := Convert(nil, Options{ListenAddress: "localhost:1080", ProxyName: name}); e == nil {
			t.Fatal("accepted", name)
		}
	}
}
