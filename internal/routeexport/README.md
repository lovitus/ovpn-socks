# Route export contract

`Convert(routes []string, opts Options) (Result, error)` is a standard-library-only converter for `vpn.Snapshot.Routes`. It never changes network configuration or writes files.

- `ListenAddress`: the SOCKS listener's host:port.
- `ProxyHost`: optional reachable host override, without port. Required for `0.0.0.0`, `[::]`, and empty listener hosts. The caller must choose an address reachable from the importing machine; the converter never silently substitutes localhost.
- `ProxyName`: default `ovpn-socks`. Commas/control characters/surrounding whitespace are rejected because mihomo rule strings have their own comma-delimited grammar.
- `IncludeRedirectGateway`: false by default. Redirect directives generate warnings and no prefixes unless explicitly enabled.

`Result.MihomoYAML` contains a SOCKS5 proxy and `IP-CIDR` / `IP-CIDR6` rules with `no-resolve`. JSON string quoting is used, which is valid YAML double-quoted scalar syntax and avoids Go-only escape forms. These are destination-IP rules; they do not configure VPN DNS or resolve domain-only requests. Merge the fragment into existing `proxies` and `rules` lists; do not create duplicate YAML keys. No `MATCH` rule is generated.

`Result.ProxifierHosts` is a semicolon-separated **Target Hosts field**, not an importable profile. Add the SOCKS5 endpoint from `Result.ProxyHost` and `Result.ProxyPort`, create a rule with these Target Hosts, select that proxy as its action, and place it above the Default rule. Keep Default Direct and preserve direct rules for the SOCKS endpoint and VPN transport/application to prevent recursion. Empty output must never be used to create a rule: an empty Target Hosts field means Any in Proxifier.

## Verified Proxifier support

Official Proxifier v4 for Windows documentation, consulted 2026-11-25:

- https://www.proxifier.com/docs/win-v4/rules.html explicitly documents semicolon-separated IPv4/IPv6 addresses and hyphen-separated ranges. It explicitly documents CIDR notation for IPv4 only. The converter therefore emits exact inclusive ranges for both families; single-address prefixes become single IPs. IPv6 CIDR notation is not assumed supported.
- https://www.proxifier.com/docs/win-v4/profiles.html confirms XML `.ppx` files but provides neither a schema nor a complete profile example. A complete importable profile has not been verified, so this library deliberately provides Target Hosts text instead of claiming `.ppx` support. No compatibility claim is made for older versions or macOS.

## Route semantics and limits

CIDRs are masked to their network addresses and exact duplicates removed. Overlapping routes are not aggregated. Malformed directives return an error and no partial export. IPv4-mapped IPv6 prefixes are rejected. Gateways and metrics are parsed but not translated: proxy rules describe destinations, not OS route selection.

An explicit `route 0.0.0.0/0` or `route-ipv6 ::/0` remains an explicit default destination and is exported as such. Empty route lists generate `rules: []` and an empty hosts string, never an all-traffic rule.

Opt-in `redirect-gateway` includes IPv4 `0.0.0.0/0` unless `!ipv4` is set. The `ipv6` flag includes `2000::/4` and `3000::/4`, not `::/0`, as documented in the [upstream OpenVPN manual source](https://github.com/OpenVPN/openvpn/blob/master/doc/man-sections/vpn-network-options.rst) (verified 2026-11-25). `def1` changes OS route implementation but not the IPv4 destination union. `local` and `autolocal` concern gateway handling. The converter cannot reproduce transport, LAN, DHCP, or DNS exceptions; `bypass-dhcp`, `bypass-dns`, `block-local`, and unknown flags cause an error when opt-in is enabled. Warnings explain that opt-in broad destination rules do not reproduce OS routing exceptions. Callers should normally leave opt-in disabled.
