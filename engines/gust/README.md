# Gust managed overlay

This directory contains newly written integration code and minimal patch anchors only. It does **not** contain the private `gust-x` implementation or a vendored copy. Apply it to authorized, fresh source checkouts; do not publish the dependency checkout, source archives, module cache, or build context.

Reviewed default branches (2026-11-25):

| Repository | Branch | Commit |
| --- | --- | --- |
| gust | master | `df7966636fae327e93db54d7a2be21514c844b88` |
| gust-x (private) | master | `6445fc38d74cc92ed9cbb26d0e5eaf0f54bf0e3f` |

Use matching default branches. The patch checks exact anchors and all new destinations before writing, so source drift or a second application fails explicitly. Refresh from clean source instead of applying twice. The private implementation is consumed only during an authorized build.

```sh
python engines/gust/apply.py /source/gust /source/gust-x
cd /source/gust
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o gust ./cmd/gost
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o gust.exe ./cmd/gost
```

The reviewed sources require Go 1.26.3 or newer; verification used Go 1.26.5. Preserve the upstream module replacement pointing to the sibling `gust-x` checkout. Private dependency credentials belong in ephemeral build credentials, not source or the binary's configuration.

## Native configuration and inspection

Set a 32-hex-character `OVPN_SOCKS_TELEMETRY_TOKEN`. The only private interface is bounded JSON on stdout prefixed with `OVPN_ENGINE_<token> `. Native stdout/stderr remain native logs, not structured status. Follow the parent protocol in [PROTOCOL.md](../PROTOCOL.md).

With `OVPN_SOCKS_INSPECT=1`, the binary uses native flag registration, native repeated `-C` YAML/JSON/inline-JSON parsing, merge ordering, and native repeated `-L`/`-F` URL expansion. It validates native names, component registrations and references, emits one inspection, and exits before service/runtime constructors. Inspection never binds/dials, starts external plugins, executes service hooks, initializes auth storage, loads/generates TLS certificates, or starts the native API/metrics servers. Thus inspection proves structural validity, not remote reachability, key validity, available ports, or constructor-specific metadata validity.

Managed mode rejects workers (`--`), watchdog/daemon modes, version/config output modes, stdin/remote HTTP configuration sources, stdio/serial listeners, and standalone service-factory listeners. Native local implicit configuration is retained. Managed listeners are capped at 256; native config/API/reload activation goes through the same cap and structural guard. Safe diagnostics are `type:error` with finite `error_code`: `invalid_arguments`, `invalid_config`, `unsupported_mode`, `config_not_found`, or `too_many_listeners`. Raw errors, paths, URLs and credentials are never included in those records.

The native CLI can intentionally normalize unknown URL schemes to auto/tcp; this overlay reports the resulting native configuration instead of inventing an alternate URL grammar. In file configuration, unknown registered types and unresolved references fail inspection. Only the main local configuration is read: referenced auth/hop/TLS resources are not activated during inspection.

## Lifecycle, addresses and counting

A process starting is not a listening service, a successful chain connection, or a connected OpenVPN client. Snapshots poll native registry status and actual addresses every 250 ms, emit changes observed by that poll, and otherwise emit every 2 seconds. Very short transient states can occur between polls. Remote rtcp/rudp/runix listeners enter native ready before their lazy bind; the added read-only accessor requires an underlying bound listener before reporting listening or an actual address. A remote-kind listener without a listener chain is local in scope. For native implementations that return declaration `:0` rather than the bound ephemeral port, actual address remains absent.

Private counters tee the existing native metric calls into a separate mutex-protected per-service aggregate. They do not enable Prometheus, create an HTTP endpoint, poll/reset native observer stats, or change native API/metrics address, path, authentication, TLS, or enabled settings. TCP metric wrappers remain active for private collection even when the public metrics subsystem is disabled; this costs the native bare-TCP splice optimization while managed telemetry is active. Original metric objects still receive the same increments and labels when the user enables their own metrics.

- Upload/download are byte deltas at native wrappers. Protocol framing/handshake bytes may be included; they are not universally application payload bytes.
- SOCKS5 UDP wraps the upstream socket in the native implementation. Only the private direction is normalized (upstream write is upload, upstream read is download); native user Prometheus semantics are unchanged.
- Total/active connections mean native accepted handler requests. UDP listeners model remote-address sessions; SOCKS5 control connections own associations. These numbers are not a universal five-tuple or UDP-association count.
- Failed connections mean native server-classified handler errors. They do not count every denied request, every failed dial, or every transient listener error. Listener failure is a lifecycle state.
- Process cumulative counters retain retired service contributions across reload. A service name keeps its cumulative counters if recreated. Restart starts a new process generation at zero.
- The private map retains at most 256 service names over the process lifetime, each at most 512 bytes; it never has client/IP/target labels. Further newly named services run but report metrics unavailable. No unbounded replacement cache is maintained.
- Service IDs are stable hashes, not raw configured names. Error details are fixed safe text. Records are capped at 256 KiB, listener address fields at 512 bytes, and listener count at 256.

Verified private counting paths are TCP/UDP/TLS/unix/rtcp/rudp/runix listeners combined with native TCP/UDP/forward/auto/HTTP/SOCKS handlers. Other native listener/handler combinations continue running but report `metrics_available:false`; their zeros are not measured traffic. A process containing an unavailable listener also reports aggregate availability false. `counter_scope` and `connection_scope` explain the covered native observations. Some complex transport payload/counter paths intentionally remain unavailable rather than claiming universal coverage.

## UDP ownership and VPN integration

The native UDP listener's pool is keyed by remote address within a bound socket, rather than a global five-tuple. `keepalive=true&ttl=2s` keeps a session alive until its expiry scan (roughly one to two TTL intervals). Default TTL is 5 seconds; default keepalive is false, so a response can close the logical session. `stateless` creates per-packet sessions. Defaults include 128 backlog/read-queue entries and a 4096-byte read buffer; full queues can drop traffic. Closing a logical session preserves the shared listening socket, while closing the listener closes it. SOCKS5 UDP association lifetime follows the TCP control connection and must not be represented as this listener TTL.

Examples using separate loopback echo targets:

```sh
gust -L 'tcp://127.0.0.1:22181/127.0.0.1:22191' \
     -L 'udp://127.0.0.1:22182/127.0.0.1:22192?keepalive=true&ttl=2s' \
     -L 'socks5://testuser:testpass@127.0.0.1:22183?udp=true'
```

The external process uses the host network by default. It does not automatically share ovpn-socks' in-process VPN stack. A user-selected VPN exit needs an explicit bridge or an in-process router/PacketConn adapter. Do not duplicate the native SOCKS5/UDP session implementation or import the private dependency's `internal` packages into the public application.

A compatible public bridge can use MIT-licensed `github.com/go-gost/relay` (reviewed dependency v0.7.0) and `github.com/go-gost/gosocks5`. Use an authenticated loopback endpoint and a native chain such as `-F 'relay://user:secret@127.0.0.1:PORT?nodelay=true'`. TCP CONNECT is a relay request/response followed by a raw byte stream. Fixed-destination UDP CONNECT uses 2-byte big-endian payload lengths. SOCKS5 UDP needs the additional UDP BIND association path: bind request to `0.0.0.0:0`, successful response plus address, then SOCKS5 UDP datagrams with payload length in RSV and FRAG `0xff`. The TCP stream owns all associated sockets. A bridge must resolve names using the selected VPN resolver and preserve host/VPN isolation; accepting a chain option alone is not proof that egress reached the VPN. True remote TCP BIND/multiplexing and arbitrary remote UDP binds are separate capabilities and should be explicitly rejected by a minimal exit bridge.

An isolated SSH direct-tcpip forwarding fixture can use native `sshd://testuser:testpass@127.0.0.1:PORT`; it does not require system/root credentials. This is an SSH forwarding service, not an operating-system shell server.

## Verification

```sh
python engines/gust/test_managed.py /path/to/instrumented/gust
cd /source/gust-x
go test ./metrics -run TestManagedIndependentBoundedCounters -count=1
```

Verified on Windows amd64: the complete black-box suite and native metrics, metrics-wrapper and config-loader test suites passed; `go vet` passed for the modified metrics, loader, service and remote-listener packages. Linux amd64 cross-compilation passed; actual Linux/VPN runtime checks belong to deployment integration.

The black-box suite exercises native repeated `-L`/mixed `-C`, JSON/YAML merge, safe error codes, unsupported modes, the 256-listener limit, occupied-port inspection, real ephemeral addresses, exact loopback TCP/UDP bytes, SOCKS5 UDP traffic and control closure, UDP idle expiry, user API/metrics custom paths and Basic authentication, and cumulative counters across timed reload. The metrics unit test verifies upstream direction normalization and that 10,000 client identities do not create private cardinality or enable native Prometheus, and enforces the 256-key lifetime bound. A fresh-process restart resets counters by construction; deployment tests should additionally exercise the supervisor's generation/discard logic and actual VPN egress.
