# FlySSH managed build overlay

This directory contains an explicit, optional ovpn-socks build overlay, not an upstream FlySSH release. Build the latest default-branch source and record its full Git commit before applying the overlay. The initial implementation was verified against `lovitus/flyssh` main commit `6fb3fa78865e830d28bc0d180cf0d43d31490859` (2026-11-14). No upstream remote is modified.

## Build

Use a separate clean source checkout. `python engines/flyssh/apply.py PATH_TO_CHECKOUT` checks every contextual replacement and the absence of prior overlay files before writing any source. Source drift or repeated application fails explicitly. The generated package is `pkg/managed`; only the main startup, native forwarding loops and gateway lifecycle are instrumented. Native forwarding syntax and native SSH config resolution remain authoritative. Tests are copied into the disposable checkout too.

Go >=1.26.0 is required (verified with 1.26.5). Main targets: `windows/amd64`, `windows/arm64`, `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`. Set `CGO_ENABLED=0`, `GOOS`, `GOARCH`, and run `go build -trimpath -o OUTPUT .`. No platform C compiler or native GUI SDK is required by these builds. Windows GUI dependencies are pure-Go `lxn/walk`, `lxn/win`; the module graph also includes `x/crypto`, `x/sys`, `x/term`, `creack/pty` and the FlySSH fork of `mosh-go`.

The `go:embed relaybin/relay-*.gz` source requires generated relay assets first. Build `./cmd/relay` with `CGO_ENABLED=0`, `-trimpath -ldflags "-s -w"` for:

- Linux amd64, arm64, 386, arm (`GOARM=6` for arm)
- Darwin amd64, arm64
- FreeBSD amd64

Gzip each executable into `pkg/forwarding/relaybin/relay-GOOS-GOARCH.gz` (arm is named `relay-linux-arm.gz`, not arm6). Python `gzip.compress(data, compresslevel=9, mtime=0)` works on every build host; no Unix gzip dependency is needed. Only one asset is enough to compile, but a complete release must contain all seven so remote relay fallback supports all advertised remote architectures. Relay architecture is independent of the client binary architecture. The assets are generated ignored files, not upstream checked-in binaries.

Upstream release automation additionally creates Windows `.syso` manifests using `github.com/akavel/rsrc` with `-manifest flyssh.manifest -arch amd64/arm64 -o rsrc_windows_ARCH.syso`; this is a release enhancement, not required for a successful cross-build. No mandatory `go generate`. Do not blindly run upstream `build.ps1`: it removes dist and contains a stale hardcoded version.

## Native command and configuration semantics

Valid managed examples:

```text
flyssh -N -L 127.0.0.1:8080:target:80 -L 127.0.0.1:8081:target:81 -D 127.0.0.1:1080 user@ssh-host
flyssh -N -ltcp://:8080/target:80,:8081/:81 -dynamicproxy://:1080 user@ssh-host
flyssh -N -R 127.0.0.1:9000:127.0.0.1:80 user@ssh-host
flyssh --ssh-gateway user:password@127.0.0.1:2222 upstream-user@ssh-host
flyssh -N -F native-ssh-config -D 1080 host-alias
```

Repeated `-L`, `-R`, and `-D` are retained independently and receive stable IDs. Standard forwarding supports `[bind:]port:host:port`; its native colon splitter does not support IPv6 `-L/-R`. `-L tcp://...`, `-L udp://...`, and `-L ltcp://...` are NOT URL forwarding support: the CLI stores them raw, then native TCP listen fails with an invalid port. The actual easy form is an independent `-ltcp://...` option. SOCKS supports TCP CONNECT only, not UDP ASSOCIATE. `-D :1080` preserves wildcard bind, while `-dynamicproxy://:1080` normalizes to loopback; inspection preserves this difference. Remote forwards are explicitly scope=remote. Port 0 is allowed; runtime actual_address comes from the successful native listener, including the mux relay's LISTEN_OK acknowledgement.

`-F` chooses the native OpenSSH-like subset file; it is not JSON/YAML. Without `-F`, FlySSH reads the user SSH config and, on non-Windows hosts, system SSH config. Native parsing silently ignores file errors and unsupported keys. `Include`, `Match`, and `LocalForward` are not a way to declare forwarding in this implementation. Do not advertise them as supported. Keep listener declarations in argv. Managed inspection explicitly rejects an unreadable `-F` instead of permitting silent fallback.

The parser has field-specific precedence rather than full OpenSSH compatibility. Hostname/User/Port/IdentityFile commonly keep the first matching value; ConnectTimeout and StrictHostKeyChecking can be overwritten by later matching blocks. Explicit CLI overrides are applied, then the supported `-o` map. For example native `-p 2222 -o Port=3333` resolves port 3333, but `-o User=...` is ignored by native config resolution. IdentityFile and UserKnownHostsFile expand `~/` only; ordinary relative paths remain relative to process cwd, not the config file directory. The supervisor must choose an intentional cwd and preserve native references. Inspection reads config but never opens authentication keys or creates known_hosts.

## Private observation contract

Set `OVPN_SOCKS_TELEMETRY_TOKEN` to random 32 hex digits. Records are stdout lines prefixed `OVPN_ENGINE_<token> `; ordinary invocation without this env has no telemetry. Set `OVPN_SOCKS_INSPECT=1` as well for one offline `type=inspect` record and immediate exit. `type=error` emits only a finite `error_code`: invalid_arguments, invalid_config, unsupported_mode, config_not_found, too_many_listeners. Native stderr is not a diagnostic API and may contain user-provided values; parent should map only these codes to UI guidance.

Managed mode accepts foreground `-N` forwarding or native `--ssh-gateway` (the latter rejects `-N` natively). It rejects interactive commands/shells, `-W` stdio, transfer/GUI/mosh modes, `-f`, forced TTY, subsystem and X11, plus ProxyCommand subprocesses. Native `-g` and `-f` booleans have no effective forwarding implementation in this revision; do not promise daemonization or wildcard semantics from them.

Snapshots are emitted at lifecycle changes and every 2 seconds. A bounded one-record queue decouples stdout backpressure from forwarding; lifecycle changes can coalesce and the next periodic snapshot reports current state. At most 256 listeners, host length <=253, no dynamic target/client labels, no payloads, credentials, config paths or command text. The parent must drain stdout, enforce its own record limit, track exit/staleness, and never equate process alive with SSH connected or listener ready.

SSH state becomes connected only after the full chain connects. Listener states originate in the native bind/accept lifecycle, with epochs preventing a delayed close from an old listener generation overwriting the current one. Unmanaged native reconnect remains enabled unless `--no-reconnect`; it uses exponential delay 3s to 60s by default. Managed runtime explicitly sets native NoReconnect=true after offline inspection; the parent supervisor exclusively owns restart/backoff policy and per-process accounting. When a connected cycle ends, all listener epochs are invalidated and readiness cleared synchronously, so delayed native close callbacks cannot restore or overwrite stale readiness. Native bind retry is separate (250ms to 5s) and may continue even with `--no-reconnect`. Stop the owned process/process group; upstream catches SIGINT/SIGTERM and exits, without a native control API.

Local, remote and SOCKS listeners report successful payload writes continuously, including still-open long flows. Upload means local side toward SSH; for `-R` this is local destination toward remote accepted client. SOCKS negotiation and SSH framing are excluded. Active is the number of accepted flows still being served, total counts accepted flows, failed counts upstream dial failures and unsupported SOCKS commands. Malformed/incomplete SOCKS handshakes are not all counted as failures. Counts are monotonic per process except active. A payload connection remains active until both copy directions finish; half-closed flows may legitimately remain active. The overlay changes concrete TCP-only CloseWrite checks to the CloseWrite interface so SSH and idleConn wrappers can finish half-close correctly. The mux relay protocol itself does not implement half-close; complete mux closure is still governed by native transport semantics.

SSH gateway has real listener lifecycle but `metrics_available=false`; no unobserved gateway traffic is represented as measured zero. Aggregate metric availability is false when gateway is configured. No native management HTTP API or metrics endpoint exists. Optional auth prompt brokers and remote relay Unix sockets are auxiliary IPC, not user-managed forwarding listeners.

## Verification

Run `python engines/flyssh/test_inspect.py BINARY` for offline parsing, no-bind inspection with an already occupied port, invalid URL/IPv6, managed mode rejection, config lookup errors, credential redaction, relative config references, no known_hosts/key side effects and the 256-listener bound.

From the patched source, set `OVPN_FLYSSH_TEST_BINARY` to the native instrumented executable and run `go test -timeout 90s -run '^TestManagedObservationWire$' .`. This starts a mock SSH server, two local forwards, one remote forward and SOCKS on actual ephemeral ports. It verifies exact streamed payload totals while four connections are still open, then verifies active returns to zero and totals persist after both endpoints close. The mock upstream testkit does not half-close relay directions, so the test explicitly closes its echo endpoint too.

Verified on Windows with Go 1.26.5: native CLI selected parsing/validation tests, config tests, single/multiple/mixed L/R/D integration tests, offline managed inspection and full telemetry subprocess test. All six unmodified main targets and all six final instrumented main targets compile. The final inspection tests also verify that a refused loopback SSH connection exits promptly without native reconnect, leaving retry policy to the supervisor. `test_apply.py SOURCE_CHECKOUT` verifies clean HEAD application, repeat-application rejection and context-drift rejection before any file is written. The upstream complete forwarding suite has a failing Windows mux-fallback test; its test server runs `sh -lc`, so that suite is not claimed wholly passing. The complete CLI suite can hang in TestPrintUsage_HidesGUIInternalFlags because it writes a pipe synchronously before reading; use selected parsing/validation tests with a timeout.

## Upstream evidence at the audited commit

- CLI forwarding and normalization: https://github.com/lovitus/flyssh/blob/6fb3fa78865e830d28bc0d180cf0d43d31490859/pkg/cli/cli.go#L442
- Native config parser and resolution: https://github.com/lovitus/flyssh/blob/6fb3fa78865e830d28bc0d180cf0d43d31490859/pkg/config/config.go#L79
- Forward bind, SOCKS command and byte-copy implementation: https://github.com/lovitus/flyssh/blob/6fb3fa78865e830d28bc0d180cf0d43d31490859/pkg/forwarding/forwarding.go#L444
- SSH chain and forward lifecycle: https://github.com/lovitus/flyssh/blob/6fb3fa78865e830d28bc0d180cf0d43d31490859/main.go#L238
- Generated relay and release targets: https://github.com/lovitus/flyssh/blob/6fb3fa78865e830d28bc0d180cf0d43d31490859/.github/workflows/release.yml#L81
