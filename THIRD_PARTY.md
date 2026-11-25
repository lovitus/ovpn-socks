# Third-party components

## OpenVPN protocol engine

- Source: https://github.com/SagerNet/sing-openvpn
- Pinned upstream commit: `d1e498f993a04d705024b41f9477a8d8936e7cc3`
- License: GPL-3.0-or-later (see `third_party/sing-openvpn/LICENSE`).
- Source is included under `third_party/sing-openvpn` and selected by the root `go.mod` replace directive. It is used as an in-process userspace OpenVPN protocol library; no external OpenVPN process or device driver is required.
- Local changes: an optional credentials callback refreshes TOTP at each password-based TLS key exchange, an optional DisableReconnect setting implements the profile's manual reconnect choice, and reconnect backoff now uses a stable-connection reset threshold, bounded jitter, and a thread-safe status snapshot. See `third_party/sing-openvpn/PATCHES.md` for exact behavior and test coverage.
- Vendored subset includes library Go source, `proto`, module metadata, license, and tests for local modifications. Upstream's larger reference test fixture suite is not vendored. This application's integration tests run a real official OpenVPN server separately.

## Userspace TCP/IP

- Source: https://gvisor.dev / https://github.com/google/gvisor
- Module: `gvisor.dev/gvisor`, pinned in `go.mod` and `go.sum`.
- License: Apache-2.0; upstream copyright and license notices remain in the Go module source.
- Used through channel link endpoints and gonet adapters. Every VPN session gets its own stack and only raw VPN IP packets enter or leave that stack.

## Managed native engines

- FlySSH: https://github.com/lovitus/flyssh, MIT (Copyright 2026 Lovitus).
- gust: https://github.com/lovitus/gust, MIT (Copyright 2016 ginuerzh); its private `lovitus/gust-x` dependency retains the same MIT notice. Release archives contain compiled engines and license notices; private dependency source is not copied into this public repository.
- Builds resolve the current default branch of each repository once and record the exact commits, observation-overlay SHA256 and binary SHA256 in `engines/manifest.json`. `ENGINE_SOURCES.json` records the common build input. Reproduction requires checking out those exact commits, including authorized access to the private dependency, rather than fetching a newer HEAD.
- These are explicitly instrumented builds. The optional observation overlays under `engines/flyssh` and `engines/gust` add native inspection, listener lifecycle, bounded per-service counters and a private stdout telemetry channel. Native public API/metrics settings are preserved. Overlay application fails on unexpected upstream source drift.
- FlySSH's overlay also completes half-close propagation through SSH wrappers and delegates reconnect to the parent process. Embedded fallback relays are built from the same FlySSH source for Linux amd64/arm64/386/arm, macOS amd64/arm64 and FreeBSD amd64.
- Native engine dependencies remain governed by their upstream module metadata and licenses. These executables run as companion processes; they are not linked into the OpenVPN application binary.

## Transitive dependencies

Dependency versions and integrity hashes are recorded in the root module metadata and the included OpenVPN module metadata. This includes SagerNet sing (GPL-3.0-or-later), Go x packages (BSD-style licenses), cryptographic algorithm implementations, and compression implementations. Source and licenses are available at their module URLs via `go list -m all` / `go mod download`.

Release artifacts can be reproduced from their corresponding repository commit with Go 1.26.5 and `CGO_ENABLED=0`. No real VPN credentials are used by the build or test workflows.
