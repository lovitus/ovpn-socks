# Third-party components

## OpenVPN protocol engine

- Source: https://github.com/SagerNet/sing-openvpn
- Pinned upstream commit: `d1e498f993a04d705024b41f9477a8d8936e7cc3`
- License: GPL-3.0-or-later (see `third_party/sing-openvpn/LICENSE`).
- Source is included under `third_party/sing-openvpn` and selected by the root `go.mod` replace directive. It is used as an in-process userspace OpenVPN protocol library; no external OpenVPN process or device driver is required.
- Local changes: an optional credentials callback refreshes TOTP at each password-based TLS key exchange, and an optional DisableReconnect setting implements the profile's manual reconnect choice. See `third_party/sing-openvpn/PATCHES.md` for exact behavior and test coverage.
- Vendored subset includes library Go source, `proto`, module metadata, license, and tests for local modifications. Upstream's larger reference test fixture suite is not vendored. This application's integration tests run a real official OpenVPN server separately.

## Userspace TCP/IP

- Source: https://gvisor.dev / https://github.com/google/gvisor
- Module: `gvisor.dev/gvisor`, pinned in `go.mod` and `go.sum`.
- License: Apache-2.0; upstream copyright and license notices remain in the Go module source.
- Used through channel link endpoints and gonet adapters. Every VPN session gets its own stack and only raw VPN IP packets enter or leave that stack.

## Transitive dependencies

Dependency versions and integrity hashes are recorded in the root module metadata and the included OpenVPN module metadata. This includes SagerNet sing (GPL-3.0-or-later), Go x packages (BSD-style licenses), cryptographic algorithm implementations, and compression implementations. Source and licenses are available at their module URLs via `go list -m all` / `go mod download`.

Release artifacts can be reproduced from their corresponding repository commit with Go 1.26.5 and `CGO_ENABLED=0`. No real VPN credentials are used by the build or test workflows.
